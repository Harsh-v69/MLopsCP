"""Phase 10 — automated recovery cycle: quarantine -> retrain -> revalidate
-> redeploy. State machine locked in docs/phase10_attack_lab_spec.md
(Part B) before this file was written.

Every step below calls the SAME functions every other phase already wrote
and tested (src.pipeline.*, src.security.*, src.governance.*) - "no
manual code changes" (project plan, Phase 10 Validate) means exactly
that: this file is an orchestrator, not a reimplementation.
"""
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.governance.approval import approve_or_reject, log_gate_result
from src.governance.audit_log import AuditLog
from src.governance.auth import APPROVER, issue_token
from src.incident.postmortem import generate_postmortem, save_postmortem
from src.pipeline import data_scan, ingest, model_scan, register, train as train_step, validate
from src.security.gate import GateResult, run_gate
from src.security.sign_model import sign_model_at

REPO_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = REPO_ROOT / "models" / "phase3_model.joblib"
SIGNATURE_PATH = REPO_ROOT / "models" / "phase3_model.joblib.sig"
QUARANTINE_DIR = REPO_ROOT / "data" / "quarantine"
POISONING_EVAL_PATH = REPO_ROOT / "data" / "processed" / "current_run_poisoning_eval.json"
ADVERSARIAL_EVAL_PATH = REPO_ROOT / "data" / "processed" / "current_run_adversarial_eval.json"

CALIBRATION_POISON_RATE = 0.10  # Phase 5's normal rate, not the attack-lab's attack rate


def run_current_pipeline_gate(audit_log: AuditLog) -> GateResult:
    """Evaluates the gate against whatever model/eval files the current
    run just produced (models/phase3_model.joblib + the current_run_*.json
    files), logs the result, and returns it."""
    result = run_gate(
        poisoning_eval_path=POISONING_EVAL_PATH,
        adversarial_eval_path=ADVERSARIAL_EVAL_PATH,
        model_artifact_path=MODEL_PATH,
        model_signature_path=SIGNATURE_PATH,
    )
    log_gate_result(result, audit_log)
    return result


def quarantine_current_artifact(incident_id: str) -> Optional[Path]:
    """Moves (never deletes) the current model artifact + signature aside,
    preserved for forensics, and never reachable via the registered model
    name again until a clean replacement is redeployed."""
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    dest = None
    if MODEL_PATH.exists():
        dest = QUARANTINE_DIR / f"{incident_id}_{MODEL_PATH.name}"
        shutil.move(str(MODEL_PATH), str(dest))
    if SIGNATURE_PATH.exists():
        shutil.move(str(SIGNATURE_PATH), str(QUARANTINE_DIR / f"{incident_id}_{SIGNATURE_PATH.name}"))
    return dest


def retrain_clean_and_revalidate(audit_log: AuditLog) -> GateResult:
    """RETRAIN -> REVALIDATE. Ingest with NO source override (explicitly
    cleared here, regardless of what an attack scenario set) so recovery
    can never accidentally retrain on the same attacked input - reads from
    the original Phase 0 locked, hash-verified raw data. Uses the
    STANDARD (fast) robustness check and the calibration (10%) poison
    rate, not the attack lab's deliberately-harsh parameters - revalidating
    a clean model doesn't need the expensive attack-strength checks, only
    confirming it still clears the normal bar."""
    os.environ.pop("MLSHIELD_INGEST_TRAIN_SOURCE", None)

    assert ingest.main() == 0, "recovery retrain: ingest failed"
    assert validate.main() == 0, "recovery retrain: validate failed"
    assert train_step.main() == 0, "recovery retrain: train failed"

    sign_model_at(MODEL_PATH, SIGNATURE_PATH)
    model_scan.main(model_path=MODEL_PATH, signature_path=SIGNATURE_PATH, robustness_mode="standard")
    data_scan.main(poison_rate=CALIBRATION_POISON_RATE)

    return run_current_pipeline_gate(audit_log)


def redeploy() -> int:
    return register.main()


@dataclass
class RecoveryResult:
    incident_id: str
    quarantined_path: Optional[str]
    revalidated_gate: GateResult
    recovery_outcome: str  # "redeployed_clean" | "recovery_failed"


def run_recovery(audit_log: AuditLog) -> RecoveryResult:
    """QUARANTINE -> RETRAIN -> REVALIDATE -> REDEPLOY (if the revalidated,
    clean-retrained model PASSes; anything else is a new incident, not a
    silent retry)."""
    incident_id = str(uuid.uuid4())

    quarantined_path = quarantine_current_artifact(incident_id)
    audit_log.append(
        actor="system", role="SYSTEM", action="artifact_quarantined",
        details={"incident_id": incident_id, "quarantined_to": str(quarantined_path) if quarantined_path else None},
    )

    revalidated = retrain_clean_and_revalidate(audit_log)

    if revalidated.decision == "PASS":
        redeploy_exit = redeploy()
        outcome = "redeployed_clean" if redeploy_exit == 0 else "recovery_failed"
    else:
        outcome = "recovery_failed"

    audit_log.append(
        actor="system", role="SYSTEM", action="recovery_cycle_completed",
        details={"incident_id": incident_id, "outcome": outcome, "revalidated_decision": revalidated.decision},
    )

    return RecoveryResult(
        incident_id=incident_id,
        quarantined_path=str(quarantined_path) if quarantined_path else None,
        revalidated_gate=revalidated,
        recovery_outcome=outcome,
    )


def handle_detected_attack(
    attack_type: str,
    gate_result: GateResult,
    audit_log: AuditLog,
    approver_subject: str = "attack-lab-approver",
) -> dict:
    """The full response to a detected attack: FAIL -> quarantine
    immediately; BORDERLINE -> a real Approver call (through Phase 8's
    RBAC, not a bypass) reviews the evidence and rejects - a correct human
    judgment call given known-attack evidence - THEN quarantine. Either
    way, recovery runs automatically after, and a postmortem is generated
    whether recovery succeeds or not."""
    approval_record = None

    if gate_result.decision == "BORDERLINE":
        token = issue_token(approver_subject, APPROVER)
        justification = (
            f"Rejecting: {attack_type.replace('_', ' ')} attack evidence in this run's "
            f"scan results (security_score={gate_result.security_score:.2f}, "
            f"data_score={gate_result.data_score:.2f}, model_score={gate_result.model_score:.2f})."
        )
        outcome = approve_or_reject(gate_result, token, "rejected", justification, audit_log)
        assert outcome.recorded, f"expected the simulated Approver rejection to be recorded: {outcome.reason}"
        approval_record = {
            "actor": outcome.audit_entry["actor"],
            "role": outcome.audit_entry["role"],
            "justification": outcome.audit_entry["details"]["justification"],
            "timestamp": outcome.audit_entry["timestamp"],
        }
        action_taken = "quarantined_after_approver_rejection"
    elif gate_result.decision == "FAIL":
        action_taken = "quarantined_immediately"
    else:
        raise ValueError(f"handle_detected_attack called with decision={gate_result.decision!r} - not an attack outcome")

    recovery = run_recovery(audit_log)

    postmortem = generate_postmortem(
        attack_type=attack_type,
        evidence=gate_result.details,
        gate_decision=gate_result.decision,
        action_taken=action_taken,
        recovery_outcome=recovery.recovery_outcome,
        approval_record=approval_record,
        incident_id=recovery.incident_id,
    )
    postmortem_path = save_postmortem(postmortem)

    return {
        "postmortem": postmortem,
        "postmortem_path": str(postmortem_path),
        "recovery": recovery,
    }
