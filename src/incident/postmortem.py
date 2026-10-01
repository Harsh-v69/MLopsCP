"""Phase 10 — auto-populated incident postmortem. Field list locked in
docs/phase10_attack_lab_spec.md (Part C) before this file was written.
Generated whether recovery succeeds or not - a failed recovery is itself
an incident-worthy fact, not something to leave unrecorded.
"""
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
INCIDENTS_DIR = REPO_ROOT / "data" / "incidents"

ATLAS_TACTIC = {
    "data_poisoning": "Poisoning",
    "evasion": "Evasion",
    "model_tampering": "Persistence / ML Model Access",
}

DETECTION_MECHANISM = {
    "data_poisoning": "data_scan",
    "evasion": "model_scan (robustness)",
    "model_tampering": "model_scan (integrity)",
}


@dataclass
class Postmortem:
    incident_id: str
    detected_at: str
    attack_type: str
    atlas_tactic: str
    detection_mechanism: str
    evidence: dict
    gate_decision: str
    action_taken: str
    approval_record: Optional[dict]
    recovery_outcome: str
    linked_audit_log_seqs: list = field(default_factory=list)
    postmortem_summary: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _compose_summary(p: "Postmortem") -> str:
    """Built from the fields themselves by template - not hand-written per
    incident (see spec: 'auto-composed, not freeform prose')."""
    approval_clause = ""
    if p.approval_record:
        approval_clause = (
            f" An Approver ({p.approval_record['actor']}) reviewed the evidence and "
            f"recorded: \"{p.approval_record['justification']}\"."
        )

    return (
        f"Incident {p.incident_id}: a {p.attack_type.replace('_', ' ')} attack "
        f"(MITRE ATLAS: {p.atlas_tactic}) was detected via {p.detection_mechanism} "
        f"at {p.detected_at}. The Security Gate returned {p.gate_decision}."
        f"{approval_clause} Action taken: {p.action_taken.replace('_', ' ')}. "
        f"Recovery outcome: {p.recovery_outcome.replace('_', ' ')}."
    )


def generate_postmortem(
    attack_type: str,
    evidence: dict,
    gate_decision: str,
    action_taken: str,
    recovery_outcome: str,
    approval_record: Optional[dict] = None,
    linked_audit_log_seqs: Optional[list] = None,
    incident_id: Optional[str] = None,
) -> Postmortem:
    """incident_id can be supplied by the caller (e.g. src/recovery/cycle.py,
    which needs the same id for the quarantine filename and the
    postmortem record) - defaults to a fresh uuid4 if not given."""
    if attack_type not in ATLAS_TACTIC:
        raise ValueError(f"unknown attack_type: {attack_type!r} (must be one of {sorted(ATLAS_TACTIC)})")

    p = Postmortem(
        incident_id=incident_id or str(uuid.uuid4()),
        detected_at=datetime.now(timezone.utc).isoformat(),
        attack_type=attack_type,
        atlas_tactic=ATLAS_TACTIC[attack_type],
        detection_mechanism=DETECTION_MECHANISM[attack_type],
        evidence=evidence,
        gate_decision=gate_decision,
        action_taken=action_taken,
        approval_record=approval_record,
        recovery_outcome=recovery_outcome,
        linked_audit_log_seqs=linked_audit_log_seqs or [],
    )
    p.postmortem_summary = _compose_summary(p)
    return p


def save_postmortem(postmortem: Postmortem) -> Path:
    INCIDENTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = INCIDENTS_DIR / f"{postmortem.incident_id}.json"
    out_path.write_text(json.dumps(postmortem.to_dict(), indent=2))
    return out_path
