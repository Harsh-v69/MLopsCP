"""Phase 7 — Security Gate scoring and decision logic.

Implements docs/security_gate_formula.md (as amended in Phase 7 for
dependency_score - see that file's Section 1.3 for the dated, reasoned
change). Test scenarios and their exact expected values are locked in
docs/phase7_gate_decision_spec.md before this file was written.
"""
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from src.security.dependency_scan import count_vulnerabilities, run_pip_audit
from src.security.verify_model import verify as verify_model_signature

REPO_ROOT = Path(__file__).resolve().parents[2]
POISONING_EVAL_PATH = REPO_ROOT / "data" / "processed" / "phase5_poisoning_eval.json"
ADVERSARIAL_EVAL_PATH = REPO_ROOT / "data" / "processed" / "phase6_adversarial_eval.json"
REQUIREMENTS_PATH = REPO_ROOT / "requirements.txt"

MAX_ALLOWED_FPR = 0.10          # locked in docs/security_gate_formula.md / Phase 5
MAX_ALLOWED_DEGRADATION = 0.30  # locked in docs/security_gate_formula.md / Phase 6
DEPENDENCY_VULN_CAP = 10        # locked in the Phase 7 amendment
DEPENDENCY_PENALTY_PER_VULN = 10

DATA_SCORE_WEIGHT = 0.35
MODEL_SCORE_WEIGHT = 0.40
DEPENDENCY_SCORE_WEIGHT = 0.25

PASS_THRESHOLD = 80
BORDERLINE_THRESHOLD = 50


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def compute_data_score(recall: float, fpr: float) -> float:
    return 100 - 60 * _clamp(1 - recall, 0, 1) - 40 * _clamp(fpr / MAX_ALLOWED_FPR, 0, 1)


def compute_model_score(integrity_ok: bool, clean_accuracy: float, adversarial_accuracy: float):
    integrity_component = 100.0 if integrity_ok else 0.0
    degradation = clean_accuracy - adversarial_accuracy
    robustness_component = 100 * _clamp(1 - degradation / MAX_ALLOWED_DEGRADATION, 0, 1)
    model_score = 0.5 * integrity_component + 0.5 * robustness_component
    return model_score, integrity_component


def compute_dependency_score(vulnerability_count: int) -> float:
    return max(0, 100 - DEPENDENCY_PENALTY_PER_VULN * min(vulnerability_count, DEPENDENCY_VULN_CAP))


def compute_security_score(data_score: float, model_score: float, dependency_score: float) -> float:
    return (
        DATA_SCORE_WEIGHT * data_score
        + MODEL_SCORE_WEIGHT * model_score
        + DEPENDENCY_SCORE_WEIGHT * dependency_score
    )


def decide(security_score: float, integrity_component: float) -> str:
    if integrity_component == 0:
        return "FAIL"
    if security_score >= PASS_THRESHOLD:
        return "PASS"
    if security_score >= BORDERLINE_THRESHOLD:
        return "BORDERLINE"
    return "FAIL"


@dataclass
class GateResult:
    data_score: float
    model_score: float
    dependency_score: float
    security_score: float
    integrity_component: float
    decision: str
    details: dict = field(default_factory=dict)


def run_gate(
    poisoning_eval_path: Path = POISONING_EVAL_PATH,
    adversarial_eval_path: Path = ADVERSARIAL_EVAL_PATH,
    requirements_path: Path = REQUIREMENTS_PATH,
) -> GateResult:
    """Integration entry point: reads Phase 5/6's stored evaluation
    results, runs live integrity verification and a live dependency scan,
    and returns the full gate decision with every sub-score shown (never
    just the decision alone)."""
    details = {}

    # data_score — fail-closed if the stored Phase 5 result is missing/unreadable.
    try:
        poisoning_eval = json.loads(Path(poisoning_eval_path).read_text())
        recall = poisoning_eval["recall"]
        fpr = poisoning_eval["false_positive_rate"]
        data_score = compute_data_score(recall, fpr)
        details["data_scan"] = {"recall": recall, "false_positive_rate": fpr, "status": "ok"}
    except (FileNotFoundError, KeyError, json.JSONDecodeError) as e:
        data_score = 0.0
        details["data_scan"] = {"status": "failed", "error": str(e)}

    # model_score — integrity is live; robustness comes from Phase 6's stored result.
    try:
        integrity_ok = verify_model_signature()
    except Exception as e:  # fail-closed: any error verifying integrity = failed integrity
        integrity_ok = False
        details["integrity_check_error"] = str(e)

    try:
        adversarial_eval = json.loads(Path(adversarial_eval_path).read_text())
        clean_accuracy = adversarial_eval["clean_accuracy"]
        adversarial_accuracy = adversarial_eval["adversarial_accuracy"]
        model_score, integrity_component = compute_model_score(integrity_ok, clean_accuracy, adversarial_accuracy)
        details["model_scan"] = {
            "integrity_ok": integrity_ok,
            "clean_accuracy": clean_accuracy,
            "adversarial_accuracy": adversarial_accuracy,
            "status": "ok",
        }
    except (FileNotFoundError, KeyError, json.JSONDecodeError) as e:
        # Robustness data missing -> that half of model_score is
        # fail-closed to 0 directly (NOT by feeding compute_model_score
        # bogus accuracy values - clean=0/adv=1 would compute as *negative*
        # degradation and award full robustness credit, the opposite of
        # fail-closed). integrity_component still reflects the real,
        # already-checked live integrity result.
        integrity_component = 100.0 if integrity_ok else 0.0
        model_score = 0.5 * integrity_component + 0.5 * 0.0
        details["model_scan"] = {"integrity_ok": integrity_ok, "status": "robustness_data_missing", "error": str(e)}

    # dependency_score — live scan, fail-closed on any error.
    try:
        audit_result = run_pip_audit(Path(requirements_path))
        vulnerability_count = count_vulnerabilities(audit_result)
        dependency_score = compute_dependency_score(vulnerability_count)
        details["dependency_scan"] = {"vulnerability_count": vulnerability_count, "status": "ok"}
    except Exception as e:
        dependency_score = 0.0
        details["dependency_scan"] = {"status": "failed", "error": str(e)}

    security_score = compute_security_score(data_score, model_score, dependency_score)
    decision = decide(security_score, integrity_component)

    return GateResult(
        data_score=data_score,
        model_score=model_score,
        dependency_score=dependency_score,
        security_score=security_score,
        integrity_component=integrity_component,
        decision=decision,
        details=details,
    )


def main():
    result = run_gate()
    print(f"data_score:        {result.data_score:.4f}")
    print(f"model_score:        {result.model_score:.4f}")
    print(f"dependency_score:   {result.dependency_score:.4f}")
    print(f"security_score:     {result.security_score:.4f}")
    print(f"integrity_component: {result.integrity_component}")
    print(f"DECISION: {result.decision}")
    print(json.dumps(result.details, indent=2))
    return result


if __name__ == "__main__":
    main()
