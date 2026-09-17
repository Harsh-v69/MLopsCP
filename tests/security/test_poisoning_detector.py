"""Phase 5 gate test for the poisoning detector — runs the same injection
protocol as src/security/evaluate_poisoning_detector.py and asserts the
locked bar (docs/security_gate_formula.md: recall>=0.80 at FPR<=0.10)."""
from src.security.evaluate_poisoning_detector import main as run_poisoning_eval


def test_poisoning_detector_meets_locked_recall_fpr_bar():
    exit_code = run_poisoning_eval()
    assert exit_code == 0, "poisoning detector did not meet the locked recall/FPR bar"
