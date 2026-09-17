"""Phase 7 gate test suite. Every scenario and its exact expected value is
locked in docs/phase7_gate_decision_spec.md, computed independently in
Python before this file was written - not derived from a first
implementation run and then copied in.
"""
import pytest

from src.security.gate import (
    compute_data_score,
    compute_dependency_score,
    compute_model_score,
    compute_security_score,
    decide,
    run_gate,
)

# --- End-to-end scenarios (spec table 1) --------------------------------

def test_clear_pass_perfect():
    d = compute_data_score(recall=1.0, fpr=0.0)
    m, integrity = compute_model_score(integrity_ok=True, clean_accuracy=1.0, adversarial_accuracy=1.0)
    dep = compute_dependency_score(vulnerability_count=0)
    s = compute_security_score(d, m, dep)

    assert d == 100
    assert m == 100.0
    assert dep == 100
    assert s == 100.0
    assert decide(s, integrity) == "PASS"


def test_real_project_numbers_via_pure_functions():
    d = compute_data_score(recall=0.96625, fpr=0.0325)
    m, integrity = compute_model_score(integrity_ok=True, clean_accuracy=1.0, adversarial_accuracy=0.99)
    dep = compute_dependency_score(vulnerability_count=2)
    s = compute_security_score(d, m, dep)

    assert d == pytest.approx(84.975)
    assert m == pytest.approx(98.3333, abs=1e-3)
    assert dep == 80
    assert s == pytest.approx(89.0746, abs=1e-3)
    assert decide(s, integrity) == "PASS"


def test_real_project_numbers_via_live_run_gate():
    """Cross-checks the wiring itself (reading the real Phase 5/6 files,
    running the real live integrity check and dependency scan), not just
    the arithmetic - matches the same expected values as the pure-function
    version above, computed independently."""
    result = run_gate()
    assert result.data_score == pytest.approx(84.975)
    assert result.model_score == pytest.approx(98.3333, abs=1e-3)
    assert result.dependency_score == pytest.approx(80, abs=20)  # dependency posture can drift; see note below
    assert result.decision == "PASS"
    # dependency_score isn't pinned as tightly as the others: new CVEs can
    # legitimately be published against unchanged pinned versions between
    # when this test was written and when it runs. What must NOT change is
    # that the live scan runs successfully and produces *some* valid score.
    assert 0 <= result.dependency_score <= 100


def test_clear_fail_everything_bad_integrity_ok():
    d = compute_data_score(recall=0.0, fpr=1.0)
    m, integrity = compute_model_score(integrity_ok=True, clean_accuracy=1.0, adversarial_accuracy=0.0)
    dep = compute_dependency_score(vulnerability_count=10)
    s = compute_security_score(d, m, dep)

    assert d == 0
    assert m == 50.0
    assert dep == 0
    assert s == 20.0
    assert decide(s, integrity) == "FAIL"


def test_integrity_override_fail_despite_high_score():
    """The actual proof the hard override works - score alone reads
    exactly 80.0 (would be PASS), but a failed integrity check must still
    force FAIL."""
    d = compute_data_score(recall=1.0, fpr=0.0)
    m, integrity = compute_model_score(integrity_ok=False, clean_accuracy=1.0, adversarial_accuracy=1.0)
    dep = compute_dependency_score(vulnerability_count=0)
    s = compute_security_score(d, m, dep)

    assert s == 80.0  # score alone would be PASS
    assert integrity == 0.0
    assert decide(s, integrity) == "FAIL"  # override wins


# --- decide() boundary scenarios (spec table 2) -------------------------

@pytest.mark.parametrize("security_score,expected", [
    (80.0, "PASS"),
    (79.999, "BORDERLINE"),
    (50.0, "BORDERLINE"),
    (49.999, "FAIL"),
    (100.0, "PASS"),
    (0.0, "FAIL"),
])
def test_decide_boundaries(security_score, expected):
    assert decide(security_score, integrity_component=100) == expected


# --- compute_data_score component scenarios (spec table 3) --------------

def test_data_score_exactly_at_phase5_bar():
    """NOT a bug: the formula measures distance from a perfect detector
    (recall=1, fpr=0), not distance from Phase 5's own pass bar. A
    detector that just clears Phase 5's gate (recall=0.80, fpr=0.10)
    still costs 52 points here - fpr=0.10 alone saturates that penalty
    term fully."""
    assert compute_data_score(recall=0.80, fpr=0.10) == 48.0


def test_data_score_recall_partial():
    assert compute_data_score(recall=0.50, fpr=0.0) == 70.0


def test_data_score_fpr_partial():
    assert compute_data_score(recall=1.0, fpr=0.05) == 80.0


# --- compute_model_score component scenarios (spec table 4) -------------

def test_model_score_at_max_degradation():
    m, integrity = compute_model_score(integrity_ok=True, clean_accuracy=1.0, adversarial_accuracy=0.70)
    assert m == 50.0
    assert integrity == 100.0


def test_model_score_zero_degradation():
    m, integrity = compute_model_score(integrity_ok=True, clean_accuracy=1.0, adversarial_accuracy=1.0)
    assert m == 100.0
    assert integrity == 100.0


# --- compute_dependency_score component scenarios (spec table 5) --------

@pytest.mark.parametrize("vuln_count,expected", [
    (0, 100),
    (3, 70),
    (10, 0),
    (15, 0),
])
def test_dependency_score(vuln_count, expected):
    assert compute_dependency_score(vuln_count) == expected


# --- Fail-closed / missing-scan scenarios (spec table 6) ----------------

def test_fail_closed_missing_poisoning_eval(tmp_path):
    missing_path = tmp_path / "does_not_exist.json"
    result = run_gate(poisoning_eval_path=missing_path)
    assert result.data_score == 0.0
    assert result.details["data_scan"]["status"] == "failed"


def test_fail_closed_dependency_scan_raises(tmp_path, monkeypatch):
    missing_requirements = tmp_path / "does_not_exist_requirements.txt"
    # run_pip_audit on a nonexistent requirements file should error out
    # (pip-audit itself fails on a missing -r target) - run_gate must
    # catch that and fail closed, not crash.
    result = run_gate(requirements_path=missing_requirements)
    assert result.dependency_score == 0.0
    assert result.details["dependency_scan"]["status"] == "failed"
