"""Phase 6 gate tests for the adversarial robustness test. Bar and
reproducibility requirement locked in docs/phase6_security_gate_v2_spec.py
(Part A) / docs/security_gate_formula.md."""
from src.security.adversarial_test import run_adversarial_test


def test_degradation_within_locked_bar():
    results = run_adversarial_test()
    assert results["passed"] is True
    assert results["degradation"] <= results["max_allowed_degradation"]


def test_reproducible_across_two_runs():
    """Same code, same seeds -> bit-identical clean/adversarial accuracy.
    This is what 'reliably reproduces... not flaky/random' means
    operationally (project plan, Phase 6 Test)."""
    result_1 = run_adversarial_test()
    result_2 = run_adversarial_test()
    assert result_1["clean_accuracy"] == result_2["clean_accuracy"]
    assert result_1["adversarial_accuracy"] == result_2["adversarial_accuracy"]
    assert result_1["degradation"] == result_2["degradation"]


def test_only_rate_features_were_perturbed():
    results = run_adversarial_test()
    # Sanity bound: at most the 15 documented rate features could have
    # been perturbed (mask guarantees this structurally; this confirms it
    # empirically too).
    assert results["n_rate_feature_dims_actually_perturbed"] <= 15
