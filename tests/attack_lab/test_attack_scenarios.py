"""Phase 10 — attack lab scenario tests. Protocol locked in
docs/phase10_attack_lab_spec.md: each of the 3 attacks is run TWICE
(different seeds), against the real pipeline end-to-end (real training,
real detectors, real gate, real audit log, real recovery) - no mocking.

These are slow (full retrain cycles, and the evasion case runs a real
HopSkipJump attack) - run explicitly, not as part of the fast test suite:
    pytest tests/attack_lab/ -v -s
"""
import pytest

from tests.attack_lab.scenarios import (
    run_evasion_scenario,
    run_poisoning_scenario,
    run_tampering_scenario,
)

pytestmark = pytest.mark.slow


def _assert_recovered(result: dict):
    """Shared post-attack assertions: whatever the initial decision was,
    the attack must have been caught (not PASS), and recovery must have
    produced a clean, redeployed, PASS-ing model."""
    gate_result = result["gate_result"]
    assert gate_result.decision != "PASS", (
        f"expected the attack to be caught by the gate, got PASS "
        f"(security_score={gate_result.security_score})"
    )
    assert result["outcome"] is not None, "expected handle_detected_attack to have run"

    recovery = result["outcome"]["recovery"]
    assert recovery.recovery_outcome == "redeployed_clean", (
        f"expected recovery to redeploy a clean model, got {recovery.recovery_outcome}"
    )
    assert recovery.revalidated_gate.decision == "PASS", (
        f"expected the retrained model to revalidate PASS, got "
        f"{recovery.revalidated_gate.decision} "
        f"(security_score={recovery.revalidated_gate.security_score})"
    )

    postmortem = result["outcome"]["postmortem"]
    assert postmortem.recovery_outcome == "redeployed_clean"
    assert postmortem.gate_decision == gate_result.decision


@pytest.mark.parametrize("run_seed", [1, 2])
def test_poisoning_scenario_detected_and_recovered(run_seed):
    """Attack 1 — locked spec: 40% label-flip poisoning expected to drive
    the gate to BORDERLINE via degraded data_scan recall/FPR."""
    result = run_poisoning_scenario(run_seed=run_seed)
    gate_result = result["gate_result"]
    assert gate_result.decision == "BORDERLINE", (
        f"expected BORDERLINE per docs/phase10_attack_lab_spec.md, got "
        f"{gate_result.decision} (security_score={gate_result.security_score})"
    )
    assert result["outcome"]["postmortem"].attack_type == "data_poisoning"
    assert result["outcome"]["postmortem"].atlas_tactic == "Poisoning"
    _assert_recovered(result)


@pytest.mark.parametrize("run_seed", [1, 2])
def test_evasion_scenario_detected_and_recovered(run_seed):
    """Attack 2 — locked spec: direct HopSkipJump attack expected to drive
    the gate to BORDERLINE via degraded model_scan robustness."""
    result = run_evasion_scenario(run_seed=run_seed)
    gate_result = result["gate_result"]
    assert gate_result.decision == "BORDERLINE", (
        f"expected BORDERLINE per docs/phase10_attack_lab_spec.md, got "
        f"{gate_result.decision} (security_score={gate_result.security_score})"
    )
    assert result["outcome"]["postmortem"].attack_type == "evasion"
    assert result["outcome"]["postmortem"].atlas_tactic == "Evasion"
    _assert_recovered(result)


@pytest.mark.parametrize("run_seed", [1, 2])
def test_tampering_scenario_detected_and_recovered(run_seed):
    """Attack 3 — locked spec: a tampered artifact must FAIL via the hard
    integrity override regardless of every other sub-score."""
    result = run_tampering_scenario(run_seed=run_seed)
    gate_result = result["gate_result"]
    assert gate_result.decision == "FAIL", (
        f"expected FAIL per docs/phase10_attack_lab_spec.md (hard integrity "
        f"override), got {gate_result.decision}"
    )
    assert gate_result.integrity_component == 0.0
    assert result["outcome"]["postmortem"].attack_type == "model_tampering"
    assert result["outcome"]["postmortem"].atlas_tactic == "Persistence / ML Model Access"
    assert result["outcome"]["postmortem"].action_taken == "quarantined_immediately"
    _assert_recovered(result)
