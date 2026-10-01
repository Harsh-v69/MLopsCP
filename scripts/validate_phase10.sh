#!/usr/bin/env bash
# Phase 10 validation gate — see docs/phase10_attack_lab_spec.md.
#   Runs the full attack lab: 3 attack types (data poisoning, evasion,
#   model tampering), each run TWICE against the real pipeline end-to-end
#   (real training, real detectors, real gate, real audit log, real
#   recovery - no mocking). Slow (~45-50 min): 6 full train/attack/
#   detect/recover cycles, including 2 real HopSkipJump black-box attacks.
set -uo pipefail
cd "$(dirname "$0")/.."
FAIL=0

echo "=== Phase 10 Validation Gate ==="
echo "This runs 6 full pipeline cycles (3 attacks x 2 runs each) against the"
echo "real model, real detectors, and real recovery cycle. Expect ~45-50 min."
echo

source .venv/bin/activate

echo "[1/1] Attack lab: poisoning, evasion, tampering - each run twice, each"
echo "      expected to be caught by the gate and recovered to a clean,"
echo "      redeployed, PASS-ing model."
MLFLOW_DISABLE_AGENT_HINT=1 python3 -m pytest tests/attack_lab/test_attack_scenarios.py -v -s \
  > /tmp/phase10_attack_lab_pytest.log 2>&1
ATTACK_LAB_EXIT=$?
tail -30 /tmp/phase10_attack_lab_pytest.log
if [ "$ATTACK_LAB_EXIT" -eq 0 ]; then
  echo "  Attack lab passed (6 tests: poisoning x2, evasion x2, tampering x2 -"
  echo "  each detected and automatically recovered to a clean PASS)"
else
  echo "  FAIL: attack lab tests failed"
  FAIL=1
fi
echo

if [ "$FAIL" -eq 0 ]; then
  echo "=== PHASE 10 GATE: PASSED ==="
  exit 0
else
  echo "=== PHASE 10 GATE: FAILED ==="
  exit 1
fi
