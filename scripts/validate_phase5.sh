#!/usr/bin/env bash
# Phase 5 validation gate — see docs/phase5_security_gate_v1_spec.md.
#   1. Poisoning detector: recall >= 0.80 at FPR <= 0.10 (target locked in
#      Phase 0's docs/security_gate_formula.md, before any detector existed).
#   2. Tampering check: 10/10 tampered artifact copies fail verification,
#      the legitimate artifact passes.
set -uo pipefail
cd "$(dirname "$0")/.."
FAIL=0

echo "=== Phase 5 Validation Gate ==="
echo

source .venv/bin/activate

echo "[1/3] Poisoning detector injection test"
MLFLOW_DISABLE_AGENT_HINT=1 python3 -m src.security.evaluate_poisoning_detector
POISON_EXIT=$?
if [ "$POISON_EXIT" -eq 0 ]; then
  echo "  Poisoning detector meets the locked recall/FPR bar"
else
  echo "  FAIL: poisoning detector did not meet the locked bar"
  FAIL=1
fi
echo

echo "[2/3] Model artifact signing + tampering test suite"
python3 -m src.security.sign_model
SIGN_EXIT=$?
python3 -m src.security.verify_model
VERIFY_EXIT=$?
if [ "$SIGN_EXIT" -eq 0 ] && [ "$VERIFY_EXIT" -eq 0 ]; then
  echo "  Legitimate artifact signs and verifies correctly"
else
  echo "  FAIL: sign/verify of the legitimate artifact did not succeed"
  FAIL=1
fi

python3 -m pytest tests/security/test_model_integrity.py -v > /tmp/phase5_integrity_pytest.log 2>&1
INTEGRITY_PYTEST_EXIT=$?
tail -20 /tmp/phase5_integrity_pytest.log
if [ "$INTEGRITY_PYTEST_EXIT" -eq 0 ]; then
  echo "  10/10 tampering test cases passed (all correctly rejected)"
else
  echo "  FAIL: tampering test suite failed"
  FAIL=1
fi
echo

echo "[3/3] Full security test suite (both parts together)"
python3 -m pytest tests/security/ > /tmp/phase5_full_pytest.log 2>&1
FULL_EXIT=$?
tail -5 /tmp/phase5_full_pytest.log
if [ "$FULL_EXIT" -eq 0 ]; then
  echo "  Full tests/security/ suite passed"
else
  echo "  FAIL: full security suite failed"
  FAIL=1
fi
echo

if [ "$FAIL" -eq 0 ]; then
  echo "=== PHASE 5 GATE: PASSED ==="
  exit 0
else
  echo "=== PHASE 5 GATE: FAILED ==="
  exit 1
fi
