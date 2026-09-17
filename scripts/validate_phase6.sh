#!/usr/bin/env bash
# Phase 6 validation gate — see docs/phase6_security_gate_v2_spec.md.
#   1. Adversarial test: degradation <= 0.30 (locked in Phase 0's
#      docs/security_gate_formula.md), reproducible bit-identically across
#      two runs, and the attack surface stays confined to the 15
#      documented rate features (not a blanket-clip artifact — see
#      progress.md Phase 6 notes on the bug this caught during development).
#   2. Dependency scan: seeded vulnerability caught reliably; SBOM schema-valid.
set -uo pipefail
cd "$(dirname "$0")/.."
FAIL=0

echo "=== Phase 6 Validation Gate ==="
echo

source .venv/bin/activate

echo "[1/2] Adversarial robustness test (this runs the surrogate fit multiple"
echo "      times across the pytest suite below - can take several minutes)"
MLFLOW_DISABLE_AGENT_HINT=1 python3 -m pytest tests/security/test_adversarial.py -v \
  > /tmp/phase6_adversarial_pytest.log 2>&1
ADV_EXIT=$?
tail -20 /tmp/phase6_adversarial_pytest.log
if [ "$ADV_EXIT" -eq 0 ]; then
  echo "  Adversarial test suite passed (bar met, reproducible, attack surface confined)"
else
  echo "  FAIL: adversarial test suite failed"
  FAIL=1
fi
echo

echo "[2/2] Dependency scan + SBOM test suite"
python3 -m pytest tests/security/test_dependency_scan.py -v > /tmp/phase6_depscan_pytest.log 2>&1
DEP_EXIT=$?
tail -20 /tmp/phase6_depscan_pytest.log
if [ "$DEP_EXIT" -eq 0 ]; then
  echo "  Dependency scan / SBOM suite passed"
else
  echo "  FAIL: dependency scan / SBOM suite failed"
  FAIL=1
fi
echo

if [ "$FAIL" -eq 0 ]; then
  echo "=== PHASE 6 GATE: PASSED ==="
  exit 0
else
  echo "=== PHASE 6 GATE: FAILED ==="
  exit 1
fi
