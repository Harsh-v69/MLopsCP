#!/usr/bin/env bash
# Phase 9 validation gate — see docs/phase9_transparency_spec.md.
#   1. Backend endpoint tests (SHAP, Model Card, RBAC-gated audit log).
#   2. Frontend component tests (real fetched data + visible error states).
#   3. The gate-mandated 3-decision cross-check (PASS/FAIL/BORDERLINE
#      ground truth + live endpoint fidelity to run_gate()).
set -uo pipefail
cd "$(dirname "$0")/.."
FAIL=0

echo "=== Phase 9 Validation Gate ==="
echo

source .venv/bin/activate

echo "[1/3] Backend transparency endpoint tests"
MLFLOW_DISABLE_AGENT_HINT=1 python3 -m pytest tests/api/test_transparency_endpoints.py -v \
  > /tmp/phase9_backend_pytest.log 2>&1
BACKEND_EXIT=$?
tail -10 /tmp/phase9_backend_pytest.log
if [ "$BACKEND_EXIT" -eq 0 ]; then
  echo "  Backend endpoint tests passed (16 tests: SHAP, Model Card, RBAC-gated audit log)"
else
  echo "  FAIL: backend endpoint tests failed"
  FAIL=1
fi
echo

echo "[2/3] Dashboard component tests"
(cd dashboard && npm test > /tmp/phase9_frontend_test.log 2>&1)
FRONTEND_EXIT=$?
tail -10 /tmp/phase9_frontend_test.log
if [ "$FRONTEND_EXIT" -eq 0 ]; then
  echo "  Dashboard component tests passed (9 tests across Overview/ModelCard/AuditTrail/Explain)"
else
  echo "  FAIL: dashboard component tests failed"
  FAIL=1
fi
echo

echo "[3/3] PASS/FAIL/BORDERLINE cross-check (the literal Phase 9 gate criterion)"
MLFLOW_DISABLE_AGENT_HINT=1 python3 -m pytest tests/api/test_security_gate_cross_check.py -v \
  > /tmp/phase9_crosscheck_pytest.log 2>&1
CROSSCHECK_EXIT=$?
tail -10 /tmp/phase9_crosscheck_pytest.log
if [ "$CROSSCHECK_EXIT" -eq 0 ]; then
  echo "  Cross-check passed: formula produces all 3 decisions + live endpoint matches run_gate() exactly"
else
  echo "  FAIL: cross-check failed"
  FAIL=1
fi
echo

echo "[bonus] Dashboard production build"
(cd dashboard && npm run build > /tmp/phase9_build.log 2>&1)
BUILD_EXIT=$?
if [ "$BUILD_EXIT" -eq 0 ]; then
  echo "  Dashboard builds cleanly for production"
else
  echo "  FAIL: dashboard build failed"
  tail -20 /tmp/phase9_build.log
  FAIL=1
fi
echo

if [ "$FAIL" -eq 0 ]; then
  echo "=== PHASE 9 GATE: PASSED ==="
  exit 0
else
  echo "=== PHASE 9 GATE: FAILED ==="
  exit 1
fi
