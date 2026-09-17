#!/usr/bin/env bash
# Phase 7 validation gate — see docs/phase7_gate_decision_spec.md.
# Every one of the 21+ locked scenarios must produce exactly its
# documented expected value/decision, and a live run_gate() call against
# this project's real current state must complete and produce a sane
# decision (cross-checking the wiring, not just the arithmetic).
set -uo pipefail
cd "$(dirname "$0")/.."
FAIL=0

echo "=== Phase 7 Validation Gate ==="
echo

source .venv/bin/activate

echo "[1/2] Scripted scenario test suite (docs/phase7_gate_decision_spec.md)"
MLFLOW_DISABLE_AGENT_HINT=1 python3 -m pytest tests/security/test_gate_decision.py -v \
  > /tmp/phase7_gate_pytest.log 2>&1
GATE_EXIT=$?
tail -30 /tmp/phase7_gate_pytest.log
if [ "$GATE_EXIT" -eq 0 ]; then
  echo "  All scripted scenarios produced their exact documented expected value"
else
  echo "  FAIL: gate decision test suite failed"
  FAIL=1
fi
echo

echo "[2/2] Live gate run against real project state"
MLFLOW_DISABLE_AGENT_HINT=1 python3 -m src.security.gate
LIVE_EXIT=$?
if [ "$LIVE_EXIT" -eq 0 ]; then
  echo "  Live run_gate() completed without error"
else
  echo "  FAIL: live run_gate() errored"
  FAIL=1
fi
echo

if [ "$FAIL" -eq 0 ]; then
  echo "=== PHASE 7 GATE: PASSED ==="
  exit 0
else
  echo "=== PHASE 7 GATE: FAILED ==="
  exit 1
fi
