#!/usr/bin/env bash
# Phase 1 validation gate — see docs/phase1_baseline_spec.md for the locked
# bar and reasoning. All three checks must pass:
#   1. F1 on KDDTest+.txt >= 0.75
#   2. Two independent training runs produce bit-identical metrics
#   3. 5-fold CV F1 standard deviation < 0.05
set -euo pipefail
cd "$(dirname "$0")/.."

FAIL=0
MIN_F1=0.75
MAX_CV_STD=0.05

echo "=== Phase 1 Validation Gate ==="
echo

echo "[1/3] Training run 1"
python3 -m src.models.train_baseline
cp data/processed/phase1_metrics.json /tmp/phase1_gate_run1.json
echo

echo "[2/3] Training run 2 (reproducibility check)"
python3 -m src.models.train_baseline
if diff -q /tmp/phase1_gate_run1.json data/processed/phase1_metrics.json > /dev/null; then
  echo "  Two runs produced bit-identical metrics"
else
  echo "  FAIL: metrics differ between identical-seed runs — a step is unseeded"
  FAIL=1
fi
echo

echo "[3/3] Threshold checks"
if python3 - <<PYEOF
import json, sys

with open("data/processed/phase1_metrics.json") as f:
    m = json.load(f)

fail = False

test_f1 = m["kddtest_plus_metrics"]["f1"]
if test_f1 >= $MIN_F1:
    print(f"  KDDTest+ F1 = {test_f1:.4f} >= $MIN_F1 (PASS)")
else:
    print(f"  FAIL: KDDTest+ F1 = {test_f1:.4f} < $MIN_F1")
    fail = True

cv_std = m["cv_f1_std"]
if cv_std < $MAX_CV_STD:
    print(f"  CV F1 std = {cv_std:.4f} < $MAX_CV_STD (PASS)")
else:
    print(f"  FAIL: CV F1 std = {cv_std:.4f} >= $MAX_CV_STD (unstable baseline)")
    fail = True

sys.exit(1 if fail else 0)
PYEOF
then
  :
else
  FAIL=1
fi
echo

if [ "$FAIL" -eq 0 ]; then
  echo "=== PHASE 1 GATE: PASSED ==="
  exit 0
else
  echo "=== PHASE 1 GATE: FAILED ==="
  exit 1
fi
