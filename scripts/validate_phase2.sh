#!/usr/bin/env bash
# Phase 2 validation gate.
#
# Plan wording: "A teammate (or you, on a second machine) can clone the
# repo, dvc pull, and reproduce the exact registered model artifact from
# Phase 1 - same hash, same metrics - using only what's in DVC + MLflow."
#
# What this proves, in a genuinely fresh git clone (not just this working
# directory):
#   1. `dvc pull` retrieves the raw dataset and it matches Phase 0's locked
#      hashes exactly (data round-trips through DVC unchanged).
#   2. `dvc pull` retrieves the trained model artifact and its hash matches
#      the hash recorded in the committed .dvc pointer file exactly (the
#      model round-trips through DVC unchanged).
#   3. Loading that pulled model (NO retraining) and evaluating it on
#      KDDTest+.txt reproduces the exact same metrics committed in
#      data/processed/phase1_metrics.json - i.e. the artifact DVC handed
#      back really is the Phase 1 model, not a stand-in.
#   4. MLflow logging mechanics work: a run started against a fresh local
#      tracking store logs the same params/metrics and is queryable back
#      via the MLflow client API.
#
# Note on scope: this sandbox has no shared/cloud MLflow tracking server,
# so the local sqlite tracking store is NOT itself version-controlled (see
# progress.md Phase 2 notes) - each clone gets its own fresh store, which
# is why step 4 re-logs rather than reading a pre-existing remote run. The
# durable, hash-verifiable record of "what Phase 1 produced" is the DVC
# artifact + the committed metrics.json, which steps 1-3 check directly.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
FAIL=0

echo "=== Phase 2 Validation Gate ==="
echo

CLONE_DIR=$(mktemp -d)
trap 'rm -rf "$CLONE_DIR"' EXIT

echo "[1/4] Fresh clone + dvc pull"
git clone -q "$REPO_ROOT" "$CLONE_DIR/repo"
cd "$CLONE_DIR/repo"
dvc pull -q
echo "  Cloned to $CLONE_DIR/repo and ran dvc pull"
echo

echo "[2/4] Raw dataset hash check (must match Phase 0 locked hashes)"
EXPECTED_TRAIN="1b86d2f957b33082081bba410fe129b475efebcc13c9014c3f447c8271aadf95"
EXPECTED_TEST="fa46b0935342616aa83b7c2578db355b6a7aaabbc492248172c7a1e8b7ab8f84"
ACTUAL_TRAIN=$(sha256sum data/raw/KDDTrain+.txt | awk '{print $1}')
ACTUAL_TEST=$(sha256sum data/raw/KDDTest+.txt | awk '{print $1}')

if [ "$ACTUAL_TRAIN" = "$EXPECTED_TRAIN" ]; then
  echo "  KDDTrain+.txt hash OK (via dvc pull)"
else
  echo "  FAIL: KDDTrain+.txt hash mismatch after dvc pull"
  FAIL=1
fi
if [ "$ACTUAL_TEST" = "$EXPECTED_TEST" ]; then
  echo "  KDDTest+.txt hash OK (via dvc pull)"
else
  echo "  FAIL: KDDTest+.txt hash mismatch after dvc pull"
  FAIL=1
fi
echo

echo "[3/4] Model artifact hash check + no-retrain metric reproduction"
EXPECTED_MODEL_MD5=$(grep "md5:" models/baseline_model.joblib.dvc | awk '{print $3}')
ACTUAL_MODEL_MD5=$(md5sum models/baseline_model.joblib | awk '{print $1}')

if [ "$ACTUAL_MODEL_MD5" = "$EXPECTED_MODEL_MD5" ]; then
  echo "  Model artifact md5 matches committed .dvc pointer ($ACTUAL_MODEL_MD5)"
else
  echo "  FAIL: model artifact md5 mismatch after dvc pull"
  FAIL=1
fi

if python3 - <<'PYEOF'
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))
import joblib
from src.data.load_dataset import TEST_FILE, load_raw
from src.models.train_baseline import (
    CATEGORICAL_FEATURES,
    NUMERIC_FEATURES,
    evaluate,
    to_binary_label,
)

with open("data/processed/phase1_metrics.json") as f:
    expected = json.load(f)["kddtest_plus_metrics"]

pipeline = joblib.load("models/baseline_model.joblib")  # no retraining
test_df = load_raw(TEST_FILE)
feature_cols = CATEGORICAL_FEATURES + NUMERIC_FEATURES
X_test = test_df[feature_cols]
y_test = to_binary_label(test_df["label"])

actual = evaluate(pipeline, X_test, y_test)

if actual == expected:
    print(f"  Reproduced KDDTest+ metrics from the DVC-pulled artifact exactly: F1={actual['f1']:.4f}")
    sys.exit(0)
else:
    print(f"  FAIL: metrics from pulled artifact differ from committed phase1_metrics.json")
    print(f"        expected={expected}")
    print(f"        actual=  {actual}")
    sys.exit(1)
PYEOF
then
  :
else
  FAIL=1
fi
echo

echo "[4/4] MLflow logging mechanics (fresh local tracking store in the clone)"
if MLFLOW_DISABLE_AGENT_HINT=1 python3 -m src.models.train_baseline > /tmp/phase2_mlflow_train.log 2>&1; then
  RUN_ID=$(grep "MLflow run id:" /tmp/phase2_mlflow_train.log | awk '{print $NF}')
  python3 - <<PYEOF
import mlflow
mlflow.set_tracking_uri("sqlite:///$(pwd)/mlflow.db")
run = mlflow.get_run("$RUN_ID")
assert run.data.params["model_type"] == "RandomForestClassifier"
assert "kddtest_f1" in run.data.metrics
print(f"  MLflow run {run.info.run_id[:12]}... queried back successfully, params/metrics present")
PYEOF
else
  echo "  FAIL: training run with MLflow logging failed in clone"
  cat /tmp/phase2_mlflow_train.log
  FAIL=1
fi
echo

cd "$REPO_ROOT"

if [ "$FAIL" -eq 0 ]; then
  echo "=== PHASE 2 GATE: PASSED ==="
  exit 0
else
  echo "=== PHASE 2 GATE: FAILED ==="
  exit 1
fi
