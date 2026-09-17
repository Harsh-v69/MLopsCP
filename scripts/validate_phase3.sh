#!/usr/bin/env bash
# Phase 3 validation gate.
#
# Plan wording: "The DAG completes unattended from a cold start and
# produces a registered model identical to Phase 2's manual run. A
# deliberately-broken run correctly halts the pipeline rather than
# registering a bad model."
#
# Two runs, both via `airflow dags test` (a real, unattended, cold-start
# DAG execution - not just re-running the Python scripts directly):
#   1. Normal run: ingest -> validate -> train -> evaluate -> register all
#      succeed; KDDTest+ F1 matches the locked >=0.75 bar; a NEW model
#      version is registered in MLflow.
#   2. Corrupted run: ingest is pointed (via dag_run.conf) at a genuinely
#      malformed fixture file (tests/fixtures/corrupted_train_sample.txt -
#      wrong column count on one line, an unknown protocol_type on
#      another). validate must fail, and train/evaluate/register must
#      never run - checked by both the DAG's overall failure and the
#      model registry's version count staying unchanged.
set -uo pipefail  # not -e: we expect the second `airflow dags test` to fail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
FAIL=0

export AIRFLOW_HOME="$REPO_ROOT/airflow_home"
export AIRFLOW__CORE__DAGS_FOLDER="$REPO_ROOT/airflow/dags"
export AIRFLOW__CORE__LOAD_EXAMPLES=False

AIRFLOW_PY="$REPO_ROOT/.venv-airflow/bin/python"
ML_PY="$REPO_ROOT/.venv/bin/python"
AIRFLOW_BIN="$REPO_ROOT/.venv-airflow/bin/airflow"

registry_version_count() {
  MLFLOW_DISABLE_AGENT_HINT=1 "$ML_PY" -c "
import mlflow
mlflow.set_tracking_uri('sqlite:///$REPO_ROOT/mlflow.db')
client = mlflow.MlflowClient()
try:
    versions = client.search_model_versions(\"name='mlshield-baseline-rf'\")
    print(len(versions))
except mlflow.exceptions.MlflowException:
    print(0)
"
}

echo "=== Phase 3 Validation Gate ==="
echo

echo "[1/3] Cold-start normal run"
BEFORE_COUNT=$(registry_version_count)
"$AIRFLOW_BIN" dags test mlshield_baseline "2027-01-01" > /tmp/phase3_gate_normal.log 2>&1
NORMAL_EXIT=$?
AFTER_COUNT=$(registry_version_count)

if [ "$NORMAL_EXIT" -eq 0 ]; then
  echo "  DAG run succeeded (exit 0)"
else
  echo "  FAIL: normal DAG run exited $NORMAL_EXIT (expected 0)"
  tail -30 /tmp/phase3_gate_normal.log
  FAIL=1
fi

if grep -q "task_id=register.*Marking task as SUCCESS\|Marking task as SUCCESS.*task_id=register" /tmp/phase3_gate_normal.log; then
  echo "  register task succeeded"
else
  echo "  FAIL: register task did not report success"
  FAIL=1
fi

if [ "$AFTER_COUNT" -gt "$BEFORE_COUNT" ]; then
  echo "  Model registry gained a new version ($BEFORE_COUNT -> $AFTER_COUNT)"
else
  echo "  FAIL: model registry version count did not increase ($BEFORE_COUNT -> $AFTER_COUNT)"
  FAIL=1
fi

F1_VALUE=$(grep -o "KDDTest+ F1=[0-9.]*" /tmp/phase3_gate_normal.log | tail -1 | grep -o "[0-9.]*$")
if [ -n "$F1_VALUE" ] && python3 -c "import sys; sys.exit(0 if float('$F1_VALUE') >= 0.75 else 1)"; then
  echo "  KDDTest+ F1=$F1_VALUE (meets >=0.75 bar, matches Phase 1/2's locked threshold)"
else
  echo "  FAIL: could not confirm KDDTest+ F1 >= 0.75 in the run log (got '$F1_VALUE')"
  FAIL=1
fi
echo

echo "[2/3] Deliberately-broken run (corrupted training data)"
CORRUPT_FILE="$REPO_ROOT/tests/fixtures/corrupted_train_sample.txt"
if [ ! -f "$CORRUPT_FILE" ]; then
  echo "  FAIL: corrupted fixture missing at $CORRUPT_FILE"
  FAIL=1
else
  BEFORE_COUNT_2=$(registry_version_count)
  "$AIRFLOW_BIN" dags test mlshield_baseline "2027-01-02" \
    --conf "{\"train_source_override\": \"$CORRUPT_FILE\"}" \
    > /tmp/phase3_gate_corrupt.log 2>&1
  CORRUPT_EXIT=$?
  AFTER_COUNT_2=$(registry_version_count)

  if [ "$CORRUPT_EXIT" -ne 0 ]; then
    echo "  DAG run failed as expected (exit $CORRUPT_EXIT)"
  else
    echo "  FAIL: corrupted-input DAG run exited 0 (expected non-zero)"
    FAIL=1
  fi

  if grep -q "task_id=validate.*Marking task as FAILED\|Marking task as FAILED.*task_id=validate" /tmp/phase3_gate_corrupt.log; then
    echo "  validate task failed, as expected"
  else
    echo "  FAIL: validate task did not report failure"
    FAIL=1
  fi

  if grep -q "starting task_id=train\|starting task_id=evaluate\|starting task_id=register" /tmp/phase3_gate_corrupt.log; then
    echo "  FAIL: a downstream task (train/evaluate/register) started after validate failed"
    FAIL=1
  else
    echo "  No downstream task (train/evaluate/register) ever started"
  fi

  if [ "$AFTER_COUNT_2" -eq "$BEFORE_COUNT_2" ]; then
    echo "  Model registry version count unchanged ($BEFORE_COUNT_2) - no bad model registered"
  else
    echo "  FAIL: model registry version count changed ($BEFORE_COUNT_2 -> $AFTER_COUNT_2) on a broken run"
    FAIL=1
  fi
fi
echo

echo "[3/3] Repo scaffolding"
for f in airflow/dags/mlshield_baseline_dag.py src/pipeline/ingest.py src/pipeline/validate.py \
         src/pipeline/train.py src/pipeline/evaluate.py src/pipeline/register.py; do
  if [ -f "$f" ]; then
    echo "  $f present"
  else
    echo "  FAIL: $f missing"
    FAIL=1
  fi
done
echo

if [ "$FAIL" -eq 0 ]; then
  echo "=== PHASE 3 GATE: PASSED ==="
  exit 0
else
  echo "=== PHASE 3 GATE: FAILED ==="
  exit 1
fi
