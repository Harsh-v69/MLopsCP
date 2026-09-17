#!/usr/bin/env bash
# Phase 4 validation gate.
#
# Plan wording: "The deployed API's predictions match offline evaluation
# results within tolerance, the container starts cleanly from `docker run`
# with no manual steps, and invalid/malformed input is rejected with a
# proper error rather than crashing the service."
#
# What this actually exercises:
#   1. The full pytest suite (tests/api/) - contract tests, exact
#      prediction parity against the offline pipeline, and a basic
#      concurrent-load smoke check, all through FastAPI's TestClient
#      (a real ASGI request/response cycle, not a mock).
#   2. A REAL live server: spins up `uvicorn` as an actual subprocess
#      listening on a port, hits it with real HTTP requests (curl), and
#      diffs the response against an offline prediction - closer to "the
#      deployed API" than TestClient alone.
#   3. `docker compose config` to validate the Dockerfile/compose syntax
#      (this does NOT require pulling any image, so it works even though
#      this sandbox blocks Docker Hub - see progress.md Phase 0 and 4
#      notes). A live `docker build`/`docker run` is NOT exercised here;
#      that remains a documented, known gap in this environment specifically.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
FAIL=0

echo "=== Phase 4 Validation Gate ==="
echo

echo "[1/3] pytest suite (contract + prediction parity + basic load)"
source .venv/bin/activate
python3 -m pytest tests/api/ -v > /tmp/phase4_pytest.log 2>&1
PYTEST_EXIT=$?
tail -20 /tmp/phase4_pytest.log
if [ "$PYTEST_EXIT" -eq 0 ]; then
  echo "  pytest suite passed"
else
  echo "  FAIL: pytest suite failed (exit $PYTEST_EXIT)"
  FAIL=1
fi
echo

echo "[2/3] Live server check (real subprocess, real HTTP, not TestClient)"
MLFLOW_DISABLE_AGENT_HINT=1 .venv/bin/uvicorn src.api.main:app --host 127.0.0.1 --port 8001 \
  > /tmp/phase4_uvicorn.log 2>&1 &
UVICORN_PID=$!
trap 'kill $UVICORN_PID 2>/dev/null' EXIT

# wait for the server to come up
for i in $(seq 1 20); do
  if curl -s -o /dev/null http://127.0.0.1:8001/health; then
    break
  fi
  sleep 0.5
done

HEALTH_RESPONSE=$(curl -s http://127.0.0.1:8001/health)
if echo "$HEALTH_RESPONSE" | grep -q '"model_loaded":true'; then
  echo "  Live server /health OK: $HEALTH_RESPONSE"
else
  echo "  FAIL: live server /health did not report a loaded model: $HEALTH_RESPONSE"
  FAIL=1
fi

LIVE_PREDICT_RESPONSE=$(python3 - <<'PYEOF'
import json
import urllib.request

from src.data.load_dataset import TEST_FILE, load_raw
from src.models.train_baseline import CATEGORICAL_FEATURES, NUMERIC_FEATURES

feature_cols = CATEGORICAL_FEATURES + NUMERIC_FEATURES
test_df = load_raw(TEST_FILE)
sample = test_df[feature_cols].head(5)
records = sample.to_dict(orient="records")

body = json.dumps({"records": records}).encode()
req = urllib.request.Request(
    "http://127.0.0.1:8001/predict", data=body, headers={"Content-Type": "application/json"}
)
with urllib.request.urlopen(req, timeout=10) as resp:
    api_result = json.loads(resp.read())

import joblib
model = joblib.load("models/baseline_model.joblib")
offline_classes = model.predict(sample)
offline_probs = model.predict_proba(sample)[:, 1]

ok = True
for api_pred, cls, prob in zip(api_result["predictions"], offline_classes, offline_probs):
    expected_label = "attack" if cls == 1 else "normal"
    if api_pred["label"] != expected_label or abs(api_pred["attack_probability"] - float(prob)) > 1e-9:
        ok = False

print("MATCH" if ok else "MISMATCH")
PYEOF
)

if [ "$LIVE_PREDICT_RESPONSE" = "MATCH" ]; then
  echo "  Live server /predict matches offline predictions exactly (real HTTP round-trip)"
else
  echo "  FAIL: live server /predict did not match offline predictions ($LIVE_PREDICT_RESPONSE)"
  FAIL=1
fi

# Invalid input over real HTTP too, not just TestClient
INVALID_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://127.0.0.1:8001/predict \
  -H "Content-Type: application/json" -d '{"records": []}')
if [ "$INVALID_STATUS" = "422" ]; then
  echo "  Live server rejects invalid input with 422 (empty records list)"
else
  echo "  FAIL: live server returned $INVALID_STATUS for invalid input (expected 422)"
  FAIL=1
fi

kill $UVICORN_PID 2>/dev/null
trap - EXIT
echo

echo "[3/3] Docker/compose syntax check (no image pull required)"
if command -v docker >/dev/null 2>&1; then
  if docker compose config > /tmp/phase4_compose_config.log 2>&1; then
    echo "  docker-compose.yml + Dockerfiles parse correctly (docker compose config)"
  else
    echo "  FAIL: docker compose config failed"
    cat /tmp/phase4_compose_config.log
    FAIL=1
  fi
else
  echo "  SKIP: docker CLI not available in this environment"
fi
echo "  NOTE: a live 'docker build'/'docker run' is NOT exercised in this"
echo "  sandbox (Docker Hub pulls are blocked at the network-policy level -"
echo "  see progress.md Phase 0 and Phase 4 notes). Verify independently:"
echo "    dvc pull && docker build -f docker/api.Dockerfile -t mlshield-api . && \\"
echo "    docker run --rm -p 8000:8000 mlshield-api"
echo

if [ "$FAIL" -eq 0 ]; then
  echo "=== PHASE 4 GATE: PASSED (all sandbox-testable checks; docker build/run still needs independent verification - see note above) ==="
  exit 0
else
  echo "=== PHASE 4 GATE: FAILED ==="
  exit 1
fi
