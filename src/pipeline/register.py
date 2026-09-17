"""Phase 3 pipeline step 5/5 — register.

Only reached if `evaluate` (step 4/5) exited 0. Registers the model logged
by `train` (step 3/5) as a new version of the MLflow model registry entry
`mlshield-baseline-rf` — the same registered-model name Phase 2 used
manually, so this is the automated equivalent of that manual step, not a
parallel, disconnected one.
"""
import json
import sys
from pathlib import Path

import mlflow

from src.models.train_baseline import MLFLOW_REGISTERED_MODEL_NAME, MLFLOW_TRACKING_URI

REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_INFO_IN = REPO_ROOT / "data" / "processed" / "phase3_run_info.json"


def main() -> int:
    if not RUN_INFO_IN.exists():
        print(f"REGISTER FAIL: run info file not found: {RUN_INFO_IN}", file=sys.stderr)
        return 1

    with open(RUN_INFO_IN) as f:
        run_info = json.load(f)

    mlflow.set_tracking_uri(MLFLOW_TRACKING_URI)
    model_uri = f"runs:/{run_info['run_id']}/{run_info['model_artifact_path']}"
    result = mlflow.register_model(model_uri, MLFLOW_REGISTERED_MODEL_NAME)

    print(f"REGISTER OK: {MLFLOW_REGISTERED_MODEL_NAME} version {result.version} "
          f"(run_id={run_info['run_id']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
