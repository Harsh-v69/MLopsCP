"""Phase 4 — FastAPI inference service.

Serves the Phase 1/2 baseline model (models/baseline_model.joblib, the
DVC-tracked artifact) behind /health and /predict. Contract locked in
docs/phase4_api_spec.md before this file was written.
"""
import sys
from pathlib import Path

import joblib
import pandas as pd
from fastapi import FastAPI

from src.api.schemas import HealthResponse, PredictRequest, PredictResponse, Prediction
from src.models.train_baseline import CATEGORICAL_FEATURES, NUMERIC_FEATURES

REPO_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = REPO_ROOT / "models" / "baseline_model.joblib"
FEATURE_COLUMNS = CATEGORICAL_FEATURES + NUMERIC_FEATURES  # same order used at training time

app = FastAPI(title="MLShield Inference API", version="0.1.0")

# Loaded once at process startup, not per-request. Fail fast, on purpose
# (see docs/phase4_api_spec.md "Startup behavior") - a process that comes
# up without a model is worse than one that never starts.
try:
    _model = joblib.load(MODEL_PATH)
except FileNotFoundError:
    print(
        f"FATAL: model artifact not found at {MODEL_PATH}. "
        f"Run `dvc pull` (see progress.md Phase 2) before starting the API.",
        file=sys.stderr,
    )
    raise


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", model_loaded=_model is not None, model_source=str(MODEL_PATH))


@app.post("/predict", response_model=PredictResponse)
def predict(request: PredictRequest) -> PredictResponse:
    rows = [record.model_dump() for record in request.records]
    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)

    attack_probabilities = _model.predict_proba(df)[:, 1]
    predicted_classes = _model.predict(df)

    predictions = [
        Prediction(
            label="attack" if cls == 1 else "normal",
            attack_probability=float(prob),
        )
        for cls, prob in zip(predicted_classes, attack_probabilities)
    ]
    return PredictResponse(predictions=predictions)
