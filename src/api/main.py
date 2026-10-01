"""Phase 4 — FastAPI inference service.

Serves the Phase 1/2 baseline model (models/baseline_model.joblib, the
DVC-tracked artifact) behind /health and /predict. Contract locked in
docs/phase4_api_spec.md before this file was written.

Phase 9 adds the transparency layer endpoints (/predict/explain,
/model-card, /security-gate, /audit-log) plus a dev-only token issuance
endpoint for the dashboard - see docs/phase9_transparency_spec.md.
"""
import sys
from pathlib import Path
from typing import Optional

import joblib
import pandas as pd
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from src.api.schemas import HealthResponse, PredictRequest, PredictResponse, Prediction
from src.explainability.shap_explainer import explain_records
from src.governance.audit_log import AuditLog
from src.governance.auth import ROLES, authorize, issue_token
from src.models.train_baseline import CATEGORICAL_FEATURES, NUMERIC_FEATURES
from src.security.gate import run_gate
from src.transparency.model_card import generate_model_card

REPO_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = REPO_ROOT / "models" / "baseline_model.joblib"
FEATURE_COLUMNS = CATEGORICAL_FEATURES + NUMERIC_FEATURES  # same order used at training time

app = FastAPI(title="MLShield Inference API", version="0.1.0")

# Dev-only: lets the dashboard (a different origin under Vite) call this
# API during local development. Not a production CORS policy.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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


@app.post("/predict/explain")
def predict_explain(request: PredictRequest) -> dict:
    """SHAP explanation per record - same request schema as /predict
    (docs/phase4_api_spec.md), inherits its validation exactly. See
    docs/phase9_transparency_spec.md Part A."""
    rows = [record.model_dump() for record in request.records]
    return {"explanations": explain_records(rows)}


@app.get("/model-card")
def model_card() -> dict:
    """Regenerated fresh on every call from real pipeline artifacts - see
    docs/phase9_transparency_spec.md Part B for the exact source of every
    field."""
    return generate_model_card()


@app.get("/security-gate")
def security_gate() -> dict:
    """The live Phase 7 gate result - what the dashboard's Overview page
    reads, so 'the dashboard matches the backend' (Phase 9 gate) is
    checking exactly this response."""
    result = run_gate()
    return {
        "decision": result.decision,
        "security_score": result.security_score,
        "data_score": result.data_score,
        "model_score": result.model_score,
        "dependency_score": result.dependency_score,
        "integrity_component": result.integrity_component,
        "details": result.details,
    }


@app.post("/auth/dev-token")
def dev_token(subject: str, role: str) -> dict:
    """DEV-ONLY stand-in for a real login flow - there is no identity
    provider in this MVP (same honest treatment as every other local-auth
    stand-in in this project; see docs/phase8_governance_spec.md and
    docs/phase9_transparency_spec.md Part C). Issues a real, correctly
    scoped JWT for the requested role so the dashboard can demonstrate the
    RBAC-gated audit log without a real IdP."""
    if role not in ROLES:
        raise HTTPException(status_code=400, detail=f"unknown role: {role!r} (must be one of {sorted(ROLES)})")
    return {"token": issue_token(subject, role)}


@app.get("/audit-log")
def audit_log(authorization: Optional[str] = Header(default=None)) -> dict:
    """RBAC-gated per docs/phase8_governance_spec.md's permission matrix
    (view_audit_log: SECURITY_REVIEWER, APPROVER only). Returns a real
    403, not a filtered/empty response, for an unauthorized role."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing or malformed Authorization header")

    token = authorization.removeprefix("Bearer ").strip()
    auth_result = authorize(token, "view_audit_log")
    if not auth_result.allowed:
        raise HTTPException(status_code=403, detail=auth_result.reason)

    log = AuditLog()
    chain = log.verify_chain()
    return {
        "entries": log.entries(),
        "chain_valid": chain.valid,
        "n_entries": chain.n_entries,
    }
