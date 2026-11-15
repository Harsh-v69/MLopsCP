"""Phase 4 — FastAPI inference service.

Serves the Phase 1/2 baseline model (models/baseline_model.joblib, the
DVC-tracked artifact) behind /health and /predict. Contract locked in
docs/phase4_api_spec.md before this file was written.

Phase 9 adds the transparency layer endpoints (/predict/explain,
/model-card, /security-gate, /audit-log) plus a dev-only token issuance
endpoint for the dashboard - see docs/phase9_transparency_spec.md.
"""
import os
import sys
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import joblib
import pandas as pd
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.api.hardening import add_hardening, app_env, cors_origins
from src.api.schemas import HealthResponse, PredictRequest, PredictResponse, Prediction
from src.explainability.shap_explainer import explain_records
from src.governance.audit_log import DEFAULT_LOG_PATH, AuditLog
from src.governance.auth import ROLES, authorize, issue_token
from src.models.train_baseline import CATEGORICAL_FEATURES, NUMERIC_FEATURES
from src.security.dependency_scan import run_pip_audit_cached
from src.security.gate import REQUIREMENTS_PATH, run_gate
from src.transparency.model_card import generate_model_card

REPO_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = REPO_ROOT / "models" / "baseline_model.joblib"
FEATURE_COLUMNS = CATEGORICAL_FEATURES + NUMERIC_FEATURES  # same order used at training time

@asynccontextmanager
async def lifespan(_app):
    # Warm the dependency-scan cache in the background so the dashboard's
    # first load doesn't wait minutes for pip-audit. Errors are ignored here;
    # a failed scan surfaces (fail-closed) on the first real gate call.
    def warm():
        try:
            run_pip_audit_cached(REQUIREMENTS_PATH)
        except Exception:
            pass

    threading.Thread(target=warm, daemon=True).start()
    yield


ENV = app_env()  # raises on a bad value or on production with dev auth set
# API docs are served only in dev (the docs page loads scripts from a CDN, which
# the production Content-Security-Policy blocks anyway).
_docs = {} if ENV == "dev" else {"docs_url": None, "redoc_url": None, "openapi_url": None}
app = FastAPI(title="MLShield Inference API", version="0.1.0", lifespan=lifespan, **_docs)

# Origins come from MLSHIELD_CORS_ORIGINS; in dev only, the Vite dev server is allowed by default.
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins(ENV),
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Correlation-ID"],
)
add_hardening(app, ENV)

def requires(action: str):
    """Route dependency: 401 without a Bearer header, 403 unless the token's role
    is permitted `action` (permission matrix in src/governance/auth.py)."""
    def check(authorization: Optional[str] = Header(default=None)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing or malformed Authorization header")
        result = authorize(authorization.removeprefix("Bearer ").strip(), action)
        if not result.allowed:
            raise HTTPException(status_code=403, detail=result.reason)
        return result
    return check


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


# Files the gate and model card read at request time. Readiness reports them
# missing instead of letting the first real request fail.
_READY_FILES = [
    MODEL_PATH,
    REPO_ROOT / "models" / "baseline_model.joblib.sig",
    REPO_ROOT / "security" / "signing_public_key.pem",
    REPO_ROOT / "data" / "processed" / "phase5_poisoning_eval.json",
    REPO_ROOT / "data" / "processed" / "phase6_adversarial_eval.json",
    REPO_ROOT / "requirements.txt",
]


@app.get("/health/live")
def health_live() -> dict:
    """Process is up. Deliberately checks nothing else, so an orchestrator never
    restarts a healthy process because a dependency is slow."""
    return {"status": "alive"}


@app.get("/health/ready")
def health_ready():
    """Can this instance do its job: required files present and the audit log
    directory writable. Does NOT run the (slow) dependency scan."""
    problems = [f"missing: {p.name}" for p in _READY_FILES if not p.exists()]
    if not os.access(DEFAULT_LOG_PATH.parent, os.W_OK):
        problems.append("audit log directory is not writable")
    if problems:
        return JSONResponse(status_code=503, content={"status": "not ready", "problems": problems})
    return {"status": "ready"}


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", model_loaded=_model is not None, model_source=str(MODEL_PATH))


@app.post("/predict", response_model=PredictResponse, dependencies=[Depends(requires("run_prediction"))])
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


@app.post("/predict/explain", dependencies=[Depends(requires("run_prediction"))])
def predict_explain(request: PredictRequest) -> dict:
    """SHAP explanation per record - same request schema as /predict
    (docs/phase4_api_spec.md), inherits its validation exactly. See
    docs/phase9_transparency_spec.md Part A."""
    rows = [record.model_dump() for record in request.records]
    return {"explanations": explain_records(rows)}


@app.get("/model-card", dependencies=[Depends(requires("view_model_metrics"))])
def model_card() -> dict:
    """Regenerated fresh on every call from real pipeline artifacts - see
    docs/phase9_transparency_spec.md Part B for the exact source of every
    field."""
    return generate_model_card()


@app.get("/security-gate", dependencies=[Depends(requires("view_security_gate_result"))])
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


if ENV == "dev":  # not registered at all in production, so the route returns 404
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


@app.get("/audit-log", dependencies=[Depends(requires("view_audit_log"))])
def audit_log() -> dict:
    """RBAC-gated per docs/phase8_governance_spec.md's permission matrix
    (view_audit_log: SECURITY_REVIEWER, APPROVER only). Returns a real
    403, not a filtered/empty response, for an unauthorized role."""
    log = AuditLog()
    chain = log.verify_chain()
    return {
        "entries": log.entries(),
        "chain_valid": chain.valid,
        "n_entries": chain.n_entries,
    }
