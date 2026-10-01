# MLShield Dashboard

Phase 9's transparency layer — a React + Vite app that fetches live data
from the FastAPI backend (`src/api/main.py`). No mock data, no
client-side recomputation of anything the backend already computed.
Contract and pages locked in `docs/phase9_transparency_spec.md`.

## Pages

- **Overview** — the live Security Gate decision and sub-scores
  (`GET /security-gate`).
- **Audit Trail** — the hash-chained audit log (`GET /audit-log`),
  RBAC-gated per `docs/phase8_governance_spec.md`. Dev-only sign-in issues
  a real JWT for a chosen role (`POST /auth/dev-token`) — there's no real
  identity provider in this MVP; an unauthorized role gets a real `403`.
- **Model Card** — auto-generated from real pipeline artifacts
  (`GET /model-card`).
- **Explain** — SHAP explanation for a prediction (`POST /predict/explain`).

## Run it

Backend first (from the repo root):
```
source .venv/bin/activate
uvicorn src.api.main:app --reload
```

Then, from this directory:
```
npm install
npm run dev
```

## Test

```
npm test
```
