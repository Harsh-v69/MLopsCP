# Phase 9 — Transparency Layer Spec (Dashboard, Model Cards, SHAP)

Locked before code, same practice as every prior phase. This phase is
what makes the SDG 16 "transparent reasoning" claim real: every release
ships with an explanation a non-engineer reviewer could read (Model Card
+ SHAP), and the dashboard shows exactly what the backend knows — never a
rounder, friendlier, or stale version of it.

## Part A — SHAP explanations

### Method

**`shap.TreeExplainer`** against the RandomForest (`pipeline.named_steps["model"]`)
directly on its preprocessed input space (one-hot categorical + numeric
passthrough, 121 dimensions — same space Phase 6's adversarial test
already operates in). `TreeExplainer` computes **exact** Shapley values
for tree ensembles (no sampling approximation needed, unlike the
model-agnostic `KernelExplainer`) — the right choice given the model is
already a `RandomForestClassifier`, not a black box.

- `explainer.shap_values(X)` returns an array of shape
  `(n_samples, 121, 2)` in this SHAP version (0.51.0) — per-feature,
  per-class contributions. We report the **attack-class slice**
  (`[:, :, 1]`), matching the API's existing `attack_probability` framing
  (Phase 4) — a positive SHAP value pushes the prediction toward
  "attack", negative pushes toward "normal".
- Feature names for the 121 dimensions: the fitted
  `OneHotEncoder.get_feature_names_out()` (83 one-hot dims) followed by
  `NUMERIC_FEATURES` in order (38 dims) — identical ordering logic
  already used in Phase 6's `_build_perturbation_mask`.
- Response returns the **top 10 contributing features by |SHAP value|**,
  not all 121 — a human-readable explanation, not a raw dump. Each entry:
  `{feature, value, shap_value}` (the feature's actual input value is
  included, not just its name/contribution — "why" needs "what" next to
  it).
- `expected_value[1]` (the attack-class base rate from training) is
  returned alongside, so the explanation reads as
  "`base_rate + sum(contributions) ≈ predicted probability`" — a
  checkable equation, not just a ranked list.

### New endpoint

`POST /predict/explain` — same request schema as `/predict`
(`docs/phase4_api_spec.md`), batch of records. Response per record:
```json
{
  "label": "attack", "attack_probability": 0.94,
  "base_rate": 0.4653,
  "top_contributing_features": [
    {"feature": "dst_host_srv_count", "value": 1.0, "shap_value": 0.18},
    ...
  ]
}
```
No new validation rules — inherits `/predict`'s existing schema and error
behavior exactly (same Pydantic model).

## Part B — Model Card

### Principle: generated, not authored

Every field is pulled programmatically from real pipeline artifacts
already on disk — never hand-typed prose a human could get out of sync
with reality. This is also what makes the field testable: the Phase 9
gate requires checking a generated card's fields against the actual data
it claims to summarize (project plan, Phase 9 Test).

### Fields and their exact source

| Section | Field | Source |
|---|---|---|
| Identity | `model_name`, `model_version` | `models/baseline_model.joblib.dvc`'s md5 (first 12 chars, as a stable version id) |
| Intended use | framing, out-of-scope note | static text from `docs/phase1_baseline_spec.md` (binary normal/attack framing) — the one hand-authored section, quoting the locked spec rather than restating it loosely |
| Training data | dataset, size, split hash | `data/raw/README.md` + `data/processed/expected_split_hash.txt` |
| Performance | accuracy/precision/recall/F1 (validation + KDDTest+) | `data/processed/phase1_metrics.json` |
| Security — data scan | recall, FPR, pass/fail vs. bar | `data/processed/phase5_poisoning_eval.json` |
| Security — model integrity | signature verification result | **live**, `src/security/verify_model.verify()` |
| Security — adversarial robustness | clean/adversarial accuracy, degradation | `data/processed/phase6_adversarial_eval.json` |
| Security — dependency scan | vulnerability count | **live**, `src/security/dependency_scan.run_pip_audit()` |
| Security Gate decision | composite score, sub-scores, decision | **live**, `src/security/gate.run_gate()` (Phase 7) |
| Governance | audit log entry count, chain validity | **live**, `src/governance/audit_log.AuditLog` |
| Generated | `generated_at` timestamp | wall clock at generation time |

Any field whose source file is missing is rendered as
`"status": "not available"`, never a guessed/omitted value — a Model
Card with a silently missing section is worse than one that says so.

### New endpoint

`GET /model-card` — regenerates and returns the card fresh on every call
(cheap — same live calls `run_gate()` already makes, no new cost). JSON,
not markdown, for the API response — the dashboard renders it; a
markdown export is a presentation detail layered on top (see Part C),
not the source of truth.

## Part C — Dashboard

### Stack

**React + Vite** (`dashboard/`), not Next.js — the project plan names
"React or Next.js" as an either/or (tech stack §9), and this is a
client-rendered app calling a REST API with no server-rendering need, so
Vite's lighter build/dev toolchain is the better fit without giving up
anything the plan asked for.

### Pages

1. **Overview** — live Security Gate result (decision pill, 3 sub-score
   bars, composite score — visually similar to the progress-demo artifact
   from earlier, but **live-fetched from the backend**, not a static
   snapshot).
2. **Audit Trail** — calls `GET /audit-log`, which (new, Phase 8-gated)
   requires a valid `Authorization: Bearer <token>` header with
   `SECURITY_REVIEWER` or `APPROVER` role (`view_audit_log` permission,
   locked in `docs/phase8_governance_spec.md`). The dashboard has a
   simple role-selector + "sign in" that calls a **dev-only**
   `POST /auth/dev-token` endpoint (issues a token for a chosen
   role/subject — explicitly documented as a stand-in for a real login
   flow, since there's no real identity provider in this MVP, same
   honest treatment as every other local-auth stand-in in this project).
   An unauthorized role sees a real `403` and a real "not authorized"
   state, not a hidden tab.
3. **Model Card** — calls `GET /model-card`, renders every section above.
4. **Explain a prediction** — a form for the 41 feature fields (reuses
   the Phase 4 schema), calls `POST /predict/explain`, renders the
   prediction plus the top-10 SHAP bar chart.

### What "no stale or fabricated data" means concretely

- No page ships a hardcoded example value anywhere in its rendered
  output — only loading/error states are static text.
- Every number shown is the direct JSON value from the most recent
  fetch, not a cached/computed-in-the-frontend derivative that could
  drift from the backend's own arithmetic (e.g. the composite score is
  read from the API response, never recomputed client-side from the
  sub-scores).
- A failed fetch renders a visible error state, never a silently empty
  or last-known-good-looking page.

## Part D — Test plan (locked before test code)

1. **Backend**: endpoint tests for `/predict/explain` (valid input →
   explanation with `len(top_contributing_features) <= 10`, SHAP values
   sum reasonably close to the prediction gap from base rate) and
   `/model-card` (every documented field present, no silent omissions)
   and `/audit-log` (RBAC-gated — `SECURITY_REVIEWER`/`APPROVER` allowed,
   other roles get `403`, matching Phase 8's permission matrix exactly).
2. **Frontend component tests** (Vitest + React Testing Library): each
   page renders real fetched data correctly, and renders a visible error
   state on a failed fetch (not a blank/broken page).
3. **The gate-mandated cross-check**: for **3 real pipeline runs** — one
   engineered to PASS, one to FAIL, one to BORDERLINE (via
   `src/security/gate.py`'s pure functions, same technique Phase 7's
   scenarios used) — call the backend's `/security-gate` endpoint and
   assert the JSON response's `decision` and every sub-score match
   exactly what feeding those same inputs through `run_gate()`'s formula
   produces directly. This is the literal gate criterion (project plan,
   Phase 9 Validate): "the dashboard's displayed state exactly matches
   the backend's ground truth" — checked at the API layer that feeds the
   dashboard, since that's the actual contract the frontend depends on.

## Phase 9 gate

1. All backend endpoint tests pass (SHAP, Model Card, RBAC-gated audit log).
2. Frontend component tests pass (live-rendered real data + visible error states).
3. All 3 pipeline-run cross-checks (PASS/FAIL/BORDERLINE) match exactly.
