# Phase 4 — Inference API Spec

Locked before the FastAPI code is written, same practice as Phase 1's
model spec: the contract is decided first, not inferred from whatever the
implementation happens to do.

## Endpoints

### `GET /health`

Liveness/readiness check. No auth, no body.

Response `200`:
```json
{"status": "ok", "model_loaded": true, "model_source": "models/baseline_model.joblib"}
```

If the model failed to load at startup, the process should not report
healthy — see "Startup behavior" below.

### `POST /predict`

Batch prediction endpoint. Always a batch, even for one record — a client
predicting a single connection just sends a one-element list. No separate
single-record endpoint; one contract, no special-casing.

Request:
```json
{"records": [ { <41 NSL-KDD feature fields> }, ... ]}
```

The 41 feature fields are exactly `src/data/load_dataset.py`'s
`COLUMN_NAMES` minus `label` and `difficulty` (those two are dataset
metadata, not real-time features — a live inference request was never
going to have them). Field names and types below.

Response `200`:
```json
{
  "predictions": [
    {"label": "attack", "attack_probability": 0.94}
  ]
}
```

`label` is `"normal"` or `"attack"` (mirrors Phase 1's binary framing —
see `docs/phase1_baseline_spec.md`). `attack_probability` is the
underlying `RandomForestClassifier`'s `predict_proba` for the positive
(attack) class, exposed so a caller (or, later, the Security Gate) can
apply its own threshold instead of only trusting the model's default 0.5
cut — relevant groundwork for Phase 5+, not used by anything yet.

## Field schema (`records[i]`)

| Field | Type | Constraint |
|---|---|---|
| `duration` | int | ≥ 0 |
| `protocol_type` | string | one of `tcp`, `udp`, `icmp` (rejected otherwise — small, fully known domain) |
| `service` | string | any non-empty string (NOT restricted to a known set — Phase 1's `OneHotEncoder(handle_unknown="ignore")` was deliberately chosen because `KDDTest+.txt` contains `service` values absent from training; the API must not be stricter than the model it's serving) |
| `flag` | string | one of the 11 known NSL-KDD flag values (`SF`, `S0`, `REJ`, `RSTR`, `RSTO`, `SH`, `S1`, `S2`, `S3`, `RSTOS0`, `OTH`) |
| `src_bytes`, `dst_bytes` | int | ≥ 0 |
| `land` | int | 0 or 1 |
| `wrong_fragment`, `urgent`, `hot`, `num_failed_logins` | int | ≥ 0 |
| `logged_in` | int | 0 or 1 |
| `num_compromised`, `num_root`, `num_file_creations`, `num_shells`, `num_access_files`, `num_outbound_cmds` | int | ≥ 0 |
| `root_shell`, `su_attempted`, `is_host_login`, `is_guest_login` | int | 0 or 1 |
| `count`, `srv_count`, `dst_host_count`, `dst_host_srv_count` | int | ≥ 0 |
| `serror_rate`, `srv_serror_rate`, `rerror_rate`, `srv_rerror_rate`, `same_srv_rate`, `diff_srv_rate`, `srv_diff_host_rate`, `dst_host_same_srv_rate`, `dst_host_diff_srv_rate`, `dst_host_same_src_port_rate`, `dst_host_srv_diff_host_rate`, `dst_host_serror_rate`, `dst_host_srv_serror_rate`, `dst_host_rerror_rate`, `dst_host_srv_rerror_rate` | float | 0.0 ≤ x ≤ 1.0 (all are rate/fraction features in the raw dataset) |

These bounds are taken directly from the NSL-KDD feature definitions (all
of these are documented as counts or [0,1] rates in the dataset's own
schema) — not arbitrary API design choices, so a legitimate record from
the dataset can never itself be rejected by these checks.

## Error behavior

- **Missing a required field** → `422`, FastAPI/Pydantic's standard
  validation error body, naming the missing field. Not a `500`.
- **Wrong type** (e.g. a string where a number is expected) → `422`, same
  as above.
- **`protocol_type` or `flag` outside their known domain** → `422` — these
  are genuinely closed sets in the dataset; a value outside them is a
  malformed/corrupted request, not a legitimate edge case.
- **Numeric field out of its documented bound** (e.g. a negative
  `duration`, a rate `> 1.0`) → `422`.
- **`service` value not seen during training** → **not** an error. `200`,
  handled by the model's `handle_unknown="ignore"` encoding. This is the
  one deliberate asymmetry in the schema, and it's called out here so it
  isn't mistaken for an oversight later.
- **Empty `records` list** → `422` (nothing to predict is a client error,
  not a valid empty-batch success).
- **Anything that would otherwise reach the model in a shape it can't
  handle** → must not happen, by construction: if Pydantic validation
  passes, the record is guaranteed shaped correctly for the pipeline. The
  API must never let a raw exception from the model/pipeline surface as an
  unhandled `500` — Pydantic validation is the only gate, and it's placed
  ahead of the model on purpose.

## Startup behavior

The model artifact (`models/baseline_model.joblib`) is loaded once at
process startup, not per-request. If it's missing or fails to load, the
process should fail fast (crash on startup) rather than come up and serve
`503`s per-request — a service silently running with no model is worse
than one that never started. `GET /health` reporting `model_loaded: true`
is therefore only reachable if startup already succeeded.

## Gate (Phase 4)

Per the project plan, all of the following, checked without requiring a
live Docker run (see progress.md Phase 4 notes on the Docker limitation):

1. **Prediction parity**: for a fixed sample of `KDDTest+.txt` records, the
   API's `/predict` output matches the offline batch prediction (same
   pipeline, same input, called directly in Python) exactly — same label,
   same probability, not just "close".
2. **Contract tests**: valid input → `200` with a well-formed response;
   each invalid-input case above → `422`, not a crash/`500`/hang.
3. **Basic load check**: a batch of concurrent requests all complete
   successfully with reasonable latency (smoke-level, not a full
   performance benchmark — that's out of scope for the MVP).
4. Dockerfile exists, is well-formed, and (documented, not verified in
   this sandbox — see progress.md) is expected to start cleanly via
   `docker run` with no manual steps.
