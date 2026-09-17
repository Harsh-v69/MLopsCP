# MLShield — Progress Log

## What this project is

**MLShield** is a secure MLOps platform. It takes a machine learning pipeline
(data → training → deployment → monitoring) and wraps it in security and
governance controls so that:

1. **Attacks are caught before they matter.** The pipeline is continuously
   tested against four core threats: data poisoning, adversarial inputs,
   model tampering, and vulnerable/compromised dependencies.
2. **Bad models never reach production silently.** A Security Gate scores
   every model release and blocks anything that fails; borderline cases go
   to a named human approver instead of an automatic pass.
3. **Every decision is accountable and auditable.** Deployment decisions are
   written to a tamper-evident (hash-chained) audit log, and every release
   ships with a plain-language Model Card and explanation report.

## What we're trying to achieve

The project demonstrates a full lifecycle: **deploy → monitor → attack →
detect → block/approve → recover → verify**, with every step leaving a
transparent record. It is built as evidence for two UN SDGs:

- **SDG 9 (Industry, Innovation and Infrastructure)** — resilient,
  security-hardened ML infrastructure.
- **SDG 16 (Peace, Justice and Strong Institutions)** — not just resilient
  infrastructure, but *accountable institutions*: transparent rules, a
  tamper-evident record, named human accountability for risky decisions.

Every security/governance control is also mapped to a real, external,
checkable standard (MITRE ATLAS, OWASP ML Security Top 10, NIST AI RMF,
ISO/IEC 42001/23894/27001, NIST SSDF, SLSA) rather than invented terminology
— see `docs/security_gate_formula.md` and the project plan for details.

The build follows a strict **stage-gate process**: each phase has a Build /
Test / Validate step, and the next phase does not start until the current
phase's validation gate passes. This file is the running record of that —
anyone should be able to read it and understand exactly what exists today
and what doesn't yet.

## Traceability: finding which phase an issue came from

Every phase's section below starts with **"Git commit range"**: the exact
commit SHA where the phase's gate passed (and, once there's more than one
phase, the SHA range covering just that phase). This is the primary
mechanism — it doesn't depend on anything beyond normal git:

- `git show <sha>` / `git log <sha-start>..<sha-end>` shows exactly the
  commits in a phase.
- `git diff <sha-start>..<sha-end> -- <path>` shows exactly what changed in
  a given file during that phase.
- `git bisect` between two phase-boundary SHAs will land on the exact
  commit, which — because commits are one-phase-at-a-time (see rule below)
  — tells you the phase.

(Note: this session's push credentials are scoped to the
`claude/funny-johnson-dz42uw` branch ref only, so annotated git tags
created locally for phase boundaries do not push to the remote — a 403 on
`refs/tags/*` specifically, while branch pushes work fine. Commit SHAs
recorded here are the durable, remote-visible record instead.)

Each phase section below also lists exactly which files/commands it
introduced or changed, so you don't strictly need git to find the origin —
the log here is a second, human-readable copy of the same information.

**Rule going forward:** work for a phase stays in that phase's commit(s);
nothing from a later phase gets silently mixed into an earlier phase's
commit or tag. If a fix for an old phase's bug is needed after later phases
have started, it lands as a new commit and is called out explicitly in that
later phase's section (e.g. "Phase 3 note: fixed a Phase 1 bug in ...") —
never rewritten into the original tagged commit.

## Phase status

| Phase | Status |
|---|---|
| **Phase 0 — Foundation & Scope Lock** | ✅ Complete — gate passed (see below) |
| **Phase 1 — ML Baseline** | ✅ Complete — gate passed (see below) |
| **Phase 2 — MLOps Foundation (DVC + MLflow)** | ✅ Complete — gate passed (see below) |
| **Phase 3 — Pipeline Automation (Airflow)** | ✅ Complete — gate passed (see below) |
| **Phase 4 — Deployment Service (FastAPI + Docker)** | ✅ Complete — gate passed for everything testable in this sandbox; Docker build/run accepted as a known, documented unverified risk (user decision, see below) rather than independently confirmed |
| **Phase 5 — Security Gate v1 (Data & Model Integrity)** | ✅ Complete — gate passed (see below) |
| **Phase 6 — Security Gate v2 (Adversarial + Dependency)** | ✅ Complete — gate passed (see below) |
| Phase 7 — Security Scoring & Gate Decision Logic | Not started |
| Phase 8 — Governance Layer (RBAC + Audit Log) | Not started |
| Phase 9 — Transparency Layer (Dashboard, Model Cards, SHAP) | Not started |
| Phase 10 — Attack Laboratory & Recovery Cycle | Not started |
| Phase 11 — Final End-to-End Validation | Not started |

---

## Phase 0 — Foundation & Scope Lock

**Git commit range:** repo start `c4b6ed2` (dataset + formula + scaffold)
through `b96a894` (this traceability note) — everything in this phase is
these two commits; nothing else has been committed yet.

**Goal:** lock the dataset, lock the security-score formula (before any
detection code exists), and confirm the project environment is reproducible.

### What was built

- **Dataset locked: NSL-KDD.** Chosen over CICIDS2017 because it's small
  enough to version reliably in git (~23 MB) and well-documented for a
  network-intrusion-detection framing. Files committed at
  `data/raw/KDDTrain+.txt` (125,973 rows) and `data/raw/KDDTest+.txt`
  (22,544 rows), with source, license and SHA-256 integrity hashes recorded
  in `data/raw/README.md`. Rationale for the choice (and for *not* using
  CICIDS2017) is written down there too — this is a scope-lock decision and
  is not expected to change during the MVP.
- **Security-score formula locked** in `docs/security_gate_formula.md`,
  written *before* any detector code exists (per the plan, an undefined
  scoring formula is the single biggest risk to the whole project). It
  defines how the future Data Scan, Model Scan, and Dependency Scan
  sub-scores combine into one composite score, and the exact
  PASS (≥80) / BORDERLINE (50–79) / FAIL (<50) thresholds, plus a hard
  override: a failed model-integrity check always fails the gate regardless
  of the composite score.
- **Deterministic dataset loader/splitter**: `src/data/load_dataset.py`.
  Loads the raw NSL-KDD files, performs a fixed-seed (42), stratified
  80/20 train/validation split, and prints a SHA-256 hash of *which rows*
  went into which split — not a hash of file bytes, but of the actual split
  assignment, which is the thing that has to be reproducible.
- **Containerization scaffold**: `docker/Dockerfile`, `docker-compose.yml`,
  `requirements.txt`. Minimal Python 3.11-slim image that installs
  dependencies and runs the loader.
- **Validation gate script**: `scripts/validate_phase0.sh`, runs all Phase 0
  checks and exits non-zero if any fail.

### Known environment limitation (documented, not hidden)

This development session runs in a sandboxed remote environment whose
network policy blocks pulls from Docker Hub's CDN (`docker build` fails with
a policy-level 403, not a transient error). Per that environment's own
operating rules, this is a policy denial to be reported, not worked around.

Consequence: the Phase 0 gate below verifies the Dockerfile/compose file
exist and are well-formed, and verifies reproducibility via direct,
repeated Python execution (not via a container), rather than via an actual
`docker build && docker run`. **Anyone with normal Docker Hub access should
independently run:**

```
docker build -f docker/Dockerfile -t mlshield-phase0 .
docker run --rm mlshield-phase0
```

and confirm it prints the same split hash as below. This is a one-time
environment gap, not a project design gap — from Phase 4 onward (the real
deployment service), this needs to be verified in an environment with
normal registry access before that phase's gate can be called passed.

### Validation gate result

Run: `bash scripts/validate_phase0.sh`

```
=== Phase 0 Validation Gate ===

[1/4] Raw dataset integrity
  KDDTrain+.txt hash OK
  KDDTest+.txt hash OK

[2/4] Security-score formula document
  docs/security_gate_formula.md exists and defines PASS/BORDERLINE/FAIL

[3/4] Deterministic split reproducibility
  Two runs produced identical split hash: b34944a6f2c1f92d4226eadd46cc4ee3eb1235cb0de3ea22ac212d691b7cd7c5
  Split hash matches locked expected value from Phase 0

[4/4] Environment scaffolding
  docker/Dockerfile present
  docker-compose.yml present
  requirements.txt present
  progress.md present

=== PHASE 0 GATE: PASSED ===
```

**Locked split hash for future reference:**
`b34944a6f2c1f92d4226eadd46cc4ee3eb1235cb0de3ea22ac212d691b7cd7c5`
(seed=42, validation_fraction=0.2). If this ever changes on a re-run without
a deliberate, documented change to the split logic, something is wrong —
treat it as a regression, not noise.

### Repo layout after Phase 0

```
data/
  raw/                  KDDTrain+.txt, KDDTest+.txt, README.md (source + hashes)
  processed/            expected_split_hash.txt (locked Phase 0 value)
docs/
  security_gate_formula.md
docker/
  Dockerfile
docker-compose.yml
requirements.txt
scripts/
  validate_phase0.sh
src/
  data/load_dataset.py
progress.md            (this file)
```

---

## Phase 1 — ML Baseline

**Git commit range:** `9b78e23..1886379` (single commit `1886379`, right
after Phase 0's `9b78e23`).

**Goal:** train a working binary (normal/attack) classifier on the locked
NSL-KDD split, no security features yet, and prove it clears a pre-agreed,
pre-written performance bar and is exactly reproducible.

### What was built

- **Spec locked first**, in `docs/phase1_baseline_spec.md`, before any
  training code existed: binary-classification framing (`normal` vs
  `attack` — NSL-KDD's ~23 attack subtypes are collapsed, since the
  Security Gate only needs a block/allow signal, not attack typing),
  preprocessing choices (one-hot encode `protocol_type`/`service`/`flag`
  with `handle_unknown="ignore"`; drop the `difficulty` column as
  KDD-competition metadata that would leak information), model choice
  (`RandomForestClassifier`, `n_estimators=200`, `random_state=42`,
  `n_jobs=1` for determinism), and — most importantly — the minimum bar:
  **F1 ≥ 0.75 on `KDDTest+.txt`**, deliberately lower than a naive "F1
  should be high" instinct because NSL-KDD's official test set is built to
  contain attack types absent from training, and a much higher score there
  would actually indicate a data leak, not a better model. That reasoning
  is written down in the spec, not just the number.
- **Training/eval script**: `src/models/train_baseline.py`. Trains on
  Phase 0's fixed-seed train split, evaluates on both the Phase 0
  validation split (same-distribution sanity check) and `KDDTest+.txt` (the
  real gate metric), runs 5-fold stratified CV on the training split for a
  stability check, and writes everything to
  `data/processed/phase1_metrics.json`.
- **`requirements.txt` corrected** to the package versions actually
  installed and tested (`pandas==3.0.5`, `numpy==2.4.6`,
  `scikit-learn==1.9.1`) — the Phase 0 pins were aspirational and had
  drifted from what `pip install` actually resolved in this environment;
  fixed now so the pinned versions match what was verified, not a guess.
- **Validation gate script**: `scripts/validate_phase1.sh`.

### Validation gate result

Run: `bash scripts/validate_phase1.sh`

```
=== Phase 1 Validation Gate ===

[1/3] Training run 1
Validation split F1: 0.9985
KDDTest+ F1:         0.7653
CV F1 mean/std:      0.9986 / 0.0003

[2/3] Training run 2 (reproducibility check)
Validation split F1: 0.9985
KDDTest+ F1:         0.7653
CV F1 mean/std:      0.9986 / 0.0003
  Two runs produced bit-identical metrics

[3/3] Threshold checks
  KDDTest+ F1 = 0.7653 >= 0.75 (PASS)
  CV F1 std = 0.0003 < 0.05 (PASS)

=== PHASE 1 GATE: PASSED ===
```

Read the two F1 numbers together, not separately: 0.9985 on the
same-distribution validation split shows the model learned the training
distribution well; 0.7653 on `KDDTest+` (which contains attack types the
model never saw) shows a realistic, non-leaked generalization gap — exactly
the pattern the spec predicted before training ran.

### Repo additions in this phase

```
docs/
  phase1_baseline_spec.md
src/
  models/train_baseline.py
data/
  processed/phase1_metrics.json   (metrics from the last training run)
scripts/
  validate_phase1.sh
```

---

## Phase 2 — MLOps Foundation (DVC + MLflow)

**Git commit range:** `0ead56d..3e604cc` (end of Phase 1 through the gate
script fix below).

**Goal:** version the dataset and the Phase 1 model with DVC, add MLflow
experiment tracking, and prove that a genuinely fresh clone can pull the
exact Phase 1 model artifact (same hash) and reproduce its exact metrics —
without retraining.

### What was built

- **DVC initialized**, anonymous analytics explicitly disabled
  (`dvc config core.analytics false` — no telemetry leaving the project
  without it being a deliberate, visible choice).
- **Raw dataset migrated from plain git to DVC.** `data/raw/KDDTrain+.txt`
  and `KDDTest+.txt` are no longer committed as git blobs; git now holds
  only the small `.dvc` pointer files (hashes), and the actual content is
  retrieved via `dvc pull`. `data/raw/README.md` updated to explain this.
- **DVC remote**: a local directory
  (`/home/user/dvc-remote-storage`, outside the repo). **This is a known
  MVP stand-in, not a design choice to keep** — there is no cloud storage
  account available in this environment. A real deployment would point
  `dvc remote` at S3/GCS/Azure Blob. Documented here rather than left
  implicit, same treatment as the Docker Hub limitation from Phase 0.
- **Phase 1 training script extended** (`src/models/train_baseline.py`)
  to, in the same run:
  - serialize the trained pipeline via `joblib` to
    `models/baseline_model.joblib` (now DVC-tracked, pushed to the remote)
  - log params, metrics, and the model itself to a local **MLflow**
    tracking store (`sqlite:///mlflow.db`), under experiment
    `mlshield-baseline`, registering it as `mlshield-baseline-rf` in
    MLflow's local model registry.
  - Confirmed by direct test: two independent training runs produced a
    **byte-identical** `baseline_model.joblib` (same sha256) and identical
    logged metrics — the RandomForest baseline (seed=42, `n_jobs=1`) is
    fully deterministic end-to-end, not just prediction-equivalent.
- **MLflow tracking store is *not* version-controlled** (`mlflow.db`,
  `mlruns/` are gitignored). This is also a documented MVP limitation, not
  an oversight: there's no shared/cloud MLflow tracking server available
  here, so each clone gets its own fresh local store. The durable,
  hash-verifiable record of "what Phase 1 produced" is instead the
  DVC-tracked model artifact plus the git-committed
  `data/processed/phase1_metrics.json` — arguably a more rigorous source of
  truth for the SDG 16 auditability goal than a mutable local UI store
  would be anyway; MLflow here is a convenience/experiment-tracking layer,
  not the system of record.
- **Validation gate script**: `scripts/validate_phase2.sh`. Clones the repo
  fresh into a temp directory (real `git clone`, not just re-running in
  place), runs `dvc pull`, and checks all of: raw-data hashes still match
  Phase 0's locked values, the model artifact's hash matches its committed
  `.dvc` pointer, loading that pulled model **without retraining** and
  evaluating it on `KDDTest+.txt` reproduces Phase 1's committed metrics
  exactly, and a training run's MLflow logging is queryable back via the
  MLflow client API.

### A bug the gate caught (worth recording, not hiding)

First run of the gate script failed at the model-hash-match step. Cause:
the `.dvc` pointer file's YAML is `- md5: <hash>`, so splitting the line on
whitespace puts the literal token `md5:` in field 2, not the hash — the
script's `awk '{print $2}'` was reading the wrong field. Fixed to `$3` and
re-run confirmed a real pass (`3e604cc`). This is exactly the kind of thing
the phase-by-phase gate process exists to catch before it compounds into
later phases — recorded here per the traceability rule above rather than
folded silently into the original commit.

### Validation gate result

Run: `bash scripts/validate_phase2.sh` (requires the project virtualenv —
see `.venv/` setup note below)

```
=== Phase 2 Validation Gate ===

[1/4] Fresh clone + dvc pull
  Cloned to /tmp/.../repo and ran dvc pull

[2/4] Raw dataset hash check (must match Phase 0 locked hashes)
  KDDTrain+.txt hash OK (via dvc pull)
  KDDTest+.txt hash OK (via dvc pull)

[3/4] Model artifact hash check + no-retrain metric reproduction
  Model artifact md5 matches committed .dvc pointer (a898ab58db2f9c65de0ffab0a2b17a7d)
  Reproduced KDDTest+ metrics from the DVC-pulled artifact exactly: F1=0.7653

[4/4] MLflow logging mechanics (fresh local tracking store in the clone)
  MLflow run d1f2d9c4819c... queried back successfully, params/metrics present

=== PHASE 2 GATE: PASSED ===
```

### Environment note: Python virtualenv

Phase 2 introduced DVC and MLflow, which failed to install into the system
Python via plain `pip install` in this sandbox (a `setuptools`/`distutils`
packaging bug unrelated to this project, triggered on the Debian-managed
system Python). Fixed by creating a project virtualenv (`.venv/`, gitignored)
and installing everything there — `source .venv/bin/activate` before running
any script in this repo from here on. Not a project design decision, just
a note for anyone hitting the same system-Python error.

### Repo additions in this phase

```
.dvc/                              DVC internal config (analytics off, remote configured)
.dvcignore
data/raw/
  KDDTrain+.txt.dvc, KDDTest+.txt.dvc   (pointer files; actual data via dvc pull)
models/
  baseline_model.joblib.dvc             (pointer file; actual model via dvc pull)
scripts/
  validate_phase2.sh
```

---

## Phase 3 — Pipeline Automation (Airflow)

**Git commit range:** `d684bb3..2e5fde1` (single commit `2e5fde1`, right
after Phase 2's `d684bb3`).

**Goal:** replace manual step-by-step script execution with an Airflow DAG
(ingest → validate → train → evaluate → register), and prove two things:
a cold-start unattended run reproduces Phase 2's model exactly, and a
genuinely broken input run halts the pipeline before anything bad gets
registered.

### What was built

- **Pipeline split into five discrete steps** (`src/pipeline/`), each a
  standalone, independently-runnable script:
  - `ingest.py` — copies the locked raw dataset into `data/staging/`
    (nothing downstream touches `data/raw/` directly), checking source
    files against Phase 0's locked SHA-256 hashes. Accepts an env-var
    override (`MLSHIELD_INGEST_TRAIN_SOURCE`) so a corrupted file can be
    substituted for testing without faking the check itself.
  - `validate.py` — **real schema validation**, not a placeholder: exact
    per-row column count (checked at the raw line level, independent of
    pandas' own parsing leniency), `protocol_type`/`flag` value-domain
    checks, label completeness, numeric-column sanity. This is what
    actually catches bad input; it doesn't know or care why a file might
    be bad.
  - `train.py` — same model/logic as Phase 1's training script, reading
    from staged data, logging params/metrics/model to MLflow — but
    **not** registering the model. Registration is a separate, gated step.
  - `evaluate.py` — checks the trained model's `KDDTest+` F1 against the
    same locked bar as Phase 1 (≥0.75). Exits non-zero on failure.
  - `register.py` — only reached if `evaluate` exits 0 (Airflow's task
    dependency graph is what enforces this, not a convention); registers
    the MLflow-logged model as a new version of `mlshield-baseline-rf`,
    the same registry entry Phase 2 used manually.
- **Airflow DAG**: `airflow/dags/mlshield_baseline_dag.py`, wiring
  `ingest >> validate >> train >> evaluate >> register` as `BashOperator`
  tasks, each shelling out to the ML virtualenv's Python interpreter.
- **Airflow installed in its own virtualenv** (`.venv-airflow/`, separate
  from `.venv/`) — see the environment note below for why this isn't
  optional.
- **Deliberate-failure test fixture**:
  `tests/fixtures/corrupted_train_sample.txt` — a real copy of training
  data with a genuinely malformed row (wrong column count) and an unknown
  `protocol_type` value injected, not a simulated/faked failure.

### A bug the pipeline caught (worth recording, not hiding)

Wiring `train.py`'s MLflow logging (same call pattern as Phase 2's script)
started failing with `skops.io.exceptions.UntrustedTypesFoundException`.
Cause: `skops` (not pinned in `requirements.txt` since nothing imports it
directly — it's a transitive dependency of mlflow's default sklearn
serializer) resolved to a newer version between the Phase 2 and Phase 3
venv rebuilds, and that version's load-time safety audit now blocks
`sklearn.tree._tree.Tree` objects by default — a real protection against
loading an untrusted third-party model file, but not a threat model that
applies here (this artifact's integrity is already covered by our own DVC
content hash). Fixed by explicitly pinning
`serialization_format="cloudpickle"` on both `mlflow.sklearn.log_model`
call sites (`src/models/train_baseline.py` and `src/pipeline/train.py`),
so the artifact format no longer depends on whichever `skops` version
happens to be installed.

### Environment note: two virtualenvs, not one

Installing `apache-airflow==2.10.5` (with its official constraints file)
into the same venv as `dvc`/`mlflow` downgraded shared libraries
(`cryptography`, `protobuf`, `typing-extensions`, `click`, `tzdata`, `cffi`)
and broke `import dvc` / `import mlflow` with a concrete `ImportError` —
confirmed by hitting it, not assumed. Fixed by giving Airflow its own
virtualenv (`.venv-airflow/`, gitignored) and having every DAG task shell
out to the ML venv's Python (`.venv/bin/python`) rather than importing ML
code into Airflow's process. See `requirements-airflow.txt` for the
install command. This also mirrors a realistic production setup: an
orchestrator and the ML code it calls commonly live in separate
services/images with independent dependency trees, not one shared
environment.

### Validation gate result

Run: `bash scripts/validate_phase3.sh` (requires both `.venv/` and
`.venv-airflow/` — see environment note above)

```
=== Phase 3 Validation Gate ===

[1/3] Cold-start normal run
  DAG run succeeded (exit 0)
  register task succeeded
  Model registry gained a new version (7 -> 8)
  KDDTest+ F1=0.7653 (meets >=0.75 bar, matches Phase 1/2's locked threshold)

[2/3] Deliberately-broken run (corrupted training data)
  DAG run failed as expected (exit 1)
  validate task failed, as expected
  No downstream task (train/evaluate/register) ever started
  Model registry version count unchanged (8) - no bad model registered

[3/3] Repo scaffolding
  airflow/dags/mlshield_baseline_dag.py present
  src/pipeline/ingest.py present
  src/pipeline/validate.py present
  src/pipeline/train.py present
  src/pipeline/evaluate.py present
  src/pipeline/register.py present

=== PHASE 3 GATE: PASSED ===
```

Also confirmed directly (not just inferred from the gate): the
pipeline-trained model artifact and its metrics are **byte-identical** to
Phase 1/2's manually-trained ones (same sha256, same JSON). The automation
reproduces the exact same result, not just "a similar" one. Also confirmed
the gate script is idempotent — reran it twice in a row, registry version
count advanced predictably each time (7→8, 8→9 on the run after), no
state corruption between runs.

### Repo additions in this phase

```
airflow/
  dags/mlshield_baseline_dag.py
requirements-airflow.txt             (separate venv setup instructions)
src/
  pipeline/{ingest,validate,train,evaluate,register}.py
tests/
  fixtures/corrupted_train_sample.txt
scripts/
  validate_phase3.sh
```

Gitignored (generated/ephemeral, regenerated by running the pipeline —
see `.gitignore` for the specific reasoning per entry):
`airflow_home/`, `.venv-airflow/`, `data/staging/`,
`data/processed/phase3_run_info.json`, `data/processed/phase3_metrics.json`,
`models/phase3_model.joblib`.

---

## Phase 4 — Deployment Service (FastAPI + Docker)

**Git commit range:** `ac510c3..bf3f323` (single commit `bf3f323`, right
after Phase 3's `ac510c3`).

**Goal:** wrap the Phase 1/2 model in an inference API, prove its served
predictions match offline predictions exactly, prove it rejects bad input
without crashing, and containerize it.

**Status is intentionally marked ⚠️, not ✅** — see "What's NOT verified"
below. Everything sandbox-testable passed; the one plan-mandated check this
sandbox cannot perform (a live `docker build`/`docker run`) has not been
done by anyone yet, and this file says so plainly rather than assuming it
would pass.

### What was built

- **API contract locked first**, in `docs/phase4_api_spec.md`: a single
  batch `POST /predict` endpoint (no separate single-record endpoint — one
  contract, no special-casing), `GET /health`, and per-field validation
  bounds taken directly from NSL-KDD's own documented feature definitions
  (counts ≥0, binary flags ∈{0,1}, rate features ∈[0,1]) — not arbitrary
  API design, so a legitimate dataset record can never itself be rejected.
  One deliberate, documented asymmetry: `service` values outside the
  training set are accepted (`200`, not `422`), because Phase 1's model
  itself was built with `OneHotEncoder(handle_unknown="ignore")`
  specifically for this reason — the API must not be stricter than the
  model it serves.
- **`src/api/main.py` + `schemas.py`**: loads
  `models/baseline_model.joblib` once at process startup and **fails
  fast** if it's missing (crashes on startup rather than serving `503`s
  per-request — a silently modelless service is worse than one that never
  starts). Pydantic validation sits in front of the model as the only
  gate, so a validated request is guaranteed shaped correctly before it
  ever reaches the pipeline.
- **13-test pytest suite** (`tests/api/test_predict_api.py`), all via
  FastAPI's `TestClient` (a real ASGI request/response cycle, not a mock):
  - exact prediction parity — API output vs. calling the loaded pipeline
    directly on the same `KDDTest+.txt` records, not just "close" (`pytest.approx` at `1e-12`, matching float noise only)
  - full invalid-input contract coverage: missing field, wrong type,
    unknown `protocol_type`/`flag`, out-of-range rate, negative count,
    empty batch, malformed body — every case → `422`, none crash
  - the one deliberate exception (unseen `service` value) → confirmed `200`
  - a basic concurrent-load smoke check (30 requests, 10 workers)
- **`docker/api.Dockerfile`**: bakes the DVC-pulled model into the image,
  runs via `uvicorn`, includes a `HEALTHCHECK` that hits the real
  `/health` endpoint (not just "is the process alive"). `docker-compose.yml`
  gained an `api` service.

### What the gate script additionally proves beyond the pytest suite

`scripts/validate_phase4.sh` goes further than the test suite alone:

- Spins up a **real `uvicorn` subprocess** (not `TestClient`) and hits it
  with real HTTP requests via `curl`/`urllib` — confirming the live server's
  `/health` and `/predict` behave identically to the in-process tests,
  including exact prediction-parity match and `422` on invalid input over
  a real HTTP round-trip.
- Runs `docker compose config` to validate the Dockerfile/compose YAML
  syntax — this does **not** require pulling any image, so it works even
  under this sandbox's Docker Hub block, and it did catch that both
  Dockerfiles parse correctly.

### What's NOT verified (read this before trusting the gate)

A live `docker build -f docker/api.Dockerfile ...` followed by
`docker run` has **not** been executed by anyone, in this sandbox or
otherwise, as of this commit. This sandbox's Docker Hub pulls are blocked
at the network-policy level (see Phase 0 notes) — same limitation, but
higher-stakes here since Phase 4's actual deliverable is the container.
Unlike Phase 0 (where the containerized piece was incidental to that
phase's real goal), this phase's plan-mandated gate criterion
("the container starts cleanly from `docker run` with no manual steps")
is **not yet independently confirmed by a human or CI**. To close this
out for real:

```
dvc pull
docker build -f docker/api.Dockerfile -t mlshield-api .
docker run --rm -p 8000:8000 mlshield-api
curl http://localhost:8000/health
curl -X POST http://localhost:8000/predict -H "Content-Type: application/json" \
  -d '{"records": [{...one full NSL-KDD record...}]}'
```

Until that's run somewhere with real Docker Hub access and confirmed
working, treat this phase as "code complete, container unverified" rather
than fully done.

**Decision recorded:** asked the user explicitly how to handle this gap
(same choice as Phase 0's Docker limitation). They chose to accept it as a
known, documented risk and proceed rather than pause the whole project on
it — not something assumed silently. If the build/run is later verified
(or found to fail) elsewhere, update this section rather than treating the
gate as re-opened from scratch.

### Validation gate result

Run: `bash scripts/validate_phase4.sh`

```
=== Phase 4 Validation Gate ===

[1/3] pytest suite (contract + prediction parity + basic load)
  ... 13 passed, 2 warnings in 4.25s
  pytest suite passed

[2/3] Live server check (real subprocess, real HTTP, not TestClient)
  Live server /health OK: {"status":"ok","model_loaded":true,"model_source":"/home/user/MLopsCP/models/baseline_model.joblib"}
  Live server /predict matches offline predictions exactly (real HTTP round-trip)
  Live server rejects invalid input with 422 (empty records list)

[3/3] Docker/compose syntax check (no image pull required)
  docker-compose.yml + Dockerfiles parse correctly (docker compose config)
  NOTE: a live 'docker build'/'docker run' is NOT exercised in this
  sandbox (Docker Hub pulls are blocked at the network-policy level -
  see progress.md Phase 0 and Phase 4 notes). Verify independently:
    dvc pull && docker build -f docker/api.Dockerfile -t mlshield-api . && \
    docker run --rm -p 8000:8000 mlshield-api

=== PHASE 4 GATE: PASSED (all sandbox-testable checks; docker build/run still needs independent verification - see note above) ===
```

### Repo additions in this phase

```
docs/
  phase4_api_spec.md
src/
  api/{main,schemas}.py
tests/
  api/test_predict_api.py
docker/
  api.Dockerfile
scripts/
  validate_phase4.sh
```

---

## Phase 5 — Security Gate v1 (Data & Model Integrity)

**Git commit range:** `c330748..0d3c902` (single commit `0d3c902`, right
after Phase 4's `c330748`).

**Goal:** implement the first two real security controls the whole project
is named for — a data-poisoning detector and cryptographic model-artifact
integrity verification — and prove both meet targets that were locked
*before this phase started* (the recall/FPR bar was written into
`docs/security_gate_formula.md` back in Phase 0).

### What was built

- **Poisoning detector (Data Scan)**: k-Nearest-Neighbors label-consistency
  filtering (`src/security/poisoning_detector.py`) — for each training
  sample, checks whether its label agrees with the majority of its
  feature-space neighbors; flags it as suspected-poisoned if not. Chosen
  over an anomaly-detection alternative (e.g. Isolation Forest) because
  label-flipping poisoning breaks *local* label consistency specifically,
  which kNN agreement measures directly — and because it's a simple,
  auditable rule, not another opaque model sitting in front of the one
  being protected (matters for the SDG 16 transparency goal this whole
  project is built around).
  - Method, parameters (`k=15`, `agreement_threshold=0.5`,
    `n=8000`-row fixed subsample), and the injection test protocol are all
    locked in `docs/phase5_security_gate_v1_spec.md`, written before the
    detector code.
  - **Calibration result**: the locked parameters met the bar on the
    *first* run, no post-hoc tuning — a controlled 10%-label-flip
    injection test measured **recall=0.9663, FPR=0.0325** against
    **recall≥0.80, FPR≤0.10** (the target Phase 0 committed to before any
    detector existed). Worth stating plainly: this means the spec's
    locked numbers weren't chosen to be easy — they had real margin.
- **Model artifact integrity (Model Scan)**: Ed25519 cryptographic signing
  (`src/security/model_integrity.py`, `sign_model.py`, `verify_model.py`)
  — not a bare content hash. A hash only proves a file wasn't
  *accidentally* corrupted; signing proves *authorized origin*, which is
  what `docs/security_gate_formula.md`'s hard fail-closed override on this
  check actually depends on. Signs the SHA-256 digest of
  `models/baseline_model.joblib`.
  - Private key generated once, kept **outside the repo**
    (`~/mlshield-signing-key/private_key.pem`) — a documented MVP
    stand-in for a real KMS/HSM boundary (same treatment as the local DVC
    remote from Phase 2). Public key **is** committed
    (`security/signing_public_key.pem`) — verification must work for
    anyone with this repo, without the private key.
  - The signature itself (`models/baseline_model.joblib.sig`) is also
    committed — small, human-readable JSON, same treatment as
    `phase1_metrics.json`.
- **10-case tampering test** (`tests/security/test_model_integrity.py`):
  byte flips at five different offsets, truncation (two ways), appending
  extra bytes, zeroing a chunk, prepending bytes — **all 10 correctly fail
  verification**, and the legitimate, unmodified artifact correctly
  passes. 13 tests total in `tests/security/` (10 tamper cases + the
  legitimate-artifact check + the explicit "count == 10" check + the
  poisoning-detector gate test), all passing.

### Validation gate result

Run: `bash scripts/validate_phase5.sh`

```
=== Phase 5 Validation Gate ===

[1/3] Poisoning detector injection test
Recall:              0.9663 (bar: >= 0.8)
False positive rate: 0.0325 (bar: <= 0.1)
PASS

[2/3] Model artifact signing + tampering test suite
SIGN OK: models/baseline_model.joblib signed
VERIFY OK: models/baseline_model.joblib matches its signature
  10/10 tampering test cases passed (all correctly rejected)

[3/3] Full security test suite (both parts together)
============================== 13 passed in 5.64s ==============================

=== PHASE 5 GATE: PASSED ===
```

### Repo additions in this phase

```
docs/
  phase5_security_gate_v1_spec.md
src/
  security/{poisoning_detector,evaluate_poisoning_detector,model_integrity,sign_model,verify_model}.py
tests/
  security/{test_model_integrity,test_poisoning_detector}.py
security/
  signing_public_key.pem          (committed — verification needs this)
models/
  baseline_model.joblib.sig       (committed — small, human-readable)
scripts/
  validate_phase5.sh
```

Outside the repo (documented, not hidden — see "What was built" above):
`~/mlshield-signing-key/private_key.pem`.

---

## Phase 6 — Security Gate v2 (Adversarial Testing & Dependency Scan)

**Git commit range:** `fe5551f..4b4d02b` (single commit `4b4d02b`, right
after Phase 5's `fe5551f`).

**Goal:** finish the Model Scan (robustness, alongside Phase 5's
integrity check) and add the Dependency Scan — both against bars locked
back in Phase 0.

### What was built

- **Adversarial robustness test**: the plan's example names FGSM/PGD via
  IBM's Adversarial Robustness Toolbox (ART) — but Phase 1's model is a
  `RandomForestClassifier`, which has no gradients, so a gradient-based
  attack cannot be run against it directly. Rather than fake a gradient or
  quietly swap in a different (differentiable) production model, this is
  documented head-on in `docs/phase6_security_gate_v2_spec.md`, and a
  named, published alternative is used instead: a **transfer-based
  black-box attack via a differentiable surrogate** (Papernot et al. 2016,
  "Practical Black-Box Attacks against Machine Learning"). A
  `LogisticRegression` surrogate is trained on the same preprocessed
  feature space, ART's `FastGradientMethod` (single-step FGSM) attacks
  the surrogate, and the resulting perturbations are transferred to and
  evaluated against the real RandomForest
  (`src/security/adversarial_test.py`).
  - **Attack surface restricted to the 15 documented `[0,1]` rate
    features** via an explicit ART `mask` — everything else (one-hot
    categoricals, integer counts, binary flags) held fixed, both because
    a fractional perturbation on those is meaningless/unrealistic and
    because it keeps every generated adversarial example a valid,
    schema-conformant request against the Phase 4 API contract.
  - `epsilon = 0.05` (L∞), evaluated on 100 fixed, correctly-classified
    `KDDTest+.txt` points. `max_allowed_degradation = 0.30` — the same
    number `docs/security_gate_formula.md` floated as its own
    illustrative example in Phase 0, adopted here rather than picked
    after seeing results.
  - **Result**: `clean_accuracy = 1.0000`, `adversarial_accuracy = 0.9900`,
    `degradation = 0.01` — well inside the 0.30 bar — and confirmed
    **bit-identical across repeated runs**.
- **Dependency scan + SBOM** (`src/security/dependency_scan.py`):
  `pip-audit` against the OSV.dev vulnerability database, CycloneDX SBOM
  generation via `cyclonedx-py` with built-in schema validation plus an
  independent structural check on top of it. A fixture requirements file
  (`tests/fixtures/vulnerable_requirements.txt`, pinning `urllib3==1.24.1`
  — never installed into this project's own environment) confirms
  detection works against a real, multiply-documented CVE.
- **Real scan of this project's own dependencies, recorded honestly, not
  swept under the rug**: `pip-audit` against the actual `requirements.txt`
  found **2 known vulnerabilities in `diskcache` 5.6.3** (pulled in
  transitively via `dvc-data`; no fix version available yet in the
  advisory data). This is explicitly *not* the Phase 6 gate criterion
  (see spec), but leaving it undocumented would undercut the whole
  point of running a real scanner instead of a token one.
- 20 tests total in `tests/security/` (13 carried over from Phase 5 + 7
  new this phase), all passing.

### A bug the sanity test caught (worth recording, not hiding)

First implementation passed the accuracy-degradation bar but failed a
sanity check asserting no more than the 15 documented rate-feature
dimensions had actually changed — it found **23**. Root cause: the ART
`SklearnClassifier` was constructed with `clip_values=(0.0, 1.0)`, which
ART applies **globally, to every dimension** during attack generation —
but only the 15 rate features are actually bounded to `[0,1]`;
`src_bytes`/`duration`/counts are not (e.g. `src_bytes` legitimately
ranges into the tens of thousands). That blanket clip was silently
clamping those large legitimate values down to `1.0`, producing huge
artifactual "perturbations" on features the mask was supposed to leave
completely untouched — a real correctness bug, not a flaky test. Fixed by
dropping the classifier's global `clip_values` entirely and clipping only
the actual rate-feature dimensions afterward. Re-ran and confirmed exactly
15 dimensions perturbed, matching the mask by construction. This is
exactly why the spec required an explicit sanity check on the attack
surface rather than trusting the mask parameter alone.

### Validation gate result

Run: `bash scripts/validate_phase6.sh` (slow — trains the surrogate
`LogisticRegression` multiple times across the test suite; expect ~9
minutes)

```
=== Phase 6 Validation Gate ===

[1/2] Adversarial robustness test
... 3 passed, 5 warnings in 514.03s (0:08:34)
  Adversarial test suite passed (bar met, reproducible, attack surface confined)

[2/2] Dependency scan + SBOM test suite
tests/security/test_dependency_scan.py::test_seeded_vulnerability_is_caught PASSED
tests/security/test_dependency_scan.py::test_seeded_vulnerability_is_caught_reliably PASSED
tests/security/test_dependency_scan.py::test_sbom_generation_and_structure PASSED
tests/security/test_dependency_scan.py::test_sbom_covers_declared_packages PASSED
============================== 4 passed in 20.92s ==============================
  Dependency scan / SBOM suite passed

=== PHASE 6 GATE: PASSED ===
```

(The `lbfgs failed to converge` warning during surrogate training is
benign and expected — the surrogate only needs to approximate the real
model's decision boundary well enough for perturbations to transfer, not
converge to a production-quality fit on unscaled features. Confirmed the
non-convergence itself is deterministic: identical warning, identical
results, across repeated runs.)

### Repo additions in this phase

```
docs/
  phase6_security_gate_v2_spec.md
src/
  security/{adversarial_test,dependency_scan}.py
tests/
  security/{test_adversarial,test_dependency_scan}.py
  fixtures/vulnerable_requirements.txt
data/processed/
  phase6_adversarial_eval.json
  sbom.json
scripts/
  validate_phase6.sh
```

### Next: Phase 7 — Security Scoring & Gate Decision Logic

Implement the actual formula from Phase 0 (`docs/security_gate_formula.md`)
combining the Phase 5/6 scan outputs into PASS/BORDERLINE/FAIL. Gate: the
gate produces the documented, expected outcome for every one of ~15-20
scripted synthetic scenarios covering clear-pass, clear-fail, and
deliberately ambiguous boundary cases — no undocumented logic, no silent
tie-breaking. Not started yet — waiting on Phase 6 sign-off.
