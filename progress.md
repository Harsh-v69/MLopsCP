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
| Phase 3 — Pipeline Automation (Airflow) | Not started |
| Phase 4 — Deployment Service (FastAPI + Docker) | Not started |
| Phase 5 — Security Gate v1 (Data & Model Integrity) | Not started |
| Phase 6 — Security Gate v2 (Adversarial + Dependency) | Not started |
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

### Next: Phase 3 — Pipeline Automation (Airflow)

Build an Airflow DAG automating ingest → validate → train → evaluate →
register, replacing manual script execution. Gate: the DAG completes
unattended from a cold start and produces a registered model identical to
Phase 2's manual run; a deliberately-broken run correctly halts the
pipeline instead of registering a bad model. Not started yet — waiting on
Phase 2 sign-off.
