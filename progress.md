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

## Phase status

| Phase | Status |
|---|---|
| **Phase 0 — Foundation & Scope Lock** | ✅ Complete — gate passed (see below) |
| Phase 1 — ML Baseline | Not started |
| Phase 2 — MLOps Foundation (DVC + MLflow) | Not started |
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

### Next: Phase 1 — ML Baseline

Train a baseline classifier on the locked NSL-KDD split, no security
features yet. Gate: minimum performance bar (F1) agreed and met, and
retraining with the same seed reproduces the same metrics within tolerance.
Not started yet — waiting on Phase 0 sign-off.
