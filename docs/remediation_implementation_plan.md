# MLShield: Remediation Implementation Plan

Source: `MLShield_Pre_Deployment_Remediation_and_Readiness_Plan.md` (the "readiness plan"; section
numbers below refer to it). This file is the working plan: every requirement in the readiness plan is
mapped to a milestone (M0 to M10, from its section 23), with the tasks, the evidence that closes it,
and what needs a human decision or an external resource. The readiness plan's rule applies throughout:
**nothing is marked done because code was written; it is done when a test or a verified run shows it.**

How we work: one milestone at a time, in order. Each milestone ends with an exit check, a commit
(or several), and an update to the status table below. A milestone's work never lands inside an
earlier milestone's commit.

## Status

| Milestone | Scope | Status |
|---|---|---|
| M0 | Baseline stabilization (B-10, B-03, docs, tests) | done except B-03 (waiting on owner decision) and the full attack-lab rerun |
| M1 | Portable packaging (B-07, section 13) | mostly verified on 2026-11-15: both images build (API via a PyPI mirror), stack starts, health/ready work, non-root, read-only root, only web published, audit log and JWT secret survive down/up. **Not verified:** gate dependency scan inside the container (timed out; pip-audit installs packages from PyPI, which is slow here), Trivy scan (vulnerability DB download failed), clean-checkout build |
| M2 | Persistent infrastructure (B-08, section 8) | started: schema + migration verified on SQLite and real Postgres; backup/restore proven; MinIO, Redis/Celery, MLflow-on-Postgres, API wiring not done (PyPI downloads of psycopg/boto3/redis time out) |
| M3 | Identity and access (B-01, section 6) | started 2026-11-15: dev-token removed from production (route not registered, startup refuses dev auth in production), API hardening (size limit, rate limit, CORS allowlist from env, security headers, correlation IDs, safe errors, docs off in production), 9 new tests. **Not done:** Keycloak/OIDC and PKCE login, 7-role matrix, project membership/isolation, escalation tests, per-route authorization tests, dashboard login |
| M4 | Trust architecture (B-02, B-03, B-09, sections 7 and 9) | not started |
| M5 | Model independence (B-05, section 4) | not started |
| M6 | Evidence quality, policy engine (sections 5 and 15) | not started |
| M7 | Deployment lifecycle (B-04, sections 10 and 12) | not started |
| M8 | Observability (B-06, section 11) | not started |
| M9 | Pilot readiness (sections 14, 21, 22) | not started |
| M10 | Production readiness (sections 19 stages 2 and 3, 24) | not started |

## Reality check on scope

The readiness plan describes a multi-month engineering programme (identity provider, KMS or Sigstore
signing, object storage, background workers, a deployment controller with canary and rollback,
monitoring stack, two new model-framework adapters, a policy engine, CI/CD, 14 runbooks). It is
implemented here milestone by milestone and each is verified before the next starts. Items that
depend on infrastructure only the owner can provide (cloud account, domain, VM, managed KMS, a real
on-call destination) are marked **[OWNER]** and are built and verified locally first, with the cloud
step documented as a clearly separate task, not silently skipped.

---

## M0: Baseline stabilization

Closes: B-10, part of B-03, readiness plan section 23 "M0".

| # | Task | Evidence that closes it |
|---|---|---|
| 0.1 | Fix the dependency scan so it works on the full requirements (**done, verified**: in the API server pip-audit's stdout came back empty although the scan completed, so output now goes to a file via `-o`, with UTF-8 forced and stdin closed) | `/security-gate` returns a numeric dependency score; scanner failure still scores 0 and is reported as failure, not "0 vulnerabilities" |
| 0.2 | Key the scan cache on the SHA-256 of the requirements content (not mtime/size) and expose scan age | unit test: same content hits cache, changed content rescans, failure never cached |
| 0.3 | Fix the `progress.md` phase table (Phase 10 and 11 status) and record the remediation programme | table matches reality |
| 0.4 | Run the full test suites and record the true pass/fail state | recorded result, failures listed not hidden |
| 0.5 | **B-03 model trust: decision required.** Option A (restore the original signed artifact) needs the original model and private signing key, neither of which exists on this machine. Option B (new trust root) needs the owner's explicit authorization | **[OWNER]** decision recorded, then executed in M4 where the signing design is built, so the new trust root is created once, properly, not twice |

Exit: reproducible baseline, dependency scan verified on the full requirements, honest test status.

## M1: Portable packaging

Closes: B-07, section 13, readiness plan stage 1 (first part).

- Separate images: `api`, `worker` (later), `frontend`; multi-stage builds, pinned bases, non-root user,
  no secrets or keys in layers, `.dockerignore`.
- `/health/live` and `/health/ready` (liveness never depends on optional services).
- Compose stack (initially `frontend`, `api`, `nginx`), private network, only the proxy published,
  named volumes, resource limits, healthchecks.
- Verify from a clean checkout: build, start, health, restart, data survives.
- Image vulnerability scan (Trivy) reviewed.

Exit (section 13.5): images build clean, Compose starts, health/readiness behave, restart keeps data.
Needs Docker daemon running on this machine. **[OWNER]** only for the "clean second machine" repeat.

## M2: Persistent infrastructure

Closes: B-08, section 8.

- PostgreSQL + migrations (Alembic): projects, models, versions, assessments, policies, approvals,
  deployments, incidents, audit events.
- S3-compatible storage (MinIO) for artifacts, reports, SBOMs, manifests; immutable keys.
- MLflow on PostgreSQL backend + object-store artifacts, documented link between MLflow version and
  MLShield release ID.
- Redis + Celery worker; assessments become jobs (API returns a job ID).
- Data retention and encryption-at-rest/in-transit decisions written down.
- Backup and restore script, **restore tested into a clean environment**.

Exit (8.6): state and artifacts survive restart; second API instance reads the same release;
migrations versioned; restore proven.

## M3: Identity and access

Closes: B-01, section 6.

- Remove `POST /auth/dev-token` from production routes (separate dev-only router, startup fails if
  dev auth is enabled in production, test asserts 404 in production).
- OIDC with Keycloak (self-hosted, in Compose): issuer and audience validation, expiry, key rotation,
  redirect URIs, logout.
- Roles: Admin, Data Engineer, ML Engineer, Security Reviewer, Approver, Auditor, Operator; backend-enforced.
- Project membership and isolation; horizontal and vertical escalation tests; audit of permission changes.
- API hardening: size/upload limits, rate limiting, strict CORS allowlist, secure headers,
  correlation IDs, safe errors, no tokens in logs.
- Dashboard login via OIDC (authorization code with PKCE).

Exit (6.6): dev endpoint absent in production; expired, wrong-audience, wrong-issuer, bad-signature
tokens rejected; every privileged route has an authorization test; no secrets in logs.

## M4: Trust architecture

Closes: B-02, B-03, B-09, sections 7 and 9.

- Signing service abstraction with two backends: local-dev key (clearly labelled) and a production
  backend (Sigstore/Cosign keyless or cloud KMS). **[OWNER]** choose the production backend and
  provide the account; the abstraction and tests are built regardless.
- B-03 executed here: new trust root (Option B) with a documented, audited transition, or original
  artifact restore (Option A) if the owner can supply it.
- Canonical, schema-validated release manifest binding artifact digest, lineage, SBOM, assessment
  report digest, policy version, approval ID; signed as a unit.
- Verification at every boundary (register, assess, stage, promote, rollback, investigate).
- Key lifecycle: ids and versions, rotation that keeps old releases verifiable, revocation, recovery.
- Audit log in PostgreSQL; signed periodic checkpoints exported to storage the app host cannot
  rewrite (object lock / separate account); periodic verification and alert; approvals bound to the
  exact artifact and report digest and invalidated if either changes.
- Auditor evidence export for a release.

Exit (7.6, 9.4): verify on a different host; changed artifact rejected; revoked identity rejected;
history verifiable after rotation; altered, removed, reordered audit events detected.

## M5: Model independence

Closes: B-05, section 4.

- Move NSL-KDD to `examples/` as a fixture; core stops assuming its columns, labels, model class.
- `ModelAdapter` contract with declared capabilities (gradients, probabilities, feature names,
  supported attacks) and explicit "unsupported".
- scikit-learn adapter first, ONNX second (PyTorch deferred per the plan).
- Safe loading: isolated worker container, CPU/memory/time/disk limits, non-root, no network,
  size and archive-extraction limits, digest recorded before any processing, original artifact immutable.
- Standard assessment input/output contract with per-check status
  (PASS, FAIL, WARNING, INCONCLUSIVE, NOT_APPLICABLE).

Exit (4.6): NSL-KDD still works through the adapter; a second sklearn model and an ONNX model are
assessed without core edits; invalid model file cannot crash the API; limits enforced; digest unchanged.

## M6: Evidence quality and policy engine

Closes: section 5, section 15.

- Robustness: stronger black-box test in the gate where applicable; record attack family, parameters,
  budget, sample count, confidence intervals, clean vs attacked metrics, attack success rate;
  "could not run" is INCONCLUSIVE; attacks chosen per model family.
- Poisoning: held-out evaluation with attack types and data sources the detector was not tuned on
  (label flip, feature manipulation, targeted, untargeted, several rates, legitimate distribution
  shift), fixed recorded seeds, recall, precision, FPR, FNR, AUC, confidence intervals, limitations.
  Wording: evidence and risk signal, never "prevents poisoning".
- Gate rework: add INCONCLUSIVE and NOT_APPLICABLE; hard blockers evaluated before any weighted score;
  stored formula version, policy version, per-control scores and weights, missing evidence, timestamp;
  old decisions stay reproducible (versioned formulas, no silent change).
- Dependencies: lock file, scanner and database context recorded, exceptions with owner, reason,
  expiry, approval; cache keyed on lock digest; freshness shown.
- CycloneDX SBOM for the app and serving images, with digests.
- Policy-as-code: versioned immutable policy documents, per-profile checks (tabular first; vision, NLP,
  time-series, custom defined as profiles with unsupported checks explicit), exceptions time-bounded.

Exit (5.8, 15.4): a failed-to-run check yields INCONCLUSIVE; integrity cannot be offset by score;
decisions reproducible from stored evidence and policy version; a policy changes without code edits.

## M7: Deployment lifecycle and incident redesign

Closes: B-04, sections 10 and 12.

- Separate deployment controller (not callable around the checks) with dev, staging, production
  environments; the 16-step sequence of section 10.4; PASS, BORDERLINE, FAIL, INCONCLUSIVE rules.
- Smoke tests, configurable canary schedule, promotion only when thresholds pass.
- First-class rollback to a verified previous release; failed release preserved.
- Serving: FastAPI kept, split cleanly from the governance API (Kubernetes/KServe explicitly deferred).
- Incident redesign: containment separated from recovery; no automatic retrain-and-redeploy;
  retrained candidate gets a new immutable release ID and goes through the full gate and approval;
  incident-to-release links; postmortem links all artifacts.

Exit (10.8, 12.4): PASS reaches staging, BORDERLINE needs approval, FAIL and INCONCLUSIVE blocked,
modified artifact cannot deploy, smoke failure stops promotion, canary failure triggers a tested rollback.

## M8: Observability

Closes: B-06, section 11.

- Prometheus metrics (API, workers, queue, DB, storage), Grafana dashboards, OpenTelemetry traces,
  centralized logs with correlation IDs, error reporting.
- Model monitoring (input and prediction distributions, drift, quality when labels arrive), with
  drift treated as a signal, never auto-classified as an attack, never auto-retrained.
- Security and operational monitoring and alert rules with severity and owner (section 11.6 table).
- Alert destination: **[OWNER]** provide e-mail/Slack/pager target; built against a local receiver first.

Exit (11.7): simulated outage alerts; simulated quality regression detected; monitoring survives restarts.

## M9: Pilot readiness

Closes: sections 14, 21, 22, readiness plan stage 1 completion.

- CI (static checks, Python and frontend tests, dependency and secret scans, image build and scan,
  integration tests, gate regression tests, SBOM) and CD (build once, sign, provenance, promote the
  same image digest).
- Test programme of section 21: unit, integration, end-to-end release, negative/security, reliability,
  load (capacity stated only from measurements).
- The 14 runbooks of section 22 (`DEPLOYMENT`, `CONFIGURATION`, `SECURITY`, `KEY_MANAGEMENT`,
  `BACKUP_RESTORE`, `INCIDENT_RESPONSE`, `ROLLBACK`, `MONITORING`, `POLICY_GUIDE`, `MODEL_ADAPTERS`,
  `DATA_RETENTION`, `DISASTER_RECOVERY`, `TROUBLESHOOTING`, `RELEASE_PROCESS`).
- Dashboard rebuilt to the section 16 sections (Overview, Projects, Model Registry, Assessments,
  Security Policies, Deployments, Monitoring, Incidents, Audit Trail, Users and Roles, Reports) with
  freshness, failed scans, inconclusive checks, digests, policy version, approver, rollout state.
- Pilot owner and support assigned: **[OWNER]**.

## M10: Production readiness

Closes: section 19 stages 2 and 3, section 24.

- Stage 2 cloud demo on one VM (**[OWNER]**: VM, domain, DNS, TLS, firewall, secrets, backups) following
  the 15-step list of section 19, with security and end-to-end tests run against it.
- Stage 3 (managed services, Kubernetes, KServe, multi-zone) is documented as driven by measured
  need, not built speculatively (readiness plan sections 18.1 and 25).
- Go-live checklist (section 24) filled in with evidence links; P0 items all closed; P1 exceptions
  formally recorded.

---

## Traceability: every section of the readiness plan

| Readiness plan | Where it is handled |
|---|---|
| 1 Executive summary, 2 Product boundary | Governs all work; "do not replace MLflow/Keycloak/Prometheus" enforced in M2, M3, M8 |
| 3 Blockers B-01 to B-10 | B-10 M0; B-07 M1; B-08 M2; B-01 M3; B-02, B-03, B-09 M4; B-05 M5; B-04 M7; B-06 M8 |
| 4 Workstream A (model-agnostic) | M5 |
| 5 Workstream B (evidence quality) | M6 (dependency part started in M0) |
| 6 Workstream C (auth, app security) | M3 |
| 7 Workstream D (trust, signing) | M4 |
| 8 Workstream E (storage) | M2 |
| 9 Workstream F (audit, governance) | M4 |
| 10 Workstream G (deployment) | M7 |
| 11 Workstream H (monitoring) | M8 |
| 12 Workstream I (incident response) | M7 |
| 13 Workstream J (containers) | M1, extended in M2, M3, M8 |
| 14 Workstream K (CI/CD) | M9 |
| 15 Workstream L (policy-as-code) | M6 |
| 16 Workstream M (dashboard) | M3 (login), M9 (rebuild) |
| 17 Architecture, 18 Stack | Target for M1 to M8; stack adopted in the staged order the plan gives |
| 19 Deployment stages | Stage 1 M1 to M9, stage 2 and 3 M10 |
| 20 User workflow | Becomes the end-to-end test in M9 |
| 21 Testing | Built per milestone, completed in M9 |
| 22 Runbooks | Written alongside each milestone, completed in M9 |
| 23 Milestones, priorities | This plan; P0 items are M0 to M4 plus M1 and M2 |
| 24 Go-live checklist | M10 |
| 25 Over-engineering list | Kept as constraints (no Kubernetes first, no custom auth, no custom registry, no auto-retrain) |
| 27 References | Consulted at implementation time for current versions |
