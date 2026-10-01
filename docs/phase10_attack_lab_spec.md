# Phase 10 — Attack Laboratory & Recovery Cycle Spec

Locked before code, same practice as every prior phase. This is the
capstone integration phase: it doesn't add a new detector (that was
Phases 5-6) — it proves the detectors, the gate (Phase 7), governance
(Phase 8), and the pipeline (Phase 3) all work together, live, against
real attacks, with automated recovery. Every number below was measured
against this project's real model before being locked here, not guessed
— see the empirical notes under each attack.

## Why this phase changes a few things that look "done"

Two existing modules were built as fast, CI-style checks (Phase 5's
calibration benchmark, Phase 6's surrogate-transfer robustness test) that
read/write a **fixed, stored** result file. This phase needs **live,
per-run** checks against whatever model a given pipeline run actually
produces (including a deliberately attacked one) — so:

- `src/security/gate.run_gate()` gains an optional `model_artifact_path` /
  `model_signature_path` override (defaults unchanged) so it can verify
  integrity of *this run's* model, not only the fixed production one.
- `src/security/sign_model.py` gains a reusable `sign_model_at(path, sig_path)`
  function (the CLI entry point's behavior is unchanged) so the recovery
  cycle can sign a freshly retrained model without duplicating the signing
  logic.
- New pipeline steps, `src/pipeline/data_scan.py` and
  `src/pipeline/model_scan.py`, call the *same* detector code Phase 5/6
  already wrote (`poisoning_detector`, `adversarial_test`'s building
  blocks), just against this run's staged/trained artifacts instead of the
  fixed calibration subsample — not a rewrite, a live wiring.

## Part A — Three attack scenarios, mapped to MITRE ATLAS

| # | Attack | ATLAS tactic | Detection mechanism |
|---|---|---|---|
| 1 | Data poisoning | Poisoning | `data_scan` (Phase 5's kNN detector, live) |
| 2 | Evasion (adversarial input) | Evasion | `model_scan` (direct black-box attack, live) |
| 3 | Model tampering | Persistence / ML Model Access | `model_scan` (Phase 5 signature check, live) |

### Attack 1 — Data poisoning

**Technique**: same random label-flip method as Phase 5's calibration
benchmark, but at **attack strength (40%)** instead of calibration
strength (10%) — this is the "sophisticated/aggressive attacker" case,
not a new technique. `src/pipeline/ingest.py`'s existing
`MLSHIELD_INGEST_TRAIN_SOURCE` override (already used for Phase 3's
corrupted-input test) points at a pre-poisoned copy of `KDDTrain+.txt`.

**Measured before locking** (same detector, same `k=15`/`threshold=0.5`
as Phase 5, on the real training subsample): recall drops from 0.965 (at
10%, Phase 5's calibration point) to **0.777**, and FPR rises from 0.029
to **0.237**, at a 40% poison rate. Feeding that into the locked
`data_score` formula: `100 - 60*(1-0.777) - 40*clamp(0.237/0.10,0,1)
≈ 46.6` — a substantial degradation from a clean run's ~85-100.

**Expected gate outcome**: with model/dependency sub-scores unaffected,
`security_score ≈ 0.35*46.6 + 0.40*(~98) + 0.25*(~70-100) ≈ 73-77` —
**BORDERLINE**, not FAIL. This is realistic and worth stating plainly:
a 40%-poisoned dataset doesn't make the *rest* of the system bad, so the
composite score reflects a real, partial risk signal, not a blanket
failure — exactly the graduated response the gate was designed to produce
(docs/security_gate_formula.md).

### Attack 2 — Evasion (adversarial input)

**Technique switch from Phase 6, and why**: Phase 6's surrogate-transfer
FGSM attack was re-tested here directly (single-step, iterative/PGD, small
and large epsilon, restricted and unrestricted feature surface) and
**could not** push degradation past ~3% in any configuration — a genuine
finding that RandomForest ensembles have low transferability from a
simple linear surrogate, not a bug to chase further. Phase 6's test
remains valid and correct for what it is: a fast, practical CI regression
check. For the attack lab specifically — which can afford to be slow and
wants to model a more determined, realistic adversary with only **query
access to the live API** (exactly what Phase 4's `/predict` endpoint
actually exposes to the outside world) — this phase uses **ART's
`HopSkipJump`**, a direct, decision-based black-box attack against the
real RandomForest itself (no surrogate, no gradients needed).

**Measured before locking**: `max_iter=10, max_eval=200, init_eval=50`,
20 correctly-classified `KDDTest+.txt` points (fixed seed): clean
accuracy 1.00 → adversarial accuracy 0.65, **35% degradation**, in ~23
seconds. This comfortably and reliably crosses the locked 30%
`max_allowed_degradation` bar from `docs/security_gate_formula.md`.

**Expected gate outcome**: `robustness_component` clamps to 0 (since
degradation exceeds the bar), `model_score = 0.5*100 + 0.5*0 = 50`
(integrity still intact in this scenario). `security_score ≈
0.35*(~85-100) + 0.40*50 + 0.25*(~70-100) ≈ 70-80` — **BORDERLINE**, by
the same margin-of-real-risk logic as the poisoning case.

### Attack 3 — Model tampering

**Technique**: identical to Phase 5's 10-case tampering test (byte flip),
applied live to a freshly-trained model artifact before registration,
instead of to the fixed production artifact in a unit test.

**Expected gate outcome**: `integrity_component = 0` →
`decide()`'s hard override fires regardless of the composite score —
**FAIL**, deterministically, every time (already proven exactly via
Phase 7's `integrity_override_fail` scenario; this phase proves it live).

## Part B — Recovery cycle

```
ATTACK/DETECTION
       |
       v
  [security_gate_evaluated, logged to audit log]
       |
  +----+-----------------+
  |                       |
FAIL                 BORDERLINE
  |                       |
  |                 [Approver reviews the evidence
  |                  (degraded sub-score + its cause)
  |                  and REJECTS - a correct human
  |                  judgment call given known-attack
  |                  evidence, recorded via Phase 8's
  |                  approve_or_reject(), justification
  |                  citing the specific finding]
  |                       |
  +-----------+-----------+
              |
              v
        QUARANTINE
  (attacked artifact moved aside, never deleted -
   preserved for the postmortem/forensics, never reachable
   via the registered model name again)
              |
              v
          RETRAIN
  (on the ORIGINAL Phase 0 locked, hash-verified raw data -
   src/pipeline/ingest.py with NO source override, so recovery
   can never accidentally retrain on the same poisoned/attacked
   input)
              |
              v
         REVALIDATE
  (full gate re-run against the newly retrained model -
   data_scan + model_scan, using the STANDARD fast checks,
   not the attack lab's expensive direct techniques - revalidating
   robustness of a clean model doesn't need the slow query-based
   attack, only confirming it still clears the bar)
              |
         +----+----+
         |         |
       PASS    (anything else - logged as a new
         |      incident, cycle does not silently retry)
         v
      REDEPLOY
  (src/pipeline/register.py - the same registration path
   Phase 3's normal pipeline uses, not a parallel one)
```

**No manual code changes at any step** — the orchestrator
(`src/recovery/cycle.py`) calls the same `src/pipeline/*.py`,
`src/security/*.py`, and `src/governance/*.py` functions every other
phase already wrote and tested; "automated recovery" means exactly that
here, not a hand-run script with edits between steps.

## Part C — Incident postmortem (auto-populated)

Generated by `src/incident/postmortem.py`, one per detected attack, fields
locked here (not freeform prose):

```json
{
  "incident_id": "<uuid>",
  "detected_at": "<ISO timestamp>",
  "attack_type": "data_poisoning | evasion | model_tampering",
  "atlas_tactic": "Poisoning | Evasion | Persistence / ML Model Access",
  "detection_mechanism": "data_scan | model_scan (integrity) | model_scan (robustness)",
  "evidence": { <the specific sub-score(s) and raw metrics that triggered detection> },
  "gate_decision": "FAIL | BORDERLINE",
  "action_taken": "quarantined_immediately | quarantined_after_approver_rejection",
  "approval_record": { <actor, role, justification, timestamp> or null if FAIL (no approval step applies) },
  "recovery_outcome": "redeployed_clean | recovery_failed",
  "linked_audit_log_seqs": [<every audit log entry seq number tied to this incident>],
  "postmortem_summary": "<one auto-composed paragraph, built from the fields above by template, not hand-written per incident>"
}
```

A postmortem is generated whether recovery succeeds or not — a failed
recovery is itself an incident-worthy fact, not something to leave
unrecorded.

## Part D — Test protocol

Each of the three attack scenarios is run **twice**, start to finish,
against the live system (real training, real detectors, real gate, real
audit log) — "to rule out a lucky single run" (project plan, Phase 10
Test). For each run: confirm the expected decision category (BORDERLINE
for poisoning/evasion, FAIL for tampering), confirm recovery completes
without manual intervention beyond the one designed approval step,
confirm a complete postmortem is generated, and confirm the retrained
model that comes out the other side genuinely PASSes (not just "didn't
error").

## Phase 10 gate

1. All three attack types detected, and each correctly produces its
   expected decision category, on both runs (6 total attack runs).
2. Recovery completes automatically in every run — only the BORDERLINE
   cases' approval step involves a human-shaped action (the simulated
   Approver rejection), and even that is a real call through Phase 8's
   RBAC, not a bypass.
3. Every run produces a complete postmortem record with every field
   populated (or explicitly null where structurally inapplicable, e.g.
   `approval_record` for a FAIL case — never silently missing).
