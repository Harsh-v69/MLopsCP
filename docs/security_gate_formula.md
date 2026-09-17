# MLShield Security Gate — Score Formula & Thresholds

Locked in Phase 0, before any detection code exists (per the Phase 0 gate: an
undefined scoring formula is the single biggest risk in this plan — this
document exists to remove that risk before Phase 5-7 implement it).

This formula is provisional in its per-check numeric assumptions (e.g. what
"good" recall looks like) but the **structure, weights, and PASS/BORDERLINE/FAIL
thresholds are locked** and must not change silently once Phase 5-7 start
depending on them. Any change after that point must be a reviewed edit to this
file, with the reason recorded in `progress.md`.

## 1. Inputs

The gate combines three sub-scores, one per scan implemented in Phase 5-6:

| Sub-score | Produced by | Range |
|---|---|---|
| `data_score` | Data Scan (poisoning detection) | 0-100 |
| `model_score` | Model Scan (artifact integrity + adversarial robustness) | 0-100 |
| `dependency_score` | Dependency Scan (vulnerability + SBOM check) | 0-100 |

Each sub-score is itself a combination of pass/fail checks and measured
metrics, defined below. All three must be present for the gate to run; a
missing scan is treated as `0` for that sub-score (fail-closed, not
fail-open — a scan that didn't run is not evidence of safety).

### 1.1 `data_score` (Poisoning Detection)

```
data_score = 100
  - 60 * clamp(1 - recall_at_target_fpr, 0, 1)   # detector must catch injected poison
  - 40 * clamp(false_positive_rate / max_allowed_fpr, 0, 1)
```

- Target defined per Phase 5 gate: recall ≥ 0.80 at false-positive rate ≤ 0.10
  on the controlled poisoning-injection test set.
- `recall_at_target_fpr` and `false_positive_rate` are measured against a
  labeled validation set with known-injected poisoned samples (ground truth),
  not against production data (where ground truth doesn't exist).

### 1.2 `model_score` (Integrity + Adversarial Robustness)

```
model_score = 0.5 * integrity_component + 0.5 * robustness_component

integrity_component =
  100 if artifact signature/hash verification passes
  0   if it fails (binary — a tampered artifact is never "partially" trusted)

robustness_component =
  100 * clamp(1 - (clean_accuracy - adversarial_accuracy) / max_allowed_degradation, 0, 1)
```

- `max_allowed_degradation` is set per Phase 6 gate (e.g. accuracy must not
  drop more than 30 percentage points under the fixed-budget FGSM/PGD test);
  the exact number is finalized when the adversarial test is built, but the
  formula shape is locked now.
- Integrity is binary and weighted first in the `min()` sense conceptually:
  see Section 3 override rule — a failed integrity check overrides the whole
  gate regardless of arithmetic score.

### 1.3 `dependency_score` (Supply Chain)

> **Amended in Phase 7** (see `progress.md` Phase 7 section for the full
> reasoning) — the original severity-tiered formula below this note is
> kept for the record, struck through, per this file's own §5 change
> control ("be made via a normal commit, noted in progress.md"). It was
> never implemented against real data.
>
> ~~```~~
> ~~dependency_score = 100~~
> ~~  - 100 if any CRITICAL-severity vulnerability found~~
> ~~  - 25 * count(HIGH-severity vulnerabilities, capped at 4)~~
> ~~  - 5  * count(MEDIUM-severity vulnerabilities, capped at 10)~~
> ~~  (floor at 0)~~
> ~~```~~
>
> **Reason for the change**: Phase 6 locked `pip-audit` (against OSV.dev,
> via PyPI's own JSON API) as the dependency scanner. Neither pip-audit's
> output, nor PyPI's vulnerability API, nor OSV.dev's own API (blocked by
> this environment's network policy — confirmed via a direct request, not
> assumed) provide a CRITICAL/HIGH/MEDIUM severity classification for
> findings — OSV-sourced records here carry an id, aliases (CVE/GHSA),
> and a description, but no CVSS score or severity tier. The severity
> tiers this formula originally assumed are not obtainable data in this
> project's actual toolchain, in this environment. Rather than fabricate
> severity labels (which would make the score look more rigorous than it
> is — directly against this project's own SDG 16 transparency goal), the
> formula is revised to use what the scanner actually and reliably
> provides: a vulnerability **count**.

```
dependency_score = 100 - 10 * min(vulnerability_count, 10)
  (floor at 0 — i.e. 10 or more findings scores 0)
```

- `vulnerability_count` = total number of vulnerability findings pip-audit
  reports across all scanned packages (not deduplicated by CVE — the same
  underlying CVE reported against two different vulnerable packages counts
  twice, since both are real, independent supply-chain exposures).
- A missing/unparseable SBOM, or a scan that fails to run at all, is
  treated as a scan failure (sub-score = 0), not skipped — unchanged from
  the original formula's fail-closed rule.
- If a future environment/toolchain change makes real severity data
  available (e.g. running outside this network-restricted sandbox, or
  adding a scanner/API with CVSS support), the severity-tiered formula
  above can be reinstated — that would itself be a Phase-7-style
  documented amendment, not a silent revert.

## 2. Composite Security Score

```
security_score = 0.35 * data_score + 0.40 * model_score + 0.25 * dependency_score
```

Weighting rationale: model integrity/robustness is weighted highest (0.40)
because a tampered or trivially-evadable model is the most direct path to a
bad production outcome; data poisoning next (0.35) since it's the more novel
detection problem this project builds; dependency risk last (0.25) since it's
the most mechanical/well-tooled of the three.

## 3. Decision Thresholds

```
if integrity_component == 0:
    decision = FAIL          # hard override — a tampered artifact never deploys,
                              # regardless of composite score
elif security_score >= 80:
    decision = PASS
elif security_score >= 50:
    decision = BORDERLINE
else:
    decision = FAIL
```

| Decision | Range | Action |
|---|---|---|
| **PASS** | `security_score >= 80` (and integrity check passed) | Auto-deploy; audit log entry written, no human approval required |
| **BORDERLINE** | `50 <= security_score < 80` | Routed to human approval (RBAC-gated `Approver` role, Phase 8); deploy only on recorded approval |
| **FAIL** | `security_score < 50`, or integrity check failed | Blocked; artifact quarantined; incident postmortem opened (Phase 10) |

These threshold numbers (80 / 50) are the ones referenced everywhere else in
the project plan (Section 7 "Security Scoring & Gate Decision Logic",
Phase 7 gate). They are deliberately round for auditability — an auditor
should be able to recompute a decision by hand from the three sub-scores
without needing this codebase.

## 4. Non-goals for this formula

- It does not claim statistical optimality — it is a transparent, auditable,
  hand-checkable rule set, which is the point (see SDG 16 "rule of law
  equivalent" framing in the project plan). A more sophisticated learned
  scorer is explicitly out of scope.
- It does not adapt per-model-class in the MVP. Multi-tier risk weighting by
  model class is listed as Phase 2 (post-MVP) governance maturity work.

## 5. Change control

Any change to the weights, sub-score formulas, or thresholds above must:

1. Be made in this file via a normal commit (not silently in code).
2. Be noted in `progress.md` with the date and reason.
3. Not be back-dated to apply to already-recorded audit log entries — past
   gate decisions are evaluated under the formula in effect at the time.
