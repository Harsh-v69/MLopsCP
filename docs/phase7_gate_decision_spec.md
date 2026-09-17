# Phase 7 — Security Scoring & Gate Decision Logic Spec

Locked before `src/security/gate.py` is written. This phase implements
`docs/security_gate_formula.md` as code — it does not change the formula's
structure, weights, or PASS/BORDERLINE/FAIL thresholds, only its
`dependency_score` input availability (see that file's Phase 7 amendment,
made via its own documented change-control process before this spec was
written).

## How each sub-score is sourced

| Sub-score | Source |
|---|---|
| `data_score` | `recall` / `false_positive_rate` read from `data/processed/phase5_poisoning_eval.json` (Phase 5's stored injection-test result — not re-run live, since it's an offline evaluation of the fixed detector against a fixed ground-truth injection, not something that changes run to run) |
| `model_score` (integrity half) | **Live** — `src/security/verify_model.py`'s `verify()` run against the current `models/baseline_model.joblib` and its signature. Live, not cached, because integrity is exactly the kind of thing that must be checked at gate-evaluation time, not assumed from a past record. |
| `model_score` (robustness half) | `clean_accuracy` / `adversarial_accuracy` read from `data/processed/phase6_adversarial_eval.json` (Phase 6's stored result — same reasoning as `data_score`: an offline evaluation, not re-run live) |
| `dependency_score` | **Live** — `src/security/dependency_scan.py`'s `run_pip_audit()` against the current `requirements.txt`. Live, not cached, because new CVEs get published against unchanged code — a dependency's risk posture can change without this project changing at all. |

A missing or unreadable input file, or a live check that raises instead of
returning cleanly, is caught and treated as that sub-score = 0
(fail-closed — same rule `docs/security_gate_formula.md` §1 already
states for "a missing scan").

## Code structure

Pure, independently-testable functions for each formula piece — no file
I/O, no network calls inside them — plus one integration function that
wires them to real data:

- `compute_data_score(recall, fpr) -> float`
- `compute_model_score(integrity_ok, clean_accuracy, adversarial_accuracy) -> (model_score, integrity_component)`
- `compute_dependency_score(vulnerability_count) -> float`
- `compute_security_score(data_score, model_score, dependency_score) -> float`
- `decide(security_score, integrity_component) -> "PASS" | "BORDERLINE" | "FAIL"`
- `run_gate() -> GateResult` — the integration entry point; reads the real
  files, runs the live checks, calls the pure functions above, and
  returns every sub-score plus the final decision (never just the
  decision alone — auditability requires showing the working, per the
  SDG 16 "rule of law" framing already established in
  `docs/security_gate_formula.md`).

## Locked test scenarios (expected values computed and fixed before the

test file is written — not derived by running the code and copying its
output)

All values below were computed independently in Python against the
formula as written, not read off a first implementation run.

### End-to-end scenarios (all three sub-scores → decision)

| # | Name | Inputs | data_score | model_score | dependency_score | security_score | Decision |
|---|---|---|---|---|---|---|---|
| 1 | `clear_pass_perfect` | recall=1.0, fpr=0.0, integrity=OK, clean=1.0, adv=1.0, vulns=0 | 100 | 100.0 | 100 | 100.0 | **PASS** |
| 2 | `real_project_numbers` | recall=0.96625, fpr=0.0325 (Phase 5's actual stored result), integrity=OK, clean=1.0, adv=0.99 (Phase 6's actual stored result), vulns=2 (this project's actual current dependency scan) | 84.975 | 98.3333... | 80 | 89.0746 (rounded) | **PASS** |
| 3 | `clear_fail_everything_bad_integrity_ok` | recall=0.0, fpr=1.0, integrity=OK, clean=1.0, adv=0.0 (100% degradation), vulns=10 | 0 | 50.0 | 0 | 20.0 | **FAIL** |
| 4 | `integrity_override_fail` | recall=1.0, fpr=0.0, **integrity=FAILED**, clean=1.0, adv=1.0, vulns=0 | 100 | 50.0 | 100 | 80.0 | **FAIL** (hard override — score alone would read PASS at exactly 80.0; this is the actual proof the override works, not just documentation of intent) |

Scenario 2 is cross-checked against a live `run_gate()` call in the test
suite too — not just the pure-function scenario — so the wiring itself
(reading the real Phase 5/6 files, running the real live checks) is
verified, not only the arithmetic.

### `decide()` boundary scenarios (direct, to hit exact boundaries cleanly)

| # | Name | security_score | integrity_component | Decision |
|---|---|---|---|---|
| 5 | `boundary_pass_at_exactly_80` | 80.0 | 100 | **PASS** (`>=80` is inclusive) |
| 6 | `boundary_borderline_just_under_80` | 79.999 | 100 | **BORDERLINE** |
| 7 | `boundary_borderline_at_exactly_50` | 50.0 | 100 | **BORDERLINE** (`>=50` is inclusive) |
| 8 | `boundary_fail_just_under_50` | 49.999 | 100 | **FAIL** |
| 9 | `boundary_pass_at_100` | 100.0 | 100 | **PASS** |
| 10 | `boundary_fail_at_0` | 0.0 | 100 | **FAIL** |

### `compute_data_score` component scenarios

| # | Name | recall | fpr | Expected |
|---|---|---|---|---|
| 11 | `data_score_exactly_at_phase5_bar` | 0.80 | 0.10 | **48.0** — worth stating explicitly: this is *not* a bug. The formula measures distance from a *perfect* detector (recall=1, fpr=0), not distance from the Phase 5 pass/fail bar. A detector that just barely clears Phase 5's own gate (recall≥0.80, fpr≤0.10) still costs 52 points here, because `fpr=0.10` alone saturates the fpr penalty term fully (`clamp(0.10/0.10,0,1)=1` → full 40-point penalty) and `recall=0.80` is 20 points of "missing recall" on the 60-point recall term. This sub-score is intentionally stricter than Phase 5's own pass bar. |
| 12 | `data_score_recall_partial` | 0.50 | 0.0 | **70.0** |
| 13 | `data_score_fpr_partial` | 1.0 | 0.05 | **80.0** |

### `compute_model_score` component scenarios

| # | Name | integrity | clean_acc | adv_acc | Expected (model_score, integrity_component) |
|---|---|---|---|---|---|
| 14 | `model_score_at_max_degradation` | OK | 1.0 | 0.70 (exactly the 0.30 max) | **(50.0, 100.0)** — robustness bottoms out to 0 exactly at the bar, not before |
| 15 | `model_score_zero_degradation` | OK | 1.0 | 1.0 | **(100.0, 100.0)** |

### `compute_dependency_score` component scenarios

| # | Name | vulnerability_count | Expected |
|---|---|---|---|
| 16 | `dep_score_zero_vulns` | 0 | **100** |
| 17 | `dep_score_three_vulns` | 3 | **70** |
| 18 | `dep_score_at_cap` | 10 | **0** |
| 19 | `dep_score_over_cap` | 15 | **0** (capped, not negative) |

### Fail-closed / missing-scan scenarios (integration level, `run_gate()`)

| # | Name | Setup | Expected |
|---|---|---|---|
| 20 | `fail_closed_missing_poisoning_eval` | `data/processed/phase5_poisoning_eval.json` path patched to a nonexistent file | `data_score` forced to 0, not skipped or defaulted to something permissive |
| 21 | `fail_closed_dependency_scan_raises` | `run_pip_audit` patched to raise an exception | `dependency_score` forced to 0, `run_gate()` does not crash |

## Phase 7 gate

Every one of the 21 scenarios above must produce **exactly** the
documented expected value/decision — no undocumented logic, no silent
tie-breaking (project plan, Phase 7 Validate). A live `run_gate()` call
against this project's real current state must also complete without
error and match scenario 2's expected decision.
