# Phase 1 — ML Baseline Spec

Locked before training code is written or run, per the stage-gate rule: the
bar is decided first, not fitted to whatever number comes out.

## Task framing

**Binary classification: `normal` vs `attack`.** NSL-KDD's raw `label`
column has ~23 distinct attack types across 4 attack categories (DoS, Probe,
R2L, U2R). MLShield's security gate cares about "is this compromised /
should this be blocked", not which of 23 attack families it is — multi-class
attack typing is not needed for the MVP's gate decision and is out of scope
here (could be revisited as a Phase-2-maturity item, not now). So:

```
binary_label = "normal" if label == "normal" else "attack"
```

## Preprocessing

- Categorical features (`protocol_type`, `service`, `flag`) → one-hot
  encoded, `handle_unknown="ignore"` (NSL-KDD's `KDDTest+.txt` is known to
  contain `service` values not present in `KDDTrain+.txt` — this is a
  documented property of the dataset, not a bug, so it must not crash
  evaluation).
- Numeric features → passed through unscaled (tree-based model, doesn't
  need scaling).
- `difficulty` column dropped — it's a KDD-specific metadata field (how hard
  a record was to classify in the original 1999 competition), not a real
  network feature, and using it would leak information not available at
  inference time.

## Model

**RandomForestClassifier** (scikit-learn), `n_estimators=200`,
`random_state=42`, `n_jobs=1` (single-threaded specifically so tree
construction order cannot introduce run-to-run nondeterminism — speed is
not a concern at this dataset size). This is a deliberately simple,
well-understood baseline; no security-specific behavior expected or wanted
here — that's Phase 5+.

## Evaluation

Two held-out sets, evaluated on the model trained on Phase 0's fixed-seed
train split:

1. **Phase 0 validation split** (20% held out from `KDDTrain+.txt`, same
   distribution as training) — sanity check the model learned anything at
   all.
2. **`KDDTest+.txt`** (NSL-KDD's official held-out test set) — the real
   gate metric. This set is deliberately constructed by the dataset's
   authors to include attack records **not present in `KDDTrain+.txt`**, to
   stop models from just memorizing known attack signatures. This is
   documented dataset behavior, not noise.

Metrics: accuracy, precision, recall, F1 (binary, `attack` as positive
class), confusion matrix. Plus 5-fold stratified cross-validation F1 on the
training split, to check the baseline isn't unstable across folds.

## Minimum performance bar (locked before running)

**F1 ≥ 0.75 on `KDDTest+.txt`.**

This is set below the ≥0.85 example figure in the project plan, and that's
a deliberate, documented call, not a lowered bar to pass: NSL-KDD's
`KDDTest+.txt` is well known in the literature to cap simple-classifier
performance around 0.75-0.80 F1 precisely *because* it contains novel
attack types absent from training (e.g. Tavallaee et al.'s own analysis,
and it's the reason NSL-KDD replaced the original KDD'99 test set — KDD'99
had near-100% scores that turned out to be memorization, not detection). A
score conspicuously above ~0.90 on this specific test file would be a
signal of a data leak (e.g. `difficulty` column or `KDDTest+` rows leaking
into training) rather than a better model, and should be treated as a bug,
not a win.

The Phase 0 validation split (same-distribution) is expected to score much
higher (>0.99 is normal here) — that number is reported but is **not** the
gate metric, precisely because it's the easy, same-distribution one.

## Reproducibility tolerance

Retraining from the same Phase 0 split with `random_state=42` must
reproduce every reported metric **exactly** (not "within tolerance") —
`RandomForestClassifier` with a fixed seed and `n_jobs=1` is fully
deterministic, so any drift between two runs is a bug (e.g. an
unseeded step in preprocessing) and fails the gate, not a rounding
allowance.

## Gate (Phase 1)

1. F1 on `KDDTest+.txt` ≥ 0.75.
2. Two independent training runs (same code, same split) produce bit-identical
   metrics.
3. 5-fold CV F1 on the training split has a standard deviation < 0.05
   (baseline isn't wildly unstable across folds).
