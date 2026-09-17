# Phase 5 — Security Gate v1 Spec (Data Scan + Model Integrity Scan)

Locked before detector/signing code is written, same practice as every
prior phase. The recall/FPR target below is not new — it was already
committed in Phase 0's `docs/security_gate_formula.md` §1.1, before any
detector existed. This document adds the *method* and *test protocol*
that target has to be met with.

## Part A — Data Scan: poisoning detection

### Threat model

Data poisoning in this project's ATLAS mapping (see the project plan) is
training-data manipulation. For a binary normal/attack classifier, the
simplest, most realistic poisoning attack is **label flipping**: an
attacker who can influence a slice of training data flips `attack` labels
to `normal` (to make future attacks of that type "look normal" to the
trained model) or vice versa. This is what the injection test below
simulates — not a synthetic, unrealistic attack, but the textbook one for
this task shape.

### Method: k-NN label-consistency filter

**Named technique**: k-Nearest-Neighbors label-consistency filtering (a
long-standing approach to mislabeled/noisy/poisoned sample detection —
related to Wilson's Edited Nearest Neighbor rule). Concretely:

1. Preprocess training features the same way the model does (categorical
   one-hot, numeric passthrough — reuses `build_pipeline`'s preprocessing
   step from `src/models/train_baseline.py`, not a separate encoding).
2. For each training sample, find its `k` nearest neighbors **by feature
   distance**, excluding itself.
3. Compute `agreement = (# neighbors sharing this sample's label) / k`.
4. Flag the sample as **suspected poisoned** if `agreement < threshold`
   (majority of its feature-space neighbors disagree with its label).

Rationale: label-flipping poisoning breaks *local* label consistency — a
flipped sample now has a label that contradicts its feature-space
neighborhood, which otherwise reflects genuine attack/normal structure.
This is a detection method, not a robustness guarantee — a poisoner who
also perturbs features to escape their neighborhood is a harder threat
(model tampering / adversarial territory, Phase 6), out of scope here.

**Why this method over an alternative** (e.g. Isolation Forest anomaly
detection): label-flipping poisoning doesn't necessarily make a sample
look *globally* anomalous (an anomaly detector might miss it) — it makes
the sample locally inconsistent with same-labeled neighbors, which is
exactly what kNN agreement measures directly. It's also simple enough to
be auditable by a human reviewer without a black-box model of its own,
which matters for this project's SDG 16 transparency goal — a poisoning
*detector* that is itself an opaque ML model would undercut that.

### Parameters (locked before calibration)

- `k = 15` neighbors.
- `agreement_threshold = 0.5` (flag if fewer than half of neighbors share
  the sample's label — a simple majority rule, not a tuned magic number).
- Computed on a **fixed-size random subsample** of the training split
  (`n = 8000`, `random_state = 42`) rather than the full ~100k rows —
  documented compute-budget decision: brute-force kNN is O(n²)-ish and a
  production system would need an approximate-nearest-neighbor index
  (out of scope for the MVP); the subsample is large enough to be
  statistically meaningful for the recall/FPR measurement below and the
  sampling is itself fixed-seed and reproducible.

If calibration testing (below) cannot meet the locked recall/FPR bar with
these parameters, the parameters get revisited **and this doc gets
updated with the reason** — not silently tuned in code until a number
appears.

### Injection test protocol (ground truth for recall/FPR)

1. Take the same fixed subsample described above.
2. Randomly select `poison_rate = 10%` of samples (fixed seed) and flip
   their label (`normal` → `attack` or `attack` → `normal`). This is the
   ground-truth poisoned set.
3. Run the kNN detector on the resulting (partially poisoned) subsample.
4. Compare flagged samples against the ground-truth poisoned set:
   - **Recall** = (flagged ∩ poisoned) / poisoned — did we catch the
     injected poison?
   - **False positive rate** = (flagged ∩ NOT poisoned) / NOT poisoned —
     how often do we wrongly flag a clean, legitimately-labeled sample?

### Gate target (locked in Phase 0, restated here)

**Recall ≥ 0.80 at false-positive rate ≤ 0.10**, on the injection test
above. This is the same number `docs/security_gate_formula.md` already
commits to using for `data_score` — Phase 5's job is to prove a real
detector can hit it, not to pick a new number that happens to be
achievable.

## Part B — Model Scan: artifact integrity (cryptographic signing)

### Why signing, not just a hash

A bare content hash (already used for the raw dataset and DVC artifacts
in Phases 0-2) proves a file wasn't *accidentally* corrupted, but proves
nothing about *authorized origin* — anyone can recompute a hash over a
tampered file and publish the new hash as if it were legitimate. Signing
proves the artifact was produced/approved by whoever holds the private
key. This is the actual reason `docs/security_gate_formula.md` calls this
check "signature/hash verification" and treats a failure as a hard
override on the whole gate, not just a scoring penalty.

### Scheme

- **Ed25519** asymmetric signing (via the `cryptography` library) —
  smaller keys/signatures than RSA, fast, no configurable parameters to
  get wrong (no key-size/padding-scheme choices that could be misused).
- A private signing key is generated once and kept **outside the repo**
  (a real deployment would use a proper KMS/HSM; simulating that boundary
  here by keeping the key file out of version control, `.gitignore`d, and
  documented as a stand-in for real key management — same treatment as
  the Docker/DVC-remote MVP stand-ins from earlier phases).
- The public key **is** committed to the repo (`security/signing_public_key.pem`)
  — verification must be possible by anyone who has this repo, without
  needing access to the private key.
- Signing target: the SHA-256 digest of the model artifact
  (`models/baseline_model.joblib`) — sign the hash, not the whole file
  in one pass, so the same pattern scales to signing large artifacts
  without loading them entirely for the crypto operation.

### Tampering test protocol

1. Sign the current, legitimate model artifact. Confirm verification
   passes.
2. Produce 10 independently-tampered copies of the artifact (different
   byte-level modifications — e.g. flip one byte at different offsets,
   truncate, append data, zero out a chunk). For each, confirm signature
   verification **fails**.
3. Confirm the original, unmodified artifact still verifies (i.e. the
   test isn't just "verification always fails").

### Gate target

**10/10 tampered copies correctly fail verification, and the legitimate
artifact correctly passes.** No partial credit — per
`docs/security_gate_formula.md` §1.2, `integrity_component` is binary by
design (100 or 0), so the check itself must be binary and exact.

## Phase 5 gate (both parts required)

1. Poisoning detector: recall ≥ 0.80 at FPR ≤ 0.10 on the injection test.
2. Tampering check: 10/10 tampered artifacts rejected, legitimate artifact
   accepted.
