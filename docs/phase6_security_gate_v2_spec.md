# Phase 6 — Security Gate v2 Spec (Adversarial Test + Dependency Scan)

Locked before code, same practice as every prior phase. Part A's bar
(`max_allowed_degradation`) restates a number already floated as the
illustrative example in `docs/security_gate_formula.md` §1.2 back in
Phase 0 — adopting it here rather than picking a new number post-hoc.

## Part A — Adversarial robustness test

### The model has no gradients — why FGSM/PGD can't be applied directly

The project plan's example names FGSM/PGD via IBM's Adversarial
Robustness Toolbox (ART). Both are **gradient-based** attacks: they need
`∂loss/∂input` from the model itself. Phase 1's model is a
`RandomForestClassifier` — a non-differentiable ensemble of decision
trees. There is no gradient to take. Running FGSM directly against it is
not possible, not just impractical, and pretending otherwise (e.g. by
approximating a "gradient" some ad hoc way) would produce a number that
doesn't mean what it claims to mean.

### Method: FGSM against a differentiable surrogate, transferred to the real model

This is a named, published technique — **transfer-based black-box
attack via a substitute model** (Papernot et al., 2016, "Practical
Black-Box Attacks against Machine Learning"). Concretely:

1. Train a **differentiable surrogate** — `sklearn.linear_model.LogisticRegression`
   — on the same preprocessed feature space (categorical one-hot +
   numeric passthrough, identical encoding to `build_pipeline`) to
   approximate the RandomForest's binary decision boundary. The surrogate
   does not need to match the RandomForest's accuracy; it needs to
   approximate its decision boundary well enough that perturbations
   crafted against it transfer.
2. Wrap the surrogate in ART's `SklearnClassifier` (ART implements exact,
   closed-form gradients for `LogisticRegression` — no autograd
   framework, no PyTorch/TensorFlow dependency needed).
3. Run ART's `FastGradientMethod` (single-step FGSM, `eps_step = eps`) on
   a fixed sample of correctly-classified test points, generating
   adversarial perturbations against the **surrogate**.
4. **Transfer**: apply the same perturbed inputs to the real,
   production RandomForest and measure its accuracy on them.

This is why ART is still the right tool named in the plan (it supplies
both the FGSM implementation and the exact-gradient sklearn wrapper) even
though the target model itself can't be attacked directly.

### Attack surface: which features are perturbable

Only the **15 rate features** (`serror_rate`, `srv_serror_rate`,
`rerror_rate`, `srv_rerror_rate`, `same_srv_rate`, `diff_srv_rate`,
`srv_diff_host_rate`, `dst_host_same_srv_rate`, `dst_host_diff_srv_rate`,
`dst_host_same_src_port_rate`, `dst_host_srv_diff_host_rate`,
`dst_host_serror_rate`, `dst_host_srv_serror_rate`,
`dst_host_rerror_rate`, `dst_host_srv_rerror_rate`) are perturbed, via
ART's `mask` parameter. Everything else — categorical one-hot dimensions,
integer counts, binary flags — is held fixed. Two reasons, not one:

- These are the only genuinely continuous, naturally-fractional features
  in the schema (already documented as `[0.0, 1.0]`-bounded in
  `docs/phase4_api_spec.md`). Perturbing an integer count field by a
  fractional epsilon would produce an input the API itself would reject
  (`422`) — an "attack" that can't actually be submitted isn't a real
  threat model.
- Perturbing one-hot categorical dimensions by a small continuous epsilon
  produces meaningless fractional category memberships with no
  real-world interpretation.

After perturbation, values are clipped back to `[0.0, 1.0]` — the same
bound the API itself enforces, so every adversarial example this test
produces is, by construction, a submittable, schema-valid request.

### Parameters (locked before running)

- `epsilon = 0.05`, L∞ norm — a small perturbation relative to the
  feature's full `[0,1]` range (5% of the range), standard magnitude in
  tabular adversarial-robustness literature for `[0,1]`-normalized
  features.
- Single-step FGSM (`eps_step = epsilon`), not iterative PGD — chosen for
  the same reliability reason the kNN poisoning detector was chosen over
  a noisier alternative in Phase 5: FGSM is a single deterministic
  gradient computation, so repeated runs must produce identical results
  (a gate requirement below), whereas iterative/randomized attacks are
  harder to make bit-reproducible without extra care.
- Evaluated on a fixed sample of **100 correctly-classified points** from
  `KDDTest+.txt` (fixed seed = 42) — only correctly-classified points,
  because degradation on a point the model already gets wrong isn't a
  meaningful robustness signal.

### Gate target

**`max_allowed_degradation = 30 percentage points`** — adopting the
number `docs/security_gate_formula.md` already floated as its own
illustrative example in Phase 0, rather than choosing a new one now that
the real result is known. I.e.: `clean_accuracy - adversarial_accuracy <= 0.30`.

**Reproducibility requirement**: two independent runs of the attack (same
code, same seeds) must produce bit-identical `clean_accuracy` and
`adversarial_accuracy` — this is what "reliably reproduces... not
flaky/random" (project plan, Phase 6 Test) means operationally.

## Part B — Dependency scan + SBOM

### Tooling

- **`pip-audit`** — scans installed/declared dependencies against the
  OSV.dev vulnerability database (confirmed reachable from this
  environment; no Trivy/OWASP-Dependency-Check binary install needed,
  keeping the toolchain pure-Python like the rest of this repo).
- **SBOM**: CycloneDX JSON format, generated via `cyclonedx-py` from
  `requirements.txt`. CycloneDX chosen over SPDX — it's the format
  `pip-audit` and the Python packaging ecosystem's tooling most directly
  support, and `docs/security_gate_formula.md`'s own text lists CycloneDX
  first.

### Test protocol

1. **Seeded-vulnerability test** (the actual detection-capability
   check): a fixture requirements file
   (`tests/fixtures/vulnerable_requirements.txt`) pins `urllib3==1.24.1`
   — a real package version with multiple long-documented CVEs (used only
   as a scan *target*, never installed into this project's own
   environment). Run `pip-audit` against it; it must report at least one
   vulnerability, on every run (not flaky — vulnerability databases don't
   change mid-test-run).
2. **Real scan** (project health, not the gate's pass/fail criterion but
   recorded): `pip-audit` run against this project's actual
   `requirements.txt`, output kept for the record.
3. **SBOM generation + validation**: generate a CycloneDX SBOM from
   `requirements.txt`; validate it has the required top-level CycloneDX
   structure (`bomFormat: "CycloneDX"`, a `specVersion`, a non-empty
   `components` list covering the pinned packages).

### Gate target

1. The seeded-vulnerability scan reports ≥1 finding, on repeated runs.
2. The generated SBOM is schema-valid (required top-level fields present,
   `components` non-empty and matching `requirements.txt`'s package set).

## Phase 6 gate (both parts required)

1. Adversarial test: `clean_accuracy - adversarial_accuracy <= 0.30`,
   reproduced bit-identically across two runs.
2. Dependency scan: seeded vulnerability caught on repeated runs; SBOM is
   schema-valid.
