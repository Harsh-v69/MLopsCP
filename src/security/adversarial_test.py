"""Phase 6 — adversarial robustness test: FGSM against a differentiable
surrogate, transferred to the real (non-differentiable) RandomForest.

Method, attack surface, and parameters locked in
docs/phase6_security_gate_v2_spec.md (Part A) before this file was
written — including WHY a surrogate is needed (the production model has
no gradients) and WHY only rate features are perturbed (everything else
either can't take a fractional value or has no real-world meaning
fractional).
"""
import json
import sys
from pathlib import Path

import joblib
import numpy as np
from art.attacks.evasion import FastGradientMethod
from art.estimators.classification import SklearnClassifier
from sklearn.linear_model import LogisticRegression

from src.data.load_dataset import TEST_FILE, load_raw
from src.models.train_baseline import CATEGORICAL_FEATURES, NUMERIC_FEATURES, to_binary_label

REPO_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = REPO_ROOT / "models" / "baseline_model.joblib"
RESULTS_OUT = REPO_ROOT / "data" / "processed" / "phase6_adversarial_eval.json"

EPSILON = 0.05
N_EVAL_SAMPLES = 100
RANDOM_SEED = 42
MAX_ALLOWED_DEGRADATION = 0.30

RATE_FEATURES = [
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]
FEATURE_COLUMNS = CATEGORICAL_FEATURES + NUMERIC_FEATURES


def _build_perturbation_mask(preprocess) -> np.ndarray:
    """Mask over the transformed feature vector: 1.0 for the rate-feature
    positions (perturbable), 0.0 everywhere else (one-hot cat dims, counts,
    binary flags)."""
    onehot_width = len(preprocess.named_transformers_["cat"].get_feature_names_out())
    total_width = onehot_width + len(NUMERIC_FEATURES)

    mask = np.zeros(total_width, dtype=np.float32)
    for feature_name in RATE_FEATURES:
        position = onehot_width + NUMERIC_FEATURES.index(feature_name)
        mask[position] = 1.0
    return mask


def run_adversarial_test() -> dict:
    pipeline = joblib.load(MODEL_PATH)
    preprocess = pipeline.named_steps["preprocess"]
    rf_model = pipeline.named_steps["model"]

    test_df = load_raw(TEST_FILE)
    X_raw = test_df[FEATURE_COLUMNS]
    y_true = to_binary_label(test_df["label"]).to_numpy()

    X_transformed = preprocess.transform(X_raw)
    if hasattr(X_transformed, "toarray"):
        X_transformed = X_transformed.toarray()
    X_transformed = X_transformed.astype(np.float32)

    # Fixed sample of correctly-classified points only (see spec: degradation
    # on an already-wrong point isn't a meaningful robustness signal).
    clean_predictions = rf_model.predict(X_transformed)
    correct_mask = clean_predictions == y_true
    correct_indices = np.where(correct_mask)[0]

    rng = np.random.default_rng(RANDOM_SEED)
    eval_indices = rng.choice(correct_indices, size=min(N_EVAL_SAMPLES, len(correct_indices)), replace=False)
    eval_indices.sort()

    X_eval = X_transformed[eval_indices]
    y_eval = y_true[eval_indices]

    # Train the differentiable surrogate on the same transformed space the
    # real model consumes.
    train_raw = load_raw(REPO_ROOT / "data" / "raw" / "KDDTrain+.txt")
    from src.data.load_dataset import make_split
    train_df, _ = make_split(train_raw)
    X_train_transformed = preprocess.transform(train_df[FEATURE_COLUMNS])
    if hasattr(X_train_transformed, "toarray"):
        X_train_transformed = X_train_transformed.toarray()
    y_train = to_binary_label(train_df["label"]).to_numpy()

    surrogate = LogisticRegression(random_state=RANDOM_SEED, max_iter=5000)
    surrogate.fit(X_train_transformed, y_train)

    # No clip_values on the classifier: rate features are [0,1], but
    # counts/bytes/duration are NOT (src_bytes alone ranges into the tens
    # of thousands) - a blanket (0.0, 1.0) clip_values here would make ART
    # clamp those large legitimate values down to 1.0 during attack
    # generation, producing huge artifactual "perturbations" on unmasked
    # dimensions that have nothing to do with the actual attack (caught by
    # test_only_rate_features_were_perturbed during Phase 6 development -
    # see progress.md). The mask alone is what restricts perturbation to
    # rate features; clipping is applied by us afterward, only to those
    # same rate-feature dimensions.
    art_classifier = SklearnClassifier(model=surrogate, clip_values=None)
    mask = _build_perturbation_mask(preprocess)
    mask_batch = np.tile(mask, (len(X_eval), 1))

    attack = FastGradientMethod(estimator=art_classifier, eps=EPSILON, eps_step=EPSILON, norm=np.inf)
    X_adv = attack.generate(x=X_eval, mask=mask_batch)

    # Clip ONLY the rate-feature dimensions to [0,1] (same bound the API
    # itself enforces, docs/phase4_api_spec.md) - not a blanket clip over
    # every dimension, which would corrupt unmasked large-magnitude
    # features (see comment above).
    rate_dim_positions = np.where(mask == 1.0)[0]
    X_adv[:, rate_dim_positions] = np.clip(X_adv[:, rate_dim_positions], 0.0, 1.0)

    clean_accuracy = float(np.mean(rf_model.predict(X_eval) == y_eval))
    adversarial_accuracy = float(np.mean(rf_model.predict(X_adv) == y_eval))
    degradation = clean_accuracy - adversarial_accuracy

    n_perturbed_features_used = int(np.sum(np.any(np.abs(X_adv - X_eval) > 1e-9, axis=0)))

    return {
        "epsilon": EPSILON,
        "n_eval_samples": int(len(X_eval)),
        "clean_accuracy": clean_accuracy,
        "adversarial_accuracy": adversarial_accuracy,
        "degradation": degradation,
        "max_allowed_degradation": MAX_ALLOWED_DEGRADATION,
        "n_rate_feature_dims_actually_perturbed": n_perturbed_features_used,
        "passed": bool(degradation <= MAX_ALLOWED_DEGRADATION),
    }


def main() -> int:
    results = run_adversarial_test()

    RESULTS_OUT.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_OUT.write_text(json.dumps(results, indent=2))

    print(f"Clean accuracy:        {results['clean_accuracy']:.4f}")
    print(f"Adversarial accuracy:  {results['adversarial_accuracy']:.4f}")
    print(f"Degradation:           {results['degradation']:.4f} (bar: <= {MAX_ALLOWED_DEGRADATION})")
    print("PASS" if results["passed"] else "FAIL")
    print(f"Results written to {RESULTS_OUT}")

    return 0 if results["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
