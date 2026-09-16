"""Phase 1 — ML baseline: binary (normal/attack) classifier on NSL-KDD.

No security features here (poisoning/tampering/adversarial detection is
Phase 5+) — this is only the working classifier the rest of the pipeline
will later wrap in the Security Gate. Spec locked in
docs/phase1_baseline_spec.md before this file was written.
"""
import json
from pathlib import Path

import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from src.data.load_dataset import COLUMN_NAMES, TEST_FILE, load_raw, make_split

RANDOM_SEED = 42
N_ESTIMATORS = 200

CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]
DROPPED_COLUMNS = ["label", "difficulty"]
NUMERIC_FEATURES = [
    c for c in COLUMN_NAMES if c not in CATEGORICAL_FEATURES + DROPPED_COLUMNS
]

METRICS_OUT = Path(__file__).resolve().parents[2] / "data" / "processed" / "phase1_metrics.json"


def to_binary_label(label_col: "pd.Series") -> "pd.Series":
    return (label_col != "normal").astype(int)  # 1 = attack, 0 = normal


def build_pipeline() -> Pipeline:
    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
        ],
        remainder="passthrough",  # numeric features pass through unscaled
    )
    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        random_state=RANDOM_SEED,
        n_jobs=1,
    )
    return Pipeline(steps=[("preprocess", preprocessor), ("model", model)])


def evaluate(pipeline: Pipeline, X, y_true) -> dict:
    y_pred = pipeline.predict(X)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred),
        "recall": recall_score(y_true, y_pred),
        "f1": f1_score(y_true, y_pred),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def main():
    # Phase 0's locked, fixed-seed split.
    train_raw = load_raw(Path(__file__).resolve().parents[2] / "data" / "raw" / "KDDTrain+.txt")
    train_df, val_df = make_split(train_raw)
    test_df = load_raw(TEST_FILE)

    feature_cols = CATEGORICAL_FEATURES + NUMERIC_FEATURES

    X_train, y_train = train_df[feature_cols], to_binary_label(train_df["label"])
    X_val, y_val = val_df[feature_cols], to_binary_label(val_df["label"])
    X_test, y_test = test_df[feature_cols], to_binary_label(test_df["label"])

    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    val_metrics = evaluate(pipeline, X_val, y_val)
    test_metrics = evaluate(pipeline, X_test, y_test)

    # 5-fold stratified CV on the training split for stability check.
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
    cv_scores = cross_val_score(
        build_pipeline(), X_train, y_train, cv=cv, scoring="f1", n_jobs=1
    )

    results = {
        "random_seed": RANDOM_SEED,
        "n_estimators": N_ESTIMATORS,
        "validation_split_metrics": val_metrics,
        "kddtest_plus_metrics": test_metrics,
        "cv_f1_scores": cv_scores.tolist(),
        "cv_f1_mean": float(np.mean(cv_scores)),
        "cv_f1_std": float(np.std(cv_scores)),
    }

    METRICS_OUT.parent.mkdir(parents=True, exist_ok=True)
    METRICS_OUT.write_text(json.dumps(results, indent=2))

    print(f"Validation split F1: {val_metrics['f1']:.4f}")
    print(f"KDDTest+ F1:         {test_metrics['f1']:.4f}")
    print(f"CV F1 mean/std:      {results['cv_f1_mean']:.4f} / {results['cv_f1_std']:.4f}")
    print(f"Metrics written to {METRICS_OUT}")
    return results


if __name__ == "__main__":
    main()
