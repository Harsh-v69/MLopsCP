"""Phase 1 — ML baseline: binary (normal/attack) classifier on NSL-KDD.

No security features here (poisoning/tampering/adversarial detection is
Phase 5+) — this is only the working classifier the rest of the pipeline
will later wrap in the Security Gate. Spec locked in
docs/phase1_baseline_spec.md before this file was written.
"""
import json
from pathlib import Path

import joblib
import mlflow
import mlflow.sklearn
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

REPO_ROOT = Path(__file__).resolve().parents[2]
METRICS_OUT = REPO_ROOT / "data" / "processed" / "phase1_metrics.json"
MODEL_OUT = REPO_ROOT / "models" / "baseline_model.joblib"
MLFLOW_TRACKING_URI = f"sqlite:///{REPO_ROOT / 'mlflow.db'}"
MLFLOW_EXPERIMENT_NAME = "mlshield-baseline"
MLFLOW_REGISTERED_MODEL_NAME = "mlshield-baseline-rf"


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

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_OUT)

    mlflow.set_tracking_uri(MLFLOW_TRACKING_URI)
    mlflow.set_experiment(MLFLOW_EXPERIMENT_NAME)
    with mlflow.start_run(run_name="baseline-random-forest") as run:
        mlflow.log_params({
            "random_seed": RANDOM_SEED,
            "n_estimators": N_ESTIMATORS,
            "model_type": "RandomForestClassifier",
            "task": "binary_normal_vs_attack",
            "n_jobs": 1,
        })
        mlflow.log_metrics({
            "val_f1": val_metrics["f1"],
            "val_accuracy": val_metrics["accuracy"],
            "val_precision": val_metrics["precision"],
            "val_recall": val_metrics["recall"],
            "kddtest_f1": test_metrics["f1"],
            "kddtest_accuracy": test_metrics["accuracy"],
            "kddtest_precision": test_metrics["precision"],
            "kddtest_recall": test_metrics["recall"],
            "cv_f1_mean": results["cv_f1_mean"],
            "cv_f1_std": results["cv_f1_std"],
        })
        mlflow.log_artifact(str(METRICS_OUT), artifact_path="metrics")
        mlflow.sklearn.log_model(
            pipeline,
            name="model",
            registered_model_name=MLFLOW_REGISTERED_MODEL_NAME,
        )
        results["mlflow_run_id"] = run.info.run_id

    print(f"Validation split F1: {val_metrics['f1']:.4f}")
    print(f"KDDTest+ F1:         {test_metrics['f1']:.4f}")
    print(f"CV F1 mean/std:      {results['cv_f1_mean']:.4f} / {results['cv_f1_std']:.4f}")
    print(f"Metrics written to {METRICS_OUT}")
    print(f"Model artifact written to {MODEL_OUT}")
    print(f"MLflow run id: {results['mlflow_run_id']}")
    return results


if __name__ == "__main__":
    main()
