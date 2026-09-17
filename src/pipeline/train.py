"""Phase 3 pipeline step 3/5 — train.

Same model/training logic as Phase 1's src/models/train_baseline.py, but
reading from the pipeline's staged data (data/staging/, written by ingest,
checked by validate) instead of data/raw/ directly, and *not* registering
the model in MLflow — that only happens if `evaluate` passes (step 4/5),
carried out by `register` (step 5/5). This is what makes the "gate blocks
a bad model" property real: a model that fails the bar is trained and
logged (for audit purposes — see Section 3 of docs/security_gate_formula.md
on fail-closed handling) but never becomes a registered, deployable version.
"""
import json
import sys
from pathlib import Path

import joblib
import mlflow
import mlflow.sklearn
import numpy as np

from src.data.load_dataset import load_raw, make_split
from src.models.train_baseline import (
    CATEGORICAL_FEATURES,
    MLFLOW_EXPERIMENT_NAME,
    MLFLOW_TRACKING_URI,
    NUMERIC_FEATURES,
    N_ESTIMATORS,
    RANDOM_SEED,
    build_pipeline,
    evaluate,
    to_binary_label,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score

REPO_ROOT = Path(__file__).resolve().parents[2]
STAGING_DIR = REPO_ROOT / "data" / "staging"
METRICS_OUT = REPO_ROOT / "data" / "processed" / "phase3_metrics.json"
MODEL_OUT = REPO_ROOT / "models" / "phase3_model.joblib"
RUN_INFO_OUT = REPO_ROOT / "data" / "processed" / "phase3_run_info.json"


def main() -> int:
    train_raw = load_raw(STAGING_DIR / "KDDTrain+.txt")
    train_df, val_df = make_split(train_raw)
    test_df = load_raw(STAGING_DIR / "KDDTest+.txt")

    feature_cols = CATEGORICAL_FEATURES + NUMERIC_FEATURES
    X_train, y_train = train_df[feature_cols], to_binary_label(train_df["label"])
    X_val, y_val = val_df[feature_cols], to_binary_label(val_df["label"])
    X_test, y_test = test_df[feature_cols], to_binary_label(test_df["label"])

    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    val_metrics = evaluate(pipeline, X_val, y_val)
    test_metrics = evaluate(pipeline, X_test, y_test)

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
    cv_scores = cross_val_score(build_pipeline(), X_train, y_train, cv=cv, scoring="f1", n_jobs=1)

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
    with mlflow.start_run(run_name="pipeline-run") as run:
        mlflow.log_params({
            "random_seed": RANDOM_SEED,
            "n_estimators": N_ESTIMATORS,
            "model_type": "RandomForestClassifier",
            "task": "binary_normal_vs_attack",
            "source": "airflow_pipeline",
        })
        mlflow.log_metrics({
            "val_f1": val_metrics["f1"],
            "kddtest_f1": test_metrics["f1"],
            "cv_f1_mean": results["cv_f1_mean"],
            "cv_f1_std": results["cv_f1_std"],
        })
        mlflow.log_artifact(str(METRICS_OUT), artifact_path="metrics")
        # Logged, NOT registered — registration is a separate, gated step.
        # serialization_format pinned to cloudpickle; see the comment on the
        # equivalent call in src/models/train_baseline.py for why.
        mlflow.sklearn.log_model(pipeline, name="model", serialization_format="cloudpickle")
        run_id = run.info.run_id

    RUN_INFO_OUT.write_text(json.dumps({"run_id": run_id, "model_artifact_path": "model"}, indent=2))

    print(f"TRAIN OK: KDDTest+ F1={test_metrics['f1']:.4f}, mlflow run_id={run_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
