"""Phase 9 — SHAP explanations for the RandomForest model. Method locked
in docs/phase9_transparency_spec.md (Part A) before this file was written:
exact TreeExplainer, attack-class slice, top-10 contributing features.
"""
from pathlib import Path
from typing import List

import joblib
import numpy as np
import pandas as pd
import shap

from src.models.train_baseline import CATEGORICAL_FEATURES, NUMERIC_FEATURES

REPO_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = REPO_ROOT / "models" / "baseline_model.joblib"
FEATURE_COLUMNS = CATEGORICAL_FEATURES + NUMERIC_FEATURES

TOP_K_FEATURES = 10

_pipeline = None
_explainer = None
_feature_names = None


def _load():
    global _pipeline, _explainer, _feature_names
    if _pipeline is None:
        _pipeline = joblib.load(MODEL_PATH)
        preprocess = _pipeline.named_steps["preprocess"]
        rf = _pipeline.named_steps["model"]
        _explainer = shap.TreeExplainer(rf)
        _feature_names = list(preprocess.named_transformers_["cat"].get_feature_names_out()) + NUMERIC_FEATURES
    return _pipeline, _explainer, _feature_names


def explain_records(records: List[dict]) -> List[dict]:
    """records: list of dicts with the 41 NSL-KDD feature fields (same
    shape /predict accepts). Returns one explanation dict per record."""
    pipeline, explainer, feature_names = _load()
    preprocess = pipeline.named_steps["preprocess"]

    df = pd.DataFrame(records, columns=FEATURE_COLUMNS)
    X_transformed = preprocess.transform(df)
    if hasattr(X_transformed, "toarray"):
        X_transformed = X_transformed.toarray()

    shap_values = explainer.shap_values(X_transformed)  # (n, n_features, 2)
    attack_shap = shap_values[:, :, 1]
    base_rate = float(explainer.expected_value[1])

    predictions = pipeline.named_steps["model"].predict(X_transformed)
    probabilities = pipeline.named_steps["model"].predict_proba(X_transformed)[:, 1]

    results = []
    for i in range(len(records)):
        row_shap = attack_shap[i]
        row_values = X_transformed[i]
        order = np.argsort(-np.abs(row_shap))[:TOP_K_FEATURES]

        top_features = [
            {
                "feature": feature_names[j],
                "value": float(row_values[j]),
                "shap_value": float(row_shap[j]),
            }
            for j in order
        ]

        results.append({
            "label": "attack" if predictions[i] == 1 else "normal",
            "attack_probability": float(probabilities[i]),
            "base_rate": base_rate,
            "top_contributing_features": top_features,
        })

    return results
