"""Phase 5 — Data Scan: k-NN label-consistency poisoning detector.

Method, parameters, and the recall/FPR target this has to meet are locked
in docs/phase5_security_gate_v1_spec.md (Part A) before this file was
written; the target itself was locked even earlier, in Phase 0's
docs/security_gate_formula.md.
"""
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import OneHotEncoder

from src.models.train_baseline import CATEGORICAL_FEATURES, NUMERIC_FEATURES

K_NEIGHBORS = 15
AGREEMENT_THRESHOLD = 0.5
SUBSAMPLE_SIZE = 8000
SUBSAMPLE_SEED = 42


def _build_feature_transformer() -> ColumnTransformer:
    """Same encoding shape as src/models/train_baseline.py's build_pipeline
    preprocessing step, but fit fresh on whatever data is handed to the
    detector — this is a standalone data-quality check, not reusing the
    trained model's fitted encoder."""
    return ColumnTransformer(
        transformers=[("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES)],
        remainder="passthrough",
    )


@dataclass
class PoisoningDetectionResult:
    flagged_mask: np.ndarray  # boolean, aligned to the input DataFrame's row order
    agreement_scores: np.ndarray  # float, fraction of neighbors agreeing per row


def detect_poisoning(
    features_df: pd.DataFrame,
    binary_labels: pd.Series,
    k: int = K_NEIGHBORS,
    threshold: float = AGREEMENT_THRESHOLD,
) -> PoisoningDetectionResult:
    """features_df: rows with CATEGORICAL_FEATURES + NUMERIC_FEATURES columns.
    binary_labels: aligned 0/1 label per row (1 = attack, 0 = normal).
    Returns a flagged_mask the same length/order as the input."""
    feature_cols = CATEGORICAL_FEATURES + NUMERIC_FEATURES
    X = _build_feature_transformer().fit_transform(features_df[feature_cols])
    y = binary_labels.to_numpy()

    n = X.shape[0]
    if n <= k:
        raise ValueError(f"Need more than k={k} samples to run kNN detection, got {n}")

    nn = NearestNeighbors(n_neighbors=k + 1)  # +1 because a point is its own nearest neighbor
    nn.fit(X)
    _, neighbor_indices = nn.kneighbors(X)
    neighbor_indices = neighbor_indices[:, 1:]  # drop self

    neighbor_labels = y[neighbor_indices]  # shape (n, k)
    agreement_scores = (neighbor_labels == y[:, None]).mean(axis=1)
    flagged_mask = agreement_scores < threshold

    return PoisoningDetectionResult(flagged_mask=flagged_mask, agreement_scores=agreement_scores)
