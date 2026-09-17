"""Phase 5 — controlled label-flip injection test for the poisoning
detector. Protocol locked in docs/phase5_security_gate_v1_spec.md (Part A,
"Injection test protocol") before this file was written.
"""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from src.data.load_dataset import load_raw, make_split
from src.models.train_baseline import CATEGORICAL_FEATURES, NUMERIC_FEATURES, to_binary_label
from src.security.poisoning_detector import (
    AGREEMENT_THRESHOLD,
    K_NEIGHBORS,
    SUBSAMPLE_SEED,
    SUBSAMPLE_SIZE,
    detect_poisoning,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS_OUT = REPO_ROOT / "data" / "processed" / "phase5_poisoning_eval.json"

POISON_RATE = 0.10
MIN_RECALL = 0.80
MAX_FPR = 0.10


def main() -> int:
    train_raw = load_raw(REPO_ROOT / "data" / "raw" / "KDDTrain+.txt")
    train_df, _ = make_split(train_raw)

    rng = np.random.default_rng(SUBSAMPLE_SEED)
    subsample = train_df.sample(n=SUBSAMPLE_SIZE, random_state=SUBSAMPLE_SEED).reset_index(drop=True)

    feature_cols = CATEGORICAL_FEATURES + NUMERIC_FEATURES
    features_df = subsample[feature_cols].copy()
    binary_labels = to_binary_label(subsample["label"]).to_numpy().copy()

    n = len(binary_labels)
    n_poison = int(round(n * POISON_RATE))
    poison_indices = rng.choice(n, size=n_poison, replace=False)
    is_poisoned = np.zeros(n, dtype=bool)
    is_poisoned[poison_indices] = True

    poisoned_labels = binary_labels.copy()
    poisoned_labels[poison_indices] = 1 - poisoned_labels[poison_indices]  # flip

    result = detect_poisoning(
        features_df,
        pd.Series(poisoned_labels),
        k=K_NEIGHBORS,
        threshold=AGREEMENT_THRESHOLD,
    )
    flagged = result.flagged_mask

    true_positives = np.sum(flagged & is_poisoned)
    false_negatives = np.sum(~flagged & is_poisoned)
    false_positives = np.sum(flagged & ~is_poisoned)
    true_negatives = np.sum(~flagged & ~is_poisoned)

    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) else 0.0
    fpr = false_positives / (false_positives + true_negatives) if (false_positives + true_negatives) else 0.0

    results = {
        "k": K_NEIGHBORS,
        "agreement_threshold": AGREEMENT_THRESHOLD,
        "subsample_size": SUBSAMPLE_SIZE,
        "poison_rate": POISON_RATE,
        "n_poisoned": int(n_poison),
        "true_positives": int(true_positives),
        "false_negatives": int(false_negatives),
        "false_positives": int(false_positives),
        "true_negatives": int(true_negatives),
        "recall": float(recall),
        "false_positive_rate": float(fpr),
        "min_recall_bar": MIN_RECALL,
        "max_fpr_bar": MAX_FPR,
        "passed": bool(recall >= MIN_RECALL and fpr <= MAX_FPR),
    }

    RESULTS_OUT.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_OUT.write_text(json.dumps(results, indent=2))

    print(f"Recall:              {recall:.4f} (bar: >= {MIN_RECALL})")
    print(f"False positive rate: {fpr:.4f} (bar: <= {MAX_FPR})")
    print(f"PASS" if results["passed"] else "FAIL")
    print(f"Results written to {RESULTS_OUT}")

    return 0 if results["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
