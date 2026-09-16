"""Deterministic loader/splitter for the locked NSL-KDD dataset (Phase 0).

Loads KDDTrain+.txt, produces a fixed-seed, stratified train/validation split,
and prints a hash of that split so reproducibility can be checked across
machines and across container rebuilds. KDDTest+.txt is kept as a separate,
untouched held-out set (never used for splitting/tuning).
"""
import hashlib
import json
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

RANDOM_SEED = 42
VALIDATION_FRACTION = 0.2

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "raw"
TRAIN_FILE = DATA_DIR / "KDDTrain+.txt"
TEST_FILE = DATA_DIR / "KDDTest+.txt"

COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]


def load_raw(path: Path) -> pd.DataFrame:
    return pd.read_csv(path, names=COLUMN_NAMES, header=None)


def make_split(df: pd.DataFrame):
    """Stratified train/validation split, fixed seed, reproducible row order."""
    train_df, val_df = train_test_split(
        df,
        test_size=VALIDATION_FRACTION,
        random_state=RANDOM_SEED,
        stratify=df["label"],
    )
    return train_df.sort_index(), val_df.sort_index()


def split_hash(train_df: pd.DataFrame, val_df: pd.DataFrame) -> str:
    """Hash of the *assignment* (which original row indices went to val),
    not the file bytes — this is what proves the split logic is reproducible,
    independent of how the raw file happens to be re-encoded."""
    payload = {
        "train_indices": sorted(train_df.index.tolist()),
        "val_indices": sorted(val_df.index.tolist()),
        "seed": RANDOM_SEED,
        "validation_fraction": VALIDATION_FRACTION,
    }
    blob = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def main():
    train_raw = load_raw(TRAIN_FILE)
    test_raw = load_raw(TEST_FILE)

    train_df, val_df = make_split(train_raw)
    h = split_hash(train_df, val_df)

    print(f"Loaded KDDTrain+: {len(train_raw)} rows")
    print(f"Loaded KDDTest+:  {len(test_raw)} rows (held out, untouched)")
    print(f"Train split: {len(train_df)} rows")
    print(f"Validation split: {len(val_df)} rows")
    print(f"Split hash (seed={RANDOM_SEED}): {h}")
    return h


if __name__ == "__main__":
    main()
