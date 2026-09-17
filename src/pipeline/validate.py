"""Phase 3 pipeline step 2/5 — validate.

Schema/sanity checks on the staged data (data/staging/), written by
`ingest`. This is what actually catches a corrupted/malformed drop — the
env-var override in `ingest` only controls *which file* gets staged as
KDDTrain+.txt; this step doesn't know or care that it was overridden, it
just checks the content it's handed. A deliberately-broken run should fail
here, not train an untrustworthy model.

Not the same thing as Phase 5's poisoning detector — this is basic schema
validation (right shape, right value domains), not adversarial/statistical
poisoning detection. That's still Phase 5+ scope.
"""
import sys
from pathlib import Path

import pandas as pd

from src.data.load_dataset import COLUMN_NAMES

REPO_ROOT = Path(__file__).resolve().parents[2]
STAGING_DIR = REPO_ROOT / "data" / "staging"

EXPECTED_N_COLUMNS = len(COLUMN_NAMES)  # 43
KNOWN_PROTOCOLS = {"tcp", "udp", "icmp"}
KNOWN_FLAGS = {"SF", "S0", "REJ", "RSTR", "RSTO", "SH", "S1", "S2", "S3", "RSTOS0", "OTH"}
NUMERIC_COLUMNS = [
    c for c in COLUMN_NAMES if c not in ("protocol_type", "service", "flag", "label")
]


def validate_file(path: Path) -> list:
    """Returns a list of error strings; empty list means the file is valid."""
    errors = []

    if not path.exists():
        return [f"{path.name}: staged file missing"]

    # Raw line-level column count check, independent of pandas' own parsing
    # leniency, so a truly malformed line can't slip past silently.
    with open(path) as f:
        for i, line in enumerate(f, start=1):
            n_fields = len(line.rstrip("\n").split(","))
            if n_fields != EXPECTED_N_COLUMNS:
                errors.append(
                    f"{path.name}: line {i} has {n_fields} fields, expected {EXPECTED_N_COLUMNS}"
                )
                if len(errors) >= 5:  # don't flood output on a badly-broken file
                    errors.append(f"{path.name}: (further line errors suppressed)")
                    break
    if errors:
        return errors  # malformed rows make the rest of this function unsafe to run

    df = pd.read_csv(path, names=COLUMN_NAMES, header=None)

    if len(df) == 0:
        errors.append(f"{path.name}: no rows")

    bad_protocols = set(df["protocol_type"].unique()) - KNOWN_PROTOCOLS
    if bad_protocols:
        errors.append(f"{path.name}: unknown protocol_type values: {bad_protocols}")

    bad_flags = set(df["flag"].unique()) - KNOWN_FLAGS
    if bad_flags:
        errors.append(f"{path.name}: unknown flag values: {bad_flags}")

    if df["label"].isna().any() or (df["label"].astype(str).str.strip() == "").any():
        errors.append(f"{path.name}: null/empty label values present")

    for col in NUMERIC_COLUMNS:
        non_numeric = pd.to_numeric(df[col], errors="coerce").isna() & df[col].notna()
        if non_numeric.any():
            errors.append(f"{path.name}: column '{col}' has non-numeric values")

    return errors


def main() -> int:
    all_errors = []
    for filename in ["KDDTrain+.txt", "KDDTest+.txt"]:
        all_errors.extend(validate_file(STAGING_DIR / filename))

    if all_errors:
        print("VALIDATE FAIL:", file=sys.stderr)
        for e in all_errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print("VALIDATE OK: staged data passes schema checks (shape, protocol/flag domains, "
          "label completeness, numeric columns)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
