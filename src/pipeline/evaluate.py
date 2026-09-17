"""Phase 3 pipeline step 4/5 — evaluate.

Reads the metrics `train` just produced and checks them against the locked
Phase 1 gate (F1 >= 0.75 on KDDTest+.txt — see docs/phase1_baseline_spec.md).
Exits non-zero on failure, which — because Airflow tasks are wired
train >> evaluate >> register — stops `register` from ever running. This is
the actual enforcement mechanism behind "a model that fails the bar never
gets registered", not just a written rule.
"""
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
METRICS_IN = REPO_ROOT / "data" / "processed" / "phase3_metrics.json"

MIN_F1 = 0.75  # locked in docs/phase1_baseline_spec.md; kept in sync manually


def main() -> int:
    if not METRICS_IN.exists():
        print(f"EVALUATE FAIL: metrics file not found: {METRICS_IN}", file=sys.stderr)
        return 1

    with open(METRICS_IN) as f:
        metrics = json.load(f)

    f1 = metrics["kddtest_plus_metrics"]["f1"]

    if f1 >= MIN_F1:
        print(f"EVALUATE OK: KDDTest+ F1={f1:.4f} >= {MIN_F1}")
        return 0
    else:
        print(f"EVALUATE FAIL: KDDTest+ F1={f1:.4f} < {MIN_F1} — model will not be registered", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
