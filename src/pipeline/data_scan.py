"""Phase 10 pipeline step — data_scan.

Live wiring of Phase 5's poisoning detector against THIS run's staged
training data (data/staging/KDDTrain+.txt, written by ingest), not the
fixed Phase 0 calibration subsample. Runs the same injection-benchmark
protocol (src.security.evaluate_poisoning_detector.run_injection_test)
against the actual staged data, so a poisoned source file shows up as a
measurably different (worse) recall/FPR than the clean calibration
baseline. Locked in docs/phase10_attack_lab_spec.md (Attack 1).
"""
import json
import sys
from pathlib import Path

from src.data.load_dataset import load_raw, make_split
from src.security.evaluate_poisoning_detector import POISON_RATE, SUBSAMPLE_SEED, run_injection_test

REPO_ROOT = Path(__file__).resolve().parents[2]
STAGING_DIR = REPO_ROOT / "data" / "staging"
RESULTS_OUT = REPO_ROOT / "data" / "processed" / "current_run_poisoning_eval.json"


def main(poison_rate: float = POISON_RATE) -> int:
    """poison_rate defaults to Phase 5's calibration rate (10%) for a
    normal pipeline run; the attack lab calls this with the attack-strength
    rate (40%) to simulate a sophisticated attacker instead - see
    docs/phase10_attack_lab_spec.md Attack 1."""
    train_raw = load_raw(STAGING_DIR / "KDDTrain+.txt")
    train_df, _ = make_split(train_raw)

    results = run_injection_test(train_df, poison_rate=poison_rate, seed=SUBSAMPLE_SEED)

    RESULTS_OUT.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_OUT.write_text(json.dumps(results, indent=2))

    print(f"DATA_SCAN: recall={results['recall']:.4f}, fpr={results['false_positive_rate']:.4f} "
          f"(poison_rate used for this benchmark: {poison_rate})")
    print(f"Results written to {RESULTS_OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
