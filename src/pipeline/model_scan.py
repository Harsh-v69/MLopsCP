"""Phase 10 pipeline step — model_scan.

Live wiring of Phase 5's integrity check and Phase 6's robustness check
against THIS run's just-trained model artifact, instead of only the fixed
production one. Does not sign the model itself (signing happens right
after training, a separate explicit step - see src/recovery/cycle.py) -
this step only verifies whatever signature already exists, which is what
makes the tampering attack scenario realistic: sign a legitimate model,
THEN simulate an attacker corrupting the file, THEN this step is what
catches it.

robustness_mode:
  - "standard": Phase 6's fast surrogate-transfer check (run_adversarial_test) -
    used for normal pipeline runs and recovery revalidation.
  - "direct_attack": Phase 10's HopSkipJump direct attack
    (run_direct_evasion_attack) - used only for the evasion attack-lab
    scenario itself (slow, ~25s, deliberately more thorough).
  - "skip": no robustness check this run (e.g. the poisoning/tampering
    attack scenarios don't need to re-run it every time).

Locked in docs/phase10_attack_lab_spec.md (Attacks 2 and 3, Part B).
"""
import json
import sys
from pathlib import Path

from src.security.adversarial_test import run_adversarial_test, run_direct_evasion_attack
from src.security.verify_model import verify as verify_model_signature

REPO_ROOT = Path(__file__).resolve().parents[2]
MODEL_OUT = REPO_ROOT / "models" / "phase3_model.joblib"  # written by src/pipeline/train.py
SIGNATURE_OUT = REPO_ROOT / "models" / "phase3_model.joblib.sig"
ADVERSARIAL_RESULTS_OUT = REPO_ROOT / "data" / "processed" / "current_run_adversarial_eval.json"


def main(
    model_path: Path = MODEL_OUT,
    signature_path: Path = SIGNATURE_OUT,
    robustness_mode: str = "standard",
) -> int:
    integrity_ok = verify_model_signature(artifact_path=model_path, signature_path=signature_path)
    print(f"MODEL_SCAN: integrity {'OK' if integrity_ok else 'FAILED'} ({model_path})")

    if robustness_mode == "skip":
        print("MODEL_SCAN: robustness check skipped for this run")
    else:
        if robustness_mode == "direct_attack":
            results = run_direct_evasion_attack(model_path=model_path)
        elif robustness_mode == "standard":
            results = run_adversarial_test(model_path=model_path)
        else:
            raise ValueError(f"unknown robustness_mode: {robustness_mode!r}")

        ADVERSARIAL_RESULTS_OUT.parent.mkdir(parents=True, exist_ok=True)
        ADVERSARIAL_RESULTS_OUT.write_text(json.dumps(results, indent=2))
        print(f"MODEL_SCAN: clean_acc={results['clean_accuracy']:.4f} "
              f"adv_acc={results['adversarial_accuracy']:.4f} "
              f"degradation={results['degradation']:.4f} (mode={robustness_mode})")

    return 0 if integrity_ok else 1


if __name__ == "__main__":
    sys.exit(main())
