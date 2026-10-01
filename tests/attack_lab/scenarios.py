"""Phase 10 — shared attack-scenario runners. Each function runs ONE live
pass of the real pipeline (real training, real detectors, real gate, real
audit log) for one attack type, per docs/phase10_attack_lab_spec.md. Test
files call these twice each (the spec's "run twice" requirement) and
assert on the results.
"""
import os
import shutil
from pathlib import Path

import numpy as np
import pandas as pd

from src.data.load_dataset import COLUMN_NAMES, load_raw
from src.governance.audit_log import AuditLog
from src.pipeline import data_scan, ingest, model_scan, train as train_step, validate
from src.recovery.cycle import MODEL_PATH, SIGNATURE_PATH, handle_detected_attack, run_current_pipeline_gate
from src.security.sign_model import sign_model_at

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "tests" / "attack_lab" / "fixtures"
ATTACK_POISON_RATE = 0.40  # locked in docs/phase10_attack_lab_spec.md Attack 1

LABEL_COL_INDEX = COLUMN_NAMES.index("label")


def generate_poisoned_training_file(seed: int, poison_rate: float = ATTACK_POISON_RATE) -> Path:
    """Writes a poisoned copy of the real KDDTrain+.txt (random label
    flips at attack strength, same technique as Phase 5's calibration
    benchmark) for use as an ingest source override - a real file on disk,
    not an in-memory simulation."""
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    out_path = FIXTURES_DIR / f"poisoned_train_rate{int(poison_rate*100)}_seed{seed}.txt"
    if out_path.exists():
        return out_path  # deterministic given (seed, rate) - reuse across runs

    raw_path = REPO_ROOT / "data" / "raw" / "KDDTrain+.txt"
    lines = raw_path.read_text().splitlines()

    # Candidate pool restricted to rows already labeled "normal" or
    # "neptune" (the two largest classes) - flipping an arbitrary OTHER
    # attack subtype (e.g. the 4-row "phf" or 2-row "spy" classes) to
    # "normal" can wipe a rare class below the 2-member minimum
    # make_split's stratified split requires, crashing train_step.main()
    # with a ValueError unrelated to the attack itself. Restricting the
    # pool keeps every other class's population untouched.
    candidate_indices = [
        i for i, line in enumerate(lines)
        if line.split(",")[LABEL_COL_INDEX] in ("normal", "neptune")
    ]

    rng = np.random.default_rng(seed)
    n = len(lines)
    n_poison = min(int(round(n * poison_rate)), len(candidate_indices))
    poison_indices = rng.choice(candidate_indices, size=n_poison, replace=False)

    for i in poison_indices:
        fields = lines[i].split(",")
        fields[LABEL_COL_INDEX] = "normal" if fields[LABEL_COL_INDEX] != "normal" else "neptune"
        lines[i] = ",".join(fields)

    out_path.write_text("\n".join(lines) + "\n")
    return out_path


def run_poisoning_scenario(run_seed: int) -> dict:
    """Attack 1: data poisoning. Live pipeline run with a pre-poisoned
    ingest source; expects the gate to react via data_scan's degraded
    recall/FPR."""
    poisoned_file = generate_poisoned_training_file(seed=run_seed)
    os.environ["MLSHIELD_INGEST_TRAIN_SOURCE"] = str(poisoned_file)
    try:
        assert ingest.main() == 0
        assert validate.main() == 0
        assert train_step.main() == 0
    finally:
        os.environ.pop("MLSHIELD_INGEST_TRAIN_SOURCE", None)

    sign_model_at(MODEL_PATH, SIGNATURE_PATH)
    # "standard" (not "skip") so current_run_adversarial_eval.json is
    # freshly written by THIS run - robustness_mode="skip" leaves that file
    # untouched, which would let the gate silently read a stale result left
    # over from a previous scenario (e.g. the evasion scenario's 35%
    # degradation) instead of this run's genuinely clean robustness. The
    # poisoning scenario is meant to isolate data_scan as the sole trigger.
    model_scan.main(model_path=MODEL_PATH, signature_path=SIGNATURE_PATH, robustness_mode="standard")
    data_scan.main(poison_rate=ATTACK_POISON_RATE)

    audit_log = AuditLog()
    gate_result = run_current_pipeline_gate(audit_log)

    outcome = None
    if gate_result.decision != "PASS":
        outcome = handle_detected_attack("data_poisoning", gate_result, audit_log)

    return {"gate_result": gate_result, "outcome": outcome}


def run_evasion_scenario(run_seed: int) -> dict:
    """Attack 2: evasion. Live pipeline run on CLEAN data, but model_scan
    runs in direct_attack mode (HopSkipJump against the real model) -
    expects the gate to react via model_scan's degraded robustness."""
    os.environ.pop("MLSHIELD_INGEST_TRAIN_SOURCE", None)
    assert ingest.main() == 0
    assert validate.main() == 0
    assert train_step.main() == 0

    sign_model_at(MODEL_PATH, SIGNATURE_PATH)
    model_scan.main(model_path=MODEL_PATH, signature_path=SIGNATURE_PATH, robustness_mode="direct_attack")
    data_scan.main(poison_rate=0.10)  # clean data this run - calibration rate, not attack rate

    audit_log = AuditLog()
    gate_result = run_current_pipeline_gate(audit_log)

    outcome = None
    if gate_result.decision != "PASS":
        outcome = handle_detected_attack("evasion", gate_result, audit_log)

    return {"gate_result": gate_result, "outcome": outcome}


def run_tampering_scenario(run_seed: int) -> dict:
    """Attack 3: model tampering. Live pipeline run on clean data; the
    freshly-signed model artifact is corrupted (single byte flip) BEFORE
    model_scan verifies it - expects the hard integrity override to FAIL
    the gate regardless of every other sub-score."""
    os.environ.pop("MLSHIELD_INGEST_TRAIN_SOURCE", None)
    assert ingest.main() == 0
    assert validate.main() == 0
    assert train_step.main() == 0

    sign_model_at(MODEL_PATH, SIGNATURE_PATH)

    # Tamper AFTER legitimate signing - same technique as Phase 5's
    # 10-case tampering test, applied live to this run's artifact.
    data = bytearray(MODEL_PATH.read_bytes())
    data[len(data) // 2] ^= 0xFF
    MODEL_PATH.write_bytes(bytes(data))

    # "standard" (not "skip") for the same reason as the poisoning scenario
    # above: a fresh, genuinely clean robustness result each run, not
    # whatever current_run_adversarial_eval.json happened to contain from a
    # previous scenario. The tampering scenario is meant to isolate the
    # integrity hard-override as the sole trigger - note run_adversarial_test
    # loads the tampered artifact via joblib.load(model_path), so this call
    # happens AFTER the byte-flip and exercises the same corrupted file the
    # gate will also see.
    model_scan.main(model_path=MODEL_PATH, signature_path=SIGNATURE_PATH, robustness_mode="standard")
    data_scan.main(poison_rate=0.10)

    audit_log = AuditLog()
    gate_result = run_current_pipeline_gate(audit_log)

    outcome = None
    if gate_result.decision != "PASS":
        outcome = handle_detected_attack("model_tampering", gate_result, audit_log)

    return {"gate_result": gate_result, "outcome": outcome}
