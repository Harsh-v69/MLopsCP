"""Phase 5 tampering test — protocol locked in
docs/phase5_security_gate_v1_spec.md (Part B). 10 independently-tampered
copies of the model artifact, each must fail verification; the
unmodified artifact must pass.
"""
import shutil
from pathlib import Path

import pytest

from src.security.model_integrity import (
    generate_keypair,
    sha256_digest,
    sign_artifact,
    verify_artifact,
)


@pytest.fixture
def signed_artifact(tmp_path):
    """A real artifact (copy of the actual trained model, not a stub) with
    a real signature, in an isolated tmp dir so tests never touch the
    committed models/baseline_model.joblib.sig."""
    repo_root = Path(__file__).resolve().parents[2]
    original = repo_root / "models" / "baseline_model.joblib"
    if not original.exists():
        pytest.skip("models/baseline_model.joblib not present (run `dvc pull` first)")

    artifact_path = tmp_path / "model.joblib"
    shutil.copyfile(original, artifact_path)

    private_key, public_key = generate_keypair()
    signature = sign_artifact(artifact_path, private_key)
    return artifact_path, signature, public_key


def test_legitimate_artifact_verifies(signed_artifact):
    artifact_path, signature, public_key = signed_artifact
    assert verify_artifact(artifact_path, signature, public_key) is True


def _tamper_flip_byte(data: bytearray, offset: int) -> bytearray:
    data[offset] ^= 0xFF
    return data


TAMPER_CASES = [
    ("flip_byte_at_start", lambda d: _tamper_flip_byte(d, 0)),
    ("flip_byte_at_1000", lambda d: _tamper_flip_byte(d, 1000)),
    ("flip_byte_at_middle", lambda d: _tamper_flip_byte(d, len(d) // 2)),
    ("flip_byte_near_end", lambda d: _tamper_flip_byte(d, len(d) - 10)),
    ("flip_last_byte", lambda d: _tamper_flip_byte(d, len(d) - 1)),
    ("truncate_last_100_bytes", lambda d: d[:-100]),
    ("truncate_to_half", lambda d: d[: len(d) // 2]),
    ("append_extra_bytes", lambda d: d + b"malicious-appended-payload"),
    ("zero_out_a_chunk", lambda d: d[:5000] + bytearray(200) + d[5200:]),
    ("prepend_bytes", lambda d: bytearray(b"\x00\x01\x02") + d),
]


@pytest.mark.parametrize("case_name,tamper_fn", TAMPER_CASES, ids=[c[0] for c in TAMPER_CASES])
def test_tampered_artifact_fails_verification(signed_artifact, tmp_path, case_name, tamper_fn):
    artifact_path, signature, public_key = signed_artifact

    original_bytes = bytearray(artifact_path.read_bytes())
    tampered_bytes = tamper_fn(bytearray(original_bytes))
    assert bytes(tampered_bytes) != bytes(original_bytes), f"{case_name} didn't actually change the content"

    tampered_path = tmp_path / f"tampered_{case_name}.joblib"
    tampered_path.write_bytes(bytes(tampered_bytes))

    assert verify_artifact(tampered_path, signature, public_key) is False


def test_ten_tamper_cases_all_fail_and_original_passes(signed_artifact):
    """Explicit count check matching the spec's '10/10' gate wording, not
    just individual parametrized passes."""
    assert len(TAMPER_CASES) == 10

    artifact_path, signature, public_key = signed_artifact
    original_bytes = artifact_path.read_bytes()

    failures = 0
    for case_name, tamper_fn in TAMPER_CASES:
        tampered = tamper_fn(bytearray(original_bytes))
        tmp_file = artifact_path.parent / f"case_{case_name}.joblib"
        tmp_file.write_bytes(bytes(tampered))
        if verify_artifact(tmp_file, signature, public_key) is False:
            failures += 1

    assert failures == 10, f"expected all 10 tampered cases to fail verification, got {failures}/10"
    assert verify_artifact(artifact_path, signature, public_key) is True
