"""Phase 5 — sign the current model artifact.

Bootstraps a signing keypair on first run (private key kept OUTSIDE the
repo — see docs/phase5_security_gate_v1_spec.md "Scheme" and progress.md
Phase 5 notes for why: this stands in for a real KMS/HSM boundary in an
environment with no such infrastructure, same treatment as the DVC remote
in Phase 2). Writes the signature alongside the artifact as
models/baseline_model.joblib.sig (base64, plus metadata, JSON).
"""
import base64
import json
import sys
from pathlib import Path

from src.security.model_integrity import (
    PUBLIC_KEY_PATH,
    generate_keypair,
    load_private_key,
    save_private_key,
    save_public_key,
    sign_artifact,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = REPO_ROOT / "models" / "baseline_model.joblib"
SIGNATURE_PATH = REPO_ROOT / "models" / "baseline_model.joblib.sig"

# Outside the repo on purpose - a private signing key must never be
# committed. Path is local to whatever machine does the signing (analogous
# to the local DVC remote from Phase 2 - a documented MVP stand-in for a
# real KMS/HSM, not something to be reused as-is in production).
PRIVATE_KEY_PATH = Path.home() / "mlshield-signing-key" / "private_key.pem"


def get_or_create_private_key():
    if PRIVATE_KEY_PATH.exists():
        return load_private_key(PRIVATE_KEY_PATH)

    print(f"No signing key found at {PRIVATE_KEY_PATH} — generating a new keypair.")
    private_key, public_key = generate_keypair()
    save_private_key(private_key, PRIVATE_KEY_PATH)
    save_public_key(public_key, PUBLIC_KEY_PATH)
    print(f"Private key written to {PRIVATE_KEY_PATH} (kept outside the repo)")
    print(f"Public key written to {PUBLIC_KEY_PATH} (committed to the repo)")
    return private_key


def main() -> int:
    if not MODEL_PATH.exists():
        print(f"FATAL: model artifact not found at {MODEL_PATH}. Run `dvc pull` first.", file=sys.stderr)
        return 1

    private_key = get_or_create_private_key()
    signature = sign_artifact(MODEL_PATH, private_key)

    SIGNATURE_PATH.write_text(json.dumps({
        "artifact": MODEL_PATH.name,
        "algorithm": "Ed25519",
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }, indent=2))

    print(f"SIGN OK: {MODEL_PATH} signed, signature written to {SIGNATURE_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
