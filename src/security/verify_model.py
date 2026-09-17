"""Phase 5 — verify the current model artifact against its signature.

Uses only the committed public key (security/signing_public_key.pem) —
verification must work for anyone with this repo, without access to the
private signing key. Exit code doubles as the pass/fail signal for the
Security Gate's integrity_component (see docs/security_gate_formula.md
§1.2 — this check is binary by design, no partial credit).
"""
import base64
import json
import sys
from pathlib import Path

from src.security.model_integrity import PUBLIC_KEY_PATH, load_public_key, verify_artifact

REPO_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = REPO_ROOT / "models" / "baseline_model.joblib"
SIGNATURE_PATH = REPO_ROOT / "models" / "baseline_model.joblib.sig"


def verify(artifact_path: Path = MODEL_PATH, signature_path: Path = SIGNATURE_PATH) -> bool:
    if not artifact_path.exists() or not signature_path.exists():
        return False

    sig_data = json.loads(signature_path.read_text())
    signature = base64.b64decode(sig_data["signature_b64"])
    public_key = load_public_key(PUBLIC_KEY_PATH)

    return verify_artifact(artifact_path, signature, public_key)


def main() -> int:
    ok = verify()
    if ok:
        print(f"VERIFY OK: {MODEL_PATH} matches its signature")
        return 0
    else:
        print(f"VERIFY FAIL: {MODEL_PATH} does NOT match its signature — integrity check failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
