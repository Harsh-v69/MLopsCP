"""Phase 5 — Model Scan: cryptographic artifact signing (not a bare hash).

Scheme locked in docs/phase5_security_gate_v1_spec.md (Part B) before this
file was written: Ed25519, sign the SHA-256 digest of the artifact, public
key committed to the repo, private key kept outside it.
"""
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PUBLIC_KEY_PATH = REPO_ROOT / "security" / "signing_public_key.pem"


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def save_private_key(private_key: Ed25519PrivateKey, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)


def save_public_key(public_key: Ed25519PublicKey, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_public_key(path: Path = PUBLIC_KEY_PATH) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(path.read_bytes())


def sha256_digest(artifact_path: Path) -> bytes:
    h = hashlib.sha256()
    with open(artifact_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


def sign_artifact(artifact_path: Path, private_key: Ed25519PrivateKey) -> bytes:
    """Returns the raw signature bytes over the artifact's SHA-256 digest."""
    digest = sha256_digest(artifact_path)
    return private_key.sign(digest)


def verify_artifact(artifact_path: Path, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    """True if the signature is valid for the artifact's current content,
    False otherwise (never raises for an invalid signature — callers
    should treat False the same as "integrity check failed", per the
    fail-closed rule in docs/security_gate_formula.md)."""
    digest = sha256_digest(artifact_path)
    try:
        public_key.verify(signature, digest)
        return True
    except InvalidSignature:
        return False
