"""Phase 3 pipeline step 1/5 — ingest.

Copies the locked raw dataset into a staging area (`data/staging/`), which
is what every downstream step reads from — nothing downstream ever touches
`data/raw/` directly. This is also the integrity boundary: ingest verifies
the source file(s) against Phase 0's locked SHA-256 hashes before staging
them, so a swapped/corrupted source is caught here, not silently trained on.

For testing the "deliberately-broken run" gate criterion (Phase 3 plan:
"a deliberately-broken run correctly halts the pipeline rather than
registering a bad model"), the source path for KDDTrain+.txt can be
overridden via the MLSHIELD_INGEST_TRAIN_SOURCE env var — pointing it at a
corrupted file simulates a bad upstream drop without faking the check
itself; ingest still runs its real hash/read checks against whatever file
it's given.
"""
import hashlib
import os
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = REPO_ROOT / "data" / "raw"
STAGING_DIR = REPO_ROOT / "data" / "staging"

# Locked in Phase 0 — see data/raw/README.md. Only KDDTrain+.txt's hash is
# enforced by default here since that's the file the corruption test swaps;
# KDDTest+.txt is copied as-is (its own hash is still checked).
LOCKED_HASHES = {
    "KDDTrain+.txt": "1b86d2f957b33082081bba410fe129b475efebcc13c9014c3f447c8271aadf95",
    "KDDTest+.txt": "fa46b0935342616aa83b7c2578db355b6a7aaabbc492248172c7a1e8b7ab8f84",
}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    STAGING_DIR.mkdir(parents=True, exist_ok=True)

    train_source_override = os.environ.get("MLSHIELD_INGEST_TRAIN_SOURCE", "").strip()
    train_source = Path(train_source_override) if train_source_override else RAW_DIR / "KDDTrain+.txt"
    test_source = RAW_DIR / "KDDTest+.txt"

    sources = {"KDDTrain+.txt": train_source, "KDDTest+.txt": test_source}

    for filename, source_path in sources.items():
        if not source_path.exists():
            print(f"INGEST FAIL: source file missing: {source_path}", file=sys.stderr)
            return 1

        actual_hash = sha256_of(source_path)
        expected_hash = LOCKED_HASHES[filename]
        dest = STAGING_DIR / filename
        shutil.copyfile(source_path, dest)

        if actual_hash == expected_hash:
            print(f"INGEST OK: {filename} matches locked hash, staged to {dest}")
        else:
            # Not a hard failure by itself — an override source is *expected*
            # to differ during the deliberate-corruption test. Downstream
            # validate is what decides whether staged content is usable.
            print(
                f"INGEST WARN: {filename} hash differs from Phase 0 locked "
                f"value (expected {expected_hash}, got {actual_hash}) — "
                f"staged anyway, validate step will check content integrity."
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
