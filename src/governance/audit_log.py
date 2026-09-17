"""Phase 8 — append-only, hash-chained audit log with external anchoring.
Format and verification scheme locked in docs/phase8_governance_spec.md
(Part B) before this file was written.
"""
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOG_PATH = REPO_ROOT / "data" / "audit" / "audit_log.jsonl"

# Outside the repo on purpose - same documented-boundary pattern as the
# JWT secret and Phase 5's signing key. A real deployment would anchor to
# something genuinely independent of this project's own storage (a
# separate write-once cloud log, a public timestamping service).
DEFAULT_ANCHOR_PATH = Path.home() / "mlshield-audit-anchors" / "anchors.jsonl"

GENESIS_HASH = "0" * 64


def _canonical_json(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _compute_entry_hash(seq: int, timestamp: str, actor: str, role: str,
                         action: str, details: dict, prev_hash: str) -> str:
    payload = {
        "seq": seq, "timestamp": timestamp, "actor": actor, "role": role,
        "action": action, "details": details, "prev_hash": prev_hash,
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass
class ChainVerificationResult:
    valid: bool
    n_entries: int
    broken_at_seq: Optional[int] = None
    reason: str = ""


@dataclass
class AnchorVerificationResult:
    valid: bool
    n_anchors_checked: int
    failed_anchor: Optional[dict] = None
    reason: str = ""


class AuditLog:
    """Append-only. The only write path is append() - no method exists to
    edit or remove a past entry, and the file is always opened in append
    mode, never truncate/write mode."""

    def __init__(self, log_path: Path = DEFAULT_LOG_PATH, anchor_path: Path = DEFAULT_ANCHOR_PATH):
        self.log_path = Path(log_path)
        self.anchor_path = Path(anchor_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _read_entries(self) -> list:
        if not self.log_path.exists():
            return []
        entries = []
        with open(self.log_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def append(self, actor: str, role: str, action: str, details: Optional[dict] = None) -> dict:
        entries = self._read_entries()
        seq = len(entries)
        prev_hash = entries[-1]["entry_hash"] if entries else GENESIS_HASH
        timestamp = datetime.now(timezone.utc).isoformat()
        details = details or {}

        entry_hash = _compute_entry_hash(seq, timestamp, actor, role, action, details, prev_hash)
        entry = {
            "seq": seq, "timestamp": timestamp, "actor": actor, "role": role,
            "action": action, "details": details, "prev_hash": prev_hash,
            "entry_hash": entry_hash,
        }

        with open(self.log_path, "a") as f:
            f.write(_canonical_json(entry) + "\n")

        return entry

    def verify_chain(self) -> ChainVerificationResult:
        entries = self._read_entries()
        expected_prev = GENESIS_HASH

        for entry in entries:
            if entry["prev_hash"] != expected_prev:
                return ChainVerificationResult(
                    valid=False, n_entries=len(entries), broken_at_seq=entry["seq"],
                    reason=f"prev_hash mismatch at seq {entry['seq']}: "
                           f"expected {expected_prev[:12]}..., got {entry['prev_hash'][:12]}...",
                )
            recomputed = _compute_entry_hash(
                entry["seq"], entry["timestamp"], entry["actor"], entry["role"],
                entry["action"], entry["details"], entry["prev_hash"],
            )
            if recomputed != entry["entry_hash"]:
                return ChainVerificationResult(
                    valid=False, n_entries=len(entries), broken_at_seq=entry["seq"],
                    reason=f"entry_hash mismatch at seq {entry['seq']} - content was modified after logging",
                )
            expected_prev = entry["entry_hash"]

        return ChainVerificationResult(valid=True, n_entries=len(entries), reason="chain intact")

    def head_hash(self) -> str:
        entries = self._read_entries()
        return entries[-1]["entry_hash"] if entries else GENESIS_HASH

    def anchor_head(self) -> dict:
        """Records the current (seq count, head hash) to the external
        anchor store. Call periodically - each anchor is an independent
        checkpoint later tamper attempts have to survive."""
        entries = self._read_entries()
        anchor = {
            "seq_at_anchor": len(entries),
            "head_hash": self.head_hash(),
            "anchor_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.anchor_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.anchor_path, "a") as f:
            f.write(_canonical_json(anchor) + "\n")
        return anchor

    def _read_anchors(self) -> list:
        if not self.anchor_path.exists():
            return []
        anchors = []
        with open(self.anchor_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    anchors.append(json.loads(line))
        return anchors

    def verify_against_anchors(self) -> AnchorVerificationResult:
        """Replays the log up to each anchor's seq_at_anchor and confirms
        the replayed head hash still matches what was anchored - catches
        an attacker who tampers with an entry BEFORE an anchor point and
        recomputes every hash after it (which verify_chain() alone cannot
        catch, since that produces an internally-consistent chain)."""
        entries = self._read_entries()
        anchors = self._read_anchors()

        for anchor in anchors:
            n = anchor["seq_at_anchor"]
            if n == 0:
                replayed_head = GENESIS_HASH
            elif n > len(entries):
                return AnchorVerificationResult(
                    valid=False, n_anchors_checked=len(anchors), failed_anchor=anchor,
                    reason=f"anchor references seq_at_anchor={n} but log only has {len(entries)} entries "
                           f"(log was truncated/rolled back)",
                )
            else:
                replayed_head = entries[n - 1]["entry_hash"]

            if replayed_head != anchor["head_hash"]:
                return AnchorVerificationResult(
                    valid=False, n_anchors_checked=len(anchors), failed_anchor=anchor,
                    reason=f"replayed head hash at seq {n} ({replayed_head[:12]}...) does not match "
                           f"anchored hash ({anchor['head_hash'][:12]}...) - history before this "
                           f"anchor point was altered",
                )

        return AnchorVerificationResult(valid=True, n_anchors_checked=len(anchors), reason="all anchors match")
