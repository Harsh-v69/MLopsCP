"""Phase 8 gate test — audit log tamper and rollback detection. Protocol
locked in docs/phase8_governance_spec.md (Part D)."""
import json

from src.governance.audit_log import GENESIS_HASH, AuditLog, _compute_entry_hash


def _fresh_log(tmp_path):
    return AuditLog(log_path=tmp_path / "log.jsonl", anchor_path=tmp_path / "anchors.jsonl")


def test_empty_log_verifies_clean(tmp_path):
    log = _fresh_log(tmp_path)
    result = log.verify_chain()
    assert result.valid is True
    assert result.n_entries == 0


def test_first_entry_uses_genesis_prev_hash(tmp_path):
    log = _fresh_log(tmp_path)
    entry = log.append("alice", "APPROVER", "test_action")
    assert entry["prev_hash"] == GENESIS_HASH


def test_clean_chain_verifies(tmp_path):
    log = _fresh_log(tmp_path)
    for i in range(5):
        log.append("alice", "APPROVER", f"action_{i}", {"i": i})
    result = log.verify_chain()
    assert result.valid is True
    assert result.n_entries == 5


def test_in_place_tamper_detected(tmp_path):
    log = _fresh_log(tmp_path)
    for i in range(5):
        log.append("alice", "APPROVER", f"action_{i}", {"i": i})

    # Tamper: edit one historical entry's action WITHOUT recomputing hashes
    # (the naive attack).
    lines = log.log_path.read_text().splitlines()
    entries = [json.loads(l) for l in lines]
    entries[2]["action"] = "HACKED"
    log.log_path.write_text("\n".join(json.dumps(e, sort_keys=True) for e in entries) + "\n")

    result = log.verify_chain()
    assert result.valid is False
    assert result.broken_at_seq == 2


def test_deleted_entry_detected(tmp_path):
    log = _fresh_log(tmp_path)
    for i in range(5):
        log.append("alice", "APPROVER", f"action_{i}", {"i": i})

    lines = log.log_path.read_text().splitlines()
    entries = [json.loads(l) for l in lines]
    del entries[2]  # remove a historical entry, leave the rest untouched
    log.log_path.write_text("\n".join(json.dumps(e, sort_keys=True) for e in entries) + "\n")

    result = log.verify_chain()
    assert result.valid is False


def test_anchor_records_head_hash(tmp_path):
    log = _fresh_log(tmp_path)
    for i in range(3):
        log.append("alice", "APPROVER", f"action_{i}")
    anchor = log.anchor_head()
    assert anchor["seq_at_anchor"] == 3
    assert anchor["head_hash"] == log.head_hash()


def test_anchors_verify_clean_when_untampered(tmp_path):
    log = _fresh_log(tmp_path)
    for i in range(3):
        log.append("alice", "APPROVER", f"action_{i}")
    log.anchor_head()
    for i in range(3, 6):
        log.append("bob", "ML_ENGINEER", f"action_{i}")

    result = log.verify_against_anchors()
    assert result.valid is True
    assert result.n_anchors_checked == 1


def test_pre_anchor_tamper_with_full_recompute_passes_chain_but_fails_anchor(tmp_path):
    """The actual proof external anchoring exists for: an attacker who
    tampers with an entry BEFORE the anchor point and recomputes every
    hash after it produces a chain that verify_chain() alone reports as
    valid - but verify_against_anchors() still catches it, because the
    anchor recorded what the head hash genuinely was at that point in
    time, independent of what the log claims now."""
    log = _fresh_log(tmp_path)
    for i in range(3):
        log.append("alice", "APPROVER", f"action_{i}", {"i": i})
    log.anchor_head()  # anchored at seq_at_anchor=3
    for i in range(3, 6):
        log.append("bob", "ML_ENGINEER", f"action_{i}", {"i": i})

    # Tamper with entry seq=1 (before the anchor) and recompute every
    # hash after it, so the chain is internally self-consistent.
    entries = [json.loads(l) for l in log.log_path.read_text().splitlines()]
    entries[1]["action"] = "HACKED_ACTION"
    prev = GENESIS_HASH
    for e in entries:
        e["prev_hash"] = prev
        e["entry_hash"] = _compute_entry_hash(
            e["seq"], e["timestamp"], e["actor"], e["role"], e["action"], e["details"], e["prev_hash"]
        )
        prev = e["entry_hash"]
    log.log_path.write_text("\n".join(json.dumps(e, sort_keys=True) for e in entries) + "\n")

    chain_result = log.verify_chain()
    assert chain_result.valid is True, "sneaky full-recompute tamper should still pass the plain chain check"

    anchor_result = log.verify_against_anchors()
    assert anchor_result.valid is False, "but the external anchor must catch what the chain check alone cannot"
    assert anchor_result.failed_anchor["seq_at_anchor"] == 3


def test_log_truncation_after_anchor_detected(tmp_path):
    """Rolling the log file back to before an anchor point (deleting
    recent entries wholesale) must also be caught."""
    log = _fresh_log(tmp_path)
    for i in range(5):
        log.append("alice", "APPROVER", f"action_{i}")
    log.anchor_head()  # anchored at seq_at_anchor=5

    # Roll back: truncate the log to only 2 entries.
    entries = [json.loads(l) for l in log.log_path.read_text().splitlines()][:2]
    log.log_path.write_text("\n".join(json.dumps(e, sort_keys=True) for e in entries) + "\n")

    result = log.verify_against_anchors()
    assert result.valid is False
