"""Phase 8 gate test — the BORDERLINE approval workflow. Scenarios locked
in docs/phase8_governance_spec.md (Part D)."""
import pytest

from src.governance.approval import approve_or_reject, log_gate_result
from src.governance.audit_log import AuditLog
from src.governance.auth import APPROVER, ML_ENGINEER, issue_token
from src.security.gate import GateResult

TEST_SECRET = "test-secret-not-for-production-32bytes-min"


def _log(tmp_path):
    return AuditLog(log_path=tmp_path / "log.jsonl", anchor_path=tmp_path / "anchors.jsonl")


def _gate_result(decision, security_score=65.0):
    return GateResult(
        data_score=70, model_score=65, dependency_score=60,
        security_score=security_score, integrity_component=100, decision=decision,
    )


@pytest.fixture
def isolated_secret(tmp_path, monkeypatch):
    """Points auth.py's default secret file at an isolated tmp location so
    this test suite never touches (or depends on) the real
    ~/mlshield-governance/jwt_secret.key."""
    import src.governance.auth as auth_module
    secret_path = tmp_path / "jwt_secret.key"
    monkeypatch.setattr(auth_module, "JWT_SECRET_PATH", secret_path)
    return secret_path


def test_borderline_approval_end_to_end_with_default_secret_path(tmp_path, isolated_secret):
    log = _log(tmp_path)
    borderline = _gate_result("BORDERLINE")
    token = issue_token("alice", APPROVER)  # uses the (isolated) default secret path

    outcome = approve_or_reject(borderline, token, "approved", "Reviewed and acceptable risk", log)

    assert outcome.recorded is True
    assert outcome.audit_entry["actor"] == "alice"
    assert outcome.audit_entry["role"] == APPROVER
    assert outcome.audit_entry["action"] == "deployment_approved"
    assert outcome.audit_entry["details"]["justification"] == "Reviewed and acceptable risk"
    assert "timestamp" in outcome.audit_entry


def test_borderline_rejection_end_to_end(tmp_path, isolated_secret):
    log = _log(tmp_path)
    borderline = _gate_result("BORDERLINE")
    token = issue_token("alice", APPROVER)

    outcome = approve_or_reject(borderline, token, "rejected", "Recall too close to the floor this release", log)

    assert outcome.recorded is True
    assert outcome.audit_entry["action"] == "deployment_rejected"


def test_unauthorized_role_cannot_approve(tmp_path, isolated_secret):
    log = _log(tmp_path)
    borderline = _gate_result("BORDERLINE")
    token = issue_token("bob", ML_ENGINEER)

    outcome = approve_or_reject(borderline, token, "approved", "looks fine to me", log)

    assert outcome.recorded is False
    assert "not permitted" in outcome.reason
    # The denied attempt itself must still be logged - not a silent no-op.
    assert outcome.audit_entry is not None
    assert outcome.audit_entry["action"] == "approval_attempt_denied"
    assert outcome.audit_entry["actor"] == "bob"


def test_empty_justification_rejected(tmp_path, isolated_secret):
    log = _log(tmp_path)
    borderline = _gate_result("BORDERLINE")
    token = issue_token("alice", APPROVER)

    outcome = approve_or_reject(borderline, token, "approved", "   ", log)

    assert outcome.recorded is False
    assert "justification" in outcome.reason


def test_pass_result_has_no_approval_step(tmp_path, isolated_secret):
    log = _log(tmp_path)
    passing = _gate_result("PASS", security_score=95.0)
    token = issue_token("alice", APPROVER)

    outcome = approve_or_reject(passing, token, "approved", "n/a", log)

    assert outcome.recorded is False
    assert "not BORDERLINE" in outcome.reason


def test_fail_result_has_no_approval_step(tmp_path, isolated_secret):
    log = _log(tmp_path)
    failing = _gate_result("FAIL", security_score=20.0)
    token = issue_token("alice", APPROVER)

    outcome = approve_or_reject(failing, token, "approved", "n/a", log)

    assert outcome.recorded is False
    assert "not BORDERLINE" in outcome.reason


def test_log_gate_result_auto_logs_every_decision(tmp_path, isolated_secret):
    log = _log(tmp_path)
    for decision in ("PASS", "BORDERLINE", "FAIL"):
        entry = log_gate_result(_gate_result(decision), log)
        assert entry["action"] == "security_gate_evaluated"
        assert entry["details"]["decision"] == decision
        assert entry["actor"] == "system"

    assert log.verify_chain().valid is True
    assert log.verify_chain().n_entries == 3
