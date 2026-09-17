"""Phase 8 — ties Phase 7's Security Gate decision to RBAC and the audit
log. Workflow rules locked in docs/phase8_governance_spec.md (Part C)
before this file was written.
"""
from dataclasses import dataclass
from typing import Optional

from src.governance.audit_log import AuditLog, DEFAULT_LOG_PATH, DEFAULT_ANCHOR_PATH
from src.governance.auth import APPROVER, authorize
from src.security.gate import GateResult


@dataclass
class ApprovalOutcome:
    recorded: bool
    reason: str
    audit_entry: Optional[dict] = None


def log_gate_result(gate_result: GateResult, audit_log: Optional[AuditLog] = None) -> dict:
    """PASS/FAIL/BORDERLINE are all logged immediately - this is not the
    approval step, just the record that the gate ran and what it decided.
    Called by the system itself, not a named human actor."""
    audit_log = audit_log or AuditLog()
    return audit_log.append(
        actor="system",
        role="SYSTEM",
        action="security_gate_evaluated",
        details={
            "decision": gate_result.decision,
            "security_score": gate_result.security_score,
            "data_score": gate_result.data_score,
            "model_score": gate_result.model_score,
            "dependency_score": gate_result.dependency_score,
        },
    )


def approve_or_reject(
    gate_result: GateResult,
    token: str,
    decision: str,
    justification: str,
    audit_log: Optional[AuditLog] = None,
) -> ApprovalOutcome:
    """Only reachable/meaningful for a BORDERLINE gate result. Requires a
    valid APPROVER-role token and a non-empty justification - an approval
    with no stated reason is not a real approval (see spec Part C)."""
    audit_log = audit_log or AuditLog()

    if gate_result.decision != "BORDERLINE":
        return ApprovalOutcome(
            recorded=False,
            reason=f"gate decision is {gate_result.decision}, not BORDERLINE - "
                   f"no approval step applies (PASS/FAIL are auto-decided)",
        )

    if decision not in ("approved", "rejected"):
        return ApprovalOutcome(recorded=False, reason=f"decision must be 'approved' or 'rejected', got {decision!r}")

    if not justification or not justification.strip():
        return ApprovalOutcome(recorded=False, reason="justification is required and cannot be empty")

    auth_result = authorize(token, "approve_deployment" if decision == "approved" else "reject_deployment")

    if not auth_result.allowed:
        # Denial itself is logged - an unauthorized approval attempt is an
        # auditable event, not a silent no-op.
        entry = audit_log.append(
            actor=auth_result.subject or "unknown",
            role=auth_result.role or "UNKNOWN",
            action="approval_attempt_denied",
            details={"reason": auth_result.reason, "attempted_decision": decision},
        )
        return ApprovalOutcome(recorded=False, reason=auth_result.reason, audit_entry=entry)

    entry = audit_log.append(
        actor=auth_result.subject,
        role=auth_result.role,
        action=f"deployment_{decision}",
        details={
            "justification": justification.strip(),
            "security_score": gate_result.security_score,
            "gate_decision": gate_result.decision,
        },
    )
    return ApprovalOutcome(recorded=True, reason="recorded", audit_entry=entry)
