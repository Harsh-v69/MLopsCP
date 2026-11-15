"""The permission matrix, written out by hand from docs/phase8_governance_spec.md.

test_rbac.py checks authorize() against PERMISSIONS, so it cannot notice a wrong
entry in PERMISSIONS itself. This file pins the table independently: changing a
role's permissions now means changing the spec table AND this literal on purpose.
"""
import pytest

from src.governance.auth import ALL_ACTIONS, PERMISSIONS, ROLES

EXPECTED = {
    "DATA_ENGINEER": {"trigger_ingest", "trigger_validate", "view_data_scan_result", "run_prediction"},
    "ML_ENGINEER": {"trigger_train", "trigger_evaluate", "view_model_metrics", "run_prediction", "run_assessment"},
    "SECURITY_REVIEWER": {"view_security_gate_result", "view_data_scan_result", "view_model_metrics",
                          "view_audit_log", "run_prediction", "run_assessment"},
    "APPROVER": {"view_borderline_queue", "approve_deployment", "reject_deployment",
                 "view_security_gate_result", "view_audit_log", "run_prediction"},
    "AUDITOR": {"view_audit_log", "view_security_gate_result", "view_model_metrics", "view_data_scan_result"},
    "OPERATOR": {"view_security_gate_result", "view_model_metrics", "run_prediction"},
    "ADMIN": {"view_audit_log", "view_security_gate_result", "view_model_metrics", "view_data_scan_result",
              "view_borderline_queue", "run_prediction", "run_assessment"},
}

MUTATING = {"trigger_ingest", "trigger_validate", "trigger_train", "trigger_evaluate",
            "approve_deployment", "reject_deployment"}


def test_roles_match_the_spec():
    assert set(PERMISSIONS) == set(ROLES) == set(EXPECTED)


@pytest.mark.parametrize("role", sorted(EXPECTED))
def test_permissions_match_the_spec_table_exactly(role):
    assert PERMISSIONS[role] == EXPECTED[role]


def test_every_action_is_held_by_someone():
    assert set(ALL_ACTIONS) == set().union(*EXPECTED.values())


# --- separation of duties --------------------------------------------------

def test_only_the_approver_can_approve_or_reject():
    for action in ("approve_deployment", "reject_deployment"):
        assert {r for r, p in PERMISSIONS.items() if action in p} == {"APPROVER"}


def test_nobody_who_builds_can_also_approve():
    builders = {"trigger_ingest", "trigger_validate", "trigger_train", "trigger_evaluate"}
    for role, perms in PERMISSIONS.items():
        assert not (perms & builders and perms & {"approve_deployment", "reject_deployment"}), role


def test_oversight_roles_cannot_change_anything():
    for role in ("AUDITOR", "ADMIN", "OPERATOR"):
        assert not (PERMISSIONS[role] & MUTATING), f"{role} must not hold a mutating action"


def test_auditor_is_read_only():
    assert all(a.startswith("view_") for a in PERMISSIONS["AUDITOR"])


def test_no_role_holds_every_permission():
    for role, perms in PERMISSIONS.items():
        assert perms != set(ALL_ACTIONS), role
