"""Phase 8 gate test — the full RBAC permission matrix. Every role x
action combination and its expected outcome is locked in
docs/phase8_governance_spec.md (Part D) before this file was written:
44 combinations, each must match the PERMISSIONS matrix exactly.
"""
import time

import jwt
import pytest

from src.governance.auth import (
    ALL_ACTIONS,
    APPROVER,
    DATA_ENGINEER,
    JWT_ALGORITHM,
    ML_ENGINEER,
    PERMISSIONS,
    ROLES,
    SECURITY_REVIEWER,
    authorize,
    issue_token,
)

TEST_SECRET = "test-secret-not-for-production-32bytes-min"


def _token_for(role, subject="test-user"):
    return issue_token(subject, role, secret=TEST_SECRET)


# --- Full matrix: 4 roles x 11 actions = 44 combinations ------------------

MATRIX_CASES = [
    (role, action)
    for role in sorted(ROLES)
    for action in ALL_ACTIONS
]


@pytest.mark.parametrize("role,action", MATRIX_CASES, ids=[f"{r}:{a}" for r, a in MATRIX_CASES])
def test_rbac_matrix(role, action):
    token = _token_for(role)
    result = authorize(token, action, secret=TEST_SECRET)
    expected_allowed = action in PERMISSIONS[role]
    assert result.allowed == expected_allowed, (
        f"role={role} action={action}: expected allowed={expected_allowed}, got {result.allowed} "
        f"(reason: {result.reason})"
    )
    assert result.role == role
    assert result.subject == "test-user"


def test_matrix_covers_all_11_actions():
    assert len(ALL_ACTIONS) == 11


def test_matrix_covers_all_4_roles():
    assert len(ROLES) == 4


# --- Fail-closed cases beyond the plain matrix -----------------------------

def test_expired_token_denied_regardless_of_role():
    now = int(time.time())
    payload = {"sub": "alice", "role": APPROVER, "iat": now - 7200, "exp": now - 3600}
    expired_token = jwt.encode(payload, TEST_SECRET, algorithm=JWT_ALGORITHM)

    result = authorize(expired_token, "approve_deployment", secret=TEST_SECRET)
    assert result.allowed is False
    assert "expired" in result.reason


def test_forged_token_wrong_secret_denied():
    forged_token = issue_token("mallory", APPROVER, secret="wrong-secret-attacker-guessed")
    result = authorize(forged_token, "approve_deployment", secret=TEST_SECRET)
    assert result.allowed is False
    assert "invalid" in result.reason.lower()


def test_malformed_token_denied():
    result = authorize("not.a.jwt", "approve_deployment", secret=TEST_SECRET)
    assert result.allowed is False


def test_issue_token_rejects_unknown_role():
    with pytest.raises(ValueError):
        issue_token("alice", "SUPER_ADMIN", secret=TEST_SECRET)


# --- Sanity: no implicit hierarchy ------------------------------------------

def test_no_role_has_all_permissions():
    """Least-privilege design check: confirm no single role's permission
    set covers every action - i.e. there really is no de facto admin."""
    for role in ROLES:
        assert PERMISSIONS[role] != set(ALL_ACTIONS), f"{role} has every permission - no role should"
