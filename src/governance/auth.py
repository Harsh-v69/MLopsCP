"""Phase 8 — JWT-based RBAC. Roles, permission matrix, and the token
scheme are locked in docs/phase8_governance_spec.md (Part A) before this
file was written.
"""
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import jwt

from src.governance.oidc import oidc_configured, roles_from_claims, verify_oidc_token

JWT_ALGORITHM = "HS256"
JWT_DEFAULT_EXPIRY_SECONDS = 3600

# Outside the repo on purpose - a real deployment would issue tokens from
# an external identity provider (OAuth/OIDC) and verify against its public
# keys, not a shared local HMAC secret. This stands in for that boundary,
# same pattern as Phase 5's private signing key
# (~/mlshield-signing-key/private_key.pem).
JWT_SECRET_PATH = Path.home() / "mlshield-governance" / "jwt_secret.key"

DATA_ENGINEER = "DATA_ENGINEER"
ML_ENGINEER = "ML_ENGINEER"
SECURITY_REVIEWER = "SECURITY_REVIEWER"
APPROVER = "APPROVER"

ROLES = {DATA_ENGINEER, ML_ENGINEER, SECURITY_REVIEWER, APPROVER}

# Locked in docs/phase8_governance_spec.md Part A. No implicit hierarchy -
# each role's set is exactly what the spec says that role does.
PERMISSIONS = {
    DATA_ENGINEER: {"trigger_ingest", "trigger_validate", "view_data_scan_result"},
    ML_ENGINEER: {"trigger_train", "trigger_evaluate", "view_model_metrics"},
    SECURITY_REVIEWER: {
        "view_security_gate_result", "view_data_scan_result",
        "view_model_metrics", "view_audit_log",
    },
    APPROVER: {
        "view_borderline_queue", "approve_deployment", "reject_deployment",
        "view_security_gate_result", "view_audit_log",
    },
}

ALL_ACTIONS = sorted(set().union(*PERMISSIONS.values()))


def _get_or_create_secret() -> str:
    if JWT_SECRET_PATH.exists():
        return JWT_SECRET_PATH.read_text().strip()
    JWT_SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
    import secrets
    secret = secrets.token_hex(32)
    JWT_SECRET_PATH.write_text(secret)
    return secret


def issue_token(subject: str, role: str, expires_in_seconds: int = JWT_DEFAULT_EXPIRY_SECONDS,
                 secret: Optional[str] = None) -> str:
    if role not in ROLES:
        raise ValueError(f"unknown role: {role!r} (must be one of {sorted(ROLES)})")
    import time
    now = int(time.time())
    payload = {"sub": subject, "role": role, "iat": now, "exp": now + expires_in_seconds}
    return jwt.encode(payload, secret or _get_or_create_secret(), algorithm=JWT_ALGORITHM)


@dataclass
class AuthResult:
    allowed: bool
    subject: Optional[str]
    role: Optional[str]
    reason: str


def authorize(token: str, action: str, secret: Optional[str] = None) -> AuthResult:
    """Fail-closed: any decode/verification failure denies, regardless of
    what action was requested.

    Which tokens are accepted: an explicit `secret` (tests) or MLSHIELD_ENV=dev use
    the local HS256 scheme; otherwise tokens must come from the configured OIDC
    provider, and with none configured everything is denied."""
    if secret is None and oidc_configured():
        return _authorize_oidc(token, action)
    if secret is None and os.environ.get("MLSHIELD_ENV", "production") != "dev":
        return AuthResult(allowed=False, subject=None, role=None, reason="no identity provider configured")
    try:
        payload = jwt.decode(token, secret or _get_or_create_secret(), algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return AuthResult(allowed=False, subject=None, role=None, reason="token expired")
    except jwt.InvalidTokenError as e:
        return AuthResult(allowed=False, subject=None, role=None, reason=f"invalid token: {e}")

    role = payload.get("role")
    subject = payload.get("sub")

    if role not in PERMISSIONS:
        return AuthResult(allowed=False, subject=subject, role=role, reason=f"unknown role: {role}")

    if action not in PERMISSIONS[role]:
        return AuthResult(allowed=False, subject=subject, role=role,
                           reason=f"role {role} is not permitted to {action}")

    return AuthResult(allowed=True, subject=subject, role=role, reason="ok")


def _authorize_oidc(token: str, action: str) -> AuthResult:
    try:
        claims = verify_oidc_token(token)
    except jwt.ExpiredSignatureError:
        return AuthResult(allowed=False, subject=None, role=None, reason="token expired")
    except jwt.PyJWTError as e:  # bad signature/issuer/audience/claims, or keys unreachable
        return AuthResult(allowed=False, subject=None, role=None, reason=f"invalid token: {type(e).__name__}")
    subject = claims.get("sub")
    known = [r for r in roles_from_claims(claims) if r in PERMISSIONS]
    for role in known:
        if action in PERMISSIONS[role]:
            return AuthResult(allowed=True, subject=subject, role=role, reason="ok")
    return AuthResult(allowed=False, subject=subject, role=known[0] if known else None,
                       reason=f"no role permits {action}" if known else "token carries no MLShield role")
