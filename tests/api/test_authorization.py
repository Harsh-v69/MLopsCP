"""M3: authorization tests for every route, through the real API with OIDC tokens.

The route inventory test fails when a route is added without being classified
below, so a new privileged route cannot ship without an authorization test.
"""
import importlib
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import src.api.main as main_module
from src.governance import oidc
from src.governance.auth import PERMISSIONS, ROLES

ISSUER = "https://idp.example/realms/mlshield"
AUD = "mlshield-api"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Every route must be listed in exactly one place. PROTECTED maps a route to the
# action the permission matrix (docs/phase8_governance_spec.md) requires.
PROTECTED = {("GET", "/audit-log"): "view_audit_log"}

# Open on purpose today. KI-21: /security-gate and /model-card expose security
# details without a login; requiring one is an open product decision.
PUBLIC = {
    ("GET", "/health"), ("GET", "/health/live"), ("GET", "/health/ready"),
    ("POST", "/predict"), ("POST", "/predict/explain"),
    ("GET", "/model-card"), ("GET", "/security-gate"),
}
DEV_ONLY = {("POST", "/auth/dev-token")}


class _Key:
    key = KEY.public_key()


class _Jwks:
    def get_signing_key_from_jwt(self, _t):
        return _Key()


def token(roles=(), top_level_role=None, resource_roles=None, **over):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUD, "sub": "tester", "iat": now, "exp": now + 300,
              "realm_access": {"roles": list(roles)}}
    if top_level_role:
        claims["role"] = top_level_role
    if resource_roles:
        claims["resource_access"] = {"mlshield-api": {"roles": list(resource_roles)}}
    claims.update(over)
    return jwt.encode(claims, KEY, algorithm="RS256")


def routes_of(app):
    return {(m, r.path) for r in app.routes if isinstance(r, APIRoute) for m in r.methods if m != "HEAD"}


@pytest.fixture(scope="module")
def prod():
    mp = pytest.MonkeyPatch()
    mp.setenv("MLSHIELD_ENV", "production")
    mp.setenv("MLSHIELD_OIDC_ISSUER", ISSUER)
    mp.setenv("MLSHIELD_OIDC_AUDIENCE", AUD)
    mp.setattr(oidc, "_jwks_client", lambda: _Jwks())
    module = importlib.reload(main_module)
    yield module
    mp.undo()
    importlib.reload(main_module)


@pytest.fixture
def client(prod):
    return TestClient(prod.app)


# --- inventory -------------------------------------------------------------

def test_every_route_is_classified(prod):
    assert routes_of(prod.app) == set(PROTECTED) | PUBLIC


def test_dev_only_route_is_classified_in_dev():
    mp = pytest.MonkeyPatch()
    mp.setenv("MLSHIELD_ENV", "dev")
    try:
        module = importlib.reload(main_module)
        assert routes_of(module.app) == set(PROTECTED) | PUBLIC | DEV_ONLY
    finally:
        mp.undo()
        importlib.reload(main_module)


def test_protected_actions_exist_in_the_permission_matrix():
    known = set().union(*PERMISSIONS.values())
    assert set(PROTECTED.values()) <= known


# --- protected routes: authentication --------------------------------------

@pytest.mark.parametrize("method,path", sorted(PROTECTED))
@pytest.mark.parametrize("headers", [
    {},
    {"Authorization": ""},
    {"Authorization": "Basic dXNlcjpwYXNz"},
    {"Authorization": "Bearer"},
    {"Authorization": "not-a-bearer-token"},
])
def test_missing_or_malformed_credentials_are_401(client, method, path, headers):
    assert client.request(method, path, headers=headers).status_code == 401


@pytest.mark.parametrize("method,path", sorted(PROTECTED))
@pytest.mark.parametrize("bad", ["abc.def.ghi", "x", "Bearer-ish"])
def test_garbage_bearer_tokens_are_403(client, method, path, bad):
    assert client.request(method, path, headers={"Authorization": f"Bearer {bad}"}).status_code == 403


@pytest.mark.parametrize("method,path", sorted(PROTECTED))
@pytest.mark.parametrize("name,tok", [
    ("expired", lambda: token(["APPROVER"], exp=int(time.time()) - 10)),
    ("wrong audience", lambda: token(["APPROVER"], aud="other-api")),
    ("wrong issuer", lambda: token(["APPROVER"], iss="https://evil.example/realms/x")),
    ("no roles", lambda: token([])),
])
def test_invalid_tokens_are_403(client, method, path, name, tok):
    assert client.request(method, path, headers={"Authorization": f"Bearer {tok()}"}).status_code == 403, name


# --- protected routes: authorization (the permission matrix) ---------------

@pytest.mark.parametrize("method,path", sorted(PROTECTED))
@pytest.mark.parametrize("role", sorted(ROLES))
def test_each_role_gets_exactly_what_the_matrix_allows(client, method, path, role):
    expected = 200 if PROTECTED[(method, path)] in PERMISSIONS[role] else 403
    r = client.request(method, path, headers={"Authorization": f"Bearer {token([role])}"})
    assert r.status_code == expected, f"{role} on {method} {path}"


def test_audit_log_matches_the_phase8_spec_exactly(client):
    allowed = {r for r in ROLES
               if client.get("/audit-log", headers={"Authorization": f"Bearer {token([r])}"}).status_code == 200}
    assert allowed == {"SECURITY_REVIEWER", "APPROVER"}


def test_denial_says_why_without_leaking_internals(client):
    r = client.get("/audit-log", headers={"Authorization": f"Bearer {token(['DATA_ENGINEER'])}"})
    assert r.status_code == 403
    assert "no role permits view_audit_log" in r.json()["detail"]


# --- privilege escalation attempts -----------------------------------------

@pytest.mark.parametrize("name,tok", [
    ("top-level role claim", lambda: token([], top_level_role="APPROVER")),
    ("client roles instead of realm roles", lambda: token([], resource_roles=["APPROVER"])),
    ("role-like name that is not ours", lambda: token(["approver", "APPROVER "])),
    ("roles as one string", lambda: token(["APPROVER,SECURITY_REVIEWER"])),
])
def test_roles_from_the_wrong_place_grant_nothing(client, name, tok):
    assert client.get("/audit-log", headers={"Authorization": f"Bearer {tok()}"}).status_code == 403, name


def test_realm_access_that_is_not_a_list_grants_nothing(client):
    bad = token([], realm_access={"roles": "APPROVER"})
    assert client.get("/audit-log", headers={"Authorization": f"Bearer {bad}"}).status_code == 403


def test_local_dev_tokens_are_not_accepted_in_production(client):
    from src.governance.auth import issue_token
    local = issue_token("mallory", "APPROVER", secret="s" * 32)
    assert client.get("/audit-log", headers={"Authorization": f"Bearer {local}"}).status_code == 403


# --- public routes must stay free of any credential requirement ------------

@pytest.mark.parametrize("path", ["/health", "/health/live", "/health/ready"])
def test_health_routes_need_no_credentials(client, path):
    assert client.get(path).status_code in (200, 503)  # 503 only if a file is missing; never 401/403
