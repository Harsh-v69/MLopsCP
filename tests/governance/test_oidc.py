"""M3: OIDC token validation, against a locally generated key (no network)."""
import base64
import hashlib
import hmac
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.governance import auth, oidc

ISSUER = "https://idp.example/realms/mlshield"
AUD = "mlshield-api"


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


GOOD, OTHER = _key(), _key()


class _Signing:
    def __init__(self, key):
        self.key = key


class _FakeJwks:
    def get_signing_key_from_jwt(self, _token):
        return _Signing(GOOD.public_key())


class _DownJwks:
    def get_signing_key_from_jwt(self, _token):
        raise jwt.PyJWKClientConnectionError("idp unreachable")


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setenv("MLSHIELD_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("MLSHIELD_OIDC_AUDIENCE", AUD)
    monkeypatch.setenv("MLSHIELD_ENV", "production")
    monkeypatch.setattr(oidc, "_jwks_client", lambda: _FakeJwks())


def make(key=GOOD, alg="RS256", roles=("APPROVER",), **over):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUD, "sub": "alice", "iat": now, "exp": now + 300,
              "realm_access": {"roles": list(roles)}}
    claims.update(over)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg)


def test_valid_token_allowed():
    r = auth.authorize(make(), "view_audit_log")
    assert r.allowed and r.subject == "alice" and r.role == "APPROVER"


@pytest.mark.parametrize("token,why", [
    (make(aud="someone-else"), "wrong audience"),
    (make(iss="https://evil.example/realms/x"), "wrong issuer"),
    (make(exp=int(time.time()) - 10), "expired"),
    (make(key=OTHER), "signed by a different key"),
    (make(exp=None), "missing exp"),
    (make(aud=None), "missing aud"),
])
def test_bad_tokens_denied(token, why):
    assert not auth.authorize(token, "view_audit_log").allowed, why


def test_unsigned_none_algorithm_denied():
    now = int(time.time())
    token = jwt.encode({"iss": ISSUER, "aud": AUD, "sub": "x", "exp": now + 300,
                        "realm_access": {"roles": ["APPROVER"]}}, key=None, algorithm="none")
    assert not auth.authorize(token, "view_audit_log").allowed


def test_hs256_signed_with_public_key_denied():
    """Classic key-confusion attack, built by hand because PyJWT refuses to do it."""
    pem = GOOD.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=")
    now = int(time.time())
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps({"iss": ISSUER, "aud": AUD, "sub": "x", "exp": now + 300,
                           "realm_access": {"roles": ["APPROVER"]}}).encode())
    sig = b64(hmac.new(pem, head + b"." + body, hashlib.sha256).digest())
    token = (head + b"." + body + b"." + sig).decode()
    assert not auth.authorize(token, "view_audit_log").allowed


def test_role_without_permission_denied():
    assert not auth.authorize(make(roles=("DATA_ENGINEER",)), "view_audit_log").allowed


def test_no_known_role_denied_and_unknown_roles_ignored():
    r = auth.authorize(make(roles=("admin", "offline_access")), "view_audit_log")
    assert not r.allowed and "no MLShield role" in r.reason


def test_multiple_roles_union():
    assert auth.authorize(make(roles=("DATA_ENGINEER", "SECURITY_REVIEWER")), "view_audit_log").allowed


def test_identity_provider_unreachable_fails_closed(monkeypatch):
    monkeypatch.setattr(oidc, "_jwks_client", lambda: _DownJwks())
    assert not auth.authorize(make(), "view_audit_log").allowed


def test_production_without_idp_denies_local_tokens(monkeypatch):
    monkeypatch.delenv("MLSHIELD_OIDC_ISSUER")
    monkeypatch.setattr(auth, "_get_or_create_secret", lambda: "s" * 32)
    local = auth.issue_token("alice", "APPROVER", secret="s" * 32)
    r = auth.authorize(local, "view_audit_log")
    assert not r.allowed and "no identity provider" in r.reason
