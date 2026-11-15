"""M3: signing-key rotation and revocation, against a real local JWKS endpoint.

Uses short lifespans (seconds) so the timing rules are exercised for real:
a key the provider removes must stop being trusted once the cached key set
expires, new keys must be picked up, and a flood of unknown key ids must not
turn into a flood of requests to the identity provider.
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from src.governance import auth, oidc

ISSUER = "https://idp.example/realms/mlshield"
AUD = "mlshield-api"
LIFESPAN = 1.0
COOLDOWN = 0.4


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


OLD, NEW = _key(), _key()


def jwk(kid, private):
    d = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    d.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return d


class Idp:
    """A JWKS endpoint whose key set the test can change, break and count."""

    def __init__(self):
        self.keys = []
        self.fail = False
        self.hits = 0
        idp = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                idp.hits += 1
                if idp.fail:
                    self.send_response(500)
                    self.end_headers()
                    return
                body = json.dumps({"keys": idp.keys}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/certs"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()


@pytest.fixture
def idp(monkeypatch):
    server = Idp()
    monkeypatch.setenv("MLSHIELD_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("MLSHIELD_OIDC_AUDIENCE", AUD)
    monkeypatch.setenv("MLSHIELD_ENV", "production")
    monkeypatch.setattr(oidc, "_client", oidc.build_client(server.url, lifespan=LIFESPAN, cooldown=COOLDOWN))
    yield server
    server.stop()


def token(private, kid, **over):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUD, "sub": "alice", "iat": now, "exp": now + 300,
              "realm_access": {"roles": ["APPROVER"]}}
    claims.update(over)
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": kid})


def allowed(tok):
    return auth.authorize(tok, "view_audit_log").allowed


def test_new_key_is_picked_up_after_rotation(idp):
    idp.keys = [jwk("old", OLD)]
    assert allowed(token(OLD, "old"))
    idp.keys = [jwk("old", OLD), jwk("new", NEW)]  # provider publishes the new key alongside the old
    time.sleep(COOLDOWN + 0.1)
    assert allowed(token(NEW, "new"))
    assert allowed(token(OLD, "old"))  # still published, still valid


def test_removed_key_stops_being_trusted_once_the_key_set_expires(idp):
    idp.keys = [jwk("old", OLD), jwk("new", NEW)]
    assert allowed(token(OLD, "old"))
    idp.keys = [jwk("new", NEW)]  # provider revokes the old key
    assert allowed(token(OLD, "old"))  # within the cached key set's lifespan: a known, bounded window
    time.sleep(LIFESPAN + 0.2)
    assert not allowed(token(OLD, "old")), "a revoked key must not be trusted after the key set expires"
    assert allowed(token(NEW, "new"))


def test_unknown_key_ids_do_not_flood_the_identity_provider(idp):
    idp.keys = [jwk("old", OLD)]
    assert allowed(token(OLD, "old"))
    before = idp.hits
    for i in range(25):
        assert not allowed(token(NEW, f"attacker-{i}"))
    assert idp.hits - before <= 2, f"{idp.hits - before} fetches for 25 forged key ids"


def test_unreachable_provider_uses_cached_keys_then_fails_closed(idp):
    idp.keys = [jwk("old", OLD)]
    assert allowed(token(OLD, "old"))
    idp.fail = True
    assert allowed(token(OLD, "old"))  # within the lifespan the cached keys still serve
    time.sleep(LIFESPAN + 0.2)
    assert not allowed(token(OLD, "old"))  # expired cache and no provider: deny


def test_token_without_a_key_id_is_denied(idp):
    idp.keys = [jwk("old", OLD)]
    no_kid = jwt.encode({"iss": ISSUER, "aud": AUD, "sub": "a", "exp": int(time.time()) + 300,
                         "realm_access": {"roles": ["APPROVER"]}}, OLD, algorithm="RS256")
    assert not allowed(no_kid)


def test_key_published_under_a_different_id_is_not_accepted(idp):
    idp.keys = [jwk("old", OLD)]
    assert not allowed(token(NEW, "old"))  # right kid, wrong key material
