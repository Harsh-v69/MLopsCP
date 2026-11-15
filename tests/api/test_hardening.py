"""M3: production gating, request limits, headers, safe errors, token rejection."""
import importlib

import pytest
from fastapi.testclient import TestClient

import src.api.main as main_module
from src.api.hardening import app_env
from src.governance.auth import issue_token


def _load(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return importlib.reload(main_module)


@pytest.fixture
def prod(monkeypatch):
    module = _load(monkeypatch, MLSHIELD_ENV="production")
    yield module
    monkeypatch.undo()
    importlib.reload(main_module)  # restore the dev app for the other tests


def test_dev_token_and_docs_absent_in_production(prod):
    client = TestClient(prod.app)
    assert client.post("/auth/dev-token", params={"subject": "a", "role": "APPROVER"}).status_code == 404
    assert client.get("/docs").status_code == 404


def test_production_is_the_default(monkeypatch):
    monkeypatch.delenv("MLSHIELD_ENV", raising=False)
    assert app_env() == "production"


def test_startup_refuses_dev_auth_in_production(monkeypatch):
    monkeypatch.setenv("MLSHIELD_ENV", "production")
    monkeypatch.setenv("MLSHIELD_DEV_AUTH", "1")
    with pytest.raises(RuntimeError, match="refusing to start"):
        app_env()


def test_startup_refuses_unknown_environment(monkeypatch):
    monkeypatch.setenv("MLSHIELD_ENV", "staging")
    with pytest.raises(RuntimeError):
        app_env()


def test_security_headers_and_correlation_id(prod):
    r = TestClient(prod.app).get("/health/live", headers={"X-Correlation-ID": "abc123"})
    assert r.headers["X-Correlation-ID"] == "abc123"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]


def test_oversized_body_rejected(monkeypatch):
    module = _load(monkeypatch, MLSHIELD_ENV="dev", MLSHIELD_MAX_BODY_BYTES="100")
    r = TestClient(module.app).post("/predict", content=b"x" * 500, headers={"Content-Type": "application/json"})
    assert r.status_code == 413
    monkeypatch.undo()
    importlib.reload(main_module)


def test_rate_limit_applies_but_health_is_exempt(monkeypatch):
    module = _load(monkeypatch, MLSHIELD_ENV="dev", MLSHIELD_RATE_LIMIT="3")
    client = TestClient(module.app)
    codes = [client.get("/nope").status_code for _ in range(5)]
    assert 429 in codes[3:]
    assert client.get("/health/live").status_code == 200
    monkeypatch.undo()
    importlib.reload(main_module)


def test_unhandled_error_is_generic_with_correlation_id(prod):
    @prod.app.get("/boom")
    def boom():
        raise RuntimeError("secret internal detail")

    r = TestClient(prod.app, raise_server_exceptions=False).get("/boom")
    assert r.status_code == 500
    assert "secret internal detail" not in r.text
    assert r.json()["correlation_id"]


def test_wrong_signature_and_expired_tokens_denied(prod):
    client = TestClient(prod.app)
    forged = issue_token("mallory", "APPROVER", secret="not-the-real-secret")
    expired = issue_token("alice", "APPROVER", expires_in_seconds=-10)
    for token in (forged, expired):
        assert client.get("/audit-log", headers={"Authorization": f"Bearer {token}"}).status_code == 403
