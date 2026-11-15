"""M2: releases and assessment jobs, against a temporary database and an in-memory object store.
The same code runs against Postgres/MinIO/Redis in the Docker stack (see docs/known_issues.md for what was verified there)."""
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from src.api.main import app
from src.db.session import engine, session_scope
from src.governance.auth import issue_token
from src.jobs import assessments as assessments_module
from src.jobs.celery_app import run_assessment
from src.releases import current_release, register_release, verify_release
from src.storage.objects import ImmutableKeyError, MemoryStore

REPO = Path(__file__).resolve().parents[2]


def headers(role="SECURITY_REVIEWER"):
    return {"Authorization": f"Bearer {issue_token('tester', role)}"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    db = tmp_path / "m2.db"
    monkeypatch.setenv("MLSHIELD_DB_URL", f"sqlite:///{db.as_posix()}")
    engine.cache_clear()
    cfg = Config(str(REPO / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO / "migrations"))
    monkeypatch.syspath_prepend(str(REPO))
    command.upgrade(cfg, "head")

    store = MemoryStore()
    monkeypatch.setattr("src.storage.objects.store_from_env", lambda: store)
    monkeypatch.setattr(run_assessment.app.conf, "task_always_eager", True)
    # asdict() needs a dataclass, so stub run_gate to return the real type
    from src.security.gate import GateResult
    monkeypatch.setattr(assessments_module, "run_gate", lambda: GateResult(
        data_score=90.0, model_score=90.0, dependency_score=95.0, security_score=91.0,
        integrity_component=1.0, decision="PASS", details={"note": "stub"}))
    model = tmp_path / "model.joblib"
    model.write_bytes(b"model-bytes-v1")
    yield SimpleNamespace(store=store, model=model, client=TestClient(app))
    engine.cache_clear()


def register(env, data=None):
    if data is not None:
        env.model.write_bytes(data)
    with session_scope() as s:
        v = register_release(s, env.store, env.model)
        return v.release_id, v.sha256


# --- releases --------------------------------------------------------------

def test_release_id_comes_from_content_and_registration_is_idempotent(env):
    first = register(env)
    assert register(env) == first
    assert first[0] == f"r-{first[1][:16]}"
    assert register(env, b"model-bytes-v2")[0] != first[0]


def test_stored_artifact_verifies_and_tampering_is_detected(env):
    register(env)
    with session_scope() as s:
        v = current_release(s)
        assert verify_release(v, env.store)
        env.store.objects[v.artifact_key] = b"tampered"
        assert not verify_release(v, env.store)


def test_object_keys_are_immutable():
    store = MemoryStore()
    store.put_immutable("k", b"a")
    store.put_immutable("k", b"a")  # same bytes: fine
    with pytest.raises(ImmutableKeyError):
        store.put_immutable("k", b"b")


def test_releases_route_lists_what_was_registered(env):
    release_id, sha = register(env)
    body = env.client.get("/releases", headers=headers("ML_ENGINEER")).json()
    assert [(r["release_id"], r["sha256"]) for r in body["releases"]] == [(release_id, sha)]


def test_a_second_process_reads_the_same_release(env):
    release_id, _ = register(env)
    engine.cache_clear()  # a new process starts with a fresh connection pool and no memory of the first
    body = env.client.get("/releases", headers=headers("AUDITOR")).json()
    assert body["releases"][0]["release_id"] == release_id


# --- assessments as jobs ---------------------------------------------------

def test_assessment_returns_a_job_id_and_records_the_result_and_report(env):
    register(env)
    created = env.client.post("/assessments", headers=headers())
    assert created.status_code == 202
    job = created.json()["assessment_id"]

    done = env.client.get(f"/assessments/{job}", headers=headers()).json()
    assert done["status"] == "done" and done["decision"] == "PASS"
    assert done["result"]["security_score"] == 91.0
    assert done["finished_at"]
    assert env.store.objects[done["report_key"]]  # immutable report stored


def test_a_failing_gate_is_recorded_as_failed_not_lost(env, monkeypatch):
    register(env)

    def boom():
        raise RuntimeError("scanner exploded")

    monkeypatch.setattr(assessments_module, "run_gate", boom)
    job = env.client.post("/assessments", headers=headers()).json()["assessment_id"]
    row = env.client.get(f"/assessments/{job}", headers=headers()).json()
    assert row["status"] == "failed" and row["decision"] is None
    assert "scanner exploded" in row["result"]["error"]
    assert row["report_key"] is None


def test_no_release_means_409(env):
    assert env.client.post("/assessments", headers=headers()).status_code == 409


def test_unknown_assessment_is_404(env):
    assert env.client.get("/assessments/999", headers=headers()).status_code == 404


def test_unreachable_job_queue_marks_the_job_failed_and_returns_503(env, monkeypatch):
    register(env)

    def down(_id):
        raise ConnectionError("broker down")

    monkeypatch.setattr(run_assessment, "delay", down)
    r = env.client.post("/assessments", headers=headers())
    assert r.status_code == 503
    assert env.client.get("/assessments/1", headers=headers()).json()["status"] == "failed"


def test_routes_return_503_when_no_database_is_configured(monkeypatch):
    monkeypatch.delenv("MLSHIELD_DB_URL", raising=False)
    engine.cache_clear()
    client = TestClient(app)
    assert client.get("/releases", headers=headers("ML_ENGINEER")).status_code == 503
    assert client.post("/assessments", headers=headers()).status_code == 503


def test_roles_without_run_assessment_are_denied(env):
    register(env)
    for role in ("DATA_ENGINEER", "APPROVER", "AUDITOR", "OPERATOR"):
        assert env.client.post("/assessments", headers=headers(role)).status_code == 403, role
