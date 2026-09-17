"""Phase 4 gate tests — contract, prediction parity, and a basic load check.

Run with the ML venv's pytest: .venv/bin/python -m pytest tests/api/ -v

These exercise the real FastAPI app in-process via TestClient (which is a
real ASGI request/response cycle through Pydantic validation and the
loaded model — not a mock), so a pass here means the same code path a live
`uvicorn`/Docker-run server would execute. See docs/phase4_api_spec.md for
the contract these check against, and progress.md's Phase 4 notes for why
Docker itself isn't exercised in this sandbox.
"""
import concurrent.futures
import time

import pytest
from fastapi.testclient import TestClient

from src.api.main import FEATURE_COLUMNS, _model, app
from src.data.load_dataset import TEST_FILE, load_raw

client = TestClient(app)


@pytest.fixture(scope="module")
def sample_records():
    test_df = load_raw(TEST_FILE)
    sample = test_df[FEATURE_COLUMNS].head(50)
    return sample


# --- Prediction parity -------------------------------------------------

def test_predictions_match_offline_batch_exactly(sample_records):
    records = sample_records.to_dict(orient="records")
    response = client.post("/predict", json={"records": records})
    assert response.status_code == 200

    api_predictions = response.json()["predictions"]
    offline_classes = _model.predict(sample_records)
    offline_probs = _model.predict_proba(sample_records)[:, 1]

    assert len(api_predictions) == len(sample_records)
    for api_pred, offline_class, offline_prob in zip(api_predictions, offline_classes, offline_probs):
        expected_label = "attack" if offline_class == 1 else "normal"
        assert api_pred["label"] == expected_label
        assert api_pred["attack_probability"] == pytest.approx(float(offline_prob), abs=1e-12)


# --- Health --------------------------------------------------------------

def test_health_ok():
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["model_loaded"] is True


# --- Contract: valid input -----------------------------------------------

def test_valid_single_record_returns_200(sample_records):
    record = sample_records.head(1).to_dict(orient="records")[0]
    response = client.post("/predict", json={"records": [record]})
    assert response.status_code == 200
    body = response.json()
    assert len(body["predictions"]) == 1
    assert body["predictions"][0]["label"] in ("normal", "attack")
    assert 0.0 <= body["predictions"][0]["attack_probability"] <= 1.0


def test_unseen_service_value_is_not_an_error(sample_records):
    """Deliberate asymmetry documented in docs/phase4_api_spec.md: `service`
    is not restricted to a known set, matching the model's own
    handle_unknown="ignore" encoding from Phase 1."""
    record = sample_records.head(1).to_dict(orient="records")[0]
    record["service"] = "totally_novel_service_xyz"
    response = client.post("/predict", json={"records": [record]})
    assert response.status_code == 200


# --- Contract: invalid input -----------------------------------------------

@pytest.fixture
def base_record(sample_records):
    return sample_records.head(1).to_dict(orient="records")[0]


def test_missing_field_returns_422(base_record):
    bad = dict(base_record)
    del bad["duration"]
    response = client.post("/predict", json={"records": [bad]})
    assert response.status_code == 422


def test_wrong_type_returns_422(base_record):
    bad = dict(base_record)
    bad["duration"] = "not_a_number"
    response = client.post("/predict", json={"records": [bad]})
    assert response.status_code == 422


def test_unknown_protocol_type_returns_422(base_record):
    bad = dict(base_record)
    bad["protocol_type"] = "smtp_hijack"
    response = client.post("/predict", json={"records": [bad]})
    assert response.status_code == 422


def test_unknown_flag_returns_422(base_record):
    bad = dict(base_record)
    bad["flag"] = "NOTAFLAG"
    response = client.post("/predict", json={"records": [bad]})
    assert response.status_code == 422


def test_rate_above_one_returns_422(base_record):
    bad = dict(base_record)
    bad["serror_rate"] = 1.5
    response = client.post("/predict", json={"records": [bad]})
    assert response.status_code == 422


def test_negative_count_returns_422(base_record):
    bad = dict(base_record)
    bad["duration"] = -5
    response = client.post("/predict", json={"records": [bad]})
    assert response.status_code == 422


def test_empty_records_list_returns_422():
    response = client.post("/predict", json={"records": []})
    assert response.status_code == 422


def test_malformed_json_body_returns_422():
    response = client.post("/predict", json={"not_records": []})
    assert response.status_code == 422


# --- Basic load check --------------------------------------------------

def test_basic_concurrent_load(sample_records):
    """Smoke-level check, not a performance benchmark (out of scope for
    the MVP per docs/phase4_api_spec.md) - just confirms the service
    doesn't fall over or serialize badly under a burst of concurrent
    requests."""
    records = sample_records.to_dict(orient="records")
    n_requests = 30

    def make_request():
        return client.post("/predict", json={"records": records})

    start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        responses = list(executor.map(lambda _: make_request(), range(n_requests)))
    elapsed = time.monotonic() - start

    assert all(r.status_code == 200 for r in responses)
    assert all(len(r.json()["predictions"]) == len(records) for r in responses)
    assert elapsed < 30, f"{n_requests} concurrent batch requests took {elapsed:.1f}s (>30s budget)"
