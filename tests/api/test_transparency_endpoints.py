"""Phase 9 backend tests for the transparency-layer endpoints. Test plan
locked in docs/phase9_transparency_spec.md (Part D) before this file was
written.
"""
import warnings

import pytest
from fastapi.testclient import TestClient

warnings.filterwarnings("ignore")

from src.api.main import app
from src.data.load_dataset import TEST_FILE, load_raw
from src.models.train_baseline import CATEGORICAL_FEATURES, NUMERIC_FEATURES

client = TestClient(app)


@pytest.fixture(scope="module")
def sample_records():
    df = load_raw(TEST_FILE)
    return df[CATEGORICAL_FEATURES + NUMERIC_FEATURES].sample(5, random_state=11).to_dict(orient="records")


# --- /predict/explain -----------------------------------------------------

def test_explain_returns_one_explanation_per_record(sample_records):
    response = client.post("/predict/explain", json={"records": sample_records})
    assert response.status_code == 200
    explanations = response.json()["explanations"]
    assert len(explanations) == len(sample_records)


def test_explain_top_features_capped_at_10(sample_records):
    response = client.post("/predict/explain", json={"records": sample_records})
    for exp in response.json()["explanations"]:
        assert len(exp["top_contributing_features"]) <= 10
        assert "feature" in exp["top_contributing_features"][0]
        assert "shap_value" in exp["top_contributing_features"][0]


def test_explain_matches_predict_label_and_probability(sample_records):
    """The explanation endpoint's own prediction must agree with /predict's
    - two endpoints serving the same model must never disagree."""
    predict_response = client.post("/predict", json={"records": sample_records}).json()
    explain_response = client.post("/predict/explain", json={"records": sample_records}).json()

    for pred, exp in zip(predict_response["predictions"], explain_response["explanations"]):
        assert pred["label"] == exp["label"]
        assert pred["attack_probability"] == pytest.approx(exp["attack_probability"], abs=1e-9)


def test_explain_invalid_input_returns_422():
    response = client.post("/predict/explain", json={"records": []})
    assert response.status_code == 422


# --- /model-card ------------------------------------------------------------

def test_model_card_has_every_documented_section():
    response = client.get("/model-card")
    assert response.status_code == 200
    card = response.json()
    for section in ("identity", "intended_use", "training_data", "performance", "security", "governance", "generated_at"):
        assert section in card, f"model card missing documented section: {section}"


def test_model_card_security_subsections_present():
    card = client.get("/model-card").json()
    security = card["security"]
    for sub in ("data_scan", "model_integrity", "adversarial_robustness", "dependency_scan", "security_gate"):
        assert sub in security


def test_model_card_matches_live_gate(sample_records):
    """Cross-check: the card's embedded security_gate section must match
    a direct call to /security-gate - no stale/recomputed-differently data."""
    card = client.get("/model-card").json()
    gate = client.get("/security-gate").json()
    assert card["security"]["security_gate"]["decision"] == gate["decision"]
    assert card["security"]["security_gate"]["security_score"] == pytest.approx(gate["security_score"])


# --- /security-gate -----------------------------------------------------

def test_security_gate_endpoint_shape():
    response = client.get("/security-gate")
    assert response.status_code == 200
    body = response.json()
    for key in ("decision", "security_score", "data_score", "model_score", "dependency_score", "integrity_component"):
        assert key in body


# --- /audit-log (RBAC-gated) ----------------------------------------------

def test_audit_log_no_auth_header_returns_401():
    response = client.get("/audit-log")
    assert response.status_code == 401


def test_audit_log_malformed_header_returns_401():
    response = client.get("/audit-log", headers={"Authorization": "not-a-bearer-token"})
    assert response.status_code == 401


@pytest.mark.parametrize("role,expected_status", [
    ("DATA_ENGINEER", 403),
    ("ML_ENGINEER", 403),
    ("SECURITY_REVIEWER", 200),
    ("APPROVER", 200),
])
def test_audit_log_rbac_matches_phase8_permission_matrix(role, expected_status):
    """Matches docs/phase8_governance_spec.md's permission matrix exactly:
    view_audit_log is SECURITY_REVIEWER/APPROVER only."""
    token_response = client.post("/auth/dev-token", params={"subject": "test-user", "role": role})
    token = token_response.json()["token"]

    response = client.get("/audit-log", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == expected_status


def test_audit_log_authorized_response_has_verified_chain():
    token = client.post("/auth/dev-token", params={"subject": "alice", "role": "APPROVER"}).json()["token"]
    response = client.get("/audit-log", headers={"Authorization": f"Bearer {token}"})
    body = response.json()
    assert body["chain_valid"] is True
    assert body["n_entries"] == len(body["entries"])


# --- /auth/dev-token -------------------------------------------------------

def test_dev_token_rejects_unknown_role():
    response = client.post("/auth/dev-token", params={"subject": "alice", "role": "SUPER_ADMIN"})
    assert response.status_code == 400
