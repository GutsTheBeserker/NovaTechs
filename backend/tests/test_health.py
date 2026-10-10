"""Unit and integration tests for the Flask backend health-check service."""

import pytest
from app import create_app
from app.config import TestingConfig
from app.security import PrivacyValidator


@pytest.fixture
def client():
    """Create test client configured for the testing environment."""
    app = create_app(TestingConfig)
    with app.test_client() as client:
        yield client


def test_health_check_endpoint(client):
    """Verify that /api/v1/health returns HTTP 200 and expected metadata."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200

    data = response.get_json()
    assert data is not None
    assert data["status"] == "healthy"
    assert data["service"] == "adaptive-phishing-detection-api"
    assert "version" in data
    assert "timestamp_utc" in data
    assert data["privacy_shield"] == "active"

    # ML engine and model provenance
    ml_engine = data["ml_engine"]
    assert "model_artifact_present" in ml_engine
    assert ml_engine["model_status"] in ("ready", "unavailable")
    assert "phase" in ml_engine

    # Scope disclosures
    assert data["scope_disclosure"]["analyzes_page_content"] is False
    assert data["scope_disclosure"]["server_side_fetching"] is False


def test_health_check_alias(client):
    """Verify that /health alias endpoint returns HTTP 200."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"


def test_security_headers(client):
    """Verify defensive security headers are appended to responses."""
    response = client.get("/api/v1/health")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"


def test_privacy_validator_sanitizer():
    """Verify PrivacyValidator rejects disallowed sensitive keys."""
    valid_payload = {
        "fqdn_length": 15,
        "subdomain_count": 1,
        "has_ip_literal": False,
    }
    is_valid, msg = PrivacyValidator.sanitize_and_validate(valid_payload)
    assert is_valid is True

    # PII / credential key rejection
    for sensitive_key in ["password", "token", "cookie", "session", "user", "bearer"]:
        bad_payload = {"fqdn_length": 15, sensitive_key: "leaked_secret"}
        is_valid, msg = PrivacyValidator.sanitize_and_validate(bad_payload)
        assert is_valid is False
        assert "Privacy violation" in msg
