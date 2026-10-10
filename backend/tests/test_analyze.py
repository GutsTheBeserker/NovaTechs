"""Comprehensive test suite for POST /api/v1/analyze endpoint and ML inference service."""

import pytest
from app import create_app
from app.config import TestingConfig
from app.services.predictor import PhishingPredictor


@pytest.fixture
def client():
    """Create test client configured for the testing environment."""
    app = create_app(TestingConfig)
    if hasattr(app, "rate_limiter"):
        app.rate_limiter.reset()
    with app.test_client() as client:
        yield client


def test_analyze_valid_benign_url(client):
    """Verify that analyzing a standard URL returns HTTP 200 and structured assessment."""
    response = client.post(
        "/api/v1/analyze",
        json={"url": "https://web.mit.edu"},
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200
    data = response.get_json()

    assert data["status"] in ("success", "degraded")
    assert "analysis_id" in data
    assert "timestamp_utc" in data
    assert "processing_time_ms" in data

    ml = data["ml_assessment"]
    assert ml["model_available"] is True
    assert 0 <= ml["risk_score"] <= 100
    assert ml["classification"] in ("LOW", "MEDIUM", "HIGH")
    assert 0.0 <= ml["probability"] <= 1.0
    assert isinstance(ml["evidence"], list)

    # Privacy and scope disclosures
    scope = data["scope_disclosure"]
    assert scope["analyzes_page_content"] is False
    assert scope["server_side_fetching"] is False


def test_analyze_suspicious_phishing_url(client):
    """Verify that a high-risk obfuscated URL triggers high probability and explainable evidence."""
    suspicious_url = "http://192.168.1.1@account-security-update-login.com/verify-identity"
    response = client.post(
        "/api/v1/analyze",
        json={"url": suspicious_url},
    )
    assert response.status_code == 200
    data = response.get_json()

    ml = data["ml_assessment"]
    assert ml["risk_score"] >= 60
    assert ml["classification"] == "HIGH"
    assert ml["probability"] >= 0.60

    evidence_names = [e["name"] for e in ml["evidence"]]
    assert any("Credential Obfuscation" in name or "IP Literal" in name or "Hyphens" in name for name in evidence_names)


def test_analyze_precomputed_features_zero_url_transmission(client):
    """Verify that client can submit numerical features directly without transmitting any URL."""
    features_payload = {
        "features": {
            "length_url": 25.0,
            "domain_length": 15.0,
            "qty_dot_url": 1.0,
            "qty_dot_domain": 1.0,
            "qty_slash_url": 2.0,
            "qty_vowels_domain": 5.0,
            "domain_in_ip": 0.0,
            "server_client_domain": 0.0,
            "qty_tld_url": 1.0,
        }
    }
    response = client.post("/api/v1/analyze", json=features_payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    ml = data["ml_assessment"]
    assert ml["model_available"] is True
    assert ml["features_evaluated"] == 40


def test_validation_rejects_pii_and_credential_keys(client):
    """Verify PrivacyValidator rejects payloads with sensitive keys."""
    for forbidden_key in ["password", "token", "cookie", "session", "secret", "user"]:
        bad_payload = {"url": "https://example.com", forbidden_key: "leaked_secret"}
        response = client.post("/api/v1/analyze", json=bad_payload)
        assert response.status_code == 400
        data = response.get_json()
        assert data["error_code"] == "PRIVACY_OR_SCHEMA_VIOLATION"
        assert "Privacy violation" in data["message"]


def test_validation_rejects_dangerous_schemes(client):
    """Verify endpoint rejects dangerous, non-HTTP schemes."""
    for bad_scheme_url in [
        "javascript:alert(1)",
        "data:text/html,<script>evil()</script>",
        "file:///etc/passwd",
        "blob:http://example.com/1234",
    ]:
        response = client.post("/api/v1/analyze", json={"url": bad_scheme_url})
        assert response.status_code == 400
        data = response.get_json()
        assert data["error_code"] == "PRIVACY_OR_SCHEMA_VIOLATION"


def test_validation_rejects_empty_or_malformed_payload(client):
    """Verify rejection of empty bodies, non-dict payloads, and missing fields."""
    # Empty object
    resp = client.post("/api/v1/analyze", json={})
    assert resp.status_code == 400
    assert resp.get_json()["error_code"] == "MISSING_REQUIRED_FIELDS"

    # Non-JSON content type
    resp_text = client.post("/api/v1/analyze", data="plain text", content_type="text/plain")
    assert resp_text.status_code == 400
    assert resp_text.get_json()["error_code"] == "INVALID_CONTENT_TYPE"

    # Negative feature values
    resp_neg = client.post("/api/v1/analyze", json={"features": {"length_url": -10.0}})
    assert resp_neg.status_code == 400
    assert resp_neg.get_json()["error_code"] == "PRIVACY_OR_SCHEMA_VIOLATION"


def test_rate_limiting(client):
    """Verify rate limiter blocks excessive requests from the same client IP."""
    # Send 60 requests (within limit)
    for _ in range(60):
        resp = client.post("/api/v1/analyze", json={"url": "https://example.com"})
        assert resp.status_code == 200

    # 61st request should be rate-limited
    resp_blocked = client.post("/api/v1/analyze", json={"url": "https://example.com"})
    assert resp_blocked.status_code == 429
    data = resp_blocked.get_json()
    assert data["error_code"] == "RATE_LIMIT_EXCEEDED"
    assert "Retry-After" in resp_blocked.headers


def test_cors_preflight_and_headers(client):
    """Verify CORS headers for approved extension origins and localhost."""
    extension_origin = "chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef"

    # Preflight OPTIONS request
    preflight = client.open(
        "/api/v1/analyze",
        method="OPTIONS",
        headers={"Origin": extension_origin},
    )
    assert preflight.status_code == 204
    assert preflight.headers.get("Access-Control-Allow-Origin") == extension_origin
    assert "POST" in preflight.headers.get("Access-Control-Allow-Methods")

    # Standard POST request
    post_resp = client.post(
        "/api/v1/analyze",
        json={"url": "https://example.com"},
        headers={"Origin": extension_origin},
    )
    assert post_resp.status_code == 200
    assert post_resp.headers.get("Access-Control-Allow-Origin") == extension_origin


def test_model_unavailable_fallback(monkeypatch, client):
    """Verify that an unavailable model does not crash the server and returns degraded status."""
    monkeypatch.setattr(PhishingPredictor, "is_available", property(lambda self: False))

    response = client.post("/api/v1/analyze", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "degraded"
    assert data["ml_assessment"]["model_available"] is False
    assert data["ml_assessment"]["classification"] == "UNAVAILABLE"

