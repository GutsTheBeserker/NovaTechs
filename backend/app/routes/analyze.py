"""Phishing classification analysis endpoint.

Processes incoming topological URL features or sanitized URLs,
runs inference against the trained ML model, and returns explainable risk evidence.
Guarantees zero-PII retention and never performs server-side page downloads.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from flask import Blueprint, current_app, jsonify, request

from app.security import PrivacyValidator
from app.services.predictor import PhishingPredictor

analyze_bp = Blueprint("analyze", __name__)
logger = logging.getLogger("phishguard.analyze")


@analyze_bp.route("/analyze", methods=["POST"])
@analyze_bp.route("/api/v1/analyze", methods=["POST"])
def analyze_url():
    """Analyze URL topological features for phishing indicators.

    Strict Privacy Guarantees:
    - Never fetches or browses submitted URLs.
    - Never logs query strings, tokens, or PII.
    - Only inspects topological structure (length, symbol counts, IP literals).
    """
    start_time = time.time()
    analysis_id = str(uuid.uuid4())

    # 1. Rate Limiting Check
    rate_limiter = getattr(current_app, "rate_limiter", None)
    if rate_limiter:
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
        allowed, retry_after = rate_limiter.is_allowed(client_ip)
        if not allowed:
            logger.warning("Rate limit exceeded for client %s", client_ip)
            return (
                jsonify({
                    "status": "error",
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "message": "Too many requests. Please slow down.",
                    "retry_after_seconds": retry_after,
                }),
                429,
                {"Retry-After": str(retry_after)},
            )

    # 2. Content-Type and Body Validation
    if not request.is_json:
        return (
            jsonify({
                "status": "error",
                "error_code": "INVALID_CONTENT_TYPE",
                "message": "Content-Type must be application/json",
            }),
            400,
        )

    try:
        payload = request.get_json(silent=True)
    except Exception:
        payload = None

    if not isinstance(payload, dict):
        return (
            jsonify({
                "status": "error",
                "error_code": "INVALID_PAYLOAD",
                "message": "Request body must be a valid JSON object",
            }),
            400,
        )

    # 3. Privacy & Schema Validation (reject passwords, tokens, cookies)
    is_valid, validation_msg = PrivacyValidator.sanitize_and_validate(payload)
    if not is_valid:
        return (
            jsonify({
                "status": "error",
                "error_code": "PRIVACY_OR_SCHEMA_VIOLATION",
                "message": validation_msg,
            }),
            400,
        )

    # Must contain either 'url' or 'features'
    has_url = "url" in payload and isinstance(payload["url"], str) and bool(payload["url"].strip())
    has_features = "features" in payload and isinstance(payload["features"], dict) and bool(payload["features"])

    if not has_url and not has_features:
        return (
            jsonify({
                "status": "error",
                "error_code": "MISSING_REQUIRED_FIELDS",
                "message": "Request payload must contain either 'url' or 'features' object",
            }),
            400,
        )

    # 4. Perform Inference
    model_path = current_app.config.get("MODEL_PATH")
    metadata_path = current_app.config.get("METADATA_PATH")
    predictor = PhishingPredictor.get_instance(model_path, metadata_path)

    # Prioritize pre-computed client-side features if provided (optimal privacy)
    inference_input = payload["features"] if has_features else payload["url"]
    prediction_result = predictor.predict(inference_input)

    duration_ms = round((time.time() - start_time) * 1000.0, 2)

    # 5. Anonymized Privacy-Preserving Audit Log (NEVER log URL or query params)
    client_ip_anonymized = request.remote_addr or "127.0.0.1"
    logger.info(
        "Analysis completed [id=%s, ip=%s, status=%s, class=%s, latency=%.2fms]",
        analysis_id,
        client_ip_anonymized,
        "available" if prediction_result.get("model_available") else "unavailable",
        prediction_result.get("classification"),
        duration_ms,
    )

    response_status = "success" if prediction_result.get("model_available") else "degraded"

    return (
        jsonify({
            "status": response_status,
            "analysis_id": analysis_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "ml_assessment": prediction_result,
            "scope_disclosure": {
                "analyzes_page_content": False,
                "server_side_fetching": False,
                "target": "URL and domain topological attributes only",
                "privacy_mode": "zero_pii_no_server_browsing",
            },
            "processing_time_ms": duration_ms,
        }),
        200,
    )
