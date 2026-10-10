"""Health check route blueprint providing operational status and readiness probes."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from flask import Blueprint, current_app, jsonify
from pathlib import Path

from app.services.predictor import PhishingPredictor

health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
@health_bp.route("/api/v1/health", methods=["GET"])
def health_check():
    """Return API health status, service metadata, and model readiness.

    Accurately reflects trained ML model status and provenance from model_metadata.json.
    """
    model_path = current_app.config.get("MODEL_PATH")
    metadata_path = current_app.config.get("METADATA_PATH")

    predictor = PhishingPredictor.get_instance(model_path, metadata_path)
    model_ready = predictor.is_available
    meta = predictor.metadata or {}

    ml_info = {
        "phase": "Phase 4 - Machine Learning Phishing Classification Backend",
        "model_artifact_present": model_path.exists() if model_path else False,
        "model_status": "ready" if model_ready else "unavailable",
        "model_version": meta.get("model_metadata_version"),
        "algorithm": meta.get("algorithm"),
        "trained_features_count": meta.get("features", {}).get("total_count", 0),
        "dataset_source": meta.get("dataset", {}).get("source"),
        "evaluation_metrics": meta.get("metrics"),
    }

    return (
        jsonify({
            "status": "healthy",
            "service": "adaptive-phishing-detection-api",
            "version": "1.0.0",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "environment": current_app.config.get("ENV", "unknown"),
            "ml_engine": ml_info,
            "privacy_shield": "active",
            "scope_disclosure": {
                "analyzes_page_content": False,
                "server_side_fetching": False,
                "analysis_target": "URL and domain topological attributes only",
            },
        }),
        200,
    )
