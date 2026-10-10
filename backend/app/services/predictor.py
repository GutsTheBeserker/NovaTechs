"""ML Predictor Service for Phishing Classification.

Safely loads the trained scikit-learn pipeline, validates feature payloads,
computes inference probabilities, and provides explainable factor attribution.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np

from app.ml.features import (
    FEATURE_DESCRIPTIONS,
    URL_FEATURE_NAMES,
    extract_features_vector,
)


class PhishingPredictor:
    """Thread-safe singleton predictor for URL topological phishing detection."""

    _instance: Optional[PhishingPredictor] = None
    _model = None
    _metadata: Optional[Dict[str, Any]] = None
    _model_path: Optional[Path] = None
    _metadata_path: Optional[Path] = None

    def __init__(
        self,
        model_path: Optional[Path] = None,
        metadata_path: Optional[Path] = None,
    ) -> None:
        self._model_path = model_path
        self._metadata_path = metadata_path
        self._load_model()

    @classmethod
    def get_instance(
        cls,
        model_path: Optional[Path] = None,
        metadata_path: Optional[Path] = None,
    ) -> PhishingPredictor:
        """Retrieve or initialize the predictor singleton."""
        if cls._instance is None:
            cls._instance = cls(model_path, metadata_path)
        elif model_path and cls._instance._model_path != model_path:
            # Reinitialize if path changed (e.g. for testing)
            cls._instance = cls(model_path, metadata_path)
        return cls._instance

    def _load_model(self) -> None:
        """Safely load model artifact and metadata without crashing if missing."""
        self._model = None
        self._metadata = None

        if not self._model_path or not self._model_path.exists():
            return

        try:
            # Load trusted locally trained joblib pipeline
            self._model = joblib.load(self._model_path)
        except Exception:
            self._model = None
            return

        if self._metadata_path and self._metadata_path.exists():
            try:
                with open(self._metadata_path, "r", encoding="utf-8") as f:
                    self._metadata = json.load(f)
            except Exception:
                self._metadata = None

    @property
    def is_available(self) -> bool:
        """Check if model is currently loaded and ready for inference."""
        return self._model is not None

    @property
    def metadata(self) -> Optional[Dict[str, Any]]:
        """Return model metadata if available."""
        return self._metadata

    def predict(
        self, input_data: Dict[str, Any] | str
    ) -> Dict[str, Any]:
        """Perform inference on input URL string or feature dictionary.

        Args:
            input_data: A URL string or a dictionary of feature values.

        Returns:
            Structured risk assessment dictionary with probability, classification,
            score, and explainable evidence.
        """
        if not self.is_available:
            return {
                "model_available": False,
                "model_version": None,
                "probability": None,
                "risk_score": None,
                "classification": "UNAVAILABLE",
                "evidence": [],
                "status": "model_not_ready",
                "message": "Phishing detection ML model is not available or not loaded.",
            }

        # 1. Extract vector and feature dictionary
        vector, feature_dict = extract_features_vector(input_data)
        X = np.array([vector], dtype=np.float32)

        # 2. Compute probabilities
        try:
            probabilities = self._model.predict_proba(X)[0]
            phishing_proba = float(probabilities[1])
        except Exception as exc:
            return {
                "model_available": False,
                "model_version": self._metadata.get("model_metadata_version") if self._metadata else None,
                "probability": None,
                "risk_score": None,
                "classification": "ERROR",
                "evidence": [],
                "status": "inference_error",
                "message": f"Inference execution failed: {str(exc)}",
            }

        # 3. Derive 0-100 risk score and classification
        risk_score = int(round(phishing_proba * 100))
        risk_score = max(0, min(100, risk_score))

        if risk_score <= 29:
            classification = "LOW"
        elif risk_score <= 59:
            classification = "MEDIUM"
        else:
            classification = "HIGH"

        # 4. Generate Explainable Factor Evidence
        evidence = self._generate_evidence(feature_dict, phishing_proba)

        # 5. Extract metadata info
        version = self._metadata.get("model_metadata_version", "1.0.0") if self._metadata else "1.0.0"
        algorithm = self._metadata.get("algorithm", "RandomForestClassifier") if self._metadata else "RandomForestClassifier"

        return {
            "model_available": True,
            "model_version": version,
            "algorithm": algorithm,
            "probability": round(phishing_proba, 4),
            "risk_score": risk_score,
            "classification": classification,
            "evidence": evidence,
            "features_evaluated": len(URL_FEATURE_NAMES),
            "privacy_mode": "topological_url_only",
            "scope": {
                "analyzes_page_content": False,
                "server_side_fetching": False,
                "analysis_target": "URL and domain topological structure",
            },
        }

    def _generate_evidence(
        self,
        features: Dict[str, float],
        phishing_proba: float,
    ) -> List[Dict[str, Any]]:
        """Identify key contributing indicators based on feature values and importances."""
        evidence_list: List[Dict[str, Any]] = []

        # Reference feature importance weights from metadata if present
        importance_map: Dict[str, float] = {}
        if self._metadata and "features" in self._metadata:
            for item in self._metadata["features"].get("feature_importances", []):
                importance_map[item["feature"]] = item.get("importance_percent", 1.0)

        # Evaluate notable anomalous signals
        # 1. IP literal domain
        if features.get("domain_in_ip", 0.0) >= 1.0:
            evidence_list.append({
                "feature": "domain_in_ip",
                "name": "Host Uses Direct IP Literal",
                "value": 1,
                "severity": "HIGH",
                "importance_weight": importance_map.get("domain_in_ip", 5.0),
                "description": "Legitimate organizations rarely use bare IP addresses for web services.",
            })

        # 2. @ symbol in URL
        if features.get("qty_at_url", 0.0) >= 1.0:
            evidence_list.append({
                "feature": "qty_at_url",
                "name": "Credential Obfuscation Character (@)",
                "value": int(features["qty_at_url"]),
                "severity": "HIGH",
                "importance_weight": importance_map.get("qty_at_url", 4.0),
                "description": "The '@' character in URLs is frequently exploited to obscure destination hosts.",
            })

        # 3. Excessive subdomains / dots
        qty_dot_domain = features.get("qty_dot_domain", 0.0)
        if qty_dot_domain >= 3.0:
            evidence_list.append({
                "feature": "qty_dot_domain",
                "name": "Excessive Subdomain Levels",
                "value": int(qty_dot_domain),
                "severity": "MEDIUM",
                "importance_weight": importance_map.get("qty_dot_domain", 6.0),
                "description": f"Domain contains {int(qty_dot_domain)} dots, indicating deep subdomain spoofing.",
            })

        # 4. Excessive hyphens in domain
        qty_hyphen_domain = features.get("qty_hyphen_domain", 0.0)
        if qty_hyphen_domain >= 2.0:
            evidence_list.append({
                "feature": "qty_hyphen_domain",
                "name": "Multiple Hyphens in Hostname",
                "value": int(qty_hyphen_domain),
                "severity": "MEDIUM",
                "importance_weight": importance_map.get("qty_hyphen_domain", 5.0),
                "description": "Phishers commonly concatenate brand names with hyphens.",
            })

        # 5. Server/Client keyword in domain
        if features.get("server_client_domain", 0.0) >= 1.0:
            evidence_list.append({
                "feature": "server_client_domain",
                "name": "Server/Client Keyword in Host",
                "value": 1,
                "severity": "MEDIUM",
                "importance_weight": importance_map.get("server_client_domain", 3.0),
                "description": "Use of 'server' or 'client' keyword in hostname often mimics internal infrastructure.",
            })

        # 6. Abnormally long URL
        length_url = features.get("length_url", 0.0)
        if length_url > 80.0:
            evidence_list.append({
                "feature": "length_url",
                "name": "Unusually Long URL",
                "value": int(length_url),
                "severity": "LOW" if length_url < 120 else "MEDIUM",
                "importance_weight": importance_map.get("length_url", 8.0),
                "description": f"URL length is {int(length_url)} characters (typical benign URLs are < 60 characters).",
            })

        # 7. Multiple TLD tokens in URL
        qty_tld = features.get("qty_tld_url", 0.0)
        if qty_tld >= 2.0:
            evidence_list.append({
                "feature": "qty_tld_url",
                "name": "Multiple TLD Patterns in URL",
                "value": int(qty_tld),
                "severity": "MEDIUM",
                "importance_weight": importance_map.get("qty_tld_url", 4.0),
                "description": "Multiple TLD suffixes inside subdomains or path frequently signal brand spoofing.",
            })

        # 8. Excessive percent encoding
        qty_percent = features.get("qty_percent_url", 0.0)
        if qty_percent >= 3.0:
            evidence_list.append({
                "feature": "qty_percent_url",
                "name": "Heavy Percent Encoding",
                "value": int(qty_percent),
                "severity": "LOW",
                "importance_weight": importance_map.get("qty_percent_url", 3.0),
                "description": "High frequency of percent-encoded hex sequences used to bypass content filters.",
            })

        # If no anomalous indicators triggered but score is low
        if not evidence_list and phishing_proba < 0.30:
            evidence_list.append({
                "feature": "url_topology_normal",
                "name": "Standard URL Topology",
                "value": 0,
                "severity": "INFO",
                "importance_weight": 0.0,
                "description": "URL length, character frequencies, and domain structure conform to normal benign profiles.",
            })

        return evidence_list
