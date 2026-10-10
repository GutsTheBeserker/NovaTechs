"""Business logic and ML model evaluation service definitions.

Phase 1 provides the service architecture contract. Phase 2 will bind the
reproducibly trained scikit-learn model and explainability feature attribution.
"""

from typing import Any, Dict


class PredictionServiceContract:
    """Interface definition for the ML prediction and explainability service."""

    @staticmethod
    def validate_features(features: Dict[str, Any]) -> bool:
        """Validate feature dictionary schema before inference."""
        raise NotImplementedError("Feature validation will be active in Phase 2.")

    @staticmethod
    def predict_risk(features: Dict[str, Any]) -> Dict[str, Any]:
        """Compute calibrated probability and factor attribution."""
        raise NotImplementedError("ML inference will be bound in Phase 2.")
