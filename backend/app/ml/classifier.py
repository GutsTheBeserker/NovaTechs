"""Explainable Logistic Regression Classifier for Phishing URL Analysis.

Inherits from scikit-learn BaseEstimator and ClassifierMixin to ensure
full interoperability with Pipeline, StandardScaler, joblib, and sklearn metrics.
Optimized using SciPy L-BFGS-B with L2 regularization and optional balanced class weights.
"""

from __future__ import annotations

import numpy as np
from scipy import optimize
from scipy.special import expit
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.utils.validation import check_array, check_is_fitted, check_X_y


class PhishingLogisticClassifier(BaseEstimator, ClassifierMixin):
    """Calibrated, explainable L2-regularized logistic regression classifier.

    Designed for URL/domain topological feature spaces with mathematical explainability.
    """

    def __init__(
        self,
        C: float = 1.0,
        max_iter: int = 300,
        tol: float = 1e-5,
        class_weight: str | None = "balanced",
        random_state: int = 42,
    ) -> None:
        self.C = C
        self.max_iter = max_iter
        self.tol = tol
        self.class_weight = class_weight
        self.random_state = random_state

    def fit(self, X, y) -> PhishingLogisticClassifier:
        """Fit the model according to the given training data."""
        X, y = check_X_y(X, y, accept_sparse=False, dtype=np.float64)
        self.classes_ = np.unique(y)
        if len(self.classes_) != 2:
            raise ValueError("PhishingLogisticClassifier supports binary classification (0: benign, 1: phishing).")

        n_samples, n_features = X.shape
        self.n_features_in_ = n_features

        # Compute sample weights if class_weight == 'balanced'
        if self.class_weight == "balanced":
            n_0 = float(np.sum(y == 0))
            n_1 = float(np.sum(y == 1))
            w0 = n_samples / (2.0 * n_0) if n_0 > 0 else 1.0
            w1 = n_samples / (2.0 * n_1) if n_1 > 0 else 1.0
            sw = np.where(y == 1, w1, w0)
        else:
            sw = np.ones(n_samples, dtype=np.float64)

        # L2 penalty parameter lambda = 1 / C
        reg = 1.0 / (float(self.C) * n_samples)

        def objective_and_gradient(weights):
            w = weights[:-1]
            b = weights[-1]
            z = np.dot(X, w) + b
            p = expit(z)

            # Binary cross entropy with sample weighting and L2 regularization
            eps = 1e-15
            loss = -np.mean(sw * (y * np.log(p + eps) + (1.0 - y) * np.log(1.0 - p + eps))) + 0.5 * reg * np.sum(w**2)

            diff = sw * (p - y)
            grad_w = (np.dot(X.T, diff) / n_samples) + (reg * w)
            grad_b = float(np.mean(diff))

            return loss, np.append(grad_w, grad_b)

        # Initial weights
        rng = np.random.RandomState(self.random_state)
        init_weights = rng.normal(0, 0.01, size=n_features + 1)
        init_weights[-1] = 0.0

        res = optimize.minimize(
            objective_and_gradient,
            init_weights,
            method="L-BFGS-B",
            jac=True,
            options={"maxiter": self.max_iter, "ftol": self.tol},
        )

        self.coef_ = res.x[:-1].reshape(1, -1)
        self.intercept_ = np.array([res.x[-1]])
        self.n_iter_ = np.array([res.nit])
        self.converged_ = res.success

        return self

    def decision_function(self, X) -> np.ndarray:
        """Compute log-odds / margin for input samples."""
        check_is_fitted(self)
        X = check_array(X, accept_sparse=False, dtype=np.float64)
        return np.dot(X, self.coef_.ravel()) + self.intercept_[0]

    def predict_proba(self, X) -> np.ndarray:
        """Compute posterior probabilities for binary classes."""
        scores = self.decision_function(X)
        prob_1 = expit(scores)
        prob_0 = 1.0 - prob_1
        return np.vstack([prob_0, prob_1]).T

    def predict(self, X) -> np.ndarray:
        """Predict binary class labels for samples in X."""
        scores = self.decision_function(X)
        return (scores >= 0.0).astype(int)
