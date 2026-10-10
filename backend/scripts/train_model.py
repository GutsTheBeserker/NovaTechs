"""Reproducible Model Training and Evaluation Pipeline.

Trains an explainable Logistic Regression classifier on the authentic Vrbančič et al.
(2020) benchmark dataset using the 40 privacy-preserving URL/domain features.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Ensure backend root is in sys.path
BACKEND_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = BACKEND_ROOT.parent
sys.path.insert(0, str(BACKEND_ROOT))

from app.ml.features import URL_FEATURE_NAMES, FEATURE_DESCRIPTIONS  # noqa: E402
from app.ml.classifier import PhishingLogisticClassifier  # noqa: E402

DATASET_PATH = REPO_ROOT / "data" / "raw" / "dataset_small.csv"
OUTPUT_DIR = BACKEND_ROOT / "app" / "ml" / "models"
MODEL_PATH = OUTPUT_DIR / "phishing_model.joblib"
METADATA_PATH = OUTPUT_DIR / "model_metadata.json"


def load_and_preprocess_dataset(csv_path: Path) -> Tuple[np.ndarray, np.ndarray, int, int]:
    """Load dataset, extract the 40 topological features, and deduplicate records."""
    if not csv_path.exists():
        raise FileNotFoundError(f"Dataset not found at {csv_path}. Run download_data.py first.")

    print(f"Loading dataset from {csv_path}...")
    X_rows: List[List[float]] = []
    y_rows: List[int] = []

    seen_vectors = set()
    total_raw_rows = 0
    duplicate_count = 0

    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_raw_rows += 1
            feature_vec = tuple(float(row[feat]) for feat in URL_FEATURE_NAMES)
            label = int(row["phishing"])

            # Deduplication key includes label to avoid data leakage across splits
            record_key = feature_vec + (label,)
            if record_key in seen_vectors:
                duplicate_count += 1
                continue
            seen_vectors.add(record_key)

            X_rows.append(list(feature_vec))
            y_rows.append(label)

    X = np.array(X_rows, dtype=np.float64)
    y = np.array(y_rows, dtype=np.int32)

    print(
        f"Loaded {total_raw_rows:,} raw rows. Removed {duplicate_count:,} duplicate vectors. "
        f"Retained {len(X):,} distinct examples (Benign: {np.sum(y == 0):,}, Phishing: {np.sum(y == 1):,})."
    )
    return X, y, total_raw_rows, duplicate_count


def calculate_sha256(file_path: Path) -> str:
    """Compute the SHA256 hash of a file."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def train_and_evaluate() -> Dict:
    """Execute full training, evaluation, serialization, and metadata generation."""
    start_time = time.time()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Load data
    X, y, total_raw, duplicates_removed = load_and_preprocess_dataset(DATASET_PATH)

    # 2. Stratified train/test split (80% train, 20% test)
    print("Splitting dataset into stratified train (80%) and test (20%) sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"Training samples: {len(X_train):,}, Test samples: {len(X_test):,}")

    # 3. Define and train pipeline
    print("Fitting Pipeline with StandardScaler and PhishingLogisticClassifier...")
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", PhishingLogisticClassifier(C=1.0, max_iter=300, random_state=42)),
    ])

    train_start = time.time()
    pipeline.fit(X_train, y_train)
    train_duration = time.time() - train_start
    print(f"Model fitting completed in {train_duration:.2f} seconds.")

    # 4. Evaluation on test set
    print("Evaluating model performance on held-out test set...")
    y_pred = pipeline.predict(X_test)
    y_pred_proba = pipeline.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_test, y_pred_proba))

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    print("=" * 60)
    print("TEST SET EVALUATION METRICS:")
    print(f"  Accuracy:           {acc:.4f} ({acc * 100:.2f}%)")
    print(f"  Precision:          {prec:.4f} ({prec * 100:.2f}%)")
    print(f"  Recall:             {rec:.4f} ({rec * 100:.2f}%)")
    print(f"  F1-Score:           {f1:.4f}")
    print(f"  ROC-AUC:            {roc_auc:.4f}")
    print(f"  False Positive Rate:{fpr:.4f} ({fpr * 100:.2f}%)")
    print(f"  Confusion Matrix:   TN={tn:,}, FP={fp:,}, FN={fn:,}, TP={tp:,}")
    print("=" * 60)

    # 5. Extract Feature Importances for Explainability
    clf: PhishingLogisticClassifier = pipeline.named_steps["classifier"]
    raw_coefs = clf.coef_.ravel()
    abs_coefs = np.abs(raw_coefs)
    total_abs = np.sum(abs_coefs) if np.sum(abs_coefs) > 0 else 1.0
    relative_pcts = (abs_coefs / total_abs) * 100.0
    sorted_idx = np.argsort(abs_coefs)[::-1]

    feature_ranking = []
    for rank, idx in enumerate(sorted_idx, 1):
        feat_name = URL_FEATURE_NAMES[idx]
        coef_val = float(raw_coefs[idx])
        importance_pct = float(relative_pcts[idx])
        feature_ranking.append({
            "rank": rank,
            "feature": feat_name,
            "coefficient": round(coef_val, 4),
            "importance_percent": round(importance_pct, 2),
            "correlation": "positive_phishing_indicator" if coef_val > 0 else "negative_benign_indicator",
            "description": FEATURE_DESCRIPTIONS.get(feat_name, ""),
        })

    print("TOP 10 MOST INFLUENTIAL FEATURES:")
    for item in feature_ranking[:10]:
        print(f"  {item['rank']}. {item['feature']:<25} {item['importance_percent']:>5.2f}% ({item['correlation']}) - {item['description']}")

    # 6. Serialize Model Artifact
    print(f"Serializing pipeline to {MODEL_PATH}...")
    joblib.dump(pipeline, MODEL_PATH, compress=3)
    artifact_size = MODEL_PATH.stat().st_size
    artifact_sha = calculate_sha256(MODEL_PATH)
    print(f"Saved model artifact ({artifact_size:,} bytes, sha256: {artifact_sha[:12]}...)")

    # 7. Generate model_metadata.json
    total_time = time.time() - start_time
    metadata = {
        "model_metadata_version": "1.0.0",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "algorithm": "PhishingLogisticClassifier",
        "hyperparameters": {
            "C": 1.0,
            "max_iter": 300,
            "solver": "L-BFGS-B",
            "regularization": "L2 (Ridge)",
        },
        "pipeline_stages": ["StandardScaler", "PhishingLogisticClassifier"],
        "dataset": {
            "source": "Vrbančič et al. (2020) Data in Brief Benchmark",
            "citation": "A full dataset of phishing websites, Data in Brief 32:106111",
            "license": "CC BY 4.0",
            "raw_samples": total_raw,
            "duplicates_removed": duplicates_removed,
            "training_samples": len(X_train),
            "test_samples": len(X_test),
        },
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "false_positive_rate": round(fpr, 4),
            "confusion_matrix": {
                "true_negatives": tn,
                "false_positives": fp,
                "false_negatives": fn,
                "true_positives": tp,
            },
        },
        "features": {
            "total_count": len(URL_FEATURE_NAMES),
            "feature_names": URL_FEATURE_NAMES,
            "feature_importances": feature_ranking,
        },
        "artifact": {
            "filename": MODEL_PATH.name,
            "size_bytes": artifact_size,
            "sha256": artifact_sha,
        },
        "limitations_and_ethics": [
            "ML model analyzes 40 URL and domain topological features exclusively.",
            "Model does NOT evaluate page content, DOM, HTML, or visual layout.",
            "Backend never performs server-side page fetching or DNS queries.",
            "Zero PII, passwords, or query string secrets are received or retained.",
        ],
        "training_duration_seconds": round(total_time, 2),
    }

    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"Model metadata successfully written to {METADATA_PATH}")
    return metadata


if __name__ == "__main__":
    train_and_evaluate()
