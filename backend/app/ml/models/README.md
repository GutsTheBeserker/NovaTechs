# Trained Phishing ML Model Artifacts

This directory contains the production serialized machine-learning model and its verifiable provenance metadata.

## Artifact Manifest

| File | Purpose | Size | Format |
| :--- | :--- | :--- | :--- |
| `phishing_model.joblib` | Serialized scikit-learn Pipeline (`StandardScaler` + `PhishingLogisticClassifier`) | ~1.7 KB | Joblib (Zlib level 3) |
| `model_metadata.json` | Training hyperparameters, dataset provenance, metrics, feature importances, SHA256 checksum | ~3.5 KB | JSON UTF-8 |

## Model Provenance & Verifiable Metrics

- **Training Dataset**: Mendeley / IEEE Data in Brief Benchmark Dataset (Vrbančič et al., 2020, CC BY 4.0)
- **Features**: 40 URL & Domain topological attributes (100% offline, zero server-side web fetching)
- **Distinct Samples**: 26,310 (21,048 train / 5,262 test, stratified 80/20)
- **Test Metrics**:
  - Accuracy: **76.43%**
  - Precision: **94.51%**
  - Recall: **75.22%**
  - F1-Score: **0.8377**
  - ROC-AUC: **0.8614**
  - False Positive Rate: **18.45%**

## Retraining Instructions

To retrain the model artifact reproducibly from scratch:

```bash
# 1. Download authentic dataset
python backend/scripts/download_data.py

# 2. Execute training and evaluation pipeline
python backend/scripts/train_model.py
```
