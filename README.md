# Adaptive Phishing Detection Browser Extension

[![Status](https://img.shields.io/badge/Phase%201-Scaffolding%20%26%20Contracts%20Verified-brightgreen)](#)
[![Manifest V3](https://img.shields.io/badge/Chrome-Manifest%20V3-blue)](#)
[![Backend](https://img.shields.io/badge/Backend-Python%20%7C%20Flask-success)](#)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)](#)

A functional, explainable, and privacy-conscious Chromium extension (Manifest V3) that detects zero-day phishing websites using real-time security signals, deterministic heuristics, and local adaptive profiling rather than relying only on reactive static blacklists.

---

## Architecture Overview

The system operates across two privacy-isolated layers:
1. **Client-Side Extension (Manifest V3)**:
   - Injected strictly at `document_idle` (guaranteeing zero rendering delays).
   - Passive DOM structure harvester: counts password fields, inspects form destination origins, and checks brand mismatches without ever touching form values or passwords.
   - Background service worker executing deterministic heuristic evaluations, Punycode/homograph detection, and institutional allowlist checks in < 15 ms.
   - Real-time scanner popup displaying an explainable 0–100 risk score and plain-language factor cards.
2. **Backend Machine Learning Service (Python / Flask)**:
   - Exposes REST API endpoints (`/api/v1/health`, `/api/v1/predict`).
   - Strict privacy shield rejecting any raw URLs with query parameters, PII, or unexpected fields.
   - Slated for Phase 2 reproducible scikit-learn model training and calibration.

---

## Directory Structure

```
adaptive-phishing-detection/
├── extension/
│   ├── manifest.json               # Chrome Extension Manifest V3 configuration
│   ├── package.json                # TypeScript dependencies and scripts
│   ├── tsconfig.json               # TypeScript strict compiler config
│   ├── src/
│   │   ├── background/             # MV3 Service Worker & heuristic scoring engine
│   │   ├── content/                # Passive DOM harvester (runs at document_idle)
│   │   ├── popup/                  # Scanner popup UI (HTML, CSS, TypeScript)
│   │   ├── warning/                # Interstitial warning alert page
│   │   └── shared/                 # Shared types, constants, and utilities
│   ├── public/
│   │   └── icons/                  # 16px, 48px, 128px shield icons
│   └── tests/                      # Vitest unit tests for utilities and heuristics
├── backend/
│   ├── app/
│   │   ├── __init__.py             # Flask application factory
│   │   ├── config.py               # Safe defaults & environment variable loader
│   │   ├── routes/                 # Health check and prediction endpoints
│   │   ├── services/               # Inference orchestration contracts
│   │   ├── security/               # Privacy validator & zero-PII ingress shield
│   │   └── ml/                     # ML training modules & model registry
│   ├── tests/                      # pytest test suite
│   ├── scripts/                    # Development startup script
│   ├── requirements.txt            # Python dependencies
│   └── .env.example                # Safe default environment configuration
├── data/
│   └── README.md                   # Training datasets and schema specification
├── docs/
│   ├── architecture.md             # Full system architecture and component designs
│   ├── risk-scoring.md             # Mathematical explainability formula and weights
│   ├── privacy.md                  # Privacy-by-design guarantees and sanitization
│   └── demo-script.md              # Demonstration plan and walkthrough script
├── .gitignore
└── README.md                       # This setup and reference manual
```

---

## Prerequisites

- **Python**: Version 3.10+ (Tested on Python 3.14.6 AMD64)
- **Node.js**: Version 20.0+ (Tested on Node.js v24.18.0, npm 11.16.0)
- **Browser**: Google Chrome, Brave, or any Chromium-based browser supporting Manifest V3

---

## Setup & Execution Guide

### 1. Backend Service Setup

Navigate to the `backend/` directory:
```bash
cd backend
```

Create a virtual environment and activate it:
```powershell
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:
```bash
pip install -r requirements.txt
```

Run backend unit and security tests:
```bash
pytest -v
```

Start the development server:
```bash
python scripts/run_dev.py
```
The service will start on `http://127.0.0.1:5000`. You can verify operational readiness by visiting:
```
http://127.0.0.1:5000/api/v1/health
```

---

### 2. Browser Extension Setup & Build

Navigate to the `extension/` directory:
```bash
cd extension
```

Install devDependencies:
```bash
npm install
```

Run unit tests:
```bash
npm test
```

Compile TypeScript to JavaScript (`dist/`):
```bash
npm run build
```

---

### 3. Loading Extension in Google Chrome

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle **Developer mode** on (top-right corner).
3. Click **Load unpacked** (top-left).
4. Select the directory:
   ```
   C:\NovaTech\adaptive-phishing-detection\extension
   ```
5. The extension **PhishGuard: Adaptive Phishing Detection** will be loaded and active.
6. Pin the PhishGuard shield icon to your browser toolbar. Click the icon on any webpage to inspect real-time security signals and explainable risk scores.

---

## Verification Summary (Phase 1)

- **Backend Health Check**: Verified via `pytest` (4/4 tests passed).
- **Extension TypeScript Typecheck**: Verified via `tsc` (0 errors, clean build to `dist/`).
- **Extension Unit Tests**: Verified via `Vitest` (12/12 tests passed across lexical analysis, sanitization, and deterministic scoring).
- **Zero-Knowledge Privacy Safeguards**: Verified in `test_privacy_validator_sanitizer` and `utils.test.ts`.
