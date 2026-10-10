# 🛡️ PhishGuard AI — Adaptive Phishing Detection

\<p align="center">
&#x20; \<strong>Detect Phishing. Browse Safely. Protect Your Privacy.\</strong>
\</p>

\<p align="center">
&#x20; \<img src="[https://img.shields.io/badge/Chrome-Manifest%20V3-blue?logo=googlechrome](https://img.shields.io/badge/Chrome-Manifest%20V3-blue?logo=googlechrome)" alt="Chrome">
&#x20; \<img src="[https://img.shields.io/badge/Python-Flask-green?logo=python](https://img.shields.io/badge/Python-Flask-green?logo=python)" alt="Python">
&#x20; \<img src="[https://img.shields.io/badge/TypeScript-Extension-blue?logo=typescript](https://img.shields.io/badge/TypeScript-Extension-blue?logo=typescript)" alt="TypeScript">
&#x20; \<img src="[https://img.shields.io/badge/License-MIT-lightgrey](https://img.shields.io/badge/License-MIT-lightgrey)" alt="MIT License">
\</p>

## 🚀 About

**PhishGuard AI** is a privacy-focused browser extension designed to detect potentially malicious and phishing websites using real-time security signals, intelligent heuristics, and explainable risk scoring.

Unlike traditional blacklist-only approaches, it analyzes suspicious URLs, domain characteristics, webpage structure, and form destinations to help identify potential threats.

## ✨ Key Features

- 🔍 **Real-Time Detection** — Analyze suspicious website characteristics.
- 🧠 **Explainable Risk Score** — Present a risk score from 0–100 with understandable reasons.
- 🌐 **Domain Protection** — Identify potential Punycode and homograph attacks.
- 🛡️ **Phishing Warnings** — Alert users to suspicious websites where warning functionality is implemented.
- 🔒 **Privacy First** — Designed to avoid collecting passwords and sensitive form values.
- ⚡ **Browser Integration** — Built using Chrome Extension Manifest V3.
- 🤖 **ML-Ready Backend** — Python Flask API designed to support future machine-learning inference.

## 🏗️ Tech Stack

| Technology         | Purpose                |
| ------------------ | ---------------------- |
| TypeScript         | Extension logic        |
| HTML & CSS         | User interface         |
| Chrome Manifest V3 | Browser integration    |
| Python & Flask     | Backend API            |
| Vitest & pytest    | Automated testing      |
| scikit-learn       | Planned ML integration |

## 📂 Project Structure

```text
adaptive-phishing-detection/
├── extension/
│   ├── src/
│   │   ├── background/
│   │   ├── content/
│   │   ├── popup/
│   │   ├── warning/
│   │   └── shared/
│   ├── public/
│   ├── tests/
│   └── manifest.json
├── backend/
│   ├── app/
│   │   ├── routes/
│   │   ├── services/
│   │   ├── security/
│   │   └── ml/
│   ├── tests/
│   └── requirements.txt
├── docs/
├── data/
└── README.md
```

## ⚙️ Installation

**1. Clone the repository**

```bash
git clone https://github.com/YOUR_USERNAME/adaptive-phishing-detection.git
cd adaptive-phishing-detection
```

**2. Start the backend**

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pytest -v
python scripts/run_dev.py
```

Backend health check:

`http://127.0.0.1:5000/api/v1/health`

**3. Build the extension**

Open a new terminal:

```bash
cd extension
npm install
npm test
npm run build
```

**4. Load in Chrome**

1. Open `chrome://extensions/`.
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select the directory containing the built extension's `manifest.json`.

## 🔌 API Endpoints

| Method | Endpoint          | Purpose                     |
| ------ | ----------------- | --------------------------- |
| GET    | `/api/v1/health`  | Check backend status        |
| POST   | `/api/v1/predict` | Threat prediction interface |

The prediction endpoint's request format and ML capabilities depend on the current implementation.

## 🔐 Privacy & Security

- Minimize the collection of browsing data.
- Never collect or transmit passwords or form values.
- Validate incoming API requests.
- Use restricted browser permissions.
- Provide transparent explanations for detected risks.

## 🛣️ Future Plans

- [ ] Integrate a trained machine-learning model.
- [ ] Improve zero-day phishing detection.
- [ ] Enhance domain spoofing detection.
- [ ] Evaluate detection accuracy and false positives.
- [ ] Improve warning and blocking functionality.

## ⚠️ Disclaimer

PhishGuard AI is an educational and defensive cybersecurity project. Detection may not be perfect, and a risk score does not guarantee that a website is malicious or safe.

## 📄 License

MIT License — see the `LICENSE` file for details.

---

\<p align="center">
&#x20; \<strong>PhishGuard AI — Smarter Detection. Safer Browsing.\</strong>
\</p>
