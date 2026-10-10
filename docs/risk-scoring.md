# Explainable Multi-Signal Phishing Risk-Scoring Engine

## 1. Executive Summary & Design Principles

The **Multi-Signal Phishing Risk Engine** calculates an explainable, composite risk score $S \in [0, 100]$ by synthesizing evidence across URL topology, domain registrar indicators, DOM form structures, redirection destinations, and third-party resource distributions.

### Engineering Principles:
1. **Explainable Attribution**: Every score contribution must be accompanied by human-readable explanations, causal reasoning, and concrete evidence.
2. **Signal vs. Proof**: Individual weak anomalies (such as HTTP transport, long URLs, or third-party CSS) are treated strictly as contextual evidence, never as unilateral proof of phishing.
3. **Strong vs. Weak Separation**: Contextual weak heuristics are bounded by category caps and **cannot** elevate a website into the HIGH risk tier without at least one corroborated strong attack vector.
4. **Anti-Double-Counting**: Correlated signals (e.g., chained subdomains with high character entropy) are dampened, and duplicate observations are deduplicated.
5. **No Blanket Trust for Unlisted Sites**: The absence of a domain on static blacklists does not confer an automatic "safe" guarantee. Only cryptographically verified institutional portals receive an institutional trust bonus.
6. **Empirical Calibration Transparency**: The scoring weights documented here represent initial expert design heuristics and are **not claimed to be empirically validated** prior to formal calibration against labelled datasets.

---

## 2. Classification Thresholds

The classification tiers are fully configurable via `risk_config.ts`:

| Risk Tier | Score Range | Semantic Meaning | Recommended User Action |
| :--- | :--- | :--- | :--- |
| **LOW RISK** | **0 – 29** | Minimal or benign security signals. Page structures match typical web standards. | Standard browsing; no user disruption. |
| **MEDIUM RISK** | **30 – 59** | Elevated contextual risk signals detected (e.g., HTTP transport, unverified auth paths, high external script ratios). | Proceed with caution. Verify URL spelling and SSL certificates before entering sensitive information. |
| **HIGH RISK** | **60 – 100** | Critical deception or credential harvesting indicators present (e.g., cross-origin password submission, Punycode homoglyphs, fake brand title). | Halt credential input immediately and navigate away from the webpage. |

---

## 3. Indicator Taxonomy & Scoring Weights

### 3.1 Strong Attack Vectors (High-Confidence Indicators)

Strong indicators represent verified deceptive mechanisms commonly observed in active phishing kits:

| Indicator Key | Category | Nominal Points ($W_k$) | Description & Reason |
| :--- | :--- | :--- | :--- |
| `PUNYCODE_HOMOGLYPH` | `URL` | $+35$ | Domain utilizes `xn--` encoding or mixed-script unicode lookalike characters (e.g., Cyrillic 'а' replacing Latin 'a'). |
| `CROSS_ORIGIN_CREDENTIAL_FORM` | `DOM` | $+35$ | Password `<input>` element submits authentication credentials to a foreign third-party origin. |
| `INSECURE_CREDENTIAL_TRANSMISSION` | `DOM` | $+30$ | Password field transmits data over unencrypted HTTP transport. |
| `INSECURE_PAYMENT_COLLECTION` | `PAYMENT` | $+35$ | Payment card fields (`cc-number`, `cvv`) submit to cross-origin or insecure endpoints. |
| `MISLEADING_BRAND_SUBDOMAIN` | `BRAND` | $+25$ | Subdomain claims a recognized brand (e.g., `paypal.com.verify.net`) while base domain is unverified. |
| `BRAND_TITLE_MISMATCH` | `BRAND` | $+25$ | Page `<title>` claims an authentic institutional brand but the registered FQDN does not match. |
| `IP_ADDRESS_HOSTNAME` | `URL` | $+25$ | Website uses a direct IPv4 or IPv6 literal instead of a registered DNS name. |
| `SUSPICIOUS_OVERLAY_IFRAME` | `DOM` | $+20$ | Full-viewport transparent overlay iframe detected (clickjacking / credential theft). |
| `KNOWN_THREAT_FEED_MATCH` | `THREAT_INTEL` | $+50$ | Verified match against documented threat-intelligence feeds. |

### 3.2 Contextual / Weak Heuristics (Supporting Evidence)

Weak indicators serve as contextual corroboration and are strictly capped:

| Indicator Key | Category | Nominal Points ($W_k$) | Contextual Cap | Description & Reason |
| :--- | :--- | :--- | :--- | :--- |
| `INSECURE_HTTP_PROTOCOL` | `SSL` | $+10$ | N/A | Communicates over plain HTTP. Lacks confidentiality and integrity. |
| `EXCESSIVE_URL_LENGTH` | `URL` | $+5$ | Cap: $30$ | URL contains $> 200$ characters. Often used to bury obfuscated tokens. |
| `SUSPICIOUS_DOMAIN_STRUCTURE` | `URL` | $+8$ | Cap: $30$ | Subdomain count $\ge 3$, hyphens $\ge 3$, or Shannon character entropy $> 3.8$. |
| `SUSPICIOUS_PATH_PATTERN` | `URL` | $+8$ | Cap: $30$ | Sensitive auth keyword (`/login`, `/banking`) present on an unverified domain. |
| `SUSPICIOUS_HEX_ENCODING` | `URL` | $+10$ | Cap: $30$ | URL contains excessive percent-encoding (`%2e%2e`, `%2f`). |
| `EMBEDDED_CREDENTIALS_TRICK` | `URL` | $+20$ | Cap: $30$ | URL uses `@` delimiter before the hostname. |
| `EXCESSIVE_EXTERNAL_RESOURCES` | `DOM` | $+10$ | Cap: $20$ | Over 80% of scripts/stylesheets originate from external third-party CDNs. |
| `DATA_URI_SCRIPT_INJECTION` | `DOM` | $+12$ | Cap: $25$ | Script element uses a `data:` URI payload instead of a standard URL. |
| `HIDDEN_IFRAMES_PRESENT` | `DOM` | $+8$ | Cap: $25$ | Multiple zero-pixel or hidden iframes detected. |
| `BEHAVIORAL_DRIFT` | `BEHAVIORAL` | $+20$ | N/A | Known domain exhibits unexpected structural mutations to its forms. |

---

## 4. Anti-Double-Counting & Safeguard Rules

1. **Deduplication Filter**:
   - The engine hashes each indicator using a composite key: `category:factor:evidence`.
   - Repeated observations (e.g. duplicate forms reporting the same cross-origin domain) are counted exactly once.
2. **Correlation Dampening**:
   - When multiple weak indicators in the same category fire (e.g., excessive hyphens + excessive subdomains + high entropy), subsequent weak indicators have a dampening factor ($\times 0.75$) applied.
3. **Category Caps**:
   - Contextual URL heuristics alone cannot exceed **$30$ points**.
   - Contextual DOM heuristics alone cannot exceed **$25$ points**.
   - External resource ratios alone cannot exceed **$20$ points**.
4. **Weak-Signal High-Risk Prevention Safeguard**:
   - If **zero strong attack vectors** are detected, the composite score is strictly capped at **$59$ (MEDIUM RISK)**.
   - This prevents benign websites with long URLs, multiple hyphens, and external assets from triggering false-positive red alerts.
5. **Institutional Trust Bonus ($B_{\text{trust}}$)**:
   - Verified institutional portals (`login.microsoftonline.com`, `.edu` domains, Okta SSO) receive a **$-40$ point** deduction.
   - Unless an explicit critical compromise (such as a known threat-intel match or Punycode homoglyph) is detected, institutional login portals are capped at **$\le 29$ (LOW RISK)**.

---

## 5. Uncertainty & Information Completeness Modeling

The engine accounts for incomplete inspections (e.g. when content scripts cannot run or scans are executed before DOM completion):

$$\text{Completeness} = 0.40 \cdot \mathbf{1}_{\text{URL Available}} + 0.60 \cdot \mathbf{1}_{\text{DOM Available}}$$

- **Completeness $= 1.0$**: Both URL and DOM features fully inspected $\rightarrow$ **HIGH Confidence**.
- **Completeness $= 0.4$**: Only URL inspected $\rightarrow$ **MEDIUM Confidence**. The engine appends explicit uncertainty notes explaining that DOM structures could not be verified.

---

## 6. Calibration Framework Against Labelled Datasets

While the initial weights are grounded in cybersecurity domain knowledge, production accuracy requires empirical calibration against labelled benchmarks.

### Calibration Procedure:

```
[Labelled Dataset: PhishTank Phishing + Tranco Legitimate]
                           │
                           ▼
              [Feature Vector Extraction]
    (x1: Punycode, x2: CrossOrigin, x3: Entropy, x4: ExternalRatio, ...)
                           │
                           ▼
          [Stratified 80/20 Train/Validation Split]
                           │
                           ▼
              [Optimization Algorithm]
  Option A: L2-Regularized Logistic Regression (Platt Scaling)
  Option B: Constrained Optimization / Genetic Algorithm maximizing F1 Score
                           │
                           ▼
             [Threshold & Weight Fitting]
  - Objective: Minimize False Positives on Institutional Logins (FP < 0.1%)
  - Objective: Maximize Detection of Zero-Day Phishing Kits (Recall > 95%)
                           │
                           ▼
      [Emit Calibrated Weights & ROC-AUC to risk_config.ts]
```

1. **Dataset Split**: Compile 5,000 verified active phishing URLs (from PhishTank/OpenPhish) and 5,000 benign URLs (from Tranco Top 10K, including university portals).
2. **Loss Function**: Define an asymmetric cost function penalizing False Positives on institutional portals $10\times$ higher than False Negatives:
   $$L(W) = \lambda_{\text{FP}} \sum_{i \in \text{Benign}} \ell(y_i, S_i) + \lambda_{\text{FN}} \sum_{j \in \text{Phish}} \ell(y_j, S_j)$$
3. **Parameter Optimization**: Fit weights $W_k$ using Nelder-Mead or bounded gradient descent such that $W_k \ge 0$, and evaluate validation ROC-AUC and F1 scores before updating `risk_config.ts`.
