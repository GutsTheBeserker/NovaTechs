# System Architecture & Technical Design

## 1. Executive Architecture Summary

The **Adaptive Phishing Detection Browser Extension** (PhishGuard) is engineered to detect novel, zero-day credential harvesting and deceptive websites without relying exclusively on slow, reactive blacklists. 

The architecture is divided into two collaborating tiers:
1. **Client-Side Chromium Extension (Manifest V3)**: Executes instant, non-blocking local heuristic analysis directly in the browser across URL lexical traits, DOM structure, SSL/TLS transport properties, redirect chains, external dependencies, and local adaptive trust baselines.
2. **Backend Classification Service (Python / Flask + Scikit-Learn)**: Hosts a reproducibly trained ML model for multidimensional feature inference when client heuristics indicate ambiguity, operating under strict Zero-PII and non-benign transmission policies.

---

## 2. Component Structure & Data Flow

```
+--------------------------------------------------------------------------------------------------+
|                                 BROWSER EXTENSION (MANIFEST V3)                                  |
|                                                                                                  |
|  +--------------------+         +--------------------------------------------------------------+ |
|  | Webpage DOM        |         | Content Script (Harvester)                                   | |
|  | (Target Webpage)   | ------> | - Injected strictly at document_idle                         | |
|  +--------------------+         | - Passive structural inspection (scripts, iframes, forms)    | |
|                                 | - Never inspects passwords, cookies, or input values         | |
|                                 +--------------------------------------------------------------+ |
|                                                                |                                 |
|                                                                v                                 |
|  +--------------------+         +--------------------------------------------------------------+ |
|  | Popup UI           | <====== | Background Service Worker Coordinator                        | |
|  | - Risk Badge       |         | - URL lexical & Punycode evaluation (url_analyzer)           | |
|  | - 0-100 Gauge      |         | - Navigation & Redirect Tracker (webNavigation)              | |
|  | - Explainability   |         | - Observable SSL/TLS Signals (ssl_analyzer)                  | |
|  | - Trust Baseline   |         | - External Dependency & CDN Analyzer (resource_analyzer)     | |
|  | - Clear Baselines  |         | - Adaptive Trust Profiles (trust_profiles - 100% Local)      | |
|  +--------------------+         | - Explainable Multi-Signal Risk Engine                       | |
|                                 +--------------------------------------------------------------+ |
|                                                                |                                 |
+----------------------------------------------------------------|---------------------------------+
                                                                 | Selective / Asynchronous
                                                                 | Sanitized 40-Feature Vector
                                                                 | (Non-benign pages only)
                                                                 v
+--------------------------------------------------------------------------------------------------+
|                                     BACKEND FLASK SERVICE                                        |
|                                                                                                  |
|  +---------------------------------------------------------------------------------------------+ |
|  | REST API Endpoints                                                                          | |
|  | - GET  /health              (Health & ML model metadata)                                    | |
|  | - POST /api/v1/analyze      (Feature inference, calibrated probabilities, top feature deltas)| |
|  +---------------------------------------------------------------------------------------------+ |
|                                                |                                                 |
|                                                v                                                 |
|  +---------------------------------------------------------------------------------------------+ |
|  | Input Validation & Privacy Shield                                                           | |
|  | - Rejects PII, credentials, query parameters, fragments, and malformed schemas               | |
|  +---------------------------------------------------------------------------------------------+ |
|                                                |                                                 |
|                                                v                                                 |
|  +---------------------------------------------------------------------------------------------+ |
|  | Machine Learning Classifier Pipeline                                                        | |
|  | - Scikit-learn Logistic Regression / StandardScaler (Vrbančič et al. 2020 dataset)          | |
|  | - Returns calibrated risk score [0, 100], model version, and ranked importance weights     | |
|  +---------------------------------------------------------------------------------------------+ |
+--------------------------------------------------------------------------------------------------+
```

---

## 3. Advanced Browser Security Signals & Browser API Boundaries

### A. Honest Browser API Boundaries & Limitations

Standard Chrome Manifest V3 public extensions operate under well-defined browser security boundaries. PhishGuard is built with complete engineering honesty regarding these boundaries:

| Security Property | Standard Chrome MV3 Availability | PhishGuard Implementation Status |
| :--- | :--- | :--- |
| **Transport Encryption (HTTPS vs HTTP)** | Fully Observable via URL schemes and navigation events | Implemented (`ssl_analyzer.ts`) |
| **Mixed Content Anomalies** | Fully Observable via DOM inspection (`http://` resources on `https://` origin) | Implemented (`ssl_analyzer.ts`) |
| **Protocol Downgrade Redirections** | Fully Observable via `webNavigation` sequence (HTTPS $\to$ HTTP) | Implemented (`redirect_tracker.ts`) |
| **Raw Server X.509 Certificate Chain** | **UNAVAILABLE** in standard public MV3 APIs (no socket/TLS access) | Explicitly documented; not fabricated |
| **OCSP Revocation Status** | **UNAVAILABLE** in standard public MV3 APIs | Explicitly documented; not fabricated |
| **TLS Cipher Suite Negotiation** | **UNAVAILABLE** in standard public MV3 APIs | Explicitly documented; not fabricated |
| **Enterprise Client Certificates** | Restricted to ChromeOS Enterprise `certificateProvider` API | Excluded (out of scope for public extension) |

> [!IMPORTANT]
> **The HTTPS Trust Fallacy**: Over 85% of active phishing infrastructure is provisioned with valid TLS certificates from automated certificate authorities (Let's Encrypt, Cloudflare, cPanel). In PhishGuard, **HTTPS is treated strictly as an encrypted transport baseline, NEVER as proof of authenticity or trustworthiness**. Absence of HTTPS on credential pages is severely penalized, but presence of HTTPS awards zero blanket trust.

---

### B. Navigation & Redirect Analysis (`redirect_tracker.ts`)

Attackers frequently employ deep redirect funnels, open redirects, and protocol downgrades to evade automated crawlers and deliver targeted landing pages.

- **Event Sources**: Listens to Chrome `webNavigation.onBeforeNavigate`, `webNavigation.onCommitted`, and `webNavigation.onCompleted` for main frames (`frameId === 0`).
- **Chain Tracking**: Maintains in-memory navigation step records per active tab (`tabId`).
- **Strict Privacy**: Records are stored strictly in memory and automatically pruned after a 60-second TTL. Zero long-term browsing history is ever persisted.
- **Race Condition Resiliency**: If `onBeforeNavigate` is missed due to rapid document loading, `onCommitted` synthesizes the initial navigation record safely.
- **Detected Patterns**:
  1. *Multi-Step Redirect Chains*: $\ge 3$ consecutive redirect hops indicate potential scanner evasion or affiliate cloaking (`SUSPICIOUS_REDIRECT_CHAIN`, HIGH severity).
  2. *Cross-Domain Hopping*: Transitions between distinct base domains (`CROSS_DOMAIN_REDIRECT_HOP`, MEDIUM severity).
  3. *Protocol Downgrades*: Navigation initiating on encrypted HTTPS that lands on plaintext HTTP (`PROTOCOL_DOWNGRADE_REDIRECT`, CRITICAL severity).
  4. *Redirect Loops / Oscillations*: Repeated circular hopping between origins (`REDIRECT_LOOP_DETECTED`, HIGH severity).

---

### C. External Resource & Dependency Analysis (`resource_analyzer.ts`)

Deceptive pages frequently hotlink brand assets while pulling malicious scripts or routing credentials to untrusted backend infrastructure.

- **Passive Inspection**: Inspects script origins, iframe targets, and form actions purely from DOM metadata. **Never downloads, fetches, or executes external code**.
- **Reputable CDNs & SSO Whitelist**: Distinguishes authentic static asset delivery (`cdnjs.cloudflare.com`, `cdn.jsdelivr.net`, `fonts.googleapis.com`, `unpkg.com`) and institutional identity providers (`login.microsoftonline.com`, `accounts.google.com`, `auth0.com`, `okta.com`) from rogue sources.
- **Untrusted Script & Form Origins**: Identifies external endpoints hosted on raw IPv4 literals or dynamic DNS / tunneling services (`duckdns.org`, `ngrok.io`, `ngrok-free.app`, `loca.lt`, `serveo.net`).
- **Anomalies Flagged**:
  1. Scripts loading from dynamic DNS or raw IP hosts (`SUSPICIOUS_SCRIPT_ORIGIN`, HIGH severity).
  2. Form action destinations pointing to dynamic DNS or raw IP hosts (`UNTRUSTED_FORM_DESTINATION_ORIGIN`, CRITICAL severity).
  3. Cross-origin frames from untrusted hosts (`UNTRUSTED_IFRAME_ORIGIN`, HIGH severity).

---

### D. Adaptive Website Trust Profiles (`trust_profiles.ts`)

PhishGuard features a privacy-preserving, locally trained behavioral profiler that baselines familiar websites and detects anomalous behavioral shifts.

- **Strict Local Persistence**: Trust profiles are stored exclusively in `chrome.storage.local`. **Trust profiles are NEVER transmitted to the backend or third-party servers**.
- **Minimal Domain Summaries**: Stores only minimal domain telemetry: base domain name, observation count, first/last seen timestamps, known form origins, known script domains, and boolean baseline flags. No URL paths, browsing histories, or page contents are recorded.
- **Baseline Establishment Requirement**: A domain requires at least **3 distinct, safe observations** before an authoritative baseline is established. New or rarely visited domains remain in `Learning` mode.
- **Anti-Poisoning Safeguards**: Malicious sites must never be allowed to establish or corrupt a baseline. Any scan with a risk score $\ge 25$ or exhibiting CRITICAL/HIGH threat indicators is strictly blocked from creating or modifying profile baselines.
- **Behavioral Drift Detection**:
  1. *Sudden Credential Prompt*: A domain that historically never requested authentication suddenly displays password or credential fields (`UNEXPECTED_CREDENTIAL_SOLICITATION`, HIGH severity).
  2. *Form Destination Hijacking*: Forms submit user data to external origins not observed during the established baseline (`UNEXPECTED_FORM_ACTION_DRIFT`, HIGH severity).
  3. *Unexpected Iframe Overlays*: Sudden emergence of unobserved cross-origin iframes on a profiled site (`UNEXPECTED_IFRAME_INFLUX`, MEDIUM severity).
- **User Control & Transparency**: Users can view the baseline status directly in the popup UI and can completely wipe all stored baselines via a one-click "Clear Stored Baselines" control.

---

## 4. Implemented Features vs. Unavailable / Future Capabilities

| Feature Area | Implemented in Current System | Unavailable or Future Capability |
| :--- | :--- | :--- |
| **URL Heuristics** | Length, entropy, IP hosts, Punycode/homographs, hex encoding, brand subdomains | DNS-over-HTTPS (DoH) lookups for domain creation date (requires external third-party API) |
| **DOM Analysis** | Password fields, payment fields, cross-origin forms, hidden iframes, brand title mismatch | Computer-vision logo matching against brand imagery (deferred to future desktop agents) |
| **Redirect Tracking** | Hops count, cross-domain hopping, HTTPS $\to$ HTTP downgrade, loop detection via `webNavigation` | Automatic active navigation probing into suspicious links (prohibited for user safety) |
| **SSL/TLS Analysis** | Protocol inspection (HTTPS vs HTTP), mixed content (scripts, iframes, forms), downgrade detection | Raw X.509 certificate chain inspection, cipher suite negotiation (prohibited by Chromium MV3 sandbox) |
| **Dependencies** | Passive origin parsing, reputable CDN allowlists, dynamic DNS/IP detection | Static AST analysis of external JavaScript payloads (requires code downloading) |
| **Trust Profiles** | Local baselines, anti-poisoning safeguards, credential drift, form action drift, user clearing | Cloud-synchronized cross-device behavioral profiles (prohibited by privacy policy) |
| **Machine Learning** | Client-side 40-feature extraction, calibrated Flask LogisticClassifier API, privacy filters | Fully local on-device WebAssembly/ONNX inference (candidate for future enhancement) |
