# Data Privacy, Zero-Knowledge Architecture & Remote Transmission Policy

## 1. Core Privacy Mandates

The Adaptive Phishing Detection Extension enforces a **Strict Privacy-by-Design** architectural model:

1. **Zero Benign Browsing History Transmission**:
   - The extension **never** transmits, logs, or stores benign user browsing activity.
   - Routinely visited websites are evaluated 100% locally within the browser sandbox without initiating any network requests.
2. **Zero Form Value or Credential Harvesting**:
   - The extension **never** queries, serializes, or transmits `<input>` values, passwords, keystrokes, or clipboard data.
   - `HTMLInputElement.value` is strictly unreferenced.
3. **Zero Session Secret or Cookie Access**:
   - The extension does not request the `cookies` permission.
   - Authentication tokens, session headers, and localStorage secrets are inaccessible and never read.
4. **No Server-Side Web Fetching or Browsing**:
   - The classification backend **never** connects to, crawls, downloads, or visits submitted URLs.
   - All evaluation relies on mathematical features computed on the client.

---

## 2. Precise Circumstances Governing Remote Transmission

Information is sent to the backend classification API **only if ALL of the following conditions are strictly met**:

| Condition | Rule & Enforcement | Test Verification |
| :--- | :--- | :--- |
| **1. Not a Restricted Page** | Internal browser schemes (`chrome://`, `chrome-extension://`, `edge://`, `about:`, `file:`, `view-source:`) are blocked immediately on the client. No remote calls are ever generated. | `remote_policy.test.ts:38` |
| **2. Not an Institutional Domain** | Institutional domains on the curated allowlist (`google.com`, `microsoft.com`, `mit.edu`, `chase.com`) are classified locally. Remote transmission is completely suppressed. | `remote_policy.test.ts:27` |
| **3. Not Clearly Benign by Local Checks** | When local heuristics determine a low risk score ($< 20$) with zero Medium, High, or Critical indicators, the local verdict is decisive. No remote network request is initiated. | `background_integration.test.ts:70` |
| **4. Remote Analysis Justification Trigger** | Remote transmission is permitted **only** when: <br>a) Local heuristics detect an elevated or ambiguous threat (risk score $\ge 20$ or threat indicators present), **OR**<br>b) The user explicitly clicks the "Scan Website" button in the popup controller. | `remote_policy.test.ts:50, 72` |
| **5. Cache & Deduplication Check** | If a remote scan for the exact hostname/path was completed within the $5\text{-minute}$ TTL, the cached assessment is reused without making a redundant network call. | `remote_policy.test.ts:85` |
| **6. Concurrent Request Coalescing** | Simultaneous scan requests across tabs on the same URL share a single in-flight network Promise, preventing request storms. | `background_integration.test.ts:110` |

---

## 3. Remote Feature Payload Specification

When remote analysis is justified, the extension transmits **only the 40 numerical topological counts**:

```json
{
  "features": {
    "length_url": 52,
    "qty_dot_url": 3,
    "qty_hyphen_url": 2,
    "qty_slash_url": 4,
    "qty_at_url": 0,
    "domain_length": 21,
    "domain_in_ip": 0,
    "server_client_domain": 0,
    ...
  }
}
```

### Absolute Ingress & Egress Restrictions:
- **No Destination URL**: Because features are extracted client-side, the raw URL itself does not need to be transmitted.
- **No Query Parameters or Fragments**: Any URL strings sent in fallback mode have all `?query=...` and `#fragment` strings completely stripped via `sanitizeUrlForRemote()`.
- **No Form Values or DOM Elements**: DOM elements, input values, passwords, and tokens are completely excluded.
- **Backend Schema Enforcement**: The backend [`PrivacyValidator`](file:///C:/NovaTech/adaptive-phishing-detection/backend/app/security/__init__.py) rejects incoming payloads containing disallowed keys (`password`, `token`, `session`, `cookie`, `secret`, `user`) with `HTTP 400 Bad Request`.

---

## 4. Offline Resilience & Non-Blocking Rendering

1. **Zero Page-Rendering Delays**:
   - The extension operates strictly out-of-band via asynchronous service worker messaging.
   - Content scripts extract passive structural metrics and return immediately. Normal page loading and rendering are never paused or blocked.
2. **Offline Fallback Guarantee**:
   - If the classification backend is offline, unreachable, or times out ($2500\text{ ms}$ threshold), the local heuristic verdict remains 100% functional.
   - The user is notified with an `[Offline Fallback]` indicator, ensuring active protection without interruption.

---

## 5. Verification Test Suite Matrix

| Privacy & Reliability Constraint | Test File | Test Case Name | Result |
| :--- | :--- | :--- | :--- |
| Benign browsing generating zero remote calls | `tests/background_integration.test.ts` | `does NOT make remote request for benign page, returning local verdict` | **PASSED** |
| Institutional pages suppressed from remote transmission | `tests/remote_policy.test.ts` | `prohibits remote transmission for institutional trusted domains` | **PASSED** |
| Restricted browser pages excluded from remote calls | `tests/remote_policy.test.ts` | `prohibits remote transmission for restricted browser internal pages` | **PASSED** |
| Zero sensitive form values or tokens in outgoing payload | `tests/remote_policy.test.ts` | `guarantees outgoing payload contains ONLY permitted topological features` | **PASSED** |
| Request storm suppression & in-flight coalescing | `tests/background_integration.test.ts` | `coalesces multiple concurrent in-flight requests into a single network call` | **PASSED** |
| Cache deduplication within TTL window | `tests/remote_policy.test.ts` | `suppresses duplicate remote requests when valid cache entry exists` | **PASSED** |
| Request timeout abort handling without unhandled error | `tests/api_client.test.ts` | `handles backend timeout safely without unhandled rejection` | **PASSED** |
| Offline backend fallback preservation | `tests/background_integration.test.ts` | `handles offline backend gracefully with local fallback verdict` | **PASSED** |
| Backend rejection of PII and sensitive parameters | `backend/tests/test_analyze.py` | `test_validation_rejects_pii_and_credential_keys` | **PASSED** |
