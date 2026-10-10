# Demonstration Plan & Video Walkthrough Script

## 1. Objective
This plan outlines the technical demonstration script for the university final-year project evaluation and project presentation.

---

## 2. Walkthrough Sequence (5–7 Minutes)

### Act I: Project Motivation & Architecture Overview (1:00)
- Introduce the threat of zero-day phishing kits bypassing static blacklists.
- Emphasize the three engineering pillars:
  1. Real-time client-side heuristics (< 200 ms overhead).
  2. Explainable risk scoring (0–100) with clear factor audit cards.
  3. Privacy preservation (zero history or credential collection).

### Act II: Benign Institutional Login Verification (1:30)
- Navigate to an official university or enterprise login page (e.g., University SSO / Microsoft Login).
- Open the active scanner popup:
  - Demonstrate **LOW RISK (Green)** classification.
  - Explain how the institutional allowlist suppressed false alarms despite complex redirection.
  - Show the latency monitor demonstrating negligible overhead (< 20 ms).

### Act III: Zero-Day Phishing Simulation & Detection (2:00)
- Navigate to a simulated zero-day credential harvesting page (mimicking a login interface on an anomalous unverified domain with cross-origin form action).
- Open the active scanner popup:
  - Demonstrate **HIGH RISK (Crimson)** alert and 85/100 score.
  - Review the explainability cards:
    - *Cross-Origin Password Target detected* (+35)
    - *Brand Title Mismatch detected* (+25)
    - *Excessive External Script Ratio* (+15)
- Highlight the warning recommendation advising the user not to input credentials.

### Act IV: Adaptive Behavioral Drift Demonstration (1:00)
- Simulate a previously trusted domain that undergoes sudden structural tampering (e.g. login form injected with third-party action).
- Show how the local trust profiler detects behavioral drift (+20 penalty) and elevates the warning tier.

### Act V: Backend API, Tests & Privacy Verification (1:00)
- Display the terminal running `pytest backend/tests` and `npm test` across unit, privacy, and benchmark suites.
- Show the reproducible training pipeline and calibration curves.
