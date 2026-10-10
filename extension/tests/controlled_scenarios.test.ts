import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PhishingRiskEngine } from '../src/shared/risk_engine.js';
import { DOMFeatureVector } from '../src/shared/types.js';

describe('Controlled Phishing Detection Scenarios (Step 5 Verification)', () => {
  const engine = new PhishingRiskEngine();

  // SCENARIO 1: A Benign Page
  it('Scenario 1: correctly classifies a benign encyclopedic page as LOW risk (Score: 0)', () => {
    const benignDOM: DOMFeatureVector = {
      numForms: 1,
      numPasswordFields: 0,
      hasLoginForm: false,
      hasPaymentForm: false,
      paymentFieldCount: 0,
      crossOriginFormAction: false,
      insecureFormAction: false,
      formActionDomains: ['wikipedia.org'],
      externalResourceRatio: 0.1,
      externalScriptCount: 1,
      totalScriptCount: 10,
      hasDataUriScript: false,
      brandMismatchDetected: false,
      hiddenIframeCount: 0,
      suspiciousIframeCount: 0,
      title: 'Computer Security - Wikipedia',
      origin: 'https://en.wikipedia.org',
    };

    const verdict = engine.evaluate({
      url: 'https://en.wikipedia.org/wiki/Computer_security',
      domFeatures: benignDOM,
    });

    expect(verdict.riskScore).toBe(0);
    expect(verdict.riskTier).toBe('LOW');
    expect(verdict.status).toBe('COMPLETE');
    expect(verdict.primaryFactors).toHaveLength(0);
    expect(verdict.scoringBreakdown.confidenceLevel).toBe('HIGH');
    expect(verdict.scoringBreakdown.informationCompleteness).toBe(1.0);
  });

  // SCENARIO 2: Fake Credential-Collection Form with Simulated Cross-Origin Form Destination
  it('Scenario 2: flags a fake credential form submitting cross-origin as HIGH risk', () => {
    const fakeCredentialDOM: DOMFeatureVector = {
      numForms: 1,
      numPasswordFields: 1,
      hasLoginForm: true,
      hasPaymentForm: false,
      paymentFieldCount: 0,
      crossOriginFormAction: true,
      insecureFormAction: false,
      formActionDomains: ['evil-phish-collector.net'],
      externalResourceRatio: 0.75,
      externalScriptCount: 6,
      totalScriptCount: 8,
      hasDataUriScript: false,
      brandMismatchDetected: true,
      detectedBrandClaim: 'paypal',
      hiddenIframeCount: 0,
      suspiciousIframeCount: 0,
      title: 'PayPal Secure Log In',
      origin: 'http://paypal-verification-center.info',
    };

    const verdict = engine.evaluate({
      url: 'http://paypal-verification-center.info/signin',
      domFeatures: fakeCredentialDOM,
    });

    expect(verdict.riskScore).toBeGreaterThanOrEqual(60);
    expect(verdict.riskTier).toBe('HIGH');
    expect(verdict.status).toBe('COMPLETE');

    const factorNames = verdict.primaryFactors.map((f) => f.factor);
    expect(factorNames).toContain('CROSS_ORIGIN_CREDENTIAL_FORM');
    expect(factorNames).toContain('BRAND_TITLE_MISMATCH');
    expect(factorNames).toContain('INSECURE_HTTP_PROTOCOL');
    expect(verdict.scoringBreakdown.strongIndicatorsCount).toBeGreaterThanOrEqual(2);
    expect(verdict.recommendation).toContain('CRITICAL RISK');
  });

  // SCENARIO 3: Several Independent Suspicious Indicators Calibrated to MEDIUM Risk
  it('Scenario 3: combines independent weak signals into calibrated MEDIUM risk (30-59)', () => {
    const multiSignalDOM: DOMFeatureVector = {
      numForms: 1,
      numPasswordFields: 1,
      hasLoginForm: true,
      hasPaymentForm: false,
      paymentFieldCount: 0,
      crossOriginFormAction: false, // same origin destination (typical phishing kit)
      insecureFormAction: false,
      formActionDomains: ['banking-portal-secure.net'],
      externalResourceRatio: 0.85, // excessive external resources (+10)
      externalScriptCount: 9,
      totalScriptCount: 10,
      hasDataUriScript: false,
      brandMismatchDetected: false,
      hiddenIframeCount: 0,
      suspiciousIframeCount: 0,
      title: 'Member Verification Center',
      origin: 'https://sub1.sub2.banking-portal-secure.net',
    };

    // URL signals:
    // - Suspicious subdomains / structure (+8)
    // - Suspicious path token /verify (+8)
    // DOM signals:
    // - Credential form present on unverified domain (+15)
    // - Excessive external resources (+10)
    const verdict = engine.evaluate({
      url: 'https://sub1.sub2.banking-portal-secure.net/account/verify',
      domFeatures: multiSignalDOM,
    });

    // Must be in MEDIUM tier [30, 59] - not collapsed to LOW, and not falsely escalated to HIGH
    expect(verdict.riskScore).toBeGreaterThanOrEqual(30);
    expect(verdict.riskScore).toBeLessThanOrEqual(59);
    expect(verdict.riskTier).toBe('MEDIUM');
    expect(verdict.status).toBe('COMPLETE');

    const factorNames = verdict.primaryFactors.map((f) => f.factor);
    expect(factorNames).toContain('SUSPICIOUS_DOMAIN_STRUCTURE');
    expect(factorNames).toContain('SUSPICIOUS_PATH_PATTERN');
    expect(factorNames).toContain('CREDENTIAL_FORM_PRESENT');
    expect(factorNames).toContain('EXCESSIVE_EXTERNAL_RESOURCES');
    expect(verdict.scoringBreakdown.strongIndicatorsCount).toBe(0); // No single critical attack vector
    expect(verdict.scoringBreakdown.weakIndicatorsCount).toBeGreaterThanOrEqual(3);
  });

  // SCENARIO 4: Legitimate Login-Page Fixture
  it('Scenario 4: suppresses false positives on legitimate institutional SSO portal with trust bonus', () => {
    const legitSSODOM: DOMFeatureVector = {
      numForms: 2,
      numPasswordFields: 1,
      hasLoginForm: true,
      hasPaymentForm: false,
      paymentFieldCount: 0,
      crossOriginFormAction: false,
      insecureFormAction: false,
      formActionDomains: ['login.microsoftonline.com'],
      externalResourceRatio: 0.25,
      externalScriptCount: 3,
      totalScriptCount: 12,
      hasDataUriScript: false,
      brandMismatchDetected: false,
      hiddenIframeCount: 0,
      suspiciousIframeCount: 0,
      title: 'Sign in to your Microsoft Account',
      origin: 'https://login.microsoftonline.com',
    };

    const verdict = engine.evaluate({
      url: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
      domFeatures: legitSSODOM,
    });

    expect(verdict.isInstitutional).toBe(true);
    expect(verdict.riskScore).toBe(0);
    expect(verdict.riskTier).toBe('LOW');
    expect(verdict.status).toBe('COMPLETE');
    expect(verdict.scoringBreakdown.trustBonusDeduction).toBe(40);
    expect(verdict.recommendation).toContain('institutional');
  });

  // SCENARIO 5: Missing / Incomplete Structural Signals
  it('Scenario 5: reports INCOMPLETE status when DOM structural inspection is omitted', () => {
    const verdict = engine.evaluate({
      url: 'https://unverified-domain.org/checkout',
      domFeatures: null,
    });

    expect(verdict.status).toBe('INCOMPLETE');
    expect(verdict.scoringBreakdown.informationCompleteness).toBe(0.4);
    expect(verdict.scoringBreakdown.confidenceLevel).toBe('MEDIUM');
    expect(verdict.scoringBreakdown.uncertaintyNotes).toContain('DOM structural inspection was not available');
  });
});
