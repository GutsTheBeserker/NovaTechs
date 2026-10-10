import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  classifyRiskTier,
  normalizeDOMFeatures,
  PhishingRiskEngine,
} from '../src/shared/risk_engine';
import { DOMFeatureVector } from '../src/shared/types';
import { createRiskConfig, DEFAULT_RISK_CONFIG } from '../src/shared/risk_config';

// Mock chrome API for background/testing environments
beforeEach(() => {
  globalThis.chrome = {
    action: {
      setBadgeText: vi.fn(),
      setBadgeBackgroundColor: vi.fn(),
    },
    runtime: {
      onMessage: { addListener: vi.fn() },
      getURL: vi.fn((path) => `chrome-extension://mock-id/${path}`),
    },
    tabs: {
      onRemoved: { addListener: vi.fn() },
      create: vi.fn(),
    },
  } as any;
});

describe('Multi-Signal Phishing Risk Engine (Phase 3)', () => {
  const engine = new PhishingRiskEngine();

  // Test 1: Benign HTTPS Website
  it('correctly evaluates a benign HTTPS website with clean DOM as LOW risk', () => {
    const cleanDOM: DOMFeatureVector = {
      numForms: 1,
      numPasswordFields: 0,
      hasLoginForm: false,
      hasPaymentForm: false,
      paymentFieldCount: 0,
      crossOriginFormAction: false,
      insecureFormAction: false,
      formActionDomains: ['wikipedia.org'],
      externalResourceRatio: 0.15,
      externalScriptCount: 2,
      totalScriptCount: 12,
      hasDataUriScript: false,
      brandMismatchDetected: false,
      hiddenIframeCount: 0,
      suspiciousIframeCount: 0,
      title: 'Phishing - Wikipedia',
      origin: 'https://en.wikipedia.org',
    };

    const result = engine.evaluate({
      url: 'https://en.wikipedia.org/wiki/Phishing',
      domFeatures: cleanDOM,
    });

    expect(result.riskTier).toBe('LOW');
    expect(result.riskScore).toBeLessThanOrEqual(29);
    expect(result.status).toBe('COMPLETE');
    expect(result.scoringBreakdown.confidenceLevel).toBe('HIGH');
    expect(result.scoringBreakdown.informationCompleteness).toBe(1.0);
    expect(result.primaryFactors).toHaveLength(0);
    expect(result.recommendation).toContain('SAFE');
  });

  // Test 2: Legitimate Institutional Login Page
  it('suppresses false positives on legitimate institutional SSO portals with trust bonus', () => {
    const ssoDOM: DOMFeatureVector = {
      numForms: 1,
      numPasswordFields: 1,
      hasLoginForm: true,
      hasPaymentForm: false,
      paymentFieldCount: 0,
      crossOriginFormAction: false,
      insecureFormAction: false,
      formActionDomains: ['login.microsoftonline.com'],
      externalResourceRatio: 0.3,
      externalScriptCount: 3,
      totalScriptCount: 10,
      hasDataUriScript: false,
      brandMismatchDetected: false,
      hiddenIframeCount: 0,
      suspiciousIframeCount: 0,
      title: 'Sign in to your account',
      origin: 'https://login.microsoftonline.com',
    };

    const result = engine.evaluate({
      url: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
      domFeatures: ssoDOM,
    });

    expect(result.isInstitutional).toBe(true);
    expect(result.riskTier).toBe('LOW');
    // Institutional allowance must cap score <= 29 (LOW threshold boundary)
    expect(result.riskScore).toBeLessThanOrEqual(29);
    expect(result.scoringBreakdown.trustBonusDeduction).toBeGreaterThan(0);
    expect(result.recommendation).toContain('Verified institutional');
  });

  // Test 3: Suspicious Credential-Collection Page
  it('identifies suspicious credential collection with cross-origin submission as HIGH risk', () => {
    const credentialTheftDOM: DOMFeatureVector = {
      numForms: 1,
      numPasswordFields: 1,
      hasLoginForm: true,
      hasPaymentForm: false,
      paymentFieldCount: 0,
      crossOriginFormAction: true,
      insecureFormAction: false,
      formActionDomains: ['stealth-collector-backend.xyz'],
      externalResourceRatio: 0.85,
      externalScriptCount: 8,
      totalScriptCount: 9,
      hasDataUriScript: false,
      brandMismatchDetected: true,
      detectedBrandClaim: 'microsoft',
      hiddenIframeCount: 0,
      suspiciousIframeCount: 0,
      title: 'Microsoft Account Login',
      origin: 'http://account-verify-login.net',
    };

    const result = engine.evaluate({
      url: 'http://account-verify-login.net/signin',
      domFeatures: credentialTheftDOM,
    });

    expect(result.riskTier).toBe('HIGH');
    expect(result.riskScore).toBeGreaterThanOrEqual(60);
    expect(result.scoringBreakdown.strongIndicatorsCount).toBeGreaterThanOrEqual(1);

    const factors = result.primaryFactors.map((f) => f.factor);
    expect(factors).toContain('CROSS_ORIGIN_CREDENTIAL_FORM');
    expect(factors).toContain('BRAND_TITLE_MISMATCH');
    expect(factors).toContain('INSECURE_HTTP_PROTOCOL');
    expect(result.recommendation).toContain('CRITICAL RISK');
  });

  // Test 4: Suspicious URL with Multiple Independent Indicators
  it('combines multiple independent URL indicators and applies category caps properly', () => {
    // Punycode + brand in subdomain + hex encoding + excessive subdomains + sensitive path
    const complexAttackUrl =
      'https://paypal.com.account-security.xn--paypa-cra.com/verify?token=123&session=%2e%2e%2f%2f';

    const result = engine.evaluate({
      url: complexAttackUrl,
      domFeatures: null, // Partial scan without DOM
    });

    expect(result.riskTier).toBe('HIGH');
    expect(result.riskScore).toBeGreaterThanOrEqual(60);

    const factors = result.primaryFactors.map((f) => f.factor);
    expect(factors).toContain('HOMOGRAPH_PUNYCODE_SPOOF');
    expect(factors).toContain('MISLEADING_BRAND_SUBDOMAIN');
    expect(factors).toContain('SUSPICIOUS_DOMAIN_STRUCTURE');
    expect(factors).toContain('SUSPICIOUS_HEX_ENCODING');
    expect(result.scoringBreakdown.categoryContributions.URL).toBeGreaterThanOrEqual(30);
  });

  // Test 5: Page with Incomplete Information (Missing DOM)
  it('accounts for uncertainty and missing information gracefully when DOM is omitted', () => {
    const result = engine.evaluate({
      url: 'https://example-shop.com/catalog',
      domFeatures: null,
    });

    expect(result.status).toBe('INCOMPLETE');
    expect(result.scoringBreakdown.informationCompleteness).toBe(0.4);
    expect(result.scoringBreakdown.confidenceLevel).toBe('MEDIUM');
    expect(result.scoringBreakdown.uncertaintyNotes).toBeDefined();
    expect(result.scoringBreakdown.uncertaintyNotes).toContain('DOM structural inspection was not available');
    // Unfamiliar domain starts at medium baseline (30) with INCOMPLETE scan status
    expect(result.riskTier).toBe('MEDIUM');
    expect(result.riskScore).toBe(30);

    // Official trusted domain with omitted DOM reports UNKNOWN tier rather than falsely claiming LOW
    const trustedOmittedResult = engine.evaluate({
      url: 'https://en.wikipedia.org/wiki/Test',
      domFeatures: null,
    });
    expect(trustedOmittedResult.status).toBe('INCOMPLETE');
    expect(trustedOmittedResult.riskTier).toBe('UNKNOWN');
  });

  // Test 6: Duplicate Indicators
  it('deduplicates identical indicators and tracks suppressed duplicates', () => {
    const domWithDuplicateEvidence: DOMFeatureVector = {
      numForms: 2,
      numPasswordFields: 2,
      hasLoginForm: true,
      hasPaymentForm: false,
      paymentFieldCount: 0,
      crossOriginFormAction: true,
      insecureFormAction: false,
      formActionDomains: ['same-thief.com', 'same-thief.com'], // duplicate domain
      externalResourceRatio: 0.1,
      externalScriptCount: 1,
      totalScriptCount: 5,
      hasDataUriScript: false,
      brandMismatchDetected: false,
      hiddenIframeCount: 0,
      suspiciousIframeCount: 0,
      title: 'Portal',
      origin: 'https://target.com',
    };

    const result = engine.evaluate({
      url: 'https://target.com/login',
      domFeatures: domWithDuplicateEvidence,
    });

    // CROSS_ORIGIN_CREDENTIAL_FORM should only be counted once
    const crossOriginFactors = result.primaryFactors.filter(
      (f) => f.factor === 'CROSS_ORIGIN_CREDENTIAL_FORM'
    );
    expect(crossOriginFactors).toHaveLength(1);
  });

  // Test 7: Missing or Malformed Signals
  it('handles malformed, NaN, and negative signal inputs without crashing', () => {
    const malformedRawDOM = {
      numForms: -10,
      numPasswordFields: 'invalid' as any,
      externalResourceRatio: NaN,
      formActionDomains: null as any,
      title: null as any,
    } as any;

    const normalized = normalizeDOMFeatures(malformedRawDOM);
    expect(normalized.isComplete).toBe(true);
    expect(normalized.features?.numForms).toBe(0);
    expect(normalized.features?.numPasswordFields).toBe(0);
    expect(normalized.features?.externalResourceRatio).toBe(0.0);
    expect(normalized.features?.formActionDomains).toEqual([]);

    const result = engine.evaluate({
      url: 'https://en.wikipedia.org/wiki/Home',
      domFeatures: normalized.features,
    });

    expect(result.status).toBe('COMPLETE');
    expect(result.riskTier).toBe('LOW');
    expect(result.riskScore).toBe(0);

    const unknownResult = engine.evaluate({
      url: 'https://unknownshop.xyz/home',
      domFeatures: normalized.features,
    });
    expect(unknownResult.status).toBe('COMPLETE');
    expect(unknownResult.riskTier).toBe('MEDIUM');
    expect(unknownResult.riskScore).toBe(30);
  });

  // Test 8: Boundary Values of 29, 30, 59, 60, and 100
  describe('Boundary Value Threshold Classification', () => {
    const thresholds = DEFAULT_RISK_CONFIG.thresholds;

    it('classifies exact boundary 29 as LOW', () => {
      expect(classifyRiskTier(29, thresholds)).toBe('LOW');
    });

    it('classifies exact boundary 30 as MEDIUM', () => {
      expect(classifyRiskTier(30, thresholds)).toBe('MEDIUM');
    });

    it('classifies exact boundary 59 as MEDIUM', () => {
      expect(classifyRiskTier(59, thresholds)).toBe('MEDIUM');
    });

    it('classifies exact boundary 60 as HIGH', () => {
      expect(classifyRiskTier(60, thresholds)).toBe('HIGH');
    });

    it('classifies exact boundary 100 as HIGH', () => {
      expect(classifyRiskTier(100, thresholds)).toBe('HIGH');
    });

    it('classifies lower boundary 0 as LOW', () => {
      expect(classifyRiskTier(0, thresholds)).toBe('LOW');
    });

    it('supports custom threshold configurations', () => {
      const customConfig = createRiskConfig({
        thresholds: {
          lowMax: 20,
          mediumMin: 21,
          mediumMax: 49,
          highMin: 50,
          highMax: 100,
        },
      });

      expect(classifyRiskTier(20, customConfig.thresholds)).toBe('LOW');
      expect(classifyRiskTier(21, customConfig.thresholds)).toBe('MEDIUM');
      expect(classifyRiskTier(50, customConfig.thresholds)).toBe('HIGH');
    });
  });

  // Test 9: Weak Heuristics Safeguard (Weak heuristics alone cannot trigger HIGH risk)
  it('prevents weak heuristics alone from triggering HIGH risk without a strong indicator', () => {
    // Unverified site with long URL, hyphens, and high external resources, but NO Punycode, NO IP, NO credential theft
    const weakHeuristicsDOM: DOMFeatureVector = {
      numForms: 0,
      numPasswordFields: 0,
      hasLoginForm: false,
      hasPaymentForm: false,
      paymentFieldCount: 0,
      crossOriginFormAction: false,
      insecureFormAction: false,
      formActionDomains: [],
      externalResourceRatio: 0.95, // Contextual
      externalScriptCount: 10,
      totalScriptCount: 11,
      hasDataUriScript: false,
      brandMismatchDetected: false,
      hiddenIframeCount: 3, // Contextual
      suspiciousIframeCount: 0,
      title: 'Free Blog Page',
      origin: 'http://my-blog-long-title-hyphens-archive.net',
    };

    const longHttpUrl =
      'http://my-blog-long-title-hyphens-archive.net/articles/post/archive/long-url-slug-test-1234567890-test-slug';

    const result = engine.evaluate({
      url: longHttpUrl,
      domFeatures: weakHeuristicsDOM,
    });

    // Weak heuristics must be capped at mediumMax (59), never crossing into HIGH without a strong attack vector
    expect(result.riskTier).toBe('MEDIUM');
    expect(result.riskScore).toBeLessThanOrEqual(59);
    expect(result.scoringBreakdown.strongIndicatorsCount).toBe(0);
  });
});
