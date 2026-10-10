import { describe, it, expect, vi, beforeEach } from 'vitest';
import { evaluateSecurity } from '../src/background/index';
import { DOMFeatureVector } from '../src/shared/types';

// Mock chrome API for background service worker test environment
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

describe('Heuristic Rule Engine & Scoring Evaluation', () => {
  const cleanDOM: DOMFeatureVector = {
    numForms: 1,
    numPasswordFields: 0,
    hasLoginForm: false,
    hasPaymentForm: false,
    paymentFieldCount: 0,
    crossOriginFormAction: false,
    insecureFormAction: false,
    externalResourceRatio: 0.1,
    externalScriptCount: 1,
    totalScriptCount: 5,
    hasDataUriScript: false,
    brandMismatchDetected: false,
    hiddenIframeCount: 0,
    suspiciousIframeCount: 0,
    title: 'Standard Educational Blog',
    origin: 'https://example.edu',
    formActionDomains: ['example.edu'],
  };

  it('correctly classifies benign standard website as LOW risk', () => {
    const verdict = evaluateSecurity('https://example.edu/articles', cleanDOM, performance.now());
    expect(verdict.riskTier).toBe('LOW');
    expect(verdict.riskScore).toBeLessThanOrEqual(39);
    expect(verdict.status).toBe('COMPLETE');
    expect(verdict.primaryFactors).toHaveLength(0);
  });

  it('suppresses false positives on legitimate institutional SSO portals', () => {
    const institutionalSSODOM: DOMFeatureVector = {
      numForms: 2,
      numPasswordFields: 1,
      hasLoginForm: true,
      hasPaymentForm: false,
      paymentFieldCount: 0,
      crossOriginFormAction: false,
      insecureFormAction: false,
      externalResourceRatio: 0.35,
      externalScriptCount: 3,
      totalScriptCount: 8,
      hasDataUriScript: false,
      brandMismatchDetected: false,
      hiddenIframeCount: 0,
      suspiciousIframeCount: 0,
      title: 'Sign in to your University Account',
      origin: 'https://login.microsoftonline.com',
      formActionDomains: ['login.microsoftonline.com'],
    };

    const verdict = evaluateSecurity(
      'https://login.microsoftonline.com/common/oauth2/authorize',
      institutionalSSODOM,
      performance.now()
    );

    expect(verdict.isInstitutional).toBe(true);
    expect(verdict.riskTier).toBe('LOW');
    expect(verdict.riskScore).toBeLessThanOrEqual(35);
  });

  it('triggers HIGH risk alert on Punycode domain with cross-origin credential harvesting', () => {
    const phishingDOM: DOMFeatureVector = {
      numForms: 1,
      numPasswordFields: 1,
      hasLoginForm: true,
      hasPaymentForm: false,
      paymentFieldCount: 0,
      crossOriginFormAction: true,
      insecureFormAction: false,
      externalResourceRatio: 0.85,
      externalScriptCount: 6,
      totalScriptCount: 7,
      hasDataUriScript: false,
      brandMismatchDetected: true,
      hiddenIframeCount: 1,
      suspiciousIframeCount: 0,
      title: 'PayPal Secure Log In',
      origin: 'https://xn--paypa-cra.com',
      formActionDomains: ['stealth-collector.xyz'],
    };

    const verdict = evaluateSecurity('https://xn--paypa-cra.com/signin', phishingDOM, performance.now());

    expect(verdict.riskTier).toBe('HIGH');
    expect(verdict.riskScore).toBeGreaterThanOrEqual(70);

    const factorNames = verdict.primaryFactors.map((f) => f.factor);
    expect(factorNames).toContain('HOMOGRAPH_PUNYCODE_SPOOF');
    expect(factorNames).toContain('CROSS_ORIGIN_CREDENTIAL_FORM');
    expect(factorNames).toContain('BRAND_TITLE_MISMATCH');
    expect(factorNames).toContain('EXCESSIVE_EXTERNAL_RESOURCES');
  });

  it('triggers critical penalties on IP address hostnames with insecure forms', () => {
    const ipAttackDOM: DOMFeatureVector = {
      numForms: 1,
      numPasswordFields: 1,
      hasLoginForm: true,
      hasPaymentForm: false,
      paymentFieldCount: 0,
      crossOriginFormAction: false,
      insecureFormAction: true,
      externalResourceRatio: 0.2,
      externalScriptCount: 1,
      totalScriptCount: 5,
      hasDataUriScript: false,
      brandMismatchDetected: false,
      hiddenIframeCount: 0,
      suspiciousIframeCount: 0,
      title: 'Login Gateway',
      origin: 'http://192.168.1.15',
      formActionDomains: ['192.168.1.15'],
    };

    const verdict = evaluateSecurity('http://192.168.1.15/login', ipAttackDOM, performance.now());

    // 5 (base) + 25 (IP) + 10 (HTTP) + 30 (Insecure Password Form) = 65 (HIGH RISK in Phase 3 >= 60)
    expect(verdict.riskTier).toBe('HIGH');
    expect(verdict.riskScore).toBeGreaterThanOrEqual(60);
    const factorNames = verdict.primaryFactors.map((f) => f.factor);
    expect(factorNames).toContain('IP_ADDRESS_HOSTNAME');
    expect(factorNames).toContain('INSECURE_CREDENTIAL_TRANSMISSION');
    expect(factorNames).toContain('INSECURE_HTTP_PROTOCOL');
  });

  it('triggers critical penalties on payment forms submitting to cross-origin destinations', () => {
    const paymentPhishDOM: DOMFeatureVector = {
      numForms: 1,
      numPasswordFields: 0,
      hasLoginForm: false,
      hasPaymentForm: true,
      paymentFieldCount: 3,
      crossOriginFormAction: true,
      insecureFormAction: false,
      externalResourceRatio: 0.5,
      externalScriptCount: 2,
      totalScriptCount: 4,
      hasDataUriScript: false,
      brandMismatchDetected: false,
      hiddenIframeCount: 0,
      suspiciousIframeCount: 0,
      title: 'Checkout Payment Gateway',
      origin: 'https://shopping-store-fake.net',
      formActionDomains: ['card-stealer.xyz'],
    };

    const verdict = evaluateSecurity('https://shopping-store-fake.net/checkout', paymentPhishDOM, performance.now());
    const factorNames = verdict.primaryFactors.map((f) => f.factor);
    expect(factorNames).toContain('INSECURE_PAYMENT_COLLECTION');
  });
});
