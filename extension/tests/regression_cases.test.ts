import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PhishingRiskEngine, classifyRiskTier } from '../src/shared/risk_engine.js';
import { DEFAULT_RISK_CONFIG } from '../src/shared/risk_config.js';
import { matchTrustedDomain } from '../src/shared/trusted_domains.js';
import { DOMFeatureVector, BackendAnalyzeResponse } from '../src/shared/types.js';
import { shouldTransmitRemotely, buildPermittedRemotePayload } from '../src/shared/remote_policy.js';
import { coordinateSecurityAnalysis, tabVerdicts } from '../src/background/index.js';
import { isRestrictedScheme } from '../src/shared/validators.js';

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

describe('PhishGuard Comprehensive Regression Test Suite (Cases A through I)', () => {
  const engine = new PhishingRiskEngine();

  // Clean DOM fixture
  const createCleanDOM = (domain: string, title = 'Official Portal'): DOMFeatureVector => ({
    numForms: 1,
    numPasswordFields: 0,
    hasLoginForm: false,
    hasPaymentForm: false,
    paymentFieldCount: 0,
    crossOriginFormAction: false,
    insecureFormAction: false,
    formActionDomains: [domain],
    externalResourceRatio: 0.1,
    externalScriptCount: 2,
    totalScriptCount: 15,
    hasDataUriScript: false,
    brandMismatchDetected: false,
    hiddenIframeCount: 0,
    suspiciousIframeCount: 0,
    title,
    origin: `https://${domain}`,
  });

  // =========================================================================
  // CASE A: Official legitimate websites
  // =========================================================================
  describe('Case A: Official legitimate websites', () => {
    const officialDomains = [
      { url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ', domain: 'youtube.com' },
      { url: 'https://m.facebook.com/profile', domain: 'facebook.com' },
      { url: 'https://en.wikipedia.org/wiki/Computer_security', domain: 'wikipedia.org' },
      { url: 'https://ganpatuniversity.ac.in/about-us', domain: 'ganpatuniversity.ac.in' },
      { url: 'https://portal.ganpatuniversity.ac.in/student/login', domain: 'ganpatuniversity.ac.in' },
    ];

    officialDomains.forEach(({ url, domain }) => {
      it(`evaluates official domain "${domain}" as LOW RISK baseline [0-29]`, () => {
        // 1. Verify trusted domain match
        const trustedMatch = matchTrustedDomain(new URL(url).hostname);
        expect(trustedMatch).not.toBeNull();
        expect(trustedMatch?.domain).toBe(domain);
        expect(trustedMatch?.provenance).toBeDefined();

        // 2. Evaluate with risk engine
        const cleanDOM = createCleanDOM(domain, 'Official Web Portal');
        const verdict = engine.evaluate({
          url,
          domFeatures: cleanDOM,
        });

        expect(verdict.isInstitutional).toBe(true);
        expect(verdict.riskScore).toBeLessThanOrEqual(29);
        expect(verdict.riskTier).toBe('LOW');
        expect(verdict.status).toBe('COMPLETE');
        expect(verdict.recommendation).toContain('SAFE');
      });
    });

    it('does not force LOW RISK on official domain if critical compromise exists', () => {
      const compromisedDOM: DOMFeatureVector = {
        ...createCleanDOM('youtube.com'),
        hasLoginForm: true,
        numPasswordFields: 1,
        crossOriginFormAction: true,
        formActionDomains: ['malicious-stealer-backend.xyz'],
      };

      const verdict = engine.evaluate({
        url: 'https://youtube.com/compromised-page',
        domFeatures: compromisedDOM,
      });

      // Compromised page must not be forced to 0 or capped at 29
      expect(verdict.riskScore).toBeGreaterThanOrEqual(30);
      const factors = verdict.primaryFactors.map((f) => f.factor);
      expect(factors).toContain('CROSS_ORIGIN_CREDENTIAL_FORM');
    });
  });

  // =========================================================================
  // CASE B: Trusted-domain lookalikes
  // =========================================================================
  describe('Case B: Trusted-domain lookalikes', () => {
    const lookalikeUrls = [
      { url: 'https://youtube.com.fake-example.com/login', lookalike: 'youtube.com' },
      { url: 'https://facebook-login.fake-example.com/auth', lookalike: 'facebook' },
      { url: 'https://ganpatuniversity-login.fake-example.com/portal', lookalike: 'ganpatuniversity' },
      { url: 'https://not-youtube.com/video', lookalike: 'youtube' },
    ];

    lookalikeUrls.forEach(({ url, lookalike }) => {
      it(`does NOT inherit trust for lookalike "${url}"`, () => {
        const hostname = new URL(url).hostname;
        const trustedMatch = matchTrustedDomain(hostname);
        expect(trustedMatch).toBeNull(); // Must NOT match official domain

        const verdict = engine.evaluate({
          url,
          domFeatures: null,
        });

        expect(verdict.isInstitutional).toBe(false);
        // Starts with unfamiliar domain baseline (30)
        expect(verdict.riskScore).toBeGreaterThanOrEqual(30);
      });
    });

    it('flags misleading brand in subdomain for youtube.com.fake-example.com', () => {
      const verdict = engine.evaluate({
        url: 'https://youtube.com.fake-example.com/watch',
        domFeatures: null,
      });

      const factors = verdict.primaryFactors.map((f) => f.factor);
      expect(factors).toContain('MISLEADING_BRAND_SUBDOMAIN');
      expect(factors).toContain('UNFAMILIAR_DOMAIN_BASELINE');
      expect(verdict.riskScore).toBeGreaterThanOrEqual(50);
    });
  });

  // =========================================================================
  // CASE C: Unknown domains
  // =========================================================================
  describe('Case C: Unknown domains', () => {
    it('applies MEDIUM baseline (30 pts) for clean synthetic unknown domains', () => {
      const syntheticUrl = 'https://synthportal.xyz/portal';
      const cleanDOM = createCleanDOM('synthportal.xyz', 'Synthetic Blog');

      const verdict = engine.evaluate({
        url: syntheticUrl,
        domFeatures: cleanDOM,
      });

      expect(verdict.isInstitutional).toBe(false);
      expect(verdict.riskScore).toBe(30);
      expect(verdict.riskTier).toBe('MEDIUM');
      expect(verdict.status).toBe('COMPLETE');

      const factors = verdict.primaryFactors.map((f) => f.factor);
      expect(factors).toContain('UNFAMILIAR_DOMAIN_BASELINE');
      expect(verdict.recommendation).toContain('PROCEED WITH CAUTION');
    });

    it('adjusts score above 30 when unusual indicators are detected', () => {
      const syntheticUrl = 'https://unknown-shop-portal.xyz/account/verify';
      const cleanDOM = createCleanDOM('unknown-shop-portal.xyz', 'Shop Checkout');

      const verdict = engine.evaluate({
        url: syntheticUrl,
        domFeatures: cleanDOM,
      });

      // 30 (unfamiliar baseline) + 8 (suspicious path token /verify) = 38
      expect(verdict.riskScore).toBeGreaterThanOrEqual(38);
      expect(verdict.riskTier).toBe('MEDIUM');
    });
  });

  // =========================================================================
  // CASE D: Suspicious credential collection
  // =========================================================================
  describe('Case D: Suspicious credential collection', () => {
    it('flags fake credential collection submitting cross-origin as HIGH RISK', () => {
      const fakeLoginDOM: DOMFeatureVector = {
        numForms: 1,
        numPasswordFields: 1,
        hasLoginForm: true,
        hasPaymentForm: false,
        paymentFieldCount: 0,
        crossOriginFormAction: true,
        insecureFormAction: false,
        formActionDomains: ['foreign-data-collector.xyz'],
        externalResourceRatio: 0.3,
        externalScriptCount: 3,
        totalScriptCount: 8,
        hasDataUriScript: false,
        brandMismatchDetected: false,
        hiddenIframeCount: 0,
        suspiciousIframeCount: 0,
        title: 'User Login Portal',
        origin: 'https://login-service-test.net',
      };

      const verdict = engine.evaluate({
        url: 'https://login-service-test.net/login',
        domFeatures: fakeLoginDOM,
      });

      // 30 (unfamiliar baseline) + 35 (cross origin password) + 15 (credential form present) = 80 -> HIGH RISK
      expect(verdict.riskScore).toBeGreaterThanOrEqual(60);
      expect(verdict.riskTier).toBe('HIGH');
      expect(verdict.status).toBe('COMPLETE');

      const factors = verdict.primaryFactors.map((f) => f.factor);
      expect(factors).toContain('CROSS_ORIGIN_CREDENTIAL_FORM');
      expect(factors).toContain('CREDENTIAL_FORM_PRESENT');
      expect(verdict.recommendation).toContain('CRITICAL RISK');
    });
  });

  // =========================================================================
  // CASE E: Multiple strong indicators
  // =========================================================================
  describe('Case E: Multiple strong indicators', () => {
    it('combines multiple strong independent indicators to reach HIGH RISK (>=60)', () => {
      const multiAttackDOM: DOMFeatureVector = {
        numForms: 1,
        numPasswordFields: 1,
        hasLoginForm: true,
        hasPaymentForm: false,
        paymentFieldCount: 0,
        crossOriginFormAction: true,
        insecureFormAction: true,
        formActionDomains: ['stealth-drop.xyz'],
        externalResourceRatio: 0.9,
        externalScriptCount: 8,
        totalScriptCount: 9,
        hasDataUriScript: false,
        brandMismatchDetected: true,
        detectedBrandClaim: 'paypal',
        hiddenIframeCount: 0,
        suspiciousIframeCount: 1, // overlay iframe
        title: 'PayPal Verification',
        origin: 'http://xn--paypa-cra.net',
      };

      const verdict = engine.evaluate({
        url: 'http://xn--paypa-cra.net/account/verify',
        domFeatures: multiAttackDOM,
      });

      expect(verdict.riskScore).toBeGreaterThanOrEqual(60);
      expect(verdict.riskTier).toBe('HIGH');
      expect(verdict.scoringBreakdown.strongIndicatorsCount).toBeGreaterThanOrEqual(3);

      const factors = verdict.primaryFactors.map((f) => f.factor);
      expect(factors).toContain('HOMOGRAPH_PUNYCODE_SPOOF');
      expect(factors).toContain('CROSS_ORIGIN_CREDENTIAL_FORM');
      expect(factors).toContain('BRAND_TITLE_MISMATCH');
      expect(factors).toContain('SUSPICIOUS_OVERLAY_IFRAME');
      expect(factors).toContain('INSECURE_CREDENTIAL_TRANSMISSION');
    });
  });

  // =========================================================================
  // CASE F: Vegamovies-like hostname
  // =========================================================================
  describe('Case F: Vegamovies-like hostname', () => {
    it('does NOT mark synthetic Vegamovies-like domain as HIGH RISK on name alone', () => {
      const syntheticMovieUrl = 'https://vegamovies.xyz/stream';
      const cleanDOM = createCleanDOM('vegamovies.xyz', 'Movie Stream Hub');

      const verdict = engine.evaluate({
        url: syntheticMovieUrl,
        domFeatures: cleanDOM,
      });

      // Name alone does NOT trigger high risk! Evaluated with unfamiliar domain baseline (30, MEDIUM)
      expect(verdict.riskTier).toBe('MEDIUM');
      expect(verdict.riskScore).toBe(30);
      expect(verdict.scoringBreakdown.strongIndicatorsCount).toBe(0);
    });

    it('elevates to HIGH RISK if real threat intelligence matches or credential theft occurs', () => {
      // Documented threat match configured in constants.ts
      const threatIntelUrl = 'https://evil-phish-bank.com/signin';
      const verdict = engine.evaluate({
        url: threatIntelUrl,
        domFeatures: null,
      });

      expect(verdict.riskTier).toBe('HIGH');
      expect(verdict.riskScore).toBeGreaterThanOrEqual(60);
      const factors = verdict.primaryFactors.map((f) => f.factor);
      expect(factors).toContain('KNOWN_THREAT_INTELLIGENCE_MATCH');
    });
  });

  // =========================================================================
  // CASE G: Scanning errors
  // =========================================================================
  describe('Case G: Scanning errors and incomplete analysis', () => {
    it('reports INCOMPLETE status when DOM structural features could not be collected', () => {
      const verdict = engine.evaluate({
        url: 'https://en.wikipedia.org/wiki/Test',
        domFeatures: null, // Simulated content-script failure
      });

      expect(verdict.status).toBe('INCOMPLETE');
      // Must not falsely claim LOW RISK when DOM analysis failed
      expect(verdict.riskTier).toBe('UNKNOWN');
      expect(verdict.recommendation).toContain('SCAN INCOMPLETE');
    });

    it('identifies restricted browser pages and returns UNSUPPORTED_SCHEME', () => {
      expect(isRestrictedScheme('chrome://settings')).toBe(true);
      expect(isRestrictedScheme('chrome-extension://abcdef/popup.html')).toBe(true);
      expect(isRestrictedScheme('file:///C:/Users/test.html')).toBe(true);

      const verdict = engine.evaluate({
        url: 'chrome://settings',
        domFeatures: null,
      });

      expect(verdict.status).toBe('UNSUPPORTED_SCHEME');
      expect(verdict.scheme).toBe('restricted');
      expect(verdict.riskScore).toBe(0);
      expect(verdict.recommendation).toContain('internal page');
    });

    it('handles offline backend gracefully with local fallback verdict', async () => {
      const mockOfflineFetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));
      const suspiciousUrl = 'http://192.168.1.1/login';
      const tabId = 999;

      const verdict = await coordinateSecurityAnalysis(
        tabId,
        suspiciousUrl,
        null,
        false,
        'test-offline-scan',
        { fetchFn: mockOfflineFetch as unknown as typeof fetch }
      );

      expect(verdict.offlineFallback).toBe(true);
      expect(verdict.scanSource).toBe('local_heuristics');
      expect(verdict.riskScore).toBeGreaterThanOrEqual(60);
    });
  });

  // =========================================================================
  // CASE H: Score boundaries
  // =========================================================================
  describe('Case H: Score boundaries (0, 29, 30, 59, 60, 100)', () => {
    const thresholds = DEFAULT_RISK_CONFIG.thresholds;

    it('classifies exact boundary 0 as LOW', () => {
      expect(classifyRiskTier(0, thresholds)).toBe('LOW');
    });

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
  });

  // =========================================================================
  // CASE I: Privacy
  // =========================================================================
  describe('Case I: Privacy and zero-PII enforcement', () => {
    it('does NOT transmit remote requests for verified institutional/official domains', () => {
      const officialVerdict = engine.evaluate({
        url: 'https://www.youtube.com',
        domFeatures: createCleanDOM('youtube.com'),
      });

      const decision = shouldTransmitRemotely(officialVerdict, 'https://www.youtube.com', false);
      expect(decision.shouldTransmit).toBe(false);
      expect(decision.payloadType).toBe('none');
    });

    it('ensures payload contains ONLY 40 numerical features with zero sensitive values', () => {
      const sensitiveUrl =
        'https://sub.portal.xyz/auth?user_id=123&password=secretPassword&token=jwt.token.abc#anchor';
      const payload = buildPermittedRemotePayload(sensitiveUrl);

      expect(payload.features).toBeDefined();
      expect(Object.keys(payload.features!)).toHaveLength(40);

      const jsonString = JSON.stringify(payload);
      expect(jsonString).not.toContain('secretPassword');
      expect(jsonString).not.toContain('jwt.token.abc');
      expect(jsonString).not.toContain('password');
      expect(jsonString).not.toContain('cookie');
      expect(jsonString).not.toContain('input');
    });
  });
});
