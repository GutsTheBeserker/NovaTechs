import { describe, it, expect } from 'vitest';
import { analyzeSSLSecurity } from '../src/shared/ssl_analyzer';
import {
  analyzeExternalResources,
  isReputableCdn,
  isReputableSSO,
  isSuspiciousOriginHostname,
} from '../src/shared/resource_analyzer';
import { DOMFeatureVector } from '../src/shared/types';

describe('SSL/TLS & External Resource Analyzers (Phase 6)', () => {
  const baseDOM: DOMFeatureVector = {
    numForms: 1,
    numPasswordFields: 0,
    hasLoginForm: false,
    hasPaymentForm: false,
    paymentFieldCount: 0,
    crossOriginFormAction: false,
    insecureFormAction: false,
    formActionDomains: ['example.com'],
    externalResourceRatio: 0.1,
    externalScriptCount: 1,
    totalScriptCount: 5,
    hasDataUriScript: false,
    brandMismatchDetected: false,
    hiddenIframeCount: 0,
    suspiciousIframeCount: 0,
    title: 'Example Domain',
    origin: 'https://example.com',
  };

  describe('SSL/TLS Security Signal Analysis', () => {
    it('honestly acknowledges MV3 TLS API boundaries and limitations', () => {
      const result = analyzeSSLSecurity('https://example.com', baseDOM);

      expect(result.tlsApiLimitationsAcknowledged).toBe(true);
      expect(result.limitationsNote).toContain('Chrome Manifest V3 extensions cannot inspect arbitrary raw X.509');
      expect(result.limitationsNote).toContain('HTTPS proves transport encryption, not website legitimacy');
      expect(result.isHttps).toBe(true);
      expect(result.signals).toHaveLength(0);
    });

    it('flags unencrypted HTTP transport when sensitive credential inputs exist', () => {
      const insecureLoginDOM: DOMFeatureVector = {
        ...baseDOM,
        origin: 'http://insecure-login.net',
        numPasswordFields: 1,
        hasLoginForm: true,
      };

      const result = analyzeSSLSecurity('http://insecure-login.net/login', insecureLoginDOM);

      expect(result.isHttps).toBe(false);
      expect(result.scoreAdjustment).toBeGreaterThanOrEqual(35);
      const sensitiveHttpSignal = result.signals.find((s) => s.factor === 'PLAINTEXT_HTTP_CREDENTIAL_FORM');
      expect(sensitiveHttpSignal).toBeDefined();
      expect(sensitiveHttpSignal?.severity).toBe('CRITICAL');
    });

    it('detects mixed content: insecure HTTP form action on an HTTPS page', () => {
      const mixedFormDOM: DOMFeatureVector = {
        ...baseDOM,
        insecureFormAction: true,
        insecureFormActions: 1,
      };

      const result = analyzeSSLSecurity('https://secure-store.com/checkout', mixedFormDOM);

      expect(result.hasMixedContent).toBe(true);
      expect(result.insecureResourceCount).toBe(1);
      const mixedSignal = result.signals.find((s) => s.factor === 'MIXED_CONTENT_INSECURE_FORM_ACTION');
      expect(mixedSignal).toBeDefined();
      expect(mixedSignal?.severity).toBe('HIGH');
    });

    it('detects mixed content: active HTTP scripts on an HTTPS page', () => {
      const mixedScriptDOM: DOMFeatureVector = {
        ...baseDOM,
        scriptOrigins: ['http://unencrypted-cdn.net', 'https://cdnjs.cloudflare.com'],
      };

      const result = analyzeSSLSecurity('https://mybank.com/dashboard', mixedScriptDOM);

      expect(result.hasMixedContent).toBe(true);
      const scriptSignal = result.signals.find((s) => s.factor === 'MIXED_CONTENT_ACTIVE_SCRIPT');
      expect(scriptSignal).toBeDefined();
      expect(scriptSignal?.evidence).toContain('http://unencrypted-cdn.net');
    });

    it('detects mixed content: insecure HTTP iframes on an HTTPS page', () => {
      const mixedIframeDOM: DOMFeatureVector = {
        ...baseDOM,
        iframeOrigins: ['http://legacy-sub.net'],
      };

      const result = analyzeSSLSecurity('https://corporate.org', mixedIframeDOM);

      expect(result.hasMixedContent).toBe(true);
      const frameSignal = result.signals.find((s) => s.factor === 'MIXED_CONTENT_INSECURE_FRAME');
      expect(frameSignal).toBeDefined();
      expect(frameSignal?.severity).toBe('MEDIUM');
    });
  });

  describe('External Resource & CDN Analysis', () => {
    it('correctly recognizes reputable CDNs and benign static asset hosts', () => {
      expect(isReputableCdn('cdnjs.cloudflare.com')).toBe(true);
      expect(isReputableCdn('sub.cdn.jsdelivr.net')).toBe(true);
      expect(isReputableCdn('fonts.googleapis.com')).toBe(true);
      expect(isReputableCdn('unpkg.com')).toBe(true);
      expect(isReputableCdn('evil-phishing-host.xyz')).toBe(false);
    });

    it('correctly recognizes reputable institutional SSO providers', () => {
      expect(isReputableSSO('login.microsoftonline.com')).toBe(true);
      expect(isReputableSSO('accounts.google.com')).toBe(true);
      expect(isReputableSSO('auth0.com')).toBe(true);
      expect(isReputableSSO('rogue-idp.top')).toBe(false);
    });

    it('flags untrusted script origins (IP literals and dynamic DNS tunnels)', () => {
      expect(isSuspiciousOriginHostname('192.168.1.1')).toBe(true);
      expect(isSuspiciousOriginHostname('45.33.32.156')).toBe(true);
      expect(isSuspiciousOriginHostname('stealth.duckdns.org')).toBe(true);
      expect(isSuspiciousOriginHostname('tunnel-gateway.ngrok-free.app')).toBe(true);
      expect(isSuspiciousOriginHostname('legitimate-corp.com')).toBe(false);

      const suspiciousDOM: DOMFeatureVector = {
        ...baseDOM,
        scriptOrigins: ['https://stealth.duckdns.org/payload.js', 'https://cdnjs.cloudflare.com/lib.js'],
      };

      const analysis = analyzeExternalResources('https://trusted-service.com', suspiciousDOM);
      expect(analysis.reputableCdnCount).toBe(1);
      expect(analysis.suspiciousScriptOriginCount).toBe(1);
      expect(analysis.suspiciousOrigins).toContain('stealth.duckdns.org');

      const signal = analysis.signals.find((s) => s.factor === 'SUSPICIOUS_SCRIPT_ORIGIN');
      expect(signal).toBeDefined();
      expect(signal?.severity).toBe('HIGH');
    });

    it('flags form action pointing directly to an untrusted dynamic DNS or IP endpoint', () => {
      const suspiciousFormDOM: DOMFeatureVector = {
        ...baseDOM,
        formActionDomains: ['harvester.ngrok.io'],
      };

      const analysis = analyzeExternalResources('https://target-brand.com', suspiciousFormDOM);
      const formSignal = analysis.signals.find((s) => s.factor === 'UNTRUSTED_FORM_DESTINATION_ORIGIN');
      expect(formSignal).toBeDefined();
      expect(formSignal?.severity).toBe('CRITICAL');
      expect(formSignal?.scoreImpact).toBe(35);
    });

    it('flags untrusted cross-origin iframe origins', () => {
      const suspiciousIframeDOM: DOMFeatureVector = {
        ...baseDOM,
        iframeOrigins: ['http://185.220.101.5/frame'],
      };

      const analysis = analyzeExternalResources('https://portal.net', suspiciousIframeDOM);
      const iframeSignal = analysis.signals.find((s) => s.factor === 'UNTRUSTED_IFRAME_ORIGIN');
      expect(iframeSignal).toBeDefined();
      expect(iframeSignal?.severity).toBe('HIGH');
    });
  });
});
