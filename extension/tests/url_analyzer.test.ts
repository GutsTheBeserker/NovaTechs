import { describe, it, expect } from 'vitest';
import { analyzeUrl } from '../src/shared/url_analyzer';

describe('Dedicated URL Analysis Module', () => {
  it('inspects excessive URL length (>200 characters) as a signal', () => {
    const longUrl = 'https://example.com/portal/auth?' + 'param='.repeat(35) + 'padding';
    const result = analyzeUrl(longUrl);
    expect(result.urlLength).toBeGreaterThan(200);

    const lengthFactor = result.indicators.find((i) => i.factor === 'EXCESSIVE_URL_LENGTH');
    expect(lengthFactor).toBeDefined();
    expect(lengthFactor?.severity).toBe('LOW');
    expect(lengthFactor?.scoreImpact).toBe(10);
  });

  it('detects IP address literals as high severity indicators', () => {
    const ipUrl = 'http://192.168.1.50/login';
    const result = analyzeUrl(ipUrl);
    expect(result.isIpAddress).toBe(true);

    const ipFactor = result.indicators.find((i) => i.factor === 'IP_ADDRESS_HOSTNAME');
    expect(ipFactor).toBeDefined();
    expect(ipFactor?.severity).toBe('HIGH');
  });

  it('detects excessive subdomains, hyphens, and high entropy', () => {
    const multiSubdomainUrl = 'https://login.secure.portal.account.verification-service.net/verify';
    const result = analyzeUrl(multiSubdomainUrl);
    expect(result.subdomainCount).toBeGreaterThanOrEqual(3);

    const domainFactor = result.indicators.find((i) => i.factor === 'SUSPICIOUS_DOMAIN_STRUCTURE');
    expect(domainFactor).toBeDefined();
    expect(domainFactor?.severity).toBe('MEDIUM');
  });

  it('detects Punycode and internationalized homoglyph spoofing', () => {
    const punycodeUrl = 'https://xn--paypa-cra.com/signin';
    const result = analyzeUrl(punycodeUrl);
    expect(result.hasPunycodeOrHomograph).toBe(true);

    const punyFactor = result.indicators.find((i) => i.factor === 'HOMOGRAPH_PUNYCODE_SPOOF');
    expect(punyFactor).toBeDefined();
    expect(punyFactor?.severity).toBe('CRITICAL');
  });

  it('detects misleading brand patterns in subdomains', () => {
    const deceptiveBrandUrl = 'https://paypal.com.secure-payment-gateway.xyz/login';
    const result = analyzeUrl(deceptiveBrandUrl);
    expect(result.hasMisleadingBrandPattern).toBe(true);
    expect(result.detectedBrandInSubdomain).toBe('paypal');

    const brandFactor = result.indicators.find((i) => i.factor === 'MISLEADING_BRAND_SUBDOMAIN');
    expect(brandFactor).toBeDefined();
    expect(brandFactor?.severity).toBe('HIGH');
    expect(brandFactor?.evidence).toContain('paypal');
  });

  it('detects unusual URL encoding and embedded @ credentials trick', () => {
    const atUrl = 'https://legit-bank.com@evil-phishing-host.com/login';
    const result = analyzeUrl(atUrl);
    expect(result.hasUnusualEncoding).toBe(true);

    const atFactor = result.indicators.find((i) => i.factor === 'EMBEDDED_CREDENTIALS_TRICK');
    expect(atFactor).toBeDefined();
    expect(atFactor?.severity).toBe('HIGH');
  });

  it('detects excessive hex encoding (%xx)', () => {
    const hexUrl = 'https://suspicious.org/%2e%2e/%2f%2f%25test';
    const result = analyzeUrl(hexUrl);
    expect(result.hasUnusualEncoding).toBe(true);

    const hexFactor = result.indicators.find((i) => i.factor === 'SUSPICIOUS_HEX_ENCODING');
    expect(hexFactor).toBeDefined();
  });

  it('treats HTTP protocol as a low-severity signal, not automatic HIGH risk', () => {
    const plainHttpUrl = 'http://simple-blog.com/about';
    const result = analyzeUrl(plainHttpUrl);
    expect(result.isHttps).toBe(false);

    const httpFactor = result.indicators.find((i) => i.factor === 'INSECURE_HTTP_PROTOCOL');
    expect(httpFactor).toBeDefined();
    expect(httpFactor?.severity).toBe('LOW');
    // Score contribution alone should be low (e.g. 10 pts)
    expect(result.urlScoreContribution).toBe(10);
  });

  it('flags known threat intelligence matches with high severity', () => {
    const knownThreatUrl = 'https://evil-phish-bank.com/signin';
    const result = analyzeUrl(knownThreatUrl);
    expect(result.hasKnownThreatMatch).toBe(true);

    const threatFactor = result.indicators.find((i) => i.factor === 'KNOWN_THREAT_INTELLIGENCE_MATCH');
    expect(threatFactor).toBeDefined();
    expect(threatFactor?.severity).toBe('CRITICAL');
  });
});
