import { beforeEach, describe, expect, it } from 'vitest';
import {
  buildPermittedRemotePayload,
  clearRemoteCache,
  getCachedRemoteAssessment,
  setCachedRemoteAssessment,
  shouldTransmitRemotely,
} from '../src/shared/remote_policy';
import { BackendAnalyzeResponse, SecurityVerdict } from '../src/shared/types';
import { TOPOLOGICAL_FEATURE_NAMES } from '../src/shared/topological_extractor';

describe('Remote Transmission Policy & Privacy Enforcement', () => {
  beforeEach(() => {
    clearRemoteCache();
  });

  const createMockVerdict = (overrides: Partial<SecurityVerdict> = {}): SecurityVerdict => ({
    url: 'https://example.com/login',
    fqdn: 'example.com',
    scheme: 'https',
    riskScore: 5,
    riskTier: 'LOW',
    status: 'COMPLETE',
    primaryFactors: [],
    isInstitutional: false,
    recommendation: 'Site appears benign.',
    timestamp: Date.now(),
    latencyMs: 3.5,
    scanSource: 'local_heuristics',
    ...overrides,
  });

  it('prohibits remote transmission for standard benign websites', () => {
    const benignVerdict = createMockVerdict({
      url: 'https://example.com',
      fqdn: 'example.com',
      riskScore: 0,
      riskTier: 'LOW',
      primaryFactors: [],
    });

    const decision = shouldTransmitRemotely(benignVerdict, 'https://example.com', false);
    expect(decision.shouldTransmit).toBe(false);
    expect(decision.reason).toContain('Benign page score below threshold');
    expect(decision.payloadType).toBe('none');
  });

  it('prohibits remote transmission for institutional trusted domains', () => {
    const instVerdict = createMockVerdict({
      url: 'https://accounts.google.com/signin',
      fqdn: 'accounts.google.com',
      isInstitutional: true,
      riskScore: 10,
    });

    const decision = shouldTransmitRemotely(instVerdict, 'https://accounts.google.com/signin', false);
    expect(decision.shouldTransmit).toBe(false);
    expect(decision.reason).toContain('Verified institutional domain');
  });

  it('prohibits remote transmission for restricted browser internal pages', () => {
    const restrictedVerdict = createMockVerdict({
      url: 'chrome://settings',
      status: 'UNSUPPORTED_SCHEME',
      scheme: 'restricted',
    });

    for (const restrictedUrl of [
      'chrome://settings',
      'chrome-extension://abcdefghijklmnop',
      'edge://flags',
      'file:///C:/Users/User/Desktop/page.html',
      'about:blank',
      'view-source:https://example.com',
    ]) {
      const decision = shouldTransmitRemotely(restrictedVerdict, restrictedUrl, true);
      expect(decision.shouldTransmit).toBe(false);
      expect(decision.reason).toContain('Restricted browser page scheme');
    }
  });

  it('permits remote transmission when local heuristics detect elevated risk', () => {
    const suspiciousVerdict = createMockVerdict({
      url: 'http://192.168.1.1@suspicious-bank-login.xyz/auth',
      riskScore: 65,
      riskTier: 'HIGH',
      primaryFactors: [
        {
          id: 'url-ip-literal',
          category: 'URL',
          severity: 'HIGH',
          factor: 'IP_ADDRESS_LITERAL',
          scoreImpact: 35,
          description: 'Host is an IP literal',
          reason: 'Phishing attack',
        },
      ],
    });

    const decision = shouldTransmitRemotely(suspiciousVerdict, suspiciousVerdict.url, false);
    expect(decision.shouldTransmit).toBe(true);
    expect(decision.payloadType).toBe('features_only');
    expect(decision.reason).toContain('Local heuristics identified suspicious');
  });

  it('permits remote transmission when user explicitly clicks rescan button', () => {
    const benignVerdict = createMockVerdict({
      url: 'https://my-blog.com',
      riskScore: 5,
    });

    // Manual rescan = true
    const decision = shouldTransmitRemotely(benignVerdict, 'https://my-blog.com', true);
    expect(decision.shouldTransmit).toBe(true);
    expect(decision.reason).toContain('User explicitly requested scan');
  });

  it('suppresses duplicate remote requests when valid cache entry exists', () => {
    const testUrl = 'https://suspicious-site.xyz/portal';
    const suspiciousVerdict = createMockVerdict({
      url: testUrl,
      riskScore: 40,
      riskTier: 'MEDIUM',
    });

    // Initial check: should transmit
    const dec1 = shouldTransmitRemotely(suspiciousVerdict, testUrl, false);
    expect(dec1.shouldTransmit).toBe(true);

    // Save cached response
    const mockResponse: BackendAnalyzeResponse = {
      status: 'success',
      analysis_id: 'cache-test-1',
      timestamp_utc: new Date().toISOString(),
      ml_assessment: {
        model_available: true,
        model_version: '1.0.0',
        algorithm: 'PhishingLogisticClassifier',
        probability: 0.65,
        risk_score: 65,
        classification: 'HIGH',
        evidence: [],
        features_evaluated: 40,
        privacy_mode: 'topological_url_only',
      },
      scope_disclosure: {
        analyzes_page_content: false,
        server_side_fetching: false,
        target: 'URL and domain topological attributes only',
        privacy_mode: 'zero_pii',
      },
      processing_time_ms: 3.1,
    };
    setCachedRemoteAssessment(testUrl, mockResponse);

    // Subsequent automatic check: should suppress duplicate request
    const dec2 = shouldTransmitRemotely(suspiciousVerdict, testUrl, false);
    expect(dec2.shouldTransmit).toBe(false);
    expect(dec2.reason).toContain('Valid cached remote verdict exists');
    expect(getCachedRemoteAssessment(testUrl)).toEqual(mockResponse);
  });

  it('guarantees outgoing payload contains ONLY permitted topological features without sensitive data', () => {
    const dangerousUrl = 'https://target.com/login?session_token=secret_jwt_xyz&user_email=alice@bank.com#auth';
    const payload = buildPermittedRemotePayload(dangerousUrl);

    // 1. Must contain 'features' object
    expect(payload.features).toBeDefined();
    const features = payload.features!;

    // 2. Exactly 40 features
    expect(Object.keys(features)).toHaveLength(TOPOLOGICAL_FEATURE_NAMES.length);
    for (const feat of TOPOLOGICAL_FEATURE_NAMES) {
      expect(features).toHaveProperty(feat);
      expect(typeof features[feat]).toBe('number');
      expect(features[feat]).toBeGreaterThanOrEqual(0);
    }

    // 3. Absolute PII and Credential absence
    const payloadJson = JSON.stringify(payload);
    expect(payloadJson).not.toContain('secret_jwt_xyz');
    expect(payloadJson).not.toContain('alice@bank.com');
    expect(payloadJson).not.toContain('password');
    expect(payloadJson).not.toContain('session_token');
    expect(payloadJson).not.toContain('cookie');
    expect(payloadJson).not.toContain('input');
    expect(payloadJson).not.toContain('document');
  });
});
