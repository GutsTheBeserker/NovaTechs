import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  coordinateSecurityAnalysis,
  mergeVerdictWithMLAssessment,
  tabVerdicts,
} from '../src/background/index';
import { clearRemoteCache } from '../src/shared/remote_policy';
import { BackendAnalyzeResponse, SecurityVerdict } from '../src/shared/types';

describe('Background Service Worker Integration with Remote API', () => {
  beforeEach(() => {
    tabVerdicts.clear();
    clearRemoteCache();
  });

  const mockValidBackendResponse: BackendAnalyzeResponse = {
    status: 'success',
    analysis_id: 'integration-test-uuid',
    timestamp_utc: new Date().toISOString(),
    ml_assessment: {
      model_available: true,
      model_version: '1.0.0',
      algorithm: 'PhishingLogisticClassifier',
      probability: 0.92,
      risk_score: 92,
      classification: 'HIGH',
      evidence: [
        {
          feature: 'qty_at_url',
          name: 'Credential Obfuscation Character (@)',
          value: 1,
          severity: 'HIGH',
          importance_weight: 13.98,
          description: 'Obfuscated destination',
        },
      ],
      features_evaluated: 40,
      privacy_mode: 'topological_url_only',
      scope: {
        analyzes_page_content: false,
        server_side_fetching: false,
        analysis_target: 'URL and domain topological attributes only',
      },
    },
    scope_disclosure: {
      analyzes_page_content: false,
      server_side_fetching: false,
      target: 'URL and domain topological attributes only',
      privacy_mode: 'zero_pii_no_server_browsing',
    },
    processing_time_ms: 2.1,
  };

  it('performs local evaluation first and upgrades to server-assisted when justified', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockValidBackendResponse,
    });

    const suspiciousUrl = 'http://192.168.1.1@security-check.example.com/login';
    const tabId = 101;

    const verdict = await coordinateSecurityAnalysis(
      tabId,
      suspiciousUrl,
      null,
      false,
      'test-scan-1',
      { fetchFn: mockFetch as unknown as typeof fetch }
    );

    expect(verdict).toBeDefined();
    expect(verdict.scanSource).toBe('server_assisted');
    expect(verdict.mlAssessment).toBeDefined();
    expect(verdict.mlAssessment?.risk_score).toBe(92);
    expect(verdict.compositeBreakdown).toBeDefined();
    expect(verdict.compositeBreakdown?.mlScore).toBe(92);

    // Verify ML evidence factors merged cleanly
    const hasMlFactor = verdict.primaryFactors.some((f) => f.id === 'ml-qty_at_url');
    expect(hasMlFactor).toBe(true);

    // Verify stored in tabVerdicts
    expect(tabVerdicts.get(tabId)).toEqual(verdict);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('does NOT make remote request for benign page, returning local verdict', async () => {
    const mockFetch = vi.fn();
    const benignUrl = 'https://example.com';
    const tabId = 102;

    const verdict = await coordinateSecurityAnalysis(
      tabId,
      benignUrl,
      null,
      false,
      'test-scan-2',
      { fetchFn: mockFetch as unknown as typeof fetch }
    );

    expect(verdict.scanSource).toBe('local_heuristics');
    expect(verdict.riskScore).toBeLessThan(20);
    expect(verdict.offlineFallback).toBeFalsy();
    // Zero network calls made for benign traffic!
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('handles offline backend gracefully with local fallback verdict', async () => {
    const mockOfflineFetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    const suspiciousUrl = 'http://192.168.1.1/login';
    const tabId = 103;

    const verdict = await coordinateSecurityAnalysis(
      tabId,
      suspiciousUrl,
      null,
      true, // manual rescan
      'test-scan-3',
      { fetchFn: mockOfflineFetch as unknown as typeof fetch }
    );

    expect(verdict).toBeDefined();
    // Preserved local heuristics without error
    expect(verdict.scanSource).toBe('local_heuristics');
    expect(verdict.offlineFallback).toBe(true);
    expect(verdict.riskScore).toBeGreaterThanOrEqual(0);
  });

  it('coalesces multiple concurrent in-flight requests into a single network call', async () => {
    let resolveFetch: (val: unknown) => void;
    const pendingPromise = new Promise((resolve) => {
      resolveFetch = resolve;
    });

    const mockFetch = vi.fn().mockImplementation(() => pendingPromise);
    const testUrl = 'http://phishing-site-test.xyz/verify';

    // Fire two concurrent analyses for different tabs on the same URL
    const p1 = coordinateSecurityAnalysis(201, testUrl, null, true, 'scan-1', {
      fetchFn: mockFetch as unknown as typeof fetch,
    });
    const p2 = coordinateSecurityAnalysis(202, testUrl, null, true, 'scan-2', {
      fetchFn: mockFetch as unknown as typeof fetch,
    });

    // Resolve the single network call
    resolveFetch!({
      ok: true,
      status: 200,
      json: async () => mockValidBackendResponse,
    });

    const [v1, v2] = await Promise.all([p1, p2]);

    expect(v1.scanSource).toBe('server_assisted');
    expect(v2.scanSource).toBe('server_assisted');
    // Only 1 network fetch executed despite 2 concurrent tabs!
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('correctly calculates weighted composite scores in mergeVerdictWithMLAssessment', () => {
    const localVerdict: SecurityVerdict = {
      url: 'https://test.com',
      fqdn: 'test.com',
      scheme: 'https',
      riskScore: 50,
      riskTier: 'MEDIUM',
      status: 'COMPLETE',
      primaryFactors: [],
      isInstitutional: false,
      recommendation: 'Check URL',
      timestamp: Date.now(),
      latencyMs: 5,
      scanSource: 'local_heuristics',
    };

    // ML Score = 90
    // Expected composite: round(0.6 * 50 + 0.4 * 90) = round(30 + 36) = 66 -> HIGH
    const merged = mergeVerdictWithMLAssessment(localVerdict, mockValidBackendResponse);
    expect(merged.riskScore).toBe(Math.round(0.6 * 50 + 0.4 * 92)); // 30 + 36.8 = 67
    expect(merged.riskTier).toBe('HIGH');
    expect(merged.compositeBreakdown?.ruleScore).toBe(50);
    expect(merged.compositeBreakdown?.mlScore).toBe(92);
  });
});
