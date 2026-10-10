import { describe, expect, it, vi } from 'vitest';
import {
  analyzeRemotely,
  DEFAULT_TIMEOUT_MS,
  validateBackendAnalyzeResponse,
} from '../src/shared/api_client';
import { BackendAnalyzeResponse } from '../src/shared/types';

describe('Backend API Client & Schema Validator', () => {
  const validBackendResponse: BackendAnalyzeResponse = {
    status: 'success',
    analysis_id: 'test-uuid-1234',
    timestamp_utc: '2026-10-10T06:00:00Z',
    ml_assessment: {
      model_available: true,
      model_version: '1.0.0',
      algorithm: 'PhishingLogisticClassifier',
      probability: 0.885,
      risk_score: 89,
      classification: 'HIGH',
      evidence: [
        {
          feature: 'qty_at_url',
          name: 'Credential Obfuscation Character (@)',
          value: 1,
          severity: 'HIGH',
          importance_weight: 13.98,
          description: 'The @ character is used to obscure destination host.',
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
    processing_time_ms: 2.5,
  };

  it('validates and accepts a conformant backend response', () => {
    const result = validateBackendAnalyzeResponse(validBackendResponse);
    expect(result.valid).toBe(true);
    expect(result.data).toBeDefined();
    expect(result.data?.ml_assessment.risk_score).toBe(89);
    expect(result.data?.ml_assessment.classification).toBe('HIGH');
  });

  it('rejects malformed responses missing required fields', () => {
    const missingMl = { status: 'success', analysis_id: '123' };
    const res1 = validateBackendAnalyzeResponse(missingMl);
    expect(res1.valid).toBe(false);
    expect(res1.error).toContain('ml_assessment');

    const nonObject = null;
    const res2 = validateBackendAnalyzeResponse(nonObject);
    expect(res2.valid).toBe(false);
  });

  it('rejects responses with out-of-bounds risk scores', () => {
    const invalidScore = JSON.parse(JSON.stringify(validBackendResponse));
    invalidScore.ml_assessment.risk_score = 150; // Max allowed is 100
    const res = validateBackendAnalyzeResponse(invalidScore);
    expect(res.valid).toBe(false);
    expect(res.error).toContain('risk_score out of bounds');

    invalidScore.ml_assessment.risk_score = -5;
    const resNegative = validateBackendAnalyzeResponse(invalidScore);
    expect(resNegative.valid).toBe(false);
  });

  it('rejects responses with invalid probability ranges', () => {
    const invalidProb = JSON.parse(JSON.stringify(validBackendResponse));
    invalidProb.ml_assessment.probability = 1.5; // Max allowed is 1.0
    const res = validateBackendAnalyzeResponse(invalidProb);
    expect(res.valid).toBe(false);
    expect(res.error).toContain('probability out of range');
  });

  it('rejects responses with unrecognized classification labels', () => {
    const badTier = JSON.parse(JSON.stringify(validBackendResponse));
    badTier.ml_assessment.classification = 'EXTREME_DANGER'; // Invalid enum
    const res = validateBackendAnalyzeResponse(badTier);
    expect(res.valid).toBe(false);
    expect(res.error).toContain('Invalid classification');
  });

  it('successfully executes remote analysis with mocked fetch', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => validBackendResponse,
    });

    const response = await analyzeRemotely(
      { features: { length_url: 45, qty_dot_url: 2 } },
      { fetchFn: mockFetch as unknown as typeof fetch }
    );

    expect(response).toBeDefined();
    expect(response?.status).toBe('success');
    expect(response?.ml_assessment.risk_score).toBe(89);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('handles backend timeout safely without unhandled rejection', async () => {
    // Simulate slow network that triggers abort
    const mockSlowFetch = vi.fn().mockImplementation((_url, options) => {
      return new Promise((_resolve, reject) => {
        options.signal.addEventListener('abort', () => {
          const err = new Error('The operation was aborted');
          err.name = 'AbortError';
          reject(err);
        });
      });
    });

    const response = await analyzeRemotely(
      { features: { length_url: 45 } },
      { timeoutMs: 50, fetchFn: mockSlowFetch as unknown as typeof fetch }
    );

    expect(response).toBeNull(); // Clean graceful fallback
  });

  it('handles offline backend (connection error) gracefully', async () => {
    const mockOfflineFetch = vi.fn().mockRejectedValue(new Error('Failed to fetch (ECONNREFUSED)'));

    const response = await analyzeRemotely(
      { features: { length_url: 45 } },
      { fetchFn: mockOfflineFetch as unknown as typeof fetch }
    );

    expect(response).toBeNull();
  });

  it('handles HTTP error status codes (e.g. 500, 429) gracefully', async () => {
    const mock500Fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({ error: 'Internal Server Error' }),
    });

    const response = await analyzeRemotely(
      { features: { length_url: 45 } },
      { fetchFn: mock500Fetch as unknown as typeof fetch }
    );

    expect(response).toBeNull();
  });
});
