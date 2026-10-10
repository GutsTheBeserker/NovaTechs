/**
 * Phishing Classification Backend API Client
 *
 * Implements typed API contract with strict schema validation, request timeouts,
 * and resilient offline error handling.
 */

import {
  AnalyzeFeaturesPayload,
  BackendAnalyzeResponse,
  MLAssessment,
  MLFactorEvidence,
  ThreatSeverity,
} from './types.js';

export const DEFAULT_API_ENDPOINT = 'http://127.0.0.1:5000/api/v1/analyze';
export const DEFAULT_TIMEOUT_MS = 2500;

export interface ApiClientOptions {
  endpointUrl?: string;
  timeoutMs?: number;
  fetchFn?: typeof fetch;
}

export interface ValidationResult {
  valid: boolean;
  data?: BackendAnalyzeResponse;
  error?: string;
}

const VALID_CLASSIFICATIONS = new Set(['LOW', 'MEDIUM', 'HIGH', 'UNAVAILABLE', 'ERROR']);
const VALID_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);

/**
 * Validates backend analysis response structure and bounds before client consumption.
 */
export function validateBackendAnalyzeResponse(data: unknown): ValidationResult {
  if (!data || typeof data !== 'object') {
    return { valid: false, error: 'Response must be a non-null object' };
  }

  const res = data as Partial<BackendAnalyzeResponse>;

  if (res.status !== 'success' && res.status !== 'degraded') {
    return { valid: false, error: `Invalid status '${String(res.status)}'` };
  }

  if (!res.ml_assessment || typeof res.ml_assessment !== 'object') {
    return { valid: false, error: 'Missing or invalid ml_assessment object' };
  }

  const ml = res.ml_assessment as Partial<MLAssessment>;

  if (typeof ml.model_available !== 'boolean') {
    return { valid: false, error: 'ml_assessment.model_available must be a boolean' };
  }

  // If model is available, validate score bounds and classifications
  if (ml.model_available) {
    if (typeof ml.risk_score !== 'number' || isNaN(ml.risk_score)) {
      return { valid: false, error: 'ml_assessment.risk_score must be a number' };
    }
    if (ml.risk_score < 0 || ml.risk_score > 100) {
      return { valid: false, error: `ml_assessment.risk_score out of bounds (0-100): ${ml.risk_score}` };
    }

    if (typeof ml.probability !== 'number' || isNaN(ml.probability)) {
      return { valid: false, error: 'ml_assessment.probability must be a number' };
    }
    if (ml.probability < 0.0 || ml.probability > 1.0) {
      return { valid: false, error: `ml_assessment.probability out of range (0.0-1.0): ${ml.probability}` };
    }

    if (!ml.classification || !VALID_CLASSIFICATIONS.has(ml.classification)) {
      return { valid: false, error: `Invalid classification: ${String(ml.classification)}` };
    }

    if (!Array.isArray(ml.evidence)) {
      return { valid: false, error: 'ml_assessment.evidence must be an array' };
    }

    for (let i = 0; i < ml.evidence.length; i++) {
      const item = ml.evidence[i] as Partial<MLFactorEvidence>;
      if (!item || typeof item !== 'object') {
        return { valid: false, error: `Evidence item [${i}] is not an object` };
      }
      if (typeof item.name !== 'string' || !item.name.trim()) {
        return { valid: false, error: `Evidence item [${i}] missing valid name` };
      }
      if (item.severity && !VALID_SEVERITIES.has(item.severity)) {
        return { valid: false, error: `Evidence item [${i}] invalid severity '${item.severity}'` };
      }
    }
  }

  return { valid: true, data: res as BackendAnalyzeResponse };
}

/**
 * Transmits permitted features to the Python classification backend.
 * Never throws unhandled exceptions; returns null on error/timeout.
 */
export async function analyzeRemotely(
  payload: AnalyzeFeaturesPayload,
  options: ApiClientOptions = {}
): Promise<BackendAnalyzeResponse | null> {
  const endpoint = options.endpointUrl || DEFAULT_API_ENDPOINT;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const fetchImpl = options.fetchFn || (typeof fetch !== 'undefined' ? fetch : undefined);

  if (!fetchImpl) {
    console.warn('[PhishGuard] Fetch API is not available in current environment');
    return null;
  }

  // Ensure payload contains valid data
  if (!payload.features && !payload.url) {
    console.warn('[PhishGuard] Aborted remote analysis: empty payload');
    return null;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort();
  }, timeoutMs);

  try {
    const response = await fetchImpl(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.warn(`[PhishGuard] Backend responded with HTTP status ${response.status}`);
      return null;
    }

    const jsonData = await response.json();
    const validation = validateBackendAnalyzeResponse(jsonData);

    if (!validation.valid || !validation.data) {
      console.warn('[PhishGuard] Backend response rejected by schema validator:', validation.error);
      return null;
    }

    return validation.data;
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    if (err instanceof Error && err.name === 'AbortError') {
      console.warn(`[PhishGuard] Remote analysis request timed out after ${timeoutMs}ms`);
    } else {
      console.warn('[PhishGuard] Remote analysis connection failed (offline or unreachable):', err);
    }
    return null;
  }
}
