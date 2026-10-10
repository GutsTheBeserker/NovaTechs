/**
 * Remote Transmission Policy & Privacy Enforcement Engine
 *
 * Enforces the strict privacy rules governing when and what data
 * is permitted to be transmitted to the remote ML classification service.
 *
 * Core Privacy Guarantees:
 * 1. Zero benign browsing history is sent remotely.
 * 2. Institutional pages are never sent remotely.
 * 3. Restricted pages (chrome://, file://, etc.) are never sent remotely.
 * 4. Only permitted numerical topological features are transmitted when justified.
 * 5. Zero form values, passwords, cookies, tokens, or DOM HTML are ever sent.
 * 6. In-flight coalescing and TTL caching prevent request storms and duplicates.
 */

import { AnalyzeFeaturesPayload, BackendAnalyzeResponse, SecurityVerdict } from './types.js';
import { extractTopologicalFeatures } from './topological_extractor.js';
import { isRestrictedScheme } from './validators.js';

export interface RemoteDecision {
  shouldTransmit: boolean;
  reason: string;
  payloadType: 'features_only' | 'none';
}

export const REMOTE_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes cache TTL

interface CacheEntry {
  timestamp: number;
  response: BackendAnalyzeResponse;
}

// In-memory cache for remote analysis responses to prevent request storms
const remoteResponseCache = new Map<string, CacheEntry>();

/**
 * Generates a stable cache key based on hostname and path without query strings.
 */
export function getSanitizedCacheKey(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`.toLowerCase();
  } catch {
    return rawUrl.split('?')[0].split('#')[0].toLowerCase();
  }
}

/**
 * Checks if local verdict contains suspicious security indicators warranting remote validation.
 */
function hasSuspiciousSignals(verdict: SecurityVerdict): boolean {
  if (verdict.riskScore >= 20) return true;
  if (verdict.riskTier === 'HIGH' || verdict.riskTier === 'MEDIUM') return true;

  return verdict.primaryFactors.some((factor) =>
    factor.severity === 'CRITICAL' ||
    factor.severity === 'HIGH' ||
    factor.category === 'URL' ||
    factor.category === 'BRAND' ||
    factor.category === 'PAYMENT'
  );
}

/**
 * Evaluates whether remote analysis is justified according to strict privacy constraints.
 */
export function shouldTransmitRemotely(
  localVerdict: SecurityVerdict,
  rawUrl: string,
  isManualRescan: boolean = false
): RemoteDecision {
  // 1. Restricted browser pages are never transmitted
  if (!rawUrl || isRestrictedScheme(rawUrl)) {
    return {
      shouldTransmit: false,
      reason: 'Restricted browser page scheme - external transmission prohibited',
      payloadType: 'none',
    };
  }

  // 2. Institutional trusted domains are never transmitted
  if (localVerdict.isInstitutional) {
    return {
      shouldTransmit: false,
      reason: 'Verified institutional domain - benign by definition, remote analysis omitted',
      payloadType: 'none',
    };
  }

  // 3. Prevent duplicate requests: check cache
  const cacheKey = getSanitizedCacheKey(rawUrl);
  const cached = remoteResponseCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < REMOTE_CACHE_TTL_MS && !isManualRescan) {
    return {
      shouldTransmit: false,
      reason: 'Valid cached remote verdict exists - duplicate scan suppressed',
      payloadType: 'none',
    };
  }

  // 4. Manual rescan explicitly requested by user in popup
  if (isManualRescan) {
    return {
      shouldTransmit: true,
      reason: 'User explicitly requested scan via popup control',
      payloadType: 'features_only',
    };
  }

  // 5. Automatic passive scanning: Only transmit if local heuristics detect ambiguous or elevated risk
  if (hasSuspiciousSignals(localVerdict)) {
    return {
      shouldTransmit: true,
      reason: 'Local heuristics identified suspicious or ambiguous signals warranting ML verification',
      payloadType: 'features_only',
    };
  }

  // 6. Default: Benign browsing traffic is never transmitted remotely
  return {
    shouldTransmit: false,
    reason: 'Benign page score below threshold - remote analysis not justified',
    payloadType: 'none',
  };
}

/**
 * Builds the permitted remote payload containing ONLY the 40 numerical features.
 * Guarantees zero sensitive form values, passwords, cookies, or full URLs.
 */
export function buildPermittedRemotePayload(rawUrl: string): AnalyzeFeaturesPayload {
  const topologicalFeatures = extractTopologicalFeatures(rawUrl);

  return {
    features: topologicalFeatures,
  };
}

export function getCachedRemoteAssessment(rawUrl: string): BackendAnalyzeResponse | null {
  const key = getSanitizedCacheKey(rawUrl);
  const entry = remoteResponseCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > REMOTE_CACHE_TTL_MS) {
    remoteResponseCache.delete(key);
    return null;
  }
  return entry.response;
}

export function setCachedRemoteAssessment(rawUrl: string, response: BackendAnalyzeResponse): void {
  const key = getSanitizedCacheKey(rawUrl);
  remoteResponseCache.set(key, {
    timestamp: Date.now(),
    response,
  });
}

export function clearRemoteCache(): void {
  remoteResponseCache.clear();
}
