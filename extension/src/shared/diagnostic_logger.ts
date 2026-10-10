/**
 * Development Diagnostic Logger for PhishGuard Extension
 *
 * Provides structured development-time diagnostic traces of the scanning pipeline.
 *
 * Privacy Guarantees:
 * - NEVER logs passwords, cookies, tokens, form values, or complete sensitive URLs.
 * - Sanitizes all URLs (protocol + host + pathname only; strips query params and fragments).
 * - Avoids persistent logging of browsing history (ephemeral console output only).
 */

import { SecurityVerdict, ThreatIndicator } from './types.js';
import { sanitizeUrl } from './utils.js';

export interface DiagnosticLogPayload {
  phase: 'POPUP_INIT' | 'SCAN_TRIGGERED' | 'DOM_HARVEST' | 'LOCAL_EVALUATION' | 'REMOTE_ML' | 'VERDICT_MERGE' | 'SCAN_INCOMPLETE' | 'ERROR';
  url?: string;
  tabId?: number;
  modulesExecuted?: string[];
  detectedSignals?: Array<{
    factor: string;
    category: string;
    severity: string;
    impact: number;
    description: string;
  }>;
  scoreBreakdown?: {
    rawScore: number;
    finalScore: number;
    tier: string;
    isInstitutional?: boolean;
    confidenceLevel?: string;
  };
  remoteStatus?: {
    requested: boolean;
    reason: string;
    success?: boolean;
    latencyMs?: number;
    mlRiskScore?: number | null;
  };
  errorReason?: string;
}

export function logDiagnostic(payload: DiagnosticLogPayload): void {
  // Ephemeral console diagnostic trace
  const sanitizedTarget = payload.url ? sanitizeUrl(payload.url) : 'N/A';
  const prefix = `[PhishGuard Diagnostic][${payload.phase}]`;

  console.groupCollapsed?.(`${prefix} Target: ${sanitizedTarget}`);

  if (payload.tabId !== undefined) {
    console.debug(`${prefix} Tab ID:`, payload.tabId);
  }

  if (payload.modulesExecuted && payload.modulesExecuted.length > 0) {
    console.debug(`${prefix} Modules executed:`, payload.modulesExecuted.join(', '));
  }

  if (payload.detectedSignals && payload.detectedSignals.length > 0) {
    console.debug(`${prefix} Detected signals (${payload.detectedSignals.length}):`, payload.detectedSignals);
  } else if (payload.modulesExecuted) {
    console.debug(`${prefix} Detected signals: None (Clean)`);
  }

  if (payload.scoreBreakdown) {
    console.debug(`${prefix} Score: ${payload.scoreBreakdown.finalScore}/100 (${payload.scoreBreakdown.tier})`, payload.scoreBreakdown);
  }

  if (payload.remoteStatus) {
    console.debug(`${prefix} Remote ML Backend:`, payload.remoteStatus);
  }

  if (payload.errorReason) {
    console.warn(`${prefix} Incomplete/Error cause:`, payload.errorReason);
  }

  console.groupEnd?.();
}

/**
 * Formats a SecurityVerdict into diagnostic indicator records.
 */
export function extractVerdictSignals(factors: ThreatIndicator[]) {
  return factors.map((f) => ({
    factor: f.factor,
    category: f.category,
    severity: f.severity,
    impact: f.scoreImpact,
    description: f.description,
  }));
}
