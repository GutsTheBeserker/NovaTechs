/**
 * Message schema and URL protocol validation utilities.
 *
 * Ensures that incoming runtime messages and active URLs strictly adhere
 * to expected type contracts before processing, protecting against crashes
 * and injection of malformed data structures.
 */

import { DOMFeatureVector, ExtensionMessage } from './types.js';
import { RESTRICTED_SCHEMES } from './constants.js';

/**
 * Checks whether a URL is restricted from extension script injection.
 */
export function isRestrictedScheme(url: string): boolean {
  if (!url || typeof url !== 'string') return true;
  try {
    const parsed = new URL(url);
    return RESTRICTED_SCHEMES.has(parsed.protocol);
  } catch {
    return true;
  }
}

/**
 * Checks whether a URL runs on supported HTTP or HTTPS protocols.
 */
export function isSupportedUrl(url: string): boolean {
  if (!url || typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Validates a DOMFeatureVector object structure.
 */
export function isDOMFeatureVector(obj: unknown): obj is DOMFeatureVector {
  if (!obj || typeof obj !== 'object') return false;
  const v = obj as Record<string, unknown>;

  return (
    typeof v.numForms === 'number' &&
    typeof v.numPasswordFields === 'number' &&
    typeof v.crossOriginFormAction === 'boolean' &&
    typeof v.insecureFormAction === 'boolean' &&
    typeof v.externalResourceRatio === 'number' &&
    typeof v.brandMismatchDetected === 'boolean' &&
    typeof v.hiddenIframeCount === 'number' &&
    typeof v.title === 'string' &&
    typeof v.origin === 'string' &&
    Array.isArray(v.formActionDomains)
  );
}

/**
 * Validates runtime ExtensionMessage payloads against expected schemas.
 */
export function validateExtensionMessage(
  raw: unknown
): { valid: boolean; message?: ExtensionMessage; error?: string } {
  if (!raw || typeof raw !== 'object') {
    return { valid: false, error: 'Message must be a non-null object' };
  }

  const msg = raw as Record<string, unknown>;
  const validTypes = [
    'DOM_FEATURES_EXTRACTED',
    'GET_SECURITY_VERDICT',
    'TRIGGER_RESCAN',
    'RESCAN_DOM_REQUEST',
    'SECURITY_VERDICT_RESPONSE',
    'OPEN_WARNING_PAGE',
    'CLEAR_TRUST_PROFILES',
    'GET_TRUST_PROFILE',
  ];

  if (typeof msg.type !== 'string' || !validTypes.includes(msg.type)) {
    return { valid: false, error: `Invalid or unrecognized message type: "${msg.type}"` };
  }

  // Type-specific schema assertions
  if (msg.type === 'DOM_FEATURES_EXTRACTED') {
    if (!isDOMFeatureVector(msg.payload)) {
      return { valid: false, error: 'Invalid DOMFeatureVector payload' };
    }
  }

  if (msg.type === 'OPEN_WARNING_PAGE') {
    const p = msg.payload as Record<string, unknown> | undefined;
    if (!p || typeof p.url !== 'string' || typeof p.riskScore !== 'number') {
      return { valid: false, error: 'Invalid OPEN_WARNING_PAGE payload' };
    }
  }

  if (msg.type === 'GET_TRUST_PROFILE') {
    if (typeof msg.domain !== 'string') {
      return { valid: false, error: 'Invalid GET_TRUST_PROFILE payload: domain must be a string' };
    }
  }

  return { valid: true, message: raw as ExtensionMessage };
}
