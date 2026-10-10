/**
 * Adaptive Website Trust Profiles Engine
 *
 * Implements privacy-preserving, strictly local behavioral baselining for visited domains.
 * Detects anomalous behavioral drift (e.g., sudden credential prompts on non-login domains,
 * unauthorized form action redirects, foreign iframe inclusions).
 *
 * Privacy & Security Guarantees:
 * - 100% LOCAL storage via chrome.storage.local. Profiles are NEVER sent remotely.
 * - Minimal summary only: domain name, observation count, known form origins, boolean flags.
 * - Anti-Poisoning Protection: Profiles are NEVER established or updated from high-risk,
 *   unverified, or suspicious visits (risk score >= 25 or high/critical indicators).
 * - Minimum 3 observations required before baseline is established.
 * - User-facing controls to view, inspect, and wipe profiles.
 */

import {
  DOMFeatureVector,
  DomainSecuritySummary,
  ThreatIndicator,
  TrustProfileDriftResult,
} from './types.js';
import { extractBaseDomain } from './utils.js';

export const MIN_OBSERVATIONS_FOR_BASELINE = 3;
export const MAX_SAFE_RISK_FOR_BASELINE = 25;
const STORAGE_KEY = 'phishguard_trust_profiles';
const MAX_PROFILES_CAP = 500;

// In-memory fallback cache for fast lookups and unit testing
let inMemoryCache: Record<string, DomainSecuritySummary> = {};
let isStorageLoaded = false;

/**
 * Helper to safely get storage API or fallback to in-memory store.
 */
async function loadStorage(): Promise<Record<string, DomainSecuritySummary>> {
  if (isStorageLoaded) return inMemoryCache;

  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    try {
      const data = await chrome.storage.local.get(STORAGE_KEY);
      inMemoryCache = (data && data[STORAGE_KEY]) || {};
      isStorageLoaded = true;
      return inMemoryCache;
    } catch {
      // In-memory fallback
      return inMemoryCache;
    }
  }

  isStorageLoaded = true;
  return inMemoryCache;
}

async function persistStorage(): Promise<void> {
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    try {
      await chrome.storage.local.set({ [STORAGE_KEY]: inMemoryCache });
    } catch {
      // Ignore storage persistence failure
    }
  }
}

/**
 * Retrieves the trust profile for a given domain, if one exists.
 */
export async function getDomainTrustProfile(domain: string): Promise<DomainSecuritySummary | null> {
  const baseDomain = extractBaseDomain(domain).toLowerCase();
  if (!baseDomain) return null;

  const profiles = await loadStorage();
  return profiles[baseDomain] || null;
}

/**
 * Retrieves all stored domain trust profiles.
 */
export async function getAllTrustProfiles(): Promise<Record<string, DomainSecuritySummary>> {
  return { ...(await loadStorage()) };
}

/**
 * Completely clears all stored trust profiles.
 */
export async function clearAllTrustProfiles(): Promise<void> {
  inMemoryCache = {};
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    try {
      await chrome.storage.local.remove(STORAGE_KEY);
    } catch {
      // Ignore
    }
  }
}

/**
 * Removes a specific domain trust profile.
 */
export async function removeDomainTrustProfile(domain: string): Promise<void> {
  const baseDomain = extractBaseDomain(domain).toLowerCase();
  const profiles = await loadStorage();
  if (profiles[baseDomain]) {
    delete profiles[baseDomain];
    await persistStorage();
  }
}

/**
 * Evaluates whether current DOM behavior constitutes an anomalous drift
 * from an established domain baseline.
 */
export async function detectTrustProfileDrift(
  domain: string,
  domFeatures: DOMFeatureVector
): Promise<TrustProfileDriftResult> {
  const baseDomain = extractBaseDomain(domain).toLowerCase();
  const profile = await getDomainTrustProfile(baseDomain);

  // If no established baseline exists yet (< 3 visits or unprofiled), no drift can be claimed
  if (!profile || !profile.baselineEstablished) {
    return {
      domain: baseDomain,
      hasDrift: false,
      driftDetails: [],
      indicators: [],
      observationCount: profile ? profile.observationCount : 0,
      baselineEstablished: false,
    };
  }

  const driftDetails: string[] = [];
  const indicators: ThreatIndicator[] = [];

  // 1. Sudden credential requests on non-login domains
  // If baseline never had password fields across multiple visits, but suddenly presents one
  if (!profile.hasBaselinePasswordFields && domFeatures.numPasswordFields > 0) {
    const detail = `Domain historically never asked for passwords, but is currently requesting credentials (${domFeatures.numPasswordFields} password fields).`;
    driftDetails.push(detail);
    indicators.push({
      id: 'drift-sudden-credential-prompt',
      category: 'BEHAVIORAL',
      severity: 'HIGH',
      factor: 'UNEXPECTED_CREDENTIAL_SOLICITATION',
      scoreImpact: 30,
      description: 'Domain suddenly solicit credentials contrary to its established safe baseline.',
      reason: 'Compromised websites or spoofed lookalikes often insert credential harvesters on pages that normally require no authentication.',
      evidence: detail,
    });
  }

  // 2. Unexpected Cross-Domain Form Action Destinations
  // If the page has cross-domain forms and they target origins not in the established baseline
  const hasCrossDomainForms = Boolean(
    (domFeatures.crossDomainFormActions && domFeatures.crossDomainFormActions > 0) ||
      domFeatures.crossOriginFormAction
  );
  if (hasCrossDomainForms && domFeatures.formActionDomains) {
    const newFormOrigins = domFeatures.formActionDomains.filter(
      (dest) => !profile.knownFormActionOrigins.includes(dest.toLowerCase())
    );

    if (newFormOrigins.length > 0) {
      const detail = `Form submission destination has drifted to previously unobserved external origins: ${newFormOrigins.join(', ')}`;
      driftDetails.push(detail);
      indicators.push({
        id: 'drift-unexpected-form-destination',
        category: 'BEHAVIORAL',
        severity: 'HIGH',
        factor: 'UNEXPECTED_FORM_ACTION_DRIFT',
        scoreImpact: 25,
        description: 'Forms submit data to previously unobserved external destinations.',
        reason: 'Form action hijacking or malicious scripts can alter form submission targets to siphon user inputs.',
        evidence: detail,
      });
    }
  }

  // 3. Sudden influx of unobserved cross-origin iframes
  if (domFeatures.iframeOrigins && domFeatures.iframeOrigins.length > 0) {
    const newIframeOrigins = domFeatures.iframeOrigins.filter(
      (ifr) => !profile.knownIframeOrigins.includes(ifr.toLowerCase())
    );

    if (newIframeOrigins.length > 0 && domFeatures.suspiciousIframeCount > 0) {
      const detail = `Unobserved external iframe origins appeared: ${newIframeOrigins.slice(0, 3).join(', ')}`;
      driftDetails.push(detail);
      indicators.push({
        id: 'drift-unexpected-iframe-overlay',
        category: 'BEHAVIORAL',
        severity: 'MEDIUM',
        factor: 'UNEXPECTED_IFRAME_INFLUX',
        scoreImpact: 15,
        description: 'New cross-origin iframes appeared that deviate from the normal baseline.',
        reason: 'Sudden introduction of cross-domain iframes on familiar sites may indicate clickjacking or malicious advertising injections.',
        evidence: detail,
      });
    }
  }

  return {
    domain: baseDomain,
    hasDrift: indicators.length > 0,
    driftDetails,
    indicators,
    observationCount: profile.observationCount,
    baselineEstablished: true,
  };
}

/**
 * Records a page observation and updates the local domain trust profile,
 * enforcing strict anti-poisoning safeguards.
 */
export async function recordDomainObservation(
  domain: string,
  domFeatures: DOMFeatureVector,
  riskScore: number,
  hasHighRiskIndicators: boolean
): Promise<DomainSecuritySummary | null> {
  const baseDomain = extractBaseDomain(domain).toLowerCase();
  if (!baseDomain) return null;

  // Anti-Poisoning Safeguard:
  // If the page is high-risk or presents significant threat indicators,
  // DO NOT record or establish a trusted baseline!
  if (riskScore >= MAX_SAFE_RISK_FOR_BASELINE || hasHighRiskIndicators) {
    return null;
  }

  const profiles = await loadStorage();
  const now = Date.now();

  let profile = profiles[baseDomain];
  if (!profile) {
    // Evict oldest if cap exceeded
    const keys = Object.keys(profiles);
    if (keys.length >= MAX_PROFILES_CAP) {
      let oldestKey = keys[0];
      let oldestTime = Infinity;
      for (const k of keys) {
        if (profiles[k].lastSeen < oldestTime) {
          oldestTime = profiles[k].lastSeen;
          oldestKey = k;
        }
      }
      delete profiles[oldestKey];
    }

    profile = {
      domain: baseDomain,
      observationCount: 1,
      firstSeen: now,
      lastSeen: now,
      baselineEstablished: false,
      knownFormActionOrigins: [],
      knownScriptDomains: [],
      knownIframeOrigins: [],
      hasBaselinePasswordFields: domFeatures.numPasswordFields > 0,
      typicalRedirectHops: 0,
    };
  } else {
    profile.observationCount += 1;
    profile.lastSeen = now;

    // Establish baseline once observation threshold is met
    if (profile.observationCount >= MIN_OBSERVATIONS_FOR_BASELINE) {
      profile.baselineEstablished = true;
    }

    if (domFeatures.numPasswordFields > 0) {
      profile.hasBaselinePasswordFields = true;
    }
  }

  // Update known origins safely
  if (domFeatures.formActionDomains) {
    for (const dest of domFeatures.formActionDomains) {
      const lower = dest.toLowerCase();
      if (!profile.knownFormActionOrigins.includes(lower)) {
        profile.knownFormActionOrigins.push(lower);
      }
    }
  }

  if (domFeatures.scriptOrigins) {
    for (const scr of domFeatures.scriptOrigins) {
      const lower = scr.toLowerCase();
      if (!profile.knownScriptDomains.includes(lower)) {
        profile.knownScriptDomains.push(lower);
      }
    }
  }

  if (domFeatures.iframeOrigins) {
    for (const ifr of domFeatures.iframeOrigins) {
      const lower = ifr.toLowerCase();
      if (!profile.knownIframeOrigins.includes(lower)) {
        profile.knownIframeOrigins.push(lower);
      }
    }
  }

  profiles[baseDomain] = profile;
  await persistStorage();
  return profile;
}
