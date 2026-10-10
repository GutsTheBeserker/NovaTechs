/**
 * Navigation & Redirect Tracker
 *
 * Listens to Chrome webNavigation events to track minimum required navigation metadata
 * per tab, identifying suspicious multi-step redirects, origin hopping, and protocol downgrades.
 *
 * Privacy Guarantees:
 * - Minimum metadata tracked (origins and redirect counts).
 * - Zero long-term browsing history stored (in-memory per active tab only, 60s TTL).
 * - Never visits suspicious destinations automatically.
 */

import { NavigationStep, TabNavigationRecord, ThreatIndicator } from './types.js';
import { extractBaseDomain } from './utils.js';
import { isRestrictedScheme } from './validators.js';

const NAVIGATION_TTL_MS = 60 * 1000; // 60 seconds TTL

// Active in-memory navigation tracking records per tab ID
const tabNavigations = new Map<number, TabNavigationRecord>();

function getOrigin(urlStr: string): string {
  try {
    return new URL(urlStr).origin.toLowerCase();
  } catch {
    return urlStr.split('/')[0].toLowerCase();
  }
}

/**
 * Initiates or updates navigation tracking for a tab.
 */
export function recordNavigationStart(
  tabId: number,
  rawUrl: string,
  transitionType: string = 'link'
): TabNavigationRecord | null {
  if (isRestrictedScheme(rawUrl)) {
    tabNavigations.delete(tabId);
    return null;
  }

  const now = Date.now();
  const origin = getOrigin(rawUrl);

  const initialStep: NavigationStep = {
    url: rawUrl,
    origin,
    timestamp: now,
    transitionType,
    isRedirect: false,
  };

  const record: TabNavigationRecord = {
    tabId,
    initialUrl: rawUrl,
    initialOrigin: origin,
    finalUrl: rawUrl,
    finalOrigin: origin,
    steps: [initialStep],
    redirectCount: 0,
    hasOriginHop: false,
    hasCrossDomainHop: false,
    hasProtocolDowngrade: false,
    hasSuspiciousChain: false,
    durationMs: 0,
    isComplete: false,
    indicators: [],
  };

  tabNavigations.set(tabId, record);
  return record;
}

/**
 * Records a committed navigation step, detecting server or client redirects.
 */
export function recordNavigationCommitted(
  tabId: number,
  rawUrl: string,
  transitionQualifiers: string[] = []
): TabNavigationRecord | null {
  if (isRestrictedScheme(rawUrl)) {
    tabNavigations.delete(tabId);
    return null;
  }

  let record = tabNavigations.get(tabId);
  const now = Date.now();
  const origin = getOrigin(rawUrl);
  const isRedirect =
    transitionQualifiers.includes('server_redirect') ||
    transitionQualifiers.includes('client_redirect');

  if (!record) {
    // Navigation race fallback: start was missed
    return recordNavigationStart(tabId, rawUrl);
  }

  // Check if this step is a redirect or new URL
  const lastStep = record.steps[record.steps.length - 1];
  if (lastStep && lastStep.url !== rawUrl) {
    record.redirectCount++;
    const step: NavigationStep = {
      url: rawUrl,
      origin,
      timestamp: now,
      isRedirect,
    };
    record.steps.push(step);
    record.finalUrl = rawUrl;
    record.finalOrigin = origin;
  }

  analyzeRecord(record);
  return record;
}

/**
 * Marks navigation as completed and computes final chain metrics.
 */
export function recordNavigationCompleted(
  tabId: number,
  rawUrl: string
): TabNavigationRecord | null {
  const record = tabNavigations.get(tabId);
  if (!record) return null;

  record.finalUrl = rawUrl;
  record.finalOrigin = getOrigin(rawUrl);
  record.isComplete = true;
  record.durationMs = Date.now() - (record.steps[0]?.timestamp || Date.now());

  analyzeRecord(record);
  return record;
}

/**
 * Analyzes navigation step history for phishing redirect patterns.
 */
function analyzeRecord(record: TabNavigationRecord): void {
  const initialDomain = extractBaseDomain(record.initialOrigin);
  const finalDomain = extractBaseDomain(record.finalOrigin);
  const indicators: ThreatIndicator[] = [];

  // 1. Origin hopping & Cross-domain hops
  if (record.initialOrigin !== record.finalOrigin) {
    record.hasOriginHop = true;
  }

  if (initialDomain && finalDomain && initialDomain !== finalDomain) {
    record.hasCrossDomainHop = true;
  }

  // 2. Protocol Downgrade Detection (HTTPS -> HTTP)
  const hadHttps = record.steps.some((s) => s.url.startsWith('https://'));
  const endedHttp = record.finalUrl.startsWith('http://');
  if (hadHttps && endedHttp) {
    record.hasProtocolDowngrade = true;
    indicators.push({
      id: 'redirect-protocol-downgrade',
      category: 'REDIRECT',
      severity: 'CRITICAL',
      factor: 'PROTOCOL_DOWNGRADE_REDIRECT',
      scoreImpact: 35,
      description: 'Navigation was downgraded from encrypted HTTPS to plain HTTP.',
      reason: 'Phishing funnels frequently strip TLS encryption on final landing pages to bypass certificate checks.',
      evidence: `Initial: ${record.initialUrl.slice(0, 50)}... -> Final: ${record.finalUrl.slice(0, 50)}...`,
    });
  }

  // 3. Multi-Step Suspicious Redirect Chain (>= 3 hops)
  if (record.redirectCount >= 3) {
    record.hasSuspiciousChain = true;
    indicators.push({
      id: 'redirect-multi-hop-chain',
      category: 'REDIRECT',
      severity: 'HIGH',
      factor: 'SUSPICIOUS_REDIRECT_CHAIN',
      scoreImpact: 25,
      description: `Navigation underwent ${record.redirectCount} successive redirects before settling.`,
      reason: 'Deep redirect funnels are deployed by phishing actors to evade URL scanners and sandboxes.',
      evidence: `Redirect count: ${record.redirectCount}`,
    });
  } else if (record.hasCrossDomainHop && record.redirectCount >= 1) {
    indicators.push({
      id: 'redirect-cross-domain-hop',
      category: 'REDIRECT',
      severity: 'MEDIUM',
      factor: 'CROSS_DOMAIN_REDIRECT_HOP',
      scoreImpact: 15,
      description: `Redirect switched domains from "${initialDomain}" to "${finalDomain}".`,
      reason: 'Cross-origin redirections can be used to tunnel victims into deceptive replica sites.',
      evidence: `${initialDomain} -> ${finalDomain}`,
    });
  }

  // 4. Redirect Loop / Oscillation Detection
  const originCounts = new Map<string, number>();
  for (const step of record.steps) {
    originCounts.set(step.origin, (originCounts.get(step.origin) || 0) + 1);
  }
  const hasOscillation = Array.from(originCounts.values()).some((cnt) => cnt >= 3);
  if (hasOscillation) {
    indicators.push({
      id: 'redirect-loop-detected',
      category: 'REDIRECT',
      severity: 'HIGH',
      factor: 'REDIRECT_LOOP_DETECTED',
      scoreImpact: 20,
      description: 'Repeated circular redirects between origins detected.',
      reason: 'Oscillating redirect loops often occur when phishing cloaking mechanisms misfire.',
    });
  }

  record.indicators = indicators;
}

/**
 * Retrieves the navigation record for a given tab, pruning expired entries.
 */
export function getTabNavigationRecord(tabId: number): TabNavigationRecord | undefined {
  const record = tabNavigations.get(tabId);
  if (!record) return undefined;

  // Prune if expired
  if (Date.now() - (record.steps[0]?.timestamp || 0) > NAVIGATION_TTL_MS) {
    tabNavigations.delete(tabId);
    return undefined;
  }

  return record;
}

/**
 * Cleans up navigation state when tab is closed or navigated away.
 */
export function clearTabNavigation(tabId: number): void {
  tabNavigations.delete(tabId);
}

/**
 * Clear all navigation records (for testing or reset).
 */
export function clearAllNavigations(): void {
  tabNavigations.clear();
}
