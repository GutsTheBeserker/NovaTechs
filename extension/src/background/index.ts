/**
 * Background Service Worker (Manifest V3)
 *
 * Coordinates tab verdicts, integrates URL analysis and DOM signals via
 * the Multi-Signal Risk Engine, validates incoming message schemas,
 * enforces institutional trustlists, and manages badge states.
 *
 * Phase 5 Integration:
 * - Asynchronously coordinates server-assisted ML classification.
 * - Enforces zero-PII and non-benign remote transmission policies.
 * - Deduplicates in-flight requests and handles offline fallbacks gracefully.
 * - Never delays page rendering or normal browsing navigation.
 */

import {
  BackendAnalyzeResponse,
  DOMFeatureVector,
  ExtensionMessage,
  SecurityVerdict,
  TabNavigationRecord,
  ThreatIndicator,
  TrustProfileDriftResult,
} from '../shared/types.js';
import { defaultRiskEngine, RiskEngineResult, classifyRiskTier } from '../shared/risk_engine.js';
import { validateExtensionMessage } from '../shared/validators.js';
import {
  buildPermittedRemotePayload,
  getCachedRemoteAssessment,
  getSanitizedCacheKey,
  setCachedRemoteAssessment,
  shouldTransmitRemotely,
} from '../shared/remote_policy.js';
import { analyzeRemotely, ApiClientOptions } from '../shared/api_client.js';
import {
  clearTabNavigation,
  getTabNavigationRecord,
  recordNavigationCommitted,
  recordNavigationCompleted,
  recordNavigationStart,
} from '../shared/redirect_tracker.js';
import {
  clearAllTrustProfiles,
  detectTrustProfileDrift,
  getDomainTrustProfile,
  recordDomainObservation,
} from '../shared/trust_profiles.js';
import { logDiagnostic, extractVerdictSignals } from '../shared/diagnostic_logger.js';

// In-memory cache of active verdicts per tab ID
export const tabVerdicts = new Map<number, SecurityVerdict>();

// Map to store latest DOM feature vector per tab for rescan operations
export const tabDOMFeatures = new Map<number, DOMFeatureVector>();

// In-flight remote request coalescing map to prevent duplicate network calls
export const inFlightRemoteRequests = new Map<string, Promise<BackendAnalyzeResponse | null>>();

/**
 * Creates an unsupported scheme verdict for browser internal pages.
 */
export function createRestrictedVerdict(rawUrl: string): SecurityVerdict {
  return defaultRiskEngine.evaluate({ url: rawUrl });
}

/**
 * Evaluates composite risk score combining dedicated URL analysis and DOM structural metrics
 * using the local multi-signal explainable risk engine.
 */
export function evaluateSecurity(
  url: string,
  domFeatures?: DOMFeatureVector | null,
  latencyStartMs?: number,
  scanId?: string,
  navigationRecord?: TabNavigationRecord | null,
  trustProfileDrift?: TrustProfileDriftResult | null
): RiskEngineResult {
  return defaultRiskEngine.evaluate({
    url,
    domFeatures,
    latencyStartMs,
    scanId,
    navigationRecord,
    trustProfileDrift,
  });
}

/**
 * Merges a validated ML assessment response into the local security verdict.
 */
export function mergeVerdictWithMLAssessment(
  localVerdict: SecurityVerdict,
  mlResponse: BackendAnalyzeResponse,
  scanSource: 'server_assisted' | 'cached' = 'server_assisted'
): SecurityVerdict {
  const ml = mlResponse.ml_assessment;
  if (!ml.model_available || ml.risk_score === null) {
    return {
      ...localVerdict,
      mlAssessment: ml,
      offlineFallback: true,
      scanSource: 'local_heuristics',
    };
  }

  // Balanced combination: 60% rule score, 40% ML score
  const compositeScore = Math.max(
    0,
    Math.min(100, Math.round(0.6 * localVerdict.riskScore + 0.4 * ml.risk_score))
  );
  const compositeTier = classifyRiskTier(compositeScore);

  // Convert ML evidence into ThreatIndicators
  const mlIndicators: ThreatIndicator[] = ml.evidence.map((ev) => ({
    id: `ml-${ev.feature}`,
    category: 'ML_TOPOLOGICAL',
    severity: ev.severity,
    factor: `ML_${ev.feature.toUpperCase()}`,
    scoreImpact: Math.round(ev.importance_weight),
    description: `ML Classifier (${ml.algorithm || 'LogisticClassifier'}): ${ev.name}`,
    reason: ev.description,
    evidence: `Value: ${ev.value} (Weight: ${ev.importance_weight}%)`,
  }));

  // Deduplicate factor IDs
  const existingIds = new Set(localVerdict.primaryFactors.map((f) => f.id));
  const mergedFactors = [...localVerdict.primaryFactors];
  for (const indicator of mlIndicators) {
    if (!existingIds.has(indicator.id)) {
      mergedFactors.push(indicator);
      existingIds.add(indicator.id);
    }
  }

  return {
    ...localVerdict,
    riskScore: compositeScore,
    riskTier: compositeTier,
    primaryFactors: mergedFactors,
    scanSource,
    mlAssessment: ml,
    compositeBreakdown: {
      ruleScore: localVerdict.riskScore,
      mlScore: ml.risk_score,
      serverLatencyMs: mlResponse.processing_time_ms,
    },
  };
}

/**
 * Coordinates security analysis: evaluates local rules immediately,
 * checks privacy transmission policies, and asynchronously calls the backend API if justified.
 */
export async function coordinateSecurityAnalysis(
  tabId: number,
  url: string,
  domFeatures?: DOMFeatureVector | null,
  isManualRescan: boolean = false,
  scanId?: string,
  apiClientOptions?: ApiClientOptions
): Promise<SecurityVerdict> {
  const startTime = performance.now();
  const navRecord = getTabNavigationRecord(tabId) || null;
  let driftResult: TrustProfileDriftResult | null = null;
  if (domFeatures) {
    try {
      driftResult = await detectTrustProfileDrift(url, domFeatures);
    } catch {
      driftResult = null;
    }
  }

  // 1. Lightweight local evaluation first (fast, < 5ms)
  const localVerdict = evaluateSecurity(url, domFeatures, startTime, scanId, navRecord, driftResult);
  tabVerdicts.set(tabId, localVerdict);
  if (domFeatures) {
    tabDOMFeatures.set(tabId, domFeatures);
    // Anti-poisoning baseline update:
    const hasHighRiskIndicators = localVerdict.primaryFactors.some(
      (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH'
    );
    recordDomainObservation(url, domFeatures, localVerdict.riskScore, hasHighRiskIndicators).catch(() => {});
  }
  updateBadge(tabId, localVerdict);

  logDiagnostic({
    phase: 'LOCAL_EVALUATION',
    url,
    tabId,
    modulesExecuted: [
      'URL_ANALYSIS',
      'SSL_ANALYSIS',
      ...(domFeatures ? ['DOM_ANALYSIS', 'RESOURCE_ANALYSIS'] : []),
      ...(driftResult ? ['TRUST_PROFILE_DRIFT'] : []),
    ],
    detectedSignals: extractVerdictSignals(localVerdict.primaryFactors),
    scoreBreakdown: {
      rawScore: localVerdict.scoringBreakdown?.rawPoints ?? localVerdict.riskScore,
      finalScore: localVerdict.riskScore,
      tier: localVerdict.riskTier,
      isInstitutional: localVerdict.isInstitutional,
      confidenceLevel: localVerdict.scoringBreakdown?.confidenceLevel,
    },
  });

  // 2. Evaluate remote transmission policy (Strict Privacy-by-Design)
  const decision = shouldTransmitRemotely(localVerdict, url, isManualRescan);
  if (!decision.shouldTransmit) {
    // Check if valid cached remote verdict exists
    const cachedResp = getCachedRemoteAssessment(url);
    if (cachedResp && !isManualRescan) {
      const merged = mergeVerdictWithMLAssessment(localVerdict, cachedResp, 'cached');
      tabVerdicts.set(tabId, merged);
      updateBadge(tabId, merged);
      return merged;
    }
    return localVerdict;
  }

  // 3. Remote analysis is justified: Send only permitted 40 numerical features
  const payload = buildPermittedRemotePayload(url);
  const cacheKey = getSanitizedCacheKey(url);

  // Coalesce in-flight requests to prevent duplicate network calls
  let requestPromise = inFlightRemoteRequests.get(cacheKey);
  if (!requestPromise) {
    requestPromise = analyzeRemotely(payload, apiClientOptions)
      .then((resp) => {
        if (resp && resp.status === 'success' && resp.ml_assessment.model_available) {
          setCachedRemoteAssessment(url, resp);
        }
        return resp;
      })
      .finally(() => {
        inFlightRemoteRequests.delete(cacheKey);
      });
    inFlightRemoteRequests.set(cacheKey, requestPromise);
  }

  const mlResponse = await requestPromise;

  if (mlResponse) {
    const finalVerdict = mergeVerdictWithMLAssessment(localVerdict, mlResponse, 'server_assisted');
    tabVerdicts.set(tabId, finalVerdict);
    updateBadge(tabId, finalVerdict);

    logDiagnostic({
      phase: 'VERDICT_MERGE',
      url,
      tabId,
      modulesExecuted: ['REMOTE_ML_BACKEND'],
      detectedSignals: extractVerdictSignals(finalVerdict.primaryFactors),
      scoreBreakdown: {
        rawScore: finalVerdict.compositeBreakdown?.ruleScore ?? finalVerdict.riskScore,
        finalScore: finalVerdict.riskScore,
        tier: finalVerdict.riskTier,
      },
      remoteStatus: {
        requested: true,
        reason: decision.reason,
        success: true,
        latencyMs: mlResponse.processing_time_ms,
        mlRiskScore: mlResponse.ml_assessment.risk_score,
      },
    });

    return finalVerdict;
  }

  // 4. Remote call failed, timed out, or offline: retain local verdict with offline fallback flag
  const fallbackVerdict: SecurityVerdict = {
    ...localVerdict,
    offlineFallback: true,
  };
  tabVerdicts.set(tabId, fallbackVerdict);
  updateBadge(tabId, fallbackVerdict);

  logDiagnostic({
    phase: 'ERROR',
    url,
    tabId,
    errorReason: 'Remote analysis failed or backend offline. Reverted to offline fallback verdict.',
  });

  return fallbackVerdict;
}

/**
 * Updates browser action badge with appropriate semantic indicators.
 */
export function updateBadge(tabId: number, verdict: SecurityVerdict): void {
  let badgeText = '';
  let badgeColor = '#10b981';

  if (verdict.status === 'UNSUPPORTED_SCHEME') {
    badgeText = '';
  } else if (verdict.riskTier === 'HIGH') {
    badgeText = '!';
    badgeColor = '#ef4444';
  } else if (verdict.riskTier === 'MEDIUM') {
    badgeText = '?';
    badgeColor = '#f59e0b';
  } else {
    badgeText = 'OK';
    badgeColor = '#10b981';
  }

  if (typeof chrome !== 'undefined' && chrome.action) {
    chrome.action.setBadgeText({ tabId, text: badgeText });
    chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
  }
}

// Runtime Message Listener with Schema Validation
if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
  chrome.runtime.onMessage.addListener((rawMessage: unknown, sender, sendResponse) => {
    const validation = validateExtensionMessage(rawMessage);
    if (!validation.valid || !validation.message) {
      console.warn('[PhishGuard] Ignored malformed message:', validation.error);
      sendResponse({ status: 'error', error: validation.error });
      return false;
    }

    const message = validation.message;
    const messageTabId = 'tabId' in message ? message.tabId : undefined;
    const tabId = sender.tab?.id ?? messageTabId;

    if (message.type === 'DOM_FEATURES_EXTRACTED') {
      const tabUrl =
        ('url' in message && typeof message.url === 'string' ? message.url : undefined) ||
        sender.url ||
        sender.tab?.url;
      const effectiveTabId = tabId ?? sender.tab?.id;

      if (effectiveTabId !== undefined && tabUrl) {
        const domFeatures = message.payload;

        coordinateSecurityAnalysis(effectiveTabId, tabUrl, domFeatures, false, message.scanId)
          .then((finalVerdict) => {
            sendResponse({ status: 'analyzed', verdict: finalVerdict });
          })
          .catch(() => {
            const fallback = evaluateSecurity(tabUrl, domFeatures);
            sendResponse({ status: 'analyzed', verdict: fallback });
          });

        return true;
      } else {
        logDiagnostic({
          phase: 'ERROR',
          tabId: effectiveTabId,
          errorReason: `DOM_FEATURES_EXTRACTED dropped: URL missing (url=${tabUrl}) or tabId missing (${effectiveTabId})`,
        });
      }
    }

    if (message.type === 'GET_SECURITY_VERDICT') {
      const activeTabId = message.tabId;
      if (activeTabId !== undefined) {
        sendResponse({
          type: 'SECURITY_VERDICT_RESPONSE',
          payload: tabVerdicts.get(activeTabId) || null,
        });
      } else {
        sendResponse({ type: 'SECURITY_VERDICT_RESPONSE', payload: null });
      }
      return true;
    }

    if (message.type === 'TRIGGER_RESCAN') {
      const targetTabId = message.tabId;
      const targetUrl =
        ('url' in message && typeof message.url === 'string' ? message.url : undefined) ||
        (targetTabId !== undefined ? tabVerdicts.get(targetTabId)?.url : undefined);

      if (targetTabId !== undefined) {
        // Forward rescan request to content script in that tab
        if (chrome.tabs?.sendMessage) {
          chrome.tabs.sendMessage(targetTabId, { type: 'RESCAN_DOM_REQUEST' }).catch(() => {
            // Content script may not be running (e.g. page opened before extension loaded)
            // If targetUrl exists and no DOM features available, initiate immediate partial analysis!
            if (targetUrl && !tabDOMFeatures.has(targetTabId)) {
              coordinateSecurityAnalysis(targetTabId, targetUrl, null, true);
            }
          });
        }

        // If targetUrl exists, trigger coordinated manual rescan immediately
        if (targetUrl) {
          const domFeatures = tabDOMFeatures.get(targetTabId) || null;
          coordinateSecurityAnalysis(targetTabId, targetUrl, domFeatures, true);
        }
      }
      sendResponse({ status: 'rescan_triggered' });
      return true;
    }

    if (message.type === 'OPEN_WARNING_PAGE') {
      const warningUrl = chrome.runtime.getURL('src/warning/warning.html');
      chrome.tabs.create({ url: warningUrl });
      sendResponse({ status: 'warning_opened' });
      return true;
    }

    if (message.type === 'CLEAR_TRUST_PROFILES') {
      clearAllTrustProfiles().then(() => {
        sendResponse({ status: 'cleared' });
      });
      return true;
    }

    if (message.type === 'GET_TRUST_PROFILE') {
      getDomainTrustProfile(message.domain).then((profile) => {
        sendResponse({ status: 'ok', profile });
      });
      return true;
    }

    return false;
  });
}

// Tab cleanup on close
if (typeof chrome !== 'undefined' && chrome.tabs?.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    tabVerdicts.delete(tabId);
    tabDOMFeatures.delete(tabId);
    clearTabNavigation(tabId);
  });
}

// Navigation Tracking via Chrome webNavigation
if (typeof chrome !== 'undefined' && chrome.webNavigation) {
  chrome.webNavigation.onBeforeNavigate?.addListener((details) => {
    if (details.frameId === 0) {
      recordNavigationStart(details.tabId, details.url);
    }
  });

  chrome.webNavigation.onCommitted?.addListener((details) => {
    if (details.frameId === 0) {
      recordNavigationCommitted(details.tabId, details.url, details.transitionQualifiers);
    }
  });

  chrome.webNavigation.onCompleted?.addListener((details) => {
    if (details.frameId === 0) {
      recordNavigationCompleted(details.tabId, details.url);
    }
  });
}
