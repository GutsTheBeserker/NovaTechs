/**
 * Multi-Signal Explainable Phishing Risk Engine
 *
 * Combines URL, domain, DOM, form, redirect, and resource indicators
 * using normalized inputs, deduplication, correlation dampening,
 * category caps, and uncertainty accounting.
 */

import {
  DOMFeatureVector,
  ExternalResourceAnalysis,
  RiskTier,
  SecurityVerdict,
  SSLSecuritySignals,
  TabNavigationRecord,
  ThreatCategory,
  ThreatIndicator,
  ThreatSeverity,
  TrustProfileDriftResult,
  URLAnalysisResult,
} from './types.js';
import {
  createRiskConfig,
  DEFAULT_RISK_CONFIG,
  RiskConfig,
  RiskThresholds,
} from './risk_config.js';
import { analyzeUrl } from './url_analyzer.js';
import { extractBaseDomain, sanitizeUrl } from './utils.js';
import { isRestrictedScheme } from './validators.js';
import { INSTITUTIONAL_ALLOWLIST } from './constants.js';
import { analyzeSSLSecurity } from './ssl_analyzer.js';
import { analyzeExternalResources } from './resource_analyzer.js';

export interface ScoringInput {
  url: string;
  domFeatures?: DOMFeatureVector | null;
  urlAnalysis?: URLAnalysisResult | null;
  isInstitutionalOverride?: boolean;
  scanId?: string;
  latencyStartMs?: number;
  navigationRecord?: TabNavigationRecord | null;
  sslSignals?: SSLSecuritySignals | null;
  resourceAnalysis?: ExternalResourceAnalysis | null;
  trustProfileDrift?: TrustProfileDriftResult | null;
}

export interface ScoringBreakdown {
  ruleScore: number;
  mlScore: number | null;
  mlStatus: string;
  compositeScore: number;
  rawPoints: number;
  cappedPoints: number;
  trustBonusDeduction: number;
  categoryContributions: Record<ThreatCategory, number>;
  strongIndicatorsCount: number;
  weakIndicatorsCount: number;
  duplicateIndicatorsSuppressed: number;
  informationCompleteness: number; // 0.0 to 1.0
  confidenceLevel: 'HIGH' | 'MEDIUM' | 'LOW';
  uncertaintyNotes?: string;
}

export interface RiskEngineResult extends SecurityVerdict {
  scoringBreakdown: ScoringBreakdown;
}

/**
 * Classifies numerical risk score into LOW, MEDIUM, or HIGH risk tier.
 * Default boundary values:
 *   0  - 29: LOW
 *   30 - 59: MEDIUM
 *   60 - 100: HIGH
 */
export function classifyRiskTier(
  score: number,
  thresholds: RiskThresholds = DEFAULT_RISK_CONFIG.thresholds
): RiskTier {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  if (clamped >= thresholds.highMin) {
    return 'HIGH';
  }
  if (clamped >= thresholds.mediumMin) {
    return 'MEDIUM';
  }
  return 'LOW';
}

/**
 * Normalizes and validates incoming DOM feature vector, providing safe defaults
 * when attributes are missing, null, or malformed.
 */
export function normalizeDOMFeatures(
  raw?: DOMFeatureVector | null
): { features: DOMFeatureVector | null; isComplete: boolean } {
  if (!raw || typeof raw !== 'object') {
    return { features: null, isComplete: false };
  }

  const safeNumber = (val: unknown, fallback = 0): number =>
    typeof val === 'number' && !isNaN(val) ? Math.max(0, Math.floor(val)) : fallback;
  const safeFloat = (val: unknown, fallback = 0.0): number =>
    typeof val === 'number' && !isNaN(val) ? Math.max(0, Math.min(1.0, val)) : fallback;
  const safeBool = (val: unknown): boolean => Boolean(val);
  const safeArray = (val: unknown): string[] => (Array.isArray(val) ? val.filter((x) => typeof x === 'string') : []);

  const normalized: DOMFeatureVector = {
    numForms: safeNumber(raw.numForms),
    numPasswordFields: safeNumber(raw.numPasswordFields),
    hasLoginForm: safeBool(raw.hasLoginForm),
    hasPaymentForm: safeBool(raw.hasPaymentForm),
    paymentFieldCount: safeNumber(raw.paymentFieldCount),
    crossOriginFormAction: safeBool(raw.crossOriginFormAction),
    insecureFormAction: safeBool(raw.insecureFormAction),
    formActionDomains: safeArray(raw.formActionDomains),
    externalResourceRatio: safeFloat(raw.externalResourceRatio),
    externalScriptCount: safeNumber(raw.externalScriptCount),
    totalScriptCount: safeNumber(raw.totalScriptCount),
    hasDataUriScript: safeBool(raw.hasDataUriScript),
    brandMismatchDetected: safeBool(raw.brandMismatchDetected),
    detectedBrandClaim: typeof raw.detectedBrandClaim === 'string' ? raw.detectedBrandClaim : undefined,
    hiddenIframeCount: safeNumber(raw.hiddenIframeCount),
    suspiciousIframeCount: safeNumber(raw.suspiciousIframeCount),
    title: typeof raw.title === 'string' ? raw.title.slice(0, 100) : '',
    origin: typeof raw.origin === 'string' ? raw.origin : '',
  };

  return { features: normalized, isComplete: true };
}

/**
 * Internal accumulator to collect and deduplicate threat indicators.
 */
class IndicatorCollector {
  private indicators: ThreatIndicator[] = [];
  private seenKeys = new Set<string>();
  private duplicateCount = 0;

  add(indicator: ThreatIndicator): boolean {
    // Generate signature key: category + factor + evidence (or description)
    const key = `${indicator.category}:${indicator.factor}:${(indicator.evidence || indicator.description).trim().toLowerCase()}`;
    if (this.seenKeys.has(key)) {
      this.duplicateCount++;
      return false; // Prevent duplicate evidence
    }
    this.seenKeys.add(key);
    this.indicators.push(indicator);
    return true;
  }

  addAll(indicators: ThreatIndicator[]): void {
    indicators.forEach((i) => this.add(i));
  }

  getIndicators(): ThreatIndicator[] {
    return [...this.indicators];
  }

  getDuplicateCount(): number {
    return this.duplicateCount;
  }
}

/**
 * Core Multi-Signal Risk Scoring Engine
 */
export class PhishingRiskEngine {
  private config: RiskConfig;

  constructor(customConfig?: Partial<RiskConfig>) {
    this.config = createRiskConfig(customConfig);
  }

  /**
   * Evaluates input security signals and produces an explainable, structured verdict.
   */
  evaluate(input: ScoringInput): RiskEngineResult {
    const startTime = input.latencyStartMs ?? performance.now();
    const rawUrl = typeof input.url === 'string' ? input.url : '';

    // Handle restricted or invalid URLs
    if (!rawUrl || isRestrictedScheme(rawUrl)) {
      return this.generateRestrictedResult(rawUrl, startTime);
    }

    const sanitized = sanitizeUrl(rawUrl);
    let parsed: URL;
    try {
      parsed = new URL(sanitized);
    } catch {
      parsed = new URL('http://unparseable-domain.invalid');
    }

    const hostname = parsed.hostname.toLowerCase();
    const baseDomain = extractBaseDomain(hostname);
    const scheme: 'http' | 'https' | 'other' =
      parsed.protocol === 'https:' ? 'https' : parsed.protocol === 'http:' ? 'http' : 'other';

    // 1. Completeness & Uncertainty Accounting
    const domNormalization = normalizeDOMFeatures(input.domFeatures);
    const domFeatures = domNormalization.features;
    const isDomComplete = domNormalization.isComplete;

    let completeness = 0.4; // URL available
    if (isDomComplete) completeness += 0.6; // DOM available

    let confidenceLevel: 'HIGH' | 'MEDIUM' | 'LOW' = 'HIGH';
    let uncertaintyNotes: string | undefined;

    if (!isDomComplete) {
      confidenceLevel = 'MEDIUM';
      uncertaintyNotes =
        'Partial evaluation: DOM structural inspection was not available. Verdict reflects URL and domain signals only.';
    }

    // 2. URL Analysis (use provided or execute fresh)
    const urlAnalysis = input.urlAnalysis || analyzeUrl(rawUrl);

    // 3. Collect and Deduplicate Indicators
    const collector = new IndicatorCollector();
    collector.addAll(urlAnalysis.indicators);

    // 4. SSL/TLS Signals Analysis
    const sslSignals =
      input.sslSignals !== undefined
        ? input.sslSignals
        : analyzeSSLSecurity(rawUrl, domFeatures || undefined, input.navigationRecord || undefined);
    if (sslSignals) {
      collector.addAll(sslSignals.signals);
    }

    // 5. Evaluate DOM Signals (if present)
    if (domFeatures) {
      this.evaluateDOMSignals(domFeatures, hostname, collector);

      // External Resource Analysis
      const resourceAnalysis =
        input.resourceAnalysis !== undefined
          ? input.resourceAnalysis
          : analyzeExternalResources(rawUrl, domFeatures);
      if (resourceAnalysis) {
        collector.addAll(resourceAnalysis.signals);
      }
    }

    // 6. Navigation and Redirect Indicators
    if (input.navigationRecord && input.navigationRecord.indicators) {
      collector.addAll(input.navigationRecord.indicators);
    }

    // 7. Trust Profile Behavioral Drift Indicators
    if (input.trustProfileDrift && input.trustProfileDrift.indicators) {
      collector.addAll(input.trustProfileDrift.indicators);
    }

    const allIndicators = collector.getIndicators();
    const duplicateCount = collector.getDuplicateCount();

    // 8. Categorize and Tally Points with Anti-Double-Counting and Category Caps
    let rawTotalPoints = this.config.baselineScore;
    let hasStrongIndicator = false;
    let strongCount = 0;
    let weakCount = 0;

    const categoryPoints: Record<ThreatCategory, number> = {
      URL: 0,
      DOM: 0,
      SSL: 0,
      BRAND: 0,
      PAYMENT: 0,
      THREAT_INTEL: 0,
      BEHAVIORAL: 0,
      REDIRECT: 0,
      ML_TOPOLOGICAL: 0,
    };
    const categoryPointsStrong: Record<ThreatCategory, number> = {
      URL: 0,
      DOM: 0,
      SSL: 0,
      BRAND: 0,
      PAYMENT: 0,
      THREAT_INTEL: 0,
      BEHAVIORAL: 0,
      REDIRECT: 0,
      ML_TOPOLOGICAL: 0,
    };
    const categoryPointsWeak: Record<ThreatCategory, number> = {
      URL: 0,
      DOM: 0,
      SSL: 0,
      BRAND: 0,
      PAYMENT: 0,
      THREAT_INTEL: 0,
      BEHAVIORAL: 0,
      REDIRECT: 0,
      ML_TOPOLOGICAL: 0,
    };

    // Correlation dampening tracking
    const categoryFactorCounts = new Map<ThreatCategory, number>();

    allIndicators.forEach((ind) => {
      const isStrong = ind.severity === 'CRITICAL' || ind.severity === 'HIGH';
      if (isStrong) {
        hasStrongIndicator = true;
        strongCount++;
      } else {
        weakCount++;
      }

      // Apply correlation dampening for repeated signals in same category
      const priorCount = categoryFactorCounts.get(ind.category) || 0;
      categoryFactorCounts.set(ind.category, priorCount + 1);

      let effectiveImpact = ind.scoreImpact;
      if (priorCount > 1 && !isStrong) {
        effectiveImpact = Math.round(effectiveImpact * this.config.correlationDampeningFactor);
      }

      if (isStrong) {
        categoryPointsStrong[ind.category] += effectiveImpact;
      } else {
        categoryPointsWeak[ind.category] += effectiveImpact;
      }
      categoryPoints[ind.category] += effectiveImpact;
      rawTotalPoints += effectiveImpact;
    });

    // 9. Apply Category Caps strictly to Contextual/Weak Heuristics
    const urlWeakCapped = Math.min(this.config.categoryCaps.maxUrlContextualCap, categoryPointsWeak.URL);
    const domWeakCapped = Math.min(this.config.categoryCaps.maxDomContextualCap, categoryPointsWeak.DOM);

    // Calculate capped total: strong attack vectors + capped weak heuristics
    let cappedPoints =
      categoryPointsStrong.URL +
      urlWeakCapped +
      categoryPointsStrong.DOM +
      domWeakCapped +
      categoryPoints.SSL +
      categoryPoints.BRAND +
      categoryPoints.PAYMENT +
      categoryPoints.THREAT_INTEL +
      categoryPoints.BEHAVIORAL +
      categoryPoints.REDIRECT +
      categoryPoints.ML_TOPOLOGICAL;

    // 7. Weak-Signal High-Risk Prevention Safeguard
    // If NO strong indicator is present, weak heuristics alone cannot trigger HIGH risk (capped at 59)
    if (this.config.requireStrongIndicatorForHighRisk && !hasStrongIndicator) {
      if (cappedPoints >= this.config.thresholds.highMin) {
        cappedPoints = this.config.thresholds.mediumMax; // Cap at 59
      }
    }

    // 8. Institutional Allowlist & Trust Deductions
    const isInstitutional =
      input.isInstitutionalOverride ||
      INSTITUTIONAL_ALLOWLIST.has(baseDomain) ||
      hostname.endsWith('.edu') ||
      INSTITUTIONAL_ALLOWLIST.has(hostname);

    let trustDeduction = 0;
    if (isInstitutional) {
      trustDeduction = this.config.trustBonuses.institutionalTrustBonus;
      cappedPoints = Math.max(0, cappedPoints - trustDeduction);

      // Unless critical homoglyph or known threat feed match occurs, cap institutional sites at LOW tier
      const hasCriticalOverride = allIndicators.some(
        (i) => i.factor === 'HOMOGRAPH_PUNYCODE_SPOOF' || i.factor === 'KNOWN_THREAT_INTELLIGENCE_MATCH'
      );
      if (!hasCriticalOverride && cappedPoints > this.config.trustBonuses.maxScoreForInstitutional) {
        cappedPoints = this.config.trustBonuses.maxScoreForInstitutional; // Capped at 29
      }
    }

    // 9. Final Score Normalization [0, 100]
    const finalScore = Math.max(0, Math.min(100, Math.round(cappedPoints)));
    const riskTier = classifyRiskTier(finalScore, this.config.thresholds);

    // Sort indicators by severity impact descending for explainability
    allIndicators.sort((a, b) => b.scoreImpact - a.scoreImpact);

    const latencyMs = parseFloat((performance.now() - startTime).toFixed(2));
    const recommendation = this.formulateRecommendation(riskTier, allIndicators, isInstitutional, !isDomComplete);

    const scoringBreakdown: ScoringBreakdown = {
      ruleScore: finalScore,
      mlScore: null,
      mlStatus: 'ML inference engine deferred (scheduled for Phase 4)',
      compositeScore: finalScore,
      rawPoints: rawTotalPoints,
      cappedPoints,
      trustBonusDeduction: trustDeduction,
      categoryContributions: categoryPoints,
      strongIndicatorsCount: strongCount,
      weakIndicatorsCount: weakCount,
      duplicateIndicatorsSuppressed: duplicateCount,
      informationCompleteness: completeness,
      confidenceLevel,
      uncertaintyNotes,
    };

    return {
      url: sanitized,
      fqdn: hostname,
      scheme,
      riskScore: finalScore,
      riskTier,
      status: isDomComplete ? 'COMPLETE' : 'INCOMPLETE',
      primaryFactors: allIndicators,
      isInstitutional,
      recommendation,
      timestamp: Date.now(),
      latencyMs,
      scanSource: 'local_heuristics',
      scanId: input.scanId,
      scoringBreakdown,
      navigationRecord: input.navigationRecord || undefined,
      sslSignals: sslSignals || undefined,
      trustProfileSummary: input.trustProfileDrift
        ? {
            baselineEstablished: input.trustProfileDrift.baselineEstablished,
            observationCount: input.trustProfileDrift.observationCount,
            hasDrift: input.trustProfileDrift.hasDrift,
            driftDetails: input.trustProfileDrift.driftDetails,
          }
        : undefined,
    };
  }

  /**
   * Evaluates DOM-specific indicators and registers them with the collector.
   */
  private evaluateDOMSignals(
    dom: DOMFeatureVector,
    hostname: string,
    collector: IndicatorCollector
  ): void {
    const baseDomain = extractBaseDomain(hostname);
    const isKnownInstitution =
      INSTITUTIONAL_ALLOWLIST.has(baseDomain) ||
      hostname.endsWith('.edu') ||
      INSTITUTIONAL_ALLOWLIST.has(hostname);

    // Active credential collection form on unverified domain (Contextual)
    if (!isKnownInstitution && (dom.hasLoginForm || dom.numPasswordFields > 0)) {
      collector.add({
        id: 'dom-credential-collection-form',
        category: 'DOM',
        severity: 'MEDIUM',
        factor: 'CREDENTIAL_FORM_PRESENT',
        scoreImpact: 15,
        description: 'Page presents an active user authentication or password input form on an unverified domain.',
        reason: 'Authentication forms on unfamiliar or non-institutional domains warrant scrutiny for credential theft.',
        evidence: `Password fields: ${dom.numPasswordFields}, Login hints: ${dom.hasLoginForm}`,
      });
    }

    // Cross-origin password or credential submission (Strong)
    if (dom.crossOriginFormAction && (dom.numPasswordFields > 0 || dom.hasLoginForm)) {
      collector.add({
        id: 'dom-cross-origin-password',
        category: 'DOM',
        severity: 'CRITICAL',
        factor: 'CROSS_ORIGIN_CREDENTIAL_FORM',
        scoreImpact: this.config.weights.crossOriginCredentialSubmission,
        description: 'Password form transmits credentials to an unverified third-party domain.',
        reason: 'Legitimate login forms rarely submit authentication secrets directly to distinct foreign hostnames.',
        evidence: `Destination: ${dom.formActionDomains.join(', ')}`,
      });
    }

    // Insecure credential submission over unencrypted HTTP (Strong)
    if (dom.insecureFormAction && dom.numPasswordFields > 0) {
      collector.add({
        id: 'dom-insecure-password',
        category: 'DOM',
        severity: 'HIGH',
        factor: 'INSECURE_CREDENTIAL_TRANSMISSION',
        scoreImpact: this.config.weights.insecureCredentialSubmission,
        description: 'Form containing password transmits data over unencrypted HTTP.',
        reason: 'Submitting passwords over plain HTTP exposes credentials to network interception and man-in-the-middle attacks.',
      });
    }

    // Payment Form Anomaly (Strong)
    if (dom.hasPaymentForm && (dom.crossOriginFormAction || dom.insecureFormAction)) {
      collector.add({
        id: 'dom-insecure-payment',
        category: 'PAYMENT',
        severity: 'CRITICAL',
        factor: 'INSECURE_PAYMENT_COLLECTION',
        scoreImpact: this.config.weights.paymentCredentialTheftKit,
        description: 'Payment card form submits data to external or unencrypted destinations.',
        reason: 'Credit card collection fields submitting cross-origin strongly correlate with e-commerce skimming or phishing kits.',
        evidence: `Detected payment fields: ${dom.paymentFieldCount}`,
      });
    }

    // Brand Title Mismatch (Strong)
    if (dom.brandMismatchDetected) {
      collector.add({
        id: 'dom-brand-title-mismatch',
        category: 'BRAND',
        severity: 'HIGH',
        factor: 'BRAND_TITLE_MISMATCH',
        scoreImpact: this.config.weights.brandDeceptionTitle,
        description: `Page title references recognized brand "${dom.detectedBrandClaim || 'brand'}" but domain does not match.`,
        reason: 'Phishing pages frequently copy authentic page titles while hosted on unrelated domain names.',
        evidence: `Title: "${dom.title}" vs Host: ${hostname}`,
      });
    }

    // Excessive External Resources (Contextual)
    if (dom.externalResourceRatio > 0.8) {
      collector.add({
        id: 'dom-excessive-external-resources',
        category: 'DOM',
        severity: 'MEDIUM',
        factor: 'EXCESSIVE_EXTERNAL_RESOURCES',
        scoreImpact: this.config.weights.excessiveExternalResources,
        description: `Over 80% (${Math.round(dom.externalResourceRatio * 100)}%) of scripts/stylesheets originate externally.`,
        reason: 'Phishing websites frequently hotlink stylesheets and images from legitimate sites without hosting their own assets.',
      });
    }

    // Data URI script injection (Contextual)
    if (dom.hasDataUriScript) {
      collector.add({
        id: 'dom-data-uri-script',
        category: 'DOM',
        severity: 'MEDIUM',
        factor: 'DATA_URI_SCRIPT_INJECTION',
        scoreImpact: this.config.weights.dataUriScript,
        description: 'Script element uses a data: URI payload instead of a standard URL.',
        reason: 'Data URIs can be utilized to inject obfuscated JavaScript into web pages.',
      });
    }

    // Suspicious overlay iframe (Strong)
    if (dom.suspiciousIframeCount > 0) {
      collector.add({
        id: 'dom-suspicious-iframe',
        category: 'DOM',
        severity: 'HIGH',
        factor: 'SUSPICIOUS_OVERLAY_IFRAME',
        scoreImpact: this.config.weights.suspiciousOverlayIframe,
        description: 'Full-viewport transparent overlay iframe detected on page.',
        reason: 'Invisible overlay iframes are commonly associated with clickjacking and deceptive credential capture.',
      });
    }

    // Hidden iframes (Contextual)
    if (dom.hiddenIframeCount >= 2) {
      collector.add({
        id: 'dom-hidden-iframes',
        category: 'DOM',
        severity: 'LOW',
        factor: 'HIDDEN_IFRAMES_PRESENT',
        scoreImpact: this.config.weights.hiddenIframes,
        description: `Multiple hidden or zero-pixel iframes detected (${dom.hiddenIframeCount} iframes).`,
        reason: 'Hidden iframes can be used for stealth tracking or background exploit delivery.',
      });
    }
  }

  /**
   * Generates a context-specific, plain-language recommendation.
   */
  private formulateRecommendation(
    tier: RiskTier,
    factors: ThreatIndicator[],
    isInstitutional: boolean,
    isPartial: boolean
  ): string {
    if (isInstitutional) {
      return 'Safe to proceed: Verified institutional or authentic Single Sign-On identity provider.';
    }

    if (tier === 'HIGH') {
      const topFactor = factors[0];
      if (topFactor) {
        return `CRITICAL RISK: Potential phishing detected due to ${topFactor.description.toLowerCase()} Do NOT submit credentials or personal data.`;
      }
      return 'CRITICAL RISK: Strong deception indicators identified. Navigate away immediately.';
    }

    if (tier === 'MEDIUM') {
      if (isPartial) {
        return 'PROCEED WITH CAUTION: Elevated URL risk signals observed. Page structure could not be fully analyzed.';
      }
      return 'PROCEED WITH CAUTION: Elevated risk indicators identified. Verify domain spelling and certificates before entering information.';
    }

    return 'SAFE: Page structures and domain indicators are consistent with normal legitimate websites.';
  }

  /**
   * Handles internal or restricted schemes.
   */
  private generateRestrictedResult(rawUrl: string, startTime: number): RiskEngineResult {
    let fqdn = 'restricted-page';
    try {
      const p = new URL(rawUrl);
      fqdn = p.hostname || p.protocol.replace(':', '');
    } catch {}

    const breakdown: ScoringBreakdown = {
      ruleScore: 0,
      mlScore: null,
      mlStatus: 'Restricted system page - analysis excluded',
      compositeScore: 0,
      rawPoints: 0,
      cappedPoints: 0,
      trustBonusDeduction: 0,
      categoryContributions: {
        URL: 0,
        DOM: 0,
        SSL: 0,
        BRAND: 0,
        PAYMENT: 0,
        THREAT_INTEL: 0,
        BEHAVIORAL: 0,
        REDIRECT: 0,
        ML_TOPOLOGICAL: 0,
      },

      strongIndicatorsCount: 0,
      weakIndicatorsCount: 0,
      duplicateIndicatorsSuppressed: 0,
      informationCompleteness: 1.0,
      confidenceLevel: 'HIGH',
    };

    return {
      url: rawUrl,
      fqdn,
      scheme: 'restricted',
      riskScore: 0,
      riskTier: 'LOW',
      status: 'UNSUPPORTED_SCHEME',
      primaryFactors: [],
      isInstitutional: false,
      recommendation: 'Browser system or internal page. Security scanning is not applicable.',
      timestamp: Date.now(),
      latencyMs: parseFloat((performance.now() - startTime).toFixed(2)),
      scanSource: 'local_heuristics',
      scoringBreakdown: breakdown,
    };
  }
}

// Default singleton instance
export const defaultRiskEngine = new PhishingRiskEngine();
