/**
 * Configurable Risk-Scoring Engine Settings & Parameters
 *
 * Implements configurable classification thresholds (LOW 0-29, MEDIUM 30-59, HIGH 60-100),
 * calibrated indicator weights, category caps, and correlation dampening.
 *
 * NOTE: These weights represent initial expert design heuristics and are structured
 * to be calibratable against labelled empirical datasets in future phases.
 */

export interface RiskThresholds {
  lowMax: number; // 29
  mediumMin: number; // 30
  mediumMax: number; // 59
  highMin: number; // 60
  highMax: number; // 100
}

export interface RiskWeights {
  // Strong indicators (high-confidence attack vectors)
  punycodeHomoglyph: number;
  crossOriginCredentialSubmission: number;
  insecureCredentialSubmission: number;
  paymentCredentialTheftKit: number;
  brandDeceptionSubdomain: number;
  brandDeceptionTitle: number;
  ipAddressHostname: number;
  knownThreatFeedMatch: number;
  suspiciousOverlayIframe: number;

  // Weak & contextual indicators (evidence signals, not proof of maliciousness)
  insecureHttpTransport: number;
  excessiveUrlLength: number;
  excessiveSubdomains: number;
  excessiveHyphens: number;
  highLexicalEntropy: number;
  suspiciousPathPattern: number;
  unusualHexEncoding: number;
  embeddedCredentialsTrick: number;
  excessiveExternalResources: number;
  hiddenIframes: number;
  dataUriScript: number;
  behavioralDrift: number;
}

export interface CategoryCaps {
  maxUrlContextualCap: number; // Max total points for weak URL heuristics alone
  maxDomContextualCap: number; // Max total points for weak DOM heuristics alone
  maxResourceCap: number; // Max total points for resource origin ratios
}

export interface TrustBonuses {
  institutionalTrustBonus: number;
  maxScoreForInstitutional: number;
}

export interface RiskConfig {
  thresholds: RiskThresholds;
  weights: RiskWeights;
  categoryCaps: CategoryCaps;
  trustBonuses: TrustBonuses;
  baselineScore: number;
  correlationDampeningFactor: number;
  requireStrongIndicatorForHighRisk: boolean;
}

export const DEFAULT_RISK_CONFIG: RiskConfig = {
  thresholds: {
    lowMax: 29,
    mediumMin: 30,
    mediumMax: 59,
    highMin: 60,
    highMax: 100,
  },
  weights: {
    // Strong indicators
    punycodeHomoglyph: 35,
    crossOriginCredentialSubmission: 35,
    insecureCredentialSubmission: 30,
    paymentCredentialTheftKit: 35,
    brandDeceptionSubdomain: 25,
    brandDeceptionTitle: 25,
    ipAddressHostname: 25,
    knownThreatFeedMatch: 50,
    suspiciousOverlayIframe: 20,

    // Weak / contextual indicators
    insecureHttpTransport: 10,
    excessiveUrlLength: 5,
    excessiveSubdomains: 8,
    excessiveHyphens: 8,
    highLexicalEntropy: 8,
    suspiciousPathPattern: 8,
    unusualHexEncoding: 10,
    embeddedCredentialsTrick: 20,
    excessiveExternalResources: 10,
    hiddenIframes: 8,
    dataUriScript: 12,
    behavioralDrift: 20,
  },
  categoryCaps: {
    maxUrlContextualCap: 30,
    maxDomContextualCap: 25,
    maxResourceCap: 20,
  },
  trustBonuses: {
    institutionalTrustBonus: 40,
    maxScoreForInstitutional: 29, // Caps verified institutional SSO to LOW tier (<=29)
  },
  baselineScore: 0,
  correlationDampeningFactor: 0.75,
  requireStrongIndicatorForHighRisk: true,
};

/**
 * Creates a merged RiskConfig object with optional user/system overrides.
 */
export function createRiskConfig(overrides?: Partial<RiskConfig>): RiskConfig {
  if (!overrides) return { ...DEFAULT_RISK_CONFIG };

  return {
    ...DEFAULT_RISK_CONFIG,
    ...overrides,
    thresholds: {
      ...DEFAULT_RISK_CONFIG.thresholds,
      ...(overrides.thresholds || {}),
    },
    weights: {
      ...DEFAULT_RISK_CONFIG.weights,
      ...(overrides.weights || {}),
    },
    categoryCaps: {
      ...DEFAULT_RISK_CONFIG.categoryCaps,
      ...(overrides.categoryCaps || {}),
    },
    trustBonuses: {
      ...DEFAULT_RISK_CONFIG.trustBonuses,
      ...(overrides.trustBonuses || {}),
    },
  };
}
