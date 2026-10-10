/**
 * Core type definitions for Adaptive Phishing Detection Browser Extension.
 */

export type RiskTier = 'LOW' | 'MEDIUM' | 'HIGH' | 'UNKNOWN';

export type ScanStatus =
  | 'IDLE'
  | 'SCANNING'
  | 'COMPLETE'
  | 'UNSUPPORTED_SCHEME'
  | 'INCOMPLETE'
  | 'ERROR';

export type ThreatCategory =
  | 'URL'
  | 'DOM'
  | 'SSL'
  | 'BRAND'
  | 'PAYMENT'
  | 'THREAT_INTEL'
  | 'BEHAVIORAL'
  | 'REDIRECT'
  | 'ML_TOPOLOGICAL';

export type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface ThreatIndicator {
  id: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  factor: string;
  scoreImpact: number;
  description: string;
  reason: string;
  evidence?: string;
}

// Retain ThreatFactor as backward-compatible alias
export type ThreatFactor = ThreatIndicator;

export interface MLFactorEvidence {
  feature: string;
  name: string;
  value: number;
  severity: ThreatSeverity;
  importance_weight: number;
  description: string;
}

export interface MLAssessment {
  model_available: boolean;
  model_version: string | null;
  algorithm: string;
  probability: number | null;
  risk_score: number | null;
  classification: 'LOW' | 'MEDIUM' | 'HIGH' | 'UNAVAILABLE' | 'ERROR';
  evidence: MLFactorEvidence[];
  features_evaluated: number;
  privacy_mode: string;
  scope?: {
    analyzes_page_content: boolean;
    server_side_fetching: boolean;
    analysis_target: string;
  };
  status?: string;
  message?: string;
}

export interface BackendAnalyzeResponse {
  status: 'success' | 'degraded';
  analysis_id: string;
  timestamp_utc: string;
  ml_assessment: MLAssessment;
  scope_disclosure: {
    analyzes_page_content: boolean;
    server_side_fetching: boolean;
    target: string;
    privacy_mode: string;
  };
  processing_time_ms: number;
}

export interface AnalyzeFeaturesPayload {
  features?: Record<string, number>;
  url?: string;
}

export interface NavigationStep {
  url: string;
  origin: string;
  timestamp: number;
  transitionType?: string;
  isRedirect?: boolean;
}

export interface TabNavigationRecord {
  tabId: number;
  initialUrl: string;
  initialOrigin: string;
  finalUrl: string;
  finalOrigin: string;
  steps: NavigationStep[];
  redirectCount: number;
  hasOriginHop: boolean;
  hasCrossDomainHop: boolean;
  hasProtocolDowngrade: boolean;
  hasSuspiciousChain: boolean;
  durationMs: number;
  isComplete: boolean;
  indicators: ThreatIndicator[];
}

export interface SSLSecuritySignals {
  isHttps: boolean;
  hasMixedContent: boolean;
  insecureResourceCount: number;
  hasDowngradeRedirect: boolean;
  signals: ThreatIndicator[];
  scoreAdjustment: number;
  tlsApiLimitationsAcknowledged: boolean;
  limitationsNote: string;
}

export interface ExternalResourceAnalysis {
  totalScripts: number;
  externalScripts: number;
  reputableCdnCount: number;
  suspiciousScriptOriginCount: number;
  suspiciousOrigins: string[];
  crossOriginFormCount: number;
  insecureFormCount: number;
  signals: ThreatIndicator[];
}

export interface DomainSecuritySummary {
  domain: string;
  observationCount: number;
  firstSeen: number;
  lastSeen: number;
  baselineEstablished: boolean;
  knownFormActionOrigins: string[];
  knownScriptDomains: string[];
  knownIframeOrigins: string[];
  hasBaselinePasswordFields: boolean;
  typicalRedirectHops: number;
}

export interface TrustProfileDriftResult {
  domain: string;
  hasDrift: boolean;
  driftDetails: string[];
  indicators: ThreatIndicator[];
  observationCount: number;
  baselineEstablished: boolean;
}

export interface SecurityVerdict {
  url: string;
  fqdn: string;
  scheme: 'http' | 'https' | 'restricted' | 'other';
  riskScore: number;
  riskTier: RiskTier;
  status: ScanStatus;
  primaryFactors: ThreatIndicator[];
  isInstitutional: boolean;
  recommendation: string;
  timestamp: number;
  latencyMs: number;
  scanSource: 'local_heuristics' | 'server_assisted' | 'cached';
  scanId?: string;
  mlAssessment?: MLAssessment;
  compositeBreakdown?: {
    ruleScore: number;
    mlScore: number | null;
    serverLatencyMs?: number;
  };
  offlineFallback?: boolean;
  navigationRecord?: TabNavigationRecord;
  sslSignals?: SSLSecuritySignals;
  trustProfileSummary?: {
    baselineEstablished: boolean;
    observationCount: number;
    hasDrift: boolean;
    driftDetails?: string[];
  };
}

export interface DOMFeatureVector {
  numForms: number;
  numPasswordFields: number;
  hasLoginForm: boolean;
  hasPaymentForm: boolean;
  paymentFieldCount: number;
  crossOriginFormAction: boolean;
  crossDomainFormActions?: number;
  insecureFormAction: boolean;
  insecureFormActions?: number;
  formActionDomains: string[];
  externalResourceRatio: number;
  externalScriptCount: number;
  totalScriptCount: number;
  hasDataUriScript: boolean;
  brandMismatchDetected: boolean;
  detectedBrandClaim?: string;
  hiddenIframeCount: number;
  suspiciousIframeCount: number;
  title: string;
  origin: string;
  scriptOrigins?: string[];
  iframeOrigins?: string[];
}

export interface URLAnalysisResult {
  url: string;
  fqdn: string;
  scheme: string;
  urlLength: number;
  isIpAddress: boolean;
  subdomainCount: number;
  hasExcessiveSubdomains: boolean;
  hyphenCount: number;
  hasExcessiveHyphens: boolean;
  hasPunycodeOrHomograph: boolean;
  lexicalEntropy: number;
  hasHighEntropy: boolean;
  hasMisleadingBrandPattern: boolean;
  detectedBrandInSubdomain?: string;
  hasUnusualEncoding: boolean;
  hasSuspiciousPathOrQuery: boolean;
  hasKnownThreatMatch: boolean;
  isHttps: boolean;
  indicators: ThreatIndicator[];
  urlScoreContribution: number;
}

export interface DomainLexicalFeatures {
  fqdn: string;
  fqdnLength: number;
  subdomainCount: number;
  hasIpLiteral: boolean;
  hasPunycode: boolean;
  lexicalEntropy: number;
  isHttps: boolean;
}

export interface BehavioralProfile {
  fqdn: string;
  firstSeen: number;
  visitCount: number;
  baselineFormCount: number;
  baselinePasswordFields: number;
  lastUpdated: number;
}

export type ExtensionMessage =
  | { type: 'DOM_FEATURES_EXTRACTED'; payload: DOMFeatureVector; tabId?: number; scanId?: string; url?: string }
  | { type: 'GET_SECURITY_VERDICT'; tabId?: number }
  | { type: 'TRIGGER_RESCAN'; tabId?: number; url?: string }
  | { type: 'RESCAN_DOM_REQUEST'; scanId?: string }
  | { type: 'SECURITY_VERDICT_RESPONSE'; payload: SecurityVerdict | null; tabId?: number }
  | { type: 'OPEN_WARNING_PAGE'; payload: { url: string; riskScore: number; factors: ThreatIndicator[] }; tabId?: number }
  | { type: 'CLEAR_TRUST_PROFILES' }
  | { type: 'GET_TRUST_PROFILE'; domain: string };
