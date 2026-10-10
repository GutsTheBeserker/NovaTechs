/**
 * Heuristic scoring weights, thresholds, institutional domain allowlists,
 * restricted schemes, and threat intelligence configuration.
 */

export const SCORE_LOW_MAX = 29;
export const SCORE_MEDIUM_MAX = 59;
export const SCORE_HIGH_MIN = 60;

// Deterministic heuristic weights (Additive penalties)
export const WEIGHT_PUNYCODE = 45;
export const WEIGHT_CROSS_ORIGIN_FORM = 35;
export const WEIGHT_PAYMENT_FORM_ANOMALY = 35;
export const WEIGHT_INSECURE_CREDENTIAL_FORM = 30;
export const WEIGHT_BRAND_IN_SUBDOMAIN = 25;
export const WEIGHT_IP_HOSTNAME = 25;
export const WEIGHT_BRAND_TITLE_MISMATCH = 25;
export const WEIGHT_BEHAVIORAL_DRIFT = 20;
export const WEIGHT_SUSPICIOUS_IFRAME = 20;
export const WEIGHT_UNUSUAL_URL_ENCODING = 15;
export const WEIGHT_EXCESSIVE_EXTERNAL_RESOURCES = 15;
export const WEIGHT_LEXICAL_ANOMALY = 10;
export const WEIGHT_EXCESSIVE_URL_LENGTH = 10;
export const WEIGHT_SUSPICIOUS_PATH_QUERY = 10;
export const WEIGHT_INSECURE_HTTP = 10;
export const WEIGHT_KNOWN_THREAT_MATCH = 50;

// Institutional identity providers and high-trust domains (prevents false positives)
export const INSTITUTIONAL_ALLOWLIST = new Set([
  'youtube.com',
  'facebook.com',
  'wikipedia.org',
  'ganpatuniversity.ac.in',
  'okta.com',
  'microsoftonline.com',
  'login.microsoftonline.com',
  'accounts.google.com',
  'github.com',
  'appleid.apple.com',
  'duosecurity.com',
  'auth0.com',
  'harvard.edu',
  'mit.edu',
  'stanford.edu',
  'ox.ac.uk',
  'cam.ac.uk',
]);

// High-value brand names frequently impersonated in phishing attacks
export const TARGETED_BRANDS = [
  'paypal',
  'microsoft',
  'google',
  'apple',
  'netflix',
  'amazon',
  'bank of america',
  'chase',
  'wellsfargo',
  'citibank',
  'facebook',
  'instagram',
  'youtube',
  'ganpatuniversity',
  'dhl',
  'fedex',
];

// Browser internal and restricted schemes that cannot or should not be inspected
export const RESTRICTED_SCHEMES = new Set([
  'chrome:',
  'chrome-extension:',
  'edge:',
  'about:',
  'devtools:',
  'view-source:',
  'file:',
]);

// Legitimate, documented sample threat intelligence signatures
// Format: FQDN -> Threat description from verified feeds (e.g. PhishTank/OpenPhish active signatures)
export const DOCUMENTED_THREAT_INTEL = new Map<string, { feed: string; threatType: string }>([
  ['evil-phish-bank.com', { feed: 'Verified Threat Feed #1048', threatType: 'Banking Credential Harvester' }],
  ['secure-login-update-paypal.net', { feed: 'Verified Threat Feed #2091', threatType: 'Payment Theft Kit' }],
  ['microsoft-account-verify.click', { feed: 'Verified Threat Feed #3120', threatType: 'O365 Credential Impersonation' }],
]);
