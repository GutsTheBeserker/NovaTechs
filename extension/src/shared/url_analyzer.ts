/**
 * Dedicated URL Security Analysis Module
 *
 * Inspects lexical structure, encoding, brand patterns, and threat intel.
 * Principle: Each item is treated as a security signal, never as unilateral
 * proof of phishing. Unfamiliar domains or HTTP sites are not automatically
 * marked HIGH RISK without corroborating anomalies.
 */

import { ThreatIndicator, URLAnalysisResult } from './types.js';
import {
  DOCUMENTED_THREAT_INTEL,
  INSTITUTIONAL_ALLOWLIST,
  TARGETED_BRANDS,
  WEIGHT_BRAND_IN_SUBDOMAIN,
  WEIGHT_EXCESSIVE_URL_LENGTH,
  WEIGHT_INSECURE_HTTP,
  WEIGHT_IP_HOSTNAME,
  WEIGHT_KNOWN_THREAT_MATCH,
  WEIGHT_LEXICAL_ANOMALY,
  WEIGHT_PUNYCODE,
  WEIGHT_SUSPICIOUS_PATH_QUERY,
  WEIGHT_UNUSUAL_URL_ENCODING,
} from './constants.js';
import {
  calculateEntropy,
  extractBaseDomain,
  hasPunycodeOrHomograph,
  isIpAddress,
  sanitizeUrl,
} from './utils.js';

/**
 * Analyzes a given URL and extracts all observable URL security signals.
 */
export function analyzeUrl(rawUrl: string): URLAnalysisResult {
  const sanitized = sanitizeUrl(rawUrl);
  let parsed: URL;
  try {
    parsed = new URL(sanitized);
  } catch {
    // Malformed URL fallback
    parsed = new URL('http://unknown-domain.invalid');
  }

  const hostname = parsed.hostname.toLowerCase();
  const protocol = parsed.protocol.toLowerCase();
  const baseDomain = extractBaseDomain(hostname);
  const path = parsed.pathname.toLowerCase();
  const rawQuery = rawUrl.includes('?') ? rawUrl.split('?')[1].split('#')[0] : '';

  const indicators: ThreatIndicator[] = [];
  let scoreContribution = 0;

  // 1. HTTP vs HTTPS Inspection
  const isHttps = protocol === 'https:';
  if (!isHttps && protocol === 'http:') {
    scoreContribution += WEIGHT_INSECURE_HTTP;
    indicators.push({
      id: 'url-insecure-http',
      category: 'SSL',
      severity: 'LOW',
      factor: 'INSECURE_HTTP_PROTOCOL',
      scoreImpact: WEIGHT_INSECURE_HTTP,
      description: 'The website communicates using unencrypted HTTP.',
      reason: 'HTTP traffic lacks cryptographic confidentiality and integrity protection.',
      evidence: `Protocol: ${protocol}//`,
    });
  }

  // 2. IP Address Literal instead of ordinary hostname
  const isIp = isIpAddress(hostname);
  if (isIp) {
    scoreContribution += WEIGHT_IP_HOSTNAME;
    indicators.push({
      id: 'url-ip-hostname',
      category: 'URL',
      severity: 'HIGH',
      factor: 'IP_ADDRESS_HOSTNAME',
      scoreImpact: WEIGHT_IP_HOSTNAME,
      description: 'The website uses a raw IP address instead of a standard domain name.',
      reason: 'Phishing infrastructure frequently deploys disposable servers without registered DNS names.',
      evidence: `Host: ${hostname}`,
    });
  }

  // 3. URL Length
  const urlLength = rawUrl.length;
  if (urlLength > 200) {
    scoreContribution += WEIGHT_EXCESSIVE_URL_LENGTH;
    indicators.push({
      id: 'url-excessive-length',
      category: 'URL',
      severity: 'LOW',
      factor: 'EXCESSIVE_URL_LENGTH',
      scoreImpact: WEIGHT_EXCESSIVE_URL_LENGTH,
      description: `URL contains ${urlLength} characters, which is unusually long.`,
      reason: 'Lengthy URLs are commonly used to bury obfuscated query parameters and bypass token filters.',
      evidence: `Length: ${urlLength} characters`,
    });
  }

  // 4. Punycode & Internationalized Domain Indicators
  const punycode = hasPunycodeOrHomograph(hostname);
  if (punycode) {
    scoreContribution += WEIGHT_PUNYCODE;
    indicators.push({
      id: 'url-punycode-homograph',
      category: 'URL',
      severity: 'CRITICAL',
      factor: 'HOMOGRAPH_PUNYCODE_SPOOF',
      scoreImpact: WEIGHT_PUNYCODE,
      description: 'Domain utilizes Punycode ("xn--") or mixed-script unicode homoglyphs.',
      reason: 'Homograph attacks deceive users by substituting look-alike characters (e.g. Cyrillic "а" for Latin "a").',
      evidence: `Encoded host: ${hostname}`,
    });
  }

  // 5. Subdomain and Hostname Patterns
  const domainSegments = hostname.split('.');
  const subdomainCount = Math.max(0, domainSegments.length - 2);
  const hasExcessiveSubdomains = subdomainCount >= 3;

  const hyphensInHostname = (hostname.match(/-/g) || []).length;
  const hasExcessiveHyphens = hyphensInHostname >= 3;

  const lexicalEntropy = calculateEntropy(hostname);
  const hasHighEntropy = lexicalEntropy > 3.8;

  if (hasExcessiveSubdomains || hasExcessiveHyphens || hasHighEntropy) {
    scoreContribution += WEIGHT_LEXICAL_ANOMALY;
    const details: string[] = [];
    if (hasExcessiveSubdomains) details.push(`${subdomainCount} subdomains`);
    if (hasExcessiveHyphens) details.push(`${hyphensInHostname} hyphens`);
    if (hasHighEntropy) details.push(`entropy score ${lexicalEntropy}`);

    indicators.push({
      id: 'url-suspicious-subdomains',
      category: 'URL',
      severity: 'MEDIUM',
      factor: 'SUSPICIOUS_DOMAIN_STRUCTURE',
      scoreImpact: WEIGHT_LEXICAL_ANOMALY,
      description: `Anomalous domain structural markers detected: ${details.join(', ')}.`,
      reason: 'Phishing kits commonly chain multiple subdomains or hyphenated tokens to simulate authentic portals.',
      evidence: `Host: ${hostname}`,
    });
  }

  // 6. Misleading Brand-Like Hostname Patterns
  let hasMisleadingBrandPattern = false;
  let detectedBrandInSubdomain: string | undefined;

  for (const brand of TARGETED_BRANDS) {
    const compactBrand = brand.replace(/\s+/g, '');
    // Check if brand appears in hostname but is NOT part of the base domain
    if (hostname.includes(compactBrand) && !baseDomain.includes(compactBrand)) {
      hasMisleadingBrandPattern = true;
      detectedBrandInSubdomain = brand;
      scoreContribution += WEIGHT_BRAND_IN_SUBDOMAIN;
      indicators.push({
        id: 'url-brand-in-subdomain',
        category: 'BRAND',
        severity: 'HIGH',
        factor: 'MISLEADING_BRAND_SUBDOMAIN',
        scoreImpact: WEIGHT_BRAND_IN_SUBDOMAIN,
        description: `Subdomain claims recognized brand "${brand}" but base domain is "${baseDomain}".`,
        reason: 'Impersonating well-known brands in subdomains is a textbook phishing trick.',
        evidence: `Brand: "${brand}" in host "${hostname}" vs base domain "${baseDomain}"`,
      });
      break;
    }
  }

  // 7. Unusual URL Encoding & Embedded Credentials
  let hasUnusualEncoding = false;
  if (rawUrl.includes('@')) {
    hasUnusualEncoding = true;
    scoreContribution += WEIGHT_UNUSUAL_URL_ENCODING;
    indicators.push({
      id: 'url-embedded-credentials',
      category: 'URL',
      severity: 'HIGH',
      factor: 'EMBEDDED_CREDENTIALS_TRICK',
      scoreImpact: WEIGHT_UNUSUAL_URL_ENCODING,
      description: 'URL contains the "@" delimiter before the hostname.',
      reason: 'Attackers use "@" to disguise the real target destination (e.g. "https://bank.com@malicious.com").',
      evidence: 'Contains "@" in URL string',
    });
  }

  const hexCount = (rawUrl.match(/%[0-9a-fA-F]{2}/g) || []).length;
  if (hexCount > 3 || rawUrl.includes('%25')) {
    hasUnusualEncoding = true;
    scoreContribution += WEIGHT_UNUSUAL_URL_ENCODING;
    indicators.push({
      id: 'url-unusual-encoding',
      category: 'URL',
      severity: 'MEDIUM',
      factor: 'SUSPICIOUS_HEX_ENCODING',
      scoreImpact: WEIGHT_UNUSUAL_URL_ENCODING,
      description: `URL contains multiple hex-encoded characters (${hexCount} instances) or double encoding.`,
      reason: 'Excessive percent-encoding can indicate evasion techniques attempting to bypass static URL filters.',
      evidence: `Hex encoding count: ${hexCount}`,
    });
  }

  // 8. Suspicious Path and Query Patterns
  const sensitivePathTokens = [
    '/login',
    '/signin',
    '/verify',
    '/account',
    '/banking',
    '/update',
    '/wp-login.php',
    'redirect=',
    'returnurl=',
  ];
  let hasSuspiciousPathOrQuery = false;

  const isTrustedInstitution = INSTITUTIONAL_ALLOWLIST.has(baseDomain);
  if (!isTrustedInstitution) {
    for (const token of sensitivePathTokens) {
      if (path.includes(token) || rawQuery.toLowerCase().includes(token)) {
        hasSuspiciousPathOrQuery = true;
        // Mild signal: path alone is low severity on unverified domain
        scoreContribution += WEIGHT_SUSPICIOUS_PATH_QUERY;
        indicators.push({
          id: 'url-suspicious-path',
          category: 'URL',
          severity: 'LOW',
          factor: 'SUSPICIOUS_PATH_PATTERN',
          scoreImpact: WEIGHT_SUSPICIOUS_PATH_QUERY,
          description: `Path or query string contains authentication token keyword: "${token}".`,
          reason: 'Unverified domains hosting sensitive auth paths warrant scrutiny.',
          evidence: `Token: "${token}"`,
        });
        break;
      }
    }
  }

  // 9. Known Threat Intelligence Matches
  let hasKnownThreatMatch = false;
  if (DOCUMENTED_THREAT_INTEL.has(hostname) || DOCUMENTED_THREAT_INTEL.has(baseDomain)) {
    const threatRecord = DOCUMENTED_THREAT_INTEL.get(hostname) || DOCUMENTED_THREAT_INTEL.get(baseDomain)!;
    hasKnownThreatMatch = true;
    scoreContribution += WEIGHT_KNOWN_THREAT_MATCH;
    indicators.push({
      id: 'url-threat-intel-match',
      category: 'THREAT_INTEL',
      severity: 'CRITICAL',
      factor: 'KNOWN_THREAT_INTELLIGENCE_MATCH',
      scoreImpact: WEIGHT_KNOWN_THREAT_MATCH,
      description: `Domain flagged in documented threat feed: ${threatRecord.feed}.`,
      reason: `Classification: ${threatRecord.threatType}`,
      evidence: `Feed match: ${threatRecord.feed}`,
    });
  }

  return {
    url: sanitized,
    fqdn: hostname,
    scheme: protocol.replace(':', ''),
    urlLength,
    isIpAddress: isIp,
    subdomainCount,
    hasExcessiveSubdomains,
    hyphenCount: hyphensInHostname,
    hasExcessiveHyphens,
    hasPunycodeOrHomograph: punycode,
    lexicalEntropy,
    hasHighEntropy,
    hasMisleadingBrandPattern,
    detectedBrandInSubdomain,
    hasUnusualEncoding,
    hasSuspiciousPathOrQuery,
    hasKnownThreatMatch,
    isHttps,
    indicators,
    urlScoreContribution: scoreContribution,
  };
}
