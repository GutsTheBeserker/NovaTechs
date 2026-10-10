/**
 * External Resource & Dependency Security Analyzer
 *
 * Inspects external scripts, iframes, and cross-origin form action destinations.
 * Distinguishes reputable content delivery networks (CDNs) and institutional SSO services
 * from suspicious external origins (IP literals, dynamic DNS, disposable hosting).
 *
 * Privacy & Safety Guarantees:
 * - Passive metadata analysis ONLY.
 * - NEVER downloads, fetches, or executes external resources.
 * - Operates strictly on origin and URL structure.
 */

import { DOMFeatureVector, ExternalResourceAnalysis, ThreatIndicator } from './types.js';
import { extractBaseDomain } from './utils.js';

// Reputable public CDNs and static asset providers
const REPUTABLE_CDN_DOMAINS = new Set([
  'cdnjs.cloudflare.com',
  'cdn.jsdelivr.net',
  'unpkg.com',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
  'ajax.googleapis.com',
  'code.jquery.com',
  'stackpath.bootstrapcdn.com',
  'maxcdn.bootstrapcdn.com',
  'cdn.tailwindcss.com',
  'use.fontawesome.com',
  'kit.fontawesome.com',
  'assets.guim.co.uk',
  'cdn.ampproject.org',
  'static.cloudflareinsights.com',
  'www.google-analytics.com',
  'www.googletagmanager.com',
]);

// Known enterprise & institutional SSO providers (benign cross-origin authentication targets)
const REPUTABLE_SSO_DOMAINS = new Set([
  'login.microsoftonline.com',
  'accounts.google.com',
  'appleid.apple.com',
  'auth0.com',
  'okta.com',
  'pingidentity.com',
  'duosecurity.com',
  'login.salesforce.com',
]);

// Dynamic DNS & tunneling domains frequently abused by disposable phishing kits
const DYNAMIC_DNS_PATTERNS = [
  'duckdns.org',
  'ngrok.io',
  'ngrok-free.app',
  'loca.lt',
  'serveo.net',
  'pagekite.me',
  'no-ip.org',
  'no-ip.com',
  'hopto.org',
  'zapto.org',
  '000webhostapp.com',
];

// IP literal regex (IPv4)
const IP_LITERAL_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;

/**
 * Checks whether an origin or hostname matches known reputable CDNs.
 */
export function isReputableCdn(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (REPUTABLE_CDN_DOMAINS.has(lower)) return true;
  for (const cdn of REPUTABLE_CDN_DOMAINS) {
    if (lower.endsWith(`.${cdn}`)) return true;
  }
  return false;
}

/**
 * Checks whether an origin or hostname matches reputable SSO / identity providers.
 */
export function isReputableSSO(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (REPUTABLE_SSO_DOMAINS.has(lower)) return true;
  for (const sso of REPUTABLE_SSO_DOMAINS) {
    if (lower.endsWith(`.${sso}`)) return true;
  }
  return false;
}

/**
 * Identifies if a hostname is an IP literal or disposable dynamic DNS service.
 */
export function isSuspiciousOriginHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase();

  // IPv4 address hostname
  if (IP_LITERAL_REGEX.test(lower)) {
    return true;
  }

  // Dynamic DNS / tunneling service
  for (const ddns of DYNAMIC_DNS_PATTERNS) {
    if (lower === ddns || lower.endsWith(`.${ddns}`)) {
      return true;
    }
  }

  return false;
}

/**
 * Analyzes DOM external resources (scripts, iframes, form destinations)
 * against the base page origin.
 */
export function analyzeExternalResources(
  pageUrl: string,
  domFeatures: DOMFeatureVector
): ExternalResourceAnalysis {
  const indicators: ThreatIndicator[] = [];
  let pageDomain = '';
  try {
    pageDomain = extractBaseDomain(new URL(pageUrl).hostname);
  } catch {
    pageDomain = '';
  }

  const scriptOrigins = domFeatures.scriptOrigins || [];
  const iframeOrigins = domFeatures.iframeOrigins || [];
  const totalScripts = domFeatures.totalScriptCount || scriptOrigins.length;

  let externalScripts = 0;
  let reputableCdnCount = 0;
  let suspiciousScriptOriginCount = 0;
  const suspiciousOrigins: string[] = [];

  // 1. Analyze script origins
  for (const rawOrigin of scriptOrigins) {
    let hostname = '';
    try {
      hostname = new URL(rawOrigin).hostname.toLowerCase();
    } catch {
      hostname = rawOrigin.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].toLowerCase();
    }

    if (!hostname) continue;

    const scriptDomain = extractBaseDomain(hostname);
    const isCrossOrigin = pageDomain && scriptDomain && pageDomain !== scriptDomain;

    if (isCrossOrigin) {
      externalScripts++;

      if (isReputableCdn(hostname)) {
        reputableCdnCount++;
      } else if (isSuspiciousOriginHostname(hostname)) {
        suspiciousScriptOriginCount++;
        suspiciousOrigins.push(hostname);
      }
    }
  }

  if (suspiciousScriptOriginCount > 0) {
    indicators.push({
      id: 'resources-suspicious-script-origins',
      category: 'DOM',
      severity: 'HIGH',
      factor: 'SUSPICIOUS_SCRIPT_ORIGIN',
      scoreImpact: 25,
      description: `Page loads scripts from ${suspiciousScriptOriginCount} untrusted origins (IP literal or dynamic DNS).`,
      reason: 'Phishing kits commonly stage credential harvesters or keyloggers on ephemeral dynamic DNS or raw IP hosts.',
      evidence: `Origins: ${suspiciousOrigins.slice(0, 3).join(', ')}`,
    });
  }

  // 2. Cross-origin Form Action destinations targeting suspicious endpoints
  const crossOriginFormCount = domFeatures.crossDomainFormActions ?? (domFeatures.crossOriginFormAction ? 1 : 0);
  const insecureFormCount = domFeatures.insecureFormActions ?? (domFeatures.insecureFormAction ? 1 : 0);
  const formTargets = domFeatures.formActionDomains || [];
  const suspiciousFormTargets = formTargets.filter((t) => isSuspiciousOriginHostname(t));

  if (suspiciousFormTargets.length > 0) {
    indicators.push({
      id: 'resources-suspicious-form-target',
      category: 'DOM',
      severity: 'CRITICAL',
      factor: 'UNTRUSTED_FORM_DESTINATION_ORIGIN',
      scoreImpact: 35,
      description: `Form action points to an untrusted dynamic DNS or IP literal endpoint: ${suspiciousFormTargets.join(', ')}`,
      reason: 'Phishing pages frequently post collected credentials directly to raw IP addresses or dynamic tunneling URLs.',
      evidence: `Targets: ${suspiciousFormTargets.join(', ')}`,
    });
  }

  // 3. Iframe Origins analysis
  const suspiciousIframeOrigins: string[] = [];
  for (const iframeOrigin of iframeOrigins) {
    let hostname = '';
    try {
      hostname = new URL(iframeOrigin).hostname.toLowerCase();
    } catch {
      hostname = iframeOrigin.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].toLowerCase();
    }

    if (isSuspiciousOriginHostname(hostname)) {
      suspiciousIframeOrigins.push(hostname);
    }
  }

  if (suspiciousIframeOrigins.length > 0) {
    indicators.push({
      id: 'resources-suspicious-iframe-origins',
      category: 'DOM',
      severity: 'HIGH',
      factor: 'UNTRUSTED_IFRAME_ORIGIN',
      scoreImpact: 20,
      description: `Page embeds cross-origin frames from untrusted hosts (${suspiciousIframeOrigins.join(', ')}).`,
      reason: 'Iframes loaded from untrusted or dynamic DNS origins are often deployed to host credential stealing widgets.',
      evidence: `Origins: ${suspiciousIframeOrigins.join(', ')}`,
    });
  }

  return {
    totalScripts,
    externalScripts,
    reputableCdnCount,
    suspiciousScriptOriginCount,
    suspiciousOrigins,
    crossOriginFormCount,
    insecureFormCount,
    signals: indicators,
  };
}
