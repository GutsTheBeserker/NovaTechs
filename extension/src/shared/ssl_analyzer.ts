/**
 * SSL/TLS-Related Security Signal Analyzer
 *
 * Evaluates transport security, mixed content, and protocol downgrade indicators
 * available through standard Chrome Manifest V3 APIs.
 *
 * Honest Browser API Boundaries:
 * - Chrome Manifest V3 does NOT expose raw X.509 certificate chains, cipher suites,
 *   or OCSP revocation data to standard public extensions.
 * - Transport encryption (HTTPS vs HTTP), mixed content (HTTP resources on HTTPS pages),
 *   and protocol downgrades (HTTPS -> HTTP transitions) are directly observable and evaluated.
 * - Over 80% of modern phishing websites utilize valid TLS certificates. HTTPS ensures
 *   confidentiality in transit, but NEVER proves domain authenticity or trustworthiness.
 */

import { DOMFeatureVector, SSLSecuritySignals, TabNavigationRecord, ThreatIndicator } from './types.js';

const TLS_LIMITATIONS_NOTE =
  'Standard Chrome Manifest V3 extensions cannot inspect arbitrary raw X.509 server certificate chains, ' +
  'cipher suites, or OCSP revocation status. PhishGuard validates observable transport security ' +
  '(HTTPS vs HTTP), mixed content anomalies, and downgrade redirections. ' +
  'HTTPS proves transport encryption, not website legitimacy.';

/**
 * Analyzes observable SSL/TLS-related security signals for a webpage.
 */
export function analyzeSSLSecurity(
  url: string,
  domFeatures?: DOMFeatureVector,
  navRecord?: TabNavigationRecord
): SSLSecuritySignals {
  const isHttps = url.toLowerCase().startsWith('https://');
  const indicators: ThreatIndicator[] = [];
  let insecureResourceCount = 0;
  let hasMixedContent = false;
  let scoreAdjustment = 0;

  // 1. Insecure Plaintext HTTP Transport Check (Elevated if sensitive data present)
  if (!isHttps && url.toLowerCase().startsWith('http://')) {
    const hasSensitiveInputs =
      domFeatures &&
      (domFeatures.numPasswordFields > 0 ||
        domFeatures.paymentFieldCount > 0);

    if (hasSensitiveInputs) {
      indicators.push({
        id: 'ssl-plaintext-http-sensitive',
        category: 'SSL',
        severity: 'CRITICAL',
        factor: 'PLAINTEXT_HTTP_CREDENTIAL_FORM',
        scoreImpact: 35,
        description: 'Page requests sensitive credentials or payment data over unencrypted HTTP.',
        reason: 'Legitimate services never solicit credentials over plain HTTP. Transmitted data is vulnerable to sniffing and manipulation.',
        evidence: `Unencrypted transport with ${domFeatures?.numPasswordFields || 0} password fields.`,
      });
      scoreAdjustment += 35;
    }
  }

  // 2. Mixed Content Analysis (Insecure HTTP resources requested on an HTTPS page)
  if (isHttps && domFeatures) {
    // Insecure form actions
    const hasInsecureForms =
      (domFeatures.insecureFormActions && domFeatures.insecureFormActions > 0) ||
      domFeatures.insecureFormAction;

    if (hasInsecureForms) {
      const count = domFeatures.insecureFormActions || 1;
      hasMixedContent = true;
      insecureResourceCount += count;
      indicators.push({
        id: 'ssl-mixed-content-insecure-form',
        category: 'SSL',
        severity: 'HIGH',
        factor: 'MIXED_CONTENT_INSECURE_FORM_ACTION',
        scoreImpact: 25,
        description: `HTTPS page submits form data to an unencrypted HTTP endpoint (${count} forms).`,
        reason: 'Submitting secure page forms to plaintext endpoints exposes submitted data to interception.',
        evidence: `Insecure form count: ${count}`,
      });
      scoreAdjustment += 25;
    }

    // Insecure script origins
    if (domFeatures.scriptOrigins) {
      const httpScripts = domFeatures.scriptOrigins.filter((origin) =>
        origin.toLowerCase().startsWith('http://')
      );
      if (httpScripts.length > 0) {
        hasMixedContent = true;
        insecureResourceCount += httpScripts.length;
        indicators.push({
          id: 'ssl-mixed-content-insecure-script',
          category: 'DOM',
          severity: 'HIGH',
          factor: 'MIXED_CONTENT_ACTIVE_SCRIPT',
          scoreImpact: 20,
          description: `HTTPS page executes active scripts loaded over unencrypted HTTP (${httpScripts.length} sources).`,
          reason: 'Active mixed content can be tampered with via man-in-the-middle attacks to execute malicious code.',
          evidence: `HTTP scripts: ${httpScripts.slice(0, 3).join(', ')}`,
        });
        scoreAdjustment += 20;
      }
    }

    // Insecure iframe origins
    if (domFeatures.iframeOrigins) {
      const httpIframes = domFeatures.iframeOrigins.filter((origin) =>
        origin.toLowerCase().startsWith('http://')
      );
      if (httpIframes.length > 0) {
        hasMixedContent = true;
        insecureResourceCount += httpIframes.length;
        indicators.push({
          id: 'ssl-mixed-content-insecure-iframe',
          category: 'DOM',
          severity: 'MEDIUM',
          factor: 'MIXED_CONTENT_INSECURE_FRAME',
          scoreImpact: 15,
          description: `HTTPS page embeds frames loaded over unencrypted HTTP (${httpIframes.length} frames).`,
          reason: 'Unencrypted iframes can be manipulated to display deceptive login prompts inside a secure outer frame.',
          evidence: `HTTP frames: ${httpIframes.slice(0, 3).join(', ')}`,
        });
        scoreAdjustment += 15;
      }
    }
  }

  // 3. Protocol Downgrade verification from Navigation Record
  const hasDowngradeRedirect = Boolean(navRecord?.hasProtocolDowngrade);

  return {
    isHttps,
    hasMixedContent,
    insecureResourceCount,
    hasDowngradeRedirect,
    signals: indicators,
    scoreAdjustment,
    tlsApiLimitationsAcknowledged: true,
    limitationsNote: TLS_LIMITATIONS_NOTE,
  };
}
