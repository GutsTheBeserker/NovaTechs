/**
 * Shared utility functions: Lexical parsing, URL sanitization, and Shannon entropy.
 */

/**
 * Strips sensitive query parameters, user auth credentials, and fragments from a URL.
 */
export function sanitizeUrl(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    return rawUrl.split('?')[0].split('#')[0];
  }
}

/**
 * Calculates Shannon character entropy of a domain name.
 * High entropy (>3.8) frequently correlates with dynamically generated / DGA phishing domains.
 */
export function calculateEntropy(input: string): number {
  if (!input || input.length === 0) return 0;
  const frequencies = new Map<string, number>();
  for (const char of input) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  const len = input.length;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(3));
}

/**
 * Detects Punycode ('xn--') or mixed-script Cyrillic/Latin homographs.
 */
export function hasPunycodeOrHomograph(hostname: string): boolean {
  if (hostname.toLowerCase().includes('xn--')) {
    return true;
  }
  // Detect non-ASCII unicode characters masquerading as Latin characters
  return /[^\u0000-\u007F]/.test(hostname);
}

/**
 * Detects if a hostname is an IPv4 or IPv6 address literal.
 */
export function isIpAddress(hostname: string): boolean {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv4Regex.test(hostname) || ipv6Regex.test(hostname);
}

/**
 * Extracts the base domain (e.g. 'sub.login.example.com' -> 'example.com').
 */
export function extractBaseDomain(hostname: string): string {
  let clean = hostname.toLowerCase().trim();
  if (clean.includes('://')) {
    try {
      clean = new URL(clean).hostname;
    } catch {
      clean = clean.split('://')[1].split('/')[0];
    }
  } else {
    clean = clean.split('/')[0].split(':')[0];
  }
  const parts = clean.split('.');
  if (parts.length <= 2) return clean;
  return parts.slice(-2).join('.');
}
