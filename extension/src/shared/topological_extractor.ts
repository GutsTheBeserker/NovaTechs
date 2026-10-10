/**
 * Client-Side Topological Feature Extractor
 *
 * Extracts the exact 40 URL and domain topological attributes
 * defined by the Vrbančič et al. (2020) benchmark.
 *
 * Privacy Guarantees:
 * - 100% offline string analysis.
 * - Extracts only mathematical character counts and length metrics.
 * - Enables sending numerical feature dictionaries rather than URLs to the backend.
 */

export const TOPOLOGICAL_FEATURE_NAMES = [
  'qty_dot_url',
  'qty_hyphen_url',
  'qty_underline_url',
  'qty_slash_url',
  'qty_questionmark_url',
  'qty_equal_url',
  'qty_at_url',
  'qty_and_url',
  'qty_exclamation_url',
  'qty_space_url',
  'qty_tilde_url',
  'qty_comma_url',
  'qty_plus_url',
  'qty_asterisk_url',
  'qty_hashtag_url',
  'qty_dollar_url',
  'qty_percent_url',
  'qty_tld_url',
  'length_url',
  'qty_dot_domain',
  'qty_hyphen_domain',
  'qty_underline_domain',
  'qty_slash_domain',
  'qty_questionmark_domain',
  'qty_equal_domain',
  'qty_at_domain',
  'qty_and_domain',
  'qty_exclamation_domain',
  'qty_space_domain',
  'qty_tilde_domain',
  'qty_comma_domain',
  'qty_plus_domain',
  'qty_asterisk_domain',
  'qty_hashtag_domain',
  'qty_dollar_domain',
  'qty_percent_domain',
  'qty_vowels_domain',
  'domain_length',
  'domain_in_ip',
  'server_client_domain',
] as const;

const COMMON_TLDS = new Set([
  'com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'co', 'info', 'biz',
  'xyz', 'top', 'club', 'online', 'site', 'vip', 'icu', 'app', 'dev',
  'uk', 'de', 'ca', 'au', 'fr', 'ru', 'cn', 'in', 'jp', 'br', 'nl', 'eu',
]);

const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;

function isIpAddress(host: string): boolean {
  if (!host) return false;
  const clean = host.replace(/^\[|\]$/g, '').split(':')[0];
  if (IPV4_REGEX.test(clean)) {
    const parts = clean.split('.').map((p) => parseInt(p, 10));
    return parts.every((p) => !isNaN(p) && p >= 0 && p <= 255);
  }
  return clean.includes(':');
}

function countChar(str: string, ch: string): number {
  let count = 0;
  for (let i = 0; i < str.length; i++) {
    if (str[i] === ch) count++;
  }
  return count;
}

function countTlds(url: string): number {
  const tokens = url.toLowerCase().split(/[\./?#&=_-]/);
  let count = 0;
  for (const token of tokens) {
    if (COMMON_TLDS.has(token)) count++;
  }
  return Math.max(1, count);
}

/**
 * Extracts the 40 topological features from a given URL string.
 */
export function extractTopologicalFeatures(rawUrl: string): Record<string, number> {
  if (!rawUrl || typeof rawUrl !== 'string') {
    const empty: Record<string, number> = {};
    for (const name of TOPOLOGICAL_FEATURE_NAMES) empty[name] = 0;
    return empty;
  }

  const cleanUrl = rawUrl.trim();
  let host = '';

  try {
    const parsed = new URL(cleanUrl.startsWith('http') ? cleanUrl : `http://${cleanUrl}`);
    host = (parsed.hostname || '').toLowerCase();
  } catch {
    // Fallback extraction
    const match = cleanUrl.match(/^(?:https?:\/\/)?([^\/\?#:]+)/i);
    host = match ? match[1].toLowerCase() : '';
  }

  // Count vowels in domain
  const vowels = new Set(['a', 'e', 'i', 'o', 'u']);
  let vowelCount = 0;
  for (let i = 0; i < host.length; i++) {
    if (vowels.has(host[i])) vowelCount++;
  }

  const domainInIp = isIpAddress(host) ? 1 : 0;
  const serverClientDomain = host.includes('server') || host.includes('client') ? 1 : 0;

  return {
    qty_dot_url: countChar(cleanUrl, '.'),
    qty_hyphen_url: countChar(cleanUrl, '-'),
    qty_underline_url: countChar(cleanUrl, '_'),
    qty_slash_url: countChar(cleanUrl, '/'),
    qty_questionmark_url: countChar(cleanUrl, '?'),
    qty_equal_url: countChar(cleanUrl, '='),
    qty_at_url: countChar(cleanUrl, '@'),
    qty_and_url: countChar(cleanUrl, '&'),
    qty_exclamation_url: countChar(cleanUrl, '!'),
    qty_space_url: countChar(cleanUrl, ' ') + (cleanUrl.match(/%20/gi)?.length || 0),
    qty_tilde_url: countChar(cleanUrl, '~'),
    qty_comma_url: countChar(cleanUrl, ','),
    qty_plus_url: countChar(cleanUrl, '+'),
    qty_asterisk_url: countChar(cleanUrl, '*'),
    qty_hashtag_url: countChar(cleanUrl, '#'),
    qty_dollar_url: countChar(cleanUrl, '$'),
    qty_percent_url: countChar(cleanUrl, '%'),
    qty_tld_url: countTlds(cleanUrl),
    length_url: cleanUrl.length,
    qty_dot_domain: countChar(host, '.'),
    qty_hyphen_domain: countChar(host, '-'),
    qty_underline_domain: countChar(host, '_'),
    qty_slash_domain: countChar(host, '/'),
    qty_questionmark_domain: countChar(host, '?'),
    qty_equal_domain: countChar(host, '='),
    qty_at_domain: countChar(host, '@'),
    qty_and_domain: countChar(host, '&'),
    qty_exclamation_domain: countChar(host, '!'),
    qty_space_domain: countChar(host, ' '),
    qty_tilde_domain: countChar(host, '~'),
    qty_comma_domain: countChar(host, ','),
    qty_plus_domain: countChar(host, '+'),
    qty_asterisk_domain: countChar(host, '*'),
    qty_hashtag_domain: countChar(host, '#'),
    qty_dollar_domain: countChar(host, '$'),
    qty_percent_domain: countChar(host, '%'),
    qty_vowels_domain: vowelCount,
    domain_length: host.length,
    domain_in_ip: domainInIp,
    server_client_domain: serverClientDomain,
  };
}

/**
 * Sanitizes a URL by stripping query strings and hash anchors for privacy.
 */
export function sanitizeUrlForRemote(rawUrl: string): string {
  if (!rawUrl) return '';
  try {
    const parsed = new URL(rawUrl);
    // Return origin + pathname (no ?query, no #fragment, no username/password)
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    return rawUrl.split('?')[0].split('#')[0];
  }
}
