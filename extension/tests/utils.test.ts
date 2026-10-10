import { describe, it, expect } from 'vitest';
import {
  calculateEntropy,
  extractBaseDomain,
  hasPunycodeOrHomograph,
  isIpAddress,
  sanitizeUrl,
} from '../src/shared/utils';

describe('Sanitization & Privacy Utilities', () => {
  it('strips sensitive query parameters and authentication tokens from URLs', () => {
    const rawUrl = 'https://portal.example.com/auth/login?session_token=secret999&user=dharm#anchor';
    const sanitized = sanitizeUrl(rawUrl);
    expect(sanitized).toBe('https://portal.example.com/auth/login');
    expect(sanitized).not.toContain('secret999');
    expect(sanitized).not.toContain('session_token');
    expect(sanitized).not.toContain('#anchor');
  });

  it('handles already clean URLs properly', () => {
    const cleanUrl = 'https://example.edu/login';
    expect(sanitizeUrl(cleanUrl)).toBe('https://example.edu/login');
  });
});

describe('Shannon Character Entropy', () => {
  it('returns 0 for empty or null strings', () => {
    expect(calculateEntropy('')).toBe(0);
  });

  it('computes higher entropy for randomized DGA-style domains', () => {
    const repetitiveDomain = 'aaaaa.com';
    const randomizedDomain = 'x7k9q2m4w8z.com';
    const lowEntropy = calculateEntropy(repetitiveDomain);
    const highEntropy = calculateEntropy(randomizedDomain);
    expect(highEntropy).toBeGreaterThan(lowEntropy);
  });
});

describe('Deceptive Domain Detection', () => {
  it('detects Punycode encoded domains', () => {
    expect(hasPunycodeOrHomograph('xn--paypa-cra.com')).toBe(true);
    expect(hasPunycodeOrHomograph('paypal.com')).toBe(false);
  });

  it('detects non-ASCII homograph glyphs masquerading as Latin characters', () => {
    // Cyrillic 'а' (U+0430) instead of Latin 'a'
    const homographDomain = 'p\u0430ypal.com';
    expect(hasPunycodeOrHomograph(homographDomain)).toBe(true);
  });

  it('detects direct IP literal hostnames', () => {
    expect(isIpAddress('192.168.1.1')).toBe(true);
    expect(isIpAddress('10.0.0.1')).toBe(true);
    expect(isIpAddress('bank-login.com')).toBe(false);
  });

  it('correctly extracts base domain', () => {
    expect(extractBaseDomain('sub.portal.bank.com')).toBe('bank.com');
    expect(extractBaseDomain('google.com')).toBe('google.com');
  });
});
