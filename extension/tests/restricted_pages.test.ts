import { describe, it, expect } from 'vitest';
import { isRestrictedScheme, isSupportedUrl } from '../src/shared/validators';
import { createRestrictedVerdict } from '../src/background/index';

describe('Restricted Browser Pages and Scheme Validation', () => {
  it('identifies internal browser schemes as restricted', () => {
    expect(isRestrictedScheme('chrome://settings')).toBe(true);
    expect(isRestrictedScheme('chrome://extensions/')).toBe(true);
    expect(isRestrictedScheme('chrome-extension://abcdefg/popup.html')).toBe(true);
    expect(isRestrictedScheme('edge://settings')).toBe(true);
    expect(isRestrictedScheme('about:blank')).toBe(true);
    expect(isRestrictedScheme('devtools://devtools/bundled/inspector.html')).toBe(true);
    expect(isRestrictedScheme('view-source:https://example.com')).toBe(true);
    expect(isRestrictedScheme('file:///C:/Users/test/index.html')).toBe(true);
  });

  it('permits standard HTTP and HTTPS schemes', () => {
    expect(isRestrictedScheme('https://www.google.com')).toBe(false);
    expect(isRestrictedScheme('http://example.edu/articles')).toBe(false);
    expect(isRestrictedScheme('https://login.microsoftonline.com/auth')).toBe(false);
  });

  it('validates supported HTTP/HTTPS URLs', () => {
    expect(isSupportedUrl('https://example.com/login')).toBe(true);
    expect(isSupportedUrl('http://insecure.org')).toBe(true);
    expect(isSupportedUrl('chrome://history')).toBe(false);
    expect(isSupportedUrl('javascript:void(0)')).toBe(false);
    expect(isSupportedUrl('data:text/html,<h1>Hello</h1>')).toBe(false);
  });

  it('creates an appropriate UNSUPPORTED_SCHEME verdict for restricted pages', () => {
    const verdict = createRestrictedVerdict('chrome://extensions/');
    expect(verdict.status).toBe('UNSUPPORTED_SCHEME');
    expect(verdict.riskScore).toBe(0);
    expect(verdict.riskTier).toBe('LOW');
    expect(verdict.primaryFactors).toHaveLength(0);
    expect(verdict.recommendation).toContain('Browser system or internal page');
    expect(verdict.scheme).toBe('restricted');
  });
});
