import { describe, it, expect, beforeEach } from 'vitest';
import {
  clearAllNavigations,
  clearTabNavigation,
  getTabNavigationRecord,
  recordNavigationCommitted,
  recordNavigationCompleted,
  recordNavigationStart,
} from '../src/shared/redirect_tracker';

describe('Navigation & Redirect Tracker (Phase 6)', () => {
  beforeEach(() => {
    clearAllNavigations();
  });

  it('records initial navigation start and handles benign single-step navigation', () => {
    const record = recordNavigationStart(1, 'https://example.com/home');
    expect(record).not.toBeNull();
    expect(record?.initialUrl).toBe('https://example.com/home');
    expect(record?.redirectCount).toBe(0);
    expect(record?.hasOriginHop).toBe(false);
    expect(record?.hasCrossDomainHop).toBe(false);

    const completed = recordNavigationCompleted(1, 'https://example.com/home');
    expect(completed?.isComplete).toBe(true);
    expect(completed?.indicators).toHaveLength(0);
  });

  it('detects multi-hop redirect chains (>= 3 hops) as suspicious evasion technique', () => {
    recordNavigationStart(2, 'https://short.link/xyz');
    recordNavigationCommitted(2, 'https://track.adnetwork.biz/hop1', ['server_redirect']);
    recordNavigationCommitted(2, 'https://cloak.gate.info/hop2', ['server_redirect']);
    const finalRecord = recordNavigationCommitted(2, 'https://deceptive-landing.cc/login', ['server_redirect']);

    expect(finalRecord?.redirectCount).toBe(3);
    expect(finalRecord?.hasSuspiciousChain).toBe(true);

    const factors = finalRecord?.indicators.map((i) => i.factor);
    expect(factors).toContain('SUSPICIOUS_REDIRECT_CHAIN');
    expect(finalRecord?.indicators.find((i) => i.factor === 'SUSPICIOUS_REDIRECT_CHAIN')?.severity).toBe('HIGH');
  });

  it('detects cross-domain redirect hopping between distinct base domains', () => {
    recordNavigationStart(3, 'https://legitimate-looking.org/start');
    const committed = recordNavigationCommitted(3, 'https://phishing-portal.xyz/secure', ['client_redirect']);

    expect(committed?.hasCrossDomainHop).toBe(true);
    const hopIndicator = committed?.indicators.find((i) => i.factor === 'CROSS_DOMAIN_REDIRECT_HOP');
    expect(hopIndicator).toBeDefined();
    expect(hopIndicator?.evidence).toContain('legitimate-looking.org -> phishing-portal.xyz');
  });

  it('detects protocol downgrade from HTTPS to HTTP as CRITICAL severity', () => {
    recordNavigationStart(4, 'https://secure-portal.com/enter');
    const committed = recordNavigationCommitted(4, 'http://insecure-harvest.com/login', ['server_redirect']);

    expect(committed?.hasProtocolDowngrade).toBe(true);
    const downgradeInd = committed?.indicators.find((i) => i.factor === 'PROTOCOL_DOWNGRADE_REDIRECT');
    expect(downgradeInd).toBeDefined();
    expect(downgradeInd?.severity).toBe('CRITICAL');
    expect(downgradeInd?.scoreImpact).toBe(35);
  });

  it('detects redirect loops and oscillations between identical origins', () => {
    recordNavigationStart(5, 'https://origin-a.com/page');
    recordNavigationCommitted(5, 'https://origin-b.com/page', ['server_redirect']);
    recordNavigationCommitted(5, 'https://origin-a.com/page', ['server_redirect']);
    recordNavigationCommitted(5, 'https://origin-b.com/page', ['server_redirect']);
    const loopRecord = recordNavigationCommitted(5, 'https://origin-a.com/page', ['server_redirect']);

    const loopIndicator = loopRecord?.indicators.find((i) => i.factor === 'REDIRECT_LOOP_DETECTED');
    expect(loopIndicator).toBeDefined();
    expect(loopIndicator?.severity).toBe('HIGH');
  });

  it('gracefully handles missing start event (navigation race condition)', () => {
    // onCommitted fires without prior onBeforeNavigate start
    const record = recordNavigationCommitted(6, 'https://fast-loading.com/index');
    expect(record).not.toBeNull();
    expect(record?.initialUrl).toBe('https://fast-loading.com/index');
    expect(record?.tabId).toBe(6);
  });

  it('ignores restricted schemes and clears tracking state', () => {
    const chromeRecord = recordNavigationStart(7, 'chrome://settings');
    expect(chromeRecord).toBeNull();
    expect(getTabNavigationRecord(7)).toBeUndefined();

    recordNavigationStart(8, 'https://example.com');
    expect(getTabNavigationRecord(8)).toBeDefined();
    recordNavigationCommitted(8, 'chrome://extensions');
    expect(getTabNavigationRecord(8)).toBeUndefined();
  });

  it('cleans up tab navigation state when tab is closed', () => {
    recordNavigationStart(9, 'https://temp-session.com');
    expect(getTabNavigationRecord(9)).toBeDefined();

    clearTabNavigation(9);
    expect(getTabNavigationRecord(9)).toBeUndefined();
  });
});
