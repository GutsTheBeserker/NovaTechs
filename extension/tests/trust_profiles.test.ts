import { describe, it, expect, beforeEach } from 'vitest';
import {
  clearAllTrustProfiles,
  detectTrustProfileDrift,
  getAllTrustProfiles,
  getDomainTrustProfile,
  recordDomainObservation,
  removeDomainTrustProfile,
  MIN_OBSERVATIONS_FOR_BASELINE,
} from '../src/shared/trust_profiles';
import { DOMFeatureVector } from '../src/shared/types';

describe('Adaptive Website Trust Profiles Engine (Phase 6)', () => {
  beforeEach(async () => {
    await clearAllTrustProfiles();
  });

  const benignCleanDOM: DOMFeatureVector = {
    numForms: 1,
    numPasswordFields: 0,
    hasLoginForm: false,
    hasPaymentForm: false,
    paymentFieldCount: 0,
    crossOriginFormAction: false,
    insecureFormAction: false,
    formActionDomains: ['localnews.org'],
    externalResourceRatio: 0.1,
    externalScriptCount: 1,
    totalScriptCount: 4,
    hasDataUriScript: false,
    brandMismatchDetected: false,
    hiddenIframeCount: 0,
    suspiciousIframeCount: 0,
    title: 'Local News Network',
    origin: 'https://localnews.org',
  };

  it('starts new unprofiled domains in learning mode without premature baseline', async () => {
    const profile = await recordDomainObservation('https://localnews.org', benignCleanDOM, 10, false);

    expect(profile).not.toBeNull();
    expect(profile?.domain).toBe('localnews.org');
    expect(profile?.observationCount).toBe(1);
    expect(profile?.baselineEstablished).toBe(false);

    const drift = await detectTrustProfileDrift('https://localnews.org', benignCleanDOM);
    expect(drift.baselineEstablished).toBe(false);
    expect(drift.hasDrift).toBe(false);
  });

  it('establishes trusted baseline strictly after reaching observation threshold (>= 3 visits)', async () => {
    // Visit 1
    await recordDomainObservation('https://localnews.org', benignCleanDOM, 10, false);
    // Visit 2
    await recordDomainObservation('https://localnews.org', benignCleanDOM, 10, false);

    let profile = await getDomainTrustProfile('localnews.org');
    expect(profile?.observationCount).toBe(2);
    expect(profile?.baselineEstablished).toBe(false);

    // Visit 3 (Baseline threshold met)
    profile = await recordDomainObservation('https://localnews.org', benignCleanDOM, 10, false);
    expect(profile?.observationCount).toBe(MIN_OBSERVATIONS_FOR_BASELINE);
    expect(profile?.baselineEstablished).toBe(true);

    const drift = await detectTrustProfileDrift('https://localnews.org', benignCleanDOM);
    expect(drift.baselineEstablished).toBe(true);
    expect(drift.hasDrift).toBe(false);
  });

  it('safeguards against baseline poisoning by ignoring high-risk or suspicious visits', async () => {
    const maliciousDOM: DOMFeatureVector = {
      ...benignCleanDOM,
      numPasswordFields: 2,
      crossOriginFormAction: true,
      formActionDomains: ['stealth-exfil.net'],
    };

    // Attempt observation on high-risk visit (risk score 75 with high risk indicator)
    const profile = await recordDomainObservation(
      'https://phishing-attempt.xyz',
      maliciousDOM,
      75,
      true // hasHighRiskIndicators
    );

    expect(profile).toBeNull();

    const stored = await getDomainTrustProfile('phishing-attempt.xyz');
    expect(stored).toBeNull();
  });

  it('detects behavioral drift: sudden credential prompt on historically non-login domain', async () => {
    // Establish benign baseline (3 visits without passwords)
    await recordDomainObservation('https://localnews.org', benignCleanDOM, 5, false);
    await recordDomainObservation('https://localnews.org', benignCleanDOM, 5, false);
    await recordDomainObservation('https://localnews.org', benignCleanDOM, 5, false);

    // Later visit suddenly has password field injected
    const compromisedDOM: DOMFeatureVector = {
      ...benignCleanDOM,
      numPasswordFields: 1,
      hasLoginForm: true,
    };

    const drift = await detectTrustProfileDrift('https://localnews.org', compromisedDOM);
    expect(drift.baselineEstablished).toBe(true);
    expect(drift.hasDrift).toBe(true);

    const credentialIndicator = drift.indicators.find(
      (i) => i.factor === 'UNEXPECTED_CREDENTIAL_SOLICITATION'
    );
    expect(credentialIndicator).toBeDefined();
    expect(credentialIndicator?.severity).toBe('HIGH');
    expect(credentialIndicator?.scoreImpact).toBe(30);
    expect(drift.driftDetails[0]).toContain('historically never asked for passwords');
  });

  it('detects behavioral drift: unexpected new form action destination', async () => {
    // Establish benign baseline with known form destination
    await recordDomainObservation('https://community-portal.com', benignCleanDOM, 5, false);
    await recordDomainObservation('https://community-portal.com', benignCleanDOM, 5, false);
    await recordDomainObservation('https://community-portal.com', benignCleanDOM, 5, false);

    // Drifting visit points form action to unobserved third-party destination
    const formDriftDOM: DOMFeatureVector = {
      ...benignCleanDOM,
      crossOriginFormAction: true,
      crossDomainFormActions: 1,
      formActionDomains: ['unobserved-foreign-destination.ru'],
    };

    const drift = await detectTrustProfileDrift('https://community-portal.com', formDriftDOM);
    expect(drift.baselineEstablished).toBe(true);
    expect(drift.hasDrift).toBe(true);

    const formDriftIndicator = drift.indicators.find(
      (i) => i.factor === 'UNEXPECTED_FORM_ACTION_DRIFT'
    );
    expect(formDriftIndicator).toBeDefined();
    expect(formDriftIndicator?.severity).toBe('HIGH');
    expect(drift.driftDetails.join(' ')).toContain('unobserved-foreign-destination.ru');
  });

  it('allows users to inspect, remove specific domains, and wipe all trust profiles', async () => {
    await recordDomainObservation('https://site-a.com', benignCleanDOM, 10, false);
    await recordDomainObservation('https://site-b.com', benignCleanDOM, 10, false);

    let allProfiles = await getAllTrustProfiles();
    expect(Object.keys(allProfiles)).toHaveLength(2);

    await removeDomainTrustProfile('site-a.com');
    allProfiles = await getAllTrustProfiles();
    expect(allProfiles['site-a.com']).toBeUndefined();
    expect(allProfiles['site-b.com']).toBeDefined();

    await clearAllTrustProfiles();
    allProfiles = await getAllTrustProfiles();
    expect(Object.keys(allProfiles)).toHaveLength(0);
  });
});
