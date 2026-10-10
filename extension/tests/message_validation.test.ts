import { describe, it, expect } from 'vitest';
import {
  isDOMFeatureVector,
  validateExtensionMessage,
} from '../src/shared/validators';
import { DOMFeatureVector } from '../src/shared/types';

describe('Message Schema Validation', () => {
  const validDOMPayload: DOMFeatureVector = {
    numForms: 1,
    numPasswordFields: 1,
    hasLoginForm: true,
    hasPaymentForm: false,
    paymentFieldCount: 0,
    crossOriginFormAction: false,
    insecureFormAction: false,
    formActionDomains: ['example.com'],
    externalResourceRatio: 0.2,
    externalScriptCount: 1,
    totalScriptCount: 5,
    hasDataUriScript: false,
    brandMismatchDetected: false,
    hiddenIframeCount: 0,
    suspiciousIframeCount: 0,
    title: 'Valid Webpage Title',
    origin: 'https://example.com',
  };

  it('validates a correct DOMFeatureVector', () => {
    expect(isDOMFeatureVector(validDOMPayload)).toBe(true);
  });

  it('rejects an invalid DOMFeatureVector missing mandatory fields', () => {
    const invalidPayload = {
      numForms: 1,
      // numPasswordFields missing
      crossOriginFormAction: false,
    };
    expect(isDOMFeatureVector(invalidPayload)).toBe(false);
  });

  it('accepts valid DOM_FEATURES_EXTRACTED extension message', () => {
    const msg = {
      type: 'DOM_FEATURES_EXTRACTED',
      payload: validDOMPayload,
      tabId: 101,
    };
    const result = validateExtensionMessage(msg);
    expect(result.valid).toBe(true);
    expect(result.message).toBeDefined();
  });

  it('rejects DOM_FEATURES_EXTRACTED message with malformed payload', () => {
    const badMsg = {
      type: 'DOM_FEATURES_EXTRACTED',
      payload: { invalidField: 123 },
    };
    const result = validateExtensionMessage(badMsg);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Invalid DOMFeatureVector');
  });

  it('accepts GET_SECURITY_VERDICT message', () => {
    const msg = { type: 'GET_SECURITY_VERDICT', tabId: 42 };
    const result = validateExtensionMessage(msg);
    expect(result.valid).toBe(true);
  });

  it('accepts TRIGGER_RESCAN message', () => {
    const msg = { type: 'TRIGGER_RESCAN', tabId: 42 };
    const result = validateExtensionMessage(msg);
    expect(result.valid).toBe(true);
  });

  it('rejects unknown message types', () => {
    const unknownMsg = { type: 'UNKNOWN_MALICIOUS_ACTION', data: {} };
    const result = validateExtensionMessage(unknownMsg);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Invalid or unrecognized message type');
  });

  it('rejects null or non-object payloads', () => {
    expect(validateExtensionMessage(null).valid).toBe(false);
    expect(validateExtensionMessage('string message').valid).toBe(false);
    expect(validateExtensionMessage(12345).valid).toBe(false);
  });
});
