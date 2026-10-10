/**
 * Passive Content Script: DOM Structure Harvester
 *
 * Runs strictly at document_idle.
 * Privacy Guarantee: NEVER reads input values, passwords, keystrokes, or cookies.
 */

interface DOMFeatureVector {
  numForms: number;
  numPasswordFields: number;
  hasLoginForm: boolean;
  hasPaymentForm: boolean;
  paymentFieldCount: number;
  crossOriginFormAction: boolean;
  crossDomainFormActions?: number;
  insecureFormAction: boolean;
  insecureFormActions?: number;
  formActionDomains: string[];
  externalResourceRatio: number;
  externalScriptCount: number;
  totalScriptCount: number;
  hasDataUriScript: boolean;
  brandMismatchDetected: boolean;
  detectedBrandClaim?: string;
  hiddenIframeCount: number;
  suspiciousIframeCount: number;
  title: string;
  origin: string;
  scriptOrigins?: string[];
  iframeOrigins?: string[];
}

interface ExtensionMessage {
  type: string;
  payload?: any;
  url?: string;
}

// High-value brand names frequently impersonated in phishing attacks
const TARGETED_BRANDS = [
  'paypal',
  'microsoft',
  'google',
  'apple',
  'netflix',
  'amazon',
  'bank of america',
  'chase',
  'wellsfargo',
  'citibank',
  'facebook',
  'instagram',
  'dhl',
  'fedex',
  'usps',
  'ups',
];

let lastScanTime = 0;
let lastFeaturesCache: DOMFeatureVector | null = null;
const SCAN_DEBOUNCE_MS = 1500;

/**
 * Inspects page DOM structures passively without touching user data or values.
 */
function harvestDOMFeatures(): DOMFeatureVector {
  const currentOrigin = window.location.origin;
  const currentHost = window.location.hostname.toLowerCase();

  // 1. Password and Login Form presence
  const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]'));
  const numPasswordFields = passwordInputs.length;

  const loginHints = ['username', 'user', 'email', 'login', 'current-password', 'new-password'];
  const hasLoginInput = Array.from(document.querySelectorAll('input')).some((input) => {
    const ac = (input.getAttribute('autocomplete') || '').toLowerCase();
    const name = (input.getAttribute('name') || '').toLowerCase();
    const id = (input.id || '').toLowerCase();
    return loginHints.some((h) => ac.includes(h) || name.includes(h) || id.includes(h));
  });

  const hasLoginForm = numPasswordFields > 0 || (hasLoginInput && document.querySelectorAll('form').length > 0);

  // 2. Payment-related Form Structure
  const paymentHints = [
    'cc-number',
    'cc-csc',
    'cc-exp',
    'cardnumber',
    'cvv',
    'cvc',
    'exp-date',
    'creditcard',
    'card-number',
  ];
  let paymentFieldCount = 0;

  document.querySelectorAll('input, select').forEach((el) => {
    const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
    const name = (el.getAttribute('name') || '').toLowerCase();
    const id = (el.id || '').toLowerCase();
    const placeholder = (el.getAttribute('placeholder') || '').toLowerCase();

    if (
      paymentHints.some(
        (h) => ac.includes(h) || name.includes(h) || id.includes(h) || placeholder.includes(h)
      )
    ) {
      paymentFieldCount++;
    }
  });

  const hasPaymentForm = paymentFieldCount >= 2;

  // 3. Form Destination Inspection
  const forms = Array.from(document.querySelectorAll('form'));
  const numForms = forms.length;

  let crossOriginFormAction = false;
  let crossDomainFormActions = 0;
  let insecureFormAction = false;
  let insecureFormActions = 0;
  const formActionDomains: string[] = [];

  forms.forEach((form) => {
    const rawAction = form.getAttribute('action') || '';
    if (!rawAction) return;

    try {
      const resolved = new URL(rawAction, window.location.href);
      formActionDomains.push(resolved.hostname.toLowerCase());

      if (resolved.origin !== currentOrigin && !resolved.protocol.startsWith('javascript')) {
        crossOriginFormAction = true;
        crossDomainFormActions++;
      }
      if (resolved.protocol === 'http:' && window.location.protocol === 'https:') {
        insecureFormAction = true;
        insecureFormActions++;
      }
    } catch {
      // Ignored for javascript: or invalid targets
    }
  });

  // 4. External scripts and Resource Origins
  const scripts = Array.from(document.querySelectorAll('script[src]'));
  const links = Array.from(document.querySelectorAll('link[rel="stylesheet"][href]'));
  const totalScriptCount = scripts.length;
  let externalScriptCount = 0;
  let hasDataUriScript = false;
  const scriptOrigins: string[] = [];

  scripts.forEach((s) => {
    const src = s.getAttribute('src') || '';
    if (src.startsWith('data:')) {
      hasDataUriScript = true;
    } else {
      try {
        const u = new URL(src, window.location.href);
        scriptOrigins.push(u.origin);
        if (u.hostname.toLowerCase() !== currentHost) {
          externalScriptCount++;
        }
      } catch {}
    }
  });

  let externalStyles = 0;
  links.forEach((l) => {
    const href = l.getAttribute('href');
    if (href) {
      try {
        const u = new URL(href, window.location.href);
        if (u.hostname.toLowerCase() !== currentHost) externalStyles++;
      } catch {}
    }
  });

  const totalResources = totalScriptCount + links.length;
  const totalExternal = externalScriptCount + externalStyles;
  const externalResourceRatio =
    totalResources > 0 ? parseFloat((totalExternal / totalResources).toFixed(2)) : 0.0;

  // 5. Iframe Usage
  const iframes = Array.from(document.querySelectorAll('iframe'));
  let hiddenIframeCount = 0;
  let suspiciousIframeCount = 0;
  const iframeOrigins: string[] = [];

  iframes.forEach((f) => {
    const src = f.getAttribute('src') || '';
    if (src) {
      try {
        const u = new URL(src, window.location.href);
        iframeOrigins.push(u.origin);
      } catch {}
    }

    const style = window.getComputedStyle(f);
    const width = parseFloat(f.getAttribute('width') || style.width || '100');
    const height = parseFloat(f.getAttribute('height') || style.height || '100');

    if (style.display === 'none' || style.visibility === 'hidden' || width <= 1 || height <= 1) {
      hiddenIframeCount++;
    }

    // Check for suspicious overlay iframe covering whole viewport
    if (
      (style.position === 'fixed' || style.position === 'absolute') &&
      width >= window.innerWidth * 0.9 &&
      height >= window.innerHeight * 0.9 &&
      parseFloat(style.opacity || '1') < 0.1
    ) {
      suspiciousIframeCount++;
    }
  });

  // 6. Brand Impersonation in Title vs FQDN
  const pageTitle = (document.title || '').toLowerCase();
  let brandMismatchDetected = false;
  let detectedBrandClaim: string | undefined;

  for (const brand of TARGETED_BRANDS) {
    if (pageTitle.includes(brand) && !currentHost.includes(brand.replace(/\s+/g, ''))) {
      brandMismatchDetected = true;
      detectedBrandClaim = brand;
      break;
    }
  }

  return {
    numForms,
    numPasswordFields,
    hasLoginForm,
    hasPaymentForm,
    paymentFieldCount,
    crossOriginFormAction,
    crossDomainFormActions,
    insecureFormAction,
    insecureFormActions,
    formActionDomains,
    externalResourceRatio,
    externalScriptCount,
    totalScriptCount,
    hasDataUriScript,
    brandMismatchDetected,
    detectedBrandClaim,
    hiddenIframeCount,
    suspiciousIframeCount,
    scriptOrigins,
    iframeOrigins,
    title: document.title.slice(0, 100),
    origin: currentOrigin,
  };
}

/**
 * Dispatches harvested structural features to the background service worker.
 */
function runHarvester(force = false): void {
  const now = Date.now();
  if (!force && lastFeaturesCache && now - lastScanTime < SCAN_DEBOUNCE_MS) {
    return; // Avoid repeated expensive DOM scans
  }

  try {
    const features = harvestDOMFeatures();
    lastScanTime = now;
    lastFeaturesCache = features;

    const message: ExtensionMessage = {
      type: 'DOM_FEATURES_EXTRACTED',
      payload: features,
      url: window.location.href,
    };

    if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage(message).catch(() => {
        // Background service worker might be dormant
      });
    }
  } catch (err) {
    console.debug('[PhishGuard] Harvester passive scan encountered:', err);
  }
}

// Rescan listener for manual user scans from popup
if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
  chrome.runtime.onMessage.addListener((message: ExtensionMessage) => {
    if (message.type === 'RESCAN_DOM_REQUEST') {
      runHarvester(true);
    }
  });
}

// Initial execution at document_idle
if (typeof document !== 'undefined') {
  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    runHarvester();
  } else {
    window.addEventListener('DOMContentLoaded', () => runHarvester(), { once: true });
  }
}
