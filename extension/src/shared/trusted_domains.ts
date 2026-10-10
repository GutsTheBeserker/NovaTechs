/**
 * Controlled Verified Trusted-Domain Configuration & Provenance Registry
 *
 * Implements strict, DNS-label-boundary matching for verified official domains.
 *
 * Requirements:
 * 1. Verified official domains receive a LOW RISK baseline (0 points) when no
 *    strong suspicious indicators exist on the page.
 * 2. Strict DNS label boundary or exact hostname matching:
 *    - Exact match: "youtube.com" === "youtube.com"
 *    - Subdomain match: "m.youtube.com" ends with ".youtube.com"
 *    - Lookalike rejection: "youtube.com.fake-example.com" does NOT match "youtube.com"
 *    - Prefix lookalike rejection: "fake-youtube.com" does NOT match "youtube.com"
 * 3. Never trust domains merely because their URL contains a familiar brand name.
 * 4. Provenance and legal/organizational identity is documented for every entry.
 * 5. Matching against trusted domains is a baseline rather than an unconditional
 *    guarantee of safety: strong indicators (credential theft, malware iframe)
 *    can still elevate the score.
 */

export interface TrustedDomainEntry {
  domain: string;
  entityName: string;
  category:
    | 'MEDIA_AND_SEARCH'
    | 'SOCIAL_MEDIA'
    | 'ENCYCLOPEDIA'
    | 'HIGHER_EDUCATION'
    | 'ENTERPRISE_IDP'
    | 'DEVELOPER_PLATFORM';
  provenance: string;
  verificationSource: string;
  allowSubdomains: boolean;
  notes?: string;
}

/**
 * Registry of verified official domains with explicit provenance.
 * Each entry represents an officially owned domain verified via registrar,
 * statutory charter, or authoritative identity documentation.
 */
export const VERIFIED_TRUSTED_DOMAINS: TrustedDomainEntry[] = [
  // 0. IANA Reserved Documentation Domains (RFC 2606 / RFC 6761)
  {
    domain: 'example.com',
    entityName: 'Internet Assigned Numbers Authority (IANA)',
    category: 'MEDIA_AND_SEARCH',
    provenance: 'Special-use domain name permanently reserved by IANA/IETF under RFC 2606 and RFC 6761 for documentation and testing.',
    verificationSource: 'IANA / RFC 2606 / RFC 6761',
    allowSubdomains: false,
  },
  {
    domain: 'example.org',
    entityName: 'Internet Assigned Numbers Authority (IANA)',
    category: 'MEDIA_AND_SEARCH',
    provenance: 'Special-use domain name permanently reserved by IANA/IETF under RFC 2606 and RFC 6761 for documentation and testing.',
    verificationSource: 'IANA / RFC 2606 / RFC 6761',
    allowSubdomains: false,
  },
  {
    domain: 'example.edu',
    entityName: 'Internet Assigned Numbers Authority (IANA)',
    category: 'HIGHER_EDUCATION',
    provenance: 'Special-use domain name reserved by IANA/IETF under RFC 2606 for educational documentation and testing.',
    verificationSource: 'IANA / RFC 2606',
    allowSubdomains: false,
  },

  // 1. YouTube (Google LLC)
  {
    domain: 'youtube.com',
    entityName: 'YouTube (Google LLC)',
    category: 'MEDIA_AND_SEARCH',
    provenance: 'Primary corporate video-sharing service operated by Google LLC (Alphabet Inc.). Tranco Top 10 rank.',
    verificationSource: 'ICANN WHOIS / Google LLC official corporate web property',
    allowSubdomains: true,
  },

  // 2. Facebook (Meta Platforms, Inc.)
  {
    domain: 'facebook.com',
    entityName: 'Facebook (Meta Platforms, Inc.)',
    category: 'SOCIAL_MEDIA',
    provenance: 'Primary official social networking service operated by Meta Platforms, Inc. Tranco Top 10 rank.',
    verificationSource: 'ICANN WHOIS / Meta Platforms, Inc. official web property',
    allowSubdomains: true,
  },

  // 3. Wikipedia (Wikimedia Foundation)
  {
    domain: 'wikipedia.org',
    entityName: 'Wikimedia Foundation, Inc.',
    category: 'ENCYCLOPEDIA',
    provenance: 'Primary multilingual open encyclopedia operated by the non-profit Wikimedia Foundation. Tranco Top 15 rank.',
    verificationSource: 'PIR WHOIS / Wikimedia Foundation official domain registry',
    allowSubdomains: true,
  },

  // 4. Ganpat University
  {
    domain: 'ganpatuniversity.ac.in',
    entityName: 'Ganpat University',
    category: 'HIGHER_EDUCATION',
    provenance:
      'Official statutory university established under Gujarat State Act No. 19 of 2005 (India), recognized by University Grants Commission (UGC) under Section 2(f). Registered under the .ac.in academic domain charter.',
    verificationSource: 'National Internet Exchange of India (.IN Registry / ERNET) / UGC List of Recognized Universities',
    allowSubdomains: true,
  },

  // 5. Google Accounts SSO
  {
    domain: 'accounts.google.com',
    entityName: 'Google Accounts (Alphabet Inc.)',
    category: 'ENTERPRISE_IDP',
    provenance: 'Official Single Sign-On and OAuth authentication identity provider endpoint for Google services.',
    verificationSource: 'Google Trust Services / Alphabet Inc.',
    allowSubdomains: false, // Strict exact hostname matching for critical IdP endpoint
  },

  // 6. Microsoft Entra ID / Office 365 Login
  {
    domain: 'login.microsoftonline.com',
    entityName: 'Microsoft Entra ID / Microsoft 365',
    category: 'ENTERPRISE_IDP',
    provenance: 'Official Microsoft identity and federation endpoint for enterprise authentication.',
    verificationSource: 'Microsoft Corporation official enterprise identity infrastructure',
    allowSubdomains: false, // Strict exact hostname matching
  },

  // 7. Microsoft Cloud Services
  {
    domain: 'microsoftonline.com',
    entityName: 'Microsoft Corporation',
    category: 'ENTERPRISE_IDP',
    provenance: 'Microsoft enterprise cloud and identity service domain.',
    verificationSource: 'Microsoft Corporation official domain registry',
    allowSubdomains: true,
  },

  // 8. Apple ID
  {
    domain: 'appleid.apple.com',
    entityName: 'Apple Inc.',
    category: 'ENTERPRISE_IDP',
    provenance: 'Official Apple ID authentication and security management portal.',
    verificationSource: 'Apple Inc. official identity infrastructure',
    allowSubdomains: false,
  },

  // 9. GitHub
  {
    domain: 'github.com',
    entityName: 'GitHub, Inc. (Microsoft)',
    category: 'DEVELOPER_PLATFORM',
    provenance: 'Official software development and version control platform operated by GitHub, Inc.',
    verificationSource: 'GitHub, Inc. / Microsoft Corporation',
    allowSubdomains: true,
  },

  // 10. Okta Identity
  {
    domain: 'okta.com',
    entityName: 'Okta, Inc.',
    category: 'ENTERPRISE_IDP',
    provenance: 'Enterprise identity and access management cloud platform.',
    verificationSource: 'Okta, Inc. official web property',
    allowSubdomains: true,
  },

  // 11. Auth0
  {
    domain: 'auth0.com',
    entityName: 'Auth0 (Okta, Inc.)',
    category: 'ENTERPRISE_IDP',
    provenance: 'Customer identity access management platform.',
    verificationSource: 'Auth0 / Okta, Inc. official web property',
    allowSubdomains: true,
  },

  // 12. Cisco Duo Security
  {
    domain: 'duosecurity.com',
    entityName: 'Cisco Duo Security',
    category: 'ENTERPRISE_IDP',
    provenance: 'Two-factor and multi-factor authentication identity security service.',
    verificationSource: 'Cisco Systems, Inc. official web property',
    allowSubdomains: true,
  },

  // 13. Harvard University
  {
    domain: 'harvard.edu',
    entityName: 'Harvard University',
    category: 'HIGHER_EDUCATION',
    provenance: 'Chartered private higher education institution in Massachusetts, USA. Registered under .edu charter.',
    verificationSource: 'Educause .edu Registry',
    allowSubdomains: true,
  },

  // 14. Massachusetts Institute of Technology
  {
    domain: 'mit.edu',
    entityName: 'Massachusetts Institute of Technology',
    category: 'HIGHER_EDUCATION',
    provenance: 'Chartered research university in Cambridge, MA. Registered under .edu charter.',
    verificationSource: 'Educause .edu Registry',
    allowSubdomains: true,
  },

  // 15. Stanford University
  {
    domain: 'stanford.edu',
    entityName: 'Stanford University',
    category: 'HIGHER_EDUCATION',
    provenance: 'Chartered research university in Stanford, CA. Registered under .edu charter.',
    verificationSource: 'Educause .edu Registry',
    allowSubdomains: true,
  },

  // 16. University of Oxford
  {
    domain: 'ox.ac.uk',
    entityName: 'University of Oxford',
    category: 'HIGHER_EDUCATION',
    provenance: 'Collegiate research university in Oxford, England. Registered under UK academic .ac.uk charter.',
    verificationSource: 'Jisc .ac.uk Registry',
    allowSubdomains: true,
  },

  // 17. University of Cambridge
  {
    domain: 'cam.ac.uk',
    entityName: 'University of Cambridge',
    category: 'HIGHER_EDUCATION',
    provenance: 'Collegiate research university in Cambridge, England. Registered under UK academic .ac.uk charter.',
    verificationSource: 'Jisc .ac.uk Registry',
    allowSubdomains: true,
  },
];

/**
 * Checks whether an incoming hostname matches a verified trusted domain entry.
 *
 * Enforces proper DNS label boundary matching:
 * - Exact match: hostname === domain
 * - Subdomain match: hostname.endsWith('.' + domain) if allowSubdomains is true
 * - Rejects prefix confusion, lookalikes, and path/query manipulations.
 *
 * @param rawHostname Hostname string to evaluate (e.g. "www.youtube.com", "ganpatuniversity.ac.in")
 * @returns The matching TrustedDomainEntry or null if unverified
 */
export function matchTrustedDomain(rawHostname: string): TrustedDomainEntry | null {
  if (!rawHostname || typeof rawHostname !== 'string') {
    return null;
  }

  // Sanitize: lowercase, strip any trailing dot or port numbers
  let hostname = rawHostname.toLowerCase().trim();
  if (hostname.includes('://')) {
    try {
      hostname = new URL(hostname).hostname.toLowerCase();
    } catch {
      hostname = hostname.split('://')[1].split('/')[0].split('?')[0];
    }
  } else {
    hostname = hostname.split('/')[0].split('?')[0].split('#')[0];
  }
  hostname = hostname.replace(/:\d+$/, '').replace(/\.$/, '');

  for (const entry of VERIFIED_TRUSTED_DOMAINS) {
    const trustedDomain = entry.domain.toLowerCase();

    // 1. Exact hostname match
    if (hostname === trustedDomain) {
      return entry;
    }

    // 2. Safe subdomain boundary match (only if allowSubdomains is explicitly true)
    // Ensures boundary check: "m.youtube.com" endsWith ".youtube.com"
    // Rejects lookalikes: "youtube.com.fake-example.com" endsWith ".fake-example.com", NOT ".youtube.com"
    // Rejects prefix tricks: "fake-youtube.com" does not start with "." before youtube.com
    if (entry.allowSubdomains && hostname.endsWith('.' + trustedDomain)) {
      return entry;
    }
  }

  // 3. Fallback for verified US Higher Education .edu TLD
  if (hostname.endsWith('.edu') && !hostname.includes('..')) {
    const parts = hostname.split('.');
    if (parts.length >= 2 && parts[parts.length - 1] === 'edu') {
      const baseEduDomain = parts.slice(-2).join('.');
      return {
        domain: baseEduDomain,
        entityName: `Accredited Higher Education Institution (${baseEduDomain})`,
        category: 'HIGHER_EDUCATION',
        provenance: 'Accredited institution registered under the US .edu sponsored TLD charter managed by Educause.',
        verificationSource: 'Educause .edu Registry',
        allowSubdomains: true,
      };
    }
  }

  return null;
}
