export const SITE = {
  name: 'CertKit',
  tagline: 'Certificate tools that never see your keys',
  url: 'https://localcertkit.pages.dev',
} as const;

/**
 * Open-source repository link. Placeholder until the repo is published:
 * when set, the trust section and footer become real links.
 */
export const REPO_URL = 'https://github.com/pantha704/localcertkit';

/**
 * Reserved slot for a future certificate-provider affiliate partner.
 * Unused in v1 — CertKit ships with zero affiliate links.
 */
export const AFFILIATE_CERT_SLOT = '';

export interface ToolLink {
  href: string;
  label: string;
  blurb: string;
}

export const TOOLS: ToolLink[] = [
  {
    href: '/pfx-to-pem/',
    label: 'PFX → PEM',
    blurb: 'Extract the private key and certificate chain from a .pfx / .p12 file.',
  },
  {
    href: '/pem-to-pfx/',
    label: 'PEM → PFX',
    blurb: 'Build a password-protected .pfx / .p12 from a key and certificates.',
  },
  {
    href: '/certificate-decoder/',
    label: 'Certificate decoder',
    blurb: 'Subject, issuer, SANs, validity, serial, signature algorithm — PEM or DER.',
  },
  {
    href: '/csr-decoder/',
    label: 'CSR decoder',
    blurb: 'Read a signing request: subject, SANs, key info, signature check.',
  },
  {
    href: '/key-cert-match/',
    label: 'Key ↔ certificate match',
    blurb: 'Check whether this private key really belongs to this certificate.',
  },
  {
    href: '/chain-order/',
    label: 'Chain order',
    blurb: 'Sort certificates leaf → intermediate → root and find missing issuers.',
  },
  {
    href: '/der-jwk-inspector/',
    label: 'DER & JWK inspector',
    blurb: 'Inspect DER certificates and JWK / JWK-set JSON without verifying claims.',
  },
];

export const NAV = [
  { href: '/', label: 'Home' },
  { href: '/#tools', label: 'Tools' },
  { href: '/roadmap/', label: 'Roadmap' },
  { href: '/privacy/', label: 'Privacy' },
  { href: '/about/', label: 'About' },
];

/** schema.org WebApplication block shared by every tool page. */
export function toolJsonLd(opts: {
  name: string;
  description: string;
  path: string;
}): Record<string, unknown> {
  return {
    '@context': 'https://schema.org',
    '@type': 'WebApplication',
    name: `${opts.name} — ${SITE.name}`,
    url: `${SITE.url}${opts.path}`,
    applicationCategory: 'UtilitiesApplication',
    operatingSystem: 'Any modern browser',
    browserRequirements: 'Requires JavaScript. Processes files locally; no upload.',
    description: opts.description,
    offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
    isAccessibleForFree: true,
    privacyPolicy: `${SITE.url}/privacy/`,
    publisher: { '@type': 'Organization', name: SITE.name, url: SITE.url },
  };
}
