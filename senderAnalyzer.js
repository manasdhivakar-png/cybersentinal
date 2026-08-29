// ═══════════════════════════════════════════════════════
// CYBERSENTINEL — Sender & Identity Analyzer
// ═══════════════════════════════════════════════════════

import { findBrandByDomain, isFreeEmailProvider } from '../data/brandDatabase';

export function analyzeSender(senderEmail, claimedIdentity = '', messageContent = '') {
  if (!senderEmail && !claimedIdentity) {
    return { score: 0, indicators: [], domain: '', claimedBrand: null, actualBrand: null, isSpoofed: false, summary: '' };
  }

  const indicators = [];
  let score = 0;

  // Extract domain from email
  const emailParts = (senderEmail || '').split('@');
  const domain = emailParts[1] || '';
  const localPart = emailParts[0] || '';

  // Check if domain matches a known brand
  const actualBrand = findBrandByDomain(domain);

  // Check claimed identity against actual domain
  let claimedBrand = null;
  const claimedLower = (claimedIdentity || messageContent).toLowerCase();
  const brandKeywords = [
    { keywords: ['sbi', 'state bank'], brand: 'SBI' },
    { keywords: ['hdfc'], brand: 'HDFC' },
    { keywords: ['icici'], brand: 'ICICI' },
    { keywords: ['axis bank'], brand: 'Axis' },
    { keywords: ['google'], brand: 'Google' },
    { keywords: ['microsoft', 'windows', 'outlook'], brand: 'Microsoft' },
    { keywords: ['apple', 'icloud', 'iphone'], brand: 'Apple' },
    { keywords: ['amazon'], brand: 'Amazon' },
    { keywords: ['paypal'], brand: 'PayPal' },
    { keywords: ['facebook', 'meta'], brand: 'Facebook' },
    { keywords: ['instagram'], brand: 'Instagram' },
    { keywords: ['whatsapp'], brand: 'WhatsApp' },
    { keywords: ['netflix'], brand: 'Netflix' },
    { keywords: ['flipkart'], brand: 'Flipkart' },
    { keywords: ['paytm'], brand: 'Paytm' },
    { keywords: ['phonepe'], brand: 'PhonePe' },
    { keywords: ['jio'], brand: 'Jio' },
    { keywords: ['airtel'], brand: 'Airtel' },
    { keywords: ['income tax', 'it department'], brand: 'Income Tax Dept' },
    { keywords: ['aadhaar', 'uidai'], brand: 'UIDAI/Aadhaar' },
    { keywords: ['epfo', 'provident fund', 'pf'], brand: 'EPFO' },
    { keywords: ['fedex'], brand: 'FedEx' },
    { keywords: ['dhl'], brand: 'DHL' },
    { keywords: ['police', 'cyber cell', 'cbi'], brand: 'Law Enforcement' },
    { keywords: ['rbi', 'reserve bank'], brand: 'RBI' },
  ];

  for (const bk of brandKeywords) {
    if (bk.keywords.some(kw => claimedLower.includes(kw))) {
      claimedBrand = bk.brand;
      break;
    }
  }

  // Mismatch detection
  const isSpoofed = claimedBrand && !actualBrand;
  if (isSpoofed) {
    indicators.push(`Claims to be "${claimedBrand}" but sent from "${domain}" — possible impersonation`);
    score += 35;
  }

  if (claimedBrand && actualBrand && claimedBrand.toLowerCase() !== actualBrand.name.toLowerCase()) {
    indicators.push(`Claims to be "${claimedBrand}" but domain belongs to "${actualBrand.name}"`);
    score += 30;
  }

  // Free email provider for business claims
  if (isFreeEmailProvider(domain)) {
    if (claimedBrand) {
      indicators.push(`Uses free email provider (${domain}) while claiming to be "${claimedBrand}"`);
      score += 25;
    }
    // Check if local part tries to look official
    const officialPatterns = /^(support|admin|security|help|info|noreply|service|team|alert|notification|update|verify)/i;
    if (officialPatterns.test(localPart)) {
      indicators.push(`Email uses official-sounding prefix "${localPart}" on free email domain`);
      score += 20;
    }
  }

  // Suspicious local part patterns
  if (/^[a-z]{2,3}\d{6,}$/i.test(localPart)) {
    indicators.push('Email local part appears auto-generated');
    score += 10;
  }

  // Suspicious domain patterns
  if (domain.includes('-') && domain.split('-').length > 2) {
    indicators.push('Sender domain contains multiple hyphens (common in phishing)');
    score += 10;
  }

  // Display name spoofing (name says one thing, email says another)
  if (claimedIdentity && senderEmail) {
    const nameLower = claimedIdentity.toLowerCase();
    if (!domain.includes(nameLower.split(' ')[0]) && claimedBrand) {
      indicators.push(`Display name "${claimedIdentity}" doesn't match sender domain "${domain}"`);
      score += 15;
    }
  }

  score = Math.min(100, score);

  return {
    score,
    indicators,
    domain,
    localPart,
    claimedBrand,
    actualBrand: actualBrand?.name || null,
    isSpoofed,
    isFreeEmail: isFreeEmailProvider(domain),
    summary: indicators.length > 0
      ? `${indicators.length} sender identity concern(s) detected`
      : 'Sender identity appears consistent'
  };
}
