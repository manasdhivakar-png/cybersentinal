// ═══════════════════════════════════════════════════════
// CYBERSENTINEL — URL & Domain Analyzer Engine
// ═══════════════════════════════════════════════════════

import { BRAND_DOMAINS } from '../data/brandDatabase';

const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz', '.club',
  '.work', '.click', '.link', '.info', '.site', '.online', '.icu',
  '.rest', '.monster', '.best', '.cam', '.space', '.website', '.fun'
];

const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
  'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc',
  'rb.gy', 'short.io', 'v.gd', 'clck.ru', 'lnkd.in'
];

const HOMOGLYPHS = {
  'a': ['а', 'ɑ', 'α', '@'],
  'e': ['е', 'ε', 'ё'],
  'o': ['о', '0', 'ο', 'ø'],
  'i': ['і', '1', 'l', '|', 'ı'],
  'l': ['1', 'I', '|', 'ℓ'],
  'c': ['с', 'ϲ'],
  'p': ['р', 'ρ'],
  's': ['ѕ', '$', '5'],
  't': ['τ', '+'],
  'n': ['ñ', 'η'],
  'g': ['ɡ', '9'],
  'u': ['υ', 'ü'],
  'd': ['ԁ', 'ɗ'],
  'b': ['Ь', 'ƅ'],
  'r': ['г', 'ɾ'],
  'w': ['ω', 'ш'],
  'm': ['rn', 'ⅿ'],
};

function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i-1] === b[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    }
  }
  return dp[m][n];
}

function extractDomain(url) {
  try {
    const u = new URL(url.startsWith('http') ? url : `https://${url}`);
    return u.hostname.toLowerCase();
  } catch {
    return url.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
  }
}

function extractPath(url) {
  try {
    const u = new URL(url.startsWith('http') ? url : `https://${url}`);
    return u.pathname + u.search;
  } catch {
    return '';
  }
}

function checkHomoglyphs(domain) {
  const findings = [];
  for (const [real, fakes] of Object.entries(HOMOGLYPHS)) {
    for (const fake of fakes) {
      if (domain.includes(fake)) {
        findings.push(`Contains homoglyph: "${fake}" resembles "${real}"`);
      }
    }
  }
  return findings;
}

function checkTyposquatting(domain) {
  const cleanDomain = domain.replace(/\.(com|net|org|co|in|io|app|dev).*$/, '').replace(/www\./, '');
  const matches = [];

  for (const brand of BRAND_DOMAINS) {
    const dist = levenshtein(cleanDomain, brand.name.toLowerCase());
    if (dist > 0 && dist <= 3) {
      matches.push({
        brand: brand.name,
        distance: dist,
        severity: dist === 1 ? 'critical' : dist === 2 ? 'high' : 'medium'
      });
    }
    // Check if domain contains brand name with additions
    if (cleanDomain.includes(brand.name.toLowerCase()) && cleanDomain !== brand.name.toLowerCase()) {
      matches.push({
        brand: brand.name,
        distance: 0,
        severity: 'high',
        note: 'Domain contains brand name with modifications'
      });
    }
  }

  return matches.sort((a, b) => a.distance - b.distance).slice(0, 5);
}

export function analyzeURL(url) {
  if (!url || url.trim().length === 0) {
    return {
      score: 0, indicators: [], domain: '', isHTTPS: true, entropy: 0,
      typosquatting: [], homoglyphs: [], isSuspiciousTLD: false,
      isIPBased: false, isShortener: false, hasAtSign: false,
      suspiciousParams: false, summary: '',
      signals: []
    };
  }

  const indicators = [];
  const signals = [];
  let score = 0;
  const domain = extractDomain(url);
  const path = extractPath(url);
  const cleanDomain = domain.replace(/\.(com|net|org|co|in|io|app|dev).*$/, '').replace(/www\./, '');

  // HTTPS check
  const isHTTPS = url.startsWith('https://') || !url.startsWith('http://');
  if (url.startsWith('http://')) {
    indicators.push('No HTTPS encryption');
    signals.push({ type: 'no_https', description: 'Connection not secure', severity: 'medium' });
    score += 10;
  }

  // IP-based URL
  const isIPBased = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain);
  if (isIPBased) {
    indicators.push('IP-based URL (no domain name)');
    signals.push({ type: 'ip_based', description: 'Using IP address instead of domain name', severity: 'high' });
    score += 40;
  }

  // Suspicious TLD
  const isSuspiciousTLD = SUSPICIOUS_TLDS.some(tld => domain.endsWith(tld));
  if (isSuspiciousTLD) {
    const tld = domain.split('.').pop();
    indicators.push(`Suspicious TLD: .${tld}`);
    signals.push({ type: 'suspicious_tld', description: `Using high-risk top-level domain (.${tld})`, severity: 'high' });
    score += 25;
  }

  // URL shortener
  const isShortener = URL_SHORTENERS.some(s => domain.includes(s));
  if (isShortener) {
    indicators.push('URL shortener (hides real destination)');
    signals.push({ type: 'url_shortener', description: 'Hiding destination using URL shortener', severity: 'medium' });
    score += 20;
  }

  // @ sign in URL (used to hide real destination)
  const hasAtSign = url.includes('@');
  if (hasAtSign) {
    indicators.push('Contains @ sign (may redirect to different domain)');
    signals.push({ type: 'at_sign', description: 'URL redirection trick using @ sign', severity: 'high' });
    score += 20;
  }

  // Shannon entropy
  const entropy = shannonEntropy(domain);
  if (entropy > 4.0) {
    indicators.push(`High domain entropy: ${entropy} (possibly randomly generated)`);
    signals.push({ type: 'high_entropy', description: 'Domain name appears randomly generated', severity: 'medium' });
    score += 10;
  }

  // Excessive subdomains
  const subdomainCount = domain.split('.').length - 2;
  if (subdomainCount > 2) {
    indicators.push(`Excessive subdomains (${subdomainCount + 1} levels)`);
    signals.push({ type: 'excessive_subdomains', description: 'Multiple subdomains to confuse user', severity: 'medium' });
    score += 5;
  }

  // Suspicious path patterns
  const suspiciousParams = /\b(login|signin|verify|confirm|secure|account|update|bank|password|credential)\b/i.test(path);
  if (suspiciousParams) {
    indicators.push('URL path contains suspicious keywords');
    signals.push({ type: 'suspicious_path', description: 'Path contains credential harvesting keywords', severity: 'medium' });
    score += 10;
  }

  // Long URL
  if (url.length > 150) {
    indicators.push('Abnormally long URL');
    signals.push({ type: 'long_url', description: 'URL is abnormally long to hide actual domain', severity: 'low' });
    score += 5;
  }

  // Homoglyphs
  const homoglyphs = checkHomoglyphs(domain);
  if (homoglyphs.length > 0) {
    indicators.push(...homoglyphs);
    signals.push({ type: 'homoglyph', description: 'Domain uses visually similar characters (Homoglyphs) to trick users', severity: 'critical' });
    score += 50;
  }

  // Brand Impersonation (Typosquatting & Subdomain Spoofing)
  const typosquatting = checkTyposquatting(domain);
  let hasBrandImpersonation = false;
  if (typosquatting.length > 0) {
    const best = typosquatting[0];
    // Check if it's an exact match on a brand but not the official domain (e.g. netflix.login.com)
    if (best.distance === 0) {
      indicators.push(`Brand spoofing: Impersonating "${best.brand}" in domain structure`);
      signals.push({ type: 'subdomain_spoof', description: `Impersonating ${best.brand} using subdomains/paths`, severity: 'critical' });
      score += 60;
      hasBrandImpersonation = true;
    } else {
      indicators.push(`Possible typosquatting of "${best.brand}" (edit distance: ${best.distance})`);
      signals.push({ type: 'brand_spoof', description: `Typosquatting: Domain looks like ${best.brand}`, severity: 'critical' });
      score += 60;
      hasBrandImpersonation = true;
    }
  }

  // Multiple hyphens
  if ((domain.match(/-/g) || []).length > 2) {
    indicators.push('Multiple hyphens in domain (common in phishing)');
    signals.push({ type: 'multiple_hyphens', description: 'Multiple hyphens used to mimic legitimate domains', severity: 'medium' });
    score += 5;
  }

  // Number-heavy domain
  if (/\d{4,}/.test(domain)) {
    indicators.push('Domain contains long numeric sequences');
    signals.push({ type: 'numeric_domain', description: 'Domain contains suspicious numeric sequences', severity: 'medium' });
    score += 5;
  }

  let level = "LOW";
  let verdict = "Clean";
  let intent = "None";

  if (score >= 70) {
    level = "CRITICAL";
    verdict = hasBrandImpersonation ? "Brand Impersonation Phishing" : "High-Risk Threat";
    intent = "Credential Harvesting / Malware";
  } else if (score >= 40) {
    level = "HIGH";
    verdict = "Suspicious Link";
    intent = "Possible Phishing / Spam";
  } else if (score >= 20) {
    level = "MEDIUM";
    verdict = "Low Reputation Link";
    intent = "Spam / Adware";
  }

  score = Math.min(100, score);

  return {
    score,
    level,
    verdict,
    intent,
    indicators,
    signals,
    domain,
    isHTTPS,
    entropy,
    typosquatting,
    homoglyphs,
    isSuspiciousTLD,
    isIPBased,
    isShortener,
    hasAtSign,
    suspiciousParams,
    summary: indicators.length > 0
      ? `${indicators.length} URL risk indicator(s) detected`
      : 'URL appears clean'
  };
}

export function extractURLs(text) {
  const urlRegex = /https?:\/\/[^\s<>"')\]]+|www\.[^\s<>"')\]]+/gi;
  return (text.match(urlRegex) || []).map(u => u.replace(/[.,;:!?]+$/, ''));
}
