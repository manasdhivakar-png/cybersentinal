// ═══════════════════════════════════════════════════════
// CYBERSENTINEL — NLP & Intent Analyzer Engine
// Social Engineering Detection via Pattern Matching
// ═══════════════════════════════════════════════════════

const URGENCY_KEYWORDS = [
  'urgent', 'immediately', 'right now', 'asap', 'hurry', 'quick', 'fast',
  'within 24 hours', 'last chance', 'final warning', 'act now', 'don\'t delay',
  'time sensitive', 'expires', 'deadline', 'suspend', 'terminated', 'deactivat',
  'limited time', 'closing', 'last day', 'emergency', 'critical', 'important update',
  'உடனடியாக', 'அவசரம்', 'तुरंत', 'जल्दी', 'వెంటనే', 'ఆలస్యం', 'ഉടനെ', 'ತಕ್ಷಣ'
];

const FEAR_KEYWORDS = [
  'suspend', 'block', 'lock', 'disable', 'unauthorized', 'breach', 'hack',
  'compromis', 'stolen', 'fraud', 'illegal', 'violation', 'penalty', 'fine',
  'arrest', 'legal action', 'court', 'police', 'jail', 'warrant', 'criminal',
  'seized', 'frozen', 'restricted', 'threat', 'risk', 'danger', 'warning',
  'நிறுத்தப்படும்', 'தடை', 'अवरुद्ध', 'ब्लॉक', 'నిలిపివేయబడుతుంది', 'ബ്ലോക്ക്', 'ನಿರ್ಬಂಧ'
];

const AUTHORITY_KEYWORDS = [
  'bank', 'rbi', 'government', 'ministry', 'income tax', 'police', 'court',
  'sbi', 'hdfc', 'icici', 'axis', 'reserve bank', 'cyber cell', 'cbi',
  'custom', 'immigration', 'aadhaar', 'pan card', 'passport', 'it department',
  'microsoft', 'google', 'apple', 'amazon', 'paypal', 'security team',
  'admin', 'support', 'helpdesk', 'official', 'verified', 'certified',
  'வங்கி', 'அரசு', 'காவல்', 'बैंक', 'सरकार', 'पुलिस', 'బ్యాంకు', 'ప్రభుత్వం', 'ബാങ്ക്', 'ಬ್ಯಾಂಕ್'
];

const REWARD_KEYWORDS = [
  'won', 'winner', 'prize', 'lottery', 'reward', 'cashback', 'free',
  'congratulations', 'selected', 'lucky', 'offer', 'discount', 'gift',
  'earn', 'income', 'profit', 'investment', 'return', 'guaranteed',
  'double', 'triple', 'bonus', 'claim', 'redeem', 'exclusive',
  'வெற்றி', 'பரிசு', 'इनाम', 'जीत', 'బహుమతి', 'സമ്മാനം', 'ಬಹುಮಾನ'
];

const CREDENTIAL_KEYWORDS = [
  'otp', 'password', 'pin', 'cvv', 'card number', 'account number',
  'social security', 'ssn', 'aadhaar', 'pan', 'login', 'credential',
  'verify your', 'confirm your', 'update your', 'enter your', 'provide your',
  'bank details', 'upi', 'upi pin', 'net banking', 'debit card', 'credit card',
  'கடவுச்சொல்', 'ரகசிய எண்', 'पासवर्ड', 'పాస్‌వర్డ్', 'പാസ്‌വേഡ്', 'ಪಾಸ್‌ವರ್ಡ್'
];

const FINANCIAL_KEYWORDS = [
  'transfer', 'send money', 'pay', 'payment', 'transaction', 'wire',
  'deposit', 'withdraw', 'rupees', 'dollars', 'bitcoin', 'crypto',
  'account', 'bank account', 'wallet', 'upi', 'gpay', 'phonepe', 'paytm',
  'பணம்', 'ரூபாய்', 'पैसा', 'रुपये', 'డబ్బు', 'പണം', 'ಹಣ'
];

const CTA_PATTERNS = [
  /click\s*(here|now|below|this|the\s*link)/i,
  /tap\s*(here|now|below)/i,
  /open\s*(this|the)\s*link/i,
  /visit\s*(this|the)\s*(link|url|website|page)/i,
  /go\s*to\s*(this|the)/i,
  /download\s*(now|here|this|the)/i,
  /install\s*(now|this|the)/i,
  /call\s*(now|this\s*number|us|immediately)/i,
  /reply\s*(now|with|yes|to)/i,
  /verify\s*(now|here|your)/i,
  /confirm\s*(now|here|your)/i,
  /update\s*(now|here|your)/i,
  /login\s*(here|now|to)/i,
  /sign\s*in\s*(here|now)/i,
];

const IMPERSONATION_PATTERNS = [
  { pattern: /dear\s*(customer|user|member|sir|madam|valued)/i, label: 'Generic greeting' },
  { pattern: /from\s*:\s*.*security.*@.*\.(tk|xyz|top|ml|ga|cf|gq)/i, label: 'Suspicious sender domain' },
  { pattern: /team\s*@|support\s*@|admin\s*@|security\s*@|alert\s*@|noreply\s*@/i, label: 'Service impersonation' },
  { pattern: /your\s*account\s*(has been|will be|is being)/i, label: 'Account threat narrative' },
];

function countKeywordMatches(text, keywords) {
  const lower = text.toLowerCase();
  let count = 0;
  const matched = [];
  for (const kw of keywords) {
    if (lower.includes(kw.toLowerCase())) {
      count++;
      matched.push(kw);
    }
  }
  return { count, matched };
}

function countPatternMatches(text, patterns) {
  let count = 0;
  const matched = [];
  for (const p of patterns) {
    const pat = p.pattern || p;
    const label = p.label || pat.toString();
    if (pat.test(text)) {
      count++;
      matched.push(label);
    }
  }
  return { count, matched };
}

function clamp(val, min = 0, max = 100) {
  return Math.max(min, Math.min(max, val));
}

function scoreFromCount(count, maxForFull = 4) {
  return clamp(Math.round((count / maxForFull) * 100));
}

export function analyzeNLP(text) {
  if (!text || text.trim().length === 0) {
    return {
      urgency: { score: 0, indicators: [] },
      fear: { score: 0, indicators: [] },
      authority: { score: 0, indicators: [] },
      reward: { score: 0, indicators: [] },
      credential: { score: 0, indicators: [] },
      financial: { score: 0, indicators: [] },
      callToAction: { score: 0, indicators: [] },
      impersonation: { score: 0, indicators: [] },
      overallManipulation: 0,
      detectedTactics: [],
      summary: ''
    };
  }

  const urgency = countKeywordMatches(text, URGENCY_KEYWORDS);
  const fear = countKeywordMatches(text, FEAR_KEYWORDS);
  const authority = countKeywordMatches(text, AUTHORITY_KEYWORDS);
  const reward = countKeywordMatches(text, REWARD_KEYWORDS);
  const credential = countKeywordMatches(text, CREDENTIAL_KEYWORDS);
  const financial = countKeywordMatches(text, FINANCIAL_KEYWORDS);
  const cta = countPatternMatches(text, CTA_PATTERNS);
  const impersonation = countPatternMatches(text, IMPERSONATION_PATTERNS);

  const uppercaseRatio = (text.replace(/[^A-Z]/g, '').length / Math.max(text.replace(/\s/g, '').length, 1));
  const exclamationCount = (text.match(/!/g) || []).length;
  const hasMultipleUrls = (text.match(/https?:\/\//g) || []).length > 1;

  const scores = {
    urgency: { score: scoreFromCount(urgency.count, 3), indicators: urgency.matched },
    fear: { score: scoreFromCount(fear.count, 3), indicators: fear.matched },
    authority: { score: scoreFromCount(authority.count, 2), indicators: authority.matched },
    reward: { score: scoreFromCount(reward.count, 3), indicators: reward.matched },
    credential: { score: scoreFromCount(credential.count, 2), indicators: credential.matched },
    financial: { score: scoreFromCount(financial.count, 3), indicators: financial.matched },
    callToAction: { score: scoreFromCount(cta.count, 2), indicators: cta.matched },
    impersonation: { score: scoreFromCount(impersonation.count, 2), indicators: impersonation.matched },
  };

  // Bonus scoring
  if (uppercaseRatio > 0.3) scores.urgency.score = clamp(scores.urgency.score + 20);
  if (exclamationCount > 3) scores.urgency.score = clamp(scores.urgency.score + 15);
  if (hasMultipleUrls) scores.callToAction.score = clamp(scores.callToAction.score + 20);

  // Credential + urgency combo = very suspicious
  if (scores.credential.score > 40 && scores.urgency.score > 40) {
    scores.credential.score = clamp(scores.credential.score + 25);
  }

  const detectedTactics = [];
  if (scores.urgency.score >= 50) detectedTactics.push('Urgency Pressure');
  if (scores.fear.score >= 50) detectedTactics.push('Fear/Threat Tactics');
  if (scores.authority.score >= 50) detectedTactics.push('Authority Manipulation');
  if (scores.reward.score >= 50) detectedTactics.push('Reward/Lure Bait');
  if (scores.credential.score >= 50) detectedTactics.push('Credential Harvesting');
  if (scores.financial.score >= 50) detectedTactics.push('Financial Request');
  if (scores.callToAction.score >= 50) detectedTactics.push('Suspicious Call-to-Action');
  if (scores.impersonation.score >= 50) detectedTactics.push('Possible Impersonation');

  const allScores = Object.values(scores).map(s => s.score);
  const overallManipulation = clamp(Math.round(
    allScores.reduce((a, b) => a + b, 0) / allScores.length * 1.3
  ));

  return {
    ...scores,
    overallManipulation,
    detectedTactics,
    summary: detectedTactics.length > 0
      ? `Detected ${detectedTactics.length} social engineering tactic(s): ${detectedTactics.join(', ')}`
      : 'No significant social engineering indicators detected.'
  };
}
