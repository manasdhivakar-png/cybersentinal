// ═══════════════════════════════════════════════════════
// CYBERSENTINEL — Risk Engine
// Unified 0-100 Risk Scoring
// ═══════════════════════════════════════════════════════

import { analyzeNLP } from './nlpAnalyzer';
import { analyzeURL, extractURLs } from './urlAnalyzer';
import { analyzeSender } from './senderAnalyzer';

export function calculateRisk(input) {
  const {
    text = '',
    url = '',
    senderEmail = '',
    claimedIdentity = '',
    inputType = 'message',
  } = input;

  // Run individual analyzers
  const nlpResult = analyzeNLP(text);

  // Analyze embedded URLs if no explicit URL
  let urlResult = analyzeURL(url);
  if (!url && text) {
    const urls = extractURLs(text);
    if (urls.length > 0) {
      const urlResults = urls.map(u => analyzeURL(u));
      urlResult = urlResults.reduce((worst, curr) =>
        curr.score > worst.score ? curr : worst
      , urlResults[0]);
    }
  }

  const senderResult = analyzeSender(senderEmail, claimedIdentity, text);

  // Context scoring
  let contextScore = 0;
  const contextIndicators = [];

  // Check for common scam templates
  const scamPatterns = [
    { pattern: /your\s*(account|card|bank)\s*(has been|will be|is)\s*(block|suspend|lock|restrict|compromis)/i, label: 'Account threat scam template', score: 25 },
    { pattern: /won\s*(a|the)?\s*(prize|lottery|reward|gift)/i, label: 'Prize/lottery scam template', score: 20 },
    { pattern: /job\s*(offer|opportunity|opening).*work\s*from\s*home/i, label: 'Job scam template', score: 18 },
    { pattern: /invest.*guaranteed.*return/i, label: 'Investment scam template', score: 22 },
    { pattern: /(police|court|warrant|arrest).*unless.*pay/i, label: 'Legal threat extortion template', score: 25 },
    { pattern: /share\s*(your)?\s*(otp|pin|password|cvv)/i, label: 'Direct credential request', score: 30 },
    { pattern: /install\s*(this|the)?\s*(app|software|tool|teamviewer|anydesk)/i, label: 'Remote access scam', score: 25 },
    { pattern: /click\s*(here|below|this).*verify.*account/i, label: 'Phishing click-verify template', score: 22 },
    { pattern: /dear\s*(customer|user).*urgent.*action\s*required/i, label: 'Generic phishing template', score: 20 },
    { pattern: /kyc\s*(update|verification|expired|pending)/i, label: 'KYC scam template', score: 22 },
  ];

  for (const sp of scamPatterns) {
    if (sp.pattern.test(text)) {
      contextIndicators.push(sp.label);
      contextScore += sp.score;
    }
  }

  contextScore = Math.min(100, contextScore);

  // Threat intelligence score (simulated)
  let threatIntelScore = 0;
  const threatIntelIndicators = [];

  if (urlResult.isSuspiciousTLD) {
    threatIntelScore += 20;
    threatIntelIndicators.push('Domain uses known suspicious TLD');
  }
  if (urlResult.typosquatting.length > 0) {
    threatIntelScore += 25;
    threatIntelIndicators.push(`Possible typosquatting of: ${urlResult.typosquatting[0].brand}`);
  }
  if (senderResult.isSpoofed) {
    threatIntelScore += 20;
    threatIntelIndicators.push('Sender identity spoofing detected');
  }
  threatIntelScore = Math.min(100, threatIntelScore);

  // Dynamic weights based on inputType
  let weights = {
    nlp: 0.30,
    url: 0.25,
    sender: 0.15,
    context: 0.18,
    threatIntel: 0.12,
  };

  if (inputType === 'url' || inputType === 'website') {
    weights = { nlp: 0, url: 0.80, sender: 0, context: 0, threatIntel: 0.20 };
  } else if (inputType === 'image' || inputType === 'screenshot' || inputType === 'qr' || inputType === 'pdf') {
    weights = { nlp: 0.40, url: 0.40, sender: 0, context: 0.10, threatIntel: 0.10 };
  } else if (inputType === 'voice') {
    weights = { nlp: 0.50, url: 0.20, sender: 0, context: 0.20, threatIntel: 0.10 };
  } else if (!senderEmail && !claimedIdentity) {
    // for SMS, Chat, Clipboard, etc. where sender is not explicitly provided
    weights = { nlp: 0.45, url: 0.30, sender: 0, context: 0.15, threatIntel: 0.10 };
  }

  const overallScore = Math.min(100, Math.round(
    nlpResult.overallManipulation * weights.nlp +
    urlResult.score * weights.url +
    senderResult.score * weights.sender +
    contextScore * weights.context +
    threatIntelScore * weights.threatIntel
  ));

  // Risk level
  let riskLevel, riskColor, riskEmoji;
  if (overallScore <= 19) {
    riskLevel = 'Low'; riskColor = 'low'; riskEmoji = '🟢';
  } else if (overallScore <= 39) {
    riskLevel = 'Medium'; riskColor = 'medium'; riskEmoji = '🟡';
  } else if (overallScore <= 69) {
    riskLevel = 'High'; riskColor = 'high'; riskEmoji = '🟠';
  } else {
    riskLevel = 'Critical'; riskColor = 'critical'; riskEmoji = '🔴';
  }

  // Threat category
  const categories = [];
  if (nlpResult.detectedTactics.includes('Credential Harvesting')) categories.push('Credential Harvesting');
  if (nlpResult.detectedTactics.includes('Possible Impersonation') || senderResult.isSpoofed) categories.push('Impersonation');
  if (nlpResult.detectedTactics.includes('Financial Request')) categories.push('Financial Scam');
  if (urlResult.typosquatting.length > 0) categories.push('Phishing');
  if (nlpResult.detectedTactics.includes('Authority Manipulation')) categories.push('Social Engineering');
  if (nlpResult.detectedTactics.includes('Reward/Lure Bait')) categories.push('Scam/Lure');
  if (contextIndicators.some(i => i.includes('Remote access'))) categories.push('Remote Access Scam');
  if (contextIndicators.some(i => i.includes('KYC'))) categories.push('KYC Fraud');
  if (categories.length === 0 && overallScore > 19) categories.push('Suspicious Content');
  if (categories.length === 0) categories.push('Clean');

  // Smart alerts (DO/DON'T)
  const doNot = [];
  const doActions = [];

  if (overallScore > 40) {
    if (urlResult.score > 20) doNot.push('Click any links in this message');
    if (nlpResult.credential.score > 30) doNot.push('Share OTP, password, PIN, or CVV');
    if (nlpResult.financial.score > 30) doNot.push('Transfer or send any money');
    doNot.push('Enter personal information on unknown pages');
    if (nlpResult.authority.score > 40) doNot.push('Trust authority claims without verification');

    doActions.push('Verify through the official app or website');
    doActions.push('Contact the organization directly using known numbers');
    if (senderResult.isSpoofed) doActions.push('Report this as impersonation');
    doActions.push('Block the sender if you don\'t recognize them');
    doActions.push('Take a screenshot for evidence');
  }

  return {
    overallScore,
    riskLevel,
    riskColor,
    riskEmoji,
    categories,
    inputType,
    breakdown: {
      nlp: { score: nlpResult.overallManipulation, weight: weights.nlp, label: 'Language Analysis', details: nlpResult },
      url: { score: urlResult.score, weight: weights.url, label: 'URL Analysis', details: urlResult },
      sender: { score: senderResult.score, weight: weights.sender, label: 'Sender Analysis', details: senderResult },
      context: { score: contextScore, weight: weights.context, label: 'Context Analysis', indicators: contextIndicators },
      threatIntel: { score: threatIntelScore, weight: weights.threatIntel, label: 'Threat Intelligence', indicators: threatIntelIndicators },
    },
    alerts: { doNot, doActions },
    detectedTactics: nlpResult.detectedTactics,
    timestamp: new Date().toISOString(),
    id: crypto.randomUUID(),
  };
}
