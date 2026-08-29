// ═══════════════════════════════════════════════════════
// CYBERSENTINEL — Explainable AI Engine
// Human-readable threat explanations
// ═══════════════════════════════════════════════════════

const DIMENSION_EXPLANATIONS = {
  urgency: {
    high: 'This message creates artificial urgency to pressure you into acting quickly without thinking.',
    medium: 'Some urgency language detected — be cautious of pressure tactics.',
    low: 'No significant urgency pressure detected.',
  },
  fear: {
    high: 'Threatening language is used to scare you into compliance.',
    medium: 'Some fear-inducing language detected.',
    low: 'No threatening language detected.',
  },
  authority: {
    high: 'Claims to be from a trusted organization/authority to gain your trust.',
    medium: 'References authority figures or organizations.',
    low: 'No authority manipulation detected.',
  },
  reward: {
    high: 'Promises unrealistic rewards to lure you into a trap.',
    medium: 'Contains reward/incentive language.',
    low: 'No reward/lure tactics detected.',
  },
  credential: {
    high: 'Directly asks for sensitive information like passwords, OTPs, or PINs.',
    medium: 'May be trying to collect personal information.',
    low: 'No credential harvesting attempts detected.',
  },
  financial: {
    high: 'Requests money transfer or financial transactions.',
    medium: 'Contains financial references.',
    low: 'No financial requests detected.',
  },
  callToAction: {
    high: 'Contains suspicious links or aggressive push to take immediate action.',
    medium: 'Contains call-to-action elements.',
    low: 'No suspicious call-to-action detected.',
  },
  impersonation: {
    high: 'Strong indicators of identity impersonation.',
    medium: 'Some impersonation indicators present.',
    low: 'No impersonation indicators detected.',
  },
};

export function generateExplanation(riskResult, language = 'en') {
  const { breakdown, overallScore, riskLevel, categories, detectedTactics } = riskResult;

  const dimensions = [];

  // NLP dimensions
  if (breakdown.nlp && breakdown.nlp.details) {
    const nlp = breakdown.nlp.details;
    const dimNames = ['urgency', 'fear', 'authority', 'reward', 'credential', 'financial', 'callToAction', 'impersonation'];

    for (const dim of dimNames) {
      if (nlp[dim]) {
        const score = nlp[dim].score;
        const level = score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low';
        dimensions.push({
          name: dim,
          label: dim.charAt(0).toUpperCase() + dim.slice(1).replace(/([A-Z])/g, ' $1'),
          score,
          level,
          explanation: DIMENSION_EXPLANATIONS[dim]?.[level] || '',
          indicators: nlp[dim].indicators || [],
        });
      }
    }
  }

  // URL dimension
  if (breakdown.url) {
    dimensions.push({
      name: 'url',
      label: 'URL Safety',
      score: breakdown.url.score,
      level: breakdown.url.score >= 60 ? 'high' : breakdown.url.score >= 30 ? 'medium' : 'low',
      explanation: breakdown.url.score >= 60
        ? 'The URL shows multiple suspicious indicators.'
        : breakdown.url.score >= 30
          ? 'Some URL concerns detected.'
          : 'URL appears safe.',
      indicators: breakdown.url.details?.indicators || [],
    });
  }

  // Sender dimension
  if (breakdown.sender) {
    dimensions.push({
      name: 'sender',
      label: 'Sender Identity',
      score: breakdown.sender.score,
      level: breakdown.sender.score >= 60 ? 'high' : breakdown.sender.score >= 30 ? 'medium' : 'low',
      explanation: breakdown.sender.score >= 60
        ? 'The sender\'s identity doesn\'t match their claims.'
        : breakdown.sender.score >= 30
          ? 'Some sender identity concerns.'
          : 'Sender identity appears consistent.',
      indicators: breakdown.sender.details?.indicators || [],
    });
  }

  // Context
  if (breakdown.context) {
    dimensions.push({
      name: 'context',
      label: 'Context Analysis',
      score: breakdown.context.score,
      level: breakdown.context.score >= 60 ? 'high' : breakdown.context.score >= 30 ? 'medium' : 'low',
      explanation: breakdown.context.score >= 60
        ? 'Matches known scam/phishing templates.'
        : breakdown.context.score >= 30
          ? 'Some contextual red flags detected.'
          : 'Context appears normal.',
      indicators: breakdown.context.indicators || [],
    });
  }

  // Threat Intel
  if (breakdown.threatIntel) {
    const isUnknown = breakdown.threatIntel.score === 0 && (!breakdown.threatIntel.indicators || breakdown.threatIntel.indicators.length === 0);
    dimensions.push({
      name: 'threatIntel',
      label: 'Threat Intelligence',
      score: breakdown.threatIntel.score,
      level: isUnknown ? 'unknown' : (breakdown.threatIntel.score >= 60 ? 'high' : breakdown.threatIntel.score >= 30 ? 'medium' : 'low'),
      explanation: isUnknown
        ? 'Unknown (No threat intel APIs active)'
        : breakdown.threatIntel.score >= 60
          ? 'Linked to known threat indicators.'
          : breakdown.threatIntel.score >= 30
            ? 'Some threat intelligence matches.'
            : 'No known threat indicators found.',
      indicators: breakdown.threatIntel.indicators || [],
    });
  }

  return {
    overallScore,
    riskLevel,
    categories,
    detectedTactics,
    dimensions: dimensions.sort((a, b) => b.score - a.score),
    confidence: calculateConfidence(dimensions),
    howWeDecided: dimensions
      .filter(d => d.score > 0 || d.name === 'threatIntel')
      .map(d => `${d.label} — ${d.level === 'high' ? 'High' : d.level === 'medium' ? 'Medium' : d.level === 'low' ? 'Low' : 'Unknown'} (${d.score}/100)`)
  };
}

function calculateConfidence(dimensions) {
  const activeCount = dimensions.filter(d => d.score > 20).length;
  const totalDims = dimensions.length;
  const avgScore = dimensions.reduce((s, d) => s + d.score, 0) / Math.max(totalDims, 1);

  if (activeCount >= 4 && avgScore > 50) return 'Very High';
  if (activeCount >= 3 && avgScore > 40) return 'High';
  if (activeCount >= 2 && avgScore > 30) return 'Medium';
  if (activeCount >= 1) return 'Low';
  return 'Very Low';
}
