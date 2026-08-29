// ═══════════════════════════════════════════════════════
// CYBERSENTINEL — Voice Guardian AI Engine
// Conversational Cybersecurity Assistant
// LISTEN → UNDERSTAND → ANALYZE → EXPLAIN → GUIDE
// ═══════════════════════════════════════════════════════

import { calculateRisk } from './riskEngine';
import { analyzeURL, extractURLs } from './urlAnalyzer';
import { analyzeNLP } from './nlpAnalyzer';
import { analyzeSender } from './senderAnalyzer';
import { analyzeFakeProfile } from './fakeProfileDetector';
import { generateExplanation } from './explainableAI';
import { t } from './translations';

// ═══ INTENT CLASSIFICATION ═══
const INTENT_PATTERNS = [
  // Scan/Check intents
  { intent: 'scan_message', patterns: [/check\s*(this)?\s*message/i, /scan\s*(this)?\s*message/i, /is\s*(this|it)\s*(message|msg)\s*(safe|dangerous|scam)/i, /message.*safe/i, /message.*scam/i, /received.*message/i, /got.*message/i, /indha\s*message/i, /ye\s*message/i, /செய்தி/i, /संदेश/i] },
  { intent: 'scan_url', patterns: [/check\s*(this)?\s*(link|url)/i, /scan\s*(this)?\s*(link|url)/i, /is\s*(this)?\s*(link|url)\s*(safe|dangerous)/i, /link.*safe/i, /link.*dangerous/i, /url.*check/i, /link-.*safe/i, /லிங்க்/i, /लिंक/i] },
  { intent: 'scan_email', patterns: [/check\s*(this)?\s*email/i, /scan\s*(this)?\s*email/i, /email.*safe/i, /email.*scam/i, /got\s*(an?)?\s*email/i, /received\s*(an?)?\s*email/i, /மின்னஞ்சல்/i, /ईमेल/i] },
  { intent: 'scan_screenshot', patterns: [/check\s*(this)?\s*screenshot/i, /analyze\s*(this)?\s*screenshot/i, /scan\s*(this)?\s*screenshot/i, /upload.*screenshot/i, /ஸ்கிரீன்ஷாட்/i] },
  { intent: 'scan_call', patterns: [/someone\s*called/i, /got\s*(a)?\s*call/i, /received\s*(a)?\s*call/i, /phone\s*call/i, /call\s*(from|saying)/i, /call.*bank/i, /call.*police/i, /call.*government/i, /அழைப்பு/i, /कॉल/i] },
  { intent: 'check_profile', patterns: [/is\s*(this)?\s*(account|profile|person)\s*(real|fake|suspicious)/i, /fake\s*(account|profile|id)/i, /check\s*(this)?\s*(instagram|facebook|twitter)/i, /suspicious\s*(account|profile)/i, /போலி/i, /फर्जी/i] },
  { intent: 'check_deepfake', patterns: [/is\s*(this)?\s*(image|video|audio|photo)\s*(real|fake|deepfake)/i, /deepfake/i, /check.*photo/i, /check.*video/i, /manipulated/i] },

  // Explain/Understand intents
  { intent: 'explain_result', patterns: [/explain/i, /why.*dangerous/i, /why.*risky/i, /why.*high/i, /why.*score/i, /tell\s*me\s*more/i, /what\s*does\s*(this|it)\s*mean/i, /don'?t\s*understand/i, /puriyala/i, /புரியல/i, /समझ\s*नहीं/i, /puriala/i, /enna\s*(ithu|indha)/i] },
  { intent: 'what_to_do', patterns: [/what\s*should\s*i\s*do/i, /what\s*to\s*do/i, /what\s*now/i, /how\s*to\s*protect/i, /enna\s*pannanum/i, /என்ன\s*பண்ணணும்/i, /क्या\s*करना/i, /kya\s*karu/i] },
  { intent: 'translate', patterns: [/translate.*tamil/i, /explain.*tamil/i, /in\s*tamil/i, /tamil-la/i, /tamil.*sollu/i, /translate.*hindi/i, /hindi.*mein/i, /hindi-la/i, /translate.*telugu/i, /translate.*malayalam/i, /translate.*kannada/i, /தமிழில்/i, /हिंदी\s*में/i] },

  // Emergency
  { intent: 'emergency', patterns: [/i\s*(think|believe)?\s*(i'?ve?\s*been|got|am)\s*scam/i, /been\s*scammed/i, /i\s*clicked\s*(the|a)?\s*link/i, /i\s*shared\s*(my)?\s*(otp|password|pin)/i, /i\s*sent\s*money/i, /i\s*gave\s*(my)?\s*(details|info|card)/i, /scammed/i, /hacked/i, /compromised/i, /fraud/i, /மோசடி/i, /धोखा/i] },

  // Navigation
  { intent: 'navigate_scanner', patterns: [/open\s*(the)?\s*scanner/i, /go\s*to\s*scan/i, /start\s*scan/i] },
  { intent: 'navigate_dashboard', patterns: [/open\s*(the)?\s*dashboard/i, /show\s*(my)?\s*dashboard/i, /show\s*stats/i] },
  { intent: 'navigate_history', patterns: [/show\s*(my)?\s*(recent)?\s*threats/i, /threat\s*history/i, /recent\s*scans/i, /show\s*history/i] },
  { intent: 'navigate_quiz', patterns: [/quiz/i, /play\s*(the)?\s*quiz/i, /scam\s*quiz/i, /test\s*me/i] },
  { intent: 'navigate_academy', patterns: [/academy/i, /learn/i, /teach\s*me/i, /cyber\s*awareness/i] },
  { intent: 'generate_report', patterns: [/generate.*report/i, /create.*report/i, /make.*report/i, /incident\s*report/i, /export.*pdf/i] },
  { intent: 'read_warning', patterns: [/read\s*(the)?\s*warning/i, /say\s*(the)?\s*result/i, /tell\s*me\s*(the)?\s*result/i] },

  // OTP/Password safety
  { intent: 'otp_safety', patterns: [/someone.*asking.*otp/i, /otp\s*ke/i, /otp.*share/i, /asking\s*(for)?\s*(my)?\s*otp/i, /asking\s*(for)?\s*(my)?\s*password/i, /asking\s*(for)?\s*(my)?\s*pin/i, /otp\s*கேக்குறாங்க/i, /OTP\s*मांग/i, /share\s*(my)?\s*otp/i, /should\s*i\s*(share|give)/i] },

  // Knowledge questions
  { intent: 'knowledge', patterns: [/what\s*is\s*(a)?\s*(phishing|deepfake|malware|ransomware|social\s*engineering|otp\s*fraud|cyber)/i, /how\s*(can|do)\s*i\s*(protect|identify|spot|detect)/i, /how\s*to\s*(protect|identify|spot|detect|report|stay\s*safe)/i, /tell\s*me\s*about/i] },

  // Greeting
  { intent: 'greeting', patterns: [/^(hi|hello|hey|good\s*(morning|afternoon|evening)|vanakkam|namaste|namaskara)/i] },
];

const SECURITY_KNOWLEDGE = {
  phishing: "Phishing is when someone sends fake messages or creates fake websites to trick you into revealing personal information. They often pretend to be from trusted organizations like banks or tech companies. Always verify the sender and never click suspicious links.",
  deepfake: "A deepfake is AI-generated or manipulated media — images, videos, or audio — that can make it appear someone said or did something they didn't. Always verify important communications through multiple channels.",
  malware: "Malware is malicious software designed to damage or gain unauthorized access to your device. It can come through suspicious downloads, email attachments, or compromised websites. Keep your software updated and use trusted security tools.",
  ransomware: "Ransomware is a type of malware that locks your files and demands payment to unlock them. Never pay the ransom. Keep regular backups and don't open suspicious attachments.",
  'social engineering': "Social engineering is when attackers manipulate people psychologically to reveal confidential information. They may impersonate trusted people, create urgency, or use fear tactics. Always verify requests through official channels.",
  'otp fraud': "OTP fraud happens when scammers trick you into sharing your One-Time Password. Remember: no legitimate bank, company, or government agency will ever call and ask for your OTP. If someone asks, it's a scam.",
  protect: "To protect your accounts: use strong unique passwords, enable two-factor authentication, never share OTPs or passwords, verify unexpected messages through official channels, keep software updated, and be cautious with links and attachments.",
  'fake website': "To identify a fake website: check if the URL matches the official domain, look for HTTPS, watch for spelling errors, be wary of URLs with random characters, and never enter credentials on pages reached through suspicious links.",
};

export function classifyIntent(text) {
  const lower = text.toLowerCase().trim();

  for (const { intent, patterns } of INTENT_PATTERNS) {
    for (const pattern of patterns) {
      if (pattern.test(lower)) {
        return intent;
      }
    }
  }

  // Fallback: if text contains a URL, treat as scan_url
  if (extractURLs(text).length > 0) return 'scan_url';

  // If text looks like it could be a suspicious message to analyze
  if (lower.length > 50 && (lower.includes('click') || lower.includes('verify') || lower.includes('urgent') || lower.includes('otp') || lower.includes('account'))) {
    return 'scan_message';
  }

  return 'general';
}

export function detectLanguage(text) {
  if (/[\u0B80-\u0BFF]/.test(text)) return 'ta';
  if (/[\u0900-\u097F]/.test(text)) return 'hi';
  if (/[\u0C00-\u0C7F]/.test(text)) return 'te';
  if (/[\u0D00-\u0D7F]/.test(text)) return 'ml';
  if (/[\u0C80-\u0CFF]/.test(text)) return 'kn';

  // Check for Romanized Tamil/Hindi
  const tamilRoman = /\b(indha|enna|pannanum|puriyala|panna|vendam|sollu|paaru|safe.?ah|dangerous.?ah)\b/i;
  const hindiRoman = /\b(kya|hai|karu|karo|batao|samjhao|ye|mein|nahi|kaise)\b/i;
  if (tamilRoman.test(text)) return 'ta';
  if (hindiRoman.test(text)) return 'hi';

  return 'en';
}

function detectTranslateTarget(text) {
  if (/tamil/i.test(text)) return 'ta';
  if (/hindi/i.test(text)) return 'hi';
  if (/telugu/i.test(text)) return 'te';
  if (/malayalam/i.test(text)) return 'ml';
  if (/kannada/i.test(text)) return 'kn';
  if (/english/i.test(text)) return 'en';
  return null;
}

// ═══ RESPONSE GENERATION ═══
export function generateResponse(intent, userText, context) {
  const { language = 'en', mode = 'advanced', lastResult, scanHistory = [], userProfile = 'employee' } = context;
  const isSimple = mode === 'simple' || userProfile === 'elderly';

  let response = { text: '', action: null, visualData: null, emotion: 'neutral' };

  switch (intent) {
    case 'greeting': {
      const greetings = {
        en: "Hello! I'm your CyberSentinel Voice Guardian. I'm here to help you stay safe online. You can ask me to check messages, links, or any suspicious content. How can I protect you today?",
        ta: "வணக்கம்! நான் உங்கள் சைபர்செண்டினல் குரல் காவலர். நீங்கள் ஆன்லைனில் பாதுகாப்பாக இருக்க உதவ இங்கே இருக்கிறேன். எந்த சந்தேகமான செய்தியையும் சரிபார்க்க என்னிடம் கேளுங்கள்.",
        hi: "नमस्ते! मैं आपका साइबरसेंटिनल वॉइस गार्डियन हूँ। मैं आपको ऑनलाइन सुरक्षित रहने में मदद करने के लिए यहाँ हूँ। कोई भी संदिग्ध संदेश या लिंक जांचने के लिए मुझसे पूछें।",
      };
      response.text = greetings[language] || greetings.en;
      response.emotion = 'friendly';
      break;
    }

    case 'scan_message':
    case 'scan_email': {
      // Check if the user text itself contains the message to analyze
      const contentToAnalyze = userText.replace(/^(check|scan|analyze|is)\s*(this|the)?\s*(message|email|msg|text)?\s*:?\s*/i, '').trim();

      if (contentToAnalyze.length > 20) {
        const result = calculateRisk({ text: contentToAnalyze, inputType: intent === 'scan_email' ? 'email' : 'message' });
        result.inputText = contentToAnalyze;
        result.explanation = generateExplanation(result, language);

        if (result.overallScore > 60) {
          response.text = isSimple
            ? getSimpleWarning(result, language)
            : getAdvancedExplanation(result, language);
          response.emotion = 'warning';
        } else if (result.overallScore > 30) {
          response.text = isSimple
            ? getMediumWarning(result, language)
            : getAdvancedExplanation(result, language);
          response.emotion = 'caution';
        } else {
          response.text = getSafeResponse(result, language);
          response.emotion = 'safe';
        }
        response.action = { type: 'add_scan', data: result };
        response.visualData = {
          type: 'risk_result',
          score: result.overallScore,
          riskLevel: result.riskLevel,
          riskColor: result.riskColor,
          categories: result.categories,
          tactics: result.detectedTactics,
          alerts: result.alerts,
        };
      } else {
        response.text = language === 'ta'
          ? "சந்தேகமான செய்தியை இங்கே paste செய்யுங்கள் அல்லது screenshot upload செய்யுங்கள். நான் check பண்ணி safe-ஆ dangerous-ஆ சொல்கிறேன்."
          : language === 'hi'
          ? "संदिग्ध संदेश यहाँ paste करें या screenshot upload करें। मैं जांच करके बताऊंगा।"
          : "Please paste the suspicious message here, or upload a screenshot. I'll analyze it and tell you if it's safe.";
        response.emotion = 'helpful';
        response.action = { type: 'request_input', inputType: 'message' };
      }
      break;
    }

    case 'scan_url': {
      const urls = extractURLs(userText);
      if (urls.length > 0) {
        const urlResult = analyzeURL(urls[0]);
        const fullResult = calculateRisk({ url: urls[0], inputType: 'url' });
        fullResult.inputText = urls[0];
        fullResult.explanation = generateExplanation(fullResult, language);

        if (urlResult.score > 50) {
          response.text = isSimple
            ? getSimpleURLWarning(urlResult, language)
            : `This link appears suspicious. Risk score: ${urlResult.score}/100. ${urlResult.indicators.join('. ')}. I recommend not clicking this link and verifying through official channels.`;
          response.emotion = 'warning';
        } else if (urlResult.score > 20) {
          response.text = `This link has some concerns: ${urlResult.indicators.join('. ')}. Score: ${urlResult.score}/100. Proceed with caution.`;
          response.emotion = 'caution';
        } else {
          response.text = "This link appears relatively safe based on my analysis. However, always exercise caution when entering personal information on any website.";
          response.emotion = 'safe';
        }
        response.action = { type: 'add_scan', data: fullResult };
        response.visualData = {
          type: 'risk_result',
          score: fullResult.overallScore,
          riskLevel: fullResult.riskLevel,
          riskColor: fullResult.riskColor,
          categories: fullResult.categories,
        };
      } else {
        response.text = "Please share the link you'd like me to check. You can paste the URL or say it.";
        response.action = { type: 'request_input', inputType: 'url' };
      }
      break;
    }

    case 'scan_call': {
      response.text = isSimple
        ? (language === 'ta'
          ? "யாரும் phone-ல OTP, password அல்லது பணம் கேட்டால் அது மோசடி. எந்த வங்கியும், போலீஸும் phone-ல இதை கேட்க மாட்டார்கள். உடனே call-ஐ cut செய்யுங்கள்."
          : "If someone on a call asks for your OTP, password, or money — it's likely a scam. No bank or police will ask for these on a call. Hang up immediately.")
        : "Phone call scams typically involve impersonating banks, police, or government agencies. They create urgency and ask for OTPs, passwords, or money transfers. Key indicators: automated voices, threats of arrest, requests for remote access software. If you received such a call, hang up and call the organization directly using their official number.";
      response.emotion = 'warning';
      response.action = { type: 'navigate', path: '/call-protection' };
      break;
    }

    case 'check_profile': {
      response.text = "I can analyze social media profiles for fake account indicators. Please go to the Fake ID Detector and enter the profile details, or tell me the username and platform.";
      response.action = { type: 'navigate', path: '/fake-profile' };
      break;
    }

    case 'check_deepfake': {
      response.text = "I can analyze images, videos, and audio for potential manipulation. Please upload the media file in the Deepfake Detector. Note that my assessment is AI-based and not absolute proof.";
      response.action = { type: 'navigate', path: '/deepfake' };
      break;
    }

    case 'explain_result': {
      if (lastResult) {
        const explanation = lastResult.explanation || generateExplanation(lastResult, language);
        if (isSimple) {
          response.text = getSimpleExplanation(lastResult, language);
        } else {
          const dims = explanation.dimensions?.filter(d => d.score > 20) || [];
          const reasons = dims.map(d => `${d.label}: ${d.explanation}`).join('. ');
          response.text = `Your last scan scored ${lastResult.overallScore} out of 100, rated as ${lastResult.riskLevel}. Here's why: ${reasons || 'The analysis considered language patterns, URL safety, sender identity, and contextual patterns.'}`;
        }
        response.visualData = {
          type: 'risk_result',
          score: lastResult.overallScore,
          riskLevel: lastResult.riskLevel,
          riskColor: lastResult.riskColor,
          categories: lastResult.categories,
          tactics: lastResult.detectedTactics,
        };
      } else {
        response.text = "I don't have a recent scan to explain. Would you like to scan something first? You can paste a message, share a link, or upload a screenshot.";
      }
      break;
    }

    case 'what_to_do': {
      if (lastResult && lastResult.overallScore > 40) {
        const doNots = lastResult.alerts?.doNot || [];
        const doActions = lastResult.alerts?.doActions || [];
        if (isSimple) {
          response.text = language === 'ta'
            ? `பாதுகாப்பாக இருக்க: ${doNots.length > 0 ? doNots.map((d,i) => `${i+1}. ${d} செய்யாதீர்கள்`).join('. ') : ''}. ${doActions.length > 0 ? doActions.map((d,i) => `${i+1}. ${d}`).join('. ') : ''}`
            : `To stay safe: ${doNots.map(d => `Don't ${d.toLowerCase()}`).join('. ')}. Instead: ${doActions.join('. ')}.`;
        } else {
          response.text = `Based on the analysis with a risk score of ${lastResult.overallScore}/100, here's what you should do:\n\n` +
            (doNots.length > 0 ? `DO NOT: ${doNots.join('. ')}.\n\n` : '') +
            (doActions.length > 0 ? `DO: ${doActions.join('. ')}.` : '');
        }
        response.emotion = 'guiding';
        response.visualData = { type: 'alerts', alerts: lastResult.alerts };
      } else {
        response.text = "If you've received something suspicious, the safest steps are: Don't click any links. Don't share OTPs, passwords, or bank details. Verify through official channels by opening the app or website directly. Block and report the sender if needed.";
        response.emotion = 'guiding';
      }
      break;
    }

    case 'otp_safety': {
      const otpResponses = {
        en: "NEVER share your OTP with anyone. No bank, company, government agency, or delivery service will ever ask for your OTP. If someone is asking for it, it is a scam. Hang up the call or ignore the message immediately. If you've already shared an OTP, change your passwords right away and contact your bank.",
        ta: "உங்கள் OTP-ஐ யாருடனும் பகிராதீர்கள். எந்த வங்கியும், நிறுவனமும், அரசு அலுவலகமும் OTP கேட்காது. யாராவது கேட்டால் அது மோசடி. உடனே call-ஐ cut செய்யுங்கள். ஏற்கனவே OTP கொடுத்திருந்தால், உடனே password-ஐ மாற்றுங்கள்.",
        hi: "अपना OTP किसी के साथ शेयर न करें। कोई भी बैंक, कंपनी या सरकारी एजेंसी OTP नहीं मांगती। अगर कोई मांग रहा है तो यह धोखाधड़ी है। तुरंत कॉल काटें। अगर OTP दे दिया है तो तुरंत पासवर्ड बदलें।",
      };
      response.text = otpResponses[language] || otpResponses.en;
      response.emotion = 'warning';
      response.visualData = {
        type: 'risk_result',
        score: 95,
        riskLevel: 'Critical',
        riskColor: 'critical',
        categories: ['OTP Fraud'],
      };
      break;
    }

    case 'emergency': {
      response.text = getEmergencyResponse(language);
      response.emotion = 'emergency';
      response.visualData = {
        type: 'emergency',
        steps: getEmergencySteps(language),
      };
      break;
    }

    case 'translate': {
      const targetLang = detectTranslateTarget(userText);
      if (lastResult && targetLang) {
        response.text = getTranslatedResult(lastResult, targetLang);
        response.emotion = 'helpful';
      } else {
        response.text = "I can translate my analysis. Please tell me which language you'd like — Tamil, Hindi, Telugu, Malayalam, or Kannada.";
      }
      break;
    }

    case 'knowledge': {
      const knowledgeKey = Object.keys(SECURITY_KNOWLEDGE).find(key =>
        userText.toLowerCase().includes(key)
      );
      response.text = knowledgeKey
        ? SECURITY_KNOWLEDGE[knowledgeKey]
        : "I can answer questions about phishing, deepfakes, malware, social engineering, OTP fraud, and online safety. What would you like to know?";
      response.emotion = 'informative';
      break;
    }

    case 'navigate_scanner':
      response.text = "Opening the Threat Scanner for you.";
      response.action = { type: 'navigate', path: '/' };
      break;
    case 'navigate_dashboard':
      response.text = "Here's your Security Dashboard.";
      response.action = { type: 'navigate', path: '/dashboard' };
      break;
    case 'navigate_history':
      response.text = `Opening your threat history. ${scanHistory.length > 0 ? `You have ${scanHistory.length} recent scans.` : 'No scans yet.'}`;
      response.action = { type: 'navigate', path: '/history' };
      break;
    case 'navigate_quiz':
      response.text = "Let's test your scam detection skills! Opening the Scam Quiz.";
      response.action = { type: 'navigate', path: '/quiz' };
      break;
    case 'navigate_academy':
      response.text = "Opening the Cyber Awareness Center. Let's learn about online safety!";
      response.action = { type: 'navigate', path: '/academy' };
      break;
    case 'generate_report':
      response.text = lastResult
        ? "Generating your incident report. You can export it as a PDF."
        : "No scan results available yet. Please scan something first, then I can generate a report.";
      if (lastResult) response.action = { type: 'navigate', path: '/report' };
      break;
    case 'read_warning':
      if (lastResult) {
        response.text = `Your last scan result: Risk score ${lastResult.overallScore} out of 100, rated as ${lastResult.riskLevel}. Categories: ${lastResult.categories.join(', ')}. ${lastResult.detectedTactics.length > 0 ? `Detected tactics: ${lastResult.detectedTactics.join(', ')}.` : ''}`;
        response.visualData = {
          type: 'risk_result',
          score: lastResult.overallScore,
          riskLevel: lastResult.riskLevel,
          riskColor: lastResult.riskColor,
        };
      } else {
        response.text = "No recent scan results to read. Would you like me to scan something?";
      }
      break;

    case 'scan_screenshot':
      response.text = "Please upload the screenshot. I'll extract the text and analyze it for threats.";
      response.action = { type: 'request_input', inputType: 'screenshot' };
      break;

    default: {
      // Attempt to analyze as potential suspicious content
      if (userText.length > 40) {
        const result = calculateRisk({ text: userText, inputType: 'message' });
        if (result.overallScore > 30) {
          result.inputText = userText;
          result.explanation = generateExplanation(result, language);
          response.text = isSimple
            ? getSimpleWarning(result, language)
            : `I analyzed your text and found a risk score of ${result.overallScore}/100. ${result.detectedTactics.length > 0 ? `Detected: ${result.detectedTactics.join(', ')}.` : ''} ${result.overallScore > 50 ? "I recommend not taking any action requested in this message." : "This seems relatively low risk, but always stay cautious."}`;
          response.action = { type: 'add_scan', data: result };
          response.visualData = {
            type: 'risk_result',
            score: result.overallScore,
            riskLevel: result.riskLevel,
            riskColor: result.riskColor,
            categories: result.categories,
          };
          response.emotion = result.overallScore > 50 ? 'warning' : 'neutral';
        } else {
          response.text = "I'm your CyberSentinel Voice Guardian. I can help you check suspicious messages, links, emails, screenshots, or answer cybersecurity questions. What would you like me to help with?";
        }
      } else {
        response.text = "I'm here to help you stay safe online. You can ask me to check a message, analyze a link, explain a scan result, or answer cybersecurity questions. Try saying something like 'Check this message' or 'Is this link safe?'";
        response.emotion = 'helpful';
      }
    }
  }

  return response;
}

// ═══ HELPER FUNCTIONS ═══
function getSimpleWarning(result, lang) {
  const warnings = {
    en: `This appears dangerous. Risk score: ${result.overallScore} out of 100. Don't click any links. Don't share your OTP or password. Verify through official channels.`,
    ta: `இது ஆபத்தானதாக இருக்கலாம். ஆபத்து மதிப்பெண்: ${result.overallScore}/100. Link-ஐ click செய்யாதீர்கள். OTP அல்லது password பகிராதீர்கள். அதிகாரப்பூர்வ வழியில் சரிபார்க்கவும்.`,
    hi: `यह खतरनाक हो सकता है। जोखिम स्कोर: ${result.overallScore}/100। किसी भी लिंक पर क्लिक न करें। OTP या पासवर्ड शेयर न करें। आधिकारिक चैनल से सत्यापित करें।`,
  };
  return warnings[lang] || warnings.en;
}

function getMediumWarning(result, lang) {
  return lang === 'ta'
    ? `இது கொஞ்சம் சந்தேகமாக தெரிகிறது. ஆபத்து: ${result.overallScore}/100. கவனமாக இருங்கள், link-ஐ click செய்வதற்கு முன் சரிபார்க்கவும்.`
    : `This has some concerning elements. Risk: ${result.overallScore}/100. Be cautious and verify before taking any action.`;
}

function getSafeResponse(result, lang) {
  return lang === 'ta'
    ? `இது பாதுகாப்பாக தெரிகிறது. ஆபத்து மதிப்பெண்: ${result.overallScore}/100. ஆனால் எப்போதும் கவனமாக இருங்கள்.`
    : `This appears relatively safe. Risk score: ${result.overallScore}/100. However, always exercise caution with any online communication.`;
}

function getSimpleURLWarning(urlResult, lang) {
  return lang === 'ta'
    ? `இந்த link ஆபத்தானதாக இருக்கலாம். Click செய்யாதீர்கள். ${urlResult.indicators[0] || ''}`
    : `This link appears suspicious. Don't click it. ${urlResult.indicators[0] || ''}`;
}

function getAdvancedExplanation(result, lang) {
  const tactics = result.detectedTactics.join(', ') || 'suspicious patterns';
  return `Risk score: ${result.overallScore}/100, rated ${result.riskLevel}. Detected indicators: ${tactics}. Categories: ${result.categories.join(', ')}. I strongly recommend not taking any action requested in this content and verifying through official channels.`;
}

function getSimpleExplanation(result, lang) {
  if (lang === 'ta') {
    return result.overallScore > 60
      ? `இது ஆபத்தானது (${result.overallScore}/100). ${result.detectedTactics.length > 0 ? 'காரணம்: ' + result.detectedTactics[0] : ''}`
      : `இது ${result.overallScore > 30 ? 'கொஞ்சம் சந்தேகமானது' : 'பாதுகாப்பாக தெரிகிறது'} (${result.overallScore}/100).`;
  }
  return result.overallScore > 60
    ? `This is dangerous (${result.overallScore}/100). ${result.detectedTactics[0] || ''}`
    : `This appears ${result.overallScore > 30 ? 'somewhat suspicious' : 'relatively safe'} (${result.overallScore}/100).`;
}

function getEmergencyResponse(lang) {
  const responses = {
    en: "I understand you may have been scammed. Stay calm — here's what to do right now:\n\n1. STOP all communication with the suspected scammer immediately.\n2. Don't provide any more information or send more money.\n3. Change passwords for affected accounts RIGHT NOW.\n4. Contact your bank immediately if you shared financial details.\n5. File a complaint at cybercrime.gov.in or call 1930 (India Cyber Crime Helpline).\n6. Save all evidence — messages, screenshots, transaction IDs.\n\nYou're doing the right thing by seeking help. Take these steps one at a time.",
    ta: "நீங்கள் மோசடிக்கு ஆளாகியிருக்கலாம். அமைதியாக இருங்கள் — இப்போது செய்ய வேண்டியது:\n\n1. மோசடியாளருடன் உடனே தொடர்பை நிறுத்துங்கள்.\n2. மேலும் தகவல்களை கொடுக்காதீர்கள்.\n3. password-களை உடனே மாற்றுங்கள்.\n4. வங்கி விவரங்களை பகிர்ந்திருந்தால் உடனே வங்கியை தொடர்பு கொள்ளுங்கள்.\n5. cybercrime.gov.in-ல் புகார் அளியுங்கள் அல்லது 1930 அழைக்கவும்.\n6. ஆதாரங்களை சேமியுங்கள் — messages, screenshots.",
    hi: "आप धोखाधड़ी का शिकार हो सकते हैं। शांत रहें — अभी ये करें:\n\n1. संदिग्ध व्यक्ति से संपर्क तुरंत बंद करें।\n2. और जानकारी न दें।\n3. पासवर्ड तुरंत बदलें।\n4. बैंक को तुरंत संपर्क करें।\n5. cybercrime.gov.in पर शिकायत दर्ज करें या 1930 पर कॉल करें।\n6. सबूत सुरक्षित रखें।",
  };
  return responses[lang] || responses.en;
}

function getEmergencySteps(lang) {
  return [
    { icon: '🛑', text: lang === 'ta' ? 'தொடர்பை நிறுத்துங்கள்' : 'Stop all communication' },
    { icon: '🚫', text: lang === 'ta' ? 'மேலும் தகவல் கொடுக்காதீர்கள்' : "Don't share more info" },
    { icon: '💰', text: lang === 'ta' ? 'பணம் அனுப்பாதீர்கள்' : "Don't send money" },
    { icon: '🔐', text: lang === 'ta' ? 'password மாற்றுங்கள்' : 'Change passwords NOW' },
    { icon: '🏦', text: lang === 'ta' ? 'வங்கியை தொடர்பு கொள்ளுங்கள்' : 'Contact your bank' },
    { icon: '📸', text: lang === 'ta' ? 'ஆதாரங்களை சேமியுங்கள்' : 'Save evidence' },
  ];
}

function getTranslatedResult(result, targetLang) {
  if (targetLang === 'ta') {
    return result.overallScore > 60
      ? `ஆபத்து மதிப்பெண்: ${result.overallScore}/100. இது ஆபத்தானதாக இருக்கலாம். Link-ஐ click செய்யாதீர்கள். OTP பகிராதீர்கள். அதிகாரப்பூர்வமாக சரிபார்க்கவும்.`
      : `ஆபத்து மதிப்பெண்: ${result.overallScore}/100. இது ஒப்பீட்டளவில் பாதுகாப்பாக தெரிகிறது. ஆனால் எப்போதும் கவனமாக இருங்கள்.`;
  }
  if (targetLang === 'hi') {
    return result.overallScore > 60
      ? `जोखिम स्कोर: ${result.overallScore}/100। यह खतरनाक हो सकता है। लिंक पर क्लिक न करें। OTP शेयर न करें। आधिकारिक रूप से सत्यापित करें।`
      : `जोखिम स्कोर: ${result.overallScore}/100। यह अपेक्षाकृत सुरक्षित प्रतीत होता है। लेकिन हमेशा सावधान रहें।`;
  }
  return `Risk score: ${result.overallScore}/100. ${result.overallScore > 60 ? 'This appears dangerous.' : 'This appears relatively safe.'}`;
}

// ═══ DEMO CONVERSATIONS ═══
export const DEMO_CONVERSATIONS = [
  {
    id: 'demo-1',
    title: 'Bank Account Scam Check',
    exchanges: [
      { role: 'user', text: "I received a message saying my bank account will be blocked. Can you check it?" },
      { role: 'assistant', text: "Sure, I can help. Please paste the message here or upload a screenshot, and I'll analyze it for you.", emotion: 'helpful' },
      { role: 'user', text: "URGENT: Your SBI account has been blocked due to KYC expiry. Update immediately: http://sbi-kyc-update.tk/verify" },
      { role: 'assistant', text: "I've analyzed this message and it shows HIGH RISK — scored 82/100. Here's why:\n\n🚨 Creates artificial urgency with 'URGENT' and 'immediately'\n🔗 Suspicious URL: sbi-kyc-update.tk — this is NOT an official SBI domain. The .tk domain is commonly used in scams.\n🎭 Impersonates SBI bank\n🔐 Asks you to 'verify' — a credential harvesting tactic\n\nDo NOT click the link. Do NOT enter any information. Real banks never send KYC update links via SMS.", emotion: 'warning',
        visualData: { type: 'risk_result', score: 82, riskLevel: 'Critical', riskColor: 'critical', categories: ['Phishing', 'Impersonation'] }
      },
      { role: 'user', text: "What should I do?" },
      { role: 'assistant', text: "Here's what you should do:\n\n1. ❌ Don't click the link\n2. ❌ Don't share OTP or password\n3. ✅ Open the official SBI app or website directly\n4. ✅ If concerned, visit your nearest SBI branch\n5. ✅ Block the sender\n6. ✅ Report as spam on your phone", emotion: 'guiding' },
      { role: 'user', text: "Can you explain this in Tamil?" },
      { role: 'assistant', text: "இந்த செய்தி ஆபத்தானதாக இருக்கலாம். ஆபத்து மதிப்பெண்: 82/100.\n\n🚨 'URGENT' என்று அவசரம் உருவாக்குகிறது\n🔗 sbi-kyc-update.tk — இது SBI-யின் உண்மையான domain அல்ல\n🎭 SBI வங்கியை ஆள்மாறாட்டம் செய்கிறது\n\n❌ Link-ஐ click செய்யாதீர்கள்\n❌ OTP பகிராதீர்கள்\n✅ SBI app-ஐ நேரடியாக திறந்து சரிபார்க்கவும்", emotion: 'helpful' },
    ]
  },
  {
    id: 'demo-2',
    title: 'OTP Request Scam',
    exchanges: [
      { role: 'user', text: "Someone is asking for my OTP. What should I do?" },
      { role: 'assistant', text: "NEVER share your OTP with anyone — no matter who they claim to be. No bank, company, government agency, or delivery service will ever call and ask for your OTP.\n\nIf someone is asking for your OTP right now:\n\n1. 🛑 Hang up the call immediately\n2. 🚫 Do not share the OTP\n3. 🔒 If you already shared it, change your passwords RIGHT NOW\n4. 🏦 Contact your bank if it's related to a financial OTP\n\nRemember: OTP is for YOUR verification only. Anyone asking for it is trying to scam you.", emotion: 'warning',
        visualData: { type: 'risk_result', score: 95, riskLevel: 'Critical', riskColor: 'critical', categories: ['OTP Fraud'] }
      },
    ]
  },
];

// ═══ SPEECH UTILITIES ═══
export function createSpeechRecognition(lang = 'en') {
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRecognition) return null;

  const recognition = new SpeechRecognition();
  recognition.continuous = false;
  recognition.interimResults = true;
  recognition.maxAlternatives = 1;

  const langMap = { en: 'en-US', ta: 'ta-IN', hi: 'hi-IN', te: 'te-IN', ml: 'ml-IN', kn: 'kn-IN' };
  recognition.lang = langMap[lang] || 'en-US';

  return recognition;
}

export function speak(text, lang = 'en', callbacks = {}) {
  if (!window.speechSynthesis) return null;

  window.speechSynthesis.cancel();
  const utterance = new SpeechSynthesisUtterance(text);

  const langMap = { en: 'en-US', ta: 'ta-IN', hi: 'hi-IN', te: 'te-IN', ml: 'ml-IN', kn: 'kn-IN' };
  const targetLang = langMap[lang] || 'en-US';
  utterance.lang = targetLang;
  utterance.rate = 0.95;
  utterance.pitch = 1;

  const voices = window.speechSynthesis.getVoices();
  if (voices.length > 0) {
    const langPrefix = targetLang.split('-')[0];
    // Prefer Google, Natural, or Premium voices for the target language
    const preferredVoice = voices.find(v => v.lang.startsWith(langPrefix) && (v.name.includes('Google') || v.name.includes('Natural') || v.name.includes('Online') || v.name.includes('Premium')));
    if (preferredVoice) {
      utterance.voice = preferredVoice;
    } else {
      const fallbackVoice = voices.find(v => v.lang.startsWith(langPrefix));
      if (fallbackVoice) utterance.voice = fallbackVoice;
    }
  }

  // Handle Chrome's 15-second TTS limit bug by pausing and resuming
  let resumeTimer;
  utterance.onstart = (e) => {
    if (callbacks.onStart) callbacks.onStart(e);
    resumeTimer = setInterval(() => {
      if (window.speechSynthesis.speaking && !window.speechSynthesis.paused) {
        window.speechSynthesis.pause();
        window.speechSynthesis.resume();
      }
    }, 14000);
  };

  utterance.onend = (e) => {
    clearInterval(resumeTimer);
    if (callbacks.onEnd) callbacks.onEnd(e);
  };
  utterance.onerror = (e) => {
    clearInterval(resumeTimer);
    if (callbacks.onError) callbacks.onError(e);
  };

  window.speechSynthesis.speak(utterance);
  return utterance;
}

export function stopSpeaking() {
  if (window.speechSynthesis) window.speechSynthesis.cancel();
}

export function pauseSpeaking() {
  if (window.speechSynthesis) window.speechSynthesis.pause();
}

export function resumeSpeaking() {
  if (window.speechSynthesis) window.speechSynthesis.resume();
}
