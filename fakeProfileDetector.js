// ═══════════════════════════════════════════════════════
// CYBERSENTINEL — Fake Profile Detection Engine
// Instagram / Facebook / Twitter/X Analysis (30+ signals)
// ═══════════════════════════════════════════════════════

import { FAKE_PROFILE_PATTERNS } from '../data/fakeProfilePatterns';

function clamp(v, min = 0, max = 100) { return Math.max(min, Math.min(max, v)); }

function analyzeUsername(username, platform) {
  const signals = [];
  let score = 0;
  const u = username.toLowerCase().trim().replace(/^@/, '');

  // Random chars/numbers
  if (/[a-z]{1,3}\d{5,}/.test(u) || /\d{5,}[a-z]{1,3}/.test(u)) {
    signals.push({ signal: 'Random character/number pattern', severity: 'high', detail: `Username "${u}" contains random character+number sequences typical of auto-generated accounts` });
    score += 25;
  }

  // Excessive special chars
  const specialCount = (u.match(/[_.]/g) || []).length;
  if (specialCount > 3) {
    signals.push({ signal: 'Excessive special characters', severity: 'medium', detail: `${specialCount} dots/underscores detected — common in impersonation accounts` });
    score += 15;
  }

  // Impersonation patterns
  const impPatterns = ['_official', 'official_', 'real_', '_real', '_backup', 'backup_', '_original', '_authentic', '_verified', '_legit', '_2024', '_2025', '_2026', '_new', '_main'];
  for (const p of impPatterns) {
    if (u.includes(p)) {
      signals.push({ signal: 'Impersonation suffix/prefix', severity: 'high', detail: `Contains "${p}" — commonly used by impersonation accounts` });
      score += 20;
      break;
    }
  }

  // Keyboard walk
  const walks = ['qwerty', 'asdfgh', 'zxcvbn', '123456', 'abcdef', 'qazwsx'];
  for (const w of walks) {
    if (u.includes(w)) {
      signals.push({ signal: 'Keyboard walk pattern', severity: 'medium', detail: `Contains keyboard walk "${w}" — suggests randomly created username` });
      score += 15;
      break;
    }
  }

  // Very short username
  if (u.length <= 3) {
    signals.push({ signal: 'Very short username', severity: 'low', detail: 'Extremely short usernames can indicate automated account creation' });
    score += 5;
  }

  // All numbers
  if (/^\d+$/.test(u)) {
    signals.push({ signal: 'All-numeric username', severity: 'high', detail: 'Username is entirely numbers — very suspicious' });
    score += 25;
  }

  return { signals, score: clamp(score) };
}

function analyzeMetadata(data, platform) {
  const signals = [];
  let score = 0;

  // Bio analysis
  if (!data.bio || data.bio.trim().length === 0) {
    signals.push({ signal: 'Empty bio', severity: 'medium', detail: 'No bio text — real active accounts usually have descriptions' });
    score += 10;
  } else {
    const bio = data.bio.toLowerCase();
    const suspiciousBioKeywords = ['dm for collab', 'earn money', 'make money', 'crypto', 'bitcoin', 'forex', 'binary', 'investment', 'cashapp', 'follow back', 'f4f', 'l4l', 'dm me', 'link in bio', 'whatsapp me', 'telegram', 'free iphone', 'giveaway', '18+', 'onlyfans', 'financial freedom'];
    const found = suspiciousBioKeywords.filter(kw => bio.includes(kw));
    if (found.length > 0) {
      signals.push({ signal: 'Suspicious bio keywords', severity: 'high', detail: `Bio contains suspicious keywords: ${found.join(', ')}` });
      score += found.length * 8;
    }

    // URLs in bio
    const urlCount = (bio.match(/https?:\/\//g) || []).length + (bio.match(/bit\.ly|tinyurl|t\.co|linktr\.ee/g) || []).length;
    if (urlCount > 2) {
      signals.push({ signal: 'Multiple links in bio', severity: 'medium', detail: `${urlCount} links in bio — may be promoting suspicious content` });
      score += 10;
    }
  }

  // No profile picture
  if (data.noProfilePic) {
    signals.push({ signal: 'No profile picture', severity: 'medium', detail: 'Account has no profile picture — common for fake/bot accounts' });
    score += 15;
  }

  // Verified claim but unverified
  if (data.claimsVerified && !data.isVerified) {
    signals.push({ signal: 'False verification claim', severity: 'critical', detail: 'Account claims to be verified but lacks official verification badge' });
    score += 30;
  }

  // Account age
  if (data.accountAgeDays !== undefined && data.accountAgeDays < 30) {
    signals.push({ signal: 'Very new account', severity: 'high', detail: `Account is only ${data.accountAgeDays} days old` });
    score += 20;
  } else if (data.accountAgeDays !== undefined && data.accountAgeDays < 90) {
    signals.push({ signal: 'Recently created account', severity: 'medium', detail: `Account is ${data.accountAgeDays} days old` });
    score += 10;
  }

  return { signals, score: clamp(score) };
}

function analyzeFollowerRatio(data) {
  const signals = [];
  let score = 0;
  const { followers = 0, following = 0, posts = 0 } = data;

  // Zero/very few followers with high following
  if (followers < 10 && following > 500) {
    signals.push({ signal: 'Mass following with no followers', severity: 'critical', detail: `${followers} followers but following ${following} accounts — strong bot/spam indicator` });
    score += 35;
  } else if (followers < 50 && following > 1000) {
    signals.push({ signal: 'Extreme follow-to-follower imbalance', severity: 'high', detail: `Following ${following} but only ${followers} followers` });
    score += 25;
  }

  // Follower/following ratio
  if (following > 0 && followers > 0) {
    const ratio = followers / following;
    if (ratio < 0.05 && following > 100) {
      signals.push({ signal: 'Very low follower ratio', severity: 'high', detail: `Follower/following ratio: ${ratio.toFixed(3)} — typical of spam accounts` });
      score += 20;
    }
  }

  // Suspicious round numbers (bought followers)
  if (followers > 1000) {
    const isRound = followers % 1000 === 0 || followers % 500 === 0;
    if (isRound && followers >= 5000) {
      signals.push({ signal: 'Suspicious follower count', severity: 'medium', detail: `Exactly ${followers.toLocaleString()} followers — round numbers can indicate purchased followers` });
      score += 10;
    }
  }

  // No posts but many followers
  if (posts === 0 && followers > 100) {
    signals.push({ signal: 'No posts but has followers', severity: 'high', detail: `${followers} followers but 0 posts — suspicious combination` });
    score += 20;
  }

  // Very high follower count with very low engagement
  if (data.avgLikes !== undefined && followers > 1000) {
    const engagementRate = (data.avgLikes / followers) * 100;
    if (engagementRate < 0.5) {
      signals.push({ signal: 'Extremely low engagement rate', severity: 'high', detail: `Engagement rate: ${engagementRate.toFixed(2)}% — suggests purchased/fake followers` });
      score += 25;
    } else if (engagementRate < 1.5) {
      signals.push({ signal: 'Below average engagement', severity: 'medium', detail: `Engagement rate: ${engagementRate.toFixed(2)}% (average is 2-5%)` });
      score += 10;
    }
  }

  return { signals, score: clamp(score) };
}

function analyzeContentPatterns(data) {
  const signals = [];
  let score = 0;

  // Generic comments
  if (data.sampleComments && data.sampleComments.length > 0) {
    const genericPhrases = ['nice', 'great', 'awesome', 'beautiful', 'amazing', 'wow', 'love it', 'follow me', 'check my', 'dm me', '🔥', '❤️', '😍', '💯', 'follow back'];
    const genericCount = data.sampleComments.filter(c => {
      const lower = c.toLowerCase();
      return genericPhrases.some(gp => lower.includes(gp)) && lower.length < 30;
    }).length;

    if (genericCount > data.sampleComments.length * 0.7) {
      signals.push({ signal: 'Generic comment patterns', severity: 'high', detail: `${genericCount}/${data.sampleComments.length} comments are generic/bot-like` });
      score += 20;
    }
  }

  // Hashtag spam
  if (data.hashtagsPerPost !== undefined && data.hashtagsPerPost > 20) {
    signals.push({ signal: 'Hashtag spam', severity: 'medium', detail: `Average ${data.hashtagsPerPost} hashtags per post — typical of spam accounts` });
    score += 15;
  }

  // Specific spam hashtags
  if (data.commonHashtags) {
    const spamTags = ['followforfollow', 'f4f', 'likeforlike', 'l4l', 'follow4follow', 'like4like', 'followback', 'teamfollowback', 'gainwithxjane'];
    const found = data.commonHashtags.filter(h => spamTags.includes(h.toLowerCase().replace('#', '')));
    if (found.length > 0) {
      signals.push({ signal: 'Spam hashtags detected', severity: 'high', detail: `Uses known spam hashtags: ${found.join(', ')}` });
      score += 20;
    }
  }

  // Link spam in posts
  if (data.linksInPosts !== undefined && data.linksInPosts > 5) {
    signals.push({ signal: 'Excessive links in posts', severity: 'medium', detail: `${data.linksInPosts} external links across posts — may be promoting suspicious content` });
    score += 15;
  }

  // All content is reposts/shared
  if (data.originalContentRatio !== undefined && data.originalContentRatio < 0.1) {
    signals.push({ signal: 'No original content', severity: 'high', detail: `Only ${(data.originalContentRatio * 100).toFixed(0)}% original content — mostly reposts/shares` });
    score += 20;
  }

  return { signals, score: clamp(score) };
}

function analyzePlatformSpecific(data, platform) {
  const signals = [];
  let score = 0;

  if (platform === 'instagram') {
    if (data.storyHighlights !== undefined && data.storyHighlights === 0 && data.accountAgeDays > 180) {
      signals.push({ signal: 'No story highlights on old account', severity: 'medium', detail: 'Account is over 6 months old but has no story highlights' });
      score += 10;
    }
    if (data.taggedPhotos !== undefined && data.taggedPhotos === 0 && data.followers > 100) {
      signals.push({ signal: 'No tagged photos', severity: 'medium', detail: 'No photos tagged by other users — real people are typically tagged by friends' });
      score += 12;
    }
    if (data.mutualFollowers !== undefined && data.mutualFollowers === 0) {
      signals.push({ signal: 'No mutual connections', severity: 'medium', detail: 'No mutual followers with your network' });
      score += 10;
    }
  }

  if (platform === 'facebook') {
    if (data.friendCount !== undefined) {
      if (data.friendCount > 4000 && data.accountAgeDays < 180) {
        signals.push({ signal: 'Rapid friend accumulation', severity: 'high', detail: `${data.friendCount} friends in ${data.accountAgeDays} days — abnormal growth rate` });
        score += 20;
      }
    }
    if (data.timelineDepth !== undefined && data.timelineDepth < 2 && data.accountAgeDays > 365) {
      signals.push({ signal: 'Shallow timeline', severity: 'high', detail: 'Account claims to be old but has very few years of timeline activity' });
      score += 18;
    }
    if (data.profilePhotoChanges !== undefined && data.profilePhotoChanges > 10 && data.accountAgeDays < 90) {
      signals.push({ signal: 'Frequent profile photo changes', severity: 'high', detail: `${data.profilePhotoChanges} photo changes in ${data.accountAgeDays} days — possible catfishing` });
      score += 20;
    }
    if (data.sharedVsOriginal !== undefined && data.sharedVsOriginal > 0.9) {
      signals.push({ signal: 'Mostly shared content', severity: 'medium', detail: 'Over 90% of posts are shares/reposts — no original content' });
      score += 12;
    }
  }

  if (platform === 'twitter') {
    if (data.tweetCount !== undefined && data.followers > 0) {
      const tweetPerFollower = data.tweetCount / data.followers;
      if (tweetPerFollower > 100) {
        signals.push({ signal: 'Abnormal tweet-to-follower ratio', severity: 'high', detail: `${data.tweetCount} tweets for ${data.followers} followers — potential spam bot` });
        score += 20;
      }
    }
    if (data.retweetRatio !== undefined && data.retweetRatio > 0.85) {
      signals.push({ signal: 'Mostly retweets', severity: 'high', detail: `${(data.retweetRatio * 100).toFixed(0)}% of activity is retweets — bot behavior` });
      score += 22;
    }
    if (data.listMemberships !== undefined && data.listMemberships === 0 && data.followers > 500) {
      signals.push({ signal: 'Not on any lists', severity: 'medium', detail: 'Not added to any Twitter lists despite having followers' });
      score += 10;
    }
    if (data.replyPatterns && data.replyPatterns === 'automated') {
      signals.push({ signal: 'Automated reply patterns', severity: 'critical', detail: 'Replies appear scripted/automated' });
      score += 25;
    }
  }

  return { signals, score: clamp(score) };
}

function analyzeUsernameDisplayNameMismatch(username, displayName) {
  const signals = [];
  let score = 0;

  if (!displayName || !username) return { signals, score };

  const uClean = username.toLowerCase().replace(/[_.\-@]/g, '');
  const dClean = displayName.toLowerCase().replace(/[^a-z]/g, '');

  // Check if username and display name share any words
  const dWords = displayName.toLowerCase().split(/\s+/).filter(w => w.length > 2);
  const hasOverlap = dWords.some(w => uClean.includes(w));

  if (!hasOverlap && dWords.length > 0 && uClean.length > 3) {
    signals.push({ signal: 'Username-DisplayName mismatch', severity: 'medium', detail: `Username "${username}" doesn't match display name "${displayName}"` });
    score += 12;
  }

  return { signals, score: clamp(score) };
}

export function analyzeFakeProfile(profileData) {
  const { platform = 'instagram', username = '', displayName = '' } = profileData;

  // Run all analyzers
  const usernameResult = analyzeUsername(username, platform);
  const metadataResult = analyzeMetadata(profileData, platform);
  const followerResult = analyzeFollowerRatio(profileData);
  const contentResult = analyzeContentPatterns(profileData);
  const platformResult = analyzePlatformSpecific(profileData, platform);
  const mismatchResult = analyzeUsernameDisplayNameMismatch(username, displayName);

  // Combine all signals
  const allSignals = [
    ...usernameResult.signals.map(s => ({ ...s, category: 'Username Analysis' })),
    ...mismatchResult.signals.map(s => ({ ...s, category: 'Name Consistency' })),
    ...metadataResult.signals.map(s => ({ ...s, category: 'Profile Metadata' })),
    ...followerResult.signals.map(s => ({ ...s, category: 'Follower Analysis' })),
    ...contentResult.signals.map(s => ({ ...s, category: 'Content Patterns' })),
    ...platformResult.signals.map(s => ({ ...s, category: `${platform.charAt(0).toUpperCase() + platform.slice(1)} Specific` })),
  ];

  // Calculate weighted authenticity score (0 = fake, 100 = real)
  const rawRisk = (
    usernameResult.score * 0.15 +
    metadataResult.score * 0.2 +
    followerResult.score * 0.25 +
    contentResult.score * 0.15 +
    platformResult.score * 0.15 +
    mismatchResult.score * 0.1
  );

  const authenticityScore = clamp(100 - rawRisk);

  // Determine verdict
  let verdict, verdictColor, verdictEmoji;
  if (authenticityScore >= 80) {
    verdict = 'Likely Authentic';
    verdictColor = 'low';
    verdictEmoji = '🟢';
  } else if (authenticityScore >= 50) {
    verdict = 'Uncertain';
    verdictColor = 'medium';
    verdictEmoji = '🟡';
  } else if (authenticityScore >= 25) {
    verdict = 'Suspicious';
    verdictColor = 'high';
    verdictEmoji = '🟠';
  } else {
    verdict = 'Likely Fake';
    verdictColor = 'critical';
    verdictEmoji = '🔴';
  }

  // Category breakdown
  const breakdown = {
    username: { score: 100 - usernameResult.score, label: 'Username Analysis' },
    metadata: { score: 100 - metadataResult.score, label: 'Profile Metadata' },
    followers: { score: 100 - followerResult.score, label: 'Follower Analysis' },
    content: { score: 100 - contentResult.score, label: 'Content Patterns' },
    platform: { score: 100 - platformResult.score, label: `${platform.charAt(0).toUpperCase() + platform.slice(1)} Signals` },
    nameconsistency: { score: 100 - mismatchResult.score, label: 'Name Consistency' },
  };

  return {
    authenticityScore,
    verdict,
    verdictColor,
    verdictEmoji,
    platform,
    username,
    displayName,
    allSignals,
    breakdown,
    totalSignals: allSignals.length,
    criticalSignals: allSignals.filter(s => s.severity === 'critical').length,
    highSignals: allSignals.filter(s => s.severity === 'high').length,
    mediumSignals: allSignals.filter(s => s.severity === 'medium').length,
    lowSignals: allSignals.filter(s => s.severity === 'low').length,
    disclaimer: 'This is an AI-based assessment and not absolute proof. Always use additional verification methods.',
    recommendations: generateRecommendations(authenticityScore, allSignals, platform),
  };
}

function generateRecommendations(score, signals, platform) {
  const recs = [];

  if (score < 50) {
    recs.push({ icon: '🚫', action: 'Do not share personal information with this account' });
    recs.push({ icon: '🔒', action: 'Do not click any links shared by this account' });
    recs.push({ icon: '📢', action: `Report this account to ${platform} for review` });
    recs.push({ icon: '🛡️', action: 'Block this account to prevent further contact' });
  }

  if (score < 75) {
    recs.push({ icon: '🔍', action: 'Verify identity through official/alternative channels' });
    recs.push({ icon: '👥', action: 'Check for mutual connections who can verify this person' });
  }

  if (signals.some(s => s.signal.includes('impersonation') || s.signal.includes('Impersonation'))) {
    recs.push({ icon: '⚠️', action: 'If this claims to be someone you know, contact them directly through a known channel' });
  }

  if (signals.some(s => s.signal.includes('follower') || s.signal.includes('engagement'))) {
    recs.push({ icon: '📊', action: 'Check recent activity — genuine accounts show organic growth patterns' });
  }

  recs.push({ icon: '🧠', action: 'Trust your instincts — if something feels off, proceed with caution' });

  return recs;
}
