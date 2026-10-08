const clamp = (value) => Math.min(Math.max(value, 0), 100);

const getRiskLevel = (score) => {
  if (score >= 70) return 'HIGH RISK';
  if (score >= 35) return 'SUSPICIOUS';
  return 'SAFE';
};

const brandDomains = [
  { brand: 'amazon', domain: 'amazon.com' },
  { brand: 'apple', domain: 'apple.com' },
  { brand: 'facebook', domain: 'facebook.com' },
  { brand: 'google', domain: 'google.com' },
  { brand: 'instagram', domain: 'instagram.com' },
  { brand: 'microsoft', domain: 'microsoft.com' },
  { brand: 'netflix', domain: 'netflix.com' },
  { brand: 'paypal', domain: 'paypal.com' },
  { brand: 'whatsapp', domain: 'whatsapp.com' },
  { brand: 'youtube', domain: 'youtube.com' }
];

function editDistanceAtMostOne(left, right) {
  if (Math.abs(left.length - right.length) > 1) return false;
  let leftIndex = 0;
  let rightIndex = 0;
  let edits = 0;

  while (leftIndex < left.length && rightIndex < right.length) {
    if (left[leftIndex] === right[rightIndex]) {
      leftIndex += 1;
      rightIndex += 1;
      continue;
    }

    edits += 1;
    if (edits > 1) return false;
    if (left.length >= right.length) leftIndex += 1;
    if (right.length >= left.length) rightIndex += 1;
  }

  return edits + (leftIndex < left.length || rightIndex < right.length ? 1 : 0) <= 1;
}

function getMessageThreatType(message) {
  if (/otp|bank details|bank account|update kyc|kyc|expired.*account|account.*blocked/i.test(message)) return 'Fake bank message / KYC scam';
  if (/winner|won|cash prize|reward|lottery|selected.*prize|claim.*reward/i.test(message)) return 'Lottery / Prize scam';
  if (/job|internship|work from home|registration fee|pay.*₹|registration.*fee/i.test(message)) return 'Fake job / internship scam';
  if (/delivery|courier|parcel.*waiting|pay .* delivery charges/i.test(message)) return 'Delivery / courier scam';
  if (/click here|link|verify now|urgent|immediately|limited time|action required/i.test(message)) return 'Phishing / Smishing';
  if (/bank|loan|investment|guaranteed returns|double your money/i.test(message)) return 'Investment scam';
  if (/scholarship|selected.*scholarship|offer.*admission/i.test(message)) return 'Fake scholarship scam';
  if (/account.*locked|password.*expired|secure.*login|update.*login/i.test(message)) return 'Credential theft attempt';
  return 'General suspicious message';
}

export function analyzeMessage(input) {
  const text = input.trim();
  let score = 6;
  const warnings = [];
  const rules = [
    { pattern: /otp|one time password/i, label: 'Requests OTP', points: 16 },
    { pattern: /bank details|bank account|account number|ifsc|cvv|pin/i, label: 'Requests bank information', points: 15 },
    { pattern: /win|won|selected|congratulations|reward|cash prize|lottery|claim/i, label: 'Fake reward claim', points: 17 },
    { pattern: /kyc|update now|account.*blocked|expired.*account|verify.*immediately/i, label: 'Urgent KYC or account alert', points: 14 },
    { pattern: /urgent|immediately|today only|limited time|act now|within hours/i, label: 'Creates urgency', points: 12 },
    { pattern: /click now|click here|click this link|link|http:|https?:\/\//i, label: 'Suspicious link', points: 14 },
    { pattern: /pay|payment|registration fee|delivery charges|security deposit|advance payment/i, label: 'Requests payment or fee', points: 15 },
    { pattern: /job|work from home|internship|salary|remote work|easy money/i, label: 'Fake job offer', points: 13 },
    { pattern: /scholarship|admission offer|selected.*student|free fee|apply now/i, label: 'Fake scholarship alert', points: 12 },
    { pattern: /parcel|delivery|courier|tracking number/i, label: 'Delivery or parcel alert', points: 11 }
  ];

  for (const rule of rules) {
    if (rule.pattern.test(text)) {
      warnings.push(rule.label);
      score += rule.points;
    }
  }

  score = clamp(score);
  const isSafe = score < 35;
  const explanation = isSafe
    ? 'This message does not show strong scam signs, but confirm the sender and be cautious with unexpected links.'
    : `This message may pressure you to act by ${warnings[0]?.toLowerCase() ?? 'making an urgent request'}. Unexpected requests for OTPs, bank details, or advance payments are warning signs.`;

  return {
    score,
    riskLevel: getRiskLevel(score),
    threatType: isSafe ? 'Safe message' : getMessageThreatType(text),
    warnings: warnings.length ? warnings : ['No major scam indicators were detected'],
    explanation,
    recommendation: isSafe
      ? 'No major scam indicators were detected. Still verify links and sender identity before sharing sensitive information.'
      : 'Do not click links or share OTPs, bank details, or PINs. Verify the sender through the organization’s official website or customer-care number.',
    simplified: isSafe
      ? 'This looks mostly normal. Be careful with unknown links and double-check the sender before sharing personal information.'
      : 'This message may be trying to rush or trick you. Do not click its links or share private details or money. Contact the organization using its official number or website.'
  };
}

export function analyzeUrl(input) {
  const value = input.trim();
  let score = 8;
  const indicators = [];
  const reputationChecks = [];
  let parsedUrl;

  const flag = (label, points, detail = label) => {
    score += points;
    indicators.push(label);
    reputationChecks.push({ label, detail, status: 'flagged' });
  };

  try {
    parsedUrl = new URL(value);
  } catch {
    flag('Invalid URL format', 20, 'The input could not be parsed as a complete URL.');
  }

  if (parsedUrl) {
    const hostname = parsedUrl.hostname.toLowerCase();
    const path = `${parsedUrl.pathname}${parsedUrl.search}`.toLowerCase();
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      flag('Unexpected URL protocol', 25, `The URL uses ${parsedUrl.protocol} instead of HTTP or HTTPS.`);
    } else if (parsedUrl.protocol !== 'https:') {
      flag('HTTP instead of HTTPS', 22, 'The connection does not use HTTPS encryption.');
    } else {
      reputationChecks.push({ label: 'HTTPS connection', detail: 'The URL uses HTTPS; this does not establish that the site itself is trustworthy.', status: 'passed' });
    }

    if (parsedUrl.username || parsedUrl.password) {
      flag('Credentials embedded in URL', 20, 'The URL contains user information before the hostname, a common deception technique.');
    } else {
      reputationChecks.push({ label: 'Embedded credentials', detail: 'No username or password is embedded before the hostname.', status: 'passed' });
    }

    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) {
      flag('IP address instead of a normal domain', 25, 'The destination uses a numeric IP address rather than a recognizable domain.');
    }

    if (/(bit\.ly|tinyurl|t\.co|cutt\.ly|goo\.gl|ow\.ly|is\.gd)/.test(hostname)) {
      flag('Shortened URL', 20, 'The final destination is hidden behind a URL-shortening service.');
    }

    if (hostname.split('.').length - 2 > 2) {
      flag('Excessive subdomains', 12, 'Several subdomain levels can obscure which organization controls the site.');
    }

    for (const keyword of ['login', 'verify', 'secure', 'claim', 'reward', 'otp', 'account', 'update', 'bank', 'invoice']) {
      if (path.includes(keyword)) {
        flag(`Phishing keyword detected: ${keyword}`, 10, `The URL path or query includes the sensitive-action term "${keyword}".`);
      }
    }

    const labels = hostname.split('.');
    const impersonatedBrand = brandDomains.find(({ brand, domain }) => {
      if (hostname === domain || hostname.endsWith(`.${domain}`)) return false;
      return labels.some((label) => {
        const candidate = label.replace(/[0-9]/g, (digit) => ({ '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's' })[digit] || digit);
        return candidate === brand || candidate.startsWith(`${brand}-`) || candidate.endsWith(`-${brand}`)
          || (candidate.length >= 4 && editDistanceAtMostOne(candidate, brand));
      });
    });

    if (impersonatedBrand) {
      flag(`Possible ${impersonatedBrand.brand} impersonation`, 22, `A domain label resembles ${impersonatedBrand.brand}, but the hostname is not ${impersonatedBrand.domain} or one of its subdomains.`);
    }

    if (hostname.includes('xn--')) {
      flag('Internationalized (punycode) domain', 15, 'The hostname contains an encoded internationalized label that may visually resemble another domain.');
    } else {
      reputationChecks.push({ label: 'Internationalized domain', detail: 'No punycode-encoded hostname label was detected.', status: 'passed' });
    }

    const riskyLookingTlds = new Set(['click', 'country', 'gq', 'loan', 'men', 'ml', 'mom', 'online', 'rest', 'support', 'top', 'work', 'xyz']);
    const tld = hostname.split('.').at(-1);
    if (riskyLookingTlds.has(tld)) {
      flag(`Uncommon high-risk TLD: .${tld}`, 10, `The .${tld} top-level domain is commonly used in suspicious links; legitimate sites can also use it.`);
    }

    if (parsedUrl.port && !['80', '443'].includes(parsedUrl.port)) {
      flag('Unusual destination port', 10, `The URL specifies non-standard port ${parsedUrl.port}.`);
    } else {
      reputationChecks.push({ label: 'Destination port', detail: 'No unusual destination port was specified.', status: 'passed' });
    }
  }

  score = clamp(score);
  const riskLevel = getRiskLevel(score);
  const domain = parsedUrl?.hostname.toLowerCase() || null;
  return {
    score,
    riskLevel,
    domain,
    reputationSource: 'Local heuristic checks only; no live threat-intelligence feed was queried.',
    reputationChecks,
    threatType: score >= 70 ? 'Potentially suspicious website' : score >= 35 ? 'Suspicious website' : 'Website not verified',
    indicators: indicators.length ? indicators : ['No strong scam indicators detected'],
    status: score >= 70 ? 'Likely phishing' : score >= 35 ? 'Potentially suspicious' : 'Unable to verify',
    recommendation: score >= 70
      ? 'This URL has several warning signs. Do not click it; open the official website directly from a trusted app or browser.'
      : score >= 35
        ? 'This link may be suspicious. Verify the domain manually and avoid entering confidential data until it is confirmed.'
        : 'No obvious red flags were detected, but this does not prove the site is safe. Verify it before sharing sensitive information.'
  };
}
