const clamp = (value) => Math.min(Math.max(value, 0), 100);

const getRiskLevel = (score) => {
  if (score >= 70) return 'HIGH RISK';
  if (score >= 35) return 'SUSPICIOUS';
  return 'SAFE';
};

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
  let parsedUrl;

  try {
    parsedUrl = new URL(value);
  } catch {
    score += 20;
    indicators.push('Invalid URL format');
  }

  if (parsedUrl) {
    const hostname = parsedUrl.hostname.toLowerCase();
    const path = `${parsedUrl.pathname}${parsedUrl.search}`.toLowerCase();
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      score += 25;
      indicators.push('Unexpected URL protocol');
    } else if (parsedUrl.protocol !== 'https:') {
      score += 22;
      indicators.push('HTTP instead of HTTPS');
    }

    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) {
      score += 25;
      indicators.push('IP address instead of a normal domain');
    }

    if (/(bit\.ly|tinyurl|t\.co|cutt\.ly|goo\.gl|ow\.ly|is\.gd)/.test(hostname)) {
      score += 20;
      indicators.push('Shortened URL');
    }

    if (hostname.split('.').length - 2 > 2) {
      score += 12;
      indicators.push('Excessive subdomains');
    }

    for (const keyword of ['login', 'verify', 'secure', 'claim', 'reward', 'otp', 'account', 'update', 'bank', 'invoice']) {
      if (path.includes(keyword)) {
        score += 10;
        indicators.push(`Phishing keyword detected: ${keyword}`);
      }
    }

    if (['g00gle', 'micr0soft', 'faceboook', 'appl3', 'lnstagram'].some((brand) => hostname.includes(brand))) {
      score += 18;
      indicators.push('Misspelled brand-like domain');
    }

    if (['-login', '-verify', '-secure', '-update'].some((pattern) => hostname.includes(pattern))) {
      score += 12;
      indicators.push('Suspicious brand impersonation pattern');
    }
  }

  score = clamp(score);
  const riskLevel = getRiskLevel(score);
  return {
    score,
    riskLevel,
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
