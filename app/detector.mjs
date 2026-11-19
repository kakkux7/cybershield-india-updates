/* CyberShield India Beta 0.2 — offline, explainable indicators only.
 * Does NOT query reputation feeds, visit URLs, or claim a link is safe.
 */

const BRAND_DOMAINS = [
  { re: /(?:^|[.-])sbi(?:[.-]|$)|statebank/i, domains: ['sbi.co.in','onlinesbi.sbi','bank.sbi','sbi'] , name: 'SBI' },
  { re: /(?:^|[.-])hdfc(?:[.-]|$)/i, domains: ['hdfcbank.com'], name: 'HDFC Bank' },
  { re: /(?:^|[.-])icici(?:[.-]|$)/i, domains: ['icicibank.com'], name: 'ICICI Bank' },
  { re: /(?:^|[.-])axis(?:[.-]|$)/i, domains: ['axisbank.com'], name: 'Axis Bank' },
  { re: /(?:^|[.-])paytm(?:[.-]|$)/i, domains: ['paytm.com','paytmbank.com'], name: 'Paytm' },
  { re: /phonepe/i, domains: ['phonepe.com'], name: 'PhonePe' },
  { re: /(?:^|[.-])irctc(?:[.-]|$)/i, domains: ['irctc.co.in','irctc.com'], name: 'IRCTC' },
  { re: /(?:^|[.-])aadhaar(?:[.-]|$)|uidai/i, domains: ['uidai.gov.in'], name: 'Aadhaar / UIDAI' },
  { re: /(?:^|[.-])amazon(?:[.-]|$)/i, domains: ['amazon.in','amazon.com'], name: 'Amazon' },
];
const SHORTENERS = new Set(['bit.ly','tinyurl.com','t.co','cutt.ly','is.gd','rb.gy','shorturl.at','tiny.cc','rebrand.ly']);
const UNUSUAL_TLDS = new Set(['zip','mov','click','top','xyz','icu','rest','cam','buzz']);
const EXECUTABLE_EXT = /\.(?:apk|exe|scr|bat|cmd|msi|jar|ps1|vbs)(?:$|[?#])/i;
const URL_PATTERN = /https?:\/\/[^\s<>"'`]+|\b(?:www\.)?[a-z0-9][a-z0-9.-]+\.[a-z]{2,}(?:\/[^\s<>"'`]*)?/i;

function add(findings, weight, heading, detail) { findings.push({ weight, heading, detail }); }
function result(type, score, findings, subject) {
  const capped = Math.min(100, score);
  const level = capped >= 55 ? 'high' : capped >= 18 ? 'caution' : 'unknown';
  return { type, level, score: capped, subject, findings,
    label: level === 'high' ? 'High risk indicators' : level === 'caution' ? 'Use caution' : 'No major warning signs found',
    summary: level === 'high' ? 'Avoid opening or sharing sensitive information until independently verified.' :
      level === 'caution' ? 'Some signals deserve a closer check. Verify through official channels.' :
      'This basic offline check found no major indicators. It cannot confirm that this is safe.' };
}
export function extractURL(text) {
  if (typeof text !== 'string') return '';
  return (text.match(URL_PATTERN) || [''])[0].replace(/[),.;!?]+$/, '');
}
export function analyzeLink(input) {
  if (typeof input !== 'string' || !input.trim()) throw new Error('Enter a link to analyze.');
  const candidate = input.trim();
  if (candidate.length > 2048) throw new Error('This link is too long for the beta checker (2,048 characters max).');
  if (/[\x00-\x1F\x7F]/.test(candidate) || /\s/.test(candidate)) throw new Error('Paste one URL without spaces or line breaks.');
  if (/^[a-z][a-z\d+.-]*:/i.test(candidate) && !/^https?:\/\//i.test(candidate)) {
    throw new Error('Only http:// and https:// website links are supported. Never open scripts or file links from strangers.');
  }
  const normalized = /^https?:\/\//i.test(candidate) ? candidate : `https://${candidate}`;
  let url;
  try { url = new URL(normalized); } catch { throw new Error('This does not look like a valid website link.'); }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || !url.hostname.includes('.') && url.hostname !== 'localhost') {
    throw new Error('Enter a complete public website address, such as example.com.');
  }
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  const path = `${url.pathname}${url.search}`.toLowerCase();
  const findings = [];
  const officialMatch = (domain) => host === domain || host.endsWith(`.${domain}`);
  if (url.protocol === 'http:') add(findings, 18, 'Connection is not encrypted', 'The link uses HTTP rather than HTTPS.');
  if (url.username || url.password || /@/.test(candidate.slice(0, candidate.indexOf('/') === -1 ? candidate.length : candidate.indexOf('/', 8)))) {
    add(findings, 45, 'Misleading address structure', 'An @ sign or embedded username can conceal the actual destination.');
  }
  if (host.includes('xn--')) add(findings, 30, 'Punycode domain', 'Encoded international characters can sometimes imitate well-known domains.');
  if (/\d+\.\d+\.\d+\.\d+/.test(host) && /^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    add(findings, 22, 'IP address instead of a domain', 'Direct IP links are less recognizable than named websites.');
  }
  if (SHORTENERS.has(host)) add(findings, 23, 'Shortened destination', 'The final website is hidden until the shortened link is resolved.');
  const pieces = host.split('.');
  if (pieces.length > 4) add(findings, 11, 'Complex subdomain', 'The hostname has many segments, which can make the true site hard to spot.');
  if (pieces.some(s => s.length > 35)) add(findings, 12, 'Unusually long domain segment', 'Long or confusing domain segments may deserve extra caution.');
  if (UNUSUAL_TLDS.has(pieces.at(-1))) add(findings, 12, 'Uncommon domain ending', 'The domain ending is sometimes used in scams, although legitimate sites use it too.');
  if (EXECUTABLE_EXT.test(path)) add(findings, 35, 'Software download link', 'The URL appears to download an installable or executable file. Avoid unknown software.');
  if (/(?:kyc|verify|verification|unlock|suspended|re-activate|reactivate|claim-prize|urgent|lottery|free-gift|refund)/i.test(path)) {
    add(findings, 17, 'Sensitive action in the URL', 'The path mentions verification, account access, reward or urgency.');
  }
  if (/(?:kyc|verify|update|secure|customer|support|login|banking|refund|claim|bonus)/i.test(host)) {
    add(findings, 12, 'Pressure or banking language in domain', 'Such words in a domain can be used to impersonate official services.');
  }
  for (const brand of BRAND_DOMAINS) {
    if (brand.re.test(host) && !brand.domains.some(officialMatch)) {
      add(findings, 44, `${brand.name} name on an unofficial-looking domain`, 'The domain mentions a familiar organization but does not match its listed main domains. This is a warning, not definitive proof of fraud.');
      break;
    }
  }
  if (/%(?:25|2f|40|5c)/i.test(candidate)) add(findings, 12, 'Encoded address characters', 'Some URL encoding can make a destination harder to read.');
  const score = findings.reduce((sum, item) => sum + item.weight, 0);
  if (!findings.length) add(findings, 0, 'No obvious structural warnings', 'No major indicators were spotted by this offline ruleset. New phishing sites can still look normal.');
  return result('link', score, findings, host);
}

const MESSAGE_RULES = [
  { regex: /\b(?:otp|one.time.password|pin|cvv|password|passcode)\b|ഒടിപി|पासवर्ड|ओटीपी/i, weight: 35, heading: 'Request involving secret codes', detail: 'Never disclose OTP, UPI PIN, CVV or passwords to anyone.' },
  { regex: /digital\s*arrest|police\s*(?:case|custody|notice)|cbi\s*officer|ഡിജിറ്റൽ അറസ്റ്റ്|डिजिटल अरेस्ट/i, weight: 38, heading: 'Authority impersonation', detail: 'Digital arrest threats are a widely used intimidation tactic. Verify through official channels.' },
  { regex: /(?:account|bank|sim|kyc).{0,45}(?:block|suspend|expire|deactivat|freeze)|(?:block|suspend|expire).{0,45}(?:account|bank|sim)|അക്കൗണ്ട്.*(?:ബ്ലോക്ക്|സസ്പെൻഡ്)|खाता.*(?:बंद|ब्लॉक)/i, weight: 25, heading: 'Account shutdown pressure', detail: 'Scammers often threaten account suspension to force quick action.' },
  { regex: /urgent|immediately|within\s*\d+\s*(?:minutes|hours)|last\s*chance|ഇപ്പോൾ തന്നെ|ഉടൻ|तुरंत|अभी/i, weight: 13, heading: 'Urgency or pressure', detail: 'Take time to verify requests before acting.' },
  { regex: /(?:guaranteed|daily|quick|instant).{0,30}(?:profit|return|income)|double your money|\b(?:earn|salary)\s*₹?\s*\d{4,}/i, weight: 24, heading: 'Unrealistic financial promise', detail: 'Guaranteed returns and effortless earning offers can be warning signs.' },
  { regex: /(?:scan|share|send).{0,40}(?:qr|upi|payment)|pay\s*(?:a\s*)?(?:fee|deposit|charge).{0,30}(?:refund|prize|job)/i, weight: 26, heading: 'Suspicious payment instruction', detail: 'Receiving money does not require entering a UPI PIN. Be careful with payment requests.' },
  { regex: /(?:click|open|visit|tap).{0,20}(?:link|here|url)|(?:verify|update).{0,25}(?:https?:\/\/|www\.)|ലിങ്കിൽ ക്ലിക്ക്|लिंक पर क्लिक/i, weight: 14, heading: 'Instruction to follow a link', detail: 'Open the official app or type the known official address yourself instead.' },
  { regex: /(?:lottery|winner|congratulations|prize|gift card|free reward)|ലോട്ടറി|സമ്മാനം|इनाम|लॉटरी/i, weight: 19, heading: 'Prize or reward claim', detail: 'Unexpected prizes often come with fraudulent conditions.' },
];
export function analyzeMessage(input) {
  if (typeof input !== 'string' || !input.trim()) throw new Error('Paste a message to analyze.');
  const text = input.trim().slice(0, 5000);
  const findings = [];
  for (const rule of MESSAGE_RULES) if (rule.regex.test(text)) add(findings, rule.weight, rule.heading, rule.detail);
  const extracted = extractURL(text);
  if (extracted) {
    add(findings, 10, 'Message contains a website link', 'Check the link separately before following it.');
    try {
      const check = analyzeLink(extracted);
      if (check.score >= 18) add(findings, Math.min(40, Math.ceil(check.score / 2)), 'Link contains risk indicators', `The included link (${check.subject}) also deserves caution.`);
    } catch { /* no remote request */ }
  }
  if (!findings.length) add(findings, 0, 'No obvious scam phrases found', 'This is only a pattern check. Fraudsters can use convincing, ordinary-sounding language.');
  return result('message', findings.reduce((s,f)=>s+f.weight,0), findings, 'Message analysis');
}
