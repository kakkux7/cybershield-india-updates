/** Evidence-based explanations. No claims of complete malware, website or caller verification. */
import { analyzeLink, analyzeMessage, extractURL } from './detector.mjs';
import { analyzePhone, analyzeQRPayload } from './intelligence.mjs';

const SUBSUFFIXES = new Set(['co.in','gov.in','ac.in','org.in','net.in','edu.in','nic.in','com.au','net.au','org.au','co.uk','org.uk','ac.uk','co.jp','com.br']);
const REDIRECT_PARAMS = new Set(['next','url','u','redirect','redirect_url','redirect_uri','return','return_url','continue','target','dest','destination','callback']);
const PRIVACY_QUERY = /(?:^|_)(?:token|otp|password|passwd|secret|key|session|auth|access_token|code)(?:_|$)/i;
const WHATSAPP_HUMAN = 'A third-party scanner cannot reliably confirm WhatsApp registration, a private subscriber name, or whether caller ID was spoofed.';

export function domainSummary(raw) {
  const input=String(raw||'').trim();
  const u=new URL(/^https?:\/\//i.test(input)?input:'https://'+input);
  if(!['http:','https:'].includes(u.protocol))throw Error('Only http and https addresses can be reviewed.');
  const host=u.hostname.toLowerCase().replace(/\.$/,'');
  if(!host || host==='localhost' || !host.includes('.'))throw Error('Enter a public website address.');
  const labels=host.split('.');
  const suffix=labels.slice(-2).join('.');
  const width=SUBSUFFIXES.has(suffix)?3:2;
  const registered=labels.length>=width?labels.slice(-width).join('.'):host;
  return {host,registered,scheme:u.protocol.slice(0,-1),path:u.pathname,domainMethod:'Approximate domain boundary for common suffixes, NOT verified RDAP ownership.',url:u};
}

export function linkEvidence(raw) {
  const local=analyzeLink(raw);
  const d=domainSummary(raw);
  const checks=[
    {name:'URL structure and lookalike clues',state:'checked',note:`${local.findings.length} visible finding(s) from local patterns`},
    {name:'Actual destination host',state:'checked',note:d.host},
    {name:'Registered domain (approximation)',state:'checked',note:d.registered},
    {name:'Known phishing and malware databases',state:'not-checked',note:'Requires a licensed online provider on a deployed CyberShield backend'},
    {name:'Page scripts, downloads and redirects',state:'not-checked',note:'The destination was not visited or executed in a sandbox'},
    {name:'Domain owner or organization identity',state:'not-verified',note:'A public registrar record does not establish who operates the website'},
  ];
  const warnings=[];
  if(d.scheme==='http')warnings.push('HTTP is not encrypted. HTTPS alone would still not establish trust.');
  if(d.host.startsWith('xn--') || d.host.split('.').some(p=>p.startsWith('xn--')))warnings.push('The domain contains encoded international characters; compare it with the official address.');
  if(d.host.includes('..'))warnings.push('Unexpected empty domain segment.');
  const u=d.url;
  if([...u.searchParams.keys()].some(k=>PRIVACY_QUERY.test(k)))warnings.push('The URL contains query parameter names associated with credentials or access tokens. Avoid forwarding the complete link.');
  for(const [key,val] of u.searchParams) {
    if(!REDIRECT_PARAMS.has(key.toLowerCase()) || val.length>2048)continue;
    try {
      const target=new URL(val, u);
      if(!['http:','https:'].includes(target.protocol)){
        warnings.push(`The ${key} parameter contains a non-website redirect destination.`);
      }else if(target.hostname.toLowerCase()!==d.host){
        warnings.push(`The ${key} parameter points to a DIFFERENT host: ${target.hostname.toLowerCase()}. Never trust only the first domain.`);
      }else warnings.push(`The ${key} parameter can redirect within this domain. A final redirect was not checked.`);
    }catch {warnings.push(`The ${key} parameter includes an unreadable redirect value.`);}
  }
  return {kind:'link',subject:d.host,registeredDomain:d.registered,
    verdict:local.level==='high'?'Strong scam warning signs':local.level==='caution'?'Use caution':'Safety NOT verified',
    why:local.summary, warnings:[...local.findings.filter(f=>f.weight>0).map(f=>f.heading+': '+f.detail),...warnings].slice(0,15),
    checks, next:'If the link asks for a password, payment or OTP, open the official app or type the known website address yourself.',
    limitation:'This is not live website code analysis, antivirus detection, or a guarantee that this link is safe.'};
}

export function messageEvidence(raw) {
  const m=analyzeMessage(raw);
  const first=extractURL(String(raw||''));
  const warnings=m.findings.filter(f=>f.weight>0).map(f=>f.heading+': '+f.detail);
  let destination='No website link recognized in the message.';
  if(first) {
    try {const d=domainSummary(first);destination=`Link points to ${d.host} (approximate registered domain ${d.registered}). Check it separately before opening.`;}
    catch {destination='The message contains a link-shaped string that could not be verified.';}
  }
  return {kind:'message',verdict:m.level==='high'?'Strong scam warning signs':m.level==='caution'?'Use caution':'Safety NOT verified',
    why:m.summary,warnings:warnings.slice(0,15),checks:[
      {name:'Social-engineering language',state:'checked',note:'Locally matched warning-sign phrases'},
      {name:'Embedded website',state:first?'checked':'not-found',note:destination},
      {name:'Sender identity, SMS origin, WhatsApp profile',state:'not-verified',note:'A pasted message cannot prove sender identity'},
      {name:'Live reputation / reported incidents',state:'not-checked',note:'No verified fraud-report database was queried by this local check'}],
    next:'Do not share OTP, PIN or money. Call the organization using a number independently found on its official site.',
    limitation:'Scam language detection is imperfect; convincing fraudulent messages can have no visible warning words.'};
}

export function phoneEvidence(raw) {
  const p=analyzePhone(raw);
  return {kind:'number',verdict:'Caller identity NOT verified',why:p.summary,
    warnings:p.findings.map(f=>f.heading+': '+f.detail),checks:[
      {name:'Number-format hints',state:'checked',note:p.formatted||'Format unknown'},
      {name:'Current carrier and line type',state:'not-verified',note:'Only if a supported licensed metadata provider is connected; mobile number portability limits certainty'},
      {name:'Private subscriber name and WhatsApp account',state:'not-available',note:WHATSAPP_HUMAN},
      {name:'Live scammer database and caller spoofing',state:'not-checked',note:'No globally complete, reliable reputation or spoofing lookup exists'}],
    next:'Hang up on pressure tactics and call the institution through its official published number. Report suspected fraud through trusted channels.',
    limitation:'Caller ID can be spoofed. No number, name or carrier result can establish a caller is safe.'};
}

export function qrEvidence(raw) {
  const q=analyzeQRPayload(raw);
  const source=String(raw||'').trim();
  const checks=[{name:'QR payload decoded',state:'checked',note:q.subject||'Non-website data'},
    {name:'Live merchant or UPI recipient identity',state:'not-verified',note:'A label in a QR is not a verified merchant identity'},
    {name:'Live malware/phishing URL reputation',state:'not-checked',note:'Only available through configured provider lookup'}];
  const warnings=q.findings.map(f=>f.heading+': '+f.detail);
  if(/^upi:\/\/pay\?/i.test(source)) {
    try {const u=new URL(source);const am=u.searchParams.get('am');const currency=u.searchParams.get('cu');
      if(am)warnings.push(`Amount prefilled in QR: ${am.slice(0,40)} ${currency||'currency not specified'}. Confirm before authorizing payment.`);
      if(u.searchParams.get('pa'))checks.push({name:'UPI recipient ID',state:'unverified-display',note:'Recipient ID is encoded in QR, not authenticated by CyberShield'});
    }catch {warnings.push('UPI payment data could not be fully decoded.');}
  }
  if(/^WIFI:/i.test(source)){
    checks.push({name:'Wi-Fi configuration QR',state:'checked',note:'Can propose joining a wireless network; does not prove router or network safety'});
    warnings.push('Only join a Wi-Fi network you recognize. QR password and Wi-Fi SSID do not prove it is secure.');
  }
  if(/^(?:smsto:|sms:|tel:)/i.test(source))warnings.push('QR requests a phone call or SMS action. Verify the recipient before continuing.');
  return {kind:'QR',verdict:q.label||'QR safety unverified',why:q.summary,warnings,checks,
    next:'Read the destination or payment recipient before scanning in your banking app. Receiving money never requires entering your UPI PIN.',
    limitation:'Decoding a QR does not verify the linked site, Wi-Fi router, payee or phone number.'};
}
