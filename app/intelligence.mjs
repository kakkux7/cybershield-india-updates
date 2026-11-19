/* Privacy-first helper logic. Pattern findings are NOT malware proof or identity verification. */
import { analyzeLink, analyzeMessage, extractURL } from './detector.mjs';

export function analyzePhone(input) {
  const raw = String(input || '').trim();
  if (!raw || raw.length > 40) throw new Error('Enter one phone number, up to 40 characters.');
  if (!/^[+\d()\s.-]+$/.test(raw)) throw new Error('Only phone number characters are supported.');
  const digits = raw.replace(/\D/g, '');
  const indian = /^(?:91)?[6-9]\d{9}$/.test(digits);
  const findings = [
    {heading: 'Caller identity not verified', detail: 'A phone number alone cannot prove who is calling. Caller ID can be spoofed.'},
    {heading: 'Never share secret codes', detail: 'Banks, police and genuine support staff do not need your OTP or UPI PIN over a call.'},
  ];
  if (!indian) findings.unshift({heading: 'Check the number format',detail:'This does not match a standard Indian mobile number. It may be a landline, foreign number or an invalid entry.'});
  return {level:'unknown', label:'Unverified number', subject:raw, findings,
    summary:indian?'The number has the shape of an Indian mobile number. This does NOT verify the caller or tell us if they are a scammer.': 'The number format needs checking. Fraud status cannot be determined from digits alone.',
    formatted:indian?'+91 '+digits.slice(-10,-5)+' '+digits.slice(-5):raw};
}
export function analyzeQRPayload(raw) {
  const value=String(raw||'').trim().slice(0,4096);
  if(!value) throw new Error('No readable QR data found.');
  if(/^https?:\/\//i.test(value) || /^[a-z\d.-]+\.[a-z]{2,}(?:\/|$)/i.test(value)) {
    return {...analyzeLink(value),source:'QR code',summary:'This QR opens a website. '+analyzeLink(value).summary};
  }
  if(/^upi:\/\/pay\?/i.test(value)) {
    const pa=decodeURIComponent((value.match(/[?&]pa=([^&]*)/i)||[])[1]||'');
    const pn=decodeURIComponent((value.match(/[?&]pn=([^&]*)/i)||[])[1]||'');
    return {level:'caution',label:'Payment QR — verify first',subject:'UPI payment request',
      findings:[{heading:'This QR requests a UPI payment',detail:'Scanning a payment QR can ask you to SEND money. It is not a way to receive a refund.'},
        {heading:'Recipient shown (unverified)',detail:'UPI ID: '+(pa||'not shown')+'. Display name: '+(pn||'not shown')+'. Check the name inside your official payment app.'}],
      summary:'This appears to contain a UPI payment instruction. CyberShield cannot verify who owns the UPI ID or whether they are trustworthy.'};
  }
  return {level:'unknown',label:'Unknown QR content',subject:'Non-website QR',findings:[{heading:'Not a website URL',detail:'The QR contains text or another type of data. Do not blindly follow instructions from strangers.'}],summary:'The QR was decoded, but its content cannot be independently verified.'};
}
export function buildReport(kind, content) {
  const safe=String(content||'').trim().slice(0,5000);
  if (!safe) throw new Error('Describe what happened before making a report.');
  const report = kind==='link'?analyzeLink(safe):kind==='phone'?analyzePhone(safe):analyzeMessage(safe);
  return [
    'CYBERSHIELD INDIA — PERSONAL FRAUD INCIDENT NOTES',
    'Not an official police complaint. No submission has taken place.',
    'Date: '+new Date().toLocaleString(),
    'Type: '+kind,
    'User-provided evidence: '+safe,
    'Automated assessment: '+report.label,
    'Summary: '+report.summary,
    'Warning signs:',
    ...report.findings.map(x=>'- '+x.heading+': '+x.detail),
    'NEXT: If money was lost, call 1930 and your bank immediately; report at https://cybercrime.gov.in/.',
    'Do not include passwords, OTPs, PINs or government ID numbers in a public report.'
  ].join('\n');
}
export function companionAdvice(question) {
 const q=String(question||'').toLowerCase().slice(0,1000);
 if (!q.trim()) throw new Error('Type your cyber-safety question.');
 const topics=[
  [/otp|pin|password|cvv|പാസ്‌വേഡ്|ओटीपी/, 'Never share OTP, UPI PIN, CVV or passwords. If you did, change account credentials in the official app and contact your bank.'],
  [/money|upi|paid|payment|refund|lost|transfer|₹|പണം|पैसे/, 'If you sent money to a scammer, call your bank and India’s 1930 helpline immediately, then file an official report at cybercrime.gov.in.'],
  [/camera|mic|microphone|record|permission|screen/, 'Review apps in CyberShield → Apps and open your phone’s Privacy Dashboard to see actual camera/microphone access history. Permission granted does not prove misuse.'],
  [/app|apk|virus|malware|install|hack|spyware/, 'Update Android and apps. Run Google Play Protect, remove unknown APKs, and review powerful permissions. CyberShield cannot perform a full malware scan.'],
  [/call|phone|number|police|arrest|cbi/, 'Caller ID can be spoofed. Do not pay anyone who threatens “digital arrest”. Hang up and contact the organization using an independently verified number.'],
  [/link|qr|website|url|phish|bank/, 'Do not open unfamiliar links or scan unexpected payment QRs. Check the real domain, use your bank’s official app, and never treat an automatic “no warning” result as proof of safety.'],
  [/message|sms|whatsapp|job|investment/, 'Treat urgency, requests for secret codes, advance fees, and guaranteed investment profits as warning signs. Verify independently before replying.'],
 ];
 for(const [re,answer] of topics) if(re.test(q)) return {answer,source:'Offline safety knowledge base (not generative AI)',verified:false};
 return {answer:'I cannot verify that from this offline knowledge base. Do not share passwords or payments. Try the link, message, app-permission, or QR tool; for an active scam contact 1930 or cybercrime.gov.in.',source:'Offline safety knowledge base (not generative AI)',verified:false};
}
export function explainAppPermission(short) {
 const items={CAMERA:'Can take photos/video when Android grants camera access. Review whether this app really needs it.',
 RECORD_AUDIO:'Can use the microphone when granted. This does not prove that the app has recorded you.',
 ACCESS_FINE_LOCATION:'Can access precise location when allowed.',
 READ_SMS:'Can read SMS if granted. Consider whether this is necessary.',
 RECEIVE_SMS:'Can receive incoming SMS messages.',
 READ_CONTACTS:'Can see contact details if granted.',
 READ_CALL_LOG:'Can read call history if granted.',
 SYSTEM_ALERT_WINDOW:'Can display overlays over other apps when allowed. Overlays can be abused in scams.',
 BIND_ACCESSIBILITY_SERVICE:'Accessibility services can interact with the phone. Check Settings for enabled services.',
 REQUEST_INSTALL_PACKAGES:'Can request installation of apps outside the Play Store.',
 MANAGE_EXTERNAL_STORAGE:'May have broad file access if specially granted.',
 MEDIA_PROJECTION:'Screen sharing requires Android screen-capture consent and generally cannot be inferred from a normal app permission listing.'};
 return items[short] || 'Review why this app asks for this permission.';
}
