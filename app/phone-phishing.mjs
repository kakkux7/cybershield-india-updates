/* CyberShield phone scam / phishing check. Offline, evidence-based, no identity claims. */
export function assessPhonePhishing(number,context=''){
  const raw=String(number??'').trim(),digits=raw.replace(/\D/g,'');
  if(!raw||raw.length>40||!/^[+\d().\s-]+$/.test(raw)||digits.length<8||digits.length>15)
    throw Error('Enter one phone number containing 8–15 digits.');
  const text=String(context??'').trim();
  if(text.length>1500)throw Error('Keep the description under 1500 characters.');
  const cues=[
    {heading:'OTP, PIN or password mentioned',re:/\b(?:otp|one.time (?:password|passcode)|upi[\s-]?pin|password|cvv|verification code)\b|ओटीपी|ഒടിപി/i,high:true,
     detail:'If anyone asks you to disclose an OTP, PIN or password, do not provide it. Verify independently.'},
    {heading:'Remote-access or APK request',re:/\b(?:anydesk|teamviewer|remote access|screen shar(?:e|ing)|install (?:an? |the )?app|apk file)\b/i,high:true,
     detail:'Never install an unknown APK or share your screen to help an unsolicited caller.'},
    {heading:'Threat or digital-arrest claim',re:/\b(?:digital arrest|arrest warrant|legal action|account (?:will be )?(?:blocked|frozen)|sim (?:will be )?(?:blocked|deactivated))\b/i,high:true,
     detail:'Do not act on unexpected threats of arrest or account suspension. Contact authorities directly.'},
    {heading:'Demand for payment or QR scan',re:/\b(?:send money|transfer money|pay (?:now|first|a fee)|upi collect|scan (?:the |a )?qr|refund fee|processing fee|security deposit)\b/i,high:true,
     detail:'Do not send money or scan payment QRs to receive a refund or stop a supposed investigation.'},
    {heading:'Authority or support impersonation',re:/\b(?:bank official|police officer|customs officer|trai|rbi|customer care|government officer|courier department)\b/i,high:false,
     detail:'A caller title or claimed employer is not identity proof. Contact the organization through its official channel.'},
    {heading:'Urgent KYC or verification demand',re:/\b(?:urgent(?:ly)?|immediately|kyc|verify (?:your |the )?account|update (?:your |the )?kyc|within 24 hours|last chance)\b|കെവൈസി|केवाईसी/i,high:false,
     detail:'Verify KYC requests using the bank or service provider’s official website or app.'},
    {heading:'Link or download prompt',re:/https?:\/\/\S+|\b(?:click (?:this |the )?link|open (?:this |the )?link|download (?:this |the )?file)\b/i,high:false,
     detail:'Do not follow an unknown caller’s link. Check it separately and visit the official address yourself.'},
  ];
  const findings=text?cues.filter(c=>c.re.test(text)):[];
  const serious=findings.some(x=>x.high);
  return {
    level:serious?'high':findings.length?'caution':'unknown',
    label:serious?'High-risk communication signals':findings.length?'Suspicious communication clues':'Caller not verified',
    subject:'••••'+digits.slice(-4),
    summary:!text?'Number digits alone cannot establish whether a call is phishing or fraud.':
      serious?'Strong scam warning phrases appear in your description. Do not act before independent verification.':
      findings.length?'Some warning phrases were detected. Independently verify the caller.':
      'No matching scam phrases were found. This is not proof that the call or number is safe.',
    findings:[...findings.map(f=>({heading:f.heading,detail:f.detail})),
      {heading:'No live identity or reputation verification',detail:'Only the text you provided was reviewed locally. Caller ID may be spoofed; no database, call logs, contacts or WhatsApp records were checked.'}]
  };
}
