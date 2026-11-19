import { compareVersion, isTrustedReleasePage, newerRelease } from './release-policy.mjs';
/* CyberShield v0.7: verified-provider lookups when configured, keyless DNS evidence otherwise.
   Never mistake a DNS record, telephone number format, or absent match for a safety verdict.
   Automatic domain-only lookup transmits the HOSTNAME, not the full URL, after user asks to scan.
*/
const $ = id => document.getElementById(id);
const put=(id,message)=>{const e=$(id);if(e){e.hidden=false;e.textContent=String(message);}};
const native=()=>typeof window.CyberShieldAndroid?.onlineRequest==='function';
const APP_VERSION='0.9.3';
let latestRelease='',lastQRUrl='',counter=0;
const pending=new Map();
let status={reputationConfigured:false,phoneConfigured:false,remoteAIConfigured:false};

function normalizedURL(input){
  let raw=String(input||'').trim();if(!/^https?:\/\//i.test(raw))raw='https://'+raw;
  if(raw.length>2048||/[\s\x00-\x1f\x7f]/.test(raw))throw Error('Enter a single complete URL without spaces.');
  const u=new URL(raw);
  if(!['http:','https:'].includes(u.protocol)||u.username||u.password)throw Error('Only normal website URLs are accepted.');
  const host=u.hostname.replace(/\.$/,'').toLowerCase();
  if(!host.includes('.')||host.endsWith('.local')||host.endsWith('.localhost')||host.endsWith('.internal')||host==='localhost'||/^\d+\.\d+\.\d+\.\d+$/.test(host)||host.includes(':'))throw Error('Local and numeric-IP destinations cannot be checked here.');
  return {url:u.href,host};
}
async function dnsEvidence(value){
  const {host}=normalizedURL(value);
  const addr='https://dns.google/resolve?'+new URLSearchParams({name:host,type:'A'});
  try{
    const r=await fetch(addr,{headers:{Accept:'application/json'},cache:'no-store',signal:AbortSignal.timeout(6500)});
    if(!r.ok)throw Error('DNS endpoint unavailable');
    const j=await r.json();const records=(j.Answer||[]).filter(x=>x?.type===1||x?.type===5);
    if(j.Status!==0&&j.Status!==3)throw Error('Unknown DNS response');
    return {checked:true,resolves:j.Status===0&&records.length>0,answerCount:records.length,
      detail:records.length?'A public DNS record exists. This does NOT mean the site is safe.':'No public IPv4 record was found; the site may use IPv6, be offline, or be blocked.'};
  }catch(e){return {checked:false,resolves:null,answerCount:0,detail:'Live DNS evidence unavailable on this network.'};}
}
function basicPhone(number){
  const raw=String(number||'').trim();if(!/^[+\d() .-]{5,35}$/.test(raw))throw Error('Enter one normal phone number.');
  const digits=raw.replace(/\D/g,'');if(digits.length<8||digits.length>15)throw Error('Use a valid-length international number.');
  const indian=/^(?:91)?[6-9]\d{9}$/.test(digits);
  return {source:'Local format hints (no live caller reputation)',maskedNumber:'****'+digits.slice(-4),
   valid:null,possible:digits.length>=8&&digits.length<=15,countryCode:indian?'IN':'Not verified',
   lineType:indian?'possibly Indian mobile':'Not verified',carrier:null,providerChecked:false,
   providerWarning:'No licensed lookup connected. Number ownership, WhatsApp account and fraud reports were not checked.',
   important:'A number that looks valid can still be used for scams or spoofing. Do not share OTP, PIN or payments.'};
}
async function fallback(kind,payload){
  if(kind==='reputation'){
    const {host}=normalizedURL(payload?.url);
    return {source:'Google Public DNS (domain evidence only)',host,threats:[],matched:false,providerChecked:false,
      providerWarning:'Malware and phishing reputation provider is NOT connected. DNS is not a fraud database.',
      dns:await dnsEvidence(payload.url),important:'No website content, scripts, downloads or redirects were inspected. Nothing here proves safety.'};
  }
  if(kind==='phone')return basicPhone(payload?.number);
  if(kind==='status'){
    const proof=await dnsEvidence('https://example.com/');
    return {version:APP_VERSION,reputationConfigured:false,phoneConfigured:false,remoteAIConfigured:false,
      dnsEvidenceSupported:proof.checked,phoneFormatSupported:true,
      note:proof.checked?'Public DNS evidence available; no licensed threat-list or caller database connected.':'Only offline checks available right now.'};
  }
  if(kind==='updates')return {currentBuild:APP_VERSION,latestVersion:APP_VERSION,published:false,checked:false,feedConfigured:false,releasePage:'',
    errorCode:'FEED_UNAVAILABLE',releaseNotes:'The official update server is not published or cannot be reached. Update status is UNKNOWN.'};
  if(kind==='fileHash')return {providerChecked:false,found:false,source:'Unavailable',providerWarning:'A licensed file-hash reputation provider is not connected. The fingerprint was not checked online.',important:'Not a malware scan.'};
  throw Error('Real online AI needs a deployed server with an authorized provider key. Offline safety guidance still works.');
}
async function call(kind,payload={}){
  const id=String(++counter);
  if(native())return new Promise((resolve,reject)=>{
    pending.set(id,{resolve,reject});
    try{window.CyberShieldAndroid.onlineRequest(kind,JSON.stringify(payload),id);}catch(e){pending.delete(id);reject(e);}
    setTimeout(()=>{if(pending.has(id)){pending.delete(id);reject(Error('Network request timed out. No verified result.'));}},90000);
  });
  const endpoint={status:'/api/status',updates:'/api/updates',reputation:'/api/reputation',phone:'/api/phone-lookup',companion:'/api/companion',fileHash:'/api/file-reputation',domain:'/api/domain-details'}[kind];
  if(!endpoint)throw Error('Unsupported online request');
  try{
    const res=await fetch(endpoint,{method:['status','updates'].includes(kind)?'GET':'POST',
      headers:{'Content-Type':'application/json'},credentials:'same-origin',cache:'no-store',
      body:['status','updates'].includes(kind)?undefined:JSON.stringify(payload),signal:AbortSignal.timeout(11000)});
    let data;try{data=await res.json();}catch{throw Error('No CyberShield backend at this address.');}
    if(!res.ok)throw Error(typeof data.detail==='string'?data.detail:'Server response '+res.status);
    return data;
  }catch(error){
    if(kind==='updates') {
      // The app can check releases even without a deployed fraud-detection API.
      // Only a public, owner-controlled HTTPS release feed is trusted.
      try {
        const url='https://raw.githubusercontent.com/kakkux7/cybershield-india-updates/main/latest.json';
        const r=await fetch(url,{cache:'no-store',headers:{Accept:'application/json'},signal:AbortSignal.timeout(6500)});
        if(!r.ok)throw Error('Release feed not published');
        const d=await r.json();
        if(!/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(d.latestVersion) || !Number.isInteger(d.versionCode))throw Error('Invalid metadata');
        if(d.published && !isTrustedReleasePage(d.releasePage))throw Error('Untrusted release URL');
        return {...d,checked:true,feedConfigured:true};
      }catch{return fallback('updates',payload);}
    }
    if(['status','reputation','phone','fileHash'].includes(kind))return fallback(kind,payload);
    throw error;
  }
}
window.CyberShieldOnlineReceive=(id,report)=>{
  const item=pending.get(String(id));if(!item)return;
  pending.delete(String(id));
  if(!report?.ok){item.reject(Error(report?.error||'Connection unavailable'));return;}
  item.resolve(report.data||{});
};
async function connectivity(){
  put('cs-connectivity-message','Connecting to the CyberShield online server… Render Free hosting may take about a minute to wake up. No paid AI or reputation services are enabled.');
  try{
    const d=await call('status');status=d;
    if($('cs-connectivity-light'))$('cs-connectivity-light').style.color=d.dnsEvidenceSupported?'#26cf96':'#f3be60';
    put('cs-connectivity-message',`CyberShield · DNS evidence: ${d.dnsEvidenceSupported?'online':'not reachable'} · Verified threat lists: ${d.reputationConfigured?'connected':'not connected'} · Phone plan metadata: ${d.phoneFormatSupported?'available':'limited'} · File fingerprint reputation: ${d.fileReputationConfigured?'connected':'not connected'} · Remote AI: ${d.remoteAIConfigured?'connected':'not connected'}.`);
  }catch(e){put('cs-connectivity-message','Internet status unavailable. Offline protection remains active.');}
}
function formatLinkReport(data){
  const types=Array.isArray(data.threats)?data.threats:[];
  if(types.length&&data.providerChecked)return `⚠ KNOWN THREAT FOUND (${types.join(', ')}). DO NOT OPEN THIS LINK. Source: ${data.source}.`;
  const dns=data.dns||{};
  const name=data.host?'Domain: '+data.host+'\n':'';
  return name+`Internet DNS check: ${dns.checked?(dns.resolves?'Domain resolves':'No IPv4 DNS record found'):'Not available'}.
${dns.detail||''}
Verified malicious-link list: ${data.providerChecked?'Checked; no known threat match':'NOT CHECKED'}.
${data.providerWarning||''}

SAFETY: UNVERIFIED. A resolving domain or missing blocklist match is not proof of safety. We did not open the website, scan its code, or test downloads.`;
}
async function lookupLink(url=null,resultId='live-result'){
  const entered=String(url||$('url-input')?.value||'').trim();
  if(!entered){put(resultId,'Enter a URL first.');return;}
  const consent=resultId==='qr-online-result'?'qr-online-consent':'live-opt-in';
  if(!$(consent)?.checked){put(resultId,'Please accept the optional online lookup consent. Automatic hostname-only DNS evidence is shown separately after a scan.');return;}
  put(resultId,'Checking available online evidence without opening the website…');
  try{put(resultId,formatLinkReport(await call('reputation',{url:normalizedURL(entered).url})));}
  catch(e){put(resultId,'Could not obtain online evidence: '+e.message+'. Link remains UNVERIFIED.');}
}
async function automaticDomainCheck(){
  const v=$('url-input')?.value?.trim();if(!v)return;
  put('cs-auto-dns','Checking domain DNS online (host name only; never opening the website)…');
  try{
    const domain=normalizedURL(v).host;
    const dns=await dnsEvidence('https://'+domain+'/');
    put('cs-auto-dns',`Domain: ${domain}\n${dns.detail}\nNo malicious-link database was checked. Safety is UNKNOWN.`);
  }catch(e){put('cs-auto-dns',e.message);}
}
async function domainRegistration(){
  const source=$('url-input')?.value?.trim();
  if(!source){put('cs-domain-report','Paste a link first.');return;}
  if(!$('cs-domain-consent')?.checked){put('cs-domain-report','Choose the public registration lookup checkbox first. Only the domain is sent; no website is opened.');return;}
  put('cs-domain-report','Checking public registrar and registration dates (not website contents)…');
  try{
    const {host}=normalizedURL(source);
    const result=await call('domain',{url:'https://'+host+'/'});
    const who=result.checked?`Registrar: ${result.registrar||'Not publicly listed'}\nRegistered: ${result.created||'Unknown'}\nExpires: ${result.expires||'Unknown'}`:'Registrar and registration dates could not be verified.';
    put('cs-domain-report',`Actual host: ${host}\nRegistered domain: ${result.registeredDomain||host}\n${who}\n${result.note||'Public records do not establish trust.'}\nSAFETY: UNVERIFIED. We did not open this site.`);
  }catch(e){put('cs-domain-report','Public domain record unavailable: '+e.message+'. Website safety remains unknown.');}
}
$('cs-domain-button')?.addEventListener('click',domainRegistration);
async function phoneLookup(){
  if(!$('number-consent')?.checked){put('number-online-result','Please consent before checking the number. When no provider is connected, we use local numbering-plan hints and do not transmit the number.');return;}
  put('number-online-result','Checking available number details…');
  try{
    const d=await call('phone',{number:$('phone-input').value.trim()});
    put('number-online-result',`Number: ${d.maskedNumber||'masked'}\nPossible number: ${d.possible===true?'Yes':d.possible===false?'No':'Not verified'}\nFormat validity: ${d.valid===true?'Valid format':d.valid===false?'Invalid format':'Unknown'}\nCountry/region: ${d.countryCode||'Unknown'}${d.region?' ('+d.region+')':''}\nLine type: ${d.lineType||'Unknown'}\nCarrier: ${d.carrier||'Unknown'}\nOnline provider check: ${d.providerChecked?'Completed':'NOT completed'}\nWhatsApp account: ${d.whatsappStatus||"NOT verifiable"}\nPrivate name/owner: Not available\nFake or spoofed number: Cannot be established from carrier data\nFraud reputation: UNKNOWN\n${d.providerWarning||''}\n\n${d.important}`);
  }catch(e){put('number-online-result','Number details could not be checked: '+e.message+'. No caller reputation verdict.');}
}
async function askAI(){
  const q=$('companion-question')?.value?.trim();if(!q){put('companion-result','Enter a question.');return;}
  if(!$('ai-opt-in')?.checked){put('companion-result','Consent required before sending a question to remote AI. Remove private details.');return;}
  put('companion-result','Consulting the configured online security assistant…');
  try{const data=await call('companion',{question:q});put('companion-result','AI advice (not a verified security verdict):\n'+data.answer);}
  catch(e){put('companion-result','Remote AI is not configured: '+e.message+'. Use offline Safety Companion for immediate guidance.');}
}
function installedVersion(){
  try{return native() && window.CyberShieldAndroid.appVersion ? window.CyberShieldAndroid.appVersion() : APP_VERSION;}
  catch{return APP_VERSION;}
}
function installedVersionCode(){
  try{return native() && window.CyberShieldAndroid.appVersionCode ? Number(window.CyberShieldAndroid.appVersionCode()) : 12;}
  catch{return 9;}
}
let lastUpdateCheck=0;
async function checkUpdates(force=false){
  const current=installedVersion();
  const pill=$('update-count-badge');if(pill)pill.textContent='v'+current;
  if(!force && Date.now()-lastUpdateCheck<15*60*1000)return;
  lastUpdateCheck=Date.now();
  put('cs-update-details','Checking official published release information…');
  $('cs-update-open').hidden=true;
  if($('cs-update-banner'))$('cs-update-banner').hidden=true;
  latestRelease='';
  if($('cs-update-download'))$('cs-update-download').hidden=true;
  if($('cs-update-install'))$('cs-update-install').hidden=true;
  try{
    const data=await call('updates');
    if(data.checked!==true || data.feedConfigured===false){
      put('cs-update-details',`Installed: v${current}. UPDATE SERVER UNAVAILABLE (the public release feed may be missing, HTTP 404).\nYour other CyberShield tools can still work. Latest version UNKNOWN; this is not an all-clear. Try again after the publisher announces a signed release.`);
      return;
    }
    if(!data.published){
      put('cs-update-details',`Installed: v${current}. Release feed reachable, but NO newer public signed release is announced.\n${data.releaseNotes||''}`);
      return;
    }
    if(!isTrustedReleasePage(data.releasePage))throw Error('Release URL is not an approved official page');
    const newer=newerRelease(data,current,installedVersionCode());
    if(newer){
      latestRelease=data.releasePage;
      put('cs-update-details',`UPDATE AVAILABLE: v${data.latestVersion}\nYou have v${current}.\nWhat's new: ${data.releaseNotes||'A newer version has been published.'}\nOpen the official page to review the release. You must approve installation; signatures must match.`);
      $('cs-update-open').hidden=false;
      if($('cs-update-download')){
        $('cs-update-download').hidden=false;
        $('cs-update-download').textContent=native()?'Download update in CyberShield':'Open official Android APK release';
      }
      if($('cs-update-banner'))$('cs-update-banner').hidden=false;
    } else put('cs-update-details',`Installed: v${current}. The official release feed reports v${data.latestVersion}. No newer compatible version is announced.\n${data.releaseNotes||''}`);
  }catch(e){
    put('cs-update-details',`Installed: v${current}. Could not verify updates: ${e.message}.\nUpdate status is UNKNOWN, not up to date.`);
  }
}
window.addEventListener('CyberShieldQRDecoded',e=>{
  const payload=String(e.detail?.value||'').trim();lastQRUrl='';
  try{const u=new URL(payload);if(['http:','https:'].includes(u.protocol))lastQRUrl=u.href;}catch{}
  if($('qr-online'))$('qr-online').disabled=!lastQRUrl;
  put('qr-online-result',lastQRUrl?'QR link decoded. Optional online evidence is available.':'QR does not contain a website. CyberShield cannot verify a UPI payee or merchant.');
});
$('link-form')?.addEventListener('submit',automaticDomainCheck);
$('number-online')?.addEventListener('click',phoneLookup);
$('qr-online')?.addEventListener('click',()=>lookupLink(lastQRUrl,'qr-online-result'));
$('cs-check-update')?.addEventListener('click',()=>checkUpdates(true));
$('cs-refresh-status')?.addEventListener('click',connectivity);
let readyToInstall=false;
window.CyberShieldReceiveSignedUpdate=(result)=>{
  const state=result?.status||'error';
  put('cs-update-install-status',result?.message||'Installer status unknown.');
  if(state==='ready'){readyToInstall=true;if($('cs-update-install'))$('cs-update-install').hidden=false;}
  if(state==='error'){readyToInstall=false;if($('cs-update-install'))$('cs-update-install').hidden=true;}
};
$('cs-update-download')?.addEventListener('click',()=>{
  if(!latestRelease)return;
  if(native() && typeof window.CyberShieldAndroid.downloadOfficialUpdate==='function'){
    readyToInstall=false;if($('cs-update-install'))$('cs-update-install').hidden=true;
    put('cs-update-install-status','Downloading and verifying official signed APK…');
    window.CyberShieldAndroid.downloadOfficialUpdate();
  }else{
    window.open(latestRelease,'_blank','noopener,noreferrer');
  }
});
$('cs-update-install')?.addEventListener('click',()=>{
  if(native() && readyToInstall)window.CyberShieldAndroid.installVerifiedUpdate();
});
$('cs-update-open')?.addEventListener('click',()=>{
  if(!latestRelease)return;
  if(native())window.CyberShieldAndroid.openOfficialUpdate(latestRelease);
  else window.open(latestRelease,'_blank','noopener,noreferrer');
});
window.CyberShieldOnline={lookupLink,askAI,phoneLookup,connectivity,checkUpdates,compareVersion,dnsEvidence,request:call};
window.CyberShieldUpdateAlertChanged=(enabled)=>put('cs-update-alert-state',enabled?'Daily update reminders enabled.':'Daily update reminders turned off.');
if(native() && typeof window.CyberShieldAndroid.setUpdateAlerts==='function'){
  const btn=$('cs-update-alerts');
  if(btn){
    btn.hidden=false;
    const updateAlertUI=()=>{const enabled=window.CyberShieldAndroid.updateAlertsEnabled();btn.textContent=enabled?'Disable update reminders':'Enable daily update reminders';return enabled;};
    updateAlertUI();
    btn.addEventListener('click',()=>{const enabled=updateAlertUI();window.CyberShieldAndroid.setUpdateAlerts(!enabled);setTimeout(updateAlertUI,600);});
  }
}
document.addEventListener('visibilitychange',()=>{if(!document.hidden)checkUpdates();});
window.addEventListener('online',()=>checkUpdates());
connectivity();checkUpdates();
