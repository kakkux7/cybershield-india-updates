import {analyzeLink,analyzeMessage} from './detector.mjs';
import {analyzePhone,analyzeQRPayload,parseUPIQR,buildReport,companionAdvice,explainAppPermission} from './intelligence.mjs';
import {summarizePermissions} from './permission-dashboard.mjs';
import {assessPhonePhishing} from './phone-phishing.mjs';
const $=(s)=>document.querySelector(s);
const bridge=()=>window.CyberShieldAndroid;
const node=(tag,text)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=String(text);return e;};
function output(id, content){const el=$('#'+id);if(!el)return;el.hidden=false;el.replaceChildren();if(typeof content==='string')el.textContent=content;else el.append(content);}
function reportView(report){
 const section=node('div');section.append(node('strong',report.label||'Review result'),node('p',report.summary||'No definitive verification possible.'));
 if(report.subject)section.append(node('p','Checked: '+String(report.subject).slice(0,180)));
 const list=node('ul');(report.findings||[]).forEach(f=>{const li=node('li');li.append(node('strong',f.heading),node('div',f.detail));list.append(li);});section.append(list);
 section.append(node('p','Important: No warning ≠ verified safe. This assessment is not a malware diagnosis.'));
 return section;
}
const on=(selector,event,fn)=>{const e=$(selector);if(e)e.addEventListener(event,fn);};
function showError(id,e){output(id,'Unable to complete check: '+(e?.message||String(e)));}
function updateFileReport(raw,kind){try{if(kind==='qr')window.dispatchEvent(new CustomEvent('CyberShieldQRDecoded',{detail:{value:String(raw)}}));const report=kind==='qr'?analyzeQRPayload(raw):analyzeMessage(raw);output(kind==='qr'?'qr-result':'screenshot-result',reportView(report));}catch(e){showError(kind==='qr'?'qr-result':'screenshot-result',e);}}

on('#phone-form','submit',(e)=>{e.preventDefault();try{
 const number=$('#phone-input').value;
 output('phone-result',reportView(analyzePhone(number)));
 output('phone-phishing-result',reportView(assessPhonePhishing(number,$('#phone-scam-context')?.value||'')));
 }catch(error){showError('phone-result',error);showError('phone-phishing-result',error);}});
on('#phone-scam-check','click',()=>{try{
 const number=$('#phone-input').value;
 output('phone-phishing-result',reportView(assessPhonePhishing(number,$('#phone-scam-context')?.value||'')));
 }catch(error){showError('phone-phishing-result',error);}});
const OFFICIAL_CALLER_LOOKUP='https://www.truecaller.com/reverse-phone-number-lookup';
on('#cs-caller-lookup','click',()=>{
 // A manual visit to a public tool, never automatic private number reverse-lookup.
 if(bridge()?.openCallerLookup)bridge().openCallerLookup();
 else window.open(OFFICIAL_CALLER_LOOKUP,'_blank','noopener,noreferrer');
});
window.addEventListener('CyberShieldQRDecoded',event=>{
 const info=parseUPIQR(event.detail?.value||'');
 const box=$('#cs-upi-inspection'),id=$('#cs-upi-id'),copy=$('#cs-upi-copy'),label=$('#cs-upi-copy-label');
 if(!box||!id||!copy||!label)return;
 box.hidden=!info;id.hidden=true;copy.hidden=true;label.hidden=true;id.value='';
 if(!info)return;
 box.textContent='UPI PAYMENT QR — NOT BANK VERIFIED\nUPI ID: '+(info.upiId||'Missing or malformed')+
  '\nName entered in QR (UNVERIFIED): '+(info.claimedName||'Not provided')+
  '\nAmount in QR (UNVERIFIED): '+(info.amount?'INR '+info.amount:'Not provided')+
  '\n'+info.reason+(info.validFormat?'':'\nWARNING: Invalid UPI identifier or amount.');
 if(info.upiId){id.value=info.upiId;id.hidden=false;copy.hidden=false;label.hidden=false;}
});
on('#cs-upi-copy','click',async()=>{
 const input=$('#cs-upi-id');if(!input?.value)return;
 let copied=false;
 try{await navigator.clipboard.writeText(input.value);copied=true;}
 catch{try{input.select();copied=document.execCommand('copy');}catch{}}
 output('cs-upi-inspection',copied?
 'UPI ID copied. Independently verify the true beneficiary name in your official bank/UPI app. No payment was made.':
 'Select and copy the UPI ID above. Check the real bank beneficiary name in your payment app. No payment was made.');
});
on('#report-form','submit',async(e)=>{
 e.preventDefault();try{const result=buildReport($('#report-type').value,$('#report-evidence').value);output('report-result','Incident notes created locally. Nothing has been sent to authorities. Review and remove private information before sharing.');
 const blob=new Blob([result],{type:'text/plain;charset=utf-8'});const a=node('a');a.href=URL.createObjectURL(blob);a.download='cybershield-incident-notes.txt';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),60000);
 }catch(error){showError('report-result',error);}
});
on('#companion-form','submit',async(e)=>{
 e.preventDefault();try{output('companion-result',reportView({label:'Safety Companion (offline)',summary:companionAdvice($('#companion-question').value).answer,findings:[]}));}catch(error){showError('companion-result',error);}
});
on('#qr-file','change',async(e)=>{
 const file=e.target.files?.[0];if(!file)return;
 if(file.size>12*1024*1024){output('qr-result','Choose an image smaller than 12 MB.');return;}
 if(!('BarcodeDetector' in window)){output('qr-result','This browser cannot decode QR images locally. Use the CyberShield Android app, or try a newer Chromium browser.');return;}
 try{const detector=new BarcodeDetector({formats:['qr_code']});const bitmap=await createImageBitmap(file);try{const data=await detector.detect(bitmap);if(!data.length)throw Error('No QR code was recognized. Try a sharper, upright photo.');updateFileReport(data[0].rawValue,'qr');}finally{bitmap.close();}}
 catch(error){showError('qr-result',error);}
});
on('#screenshot-file','change',(e)=>{
 const file=e.target.files?.[0];if(!file)return;
 if(file.size>12*1024*1024){output('screenshot-result','Choose an image smaller than 12 MB.');return;}
 output('screenshot-result','Android: select the image using the “Analyze screenshot” button to read it privately with on-device OCR. On the website, copy the words from the screenshot and paste them into the Messages checker. Browser screenshot OCR is not included in this beta.');
});
on('#qr-native','click',()=>bridge()?.selectImage?.('qr'));
on('#screenshot-native','click',()=>bridge()?.selectImage?.('screenshot'));
window.CyberShieldReceiveImage=(kind,report)=>{
 const id=kind==='qr'?'qr-result':'screenshot-result';
 if(!report?.ok){output(id,report?.error||'Could not read the image.');return;}
 if(kind==='qr')updateFileReport(report.content,'qr');
 else {
   $('#message-input').value=(report.content||'').slice(0,5000);
   output(id,reportView(analyzeMessage(report.content)));
 }
};
if(bridge()?.selectImage){$('#qr-native').hidden=false;$('#screenshot-native').hidden=false;$('#qr-file').hidden=true;$('#screenshot-file').hidden=true;$('#screenshot-web-ocr').hidden=true;$('#screenshot-consent').closest('label').hidden=true;}

on('#installed-scan','click',()=>{output('installed-result','Reading locally installed application metadata…');bridge()?.scanInstalledApps?.();});
on('#privacy-settings','click',()=>bridge()?.openPrivacyDashboard?.());
on('#app-settings','click',()=>bridge()?.openAppSettings?.());
on('#reminder-start','click',()=>{let mode=$('#reminder-frequency').value;bridge()?.setReminder?.(mode);});
on('#reminder-stop','click',()=>bridge()?.setReminder?.('off'));
window.CyberShieldReceiveReminder=(result)=>output('reminder-result',result.message||'Could not change reminder settings.');
window.CyberShieldReceiveInstalledApps=(report)=>{
 const where=$('#installed-result');where.hidden=false;where.replaceChildren();
 if(!report?.ok){where.textContent=report?.error||'Unable to read installed apps';return;}
 const apps=Array.isArray(report.apps)?report.apps:[];
  const overview=$('#cs-permissions-summary');
  if(overview){
    const data=summarizePermissions(apps);
    overview.hidden=false;overview.replaceChildren();
    overview.append(node('strong',data.visible+' visible apps reviewed locally. Counts describe reported grants or declarations, NOT actual camera/mic/screen usage.'));
    for(const group of data.groups){
      const details=node('details'),sum=node('summary',group.label+' — '+group.count);
      details.append(sum,node('p',group.meaning));
      if(!group.apps.length)details.append(node('p','None found in visible app metadata. This does not establish safety or absence of activity.'));
      else{
        const list=node('ul');
        for(const app of group.apps){
          const item=node('li',app.label+' ('+app.package+') ');
          if(bridge()?.openPackageSettings){
            const btn=node('button','Open app settings');btn.type='button';btn.className='btn btn-secondary';
            btn.addEventListener('click',()=>bridge().openPackageSettings(app.package));
            item.append(btn);
          }
          list.append(item);
        }
        details.append(list);
      }
      overview.append(details);
    }
    overview.append(node('p',data.limits));
  }

 where.append(node('strong',`Visible apps: ${apps.length}. The results show permissions, NOT spying or malware proof.`));
 const counts={camera:0,mic:0,location:0,overlay:0,sms:0};
 for(const app of apps){const p=app.granted||[];if(p.includes('CAMERA'))counts.camera++;if(p.includes('RECORD_AUDIO'))counts.mic++;if(p.includes('ACCESS_FINE_LOCATION'))counts.location++;if((app.requested||[]).includes('SYSTEM_ALERT_WINDOW'))counts.overlay++;if(p.includes('READ_SMS'))counts.sms++;}
 const tally=node('p',`Camera granted: ${counts.camera} · Microphone granted: ${counts.mic} · Location granted: ${counts.location} · Overlay requested*: ${counts.overlay} · SMS granted: ${counts.sms}`);
 where.append(tally,node('p','*Special access may be unavailable or inaccurate in this listing; check Android Settings. Requested/granted permissions do not prove misuse.'));
 const selector=$('#cs-app-select');const review=$('#cs-selected-app-button');
 if(selector){selector.replaceChildren();const prompt=document.createElement('option');prompt.value='';prompt.textContent='Choose one installed app';selector.append(prompt);
  const indexed=[...apps].sort((a,b)=>a.label.localeCompare(b.label));
  for(const app of indexed){const opt=document.createElement('option');opt.value=app.package;opt.textContent=app.label+' ('+app.package+')';selector.append(opt);}
  selector.disabled=!indexed.length;review.disabled=!indexed.length;
  const render=()=>{const app=indexed.find(a=>a.package===selector.value);const target=$('#cs-selected-app-report');
   if(!app){target.hidden=false;target.textContent='Choose an app to review it.';return;}
   const granted=(app.granted||[]), requested=(app.requested||[]);
   const advice=[];
   if(granted.includes('CAMERA'))advice.push('Camera permission granted — check if the app actually needs photos or video.');
   if(granted.includes('RECORD_AUDIO'))advice.push('Microphone permission granted — check actual access history in Android Privacy Dashboard.');
   if(granted.includes('READ_SMS')||granted.includes('READ_CALL_LOG'))advice.push('SMS or call-log access granted — sensitive; verify the app purpose.');
   if(requested.includes('SYSTEM_ALERT_WINDOW'))advice.push('App requested overlay capability. Special access may need checking in Android Settings.');
   if(granted.includes('ACCESS_FINE_LOCATION'))advice.push('Precise location granted — consider Allow only while using, if appropriate.');
   advice.push(...(app.observations||[]));
   advice.push(...(app.reviewSignals||[]));
   const rows=[`APP REVIEW: ${app.label}`,`Package ID: ${app.package}`,`Version: ${app.version||'Unknown'}`,`Installed through: ${app.installSource||'Unknown'}`,`Installed: ${app.installedAt?new Date(app.installedAt).toLocaleDateString():'Unknown'}`,`Updated: ${app.updatedAt?new Date(app.updatedAt).toLocaleDateString():'Unknown'}`, `System app: ${app.system?'Yes':'No'}`,`Target Android SDK: ${app.targetSdk||'Unknown'}`,`Granted permissions: ${granted.length} / ${requested.length} requested`,`Signing certificate fingerprint (SHA-256): ${app.signingCertificateSHA256||'Unavailable'}`,`REVIEW NOTES:`,...(advice.length?advice:['No watched high-risk permission granted. That does not prove safety.']),`This is not a live behavior monitor or malware scan. Check suspicious app in Google Play Protect and Android Settings.`];
   target.hidden=false;target.textContent=rows.join('\n');
   };
   selector.onchange=render;review.onclick=render;
 }
 const search=$('#app-search');search.hidden=false;
 const list=$('#app-list');list.replaceChildren();list.hidden=false;
 const paint=()=>{list.replaceChildren();let displayed=0;const q=search.value.toLowerCase().trim();for(const app of apps){if(q && !(app.label+' '+app.package).toLowerCase().includes(q))continue;if(displayed++>150)break;
 const card=node('div');card.className='cyber-app-card';const details=node('details');const sum=node('summary',app.label+' · '+app.granted.length+' granted / '+app.requested.length+' requested');const info=node('p',app.package);const risks=node('ul');
 (app.riskFlags||[]).forEach(flag=>{const li=node('li',flag+': '+explainAppPermission(flag.split(' —')[0]));risks.append(li);});
 if(!(app.riskFlags||[]).length)risks.append(node('li','No watched sensitive permission found; this does not establish safety.'));
 const btn=node('button','Open Android settings');btn.type='button';btn.addEventListener('click',()=>bridge()?.openPackageSettings?.(app.package));
 details.append(sum,info,risks,btn);card.append(details);list.append(card);}
 if(!displayed)list.textContent='No apps match that search.';
 };
 search.oninput=paint;paint();
};
if(!bridge()?.scanInstalledApps){$('#installed-scan').disabled=true;$('#installed-scan').textContent='Available in Android app';$('#privacy-settings').hidden=true;$('#app-settings').hidden=true;$('#reminder-panel').hidden=true;}

on('#live-lookup','click',async()=>{if(window.CyberShieldOnline?.lookupLink){await window.CyberShieldOnline.lookupLink();return;}
 const link=$('#url-input').value.trim();
 try{analyzeLink(link);}catch(error){showError('live-result',error);return;}
 if(bridge()){output('live-result','The Android beta currently works offline. Live reputation needs a separately deployed and configured service.');return;}
 if(!$('#live-opt-in').checked){output('live-result','Tick the consent checkbox to send this URL to a licensed reputation provider.');return;}
 output('live-result','Checking the configured provider, without opening the destination…');
 try{const c=new AbortController();const t=setTimeout(()=>c.abort(),10000);let response;try{response=await fetch('/api/reputation',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:link}),signal:c.signal});}finally{clearTimeout(t);}if(!response.ok)throw Error(response.status===503?'Online reputation provider has not been configured on this server.':'Online lookup unavailable (HTTP '+response.status+').');const info=await response.json();
 const types=info.threats||[];output('live-result',types.length?`KNOWN THREAT MATCH: ${types.join(', ')}. Avoid visiting this site.`:'No threat-list match. The link is still NOT verified safe; novel scams and malicious content may not be listed.');}
 catch(error){showError('live-result',error);}
});

on('#companion-online','click',async()=>{if(window.CyberShieldOnline?.askAI){await window.CyberShieldOnline.askAI();return;}
 const question=$('#companion-question').value.trim();
 if(!question){output('companion-result','Write your question first.');return;}
 if(bridge()){output('companion-result','This Android beta currently uses offline help. The optional online AI service needs a reviewed app/backend integration.');return;}
 if(!$('#ai-opt-in').checked){output('companion-result','Tick the consent checkbox first. Online AI sends your question to the configured provider. Do not include secrets.');return;}
 output('companion-result','Consulting the configured AI service…');
 try{const ctrl=new AbortController();const t=setTimeout(()=>ctrl.abort(),12000);let response;try{response=await fetch('/api/companion',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({question}),signal:ctrl.signal});}finally{clearTimeout(t);}
 if(!response.ok)throw Error(response.status===503?'Online AI not configured on this server.':'Online AI unavailable (HTTP '+response.status+').');
 const data=await response.json();output('companion-result','Online AI (may be mistaken):\n'+data.answer+'\n\nDo not rely on AI as proof that a link, app, QR or caller is safe.');}
 catch(error){showError('companion-result',error);}
});

// Explain the part of an address that the offline link checker examined.
on('#link-form','submit',()=>{
 const out=$('#url-breakdown');if(!out)return;
 try{
  const raw=$('#url-input').value.trim();const link=new URL(/^https?:\/\//i.test(raw)?raw:'https://'+raw);
  output('url-breakdown',`Actual destination domain: ${link.hostname}\nConnection: ${link.protocol==='https:'?'HTTPS (encrypted in transit, NOT guaranteed safe)':'HTTP (not encrypted)'}\nAddress path: ${link.pathname.slice(0,150)}\nChecked: URL structure, lookalike names, download clues, unusual characters.\nNOT CHECKED: website contents, malware scripts, DNS, redirects, files downloaded or the site's owner.`);
 }catch(e){out.hidden=true;}
});

// Optional server OCR is separate from on-device Android ML Kit and requires explicit consent.
on('#screenshot-web-ocr','click',async()=>{
 if(bridge()){output('screenshot-result','Use the on-device “Analyze screenshot on Android” button instead. No upload is needed.');return;}
 const file=$('#screenshot-file').files?.[0];
 if(!file){output('screenshot-result','Choose a screenshot first.');return;}
 if(file.size>4*1024*1024){output('screenshot-result','Choose a screenshot under 4 MB for the optional web OCR service.');return;}
 if(!$('#screenshot-consent').checked){output('screenshot-result','Tick the consent checkbox only if you trust the configured server. The screenshot will be uploaded.');return;}
 output('screenshot-result','Reading text on the configured OCR server…');
 try{const payload=new FormData();payload.append('image',file);const ctrl=new AbortController();const t=setTimeout(()=>ctrl.abort(),16000);let response;
 try{response=await fetch('/api/screenshot-ocr',{method:'POST',body:payload,signal:ctrl.signal});}finally{clearTimeout(t);}
 if(!response.ok)throw Error(response.status===404?'No screenshot OCR backend is running on this site.':'Screenshot OCR is unavailable (HTTP '+response.status+').');
 const result=await response.json();if(!result.text?.trim())throw Error('No readable words found.');
 $('#message-input').value=result.text.slice(0,5000);
 output('screenshot-result',reportView(analyzeMessage(result.text)));
 }catch(e){showError('screenshot-result',e);}
});

// User-controlled phone triage: we do NOT claim to perform a full spyware or kernel scan.
on('#cs-security-settings','click',()=>{if(bridge()?.openSecuritySettings)bridge().openSecuritySettings();else output('cs-security-guidance','On Android: Settings → Security & privacy → Security updates. Check system updates, unknown-app installers, and device lock.');});
on('#cs-playprotect','click',()=>{if(bridge()?.openPlayProtectHelp)bridge().openPlayProtectHelp();else output('cs-security-guidance','On Android: open Google Play Store → profile picture → Play Protect → Scan. Keep scanning enabled.');});
on('#cs-phone-check','click',()=>{
 const el=$('#cs-security-guidance');if(el){el.textContent='To review your phone: 1. Run Google Play Protect. 2. Install Android security updates. 3. Review Settings → Privacy Dashboard for camera/microphone access. 4. Review Accessibility, Device admin apps, and Install unknown apps. 5. Remove apps you cannot verify. These checks cannot guarantee that there is no spyware or hacking.';}
 $('#cs-phone-checklist')?.scrollIntoView?.({behavior:'smooth',block:'center'});
});
