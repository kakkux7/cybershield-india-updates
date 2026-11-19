/** Plain-language local-evidence layer. The native/hosted reputation services remain separate. */
import { linkEvidence,messageEvidence,phoneEvidence,qrEvidence } from './trust-report.mjs';
const $=id=>document.getElementById(id);
const line=(tag,text,cls)=>{const n=document.createElement(tag);if(cls)n.className=cls;if(text!=null)n.textContent=text;return n;};
function paint(id,report){
 const target=$(id==='cs-message-evidence' && $('cs-message-evidence-inline')?'cs-message-evidence-inline':id);if(!target)return;target.hidden=false;target.replaceChildren();
 const h=line('h3',report.verdict);const intro=line('p',report.why,'cs-evidence-lead');target.append(h,intro);
 const grid=line('div',null,'cs-evidence-grid');
 (report.checks||[]).forEach(c=>{
  const item=line('div',null,'cs-evidence-item');const state=line('span',c.state.replaceAll('-',' '),'cs-evidence-state');state.dataset.state=c.state;
  item.append(state,line('b',c.name),line('small',c.note));grid.append(item);
 });target.append(grid);
 if(report.warnings?.length){target.append(line('h3','Reasons and things to watch'));const ul=line('ul');report.warnings.slice(0,15).forEach(w=>ul.append(line('li',w)));target.append(ul);}
 target.append(line('div',report.next,'cs-evidence-action'),line('p',report.limitation,'cs-evidence-limit'));
}
const show=(id,fn,input)=>{try{paint(id,fn(input));}catch(e){const target=$(id);if(target){target.hidden=false;target.textContent='Evidence report unavailable: '+e.message;}}};
$('link-form')?.addEventListener('submit',()=>show('cs-link-evidence',linkEvidence,$('url-input')?.value));
$('message-form')?.addEventListener('submit',()=>show('cs-message-evidence',messageEvidence,$('message-input')?.value));
$('phone-form')?.addEventListener('submit',()=>show('cs-phone-evidence',phoneEvidence,$('phone-input')?.value));
window.addEventListener('CyberShieldQRDecoded',e=>show('cs-qr-evidence',qrEvidence,e.detail?.value));
const previousImage=window.CyberShieldReceiveImage;
if(typeof previousImage==='function')window.CyberShieldReceiveImage=function(kind,report){previousImage(kind,report);
 if(kind==='screenshot'&&report?.ok)show('cs-message-evidence',messageEvidence,report.content||'');
};
const previousApps=window.CyberShieldReceiveInstalledApps;
if(typeof previousApps==='function')window.CyberShieldReceiveInstalledApps=function(report){previousApps(report);
 const target=$('cs-app-evidence');if(!target)return;
 if(!report?.ok||!Array.isArray(report.apps)){target.hidden=true;return;}
 const observations=[];
 for(const app of report.apps){
  const perm=new Set(app.granted||[]);const req=new Set(app.requested||[]);
  const suspicious=[];
  if((perm.has('READ_SMS')||perm.has('RECEIVE_SMS')) && (req.has('SYSTEM_ALERT_WINDOW')||req.has('BIND_ACCESSIBILITY_SERVICE')))suspicious.push('SMS access alongside requested overlay or accessibility capability');
  if(perm.has('RECORD_AUDIO') && perm.has('CAMERA') && !app.system)suspicious.push('Both camera and microphone granted; check whether needed');
  if(perm.has('READ_CONTACTS') && perm.has('ACCESS_FINE_LOCATION') && !app.system)suspicious.push('Contacts and precise location both granted');
  if(app.debuggable && !app.system)suspicious.push('Debuggable build of a user-installed app');
  if(suspicious.length)observations.push({name:app.label||app.package,issues:suspicious});
 }
 const shown=observations.slice(0,12);target.hidden=false;target.replaceChildren();
 target.append(line('h3','Permission combinations worth reviewing'),line('p',`Found ${observations.length} visible app(s) with selected combinations. This is NOT proof of surveillance or malware.`,'cs-evidence-lead'));
 if(!shown.length)target.append(line('p','No monitored permission combinations were found in visible apps. That does not prove the phone is safe.'));
 else {const ul=line('ul');shown.forEach(a=>ul.append(line('li',`${a.name}: ${a.issues.join('; ')}`)));target.append(ul);}
 target.append(line('div','Open Android Privacy Dashboard to inspect actual camera/microphone activity, and use Play Protect for a separate malware scan.','cs-evidence-action'),line('p','Only installed-app metadata visible to Android was reviewed. Private app files, runtime network traffic, screen capture and hidden spyware were not scanned.','cs-evidence-limit'));
};
// Never allow a WebView page or a URL field to control the developer URL: the native bridge uses a fixed approved profile.
for(const a of document.querySelectorAll('[data-cs-developer]'))a.addEventListener('click',e=>{
 if(window.CyberShieldAndroid?.openDeveloperProfile){e.preventDefault();window.CyberShieldAndroid.openDeveloperProfile();}
});
