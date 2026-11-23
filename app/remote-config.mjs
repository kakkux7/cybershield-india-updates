/** Safe real-time-ish public branding layer. No admin keys or executable remote UI. */
const origin = location.hostname === 'kakkux7.github.io'
  ? 'https://cybershield-india-beta.onrender.com' : '';
const $ = selector => document.querySelector(selector);
let seenRevision = null;
let fetching = false;
const safeHex = value => typeof value === 'string' && /^#[0-9a-fA-F]{6}$/.test(value);
const OPTIONS = {
  density: ['compact','comfortable','spacious'],
  buttonStyle: ['square','rounded','pill'],
};
function cssVar(key,value){
  document.documentElement.style.setProperty(key,value);
}
function updateLogo(config){
  const mark=$('.brand-mark');
  if(!mark)return;
  let image=mark.querySelector('.cs-custom-logo');
  if(!config.theme?.logoEnabled){
    if(image)image.remove();
    mark.querySelector('svg')?.removeAttribute('hidden');
    return;
  }
  if(!image){
    image=document.createElement('img');image.className='cs-custom-logo';
    image.alt='CyberShield India custom logo';image.decoding='async';
    image.addEventListener('error',()=>{image.remove();mark.querySelector('svg')?.removeAttribute('hidden');});
    mark.append(image);
  }
  image.src=origin+'/api/app-brand/logo.png?v='+encodeURIComponent(String(config.revision||0));
  mark.querySelector('svg')?.setAttribute('hidden','');
}
export function applyPublicSettings(config){
  if(!config || typeof config!=='object')return false;
  const headline=String(config.headline??'');
  const description=String(config.subheadline??'');
  const notice=String(config.announcement??'');
  if(headline.length<5||headline.length>110||description.length<5||
    description.length>280||notice.length>250||!safeHex(config.accentColor))return false;
  const h=$('.welcome-copy h1'),p=$('.welcome-copy > p');
  if(h)h.textContent=headline;
  if(p)p.textContent=description;
  cssVar('--cs-managed-accent',config.accentColor);
  const theme=config.theme||{};
  for(const [field,css] of Object.entries({
    background:'--cs-managed-bg',surface:'--cs-managed-surface',
    foreground:'--cs-managed-fg',muted:'--cs-managed-muted'
  })){
    if(safeHex(theme[field]))cssVar(css,theme[field]);
  }
  if(Number.isInteger(theme.radius)&&theme.radius>=4&&theme.radius<=28)
    cssVar('--cs-managed-radius',theme.radius+'px');
  if(typeof theme.fontScale==='number'&&theme.fontScale>=.9&&theme.fontScale<=1.15)
    cssVar('--cs-managed-font-scale',String(theme.fontScale));
  for(const key of Object.keys(OPTIONS)){
    const attr='data-cs-'+(key==='buttonStyle'?'buttons':'density');
    if(OPTIONS[key].includes(theme[key]))
      document.documentElement.setAttribute(attr,theme[key]);
  }
  document.documentElement.classList.add('cs-managed');
  let banner=$('#cs-admin-announcement');
  if(!banner){
    banner=document.createElement('p');banner.id='cs-admin-announcement';
    banner.className='cs-managed-announcement';
    const anchor=$('#cs-update-banner')||$('.welcome-panel');
    anchor?.insertAdjacentElement('afterend',banner);
  }
  banner.textContent=notice;banner.hidden=!notice;
  const flags=config.tools||{};
  for(const name of ['links','messages','apps']){
    if(typeof flags[name]==='boolean'){
      const tile=$('.action-tile--'+name);
      if(tile)tile.hidden=!flags[name];
    }
  }
  const labels=config.labels||{};
  for(const name of ['links','messages','apps','guide']){
    const label=labels[name];
    if(typeof label==='string'&&label.length>=2&&label.length<=48){
      const tile=$('.action-tile--'+name+' .action-tile-title');
      if(tile)tile.textContent=label;
    }
  }
  updateLogo(config);
  return true;
}
async function loadSettings(){
  if(fetching||document.hidden)return;
  fetching=true;
  try{
    const native=typeof window.CyberShieldAndroid?.onlineRequest==='function';
    let config;
    if(native){
      if(typeof window.CyberShieldOnline?.request!=='function')return;
      config=await window.CyberShieldOnline.request('config');
    }else{
      const response=await fetch(origin+'/api/app-config',{cache:'no-store',
        credentials:'omit',signal:AbortSignal.timeout(8500)});
      if(!response.ok)return;
      config=await response.json();
    }
    if(!config||typeof config.revision!=='number')return;
    if(config.revision!==seenRevision){
      if(applyPublicSettings(config)){
        seenRevision=config.revision;
        document.dispatchEvent(new CustomEvent('CyberShieldBrandUpdated',
          {detail:{revision:seenRevision}}));
      }
    }
  }catch{/* offline; keep last safe settings and built-in UI */}
  finally{fetching=false;}
}
// Opt-in only, no page URLs, phone data, prompts, identifiers or IPs in payload.
// Server stores a daily HMAC hash of an ephemeral, random browser/app session.
function consentEnabled(){
  try{return localStorage.getItem('cs_usage_optin')==='yes';}catch{return false;}
}
function sessionToken(){
  try{
    let key=sessionStorage.getItem('cs_anonymous_session');
    if(!key||!/^[0-9a-f]{32}$/.test(key)){
      const bytes=new Uint8Array(16);crypto.getRandomValues(bytes);
      key=Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
      sessionStorage.setItem('cs_anonymous_session',key);
    }
    return key;
  }catch{return null;}
}
async function sendUsage(action='active'){
  if(!consentEnabled()||document.hidden)return;
  const token=sessionToken();if(!token)return;
  const body={session:token,platform:typeof window.CyberShieldAndroid?.onlineRequest==='function'?'android':'web',
    action,consent:true};
  try{
    if(body.platform==='android'){
      await window.CyberShieldOnline?.request?.('usage',body);
    }else{
      await fetch(origin+'/api/usage',{method:'POST',headers:{'Content-Type':'application/json'},
        credentials:'omit',body:JSON.stringify(body),keepalive:true,signal:AbortSignal.timeout(6000)});
    }
  }catch{/* never block safety tools because analytics is unavailable */}
}
export function setupUsageConsent(){
  const home=$('#page-home');if(!home||$('#cs-usage-consent'))return;
  const bar=document.createElement('div');
  bar.id='cs-usage-consent';bar.className='cs-usage-consent';
  const label=document.createElement('label');
  const checkbox=document.createElement('input');checkbox.type='checkbox';
  checkbox.checked=consentEnabled();checkbox.id='cs-usage-checkbox';
  const span=document.createElement('span');
  span.textContent='Help improve CyberShield: share anonymous activity counts and approximate session duration. Optional; no phone numbers, messages or location are collected for these statistics.';
  label.append(checkbox,span);bar.append(label);
  const note=document.createElement('small');
  note.textContent='You can switch this off at any time. Counts are approximate, not device tracking.';
  bar.append(note);home.append(bar);
  checkbox.addEventListener('change',()=>{
    try{localStorage.setItem('cs_usage_optin',checkbox.checked?'yes':'no');}catch{}
    if(checkbox.checked)void sendUsage('active');
  });
  if(checkbox.checked)void sendUsage('active');
  document.addEventListener('click',event=>{
    if(!consentEnabled())return;
    const button=event.target.closest('a[href*="/releases/download/"], #cs-update-download');
    if(button)void sendUsage('download_click'); // click only, not installation proof
  });
}
if(typeof document!=='undefined'){
  document.addEventListener('DOMContentLoaded',setupUsageConsent,{once:true});
  if(document.readyState!=='loading')setupUsageConsent();
  void loadSettings();
  setInterval(()=>{if(!document.hidden)void loadSettings();},12000);
  setInterval(()=>{if(!document.hidden)void sendUsage('active');},90_000);
  document.addEventListener('visibilitychange',()=>{if(!document.hidden){void loadSettings();void sendUsage('active');}});
  window.addEventListener('focus',()=>void loadSettings());
}
