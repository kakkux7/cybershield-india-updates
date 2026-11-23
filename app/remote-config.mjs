/** CyberShield editorial settings. Safe text/color/shortcut presentation only.
 * Admin credentials and editor controls never enter this client bundle.
 */
const origin = location.hostname === 'kakkux7.github.io'
  ? 'https://cybershield-india-beta.onrender.com' : '';
const $ = selector => document.querySelector(selector);
export function applyPublicSettings(config){
 if (!config || typeof config !== 'object') return false;
 const headline = String(config.headline ?? '');
 const subheadline = String(config.subheadline ?? '');
 const announcement = String(config.announcement ?? '');
 const accent = String(config.accentColor ?? '');
 if(headline.length < 5 || headline.length > 110 ||
    subheadline.length < 5 || subheadline.length > 280 ||
    announcement.length > 250 || !/^#[a-fA-F0-9]{6}$/.test(accent)) return false;
 const h = $('.welcome-copy h1'), p = $('.welcome-copy > p');
 if(h)h.textContent=headline;
 if(p)p.textContent=subheadline;
 document.documentElement.style.setProperty('--cs-managed-accent',accent);
 document.documentElement.classList.add('cs-managed');
 let banner=$('#cs-admin-announcement');
 if(!banner){
  banner=document.createElement('p');banner.id='cs-admin-announcement';banner.className='cs-managed-announcement';
  const anchor=$('#cs-update-banner')||$('.welcome-panel');
  anchor?.insertAdjacentElement('afterend',banner);
 }
 banner.textContent=announcement;banner.hidden=!announcement;
 const tools=config.tools;
 if(tools && typeof tools==='object'){
  for(const name of ['links','messages','apps']){
   if(typeof tools[name]==='boolean'){
    const tile=$('.action-tile--'+name);
    if(tile)tile.hidden=!tools[name];
   }
  }
 }
 return true;
}
async function loadSettings(){
 try{
  // The bundled Android WebView permits only its own origin. Fetch via its
  // audited native HTTPS gateway instead of exposing arbitrary web origins.
  const fromNative=typeof window.CyberShieldAndroid?.onlineRequest==='function';
  let config;
  if(fromNative){
   if(typeof window.CyberShieldOnline?.request !=='function')return;
   config=await window.CyberShieldOnline.request('config');
  }else{
   const response=await fetch(origin+'/api/app-config',{cache:'no-store',credentials:'omit',
     signal:AbortSignal.timeout(8500)});
   if(!response.ok)return;
   config=await response.json();
  }
  applyPublicSettings(config);
 }catch{ /* network offline -> use shipped UI; never show an admin error */ }
}
if(typeof document!=='undefined')loadSettings();
