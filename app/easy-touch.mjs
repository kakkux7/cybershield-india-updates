// CyberShield Easy Touch: local navigation and user-initiated Android overlay setup.
// No cross-app screen, clipboard or message access occurs in the floating button.
const el = id => document.getElementById(id);
const android = () => window.CyberShieldAndroid;
const bubble = el('cs-easy-bubble');
const panel = el('cs-easy-panel');
function setOpen(open) {
  if (!panel || !bubble) return;
  panel.hidden = !open;
  bubble.setAttribute('aria-expanded', String(open));
  bubble.textContent = open ? '×' : '✦';
}
bubble?.addEventListener('click', () => setOpen(panel.hidden));
el('cs-easy-close')?.addEventListener('click', () => setOpen(false));
document.addEventListener('keydown', e => { if(e.key === 'Escape') setOpen(false); });
function navigateTo(page) { document.querySelector(`[data-page="${page}"]`)?.click(); }
export function openQuickTool(tool) {
  const route = {link:'links',phone:'links',screen:'messages',qr:'links',apps:'apps',files:'apps',wifi:'apps',report:'guide',guide:'guide'};
  if (!Object.hasOwn(route,tool)) return false;
  setOpen(false);
  navigateTo(route[tool]);
  const id={link:'url-input',phone:'phone-input',screen:'screenshot-native',qr:'qr-native',apps:'installed-scan',files:'cs-choose-files',wifi:'cs-wifi-check',report:'report-evidence'}[tool];
  const target=id?el(id):null;
  if(target){target.scrollIntoView({block:'center',behavior:'smooth'});}
  if(tool==='screen') {
    if(android()?.selectImage) android().selectImage('screenshot');
    else el('screenshot-file')?.click();
  }else if(tool==='files'){
    if(android()?.selectFiles)android().selectFiles();else el('cs-browser-files')?.click();
  }else if(tool==='wifi'){
    el('cs-wifi-check')?.click();
  }else if(tool==='qr'){
    if(android()?.selectImage)android().selectImage('qr');
    else el('qr-file')?.click();
  } else if(tool==='link' || tool==='phone' || tool==='report'){
    target?.focus({preventScroll:true});
  }
  return true;
}
window.CyberShieldQuickOpen = openQuickTool;
document.querySelectorAll('[data-easy-tool]').forEach(button=>button.addEventListener('click',()=>openQuickTool(button.dataset.easyTool)));
const status=el('cs-easy-status');
const enable=el('cs-easy-enable'); const disable=el('cs-easy-disable');
function say(s){if(status)status.textContent=s;}
if (typeof android()?.enableEasyTouch !== 'function') {
  if(enable) {enable.disabled=true;enable.textContent='Android app only';}
  if(disable) disable.hidden=true;
  say('Inside a browser, use the ✦ floating shortcut on this page. To use it over WhatsApp or other apps, install the Android beta and enable Easy Touch there.');
} else {
  say('Easy Touch is optional and off until you enable it. Android will ask for “Display over other apps” permission.');
  enable?.addEventListener('click',()=>{
    say('Opening Android system permission if needed. Allow only if you want CyberShield displayed over other apps.');
    android().enableEasyTouch();
  });
  disable?.addEventListener('click',()=>{android().disableEasyTouch();say('Turning off Easy Touch…');});
  android().readyForQuickTools?.();
  android().easyTouchStatus?.();
}
window.CyberShieldReceiveEasyTouch = state => {
  if(!state?.android)return;
  if(!state.permission){say('Floating shield is not enabled. Use Enable to open Android Settings and grant display-over-apps permission.');return;}
  say(state.requested?'Floating shield was requested. Look for the ✦ bubble above other apps. Tap to expand; drag to move; Stop in its menu or here.':'Permission is available. Tap Enable floating shield to start it.');
};
window.CyberShieldReceiveClipboard = result => {
  const target=result?.target==='phone'?'phone-input':'url-input';
  const input=el(target); if(!input)return;
  if(result?.error){say(result.error);return;}
  input.value=String(result?.text||'');
  input.focus();
};
// Clipboard is only read in the foreground after a separate explicit button tap.
function addPasteButton(containerSelector,target){
  const form=el(containerSelector);if(!form||typeof android()?.pasteClipboard !== 'function')return;
  const b=document.createElement('button');b.type='button';b.className='btn btn-secondary cs-easy-clipboard';
  b.textContent=target==='phone'?'Paste copied number':'Paste copied link';
  b.addEventListener('click',()=>android().pasteClipboard(target));
  form.appendChild(b);
}
addPasteButton('phone-form','phone');addPasteButton('link-form','link');
