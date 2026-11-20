/** Small, user-initiated AI Companion on Home. No prompts stored or sent without consent. */
import {companionAdvice} from './intelligence.mjs';
const $=id=>document.getElementById(id);
const toggle=$('cs-ai-toggle'),panel=$('cs-ai-panel'),close=$('cs-ai-close'),form=$('cs-ai-form'),question=$('cs-ai-question'),submit=$('cs-ai-submit'),answer=$('cs-ai-answer');
let pending=false;
function show(message){answer.hidden=false;answer.textContent=message;}
function openPanel(open){
 panel.hidden=!open;
 toggle.setAttribute('aria-expanded',String(open));
 if(open)question.focus();else toggle.focus();
}
toggle?.addEventListener('click',()=>openPanel(panel.hidden));
close?.addEventListener('click',()=>openPanel(false));
form?.addEventListener('submit',async e=>{
 e.preventDefault();if(pending)return;
 const q=question.value.trim();
 if(!q||q.length>800){show('Enter a cyber-safety question under 800 characters. Do not include OTPs, passwords or identifying information.');return;}
 if(!$('cs-ai-consent')?.checked){show('To use live AI, first consent to sending this question to the external Gemini provider. Or use Offline guidance.');return;}
 pending=true;submit.disabled=true;show('Asking the optional online AI provider…');
 try{
   if(typeof window.CyberShieldOnline?.request!=='function')throw Error('Connection is not ready');
   const data=await window.CyberShieldOnline.request('companion',{question:q});
   if(!data||typeof data.answer!=='string'||!data.answer.trim())throw Error('No usable live response');
   show((data.source||'Online AI')+' — AI guidance, not verified evidence:\n'+data.answer+'\n\n'+(data.important||'Verify independently.'));
 }catch{
   show('LIVE AI UNAVAILABLE. Offline rule-based safety guidance (not generative AI):\n'+companionAdvice(q).answer);
 }finally{pending=false;submit.disabled=false;}
});
$('cs-ai-offline')?.addEventListener('click',()=>{
 const q=question.value.trim();
 try{show('OFFLINE RULE-BASED GUIDANCE (not generative AI):\n'+companionAdvice(q).answer);}
 catch(e){show(e.message);}
});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!panel.hidden)openPanel(false);});
