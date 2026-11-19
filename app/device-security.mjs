import {FILE_LIMIT,FILE_COUNT_LIMIT,inspectBrowserFile,validSHA256} from './file-security.mjs';
const $=id=>document.getElementById(id);
const native=()=>typeof window.CyberShieldAndroid?.selectFiles==='function';
let results=[];
const txt=(id,s)=>{const el=$(id);if(el){el.hidden=false;el.textContent=s;}};
function fileItem(result){
 const node=document.createElement('div');node.className='cs-file-card';
 const title=document.createElement('strong');title.textContent=result.name||'Selected file';node.append(title);
 const info=document.createElement('p');info.textContent=`${(Number(result.size||0)/1024).toFixed(1)} KB · ${result.kind||'Unknown type'} · ${result.level||'unverified'}`;node.append(info);
 for(const issue of (result.findings||[])){const p=document.createElement('p');p.className='cs-file-warning';p.textContent=`⚠ ${issue.heading}: ${issue.detail}`;node.append(p);}
 const note=document.createElement('p');note.textContent=result.conclusion||'This is not a complete malware scan.';node.append(note);
 if(result.sha256){const hash=document.createElement('p');hash.className='cs-file-hash';hash.textContent='SHA-256: '+result.sha256;node.append(hash);
  const b=document.createElement('button');b.type='button';b.className='btn btn-secondary';b.textContent='Check fingerprint online';
  b.addEventListener('click',()=>hashLookup(result.sha256,node));node.append(b);
 }
 return node;
}
function showResults(){const box=$('cs-files-results');if(!box)return;box.replaceChildren();for(const r of results)box.append(fileItem(r));}
async function hashLookup(sha,node){
 if(!validSHA256(sha))return;
 if(!$('cs-hash-consent')?.checked){txt('cs-files-status','Check the consent box first. Only the SHA-256 fingerprint will be sent; no file bytes.');return;}
 const area=document.createElement('p');area.className='cs-security-report';area.textContent='Checking available online file reputation…';node.append(area);
 try{
  const result=await window.CyberShieldOnline.request('fileHash',{sha256:sha});
  const clean=(result.malicious||0),suspect=(result.suspicious||0);
  area.textContent=result.providerChecked ?
   `Online source: ${result.source||'file hash reputation'} · ${result.found?'Known file':'No known report'} · ${clean} engines marked malicious, ${suspect} suspicious. ${result.important||'No report or zero detections cannot prove safety.'}`:
   `${result.providerWarning||'No licensed file reputation provider is configured.'} File remains UNVERIFIED.`;
 }catch(e){area.textContent='Online file reputation unavailable: '+e.message+'. Not verified; no file uploaded.';}
}
window.CyberShieldReceiveFiles=(payload)=>{
 if(!payload?.ok){txt('cs-files-status',payload?.error||'File check unavailable');return;}
 results=Array.isArray(payload.files)?payload.files:[];showResults();
 txt('cs-files-status',`Reviewed ${results.length} file(s) locally. This is a limited static review, not a full spyware/virus scan.`);
};
$('cs-choose-files')?.addEventListener('click',()=>window.CyberShieldAndroid?.selectFiles?.());
$('cs-choose-folder')?.addEventListener('click',()=>window.CyberShieldAndroid?.selectFolder?.());
$('cs-browser-files')?.addEventListener('change',async event=>{
 const selection=Array.from(event.target.files||[]).slice(0,FILE_COUNT_LIMIT);results=[];
 txt('cs-files-status',`Checking ${selection.length} selected file(s) on this device…`);
 for(const f of selection){try{results.push(await inspectBrowserFile(f));}catch(e){results.push({name:f.name,size:f.size,kind:'Unknown',level:'unverified',findings:[],conclusion:'Could not inspect: '+e.message});}}
 showResults();txt('cs-files-status',`Reviewed ${results.length} file(s). No file contents were uploaded.`);
});
window.CyberShieldReceiveWifi=info=>{
 if(!info?.ok){txt('cs-wifi-result',info?.error||'Wi-Fi check failed.');return;}
 const findings=Array.isArray(info.findings)?info.findings.join('\n• '):'No additional findings.';
 txt('cs-wifi-result',`${info.connection||'Connection unknown'}\nWi-Fi encryption: ${info.security||'Unknown'}\nInternet connectivity validated by Android: ${info.validated===true?'Yes':info.validated===false?'No':'Unknown'}\nAssessment: ${info.level||'UNVERIFIED'}\n• ${findings}\n${info.important||'This cannot prove the router or network is safe.'}`);
};
$('cs-wifi-check')?.addEventListener('click',()=>{
 if(window.CyberShieldAndroid?.checkWifi){txt('cs-wifi-result','Reading the connected network security details…');window.CyberShieldAndroid.checkWifi();}
 else txt('cs-wifi-result','Browsers do not expose Wi-Fi encryption or router security. On Android, use the CyberShield beta. On laptops, open your Wi-Fi connection properties, check for WPA2-AES/WPA3, and avoid entering sensitive data on unknown captive portals. This cannot prove the network is safe.');
});
if(native()){$('cs-browser-files').hidden=true;$('cs-choose-files').hidden=false;$('cs-choose-folder').hidden=false;}
else {$('cs-choose-files').hidden=true;$('cs-choose-folder').hidden=true;}
