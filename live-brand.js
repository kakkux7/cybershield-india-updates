/** Public site brand refresh. Safe, owner-approved text/colors/logo only. */
const API='https://cybershield-india-beta.onrender.com';
let current=null;let busy=false;
const text=(node,value)=>{if(node)node.textContent=value;};
function apply(data){
 if(!data||typeof data.revision!=='number'||data.revision===current)return;
 if(typeof data.accentColor!=='string'||!/^#[0-9a-f]{6}$/i.test(data.accentColor))return;
 const style=document.documentElement.style;
 style.setProperty('--mint',data.accentColor);
 style.setProperty('--green',data.accentColor);
 const notice=String(data.announcement||'').slice(0,250);
 let box=document.getElementById('cybershield-public-announcement');
 if(!box){
   const intro=document.querySelector('.hero-actions');
   if(intro){
     box=document.createElement('p');box.id='cybershield-public-announcement';
     box.style.cssText='border-left:3px solid var(--mint);padding:10px 14px;background:rgba(30,77,67,.40);border-radius:8px;white-space:pre-wrap';
     intro.insertAdjacentElement('beforebegin',box);
   }
 }
 if(box){box.hidden=!notice;text(box,notice);}
 const theme=data.theme||{};
 if(theme.logoEnabled===true){
   const mark=document.querySelector('.logo .mark');
   if(mark){
     let img=mark.querySelector('.cs-brand-logo');
     if(!img){
       img=document.createElement('img');img.className='cs-brand-logo';
       img.alt='CyberShield India logo';
       img.style.cssText='width:100%;height:100%;object-fit:contain';
       img.onerror=()=>{img.remove();mark.querySelector('svg')?.removeAttribute('hidden');};
       mark.append(img);
     }
     img.src=API+'/api/app-brand/logo.png?v='+data.revision;
     mark.querySelector('svg')?.setAttribute('hidden','');
   }
 }else{
   document.querySelector('.cs-brand-logo')?.remove();
   document.querySelector('.logo .mark svg')?.removeAttribute('hidden');
 }
 current=data.revision;
}
async function refresh(){
 if(busy||document.hidden)return;busy=true;
 try{
   const response=await fetch(API+'/api/app-config',{
     cache:'no-store',credentials:'omit',signal:AbortSignal.timeout(8000)});
   if(response.ok)apply(await response.json());
 }catch{/* Continue showing the built-in public site while offline */}
 finally{busy=false;}
}
if(typeof document!=='undefined'){
 void refresh();
 setInterval(refresh,15000);
 document.addEventListener('visibilitychange',()=>{if(!document.hidden)void refresh();});
}
