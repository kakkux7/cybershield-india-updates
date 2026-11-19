import { inspectBrowserZip } from './archive-intelligence.mjs';
/** Conservative, side-effect-free file metadata and signature checks. No execution or uploads. */
export const FILE_LIMIT = 48 * 1024 * 1024;
export const FILE_COUNT_LIMIT = 30;
const risky = new Set(['apk','exe','msi','scr','com','bat','cmd','ps1','vbs','vbe','hta','js','jse','jar','wsf','lnk','sh']);
const decoy = new Set(['pdf','png','jpg','jpeg','doc','docx','txt','xlsx','pptx','gif','mp4','zip']);
export function fileClues(name, size, head) {
  name=String(name || 'unnamed').slice(0,180);
  const bytes=head instanceof Uint8Array ? head : new Uint8Array(head || []);
  const ext=name.split('.').pop().toLowerCase();
  const pieces=name.toLowerCase().split('.');
  const findings=[];
  const add=(severity,heading,detail)=>findings.push({severity,heading,detail});
  let kind='Unknown';
  if(bytes.length>=2&&bytes[0]===0x4d&&bytes[1]===0x5a)kind='Windows executable (MZ)';
  else if(bytes.length>=4&&bytes[0]===0x7f&&bytes[1]===0x45&&bytes[2]===0x4c&&bytes[3]===0x46)kind='Linux executable (ELF)';
  else if(bytes.length>=4&&bytes[0]===0x50&&bytes[1]===0x4b&&bytes[2]===0x03&&bytes[3]===0x04)kind='ZIP-based container';
  else if(bytes.length>=5&&String.fromCharCode(...bytes.slice(0,5))==='%PDF-')kind='PDF document';
  else if(bytes.length>=8&&bytes.slice(0,8).every((n,i)=>n===[137,80,78,71,13,10,26,10][i]))kind='PNG image';
  else if(bytes.length>=3&&bytes[0]===0xff&&bytes[1]===0xd8&&bytes[2]===0xff)kind='JPEG image';
  else if(bytes.length>=6&&String.fromCharCode(...bytes.slice(0,3))==='GIF')kind='GIF image';
  if(risky.has(ext))add('caution','Executable or script extension','Files like this can run code. Only open files from a verified publisher.');
  if(pieces.length>=3 && decoy.has(pieces[pieces.length-2]) && risky.has(ext)) add('warning','Misleading double extension','The name looks like a document or picture, but its real extension can execute code.');
  if(kind.includes('executable') && decoy.has(ext))add('warning','File type does not match its name','Its bytes look like executable code although its name looks like a document or media file.');
  if(ext==='pdf' && kind!=='PDF document') add('caution','PDF header not recognized','This file does not begin with the usual PDF signature. It may be damaged, mislabeled, or unusual.');
  if(['png','jpg','jpeg'].includes(ext)&&kind!=='Unknown'&&!kind.toLowerCase().includes(ext==='jpg'?'jpeg':ext))add('caution','Image type mismatch','The file signature does not match its image extension.');
  // Static first bytes only; patterns are hints, never proof that code will execute.
  const visible=Array.from(bytes.slice(0,4096), b=>String.fromCharCode(b)).join('').toLowerCase();
  if(ext==='pdf' && /\/javascript|\/js\b|\/openaction/.test(visible))add('caution','Possible PDF active content','This PDF contains tokens sometimes used by interactive documents. Open it only with a current protected reader.');
  if(['html','htm','svg'].includes(ext) && /<script\b|onload\s*=|javascript\s*:/.test(visible))add('caution','Embedded active content','The file contains scripting clues. Do not open unexpected pages or SVGs from untrusted senders.');
  if(size===0)add('caution','Empty file','This file has no content to inspect.');
  return {name,size,kind,findings,level:findings.some(x=>x.severity==='warning')?'suspicious':findings.length?'caution':'unverified',
    conclusion:'This checks file names and signatures, not whether the file contains malware. No detection does NOT mean safe.'};
}
export function validSHA256(value){return /^[a-fA-F0-9]{64}$/.test(String(value||''));}
export async function inspectBrowserFile(file){
  if(!file||!Number.isFinite(file.size)||file.size>FILE_LIMIT)throw Error('File is too large (maximum 48 MB per file).');
  const head=new Uint8Array(await file.slice(0,4096).arrayBuffer());
  const report=fileClues(file.name,file.size,head);
  if(!globalThis.crypto?.subtle) {report.hashError='Secure-context SHA-256 hashing unavailable; use HTTPS or Android.';return report;}
  const bytes=await file.arrayBuffer();
  const digest=await crypto.subtle.digest('SHA-256',bytes);
  report.sha256=Array.from(new Uint8Array(digest),x=>x.toString(16).padStart(2,'0')).join('');
  if(report.kind==='ZIP-based container' && /\.(?:zip|apk)$/i.test(file.name)) {
    try {
      report.archive=await inspectBrowserZip(file);
      report.findings.push(...report.archive.findings);
      if(report.archive.findings.some(x=>x.severity==='warning')) report.level='suspicious';
      else if(report.archive.findings.some(x=>x.severity==='caution') && report.level==='unverified') report.level='caution';
    }catch {report.archive={inspected:false,findings:[],limit:'Archive metadata could not be safely inspected.'};}
  }
  return report;
}
