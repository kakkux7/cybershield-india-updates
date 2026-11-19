/** Bounded ZIP/APK filename metadata inspection. NEVER inflates or runs archive data. */
const codeFile=/\.(?:apk|exe|scr|com|bat|cmd|ps1|vbs|hta|js|jse|jar|lnk|sh|elf|dex)$/i;
const disguised=/\.(?:pdf|jpg|jpeg|png|txt|doc|docx|xlsx|mp4)\.(?:apk|exe|scr|bat|cmd|js|vbs)$/i;
const MAX_TAIL=131072, MAX_MEMBERS=250;
function read16(v,at){return v.getUint16(at,true)}
function read32(v,at){return v.getUint32(at,true)}
export function inspectZipDirectory(bytes,fullSize=bytes.length){
 if(!(bytes instanceof Uint8Array)) throw Error('Invalid archive metadata');
 const v=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);
 let eocd=-1;
 for(let i=bytes.length-22;i>=0 && i>=bytes.length-65557;i--){if(read32(v,i)===0x06054b50){eocd=i;break;}}
 if(eocd<0)return {inspected:false,findings:[{severity:'unverified',heading:'Archive listing unavailable',detail:'The ZIP end-of-directory record was not found in the permitted metadata window.'}]};
 const count=read16(v,eocd+10),centralSize=read32(v,eocd+12),centralOffset=read32(v,eocd+16);
 const base=fullSize-bytes.length,begin=centralOffset-base;
 if(count>MAX_MEMBERS || centralSize>MAX_TAIL || begin<0 || begin+centralSize>bytes.length)
   return {inspected:false,findings:[{severity:'unverified',heading:'Archive too large to list safely',detail:'Only a bounded number of archive filenames can be inspected; contents were not extracted.'}]};
 let cursor=begin,scriptCount=0,disguisedCount=0,traversalCount=0,packedBombSignals=0,processed=0;
 for(let n=0;n<count;n++){
   if(cursor<0 || cursor+46>bytes.length || read32(v,cursor)!==0x02014b50)break;
   const comp=read32(v,cursor+20),uncomp=read32(v,cursor+24);
   const nameSize=read16(v,cursor+28),extra=read16(v,cursor+30),comment=read16(v,cursor+32);
   const end=cursor+46+nameSize;
   if(end>bytes.length)break;
   const name=new TextDecoder('utf-8',{fatal:false}).decode(bytes.subarray(cursor+46,end)).slice(0,350);
   const clean=name.replace(/\\/g,'/');
   if(codeFile.test(name))scriptCount++;
   if(disguised.test(name))disguisedCount++;
   if(clean.startsWith('/') || /(?:^|\/)\.\.(?:\/|$)/.test(clean))traversalCount++;
   if(uncomp>20*1024*1024 && (comp===0 || uncomp/comp>200))packedBombSignals++;
   processed++;
   cursor=end+extra+comment;
 }
 const findings=[];
 if(scriptCount) findings.push({severity:'caution',heading:`${scriptCount} executable or script-like member(s)`,detail:'Archive includes filenames ending in runnable file types. This is a warning to review its source, not a malware verdict.'});
 if(disguisedCount)findings.push({severity:'warning',heading:`${disguisedCount} misleading double extension(s)`,detail:'Some filenames look like documents or photos but end with executable extensions.'});
 if(traversalCount)findings.push({severity:'warning',heading:`${traversalCount} path traversal name(s)`,detail:'The archive contains relative or absolute paths that could be unsafe with vulnerable extractors.'});
 if(packedBombSignals)findings.push({severity:'warning',heading:`${packedBombSignals} unusually expanded member(s)`,detail:'Some declared uncompressed sizes are very large compared with compressed sizes. Actual decompression was not performed.'});
 if(processed<count)findings.push({severity:'unverified',heading:'Archive listing incomplete',detail:'Some ZIP metadata could not be parsed safely.'});
 return {inspected:processed===count,entryCount:processed,findings,limit:'ZIP filename and declared size metadata only. No decompression, scanning inside members, script execution or definitive malware detection.'};
}
export async function inspectBrowserZip(file){
 if(!file || !Number.isFinite(file.size))throw Error('Choose a readable ZIP file.');
 const tail=new Uint8Array(await file.slice(Math.max(0,file.size-MAX_TAIL)).arrayBuffer());
 return inspectZipDirectory(tail,file.size);
}
