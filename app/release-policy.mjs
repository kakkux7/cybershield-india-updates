/** CyberShield release metadata policy; no APK download or install here. */
export function compareVersion(a,b){
  if(!/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(String(a)) || !/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(String(b)))return 0;
  const x=String(a).split('.').map(Number),y=String(b).split('.').map(Number);
  for(let i=0;i<3;i++)if(x[i]!==y[i])return x[i]>y[i]?1:-1;
  return 0;
}
export function isTrustedReleasePage(value){
  try{
    const u=new URL(value);
    if(u.protocol!=='https:' || u.username || u.password || u.hash || u.port)return false;
    if(u.hostname==='github.com' && !u.search) return /^\/kakkux7\/(?:cybershield-india|cybershield-india-updates)\/releases\/(?:latest|tag\/v\d{1,3}\.\d{1,3}\.\d{1,3})$/.test(u.pathname);
    return u.hostname==='play.google.com' && u.pathname==='/store/apps/details' && u.search==='?id=in.cybershield.india.beta';
  }catch{return false;}
}
export function newerRelease(data,current,code){
  return data?.checked===true && data?.published===true &&
    compareVersion(data.latestVersion,current)>0 &&
    Number.isInteger(data.versionCode) && data.versionCode>code &&
    isTrustedReleasePage(data.releasePage);
}
