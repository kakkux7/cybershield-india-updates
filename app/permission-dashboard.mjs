/** Permission metadata summary only. Never infer actual app usage or malware. */
const categories=[
 {id:'camera',label:'Camera granted',field:'granted',permissions:['CAMERA'],meaning:'Permission reported granted; not proof of camera use'},
 {id:'microphone',label:'Microphone granted',field:'granted',permissions:['RECORD_AUDIO'],meaning:'Permission reported granted; check actual history in Android Privacy Dashboard'},
 {id:'location',label:'Location granted',field:'granted',permissions:['ACCESS_FINE_LOCATION','ACCESS_COARSE_LOCATION','ACCESS_BACKGROUND_LOCATION'],meaning:'Location permission reported granted; not actual tracking history'},
 {id:'sms',label:'SMS granted',field:'granted',permissions:['READ_SMS','RECEIVE_SMS','SEND_SMS'],meaning:'SMS capability reported granted, subject to Android restrictions'},
 {id:'contacts',label:'Contacts granted',field:'granted',permissions:['READ_CONTACTS','WRITE_CONTACTS'],meaning:'Contacts access reported granted'},
 {id:'overlays',label:'Overlay capability requested',field:'requested',permissions:['SYSTEM_ALERT_WINDOW'],meaning:'Special access status cannot be inferred from requested permissions'},
 {id:'installers',label:'APK-install capability requested',field:'requested',permissions:['REQUEST_INSTALL_PACKAGES'],meaning:'Special access may be disabled even when requested'},
 {id:'accessibility',label:'Accessibility service declared',field:'declaredCapabilities',permissions:['ACCESSIBILITY_SERVICE'],meaning:'Declared service does not establish that Accessibility is enabled'},
 {id:'notificationListener',label:'Notification-listener service declared',field:'declaredCapabilities',permissions:['NOTIFICATION_LISTENER_SERVICE'],meaning:'Declared capability only; not proof that notification access is enabled'},
 {id:'screen',label:'Screen-capture service declared',field:'requested',permissions:['FOREGROUND_SERVICE_MEDIA_PROJECTION'],meaning:'Incomplete indicator; actual screen sharing is NOT measurable here'},
];
export function summarizePermissions(apps){
 const visible=Array.isArray(apps)?apps.slice(0,600).filter(a=>a&&typeof a.package==='string'):[];
 return {visible:visible.length,groups:categories.map(cat=>{
   const matches=visible.filter(app=>cat.permissions.some(p=>Array.isArray(app[cat.field])&&app[cat.field].includes(p)));
   return {id:cat.id,label:cat.label,meaning:cat.meaning,kind:cat.field==='granted'?'granted':'declared',count:matches.length,
     apps:matches.map(a=>({label:String(a.label||a.package).slice(0,100),package:a.package}))};
 }),limits:'These are reported grants or declarations for visible apps only, not observed usage. Screen sharing cannot be fully inventoried. Review Android Privacy Dashboard and Special app access for actual activity and enabled special services.'};
}
