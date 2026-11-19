import { analyzeLink, analyzeMessage, extractURL } from './detector.mjs';
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
let stats = { links: 0, messages: 0 };
const PAGES = new Set(['home', 'links', 'messages', 'apps', 'guide']);

function navigate(page) {
  if (!PAGES.has(page)) page = 'home';
  $$('.page').forEach(el => el.classList.toggle('hidden', el.id !== `page-${page}`));
  $$('[data-page]').forEach(el => {
    const isActive = el.dataset.page === page;
    el.classList.toggle('active', isActive);
    if (el.matches('.nav-btn, .mobile-nav-btn')) {
      if (isActive) el.setAttribute('aria-current', 'page');
      else el.removeAttribute('aria-current');
    }
  });
  window.scrollTo(0, 0);
}
$$('[data-page]').forEach(b => b.addEventListener('click', () => navigate(b.dataset.page)));
$$('[data-jump]').forEach(b => b.addEventListener('click', () => navigate(b.dataset.jump)));

function renderError(container, message) {
  container.replaceChildren();
  const p = document.createElement('div'); p.className = 'error-state'; p.textContent = message;
  container.append(p);
}
function make(tag, classes, text) {
  const el = document.createElement(tag);
  if (classes) el.className = classes;
  if (text != null) el.textContent = text;
  return el;
}
function renderResult(container, report) {
  container.replaceChildren();
  const header = make('div','result-heading');
  const titleWrap = make('div');
  titleWrap.append(make('h3',null,'Analysis complete'), make('div','result-caption',report.subject));
  const badge = make('span', `risk-badge ${report.level}`, report.level === 'high' ? 'HIGH RISK' : report.level === 'caution' ? 'CAUTION' : 'UNVERIFIED');
  header.append(titleWrap,badge);
  const summary = make('div','risk-summary',report.summary);
  const list = make('ul','findings-list');
  report.findings.forEach(item => {
    const li = make('li'); li.append(make('strong',null,item.heading),make('p',null,item.detail)); list.append(li);
  });
  const footnote = make('div','result-footnote','Offline pattern analysis only · No threat-intelligence lookup · Never assume a low-risk score means a link or message is safe.');
  container.append(header, summary, list, footnote);
}
function runLink() {
  const target = $('#link-result');
  try {
    const report = analyzeLink($('#url-input').value);
    renderResult(target,report);
    stats.links++; $('#links-count').textContent=String(stats.links);
  } catch (error) { renderError(target,error.message); }
}
function runMessage() {
  const target = $('#message-result');
  try {
    const report = analyzeMessage($('#message-input').value);
    renderResult(target,report);
    stats.messages++; $('#messages-count').textContent=String(stats.messages);
  } catch (error) { renderError(target,error.message); }
}
$('#link-form').addEventListener('submit', e=>{e.preventDefault(); runLink();});
$('#message-form').addEventListener('submit', e=>{e.preventDefault(); runMessage();});
$('#example-risky').addEventListener('click',()=>{$('#url-input').value='http://sbi-kyc-update.example/verify-login';runLink();});
$('#example-normal').addEventListener('click',()=>{$('#url-input').value='https://www.rbi.org.in/';runLink();});
$('#example-message').addEventListener('click',()=>{$('#message-input').value='URGENT: Your bank account will be blocked. Click https://sbi-kyc-update.example/verify-login and share your OTP immediately!';runMessage();});

/* Invoked by the Android shell only after it receives an explicit OS share action. */
window.CyberShieldReceiveShared = function(sharedText) {
  if (typeof sharedText !== 'string') return;
  const trimmed = sharedText.slice(0,5000).trim();
  if (!trimmed) return;
  const candidate = extractURL(trimmed);
  if (candidate && trimmed === candidate) { $('#url-input').value = candidate; navigate('links'); runLink(); }
  else { $('#message-input').value = trimmed; navigate('messages'); runMessage(); }
};

/* Online hosting can install as a PWA. Android embedded assets do not need SW. */
if ('serviceWorker' in navigator && location.hostname !== 'appassets.androidplatform.net') {
  window.addEventListener('load',()=>navigator.serviceWorker.register('./sw.js').catch(()=>{}));
}

/* APK metadata is produced by Android's PackageManager after a file-picker gesture.
 * This receives only a summary, never APK contents; use textContent to avoid HTML injection. */
const apkButton = document.getElementById('choose-apk');
const apkNote = document.getElementById('apk-device-note');
if (window.CyberShieldAndroid && typeof window.CyberShieldAndroid.selectApk === 'function') {
  apkNote.textContent = 'APK selection is private. Files are not executed or uploaded.';
  apkButton.addEventListener('click', () => window.CyberShieldAndroid.selectApk());
} else {
  apkButton.disabled = true;
  apkButton.textContent = 'Available in Android app only';
}
window.CyberShieldReceiveApk = function(report) {
  const result = document.getElementById('apk-result');
  result.replaceChildren();
  if (!report || !report.ok) {
    renderError(result, report?.error || 'Could not inspect APK.');
    return;
  }
  const heading = make('h3', null, 'APK review: ' + (report.label || 'Unknown application'));
  heading.style.marginTop = '20px';
  const verdict = make('p', 'risk-summary', 'Declared permissions: ' + report.permissionCount + ' · Caution flags: ' + report.flags.length + '. This is NOT a malware verdict.');
  const list = make('ul', 'findings-list');
  (report.flags.length ? report.flags : ['No selected high-risk permissions found. This does NOT prove the app is safe.']).forEach(label => {
    const li = make('li'); li.append(make('p', null, label)); list.append(li);
  });
  const info = make('p','result-footnote','File inspected locally, then the temporary copy is removed. Never install untrusted APKs solely based on these findings.');
  result.append(heading, verdict, list, info);
};
