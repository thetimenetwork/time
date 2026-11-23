/* Real Chrome + real local gateway, without Playwright or a shared user profile. */
import { spawn } from 'node:child_process';
import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import assert from 'node:assert/strict';
const here = path.dirname(fileURLToPath(import.meta.url));
const production = path.resolve(here, '../../..');
function argument(name, fallback) { const i = process.argv.indexOf(name); return i < 0 ? fallback : process.argv[i + 1]; }
const url = argument('--url', 'http://127.0.0.1:8907');
const out = path.resolve(argument('--out', path.join(production, 'results-v4/auth-failure-browser.json')));
const chrome = argument('--chrome', 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe');
const runId = randomBytes(5).toString('hex');
const profile = path.join(production, '.local', 'browser-' + runId);
const screenshotDirectory = out.replace(/\.json$/i, '') + '-screenshots';
const withBackup=process.argv.includes('--backup');
const downloadDirectory=path.join(profile,'encrypted-downloads');
let portableBackup;
const names = { alice: 'ea_' + runId, bob: 'eb_' + runId, carol: 'ec_' + runId };
const proofNames = Object.values(names);
const passwords = { alice: 'amber forest ' + randomBytes(20).toString('base64url'), bob: 'silver garden ' + randomBytes(20).toString('base64url'), carol: 'cedar orchard ' + randomBytes(20).toString('base64url') };
const report = { status: 'RUNNING', kind: 'REAL_HEADLESS_CHROME_LOCAL_DEVNET', url, startedAt: new Date().toISOString(), checks: [], screenshots: [], issues: [] };
let child, socket, cdp, browserLog = '', currentStep = '';
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function step(name, fn) {
  currentStep = name; const start = performance.now();
  try { const detail = await fn(); report.checks.push({ name, passed: true, ms: Math.round(performance.now() - start), ...(detail ? { detail } : {}) }); console.log('PASS ' + name); return detail; }
  catch (error) { report.checks.push({ name, passed: false, ms: Math.round(performance.now() - start), error: error.message }); throw error; }
}
class CDP {
  next = 1; pending = new Map(); events = []; listeners = new Set();
  constructor(ws) { this.ws = ws; ws.addEventListener('message', e => { const data = JSON.parse(String(e.data)); if (data.id) { const p = this.pending.get(data.id); if (!p) return; this.pending.delete(data.id); clearTimeout(p.timer); data.error ? p.reject(new Error(data.error.message)) : p.resolve(data.result); } else { this.events.push(data); if (this.events.length > 4000) this.events.shift(); for (const listener of this.listeners) Promise.resolve(listener(data)).catch(() => {}); } }); ws.addEventListener('close', () => { for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(new Error('Owned Chrome session closed')); } this.pending.clear(); }); }
  send(method, params = {}, sessionId) {
    if (this.ws.readyState !== WebSocket.OPEN) return Promise.reject(new Error('Owned Chrome session closed'));
    const id = this.next++;
    return new Promise((resolve, reject) => { const timer = setTimeout(() => { this.pending.delete(id); reject(new Error('CDP timeout: ' + method)); }, 30000); this.pending.set(id, { resolve, reject, timer }); this.ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) })); });
  }
}
async function evaluate(page, expression) {
  expression=`(async()=>{if(location.origin===${JSON.stringify(url)}&&!window.__testTrust)window.__testTrust=await fetch('/trust-manifest.json').then(r=>r.json());return await (${expression});})()`;
  const result = await cdp.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true, userGesture: true }, page.sessionId);
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
  return result.result.value;
}
async function wait(page, expression, timeout = 90000) {
  const until = Date.now() + timeout; let last;
  while (Date.now() < until) {
    if (socket?.readyState !== WebSocket.OPEN) throw new Error('Owned Chrome session closed');
    try { const value = await evaluate(page, expression); if (value) return value; } catch (e) { last = e; }
    await delay(300);
  }
  const message = await evaluate(page, `document.querySelector('#notice')?.textContent || document.body?.innerText?.slice(0,500)`).catch(() => 'no document');
  throw new Error('Timed out waiting for browser state: ' + message + (last ? ' · ' + last.message : ''));
}
async function pageAt(address, browserContextId) {
  const { targetId } = await cdp.send('Target.createTarget', { url: address, ...(browserContextId ? { browserContextId } : {}) });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  const page = { targetId, sessionId,browserContextId }; await cdp.send('Runtime.enable', {}, sessionId); await cdp.send('Page.enable', {}, sessionId);
  await wait(page, 'document.readyState === "complete"'); return page;
}
async function fill(page, id, value) {
  await evaluate(page, `(() => { const el=document.getElementById(${JSON.stringify(id)}); if(!el)throw Error('Missing input'); el.value=${JSON.stringify(value)}; el.dispatchEvent(new Event('input',{bubbles:true})); el.dispatchEvent(new Event('change',{bubbles:true})); })()`);
}
async function click(page, selector) {
  await cdp.send('Target.activateTarget', { targetId: page.targetId });
  // The wallet shows one screen at a time (Home, Send, Keys, More, and the screens under More), and keeps some parts
  // in closed sections. A control that is not on the screen is reached as a person reaches it: by the place it is in.
  await evaluate(page, `(() => { const e=document.querySelector(${JSON.stringify(selector)}); if (!e || e.getClientRects().length>0) return true; const go=name=>document.querySelector('.nav [data-panel="'+name+'"]')?.click(); const panel=e.closest('.workspace-panel'); if (e.closest('.more-list')) go('more'); else if (panel && panel.hidden) { const name=panel.id.slice('panel-'.length); if (document.querySelector('.nav [data-panel="'+name+'"]')) go(name); else document.querySelector('.more-list [data-panel="'+name+'"]')?.click(); } for (let d=e.closest('details'); d; d=d.parentElement?.closest('details')) d.open=true; return true; })()`);
  await wait(page, `(() => { const e=document.querySelector(${JSON.stringify(selector)}); return e && !e.disabled && e.getClientRects().length>0; })()`, 120000);
  await evaluate(page, `document.querySelector(${JSON.stringify(selector)}).click()`);
}
async function confirmReview(page) { await wait(page, `document.querySelector('#review-dialog').open`); await click(page, '#review-confirm'); }
async function dashboard(page, name) { return wait(page, `!document.querySelector('#dashboard').hidden && document.querySelector('#account-name').textContent===${JSON.stringify('@' + name)} && document.querySelector('#account-verification').textContent==='Checked by this browser'`); }
async function account(page, name) { return evaluate(page, `(async()=>{const v=await TimeSDK.createClient({trust:window.__testTrust}).getVerifiedState({names:${JSON.stringify(proofNames)}});if(v.verified!==true)throw Error('No verified state');return v.state.accounts.find(a=>a.name===${JSON.stringify(name)});})()`); }
async function create(page, which) {
  await wait(page, `!document.querySelector('#auth-submit').disabled`, 180000); await click(page, '#mode-create');
  await fill(page, 'username', names[which]); await fill(page, 'password', passwords[which]); await fill(page, 'password-confirm', passwords[which]);
  await click(page, '#auth-submit'); await dashboard(page, names[which]);
}
async function popupFrom(page) {
  const until = Date.now() + 30000;
  while (Date.now() < until) {
    const { targetInfos } = await cdp.send('Target.getTargets'); const target = targetInfos.find(t => t.type === 'page' && t.openerId === page.targetId && t.url.startsWith(url + '/approve'));
    if (target) { const { sessionId } = await cdp.send('Target.attachToTarget', { targetId: target.targetId, flatten: true }); const result = { targetId: target.targetId, sessionId }; await cdp.send('Runtime.enable', {}, sessionId); await cdp.send('Page.enable', {}, sessionId); await wait(result, 'document.readyState === "complete"'); return result; }
    await delay(100);
  }
  throw new Error('Website wallet popup did not open');
}
async function unlockAlicePopup(page) {
  await wait(page, `!document.querySelector('#auth-submit').disabled`); await click(page, '#mode-unlock');
  await fill(page, 'username', names.alice); await fill(page, 'password', passwords.alice); await click(page, '#auth-submit'); await dashboard(page, names.alice);
}
async function exportBackupFile(page,password){
  await mkdir(downloadDirectory,{recursive:true});
  await cdp.send('Browser.setDownloadBehavior',{behavior:'allow',downloadPath:downloadDirectory,eventsEnabled:true,...(page.browserContextId?{browserContextId:page.browserContextId}:{})});
  const began=cdp.events.length;await click(page,'#tab-security');await fill(page,'backup-export-password',password);await click(page,'#backup-export-submit');
  await wait(page,`document.querySelector('#notice').textContent.includes('Backup file downloaded')`);
  let event;for(let i=0;i<100;i++){event=cdp.events.slice(began).find(e=>e.method==='Browser.downloadWillBegin'&&e.params.suggestedFilename.endsWith('.vault.json'));if(event)break;await delay(100);}
  assert(event,'Encrypted backup download event missing');
  for(let i=0;i<100;i++){if(cdp.events.some(e=>e.method==='Browser.downloadProgress'&&e.params.guid===event.params.guid&&e.params.state==='completed'))break;await delay(100);}
  const filename=path.join(downloadDirectory,event.params.suggestedFilename),text=await readFile(filename,'utf8');
  const parsed=JSON.parse(text);assert.equal(parsed.format,'timecurrency-encrypted-vault');assert.ok(!text.includes(password));assert.ok(!text.includes('pkcs8'));
  assert.equal(await evaluate(page,`document.querySelector('#backup-export-password').value`),'');
  return {filename,text,binding:parsed.vault.binding};
}
async function restoreBackupFile(page,filename,password,expected='Backup restored'){
  await wait(page,`!document.querySelector('#backup-import-submit').disabled`);
  await evaluate(page,`document.querySelector('.backup-import').open=true`);
  const doc=await cdp.send('DOM.getDocument',{depth:0},page.sessionId),input=await cdp.send('DOM.querySelector',{nodeId:doc.root.nodeId,selector:'#backup-file'},page.sessionId);
  await cdp.send('DOM.setFileInputFiles',{files:[filename],nodeId:input.nodeId},page.sessionId);
  await fill(page,'backup-password',password);await click(page,'#backup-import-submit');
  await wait(page,`document.querySelector('#notice').textContent.includes(${JSON.stringify(expected)})`);
  assert.equal(await evaluate(page,`document.querySelector('#backup-password').value`),'');
}
async function screenshot(page, label) {
  const filename = path.join(screenshotDirectory, label + '.png');
  await evaluate(page, `document.querySelectorAll('input[type=password]').forEach(e=>{e.value='';e.style.visibility='hidden';})`);
  const result = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false }, page.sessionId);
  await writeFile(filename, Buffer.from(result.data, 'base64'));
  await evaluate(page, `document.querySelectorAll('input[type=password]').forEach(e=>e.style.visibility='')`);
  report.screenshots.push(filename); return filename;
}
async function takeFailureScreenshot() { for (const t of (await cdp.send('Target.getTargets').catch(() => ({ targetInfos: [] }))).targetInfos.filter(t => t.type === 'page' && t.url.startsWith(url))) { try { const { sessionId } = await cdp.send('Target.attachToTarget', { targetId: t.targetId, flatten: true }); await screenshot({ sessionId }, 'failure-' + report.screenshots.length); } catch {} } }
async function shutdown() {
  if (cdp) await cdp.send('Browser.close').catch(() => {}); socket?.close();
  if (child && child.exitCode === null) { await Promise.race([new Promise(resolve => child.once('exit', resolve)), delay(3000)]); if (child.exitCode === null) await new Promise(resolve => { const killer = spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' }); killer.once('exit', resolve); killer.once('error', resolve); }); }
  // This is only the fresh profile created above, with an absolute containment check before recursive deletion.
  assert.equal(path.dirname(path.resolve(profile)), path.resolve(production, '.local'));
  assert.equal(path.basename(profile), 'browser-' + runId);
  await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }).catch(error => { report.issues.push({ step: 'owned-profile-cleanup', message: error.message }); });
}
try {
  const target = new URL(url); assert(['127.0.0.1', 'localhost', '[::1]'].includes(target.hostname), 'This runner only accepts a loopback lab URL');
  await mkdir(profile, { recursive: true }); await mkdir(path.dirname(out), { recursive: true }); await mkdir(screenshotDirectory, { recursive: true });
  child = spawn(chrome, ['--headless=new', '--disable-gpu', '--disable-background-timer-throttling', '--disable-renderer-backgrounding', '--disable-backgrounding-occluded-windows', '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=0', '--user-data-dir=' + profile, '--window-size=1280,950', 'about:blank'], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] });
  child.stderr.on('data', chunk => { browserLog = (browserLog + chunk).slice(-3000); });
  child.on('error', e => { browserLog = e.message; });
  let port, browserPath;
  for (let i = 0; i < 100; i++) { try { [port, browserPath] = (await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).trim().split(/\r?\n/); break; } catch { await delay(100); } }
  assert(port && browserPath, 'Chrome DevTools did not start: ' + browserLog);
  socket = new WebSocket('ws://127.0.0.1:' + port + browserPath); await new Promise((resolve, reject) => { socket.addEventListener('open', resolve, { once: true }); socket.addEventListener('error', reject, { once: true }); }); cdp = new CDP(socket);
  report.browser = await cdp.send('Browser.getVersion');
  const alice=await pageAt(url);
  await step('failed sponsored signup locks decrypted key material and resumes the saved encrypted vault',async()=>{
    await wait(alice,`!document.querySelector('#auth-submit').disabled`);await click(alice,'#mode-create');
    await fill(alice,'username',names.alice);await fill(alice,'password',passwords.alice);await fill(alice,'password-confirm',passwords.alice);
    let failures=0;const intercept=event=>{if(event.sessionId===alice.sessionId&&event.method==='Fetch.requestPaused'){failures++;return cdp.send('Fetch.failRequest',{requestId:event.params.requestId,errorReason:'TimedOut'},alice.sessionId);}};cdp.listeners.add(intercept);
    await cdp.send('Fetch.enable',{patterns:[{urlPattern:'*/api/sponsor-registration',requestStage:'Request'}]},alice.sessionId);
    await click(alice,'#auth-submit');await wait(alice,`document.querySelector('#notice').textContent.includes('encrypted vault is saved')&&document.querySelector('#lock-button').hidden&&document.querySelector('#auth-submit').textContent==='Unlock this browser'`);
    assert.equal(failures,1);const saved=await evaluate(alice,`(()=>{const key=Object.keys(localStorage).find(k=>k.startsWith('timecurrency.vault.v1:'));const v=JSON.parse(localStorage[key]);return {binding:v.binding,encrypted:typeof v.ciphertext==='string',plaintext:localStorage[key].includes('pkcs8')};})()`);assert(saved.encrypted);assert.equal(saved.plaintext,false);
    await cdp.send('Fetch.disable',{},alice.sessionId);cdp.listeners.delete(intercept);
    await fill(alice,'password',passwords.alice);await click(alice,'#auth-submit');await dashboard(alice,names.alice);const resumed=await account(alice,names.alice);assert(resumed.devices.some(d=>d.public_key===saved.binding.publicKey));
    return {forcedNetworkFailure:true,lockedAfterFailure:true,sameEncryptedDeviceResumed:true,accountId:resumed.id};
  });
  report.status='PASS_REAL_BROWSER_LOCAL_TESTS';
} catch (error) { report.status = 'FAIL_REAL_BROWSER_LOCAL_TESTS'; report.issues.push({ step: currentStep, message: error.message }); console.error('FAIL ' + currentStep + ': ' + error.message); if (cdp) await takeFailureScreenshot(); process.exitCode = 1; }
finally { report.finishedAt = new Date().toISOString(); report.claimLimit = 'Real headless Chrome on one local devnet. Not an independent audit, hardware-custody guarantee, WAN benchmark or production scalability proof.'; await shutdown(); await writeFile(out, JSON.stringify(report, null, 2)); console.log('Report ' + out); }
