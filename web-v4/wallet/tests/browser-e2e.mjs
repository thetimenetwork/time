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
const out = path.resolve(argument('--out', path.join(production, 'results-v4/wallet-browser.json')));
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
  const alice = await pageAt(url), bob = await pageAt(url);
  await step('create Alice through real browser WebCrypto, Argon2 and finalized commit/reveal', async () => { await create(alice, 'alice'); const a = await account(alice, names.alice); assert.equal(a.balance, '0'); return { accountId: a.id, name: a.name, balance: a.balance }; });
  await step('create Bob with independent random device key', async () => { await create(bob, 'bob'); const a = await account(bob, names.bob); assert.equal(a.balance, '0'); return { accountId: a.id, name: a.name }; });
  await step('encrypted browser storage contains no plaintext password or PKCS8', async () => {
    const result = await evaluate(alice, `(() => { const values=Object.values(localStorage); return {count:values.length,hasPassword:values.some(v=>v.includes(${JSON.stringify(passwords.alice)})||v.includes(${JSON.stringify(passwords.bob)})),hasRawKeyField:values.some(v=>v.includes('"pkcs8"')),vaults:Object.keys(localStorage).filter(k=>k.startsWith('timecurrency.vault.v1:')).map(k=>{const v=JSON.parse(localStorage[k]);return {version:v.version,algorithm:v.kdf.algorithm,memoryKiB:v.kdf.memoryKiB,hasCiphertext:typeof v.ciphertext==='string'};})}; })()`);
    assert.equal(result.hasPassword, false); assert.equal(result.hasRawKeyField, false); assert.equal(result.vaults.length, 2); assert.ok(result.vaults.every(v => v.algorithm === 'argon2id' && v.memoryKiB === 65536 && v.hasCiphertext)); return result;
  });
  await step('earn through actual Bitcoin regtest header relay, account-bound receipt and lazy claim',async()=>{
    await click(alice,'[data-panel="earn"]');await click(alice,'#bid-form button[type=submit]');await confirmReview(alice);
    await wait(alice,`document.querySelector('#notice').textContent.includes('Regtest BTC receipt finalized')`,180000);
    await wait(alice,`document.querySelector('#earning-claims button')&&!document.querySelector('#earning-claims button').disabled`,120000);
    await click(alice,'#earning-claims button');await confirmReview(alice);await wait(alice,`document.querySelector('#notice').textContent.includes('Earned seconds claimed and verified')`,90000);
    let earned;for(let i=0;i<60;i++){earned=await account(alice,names.alice);if(BigInt(earned.balance)>=1000000n)break;await delay(500);}assert(BigInt(earned.balance)>=1000000n);return {balanceMicros:earned.balance,bitcoinNetwork:'regtest',realCoreTransaction:true,claimed:true};
  });
  await step('send 0.1 seconds to Bob and verify receipt plus destination balance', async () => {
    await click(alice, '[data-panel="send"]'); await fill(alice, 'recipient', names.bob); await fill(alice, 'amount', '0.1'); await click(alice, '#send-submit');
    await wait(alice, `document.querySelector('#review-dialog').open && document.querySelector('#review-title').textContent==='Send test seconds'`);
    const review = await evaluate(alice, `document.querySelector('#review-body').innerText`); assert(review.includes('0.101 seconds')); await confirmReview(alice);
    await wait(alice, `document.querySelector('#notice').textContent.includes('needs to do nothing')`, 90000);
    const recipient = await account(bob, names.bob); assert.equal(recipient.balance, '100000'); await click(bob, '#refresh');
    return { recipientId: recipient.id, recipientBalanceMicros: recipient.balance, receiptStatus: 'independently verified inclusion' };
  });
  await step('stake test seconds and observe pool reward value growth', async () => {
    await click(alice, '[data-panel="earn"]'); await fill(alice, 'stake-amount', '0.2'); await click(alice, '#stake-form button[type=submit]'); await confirmReview(alice);
    await wait(alice, `document.querySelector('#notice').textContent.includes('Delegation finalized')`);
    const first = await evaluate(alice, `document.querySelector('#bonded').textContent`); await delay(4000); await click(alice, '#refresh');
    await wait(alice, `document.querySelector('#notice').textContent.includes('balance was checked again')`);
    const after = await evaluate(alice, `document.querySelector('#bonded').textContent`);
    const toMicros = value => { const [whole, fraction = ''] = value.split(' s')[0].split('.'); return BigInt(whole) * 1000000n + BigInt(fraction.padEnd(6, '0')); };
    assert.ok(toMicros(after) > toMicros(first), 'Bonded value did not grow after eligible validator rewards'); return { before: first, after };
  });
  await step('lock, reject wrong password and unlock correct local vault', async () => {
    await click(alice, '#lock-button'); await fill(alice, 'username', names.alice); await fill(alice, 'password', 'a deliberately incorrect unique password'); await click(alice, '#auth-submit');
    await wait(alice, `document.querySelector('#notice').textContent.includes('Could not unlock')`); assert.equal(await evaluate(alice, `document.querySelector('#dashboard').hidden`), true);
    await fill(alice, 'password', passwords.alice); await click(alice, '#auth-submit'); await dashboard(alice, names.alice);
  });
  await step('approve a new independent device without copying a private key, then revoke it', async () => {
    const { browserContextId } = await cdp.send('Target.createBrowserContext'); const devicePage = await pageAt(url, browserContextId);
    const devicePassword = 'mossy river ' + randomBytes(20).toString('base64url');
    await wait(devicePage, `!document.querySelector('#auth-submit').disabled`); await click(devicePage, '#mode-link'); await fill(devicePage, 'username', names.alice); await fill(devicePage, 'password', devicePassword); await fill(devicePage, 'password-confirm', devicePassword); await click(devicePage, '#auth-submit');
    await wait(devicePage, `!document.querySelector('#enrollment-panel').hidden && document.querySelector('#enrollment-code').value.length>100`);
    const request = await evaluate(devicePage, `document.querySelector('#enrollment-code').value`); const publicRequest = JSON.parse(request); assert.equal(publicRequest.networkId.length, 64); assert.ok(!request.includes('pkcs8')); assert.ok(!request.includes(devicePassword));
    await click(alice, '[data-panel="devices"]'); await fill(alice, 'device-request', request); await click(alice, '#approve-device-form button[type=submit]'); await confirmReview(alice);
    await wait(alice, `document.querySelector('#notice').textContent.includes('The new browser is approved')`); await dashboard(devicePage, names.alice);
    assert.equal((await account(alice, names.alice)).devices.length, 2);
    const revokedBackup=withBackup?await exportBackupFile(devicePage,devicePassword):null;
    await evaluate(alice, `(() => { const row=[...document.querySelectorAll('#device-list .row')].find(e=>e.textContent.includes(${JSON.stringify(publicRequest.publicKey)})); if(!row)throw Error('Device row missing');row.querySelector('button').click(); })()`); await confirmReview(alice);
    await wait(alice, `document.querySelector('#notice').textContent.includes('The browser was removed from the account')`); assert.equal((await account(alice, names.alice)).devices.length, 1);
    await wait(devicePage, `!document.querySelector('#enrollment-panel').hidden && document.querySelector('#dashboard').hidden`, 20000);
    if(revokedBackup){
      const deniedContext=await cdp.send('Target.createBrowserContext'),denied=await pageAt(url,deniedContext.browserContextId);
      await restoreBackupFile(denied,revokedBackup.filename,devicePassword,'Backup device is no longer approved');
      assert.equal(await evaluate(denied,`Object.keys(localStorage).filter(k=>k.startsWith('timecurrency.vault.v1:')).length`),0);
      await cdp.send('Target.disposeBrowserContext',{browserContextId:deniedContext.browserContextId});
    }
    await cdp.send('Target.disposeBrowserContext', { browserContextId }); return { newPublicKey: publicRequest.publicKey, approvedAndRevoked: true };
  });
  if(withBackup)await step('encrypted backup downloads and restores the same key after browser data loss without overwriting',async()=>{
    portableBackup=await exportBackupFile(alice,passwords.alice);
    const before=await account(alice,names.alice),context=await cdp.send('Target.createBrowserContext'),restored=await pageAt(url,context.browserContextId);
    assert.equal(await evaluate(restored,`Object.keys(localStorage).filter(k=>k.startsWith('timecurrency.vault.v1:')).length`),0);
    await restoreBackupFile(restored,portableBackup.filename,passwords.alice+'wrong','Could not unlock');
    assert.equal(await evaluate(restored,`Object.keys(localStorage).filter(k=>k.startsWith('timecurrency.vault.v1:')).length`),0);
    await restoreBackupFile(restored,portableBackup.filename,passwords.alice);await unlockAlicePopup(restored);
    const after=await account(restored,names.alice);assert.equal(after.id,before.id);assert.equal(after.nonce,before.nonce);assert.deepEqual(after.devices,before.devices);
    await click(restored,'#lock-button');await restoreBackupFile(restored,portableBackup.filename,passwords.alice,'Import never overwrites');
    const saved=await evaluate(restored,`JSON.parse(localStorage.getItem('timecurrency.vault.v1:'+${JSON.stringify(portableBackup.binding.networkId)}+':'+${JSON.stringify(names.alice)})).binding.publicKey`);
    assert.equal(saved,portableBackup.binding.publicKey);await cdp.send('Target.disposeBrowserContext',{browserContextId:context.browserContextId});
    return {encryptedBytes:Buffer.byteLength(portableBackup.text),sameDeviceKey:true,wrongPasswordAndOverwriteRejected:true,revokedDeviceBackupRejected:true};
  });
  await step('separate-origin app login and order-bound payment work through real wallet popups', async () => {
    const metadata = await evaluate(alice, `TimeSDK.createClient({trust:window.__testTrust}).getNetwork()`); const merchant = await pageAt(metadata.merchantOrigin);
    await click(merchant, '#login'); let popup = await popupFrom(merchant); await unlockAlicePopup(popup);
    const origin = await evaluate(popup, `document.querySelector('#approval-origin').textContent`); assert.equal(origin, metadata.merchantOrigin);
    await click(popup, '#approve-request'); await confirmReview(popup);
    await wait(merchant, `document.querySelector('#greeting').textContent.includes(${JSON.stringify('@' + names.alice)})`, 90000); await cdp.send('Target.closeTarget', { targetId: popup.targetId });
    await click(merchant, '#pay'); popup = await popupFrom(merchant); await unlockAlicePopup(popup);
    await click(popup, '#approve-request'); await confirmReview(popup);
    await wait(merchant, `document.querySelector('#order-result').textContent.includes('Order fulfilled')`, 90000);
    const result = await evaluate(merchant, `document.querySelector('#order-result').textContent`); assert.ok(/Transaction [A-F0-9]{64}/.test(result));
    const hash = result.match(/Transaction ([A-F0-9]{64})/)[1];
    const receipt = await evaluate(alice, `TimeSDK.createClient({trust:window.__testTrust}).waitReceipt(${JSON.stringify(hash)})`); assert.equal(receipt.action.kind, 10); assert.equal(receipt.action.payload.reference.length, 64); assert.equal(receipt.verified, true);
    await screenshot(merchant, 'merchant-login-payment'); await cdp.send('Target.closeTarget', { targetId: popup.targetId });
    // Reload discards in-memory state; the persistent marker must still reject the same order in a new popup.
    await cdp.send('Page.reload', {}, alice.sessionId); await wait(alice, `document.readyState==='complete' && !document.querySelector('#auth-submit').disabled`); await unlockAlicePopup(alice);
    const beforeDuplicate = await account(alice, names.alice);
    const duplicateRequest = { type: 'payment', networkId: receipt.action.networkId, to: receipt.action.payload.to, amount: receipt.action.payload.amount, orderId: receipt.action.payload.reference };
    await evaluate(merchant, `(() => {window.__duplicatePayment=TimeSDK.requestWallet({walletOrigin:${JSON.stringify(metadata.walletOrigin)},request:${JSON.stringify(duplicateRequest)}}).then(()=>true,()=>false);return 'opened';})()`);
    const duplicatePopup = await popupFrom(merchant); await unlockAlicePopup(duplicatePopup); await click(duplicatePopup, '#approve-request');
    if(metadata.protocolVersion==='4')await wait(duplicatePopup,`document.querySelector('#notice').textContent.includes('reserved another nonce')`);
    else{await confirmReview(duplicatePopup);await wait(duplicatePopup, `document.querySelector('#notice').textContent.includes('already has a signed payment record')`);}
    const afterDuplicate = await account(alice, names.alice); assert.equal(afterDuplicate.nonce, beforeDuplicate.nonce); assert.equal(afterDuplicate.balance, beforeDuplicate.balance);
    await click(duplicatePopup, '#deny-request'); await cdp.send('Target.closeTarget', { targetId: duplicatePopup.targetId });
    if(withBackup&&metadata.protocolVersion==='4'){
      const context=await cdp.send('Target.createBrowserContext'),restored=await pageAt(url,context.browserContextId);
      await restoreBackupFile(restored,portableBackup.filename,passwords.alice);await unlockAlicePopup(restored);
      const anotherMerchant=await pageAt(metadata.merchantOrigin,context.browserContextId);
      await evaluate(anotherMerchant,`(() => {window.__duplicatePayment=TimeSDK.requestWallet({walletOrigin:${JSON.stringify(metadata.walletOrigin)},request:${JSON.stringify(duplicateRequest)}}).then(()=>true,()=>false);return 'opened';})()`);
      const popup=await popupFrom(anotherMerchant);await unlockAlicePopup(popup);await click(popup,'#approve-request');
      await wait(popup,`document.querySelector('#notice').textContent.includes('reserved another nonce')`);
      const after=await account(restored,names.alice);assert.equal(after.nonce,beforeDuplicate.nonce);assert.equal(after.balance,beforeDuplicate.balance);
      await click(popup,'#deny-request');await cdp.send('Target.disposeBrowserContext',{browserContextId:context.browserContextId});
    }
    return { loginOrigin: metadata.merchantOrigin, paymentHash: hash, actionKind: receipt.action.kind, orderReference: receipt.action.payload.reference, duplicateOrderAfterReloadRejectedWithoutNewNonceOrDebit: true };
  });
  if(withBackup)await step('wallet downloads independently verified public receipt evidence without weakening historical trust',async()=>{
    await click(alice,'[data-panel="activity"]');await cdp.send('Browser.setDownloadBehavior',{behavior:'allow',downloadPath:downloadDirectory,eventsEnabled:true});
    const began=cdp.events.length;await evaluate(alice,`[...document.querySelectorAll('#activity-list button')].find(b=>b.textContent==='Save public receipt').click()`);
    await wait(alice,`document.querySelector('#notice').textContent.includes('Public receipt evidence downloaded')`);
    const event=cdp.events.slice(began).find(e=>e.method==='Browser.downloadWillBegin'&&e.params.suggestedFilename.startsWith('seconds-receipt-'));assert(event,'Public receipt download missing');
    let evidence;for(let i=0;i<100;i++){try{evidence=JSON.parse(await readFile(path.join(downloadDirectory,event.params.suggestedFilename),'utf8'));break;}catch{await delay(100);}}
    assert.equal(evidence.format,'timecurrency-public-receipt');assert.ok(BigInt(evidence.proof.signed_header.header.version.app)>=BigInt(evidence.trust.app_version),'the header carries the version in force, which is at least the first version the trust anchor names');
    assert.ok(!JSON.stringify(evidence).includes(passwords.alice));assert.ok(!JSON.stringify(evidence).includes('pkcs8'));
    return {format:evidence.format,transactionHash:evidence.proof.tx.hash,currentAnchorTrustDays:7,canonicalHistoryAnchored:true};
  });
  await step('recover from an actually rejected stake using certified nonce cancellation without moving funds', async () => {
    const rejected = await evaluate(alice, `(async()=>{const mod=await import('/vault.mjs');const client=TimeSDK.createClient({trust:window.__testTrust});const s=await client.getVerifiedState({names:${JSON.stringify(proofNames)},include_pos:true});const a=s.state.accounts.find(a=>a.name===${JSON.stringify(names.alice)});const record=JSON.parse(localStorage.getItem('timecurrency.vault.v1:'+s.state.network_id+':'+a.name));const unlocked=await mod.openVault(record,${JSON.stringify(passwords.alice)},hashwasm.argon2id);const nonce=(BigInt(a.nonce)+1n).toString();const tx=await TimeSDK.signAction({networkId:s.state.network_id,kind:'delegate',from:a.id,nonce,authEpoch:a.auth_epoch,publicKey:record.binding.publicKey,payload:{operator:String(s.state.pos.active[0].owner),amount:'100000',min_shares:'18446744073709551615'}},unlocked.privateKey);mod.forgetSecret(unlocked.secret);const hash=await TimeSDK.transactionHash(tx);localStorage.setItem('timecurrency.pending.v1:'+s.state.network_id+':'+a.id,JSON.stringify({hash,tx:TimeSDK.base64(tx),nonce,authEpoch:a.auth_epoch,kind:'delegate',label:'Rejected staking quote for cancellation regression',at:Date.now()}));let error;try{await client.submit(tx,{wait:false});throw Error('Malformed share guard unexpectedly accepted');}catch(e){error=e.message;}if(!/slippage/i.test(error))throw Error(error);return {hash,balance:a.balance,nonce:a.nonce,authEpoch:a.auth_epoch,devices:a.devices};})()`);
    const beforeCancel = await account(alice, names.alice); assert.equal(beforeCancel.balance, rejected.balance); assert.equal(beforeCancel.nonce, rejected.nonce);
    await click(alice, '#refresh'); await wait(alice, `document.querySelector('#notice').textContent.includes('balance was checked again')`); await click(alice, '[data-panel="activity"]');
    await evaluate(alice, `(() => {const b=[...document.querySelectorAll('#pending-panel button')].find(b=>b.textContent==='Cancel pending action');if(!b)throw Error('Cancellation control missing');b.click();})()`); await wait(alice, `document.querySelector('#review-dialog').open`);
    assert.ok((await evaluate(alice, `document.querySelector('#review-body').textContent`)).includes('old action may win')); await confirmReview(alice);
    await wait(alice, `document.querySelector('#notice').textContent.includes('Cancellation finalized and verified')`);
    const afterCancel = await account(alice, names.alice); assert.equal(afterCancel.balance, rejected.balance); assert.equal(BigInt(afterCancel.nonce), BigInt(rejected.nonce) + 1n); assert.equal(BigInt(afterCancel.auth_epoch), BigInt(rejected.authEpoch) + 1n); assert.deepEqual(afterCancel.devices, rejected.devices);
    return { rejectedHash: rejected.hash, liquidBefore: rejected.balance, liquidAfter: afterCancel.balance, oldAuthorityEpoch: rejected.authEpoch, newAuthorityEpoch: afterCancel.auth_epoch, devicesPreserved: true };
  });
  await step('unbond actual PoS shares and refuse early withdrawal during the real 14-day exposure window',async()=>{
    await click(alice,'[data-panel="earn"]');await click(alice,'#refresh');await wait(alice,`document.querySelector('#notice').textContent.includes('balance was checked again')`);
    await click(alice,'#delegations button');await confirmReview(alice);await wait(alice,`document.querySelector('#notice').textContent.includes('Unbond delegation finalized')`,90000);
    const exit=await evaluate(alice,`(async()=>{const c=TimeSDK.createClient({trust:window.__testTrust});const a=await c.account(${JSON.stringify(names.alice)});const v=await c.getVerifiedState({owners:[a.id]});return v.state.stake_owners[a.id].exits[0];})()`);assert(exit&&BigInt(exit.release_height)===BigInt(exit.requested_height)+2n);
    assert.equal(await evaluate(alice,`document.querySelector('#unbonding button')===null`),true);return {entry:exit.id,releaseHeight:exit.release_height,withdrawalDelaySeconds:1209600,earlyWithdrawalUnavailable:true};
  });
  let finalWallet = alice;
  if (process.argv.includes('--recovery')) await step('guardian opt-in, minority safety, frozen login/spending, failed emergency cancel persistence and complete key replacement', async () => {
    const carol = await pageAt(url); await create(carol, 'carol');
    await click(alice, '[data-panel="send"]'); await fill(alice, 'recipient', names.carol); await fill(alice, 'amount', '0.1'); await click(alice, '#send-submit'); await confirmReview(alice); await wait(alice, `document.querySelector('#notice').textContent.includes('needs to do nothing')`);
    await click(alice, '[data-panel="recovery"]'); await fill(alice, 'recovery-guardians', names.bob + ', ' + names.carol); await fill(alice, 'recovery-threshold', '2'); await click(alice, '#recovery-policy-form button[type=submit]'); await confirmReview(alice); await wait(alice, `document.querySelector('#notice').textContent.includes('Recovery policy finalized')`);
    for (const guardian of [bob, carol]) {
      await click(guardian, '#refresh'); await wait(guardian, `document.querySelector('#notice').textContent.includes('balance was checked again')`); await click(guardian, '[data-panel="recovery"]');
      await fill(guardian, 'guardian-target-name', names.alice); await click(guardian, '#guardian-target-check');
      await wait(guardian, `!![...document.querySelectorAll('#recovery-consent-list .row')].find(e=>e.textContent.includes(${JSON.stringify('@' + names.alice)}))`);
      await delay(6000);await wait(guardian, `!![...document.querySelectorAll('#recovery-consent-list .row')].find(e=>e.textContent.includes(${JSON.stringify('@' + names.alice)}))`);
      await evaluate(guardian, `(() => { const r=[...document.querySelectorAll('#recovery-consent-list .row')].find(e=>e.textContent.includes(${JSON.stringify('@' + names.alice)})); if(!r)throw Error('Nomination missing');r.querySelector('button').click();})()`); await confirmReview(guardian); await wait(guardian, `document.querySelector('#notice').textContent.includes('Guardian consent choice finalized')`);
    }
    const { browserContextId } = await cdp.send('Target.createBrowserContext'); const recovering = await pageAt(url, browserContextId), recoveryPassword = 'blooming forest ' + randomBytes(20).toString('base64url');
    await wait(recovering, `!document.querySelector('#auth-submit').disabled`); await click(recovering, '#mode-recover'); await fill(recovering, 'username', names.alice); await fill(recovering, 'password', recoveryPassword); await fill(recovering, 'password-confirm', recoveryPassword); await click(recovering, '#auth-submit');
    await wait(recovering, `!document.querySelector('#recovery-claim-panel').hidden && document.querySelector('#recovery-claim-code').value.length>100`);
    let claim = JSON.parse(await evaluate(recovering, `document.querySelector('#recovery-claim-code').value`));
    async function guardianApprove(page, currentClaim) { await fill(page, 'recovery-request', JSON.stringify(currentClaim)); await click(page, '#recovery-approve-form button[type=submit]'); await confirmReview(page); await wait(page, `document.querySelector('#notice').textContent.includes('Guardian approval finalized')`); }
    await guardianApprove(bob, claim);
    const minority = await evaluate(alice, `(async()=>{const v=await TimeSDK.createClient({trust:window.__testTrust}).getVerifiedState({names:${JSON.stringify(proofNames)}});return v.state.recovery_cases.find(r=>r.recovery_id===${JSON.stringify(claim.recovery_id)});})()`); assert.equal(minority.approvals.length, 1); assert.equal(minority.ready_elapsed_micros, null);
    // Sign and durably reserve a real transfer but deliberately never broadcast it. This is the crash-before-submit scenario.
    const paused = await evaluate(alice, `(async()=>{const mod=await import('/vault.mjs');const s=await TimeSDK.createClient({trust:window.__testTrust}).getVerifiedState({names:${JSON.stringify(proofNames)}});const a=s.state.accounts.find(a=>a.name===${JSON.stringify(names.alice)});const b=s.state.accounts.find(a=>a.name===${JSON.stringify(names.bob)});const record=JSON.parse(localStorage.getItem('timecurrency.vault.v1:'+s.state.network_id+':'+a.name));const unlocked=await mod.openVault(record,${JSON.stringify(passwords.alice)},hashwasm.argon2id);const nonce=(BigInt(a.nonce)+1n).toString();const tx=await TimeSDK.signAction({networkId:s.state.network_id,kind:'transfer',from:a.id,nonce,authEpoch:a.auth_epoch,publicKey:record.binding.publicKey,payload:{to:b.id,amount:'1'}},unlocked.privateKey);mod.forgetSecret(unlocked.secret);const hash=await TimeSDK.transactionHash(tx);localStorage.setItem('timecurrency.pending.v1:'+s.state.network_id+':'+a.id,JSON.stringify({hash,tx:TimeSDK.base64(tx),nonce,authEpoch:a.auth_epoch,kind:'transfer',label:'Paused test transfer: never broadcast',at:Date.now()}));return {hash,accountId:a.id,networkId:s.state.network_id,authEpoch:a.auth_epoch};})()`);
    await guardianApprove(carol, claim); await click(alice, '#refresh'); await wait(alice, `document.querySelector('#notice').textContent.includes('balance was checked again')`);
    assert.equal(await evaluate(alice, `document.querySelector('#send-submit').disabled`), true);
    const recoveryMetadata = await evaluate(alice, `TimeSDK.createClient({trust:window.__testTrust}).getNetwork()`), frozenMerchant = await pageAt(recoveryMetadata.merchantOrigin);
    await click(frozenMerchant, '#login'); const frozenPopup = await popupFrom(frozenMerchant); await unlockAlicePopup(frozenPopup); assert.equal(await evaluate(frozenPopup, `document.querySelector('#approve-request').disabled`), true); await click(frozenPopup, '#deny-request'); await cdp.send('Target.closeTarget', { targetId: frozenPopup.targetId });
    let failedRequests = 0;
    const interceptor = event => { if (event.sessionId === alice.sessionId && event.method === 'Fetch.requestPaused') { failedRequests++; return cdp.send('Fetch.failRequest', { requestId: event.params.requestId, errorReason: 'TimedOut' }, alice.sessionId); } };
    cdp.listeners.add(interceptor); await cdp.send('Fetch.enable', { patterns: [{ urlPattern: url + '/api/submit', requestStage: 'Request' }] }, alice.sessionId);
    await evaluate(alice, `document.querySelector('#recovery-owner-cases button').click()`); await confirmReview(alice);
    await wait(alice, `/fetch/i.test(document.querySelector('#notice').textContent) && document.querySelector('#notice').classList.contains('error')`);
    await cdp.send('Fetch.disable', {}, alice.sessionId); cdp.listeners.delete(interceptor); assert.equal(failedRequests, 1);
    const retained = await evaluate(alice, `({transfer:!!localStorage.getItem('timecurrency.pending.v1:'+${JSON.stringify(paused.networkId)}+':'+${JSON.stringify(paused.accountId)}),cancel:!!localStorage.getItem('timecurrency.pending.v1:'+${JSON.stringify(paused.networkId)}+':emergency-cancel-'+${JSON.stringify(paused.accountId)})})`); assert.deepEqual(retained, { transfer: true, cancel: true });
    await evaluate(alice, `document.querySelector('#recovery-owner-cases button').click()`); await confirmReview(alice); await wait(alice, `document.querySelector('#notice').textContent.includes('Pending recovery canceled')`);
    const afterCancel = await account(alice, names.alice); assert.ok(BigInt(afterCancel.auth_epoch) > BigInt(paused.authEpoch));
    const cleared = await evaluate(alice, `({transfer:!!localStorage.getItem('timecurrency.pending.v1:'+${JSON.stringify(paused.networkId)}+':'+${JSON.stringify(paused.accountId)}),cancel:!!localStorage.getItem('timecurrency.pending.v1:'+${JSON.stringify(paused.networkId)}+':emergency-cancel-'+${JSON.stringify(paused.accountId)})})`); assert.deepEqual(cleared, { transfer: false, cancel: false });
    await click(recovering, '#check-recovery-claim'); await wait(recovering, `JSON.parse(document.querySelector('#recovery-claim-code').value).auth_epoch===${JSON.stringify(afterCancel.auth_epoch)}`);
    claim = JSON.parse(await evaluate(recovering, `document.querySelector('#recovery-claim-code').value`)); await guardianApprove(bob, claim); await guardianApprove(carol, claim);
    await wait(recovering, `!document.querySelector('#finalize-recovery').disabled`, 100000); await click(recovering, '#finalize-recovery'); await confirmReview(recovering); await dashboard(recovering, names.alice);
    const recovered = await account(recovering, names.alice); assert.equal(recovered.devices.length, 1); assert.equal(recovered.devices[0].public_key, claim.new_public_key);
    await wait(alice, `document.querySelector('#dashboard').hidden && !document.querySelector('#enrollment-panel').hidden`, 30000);
    await screenshot(recovering, 'recovered-wallet'); finalWallet = recovering;
    return { targetAccount: recovered.id, guardianThreshold: '2 of 2', fullTestDelaySeconds: 30, oldPausedTransferHash: paused.hash, timeoutPreservedBothReservations: true, authorityAfterCancel: afterCancel.auth_epoch, authorityAfterRecovery: recovered.auth_epoch, newPublicKey: claim.new_public_key };
  });
  await step('desktop wallet renders with no document overflow', async () => { const value = await evaluate(finalWallet, `({width:innerWidth,documentWidth:document.documentElement.scrollWidth})`); assert.ok(value.documentWidth <= value.width); await screenshot(finalWallet, 'desktop-wallet'); return value; });
  await step('mobile 390px wallet renders with no document overflow', async () => {
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true }, finalWallet.sessionId);
    const value = await evaluate(finalWallet, `({width:innerWidth,documentWidth:document.documentElement.scrollWidth})`); assert.ok(value.documentWidth <= value.width); await screenshot(finalWallet, 'mobile-wallet'); return value;
  });
  report.status = 'PASS_REAL_BROWSER_LOCAL_TESTS';
} catch (error) { report.status = 'FAIL_REAL_BROWSER_LOCAL_TESTS'; report.issues.push({ step: currentStep, message: error.message }); console.error('FAIL ' + currentStep + ': ' + error.message); if (cdp) await takeFailureScreenshot(); process.exitCode = 1; }
finally { report.finishedAt = new Date().toISOString(); report.claimLimit = 'Real headless Chrome on one local devnet. Not an independent audit, hardware-custody guarantee, WAN benchmark or production scalability proof.'; await shutdown(); await writeFile(out, JSON.stringify(report, null, 2)); console.log('Report ' + out); }
