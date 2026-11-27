// node web-v4/manager/tests/browser-smoke.mjs [chrome executable]
// A local wallet opener exercises the real manager's UI, IndexedDB, CSP, WASM and
// WebAuthn PRF with Chromium's virtual platform authenticator. No network or chain.
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createBrowser, launchChrome } from '../../../campaign/lib/browser-check.mjs';
import { AUTHENTICATORS } from '../../../campaign/lib/browser-device-check.mjs';
import { startLocalVault } from '../../../client-v4/vault-host.mjs';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const executable = process.argv[2] || (process.platform === 'win32' ? 'C:/Program Files/Google/Chrome/Application/chrome.exe' : '/usr/bin/google-chrome');
const temp = await mkdtemp(path.join(tmpdir(), 'time-vault-browser-'));
const walletHost = 'http://localhost:8780', vaultHost = 'http://localhost:8786';
const name = 'smokeuser', networkId = 'fa'.repeat(32);
const manualPassphrase = 'Canoes arrive beside lavender orchards';
const secrets = { signin: 'kerine-netoji-nesimo-vebine', spend: 'dabofi-gihaba-keleri-mibosi', recover: 'kerine netoji nesimo vebine kedafi' };
const template = { type: 'time:vault-request', v: 1, name, networkId };
const wallet = http.createServer((_req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<title>Local wallet fixture</title><script>window.events=[];window.addEventListener("message",e=>{if(e.origin==='
    + JSON.stringify(vaultHost) + ' && e.source===window.vault)events.push(e.data)})</script>');
});
let server, chrome;
try {
  await new Promise((resolve, reject) => { wallet.once('error', reject); wallet.listen(8780, '127.0.0.1', resolve); });
  server = await startLocalVault(root);
  chrome = await launchChrome({ chrome: executable, profile: temp });
  const browser = createBrowser({ cdp: chrome.cdp });
  // A timeout's usual page excerpt could include the revealed master or recovery words.
  browser.seen = async () => 'Vault page text omitted.';
  const page = await browser.open(walletHost);
  await browser.ask(page, '(window.vault=window.open(' + JSON.stringify(vaultHost) + '),true)');
  const vault = await browser.opened(page, vaultHost);
  await chrome.cdp.send('WebAuthn.enable', {}, vault.sessionId);
  const unsupported = await chrome.cdp.send('WebAuthn.addVirtualAuthenticator', { options: AUTHENTICATORS.withoutPrf }, vault.sessionId);
  const waitFor = (p, condition, what) => browser.until(p, condition, what, 16000);
  async function send(body, reload = true) {
    if (reload) {
      await browser.ask(page, '(window.events=[],true)');
      await browser.go(vault, vaultHost);
    }
    await waitFor(page, 'events.some(e=>e.type==="time:vault-ready")', 'vault handshake');
    const request = { ...template, id: crypto.randomUUID(), ...body };
    await browser.ask(page, '(vault.postMessage(' + JSON.stringify(request) + ',' + JSON.stringify(vaultHost) + '),true)');
    await waitFor(vault, '!document.querySelector("#unlock").hidden', 'master password prompt');
    return request.id;
  }
  async function answer(id) {
    await waitFor(page, 'events.some(e=>e.id===' + JSON.stringify(id) + ')', 'purpose-bound result');
    return browser.ask(page, 'events.find(e=>e.id===' + JSON.stringify(id) + ')');
  }
  async function approve(pw) {
    await browser.fill(vault, 'master', pw);
    await browser.click(vault, '#approve', 4000);
  }
  const previewCleared = `document.querySelector("#generated-value").textContent === "" &&
    !document.querySelector("#generated-value").getClientRects().length`;
  const previewMatches = `document.querySelector("#generated-value").getClientRects().length > 0 &&
    document.querySelector("#master").type === "password" && document.querySelector("#master").value.length > 0 &&
    document.querySelector("#generated-value").textContent === document.querySelector("#master").value`;
  const generatorHidden = `document.querySelector("#generator-controls").hidden &&
    !document.querySelector("#generate-master").getClientRects().length`;
  let id = await send({ operation: 'save', secrets }, false);
  await approve(manualPassphrase);
  await waitFor(vault, 'document.querySelector("#status").textContent.includes("Set up manually")', 'unsupported screen lock offers manual setup');
  assert.ok(!(await browser.text(vault, '#status')).includes('PRF'));
  await chrome.cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: unsupported.authenticatorId }, vault.sessionId);
  await chrome.cdp.send('WebAuthn.addVirtualAuthenticator', { options: AUTHENTICATORS.withPrf }, vault.sessionId);
  await approve('orchards orchards violet meadow');
  await waitFor(vault, 'document.querySelector("#status").textContent.includes("same word twice")', 'weak manual passphrase rejected');
  await browser.click(vault, '#generate-master');
  assert.ok(await browser.ask(vault, previewMatches), 'generation fills the masked input and readable preview');
  assert.ok(await browser.ask(vault, '!document.querySelector("#status").textContent.includes("same word twice")'), 'generation clears the old validation error');
  await browser.click(vault, '#toggle-generated');
  assert.ok(await browser.ask(vault, previewCleared), 'hiding clears the readable preview');
  await browser.click(vault, '#toggle-generated');
  assert.ok(await browser.ask(vault, previewMatches), 'showing restores the selected passphrase');
  await browser.fill(vault, 'master', manualPassphrase);
  assert.ok(await browser.ask(vault, previewCleared), 'typing a custom passphrase clears the preview');
  await browser.click(vault, '#generate-master');
  await browser.click(vault, '#cancel');
  const cancelled = await answer(id);
  assert.equal(cancelled.unsaved, true); assert.equal(cancelled.reason, 'cancelled');
  assert.ok(await browser.ask(vault, previewCleared + ' && document.querySelector("#master").value === ""'), 'cancel clears the generated passphrase');
  assert.ok(await browser.ask(vault, generatorHidden), 'cancel hides the generator');

  id = await send({ operation: 'save', secrets });
  await approve(manualPassphrase);
  await waitFor(vault, '!document.querySelector("#paper").hidden', 'offline recovery copy');
  assert.ok((await browser.text(vault, '#words')) === secrets.recover, 'the offline copy shows the recovery words');
  const savedAccounts = '(await (await import("/store.mjs")).openDatabase()).accounts()';
  assert.deepEqual(await browser.ask(vault, savedAccounts), []);
  await browser.click(vault, '#cancel');
  assert.equal((await answer(id)).unsaved, true);
  assert.deepEqual(await browser.ask(vault, savedAccounts), []);

  id = await send({ operation: 'save', secrets });
  const networkConditions = { latency: 0, downloadThroughput: -1, uploadThroughput: -1 };
  await chrome.cdp.send('Network.emulateNetworkConditions', { ...networkConditions, offline: true }, vault.sessionId);
  let passphrase;
  try {
    const checked = await browser.ask(vault, `(async () => {
      const { checkPassword } = await import('/wallet-lib/vault.mjs');
      const button = document.querySelector('#generate-master');
      const master = document.querySelector('#master');
      const seen = new Set();
      for (let i = 0; i < 100; i++) {
        button.click();
        const value = master.value;
        if (!/^[a-z]{6}( [a-z]{6}){7}$/.test(value) || !(${previewMatches})) return false;
        try { checkPassword(value, ${JSON.stringify(name)}); } catch { return false; }
        seen.add(value);
      }
      return !navigator.onLine && seen.size === 100;
    })()`);
    assert.ok(checked, '100 consecutive offline clicks give distinct, valid passphrases and refresh the preview');
    passphrase = await browser.ask(vault, 'document.querySelector("#master").value');
  } finally {
    await chrome.cdp.send('Network.emulateNetworkConditions', { ...networkConditions, offline: false }, vault.sessionId);
  }
  await browser.click(vault, '#approve', 4000);
  assert.ok(await browser.ask(vault, previewCleared), 'approval clears the preview before device enrollment completes');
  await waitFor(vault, '!document.querySelector("#paper").hidden', 'second enrollment reaches backup');
  await browser.click(vault, '#saved');
  assert.equal((await answer(id)).ok, true);
  const stored = await browser.ask(vault, '(async()=>{const d=await(await import("/store.mjs")).openDatabase();return JSON.stringify([await d.profile(),await d.account(' + JSON.stringify(networkId) + ',' + JSON.stringify(name) + ')])})()');
  for (const secret of [passphrase, ...Object.values(secrets)]) assert.ok(!stored.includes(secret));

  id = await send({ operation: 'save', name: 'smokeother', secrets });
  assert.ok(await browser.ask(vault, generatorHidden), 'saving another account uses the existing vault passphrase');
  await browser.click(vault, '#cancel');
  assert.equal((await answer(id)).unsaved, true);

  for (const role of ['signin', 'spend', 'recover']) {
    id = await send({ operation: 'get', role });
    assert.ok(await browser.ask(vault, generatorHidden), 'existing vaults only accept the original passphrase');
    if (role === 'signin') {
      await approve('This passphrase is incorrect');
      await waitFor(vault, 'document.querySelector("#status").textContent.includes("Could not unlock")', 'wrong master denied');
      assert.ok(!await browser.ask(page, 'events.some(e=>e.ok)'));
    }
    await approve(passphrase);
    const message = await answer(id);
    assert.ok(message.value === secrets[role], 'device and generated passphrase unlock the requested credential'); assert.equal(message.ok, true);
    assert.deepEqual(Object.keys(message).sort(), ['type','v','id','ok','value'].sort());
  }
  await browser.ask(vault, '(window.opener=null,true)');
  await browser.go(vault, vaultHost);
  await waitFor(vault, '!document.querySelector("#home").hidden', 'standalone saved accounts');
  await browser.fill(vault, 'purpose', 'spend'); await browser.click(vault, '#update');
  await browser.fill(vault, 'replacement', 'short'); await approve(passphrase);
  await waitFor(vault, 'document.querySelector("#status").textContent.includes("Enter the new password from your wallet")', 'an invalid update explains which password to correct');
  await browser.fill(vault, 'replacement', 'A new wallet payment password'); await approve(passphrase);
  await waitFor(vault, 'document.querySelector("#status").textContent.includes("Updated")', 'single-role rotation');
  await browser.fill(vault, 'purpose', 'spend'); await browser.click(vault, '#choose'); await approve(passphrase);
  await waitFor(vault, '!document.querySelector("#display").hidden', 'standalone role unlock');
  assert.ok((await browser.text(vault, '#value')) === 'A new wallet payment password', 'rotation stores the updated payment password');
  await browser.click(vault, '#hide'); assert.ok((await browser.text(vault, '#value')) === '', 'locking clears the displayed password');
  console.log('Vault browser smoke passed: 100 offline rerolls, preview cleanup, cancel before commit, backup, generated master unlock, three role approvals, wrong master rejection, standalone update and lock.');
} finally {
  if (chrome) await chrome.close();
  await Promise.all([server, wallet].filter(s => s?.listening).map(s => new Promise(resolve => s.close(resolve))));
  await rm(temp, { recursive: true, force: true, maxRetries: 4, retryDelay: 100 });
}
