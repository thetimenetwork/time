// A test network that was reset: a new chain under the same addresses (reset.mjs, and its lines in app.js and index.html).
// - The start screen of a browser that keeps accounts of the old network only says so, and offers one button that removes
//   what this browser keeps of the old network, and nothing else. "Open my account" says the same, never "New device".
// - A page that is open while its network is reset says "The test network was reset. Reload this page." in place of a
//   failed verification, once the site's trust file names another network.
//
// The real app.js on the stand-in page of protection-card.test.mjs (copied from there).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { registerHooks } from 'node:module';

const root = new URL('../../', import.meta.url);
const verifierStub = 'data:text/javascript,' + encodeURIComponent('const v=()=>globalThis.standInVerifier;' + ['verifyTrust', 'verifyLightUpdate', 'verifyViewProof', 'verifyReceipt', 'verifyFastReceipt'].map(name => `export const ${name}=(...given)=>v().${name}(...given);`).join(''));
registerHooks({ resolve(specifier, context, next) {
  if (specifier === '/sdk/proof-verifier.js') return { url: verifierStub, shortCircuit: true };
  return next(specifier === '/sdk/account-security.mjs' ? new URL('client-v4/account-security.mjs', root).href : specifier, context);
} });
await import(new URL('client-v4/time-sdk.js', root).href);
const R = await import(new URL('web-v4/wallet/reset.mjs', root).href);
const umdSource = await readFile(new URL('web-v4/wallet/vendor/argon2-4.12.0.umd.min.js', root), 'utf8'), umd = { exports: {} };
new Function('module', 'exports', umdSource)(umd, umd.exports);
const argon2id = umd.exports.argon2id;
const page = await readFile(new URL('./index.html', import.meta.url), 'utf8');

class Storage { m = new Map(); getItem(k) { return this.m.has(k) ? this.m.get(k) : null; } setItem(k, v) { this.m.set(k, String(v)); } removeItem(k) { this.m.delete(k); } }
class El {
  constructor(id) { Object.assign(this, { id, value: '', hidden: false, textContent: '', disabled: false, checked: false, open: false, returnValue: '', dataset: {}, type: 'text', children: [], listeners: {}, className: '', files: [], classList: { add() {}, remove() {}, toggle() {} } }); }
  addEventListener(type, fn, options) { (this.listeners[type] ??= []).push({ fn, once: options?.once === true }); }
  querySelectorAll() { return [this.querySelector()]; } querySelector() { return this.button ??= new El(this.id + '-button'); }
  replaceChildren(...c) { this.children = c; } append(...c) { this.children.push(...c); } remove() {} click() {}
  showModal() { this.open = true; } close() { this.open = false; }
  setAttribute(name, value) { (this.attributes ??= {})[name] = String(value); } getAttribute(name) { return this.attributes?.[name] ?? null; } removeAttribute(name) { delete this.attributes?.[name]; }
  focus() {} select() {} scrollIntoView() {}
  async fire(type) { const list = this.listeners[type] || []; this.listeners[type] = list.filter(item => !item.once); await Promise.all(list.map(item => item.fn({ preventDefault() {}, data: null }))); }
}
let dom = new Map();
const storage = new Storage(), intervals = [];
const $ = id => { if (!dom.has(id)) dom.set(id, new El(id)); return dom.get(id); };
const PANELS = [...page.matchAll(/<section class="workspace-panel" id="panel-([a-z]+)"/g)].map(found => found[1]);
const HIDDEN = [...page.matchAll(/<[a-z0-9]+\b[^>]*>/g)].map(found => found[0]).filter(tag => /\shidden(?=[\s>])/.test(tag)).map(tag => /\bid="([^"]+)"/.exec(tag)?.[1]).filter(Boolean);
globalThis.document = { getElementById: $, createElement: tag => new El(tag), querySelectorAll: selector => (selector === '.workspace-panel' ? PANELS.map(name => $('panel-' + name)) : []), addEventListener() {}, body: { append() {}, classList: { add() {}, remove() {} } }, title: '' };
Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: new Proxy(storage, { ownKeys: t => [...t.m.keys()], getOwnPropertyDescriptor: (t, k) => t.m.has(k) ? { enumerable: true, configurable: true, value: t.m.get(k) } : Reflect.getOwnPropertyDescriptor(t, k), get: (t, k) => typeof t[k] === 'function' ? t[k].bind(t) : t[k] }) });
Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { locks: { request: (name, options, fn) => fn() }, clipboard: { writeText: async () => {} } } });
globalThis.window = { addEventListener() {}, opener: null };
globalThis.location = { origin: 'https://wallet.example', pathname: '/' };
globalThis.isSecureContext = true;
globalThis.hashwasm = { argon2id };
globalThis.BroadcastChannel = undefined;
globalThis.setInterval = fn => { intervals.push(fn); return intervals.length; };
globalThis.clearInterval = id => { if (id) intervals[id - 1] = null; };
const realTimeout = globalThis.setTimeout;
const ARM_MS = Number(/\nconst REVIEW_ARM_MS = ([0-9]+);/.exec(await readFile(new URL('./app.js', import.meta.url), 'utf8'))?.[1]);
const arming = [];
globalThis.setTimeout = (fn, ms, ...given) => { if (ms === ARM_MS) { arming.push(() => fn(...given)); return null; } const timer = realTimeout(fn, ms, ...given); if (ms >= 60000) timer.unref(); return timer; };
const until = async (condition, what) => { for (let turn = 0; turn < 4000; turn++) { if (await condition()) return; await new Promise(resolve => realTimeout(resolve, 5)); } assert.fail(`waited in vain for: ${what} (the wallet's notice: ${$('notice').textContent})`); };
// The page reads the site's trust file again at most every half minute: the tests move this clock on.
let ahead = 0; const realNow = Date.now; Date.now = () => realNow() + ahead;

// ------------------------------------------------------------------ the site, before and after a reset
const OLD = 'a1'.repeat(32), NEW = 'b2'.repeat(32), NEWER = 'c3'.repeat(32), GENESIS = 1700000000000000n, DAY = 86400000000n;
const PASSWORD = 'correct horse battery staple 41';
// `served`: the network the site serves now: its trust file and what its gateway proves. `down`: the gateway proves nothing.
const site = { served: NEW, down: false, height: 900 };
const accounts = [{ id: '5', name: 'carol', balance: '1000000', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [] }];
function stateFor(query) {
  if (site.down) throw new Error('the gateway answers no read');
  const names = query.names || [], ids = query.ids || [];
  return structuredClone({ protocol_version: '4', network_id: site.served, height: String(site.height), time_micros: (GENESIS + 100n * DAY).toString(), genesis: { genesis_time_micros: GENESIS.toString() }, config: { recovery_min_delay_micros: '30000000', all_new_time_to_validators: true },
    bank: '0', auction_epoch: '1', earning_epochs: {}, earning_bids: {}, stake_owners: {}, name_commits: [], recovery_cases: [], candidates: {}, accounts: accounts.filter(a => names.includes(a.name) || ids.includes(a.id)),
    ...(query.include_security ? { security: [] } : {}), ...(query.include_pos ? { pos: { profile: 'production', candidate_ids: [], active: [], scheduled: [], safety_hold: false, bootstrap_ended: true } } : {}), ...(query.include_upgrade ? { upgrade: null } : {}) });
}
const block = height => ({ signed_header: { header: { height: String(height) } } });
globalThis.standInVerifier = {
  verifyTrust: async () => ({}),
  verifyLightUpdate: async candidateBlock => ({ verified: true, status: 'VERIFIED', checkpoint: { height: candidateBlock.signed_header.header.height, block_hash: 'cd'.repeat(32), block: candidateBlock } }),
  verifyViewProof: async (_proof, _trust, query) => ({ verified: true, completeAccountSet: false, state: stateFor(query) }),
  verifyReceipt: async proof => ({ verified: true, executionVerified: true, hash: proof.hash, rawHex: proof.rawHex, height: proof.height }),
  verifyFastReceipt: async proof => ({ verified: true, executionVerified: true, hash: proof.hash, rawHex: proof.rawHex, height: proof.height }),
};
let trustReads = 0;
globalThis.fetch = async (url) => {
  const address = new URL(String(url), location.origin), route = address.pathname;
  const trust = { app_version: '4', network_id: site.served, chain_id: 'time-devnet-v4-test' };
  if (route === '/trust-manifest.json') { trustReads += 1; return { ok: true, status: 200, json: async () => trust, text: async () => JSON.stringify(trust) }; }
  let body;
  if (route === '/api/network') body = { protocolVersion: '4', networkId: site.served, chainId: trust.chain_id, mode: 'local-devnet', publicLaunchAllowed: false };
  else if (route === '/api/light-block') body = block(address.searchParams.get('height') || site.height);
  else if (route === '/api/view-proof') body = { light_block: block(site.height) };
  else if (route === '/api/notifications') body = { items: [] };
  else body = { error: 'not served by this stand-in gateway' };
  return { ok: !body.error, status: body.error ? 400 : 200, text: async () => JSON.stringify(body), json: async () => body };
};

// ------------------------------------------------------------------ what a browser kept of the old network, and of others
const { newDevice, hex } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const { sealLegacy } = await import(new URL('web-v4/wallet/tests/legacy-vault.mjs', root).href);
const vault = async (networkId, name, device) => JSON.stringify(await sealLegacy({ ...device.secret, nameSalt: hex(crypto.getRandomValues(new Uint8Array(32))), intent: 'device' }, PASSWORD, { networkId, name, publicKey: device.publicKey }, argon2id));
const OLD_ENTRIES = {
  [`timecurrency.vault.v1:${OLD}:alice`]: await vault(OLD, 'alice', await newDevice()),
  [`timecurrency.spend-vault.v1:${OLD}:alice`]: '{}', [`timecurrency.vault-next.v1:${OLD}:alice:signin`]: '{}', [`timecurrency.vault-next.v1:${OLD}:alice:action`]: '{}',
  [`timecurrency.activity.v1:${OLD}:alice`]: '[]', [`timecurrency.names.v1:${OLD}:alice`]: '{"paid":["bob"]}', [`timecurrency.pending.v1:${OLD}:7`]: '{}',
  [`timecurrency.order.v1:${OLD}:7:${'ab'.repeat(32)}`]: '{}', [`timecurrency.pause.v1:${OLD}:alice`]: '{}', [`timecurrency.upgrade-entry.v1:${OLD}`]: '1', [`timecurrency.v4.epochs:${OLD}:7`]: '[]',
  [`timecurrency.backup-saved.v1:${OLD}:alice:${'cd'.repeat(32)}`]: '1', [`timecurrency.signal.v1:${OLD}:7`]: '{}', [`timecurrency-v4-checkpoint:${OLD}`]: '{}',
  // What the private store keeps (locked-store.mjs): the wrapped data key and the encrypted records.
  [`timecurrency.store-key.v1:${OLD}:alice`]: '{}', [`timecurrency.activity.v2:${OLD}:alice`]: '{}', [`timecurrency.names.v2:${OLD}:alice`]: '{}', [`timecurrency.orders.v2:${OLD}:alice`]: '{}',
};
// Kept: what the wallet keeps of the network it serves now, and what is not the wallet's.
const STAYING = { [`timecurrency.upgrade-entry.v1:${NEW}`]: '1', [`timecurrency-v4-checkpoint:${NEW}`]: '{}', 'another-page.setting': 'timecurrency.vault.v1:' + OLD, 'timecurrency.vault.v1:not-a-network:alice': '{}' };
for (const [key, value] of Object.entries({ ...OLD_ENTRIES, ...STAYING })) storage.setItem(key, value);

let pages = 0;
async function freshPage() {
  if (pages > 0) await $('lock-button').fire('click');
  dom = new Map(); for (const id of HIDDEN) $(id).hidden = true;
  await import(new URL(`web-v4/wallet/app.js?reset=${++pages}`, root).href);
  await until(() => /^Connected to the Time test network/.test($('notice').textContent) || $('notice').className.includes('error'), 'the wallet to start');
}
async function open(name) {
  await $('mode-unlock').fire('click');
  $('username').value = name; $('password').value = PASSWORD; $('notice').textContent = ''; $('notice').className = 'notice';
  await $('auth-form').fire('submit');
}

test('the pure part: what belongs to another network, and the words', () => {
  const keys = Object.keys({ ...OLD_ENTRIES, ...STAYING });
  assert.deepEqual(R.oldEntries(keys, NEW).sort(), Object.keys(OLD_ENTRIES).sort());
  assert.deepEqual([R.resetSeen(keys, NEW), R.resetSeen([...keys, `timecurrency.vault.v1:${NEW}:carol`], NEW), R.resetSeen(Object.keys(STAYING), NEW)], [true, false, false]);
  assert.deepEqual(R.elsewhere([...keys, `timecurrency.vault.v1:${NEWER}:dora`], NEW).names, ['alice', 'dora']);
  assert.equal(R.resetWords(['alice', 'bob', 'dora']), 'The test network was reset. Your old accounts @alice, @bob, and @dora and their test seconds no longer exist. Create a new account. This browser still keeps the old keys; they open nothing now.');
});

test('the start screen of a browser that kept the old network only: it says the network was reset, "Open my account" says the same, and one button removes the old entries and nothing else', async () => {
  await freshPage();
  assert.deepEqual([$('reset-note').hidden, $('reset-text').textContent, $('reset-forget').textContent], [false, 'The test network was reset. Your old account @alice and its test seconds no longer exist. Create a new account. This browser still keeps the old keys; they open nothing now.', 'Remove the old account from this browser']);
  await open('alice');
  assert.deepEqual([$('notice').textContent, $('notice').className.includes('error')], ['The test network was reset: @alice and its test seconds no longer exist. Create a new account.', true]);
  await open('zoe');
  assert.equal($('notice').textContent, 'The test network was reset: the accounts this browser kept are of the old one, and no longer exist. Create a new account.');
  assert.doesNotMatch($('notice').textContent, /New device/);
  // The button: a review that says what goes, then only the old network's entries are gone.
  const pressing = $('reset-forget').fire('click');
  await until(() => $('review-dialog').open, 'the review');
  assert.equal($('review-title').textContent, 'Remove the old test network from this browser');
  for (const fire of arming.splice(0)) fire();
  $('review-dialog').returnValue = 'confirm'; $('review-dialog').open = false; await $('review-dialog').fire('close'); await pressing;
  assert.deepEqual(Object.keys(OLD_ENTRIES).filter(key => storage.getItem(key) !== null), [], 'every entry of the old network is gone');
  assert.deepEqual(Object.keys(STAYING).filter(key => storage.getItem(key) === null), [], 'nothing else is');
  assert.deepEqual([$('reset-note').hidden, $('notice').textContent], [true, 'Removed. This browser keeps nothing of the test network before its reset.']);
  // Without old accounts the start screen is as before, and so is what "Open my account" says.
  await open('alice');
  assert.equal($('notice').textContent, 'No encrypted vault for this account is stored in this browser. Choose New device to request approval.');
  await freshPage();
  assert.equal($('reset-note').hidden, true);
});

test('a browser that also keeps an account of this network is not told of a reset', async () => {
  for (const [key, value] of Object.entries(OLD_ENTRIES)) storage.setItem(key, value);
  const device = await newDevice(); accounts[0].devices = [{ public_key: device.publicKey, can_manage: true, can_spend: true }];
  storage.setItem(`timecurrency.vault.v1:${NEW}:carol`, await vault(NEW, 'carol', device));
  await freshPage();
  assert.deepEqual([$('reset-note').hidden, $('username').value], [true, 'carol']);
});

test('a page open while the network is reset: a failed reading that is not one says "Verification paused"; once the trust file names another network, "Reload this page", and nothing can be signed', async () => {
  await open('carol');
  await until(() => $('dashboard').hidden === false && $('account-verification').textContent === 'Checked by this browser', 'carol open');
  const tick = async (what) => { $('notice').textContent = ''; $('notice').className = 'notice'; intervals.filter(Boolean).at(-1)(); await until(() => $('notice').className.includes('error'), what); };
  const reads = trustReads;
  // The gateway answers nothing for a moment, on the same network: the trust file is read once, and says nothing new.
  site.down = true; await tick('a failed reading');
  assert.match($('notice').textContent, /^Verification paused\. /);
  assert.equal(trustReads - reads, 1, 'the trust file was read again once');
  // The network is reset: the site serves another network. Within half a minute of the last reading nothing is asked.
  site.down = false; site.served = NEWER; await tick('a failed reading');
  assert.match($('notice').textContent, /^Verification paused\. /);
  assert.equal(trustReads - reads, 1, 'not read again within half a minute');
  ahead += 31000; await tick('the reset');
  assert.deepEqual([$('notice').textContent, trustReads - reads], [R.RESET_RELOAD, 2]);
  assert.equal($('send-form').querySelector().disabled, true, 'nothing can be signed');
  // Every later failure says the same, without reading again.
  await tick('the reset again');
  assert.deepEqual([$('notice').textContent, trustReads - reads], [R.RESET_RELOAD, 2]);
  // So does a press of a button that needs the network.
  $('notice').textContent = ''; await $('refresh').fire('click');
  await until(() => $('notice').textContent === R.RESET_RELOAD, 'the reset after a press');
});
