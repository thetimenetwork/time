// Review of the browser-check changes (commit 16d3e5d): verifiedState's wait for proven state to reach the block of
// the newest verified receipt (`receiptFloor`, app.js). Nothing else tests it: with the wait loop, the check of the
// sponsor's receipt and the wait for the commitment all removed from app.js, every test of web-v4/wallet passes.
//
// The real app.js on the stand-in page of app.test.mjs (copied from there: a page that makes its elements on demand,
// a browser storage, the real SDK and wallet modules, a stand-in for the compiled verifier and a gateway that answers
// from a mock chain). A receipt newer than the proven state is made with "Recheck" of an action this browser
// recorded before. The only 300 ms timer of the wallet is the pause of that wait (app.js, verifiedState): the test
// counts those timers to see how many waits run at once.
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
const SDK = globalThis.TimeSDK;
const umdSource = await readFile(new URL('web-v4/wallet/vendor/argon2-4.12.0.umd.min.js', root), 'utf8'), umd = { exports: {} };
new Function('module', 'exports', umdSource)(umd, umd.exports);
const argon2id = umd.exports.argon2id;

// ------------------------------------------------------------------ a stand-in page (as in app.test.mjs)
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
const dom = new Map(), storage = new Storage(), intervals = [];
const $ = id => { if (!dom.has(id)) dom.set(id, new El(id)); return dom.get(id); };
const textOf = el => [el.textContent, ...(el.children || []).map(textOf)].filter(Boolean).join(' ');
globalThis.document = { getElementById: $, createElement: tag => new El(tag), querySelectorAll: () => [], addEventListener() {}, body: { append() {}, classList: { add() {}, remove() {} } }, title: '' };
Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: new Proxy(storage, { ownKeys: t => [...t.m.keys()], getOwnPropertyDescriptor: (t, k) => t.m.has(k) ? { enumerable: true, configurable: true, value: t.m.get(k) } : Reflect.getOwnPropertyDescriptor(t, k), get: (t, k) => typeof t[k] === 'function' ? t[k].bind(t) : t[k] }) });
Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { locks: { request: (name, options, fn) => fn() }, clipboard: { writeText: async () => {} } } });
globalThis.window = { addEventListener() {}, opener: null };
globalThis.location = { origin: 'https://wallet.example', pathname: '/' };
globalThis.isSecureContext = true;
globalThis.hashwasm = { argon2id };
globalThis.BroadcastChannel = undefined;
// The refresh timer is called by the test (`intervals`). The wait's 300 ms pauses are counted (`waiting`).
globalThis.setInterval = fn => { intervals.push(fn); return intervals.length; };
globalThis.clearInterval = id => { if (id) intervals[id - 1] = null; };
const realTimeout = globalThis.setTimeout;
let waiting = 0;
globalThis.setTimeout = (fn, ms, ...given) => {
  if (ms === 300) { waiting++; return realTimeout(() => { waiting--; fn(...given); }, ms); }
  const timer = realTimeout(fn, ms, ...given); if (ms >= 60000) timer.unref(); return timer;
};
// The wait gives up after 20 s of Date.now(): the test moves the clock on instead of waiting.
const realNow = Date.now.bind(Date); let skew = 0; Date.now = () => realNow() + skew;
const sleep = ms => new Promise(resolve => realTimeout(resolve, ms));
const until = async (condition, what) => { for (let turn = 0; turn < 600; turn++) { if (await condition()) return; await sleep(5); } assert.fail(`waited in vain for: ${what} (the wallet's notice: ${$('notice').textContent})`); };
/// The most waits seen at once over `ms`.
async function mostWaits(ms) { let most = 0; for (const end = realNow() + ms; realNow() < end;) { most = Math.max(most, waiting); await sleep(10); } return most; }
/// Lets every wait give up (as 20 s later), and waits for the wallet to settle.
async function endWaits() { skew += 25000; await until(() => waiting === 0, 'every wait to end'); await sleep(200); }

// ------------------------------------------------------------------ a mock chain behind a gateway (as in app.test.mjs)
const networkId = 'c6'.repeat(32), GENESIS = 1700000000000000n, DAY = 86400000000n;
const PASSWORD = 'correct horse battery staple 41';
const validator = owner => ({ owner: String(owner), consensus_key: '11'.repeat(32), power: '1000' });
const candidate = owner => ({ owner: String(owner), consensus_key: '11'.repeat(32), jailed: false, archived: false, self_bond: '86400000000', pool_shares: '0', pool_assets: '0', commission_bps: 0, last_active_end: '0' });
const chain = { height: 900, now: 100n * DAY, security: {}, signals: [], recovery: [], included: new Map(),
  accounts: [1, 2, 3, 4].map(id => ({ id: String(id), name: 'owner_' + id, balance: '5000000', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: '2' + String(id).repeat(63), can_manage: true, can_spend: true }] })),
  candidates: Object.fromEntries([1, 2, 3, 4, 5].map(id => [String(id), candidate(id)])), active: [1, 2, 3, 4, 5].map(validator) };
function stateFor(query) {
  const ids = query.ids || [], names = query.names || [];
  const state = { protocol_version: '4', network_id: networkId, height: String(chain.height), time_micros: (GENESIS + chain.now).toString(), genesis: { genesis_time_micros: GENESIS.toString() }, config: { recovery_min_delay_micros: '30000000', all_new_time_to_validators: true },
    bank: '0', auction_epoch: '1', earning_epochs: {}, earning_bids: {}, stake_owners: {},
    accounts: chain.accounts.filter(item => ids.includes(item.id) || names.includes(item.name)), recovery_cases: chain.recovery, candidates: Object.fromEntries((query.candidates || []).map(id => [id, chain.candidates[id] ?? null])) };
  if (query.include_security) state.security = state.accounts.map(item => chain.security[item.id]).filter(Boolean);
  if (query.include_pos) state.pos = { profile: 'production', candidate_ids: Object.keys(chain.candidates), active: chain.active, scheduled: [], safety_hold: false, bootstrap_ended: true };
  if (query.include_upgrade) state.upgrade = chain.signals.length ? { signals: chain.signals } : null;
  return structuredClone(state);
}
const trust = { app_version: '4', network_id: networkId, chain_id: 'time-devnet-v4-test' };
const block = height => ({ signed_header: { header: { height: String(height) } } });
globalThis.standInVerifier = {
  verifyTrust: async () => ({}),
  verifyLightUpdate: async candidateBlock => ({ verified: true, status: 'VERIFIED', checkpoint: { height: candidateBlock.signed_header.header.height, block_hash: 'cd'.repeat(32), block: candidateBlock } }),
  verifyViewProof: async (_proof, _trust, query) => ({ verified: true, completeAccountSet: false, state: stateFor(query) }),
  verifyReceipt: async proof => ({ verified: true, executionVerified: true, hash: proof.hash, rawHex: proof.rawHex, height: proof.height }),
  verifyFastReceipt: async proof => ({ verified: true, executionVerified: true, hash: proof.hash, rawHex: proof.rawHex, height: proof.height }),
};
globalThis.fetch = async (url) => {
  const address = new URL(String(url), location.origin), route = address.pathname;
  let answer;
  if (route === '/trust-manifest.json') return { ok: true, status: 200, json: async () => trust, text: async () => JSON.stringify(trust) };
  if (route === '/api/network') answer = { protocolVersion: '4', networkId, chainId: trust.chain_id, mode: 'local-devnet', publicLaunchAllowed: false };
  else if (route === '/api/light-block') answer = block(address.searchParams.get('height') || chain.height);
  else if (route === '/api/view-proof') answer = { light_block: block(chain.height) };
  else if (route === '/api/receipt') { const hash = address.searchParams.get('hash'), found = chain.included.get(hash); answer = found ? { hash, ...found, anchor: { light_block: block(chain.height) } } : { pending: true }; }
  else answer = { error: 'not served by this stand-in gateway' };
  return { ok: !answer.error, status: answer.error ? 400 : 200, text: async () => JSON.stringify(answer), json: async () => answer };
};

// ------------------------------------------------------------------ the wallet: alice, with two earlier actions to recheck
const { newDevice, sealVault, hex } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const login = await newDevice();
chain.accounts.push({ id: '5', name: 'alice', balance: '5000000', nonce: '3', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: login.publicKey, can_manage: true, can_spend: true }] });
storage.setItem(`timecurrency.vault.v1:${networkId}:alice`, JSON.stringify(await sealVault({ ...login.secret, nameSalt: hex(crypto.getRandomValues(new Uint8Array(32))), intent: 'device' }, PASSWORD, { networkId, name: 'alice', publicKey: login.publicKey }, argon2id)));
/// An action of alice that the chain holds in block `height`, and that this browser recorded before (Activity).
const earlier = [];
for (const [nonce, height] of [['1', 950], ['2', 1000]]) {
  const tx = await SDK.signAction({ networkId, kind: 'transfer', from: '5', nonce, authEpoch: '0', publicKey: login.publicKey, payload: { to: '1', amount: '1000' } }, login.privateKey);
  const hash = (await SDK.transactionHash(tx)).toUpperCase();
  chain.included.set(hash, { height: String(height), rawHex: SDK.bytesToHex(tx) });
  earlier.push({ hash, height: String(height), label: `Earlier payment ${nonce}`, at: 0 });
}
storage.setItem(`timecurrency.activity.v1:${networkId}:alice`, JSON.stringify(earlier));
await import(new URL('web-v4/wallet/app.js', root).href);
await until(() => /^Connected to the Time test network, and checked by this browser\./.test($('notice').textContent) || $('notice').className.includes('error'), 'the wallet to start');
$('username').value = 'alice'; $('password').value = PASSWORD; await $('auth-form').fire('submit');
await until(() => $('dashboard').hidden === false && /^against the network at block /.test($('proof-height').textContent), 'alice unlocked');

/// "Recheck" of an earlier action: the wallet verifies its receipt, and its block becomes the floor.
async function recheck(label) {
  const button = $('activity-list').children.find(r => textOf(r).includes(label))?.children.find(c => c.textContent === 'Check again');
  assert.ok(button, `a button "Check again" for ${label}`);
  await button.fire('click');
  assert.equal($('notice').textContent, 'This browser checked the receipt: the action is in a block.');
}
const tick = () => intervals.filter(Boolean).at(-1)();

test('after a verified receipt of block 950, a proven state of block 900 is not taken while block 950 comes within the wait (holds the claim of change 4)', async () => {
  assert.equal($('proof-height').textContent, 'against the network at block 900');
  await recheck('Earlier payment 1');
  const step = $('refresh').fire('click');
  await sleep(800);
  assert.notEqual($('notice').textContent, 'Your balance was checked again against the network.', 'the refresh took the state of block 900');
  assert.ok(waiting >= 1, 'the wallet waits for a newer state');
  chain.height = 950; await step;
  assert.deepEqual([$('notice').textContent, $('proof-height').textContent], ['Your balance was checked again against the network.', 'against the network at block 950']);
});

// The refresh timer (app.js, auth: every 5 s, `if (!busy && session) refresh()`) does not ask whether a refresh is
// still running, and a refresh no longer ends with the first state: behind a gateway whose proven state stays below
// the newest receipt, each one waits 20 s, asking again every 300 ms. A tick every 5 s gives four of them at once,
// each with up to three verified reads a turn, for as long as the gateway stays behind.
test('the refresh timer does not start a second wait while one is still waiting', async () => {
  await recheck('Earlier payment 2'); // block 1000; proven state stays at 950
  tick(); await sleep(100); tick(); await sleep(100); tick();
  const most = await mostWaits(600);
  await endWaits();
  assert.equal(most, 1, `waits running at once after three ticks of the refresh timer: ${most}`);
});

// lock() bumps the fence and clears the timer, but the wait checks no fence: it goes on asking for up to 20 s, then
// writes `latest`, and refresh() fails on its fence check. Its catch (app.js, auth's timer) sets `latest = null`,
// renders, and puts "Verification paused" in the notice: on the lock screen the unlock button is now disabled
// (`ready` needs a verified state) and nothing reads state again (the timer was cleared). The wallet stays so until
// the page is reloaded. Behind a gateway that stays behind, a refresh is waiting at almost any moment, also when the
// idle lock (5 minutes) comes.
test('locking while a refresh waits: the wait stops, and the lock screen can still be unlocked', async () => {
  tick(); await sleep(100);
  assert.equal(waiting, 1, 'a refresh waits');
  await $('lock-button').fire('click');
  const atLock = { notice: $('notice').textContent, unlockDisabled: $('auth-submit').disabled };
  await sleep(500);
  const stillAsking = await mostWaits(400);
  await endWaits();
  assert.deepEqual({ stillAsking, notice: $('notice').textContent, unlockDisabled: $('auth-submit').disabled },
    { stillAsking: 0, notice: atLock.notice, unlockDisabled: false }, `at the lock: ${JSON.stringify(atLock)}`);
});
