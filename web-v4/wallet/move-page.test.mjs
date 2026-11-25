// "Move my account here" through the real app.js (move-ui.mjs and its lines in app.js and index.html): the start screen's
// way in, the panel, the passwords the wallet makes shown in the page's own dialog, the request found again after a reload
// before any unlock, and the account opened when the move lands: with the login key the page still holds, as after a
// sign-up, or after a reload with the login password the wallet made.
//
// The stand-in page of signup.test.mjs (copied from there), with the real SDK and wallet modules. Stood in for: the compiled
// verifier (it passes on what this chain holds), and the chain with its gateway. The old device is played by the test,
// through device-move.mjs as move-ui.mjs calls it (its page is driven in move-ui.test.mjs), and the move is applied by the
// rules of tests/mock-security-chain.mjs with its signature checked.
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
const F = await import(new URL('web-v4/wallet/security-flows.mjs', root).href);
const M = await import(new URL('web-v4/wallet/device-move.mjs', root).href);
const security = await import(new URL('client-v4/account-security.mjs', root).href);
const { MOVE_PAGE_WORDS } = await import(new URL('web-v4/wallet/move-ui.mjs', root).href);
const { openVault } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const { LOCK_WORDS } = await import(new URL('web-v4/wallet/device-lock.mjs', root).href);
const { createSecurityChain } = await import(new URL('web-v4/wallet/tests/mock-security-chain.mjs', root).href);
const { NOT_HAD, HAD } = await import(new URL('web-v4/wallet/made-dialog.mjs', root).href);
const { provenSeals } = await import(new URL('web-v4/wallet/tests/legacy-vault.mjs', root).href);
const umdSource = await readFile(new URL('web-v4/wallet/vendor/argon2-4.12.0.umd.min.js', root), 'utf8'), umd = { exports: {} };
new Function('module', 'exports', umdSource)(umd, umd.exports);
const argon2id = umd.exports.argon2id;
const page = await readFile(new URL('./index.html', import.meta.url), 'utf8');

// ------------------------------------------------------------------ a stand-in page, which can be loaded again
class Storage { m = new Map(); getItem(k) { return this.m.has(k) ? this.m.get(k) : null; } setItem(k, v) { this.m.set(k, String(v)); } removeItem(k) { this.m.delete(k); } }
class El {
  constructor(id) { Object.assign(this, { id, value: '', hidden: false, textContent: '', disabled: false, checked: false, open: false, returnValue: '', dataset: {}, type: 'text', children: [], listeners: {}, className: '', files: [], required: false, classList: { add() {}, remove() {}, toggle() {} } }); }
  addEventListener(type, fn, options) { (this.listeners[type] ??= []).push({ fn, once: options?.once === true }); }
  querySelectorAll() { return [this.querySelector()]; } querySelector() { return this.button ??= new El(this.id + '-button'); }
  replaceChildren(...c) { this.children = c; } append(...c) { this.children.push(...c); } remove() {} click() {}
  showModal() { this.open = true; } close(value) { this.open = false; if (value !== undefined) this.returnValue = value; this.fire('close'); }
  setAttribute(name, value) { (this.attributes ??= {})[name] = String(value); } getAttribute(name) { return this.attributes?.[name] ?? null; } removeAttribute(name) { delete this.attributes?.[name]; }
  focus() {} select() {} scrollIntoView() {}
  async fire(type) { const list = this.listeners[type] || []; this.listeners[type] = list.filter(item => !item.once); await Promise.all(list.map(item => item.fn({ preventDefault() {}, data: null }))); }
}
let dom = new Map();
const storage = new Storage(), intervals = [];
const $ = id => { if (!dom.has(id)) dom.set(id, new El(id)); return dom.get(id); };
const PANELS = [...page.matchAll(/<section class="workspace-panel" id="panel-([a-z]+)"/g)].map(found => found[1]);
const HIDDEN = [...page.matchAll(/<[a-z0-9]+\b[^>]*>/g)].map(found => found[0]).filter(tag => /\shidden(?=[\s>])/.test(tag)).map(tag => /\bid="([^"]+)"/.exec(tag)?.[1]).filter(Boolean);
const documentListeners = {};
globalThis.document = { getElementById: $, createElement: tag => new El(tag), querySelectorAll: selector => (selector === '.workspace-panel' ? PANELS.map(name => $('panel-' + name)) : []), addEventListener(type, fn, options) { (documentListeners[type] ??= []).push({ fn, options }); }, body: { append() {}, classList: { add() {}, remove() {} } }, title: '' };
Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: new Proxy(storage, { ownKeys: t => [...t.m.keys()], getOwnPropertyDescriptor: (t, k) => t.m.has(k) ? { enumerable: true, configurable: true, value: t.m.get(k) } : Reflect.getOwnPropertyDescriptor(t, k), get: (t, k) => typeof t[k] === 'function' ? t[k].bind(t) : t[k] }) });
// The browser keeps this site's data (navigator.storage.persisted): the warning of storage that may not last is driven in move-ui.test.mjs.
let clipboard = '';
Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { locks: { request: (name, options, fn) => fn() }, clipboard: { writeText: async text => { clipboard = text; } }, storage: { persisted: async () => true } } });
globalThis.window = { addEventListener() {}, opener: null, print() {} };
globalThis.location = { origin: 'https://wallet.example', pathname: '/' };
globalThis.isSecureContext = true;
globalThis.hashwasm = { argon2id };
globalThis.BroadcastChannel = undefined;
globalThis.setInterval = fn => { intervals.push(fn); return intervals.length; };
globalThis.clearInterval = id => { if (id) intervals[id - 1] = null; };
const realTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...given) => { const timer = realTimeout(fn, ms, ...given); if (ms >= 60000) timer.unref(); return timer; };
const until = async (condition, what) => { for (let turn = 0; turn < 6000; turn++) { if (await condition()) return; await new Promise(resolve => realTimeout(resolve, 5)); } assert.fail(`waited in vain for: ${what} (the wallet's notice: ${$('notice').textContent})`); };

// ------------------------------------------------------------------ a stand-in chain with a protected @alice, and its gateway
const NET = 'c6'.repeat(32), GENESIS = 17n * 10n ** 14n, MICROS = 1000000n, FEE = 1000n;
const verify = async (publicKey, signature, message) => crypto.subtle.verify('Ed25519', await crypto.subtle.importKey('raw', SDK.hexToBytes(publicKey, 32), 'Ed25519', false, ['verify']), SDK.hexToBytes(signature, 64), message);
const deviceRow = (publicKey, role) => ({ public_key: publicKey, can_manage: role === 'recover', can_spend: role === 'spend' });
const chain = { height: 900, now: 240n * 3600n * MICROS, accounts: [], rows: {}, rules: null };
/// A protected @alice whose keys are on another device (the old one, which the test plays), and the words of its recovery keys.
async function seed() {
  chain.accounts.length = 0; for (const k of Object.keys(chain.rows)) delete chain.rows[k];
  const quick = async ({ password, salt }) => new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([...password, ...salt])));
  const words = F.generatePassphrase(), first = await F.passphraseKey({ passphrase: words, networkId: NET, accountId: '5', argon2id: quick }), second = await F.recoveryWordsSecondKey({ passphrase: words, networkId: NET, accountId: '5', argon2id: quick });
  const [signin, spend] = await F.sealedKeys({ wanted: [{ intent: 'signin' }, { intent: 'spend' }], networkId: NET, name: 'alice', argon2id: quick });
  chain.accounts.push({ id: '5', name: 'alice', public_key: 'ab'.repeat(32), balance: '10000000', nonce: '3', auth_epoch: '1', recovery_policy: null,
    devices: [deviceRow(signin.key.publicKey, 'signin'), deviceRow(spend.key.publicKey, 'spend'), deviceRow(first.publicKey, 'recover'), deviceRow(second.publicKey, 'recover')].sort((a, b) => (a.public_key < b.public_key ? -1 : 1)) });
  chain.rows['5'] = { account: '5', version: '1', policy: { threshold: '2', daily_limit_micros: '500000', delay_seconds: '60', freeze_seconds: '120' }, allowance_micros: '500000', allowance_elapsed_micros: chain.now.toString(), frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null };
  chain.rules = createSecurityChain({ sdk: SDK, security, networkId: NET, accounts: chain.accounts, rows: chain.rows, fee: FEE });
  return { spend, first };
}
function stateFor(query) {
  const ids = query.ids || [], names = query.names || [], keys = query.public_keys || [];
  const state = { protocol_version: '4', network_id: NET, height: String(chain.height), time_micros: (GENESIS + chain.now).toString(), genesis: { genesis_time_micros: GENESIS.toString() },
    config: { recovery_min_delay_micros: '30000000', recovery_approval_window_micros: '86400000000', all_new_time_to_validators: true, registration: { fee_micros: '10000', max_lifetime_micros: '86400000000', bucket_micros: '3600000000' }, protected_registration: true },
    bank: '0', auction_epoch: '1', earning_epochs: {}, earning_bids: {}, stake_owners: {}, recovery_cases: [], candidates: Object.fromEntries((query.candidates || []).map(id => [id, null])),
    accounts: chain.accounts.filter(item => ids.includes(item.id) || names.includes(item.name) || keys.some(key => item.devices.some(d => d.public_key === key))), name_commits: [] };
  if (query.include_security) state.security = state.accounts.map(item => chain.rows[item.id]).filter(Boolean);
  if (query.include_pos) state.pos = { profile: 'production', candidate_ids: [], active: [], scheduled: [], safety_hold: false, bootstrap_ended: true };
  if (query.include_upgrade) state.upgrade = null;
  return structuredClone(state);
}
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
  const trust = { app_version: '4', network_id: NET, chain_id: 'time-devnet-v4-test' };
  if (route === '/trust-manifest.json') return { ok: true, status: 200, json: async () => trust, text: async () => JSON.stringify(trust) };
  let body;
  if (route === '/api/network') body = { protocolVersion: '4', networkId: NET, chainId: trust.chain_id, mode: 'local-devnet', publicLaunchAllowed: false };
  else if (route === '/api/light-block') body = block(address.searchParams.get('height') || chain.height);
  else if (route === '/api/view-proof') body = { light_block: block(chain.height) };
  else if (route === '/api/notifications') body = { items: [] };
  else body = { error: 'not served by this stand-in gateway' };
  return { ok: !body.error, status: body.error ? 400 : 200, text: async () => JSON.stringify(body), json: async () => body };
};

// ------------------------------------------------------------------ the person, at the wallet
let pages = 0;
async function freshPage() {
  if (pages > 0) await $('lock-button').fire('click');
  dom = new Map(); intervals.length = 0;
  for (const id of HIDDEN) $(id).hidden = true;
  await import(new URL(`web-v4/wallet/app.js?move=${++pages}`, root).href);
  await until(() => /^(Connected to the Time test network|Your account is here now)/.test($('notice').textContent) || $('move-panel').hidden === false || $('notice').className.includes('error'), 'the wallet to start');
}
/// "Move my account here", the name, and the request: the passwords the wallet made are read from its dialog, which is
/// then closed `how`: 'done' ("I have them"), 'close' (by a script) or 'escape' (the dialog's cancel event).
async function request(name = 'alice', how = 'done') {
  if ($('move-panel').hidden) await $('move-open').fire('click');
  assert.deepEqual([$('move-panel').hidden, $('auth-panel').hidden, $('move-form').hidden], [false, true, false]);
  // This stand-in page has no device that can lock keys: once the browser has said so, no choice is shown, and the form says
  // the wallet makes the passwords.
  await until(() => $('move-seal-note').hidden === false || $('move-ways').hidden === false, 'the form drawn');
  assert.deepEqual([$('move-seal-note').textContent, $('move-seal-note').hidden, $('move-ways').hidden], [LOCK_WORDS.birthMade, false, true]);
  $('move-name').value = name; $('notice').textContent = ''; $('notice').className = 'notice';
  const sent = $('move-form').fire('submit');
  await until(() => $('made-dialog').open || $('notice').className.includes('error'), 'the dialog of the passwords');
  const made = { login: $('made-login-shown').textContent, payment: $('made-payment-shown').textContent, why: $('made-why').textContent, kept: [...storage.m.keys()].filter(k => k.includes(':move')).length };
  if (how === 'done') $('made-dialog').close(HAD);
  else if (how === 'close') $('made-dialog').close();
  else await $('made-dialog').fire('cancel');
  await sent;
  if (how !== 'done') { await until(() => $('notice').className.includes('error'), 'the wallet to say nothing was kept'); return { made, text: $('move-request').value, code: $('move-code').textContent }; }
  await until(() => $('move-request').value.length > 100 || $('notice').className.includes('error'), 'the request');
  return { made, text: $('move-request').value, code: $('move-code').textContent };
}
/// The old device's part, as move-ui.mjs does it there: review, code, the replacement with its payment key and a recovery
/// key; then the chain takes it.
async function oldDeviceMoves(text, code, { spendKey, first }) {
  const state = stateFor({ names: ['alice'], include_security: true }), account = state.accounts[0], row = state.security[0], now = F.elapsedOf(state);
  const dm = M.createDeviceMove({ security });
  const review = await dm.reviewMove({ text, networkId: NET, account, security: row, now, waitsNow: now, feeMicros: FEE });
  const built = await dm.buildMove({ networkId: NET, request: review.request, typedCode: code, account, security: row, spend: spendKey, recovery: first, now, waitsNow: now, feeMicros: FEE });
  const action = SDK.decodeAction(built.tx);
  assert.ok(await verify(action.publicKey, SDK.bytesToHex(built.tx.slice(-64)), built.tx.slice(0, -64)));
  await chain.rules.apply(action, chain.now); chain.height += 1; chain.now += MICROS;
}
/// The old device's payment key, as it holds it (sealed under the password the wallet made), opened.
async function oldSpend(seeded) {
  const quick = async ({ password, salt }) => new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([...password, ...salt])));
  return { publicKey: seeded.spend.key.publicKey, privateKey: (await openVault(seeded.spend.record, seeded.spend.made, quick, crypto, 'spend')).privateKey };
}
const moveTimer = () => intervals.filter(Boolean).at(-1);

test('the new device through app.js: "Move my account here", the made passwords shown before anything is kept, the request; the move lands and the account opens with the login key the page held', async () => {
  storage.m.clear();
  const seeded = await seed();
  await freshPage();
  const { made, text, code } = await request();
  assert.ok(made.login && made.payment && made.why === MOVE_PAGE_WORDS.madeWhy);
  assert.equal(made.kept, 0, 'nothing of the move was kept while the passwords were shown');
  assert.match(code, /^[0-9A-HJKMNP-TV-Z]{4}( [0-9A-HJKMNP-TV-Z]{4}){3}$/);
  assert.match($('move-stage').textContent, /^Waiting for your other device/);
  assert.equal($('notice').textContent, MOVE_PAGE_WORDS.ready);
  await $('move-copy').fire('click'); await until(() => clipboard === text, 'the copy');
  assert.equal($('dashboard').hidden, true, 'nothing is open yet');
  await oldDeviceMoves(text, code, { spendKey: await oldSpend(seeded), first: seeded.first });
  // The page's timer reads the network: the account opens, as after a sign-up.
  const tick = moveTimer(); assert.ok(tick, 'the page reads the network while the request waits');
  tick();
  await until(() => $('dashboard').hidden === false && $('account-name').textContent === '@alice', 'the account open');
  assert.equal($('move-panel').hidden, true);
  assert.equal($('notice').textContent, MOVE_PAGE_WORDS.settled);
  // Its keys are in their places, and the move's notes are gone; Keys offers to move it again from here.
  assert.deepEqual([...storage.m.keys()].filter(k => /vault/.test(k)).sort(), [F.vaultSlots(NET, 'alice').login, F.vaultSlots(NET, 'alice').spend].sort());
  assert.deepEqual(await provenSeals({ entries: [...storage.m], shown: [made.login, made.payment], argon2id }), [], 'the keys in their places, proven by opening them');
  assert.equal($('move-card').hidden, false);
});

test('the new device through app.js, reloaded: the request is found again before any unlock; after the move the login password the wallet made opens the account', async () => {
  storage.m.clear();
  const seeded = await seed();
  await freshPage();
  const { made, text, code } = await request();
  // The page closes and opens again: the same request and code are shown at once, nothing is unlocked.
  await freshPage();
  await until(() => $('move-request').value === text, 'the request shown again');
  assert.deepEqual([$('move-panel').hidden, $('auth-panel').hidden, $('dashboard').hidden, $('move-code').textContent], [false, true, true, code]);
  // Withdraw is there while it waits.
  assert.equal($('move-withdraw').hidden, false);
  await oldDeviceMoves(text, code, { spendKey: await oldSpend(seeded), first: seeded.first });
  await freshPage();
  await until(() => $('notice').textContent === MOVE_PAGE_WORDS.settledOpen('alice'), 'the account here, to be opened');
  assert.deepEqual([$('username').value, $('auth-panel').hidden, $('move-panel').hidden], ['alice', false, true]);
  $('password').value = made.login; await $('auth-form').fire('submit');
  await until(() => $('dashboard').hidden === false && $('account-name').textContent === '@alice', 'the account open');
});

test('the passwords the wallet made go on only with "I have them": closed by a script or by Escape, nothing of the move is kept, no request is shown, and the wallet says so; with it, each record kept opens with what was shown', async () => {
  storage.m.clear();
  await seed();
  await freshPage();
  for (const how of ['close', 'escape']) {
    const { made, text, code } = await request('alice', how);
    assert.ok(made.login && made.payment, how);
    assert.equal($('notice').textContent, NOT_HAD.two, how);
    assert.deepEqual([[...storage.m.keys()].filter(k => k.includes(':move')), text, code, $('move-step').hidden, $('move-form').hidden, $('made-dialog').open], [[], '', '', true, false, false], how);
    assert.equal($('made-login-shown').textContent, '', `${how}: what was shown left the page`);
  }
  // With "I have them", the same form makes the request; the two records kept aside are proven by opening them
  // (tests/legacy-vault.mjs): each opens with a password shown, and with nothing else.
  const { made, text } = await request('alice', 'done');
  assert.ok(text.length > 100);
  assert.equal([...storage.m.keys()].filter(k => /:move(signin|spend)$/.test(k)).length, 2);
  assert.deepEqual(await provenSeals({ entries: [...storage.m], shown: [made.login, made.payment], argon2id }), []);
});
