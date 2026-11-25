// The real app.js on a stand-in page: the lines that connect the Validator signal tab to the
// wallet. app.js is a browser page's script; here it is loaded once, as it is, with a page that
// makes its elements on demand, a browser storage, and a gateway that answers from a mock chain.
// The SDK is the real one, and so is every module of the wallet. Two things are stood in for:
// - the compiled verifier (`/sdk/proof-verifier.js`): a stand-in that returns the mock chain's
//   state for whatever was asked, as the verifier would for an honest proof;
// - the browser: no layout, no real dialog, no focus. What a person must check in a browser is
//   listed in the wallet's README.
//
// What these tests hold in place, each on the line of app.js that does it:
// - the tab is shown to the owner of a validator, with the status read with proofs (`render`);
// - its buttons follow the wallet's state: not while a guardian recovery freezes the account
//   (`availability`);
// - a review that asks for a tick is not confirmed without it, whatever enabled its button;
// - a signal from the tab is kind 80, signed by this browser's key on an account with one key and
//   by the payment key on a secured account, never by the login key;
// - locking the wallet empties the tab (`reset`).
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

// ------------------------------------------------------------------ a stand-in page
class Storage { m = new Map(); getItem(k) { return this.m.has(k) ? this.m.get(k) : null; } setItem(k, v) { this.m.set(k, String(v)); } removeItem(k) { this.m.delete(k); } }
class El {
  constructor(id) { Object.assign(this, { id, value: '', hidden: false, textContent: '', disabled: false, checked: false, open: false, returnValue: '', dataset: {}, type: 'text', children: [], listeners: {}, className: '', files: [], classList: { add() {}, remove() {}, toggle() {} } }); }
  addEventListener(type, fn, options) { (this.listeners[type] ??= []).push({ fn, once: options?.once === true }); }
  querySelectorAll() { return [this.querySelector()]; } querySelector() { return this.button ??= new El(this.id + '-button'); }
  replaceChildren(...c) { this.children = c; } append(...c) { this.children.push(...c); } remove() {} click() {}
  showModal() { this.open = true; } close() { this.open = false; }
  setAttribute(name, value) { (this.attributes ??= {})[name] = String(value); } getAttribute(name) { return this.attributes?.[name] ?? null; } removeAttribute(name) { delete this.attributes?.[name]; }
  focus() {} select() {} scrollIntoView() {}
  /// Calls the listeners of an event, as a page does, and waits for what they return.
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
// The wallet refreshes every five seconds and locks after five idle minutes. Here the refresh is called by the
// test (`refreshNow`), and a long timer does not keep the test process alive.
globalThis.setInterval = fn => { intervals.push(fn); return intervals.length; };
globalThis.clearInterval = id => { if (id) intervals[id - 1] = null; };
const realTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...given) => { const timer = realTimeout(fn, ms, ...given); if (ms >= 60000) timer.unref(); return timer; };
const until = async (condition, what) => { for (let turn = 0; turn < 600; turn++) { if (await condition()) return; await new Promise(resolve => realTimeout(resolve, 5)); } assert.fail(`waited in vain for: ${what} (the wallet's notice: ${$('notice').textContent})`); };

// ------------------------------------------------------------------ a mock chain behind a gateway
const networkId = 'c6'.repeat(32), GENESIS = 1700000000000000n, DAY = 86400000000n, FEE = '1000';
const SPEC = 'a3b1c5d7'.repeat(8), PASSWORD = 'correct horse battery staple 41', PAYMENT = 'quiet harbour lanterns at dawn 77';
const validator = owner => ({ owner: String(owner), consensus_key: '11'.repeat(32), power: '1000' });
const candidate = owner => ({ owner: String(owner), consensus_key: '11'.repeat(32), jailed: false, archived: false, self_bond: '86400000000', pool_shares: '0', pool_assets: '0', commission_bps: 0, last_active_end: '0' });
const chain = { height: 900, now: 100n * DAY, security: {}, signals: [], recovery: [], included: new Map(), posted: [],
  accounts: [1, 2, 3, 4].map(id => ({ id: String(id), name: 'owner_' + id, balance: '5000000', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: '2' + String(id).repeat(63), can_manage: true, can_spend: true }] })),
  candidates: Object.fromEntries([1, 2, 3, 4, 5].map(id => [String(id), candidate(id)])), active: [1, 2, 3, 4, 5].map(validator) };
const alice = () => chain.accounts.find(item => item.name === 'alice');
/// The verified state for a selection: what the installed verifier would put in for it.
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
/// One block that holds this signed action, by the chain's rule for every account action.
async function include(tx) {
  const action = SDK.decodeAction(tx), account = chain.accounts.find(item => item.id === action.from), device = account?.devices.find(item => item.public_key === action.publicKey);
  const key = await crypto.subtle.importKey('raw', SDK.hexToBytes(action.publicKey, 32), 'Ed25519', false, ['verify']);
  if (!await crypto.subtle.verify('Ed25519', key, tx.slice(-64), tx.slice(0, -64))) throw new Error('invalid action signature');
  if (BigInt(action.nonce) !== BigInt(account.nonce) + 1n || action.authEpoch !== account.auth_epoch) throw new Error('stale authority or incorrect nonce');
  if (!device?.can_spend) throw new Error('spending device required');
  if (action.kind !== 80) throw new Error('this mock chain takes upgrade signals only');
  chain.height += 1; chain.now += 1000000n; account.nonce = action.nonce; account.balance = String(BigInt(account.balance) - BigInt(FEE));
  const plan = Object.keys(action.payload).length ? action.payload : null;
  chain.signals = chain.signals.filter(item => item.owner !== action.from).concat([{ ...(plan || {}), changed_elapsed_micros: String(chain.now), owner: action.from }]).sort((a, b) => (BigInt(a.owner) < BigInt(b.owner) ? -1 : 1));
  chain.included.set(await SDK.transactionHash(tx), { height: String(chain.height), rawHex: SDK.bytesToHex(tx) });
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
globalThis.fetch = async (url, options = {}) => {
  const address = new URL(String(url), location.origin), route = address.pathname;
  let answer;
  if (route === '/trust-manifest.json') return { ok: true, status: 200, json: async () => trust, text: async () => JSON.stringify(trust) };
  if (route === '/api/network') answer = { protocolVersion: '4', networkId, chainId: trust.chain_id, mode: 'local-devnet', publicLaunchAllowed: false };
  else if (route === '/api/light-block') answer = block(address.searchParams.get('height') || chain.height);
  else if (route === '/api/view-proof') answer = { light_block: block(chain.height) };
  else if (route === '/api/submit') { const tx = new Uint8Array(Buffer.from(JSON.parse(options.body).tx, 'base64')); chain.posted.push(SDK.decodeAction(tx)); try { await include(tx); answer = { hash: await SDK.transactionHash(tx) }; } catch (error) { answer = { error: error.message }; } }
  else if (route === '/api/receipt') { const hash = address.searchParams.get('hash'), found = chain.included.get(hash); answer = found ? { hash, ...found, anchor: { light_block: block(chain.height) } } : { pending: true }; }
  else answer = { error: 'not served by this stand-in gateway' };
  return { ok: !answer.error, status: answer.error ? 400 : 200, text: async () => JSON.stringify(answer), json: async () => answer };
};

// ------------------------------------------------------------------ the wallet: one account, one encrypted vault, the real app.js
const { newDevice, hex } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const { sealLegacy } = await import(new URL('web-v4/wallet/tests/legacy-vault.mjs', root).href);
const U = await import(new URL('web-v4/wallet/upgrade-signal.mjs', root).href);
const login = await newDevice(), spend = await newDevice(), sheet = await newDevice(), phrase = await newDevice();
chain.accounts.push({ id: '5', name: 'alice', balance: '5000000', nonce: '3', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: login.publicKey, can_manage: true, can_spend: true }] });
storage.setItem(`timecurrency.vault.v1:${networkId}:alice`, JSON.stringify(await sealLegacy({ ...login.secret, nameSalt: hex(crypto.getRandomValues(new Uint8Array(32))), intent: 'device' }, PASSWORD, { networkId, name: 'alice', publicKey: login.publicKey }, argon2id)));
await import(new URL('web-v4/wallet/app.js', root).href);
await until(() => /^Connected to the Time test network, and checked by this browser\./.test($('notice').textContent) || $('notice').className.includes('error'), 'the wallet to start');

const PLAN = () => ({ version: '5', spec: SPEC, activate_elapsed_micros: (chain.now + 30n * DAY).toString() });
async function unlock() { $('username').value = 'alice'; $('password').value = PASSWORD; await $('auth-form').fire('submit'); await until(() => $('dashboard').hidden === false && $('tab-upgrade').hidden === false && $('signal-status').children.length > 0, 'the dashboard and the tab'); }
const refreshNow = () => $('refresh').fire('click');
function type(plan) { $('signal-version').value = plan.version; $('signal-spec').value = plan.spec; $('signal-start').value = plan.activate_elapsed_micros; $('signal-node-ready').checked = true; }
/// Answers the review as a person does: waits for the dialog, ticks its box or not, and closes it with a button.
async function answer(button, { tick }) {
  await until(() => $('review-dialog').open, 'the review');
  const shown = { title: $('review-title').textContent, confirm: $('review-confirm').textContent, askedFor: $('review-ack-wrap').hidden ? null : $('review-ack-text').textContent, disabledBefore: $('review-confirm').disabled };
  if (tick) { $('review-ack').checked = true; await $('review-ack').fire('change'); }
  // A person cannot confirm a review in its first moments: the button is disabled until it is armed (app.js,
  // REVIEW_ARM_MS), and a close as confirmed before that counts as cancelled.
  await new Promise(resolve => realTimeout(resolve, 760));
  shown.disabledAfter = $('review-confirm').disabled;
  $('review-dialog').returnValue = button; $('review-dialog').open = false; await $('review-dialog').fire('close');
  return shown;
}

test('the wallet started on the stand-in page, and the signal tab is not there before an account is unlocked', () => {
  assert.match($('notice').textContent, /^Connected to the Time test network, and checked by this browser\./);
  // This gateway names no registration service, so Home offers no "Get test time" (screens.test.mjs has one that does).
  assert.equal($('faucet-button').hidden, true);
  assert.deepEqual([$('signal-status').children.length, $('signal-plans').children.length, chain.posted.length, $('username').value], [0, 0, 0, 'alice']);
});

test('an account with one key: the tab appears with the proven status, its buttons follow the wallet, a review needs its tick, and the signal is kind 80 signed by this browser\'s key', async () => {
  await unlock();
  // render: the tab is there for the owner of a validator, and the status was read with proofs.
  assert.match(textOf($('signal-status')), /The network runs version 4 of its rules\. .* Your validator holds 1000 of 5000 votes .* Your validator has not signalled\./);
  // availability: enabled for an unlocked device; not while a guardian recovery that has its approvals freezes the account.
  assert.deepEqual(['signal-submit', 'signal-withdraw', 'signal-discard', 'signal-refresh'].map(id => $(id).disabled), [false, false, false, false]);
  chain.recovery = [{ target: '5', recovery_id: '1', new_public_key: '77'.repeat(32), ready_elapsed_micros: '5', expires_elapsed_micros: (chain.now + DAY).toString(), approvals: [] }];
  await refreshNow();
  assert.deepEqual(['signal-submit', 'signal-withdraw', 'signal-discard'].map(id => $(id).disabled), [true, true, true]);
  chain.recovery = []; await refreshNow();
  assert.deepEqual(['signal-submit', 'signal-withdraw', 'signal-discard'].map(id => $(id).disabled), [false, false, false]);
  // The review of a signal asks for a tick. Closed with the button that confirms and without the tick (a key held
  // down, or a button that something enabled), it counts as cancelled: nothing is signed.
  const plan = PLAN(); type(plan);
  let step = $('signal-form').fire('submit'), shown = await answer('confirm', { tick: false }); await step;
  assert.deepEqual([shown.title, shown.confirm, shown.askedFor, shown.disabledBefore, shown.disabledAfter], ['Support version 5 of the network\'s rules', 'Sign the signal', U.SUPPORT_ACKNOWLEDGE, true, true]);
  assert.deepEqual([chain.posted.length, $('notice').textContent], [0, 'Nothing was signed.']);
  // Ticked and confirmed: one action is posted, of kind 80, with the plan as typed, signed by this browser's key.
  type(plan); step = $('signal-form').fire('submit'); shown = await answer('confirm', { tick: true }); await step;
  assert.deepEqual([shown.disabledBefore, shown.disabledAfter], [true, false]);
  assert.deepEqual(chain.posted.map(action => [action.kind, action.publicKey, action.from, action.nonce, action.payload]), [[80, login.publicKey, '5', '4', { activate_elapsed_micros: plan.activate_elapsed_micros, spec: SPEC, version: '5' }]]);
  assert.match(textOf($('signal-result')), /^Done\. The signal is in block 901, and proven state of block 90\d shows that your validator supports version 5/);
  // A review that asks for no tick (every other review of the wallet) is as before: its button is enabled.
  chain.now += 700000000n; step = $('signal-withdraw').fire('click'); shown = await answer('cancel', { tick: true }); await step;
  assert.deepEqual([shown.askedFor, chain.posted.length, $('notice').textContent], [U.WITHDRAW_ACKNOWLEDGE, 1, 'Nothing was signed.']);
});

test('locking the wallet empties the tab: nothing typed and nothing shown is left for the next session', async () => {
  type(PLAN()); $('signal-payment').value = 'typed and not sent';
  await $('lock-button').fire('click');
  assert.deepEqual(['signal-version', 'signal-spec', 'signal-start', 'signal-payment'].map(id => $(id).value), ['', '', '', '']);
  assert.deepEqual([$('signal-node-ready').checked, $('tab-upgrade').hidden, $('panel-upgrade').hidden, $('signal-status').children.length, $('signal-result').children.length, $('signal-check').textContent], [false, true, true, 0, 0, '']);
});

test('a secured account: the signal is signed by the payment key with the payment password, never by the login key', async () => {
  // The account as the Security tab leaves it: this browser's key is now the login key (it may neither spend nor
  // manage), a payment key is kept under the payment password, and two recovery keys.
  alice().devices = [{ public_key: login.publicKey, can_manage: false, can_spend: false }, { public_key: spend.publicKey, can_manage: false, can_spend: true }, { public_key: sheet.publicKey, can_manage: true, can_spend: false }, { public_key: phrase.publicKey, can_manage: true, can_spend: false }];
  chain.security['5'] = { account: '5', version: '1', policy: { threshold: '2', daily_limit_micros: '60000000', delay_seconds: '172800', freeze_seconds: '172800' }, allowance_micros: '60000000', allowance_elapsed_micros: '0', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null };
  storage.setItem(`timecurrency.spend-vault.v1:${networkId}:alice`, JSON.stringify(await sealLegacy({ pkcs8: spend.secret.pkcs8 }, PAYMENT, { networkId, name: 'alice', publicKey: spend.publicKey }, argon2id, globalThis.crypto, 'spend')));
  chain.now += 700000000n; chain.posted.length = 0;
  await unlock();
  assert.equal($('signal-payment-wrap').hidden, false, 'the tab asks for the payment password');
  // Without the payment password nothing is signed.
  let step = $('signal-withdraw').fire('click'); await answer('confirm', { tick: true }); await step;
  assert.deepEqual([chain.posted.length, $('notice').textContent], [0, 'Enter your payment password.']);
  // With it: one action of kind 80, signed by the payment key.
  $('signal-payment').value = PAYMENT; step = $('signal-withdraw').fire('click'); const shown = await answer('confirm', { tick: true }); await step;
  assert.equal(shown.confirm, 'Sign the withdrawal');
  assert.deepEqual(chain.posted.map(action => [action.kind, action.publicKey === spend.publicKey, action.publicKey === login.publicKey, action.payload]), [[80, true, false, {}]]);
  assert.match(textOf($('signal-result')), /^Done\. The withdrawal is in block 90\d/);
  assert.equal($('signal-payment').value, '', 'the payment password is not left in the field');
  await $('lock-button').fire('click');
});

// A key held down must not sign (seen in Chrome on a live network on 2026-11-19: the Enter key that sent the form,
// still held, pressed the review's confirming button). Two measures, both needed: the focus is not on the button
// when the review opens, and a repeating key does nothing in the dialog. The effect in a real browser is checked
// by the browser check of a campaign (campaign/lib/browser-check.mjs, "wallet-enter-held").
test('in a review a key that repeats because it is held down presses nothing, and the review opens with the focus on its title', async () => {
  const listeners = $('review-dialog').listeners.keydown || [];
  assert.equal(listeners.length, 1, 'the review has one listener for keys');
  const press = (event) => { let prevented = false; listeners[0].fn({ ...event, preventDefault() { prevented = true; } }); return prevented; };
  assert.equal(press({ key: 'Enter', repeat: true }), true, 'a repeating Enter is stopped');
  assert.equal(press({ key: ' ', repeat: true }), true, 'a repeating space bar is stopped: it would tick the box');
  assert.equal(press({ key: 'Enter', repeat: false }), false, 'a new press of Enter is a person\'s own');
  assert.equal(press({ key: ' ', repeat: false }), false);
  assert.equal(press({ key: 'Tab', repeat: true }), false, 'moving through the dialog with a held Tab is not stopped');
  assert.equal(press({ key: 'Escape', repeat: true }), false, 'Escape closes the review as cancelled, held or not');
  // That the review puts the focus on its title when it opens is tested where `review` itself is run
  // (review-browser-review.test.mjs). An assertion over the source text stood here first and could not fail.
  // What the page must give for it: a title that can take the focus.
  assert.match(await readFile(new URL('./index.html', import.meta.url), 'utf8'), /<h2 id="review-title" tabindex="-1">/, 'the title can take the focus');
});

// The Validator operator panel (pos-ui.mjs), in plain words. Its retire button once had its listener twice; the
// wallet's one-action-at-a-time guard (`run`) made the second call do nothing, but one click must ask once.
test('the Validator operator panel: one listener per control, what it says of the validator, and one plain answer for a text that does not fit', async () => {
  for (const [id, type] of [['validator-retire', 'click'], ['validator-register-form', 'submit'], ['self-bond-form', 'submit'], ['self-unbond-form', 'submit']]) assert.equal(($(id).listeners[type] || []).length, 1, `${id} ${type}`);
  const { NOT_A_REGISTRATION } = await import(new URL('web-v4/wallet/pos-ui.mjs', root).href);
  await unlock();
  // What it says of the validator follows the chain: in the set, in line for it (registered, not there yet), or
  // without a bond and so out of it.
  assert.equal($('validator-summary').textContent, `Validator key ${'11'.repeat(32)} · your bond 86400 s · in the set`);
  const active = chain.active; chain.active = active.filter(v => v.owner !== '5'); await refreshNow();
  assert.equal($('validator-summary').textContent, `Validator key ${'11'.repeat(32)} · your bond 86400 s · in line for the set`);
  chain.candidates['5'].self_bond = '0'; await refreshNow();
  assert.equal($('validator-summary').textContent, `Validator key ${'11'.repeat(32)} · your bond 0 s · no bond, so not in the set`);
  chain.candidates['5'].self_bond = '86400000000'; chain.active = active; await refreshNow();
  chain.candidates['5'].jailed = true; await refreshNow();
  assert.match($('validator-summary').textContent, / · your bond 86400 s · removed for signing twice$/);
  chain.candidates['5'].jailed = false; chain.candidates['5'].archived = true; await refreshNow();
  assert.match($('validator-summary').textContent, / · retired; what is still owed can be taken out$/);
  const kept = chain.candidates['5']; delete chain.candidates['5']; await refreshNow();
  assert.equal($('validator-summary').textContent, 'This account has no validator. Run the join script on your server first: it prints the registration text to paste here.');
  chain.candidates['5'] = { ...kept, archived: false }; await refreshNow();
  // A pasted text that is not a registration of this account on this network: one plain answer, no review, nothing signed.
  const posted = chain.posted.length, registration = { commission_bps: 1000, consensus_key: '33'.repeat(32), networkId, owner: '5', proof: '44'.repeat(64) };
  for (const text of ['not a registration', 'null', '[]', JSON.stringify({ ...registration, owner: '6' }), JSON.stringify({ ...registration, networkId: 'ab'.repeat(32) }), JSON.stringify({ ...registration, extra: 1 }), 'x'.repeat(4097)]) {
    $('notice').textContent = ''; $('validator-enrollment').value = text; await $('validator-register-form').fire('submit');
    await until(() => $('notice').textContent === NOT_A_REGISTRATION, `the plain answer for ${text.slice(0, 30)}`);
    assert.deepEqual([$('review-dialog').open, chain.posted.length], [false, posted], text.slice(0, 30));
  }
  // One click on "Retire my validator" asks for one review, in the panel's words; cancelled, nothing is signed.
  let reviews = 0; const opened = $('review-dialog').showModal; $('review-dialog').showModal = function () { reviews += 1; return opened.call(this); };
  const step = $('validator-retire').fire('click'), shown = await answer('cancel', { tick: false }); await step;
  await new Promise(resolve => realTimeout(resolve, 50));
  $('review-dialog').showModal = opened;
  assert.deepEqual([shown.title, shown.askedFor, reviews, $('review-dialog').open, chain.posted.length], ['Retire my validator', null, 1, false, posted]);
  assert.match(textOf($('review-body')), /What happens Only a validator that has left the set and holds nothing any more can be retired\. Its key cannot be used again\./);
  await $('lock-button').fire('click');
});
