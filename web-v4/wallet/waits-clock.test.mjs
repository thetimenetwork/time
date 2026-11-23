// The clock of the waits (security-flows.mjs, waitsOf and momentOf; TimeSDK.securityNow and securityDeadline) in every
// place where the wallet compares a moment of a protected account's security row with "now", or shows one as a date.
//
// On a network whose genesis has `waits_survive_stops`, the moments a security row stores are on the clock of the waits:
// the chain's time since genesis less the total of the chain's stops (`stopped_micros` of every proven state). Here the
// chain stood still once for six hours, so that clock is six hours behind the chain's time. Read on the chain's time, a
// freeze that holds looks over, a payment that waits looks ready, a raise of the limit looks applied and the allowance
// looks refilled: each six hours too early. Each test below shows places that read the right clock, and fails where one
// of them reads the chain's time (the wallet before this clock: every one of them did). What a key signs is dated on the
// chain's time on every network, and stays so. On a network without the setting the two clocks are one and nothing
// changes (the last test).
//
// The real app.js on the stand-in page of protection-card.test.mjs (copied from there): a page that makes its elements on
// demand, a browser storage, the real SDK and wallet modules, a stand-in for the compiled verifier and a gateway that
// answers from a mock chain. This chain takes no action: every place tested here reads, or refuses before signing.
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
const security = await import(new URL('client-v4/account-security.mjs', root).href);
const F = await import(new URL('web-v4/wallet/security-flows.mjs', root).href);
const umdSource = await readFile(new URL('web-v4/wallet/vendor/argon2-4.12.0.umd.min.js', root), 'utf8'), umd = { exports: {} };
new Function('module', 'exports', umdSource)(umd, umd.exports);
const argon2id = umd.exports.argon2id;
const page = await readFile(new URL('./index.html', import.meta.url), 'utf8');

// ------------------------------------------------------------------ a stand-in page, which can be loaded again
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
const storage = new Storage(), intervals = [], windowListeners = {}, answered = [];
const $ = id => { if (!dom.has(id)) dom.set(id, new El(id)); return dom.get(id); };
const textOf = el => [el.textContent, ...(el.children || []).map(textOf)].filter(Boolean).join(' ');
const PANELS = [...page.matchAll(/<section class="workspace-panel" id="panel-([a-z]+)"/g)].map(found => found[1]);
const HIDDEN = [...page.matchAll(/<[a-z0-9]+\b[^>]*>/g)].map(found => found[0]).filter(tag => /\shidden(?=[\s>])/.test(tag)).map(tag => /\bid="([^"]+)"/.exec(tag)?.[1]).filter(Boolean);
globalThis.document = { getElementById: $, createElement: tag => new El(tag), querySelectorAll: selector => (selector === '.workspace-panel' ? PANELS.map(name => $('panel-' + name)) : []), addEventListener() {}, body: { append() {}, classList: { add() {}, remove() {} } }, title: '' };
Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: new Proxy(storage, { ownKeys: t => [...t.m.keys()], getOwnPropertyDescriptor: (t, k) => t.m.has(k) ? { enumerable: true, configurable: true, value: t.m.get(k) } : Reflect.getOwnPropertyDescriptor(t, k), get: (t, k) => typeof t[k] === 'function' ? t[k].bind(t) : t[k] }) });
Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { locks: { request: (name, options, fn) => fn() }, clipboard: { writeText: async () => {} } } });
globalThis.window = { addEventListener(type, fn) { (windowListeners[type] ??= []).push(fn); }, opener: null };
globalThis.location = { origin: 'https://wallet.example', pathname: '/' };
globalThis.isSecureContext = true;
globalThis.hashwasm = { argon2id };
globalThis.BroadcastChannel = undefined;
globalThis.setInterval = fn => { intervals.push(fn); return intervals.length; };
globalThis.clearInterval = id => { if (id) intervals[id - 1] = null; };
const realTimeout = globalThis.setTimeout;
const ARM_MS = Number(/\nconst REVIEW_ARM_MS = ([0-9]+);/.exec(await readFile(new URL('./app.js', import.meta.url), 'utf8'))?.[1]);
assert.ok(ARM_MS > 0, 'app.js names the delay of a review');
const arming = [];
globalThis.setTimeout = (fn, ms, ...given) => { if (ms === ARM_MS) { arming.push(() => fn(...given)); return null; } const timer = realTimeout(fn, ms, ...given); if (ms >= 60000) timer.unref(); return timer; };
const until = async (condition, what) => { for (let turn = 0; turn < 4000; turn++) { if (await condition()) return; await new Promise(resolve => realTimeout(resolve, 5)); } assert.fail(`waited in vain for: ${what} (the wallet's notice: ${$('notice').textContent})`); };

// ------------------------------------------------------------------ a mock chain that stood still for six hours
const NET = 'c6'.repeat(32), SHOP = 'https://shop.example', GENESIS = 1700000000000000n, HOUR = 3600000000n, DAY = 24n * HOUR, FEE = 1000n;
const PASSWORD = 'correct horse battery staple 41', PAYMENT = 'quiet harbour lanterns at dawn 77', SPEC = 'a3b1c5d7'.repeat(8);
const STOPPED = 6n * HOUR;
const other = (id, name) => ({ id: String(id), name, balance: '1000000', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: String(id % 10).repeat(64), can_manage: true, can_spend: true }] });
const candidate = owner => ({ owner: String(owner), consensus_key: '11'.repeat(32), jailed: false, archived: false, self_bond: '86400000000', pool_shares: '0', pool_assets: '0', commission_bps: 0, last_active_end: '0' });
// `rule`: the network's genesis has `waits_survive_stops`. `stopped`: the total of its stops, which every proven state
// of such a network carries. `now` is the chain's time since genesis.
const chain = { height: 900, now: 100n * DAY, rule: true, stopped: STOPPED, security: {}, posted: [], accounts: [other(1, 'faucet'), other(2, 'bob')],
  candidates: { 1: candidate(1), 14: candidate(14) }, active: [1, 14].map(owner => ({ owner: String(owner), consensus_key: '11'.repeat(32), power: '1000' })) };
/// The clock of the waits of this chain now.
const W = () => chain.now - (chain.rule ? chain.stopped : 0n);
function stateFor(query) {
  const ids = query.ids || [], names = query.names || [];
  const state = { protocol_version: '4', network_id: NET, height: String(chain.height), time_micros: (GENESIS + chain.now).toString(), genesis: { genesis_time_micros: GENESIS.toString() },
    config: { recovery_min_delay_micros: '30000000', recovery_approval_window_micros: '86400000000', all_new_time_to_validators: true, ...(chain.rule ? { waits_survive_stops: true } : {}) },
    ...(chain.rule ? { stopped_micros: chain.stopped.toString() } : {}),
    bank: '0', auction_epoch: '1', earning_epochs: {}, earning_bids: {}, stake_owners: {}, name_commits: [],
    accounts: chain.accounts.filter(item => ids.includes(item.id) || names.includes(item.name)), recovery_cases: [], candidates: Object.fromEntries((query.candidates || []).map(id => [id, chain.candidates[id] ?? null])) };
  if (query.include_security) state.security = state.accounts.map(item => chain.security[item.id]).filter(Boolean);
  if (query.include_pos) state.pos = { profile: 'production', candidate_ids: Object.keys(chain.candidates), active: chain.active, scheduled: [], safety_hold: false, bootstrap_ended: true };
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
globalThis.fetch = async (url, options = {}) => {
  const address = new URL(String(url), location.origin), route = address.pathname;
  let answer;
  const trust = { app_version: '4', network_id: NET, chain_id: 'time-devnet-v4-test' };
  if (route === '/trust-manifest.json') return { ok: true, status: 200, json: async () => trust, text: async () => JSON.stringify(trust) };
  if (route === '/api/network') answer = { protocolVersion: '4', networkId: NET, chainId: trust.chain_id, mode: 'local-devnet', publicLaunchAllowed: false };
  else if (route === '/api/light-block') answer = block(address.searchParams.get('height') || chain.height);
  else if (route === '/api/view-proof') answer = { light_block: block(chain.height) };
  // What is sent is kept, and refused: these tests look at what the wallet signs, never at what a chain makes of it.
  else if (route === '/api/submit') { chain.posted.push(SDK.decodeAction(new Uint8Array(Buffer.from(JSON.parse(options.body).tx, 'base64')))); answer = { error: 'not taken by this stand-in gateway' }; }
  else if (route === '/api/receipt') answer = { pending: true };
  else if (route === '/api/notifications') answer = { items: [] };
  else answer = { error: 'not served by this stand-in gateway' };
  return { ok: !answer.error, status: answer.error ? 400 : 200, text: async () => JSON.stringify(answer), json: async () => answer };
};

// ------------------------------------------------------------------ carol_p, protected, in this browser; dave_p, whose login key this browser lost
const { newDevice, sealVault, hex } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const login = await newDevice(), spend = await newDevice(), phrase = await newDevice(), lostLogin = await newDevice(), daveSpend = await newDevice();
// A recovery sheet as the wallet makes one: its words, which a person types, and the key they give.
const sheetSeed = F.newSheetSeed(), SHEET = await F.encodeSheet(sheetSeed), sheet = await F.keyFromSeed(sheetSeed);
const LIMIT = 600000000n;
chain.accounts.push({ id: '14', name: 'carol_p', balance: '9000000', nonce: '7', auth_epoch: '2', recovery_policy: null, devices: [{ public_key: login.publicKey, can_manage: false, can_spend: false }, { public_key: spend.publicKey, can_manage: false, can_spend: true }, { public_key: sheet.publicKey, can_manage: true, can_spend: false }, { public_key: phrase.publicKey, can_manage: true, can_spend: false }] });
chain.accounts.push({ id: '15', name: 'dave_p', balance: '9000000', nonce: '4', auth_epoch: '1', recovery_policy: null, devices: [{ public_key: '7'.repeat(64), can_manage: false, can_spend: false }, { public_key: daveSpend.publicKey, can_manage: false, can_spend: true }, { public_key: '8'.repeat(64), can_manage: true, can_spend: false }, { public_key: '9'.repeat(64), can_manage: true, can_spend: false }] });
const freshRow = (account = '14') => ({ account, version: '1', policy: { threshold: '2', daily_limit_micros: LIMIT.toString(), delay_seconds: '172800', freeze_seconds: '172800' }, allowance_micros: LIMIT.toString(), allowance_elapsed_micros: '0', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null });
chain.security['14'] = freshRow(); chain.security['15'] = freshRow('15');
const vault = async (name, device) => storage.setItem(`timecurrency.vault.v1:${NET}:${name}`, JSON.stringify(await sealVault({ ...device.secret, nameSalt: hex(crypto.getRandomValues(new Uint8Array(32))), intent: 'device' }, PASSWORD, { networkId: NET, name, publicKey: device.publicKey }, argon2id)));
const spendVault = async (name, device) => storage.setItem(`timecurrency.spend-vault.v1:${NET}:${name}`, JSON.stringify(await sealVault({ pkcs8: device.secret.pkcs8 }, PAYMENT, { networkId: NET, name, publicKey: device.publicKey }, argon2id, globalThis.crypto, 'spend')));
await vault('carol_p', login); await spendVault('carol_p', spend);
await vault('dave_p', lostLogin); await spendVault('dave_p', daveSpend);
/// The account's security row, changed for one test.
const set = (changes, account = '14') => { chain.security[account] = { ...freshRow(account), ...changes }; };

let pages = 0;
async function freshPage({ pathname = '/', opener = null } = {}) {
  if (pages > 0) await $('lock-button').fire('click');
  dom = new Map(); for (const type of Object.keys(windowListeners)) delete windowListeners[type];
  location.pathname = pathname; window.opener = opener;
  for (const id of HIDDEN) $(id).hidden = true;
  await import(new URL(`web-v4/wallet/app.js?waits=${++pages}`, root).href);
  await until(() => /^Connected to the Time test network/.test($('notice').textContent) || $('notice').className.includes('error') || !$('security-recover-panel').hidden, 'the wallet to start');
}
async function unlock(name = 'carol_p', shown = () => $('dashboard').hidden === false && $('account-name').textContent === '@' + name && $('account-verification').textContent === 'Checked by this browser') {
  await $('mode-unlock').fire('click');
  $('username').value = name; $('password').value = PASSWORD; await $('auth-form').fire('submit');
  await until(shown, `the account ${name} open`);
}
const refreshNow = async () => { await $('refresh').fire('click'); };
/// A moment of the clock of the waits as the page writes it: the stops added, as a date of this device.
const date = moment => new Date(Number((GENESIS + moment + (chain.rule ? chain.stopped : 0n)) / 1000n)).toLocaleString();
const card = () => ({ status: $('protect-status').textContent, alert: /\bwarning\b/.test($('protect-status').className), freeze: [$('freeze-switch').checked, $('freeze-switch-state').textContent], pause: [$('pause-switch').checked, $('pause-switch-state').textContent], bar: $('limit-bar').value, limit: $('limit-text').textContent, waiting: $('protect-waiting').textContent });
/// What waits, as "Waiting on your account" lists it (the login keys it lists too are left out).
const inbox = () => $('security-inbox').children.filter(item => !/^Login key/.test(textOf(item.children[0].children[0]))).map(item => ({ title: textOf(item.children[0].children[0]), detail: textOf(item.children[0].children[1] ?? { textContent: '' }), buttons: item.children.slice(1).map(b => b.textContent) }));
/// The fields of the open review.
function fieldsOf() {
  const list = $('review-body').children.find(item => item.id === 'dl'), fields = {};
  for (let at = 0; at + 1 < (list?.children.length ?? 0); at += 2) fields[list.children[at].textContent] = list.children[at + 1].textContent;
  return fields;
}
/// After a press: the wallet's answer, or the review it opened (then cancelled, and the test fails on what it asserts).
async function answerTo(press) {
  $('notice').textContent = ''; $('notice').className = 'notice';
  const running = press();
  await until(() => $('review-dialog').open || ($('notice').textContent !== '' && !$('notice').className.includes('busy')), 'an answer or a review');
  const review = $('review-dialog').open ? $('review-title').textContent : null;
  if (review) { $('review-dialog').returnValue = 'cancel'; $('review-dialog').open = false; await $('review-dialog').fire('close'); }
  await running;
  return { review, notice: $('notice').textContent, error: $('notice').className.includes('error') };
}

await freshPage();

test('the Protection card and Keys: a freeze that the clock of the waits still holds is shown as held, and it ends "not before" its date with the stops added', async () => {
  await unlock();
  set({ frozen_until_elapsed_micros: String(W() + 2n * HOUR), freezes: '1' }); await refreshNow();
  const ends = date(W() + 2n * HOUR);
  assert.deepEqual(card(), { status: `Your account is frozen. It ends not before ${ends} (about 2 hours).`, alert: true, freeze: [true, 'On'], pause: [false, 'Off'], bar: 0, limit: 'Nothing can be paid with your payment password alone while the account is frozen. Your daily limit is 600 seconds.', waiting: 'Nothing is waiting.' });
  assert.deepEqual([$('security-title').textContent, $('security-detail').textContent], ['Your account is frozen.', `No payments and no logins until the freeze ends, not before ${ends}.`]);
  // What a frozen account cannot use is not offered (security-ui.mjs, availability).
  assert.deepEqual([$('limit-open').disabled, $('pause-switch').disabled, $('stake-frozen-note').hidden, $('send-allowance').textContent], [true, true, false, 'You can pay 600 more seconds today, fees included. The account is frozen.']);
  // A payment with the payment password alone: no review, the choice of the frozen account (flows.choosePayment).
  $('recipient').value = 'bob'; $('amount').value = '1'; $('send-payment').value = PAYMENT;
  const paid = await answerTo(() => $('send-form').fire('submit'));
  assert.deepEqual([paid.review, $('send-over-limit').hidden, $('send-over-detail').textContent], [null, false, '1 seconds to @bob. Your account is frozen, so your payment password alone cannot pay, and nothing can wait. Your payment password with one recovery key can still pay.']);
  await $('send-over-cancel').fire('click');
  // A stake (flows.checkStake): refused in words, before any review.
  $('operator').value = '1'; $('stake-amount').value = '1'; $('stake-payment').value = PAYMENT;
  const staked = await answerTo(() => $('stake-form').fire('submit'));
  assert.deepEqual([staked.review, staked.error, staked.notice], [null, true, 'Your account is frozen, so staking, unbonding and withdrawing are refused until the freeze ends. See Home.']);
  assert.equal(chain.posted.length, 0, 'nothing was signed');
  // Pausing (security-ui.mjs, the pause step): refused while frozen, before any review.
  $('pause-payment').value = PAYMENT;
  const paused = await answerTo(() => $('pause-form').fire('submit'));
  assert.deepEqual([paused.review, paused.notice], [null, 'The account is frozen: nothing can be paid at once, paused or not.']);
});

test('a freeze in its first half cannot be placed again yet, by the clock of the waits, and the moment it can is "not before"', async () => {
  // 26 of 48 hours are left by the clock of the waits; by the chain's time it would be 20, past the half.
  set({ frozen_until_elapsed_micros: String(W() + 26n * HOUR), freezes: '1' }); await refreshNow();
  assert.equal($('freeze-note').textContent, `It ends by itself at that time and is not renewed by itself. To keep the account frozen longer, freeze again not before ${date(W() + 2n * HOUR)}: a freeze can be renewed in its second half only.`);
  assert.deepEqual([$('freeze-again').hidden, $('freeze-form').querySelector().disabled], [true, true]);
  // The freeze's own check refuses too (flows.freezePayload), whatever pressed it.
  $('freeze-method').value = 'payment'; $('freeze-secret').value = PAYMENT;
  const pressed = await answerTo(() => $('freeze-form').fire('submit'));
  assert.deepEqual([pressed.review, pressed.notice], [null, 'The account is already frozen.']);
});

test('what can be paid now refills on the clock of the waits, and a raise of the limit applies "not before" its date (Home, Keys, Send)', async () => {
  // Nothing was left an hour ago by the clock of the waits: a 24th of 600 seconds has come back since, not 7 hours' worth.
  set({ allowance_micros: '0', allowance_elapsed_micros: String(W() - HOUR) }); await refreshNow();
  assert.deepEqual([card().bar, card().limit], [41, 'You can pay 25 of 600 seconds now without waiting, fees included. It refills over 24 hours.']);
  assert.deepEqual([$('security-allowance').textContent, $('send-allowance').textContent, $('stake-allowance').textContent], ['25 s', 'You can pay 25 more seconds today, fees included.', 'Today\'s limit: you can stake 25 more seconds, fee included.']);
  // A raise to 1200 seconds that applies in three hours (protection.mjs, effectiveLimit): not in force yet.
  set({ pending_limit: { id: '3', daily_limit_micros: '1200000000', ready_elapsed_micros: String(W() + 3n * HOUR) }, next_id: '4' }); await refreshNow();
  assert.equal(card().limit, `You can pay 600 of 600 seconds now without waiting, fees included. A raise to 1200 seconds is waiting: it applies not before ${date(W() + 3n * HOUR)}.`);
  assert.equal($('security-limit').textContent, '600 s');
  assert.match(textOf($('keys-cards')), /Pays up to 600 seconds at once, fees included/, 'Keys (app.js, renderKeys) names the limit in force');
  assert.deepEqual(inbox(), [{ title: 'Waiting raise of the daily limit to 1200 seconds', detail: `Applies not before ${date(W() + 3n * HOUR)} (about 3 hours).`, buttons: ['Cancel'] }]);
  // The change of the limit compares with the limit in force (security-ui.mjs, limitChangeOf).
  await $('limit-open').fire('click'); $('limit-amount').value = '900'; await $('limit-amount').fire('input');
  assert.equal($('limit-when').textContent, 'Higher than now: it waits 48 hours, and you can cancel it meanwhile. With a recovery paper it applies at once.');
  // Its review names the limit in force now: 600 seconds, not the raise that has not come.
  $('limit-payment').value = PAYMENT;
  const running = $('limit-form').fire('submit');
  await until(() => $('review-dialog').open || $('notice').className.includes('error'), 'the review of the change');
  assert.deepEqual([$('review-title').textContent, fieldsOf().Now], ['Raise the daily limit', '600 seconds'], $('notice').textContent);
  $('review-dialog').returnValue = 'cancel'; $('review-dialog').open = false; await $('review-dialog').fire('close'); await running;
  await $('limit-cancel').fire('click');
});

test('a pause that ends by waiting stays a pause until the clock of the waits says so', async () => {
  set({ policy: { ...freshRow().policy, daily_limit_micros: FEE.toString() }, allowance_micros: FEE.toString(), allowance_elapsed_micros: String(W()), pending_limit: { id: '4', daily_limit_micros: LIMIT.toString(), ready_elapsed_micros: String(W() + 3n * HOUR) }, next_id: '5' }); await refreshNow();
  assert.deepEqual([card().pause, card().status, card().limit], [[true, 'On'], 'Payments are paused.', 'Paused: nothing can be paid at once.']);
  assert.match($('pause-note').textContent, new RegExp(` The pause ends not before ${date(W() + 3n * HOUR).replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')} \\(about 3 hours\\): your limit is then 600 seconds\\.$`));
  assert.match(textOf($('keys-cards')), /Payments are paused \(see Home\)/, 'Keys (app.js, renderKeys) says paused');
  // Ending it by waiting is already asked for: the review of asking again says when, "not before".
  await $('pause-switch').fire('change');
  $('resume-amount').value = '600'; $('resume-payment').value = PAYMENT;
  const running = $('resume-wait').fire('click');
  await until(() => $('review-dialog').open || $('notice').className.includes('error'), 'the review of ending the pause');
  const fields = {}, list = $('review-body').children.find(item => item.id === 'dl');
  for (let at = 0; at + 1 < (list?.children.length ?? 0); at += 2) fields[list.children[at].textContent] = list.children[at + 1].textContent;
  assert.equal(fields.When, `After 48 hours, not before ${date(W() + 48n * HOUR)}. Until then payments stay paused, and you can cancel this under “Waiting on your account”.`, $('notice').textContent);
  $('review-dialog').returnValue = 'cancel'; $('review-dialog').open = false; await $('review-dialog').fire('close'); await running;
  // Ending it at once with a recovery paper: offered while paused, and its review names the paused limit as the one now.
  await $('pause-switch').fire('change');
  $('resume-amount').value = '600'; $('resume-payment').value = PAYMENT; $('resume-method').value = 'phrase'; $('resume-secret').value = 'not read before the review';
  const ending = $('resume-now').fire('click');
  await until(() => $('review-dialog').open || $('notice').className.includes('error'), 'the review of ending the pause at once');
  assert.deepEqual([$('review-title').textContent, fieldsOf()['Daily limit']], ['End the pause now with a recovery paper', '600 seconds a day, at once (now 0.001 seconds)'], $('notice').textContent);
  $('review-dialog').returnValue = 'cancel'; $('review-dialog').open = false; await $('review-dialog').fire('close'); await ending;
  await $('resume-cancel').fire('click');
});

test('a payment that waits is not offered to be sent before its time, and a new one is said to wait "not before"', async () => {
  set({ allowance_micros: (2n * FEE).toString(), allowance_elapsed_micros: String(W()), pending_payments: [{ id: '5', to: '2', amount: '2000000', ready_elapsed_micros: String(W() + 2n * HOUR) }], next_id: '6' }); await refreshNow();
  assert.deepEqual(inbox(), [{ title: 'Waiting payment: 2 seconds to account 2', detail: `Can be sent not before ${date(W() + 2n * HOUR)} (about 2 hours).`, buttons: ['Cancel'] }]);
  assert.equal(card().waiting, '1 payment is waiting. See “Waiting on your account” below: each can be cancelled.');
  // Above what is left (two fees, by the clock of the waits): the choice to let it wait, and its review.
  $('recipient').value = 'bob'; $('amount').value = '1'; $('send-payment').value = PAYMENT;
  const paid = await answerTo(() => $('send-form').fire('submit'));
  assert.deepEqual([paid.review, $('send-over-limit').hidden, $('send-wait-note').textContent], [null, false, 'It waits 48 hours, then you send it from Home, under “Waiting on your account”. Until then you can cancel it.']);
  const running = $('send-wait').fire('click');
  await until(() => $('review-dialog').open || $('notice').className.includes('error'), 'the review of a payment that waits');
  const list = $('review-body').children.find(item => item.id === 'dl'), fields = {};
  for (let at = 0; at + 1 < (list?.children.length ?? 0); at += 2) fields[list.children[at].textContent] = list.children[at + 1].textContent;
  assert.equal(fields.Waits, `48 hours: it can be sent not before ${date(W() + 48n * HOUR)}`, $('notice').textContent);
  $('review-dialog').returnValue = 'cancel'; $('review-dialog').open = false; await $('review-dialog').fire('close'); await running;
  await $('send-over-cancel').fire('click');
});

test('a validator\'s signal: refused while less than a fee is left by the clock of the waits; a frozen owner is told when the freeze ends, "not before"', async () => {
  set({ allowance_micros: '500', allowance_elapsed_micros: String(W()) }); await refreshNow();
  await until(() => $('tab-upgrade').hidden === false && $('signal-status').children.length > 0, 'the signal screen');
  $('signal-version').value = '5'; $('signal-spec').value = SPEC; $('signal-start').value = (chain.now + 30n * DAY).toString(); $('signal-node-ready').checked = true;
  const signalled = await answerTo(() => $('signal-form').fire('submit'));
  assert.deepEqual([signalled.review, signalled.notice], [null, 'A signal costs the network fee, and less than that is left of your daily limit today. Try again later, or raise your daily limit on Home.']);
  // Frozen: the SDK reads the signal's facts on the clock of the waits; the date of the end has the stops added.
  set({ frozen_until_elapsed_micros: String(W() + 2n * HOUR), freezes: '1' }); await refreshNow();
  await $('signal-refresh').fire('click');
  const utc = new Date(Number((GENESIS + W() + 2n * HOUR + STOPPED) / 1000n)).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  await until(() => textOf($('signal-status')).includes('This account is frozen'), 'the signal screen to say the account is frozen');
  assert.match(textOf($('signal-status')), new RegExp(`This account is frozen; the freeze ends not before ${utc}\\. Until the freeze ends its signal does not count`));
  assert.equal(chain.posted.length, 0, 'nothing was signed');
});

test('what a key signs stays on the chain\'s time: a freeze signed here expires five minutes after the chain\'s time, not the clock of the waits', async () => {
  set({}); await refreshNow();
  await $('freeze-switch').fire('change'); $('freeze-method').value = 'payment'; $('freeze-secret').value = PAYMENT;
  const running = $('freeze-form').fire('submit');
  await until(() => $('review-dialog').open, 'the review of the freeze');
  for (const fire of arming.splice(0)) fire();
  $('review-dialog').returnValue = 'confirm'; $('review-dialog').open = false; await $('review-dialog').fire('close'); await running;
  await until(() => chain.posted.length > 0, 'the freeze to be sent');
  const freeze = chain.posted.at(-1);
  assert.deepEqual([freeze.kind, freeze.payload.expires_elapsed_micros], [72, String(chain.now + 5n * 60000000n)]);
  // The signed freeze waits for its receipt in this browser: it is retired by its signed expiry, on the chain's time.
  for (const key of Object.keys(storage.m).filter(k => k.startsWith('timecurrency.pending.v1:'))) storage.removeItem(key);
  chain.posted.length = 0;
  // Ending a freeze that the chain's time would call over: the builder compares with the clock of the waits (it is handed
  // that clock, security-ui.mjs, sendSecurity), and the approvals are dated ten minutes after the chain's time.
  set({ frozen_until_elapsed_micros: String(W() + 2n * HOUR), freezes: '1' }); await refreshNow();
  await $('freeze-switch').fire('change');
  assert.equal($('unfreeze-form').hidden, false, 'the switch of a frozen account opens "End the freeze"');
  $('unfreeze-payment').value = PAYMENT; $('unfreeze-method').value = 'sheet'; $('unfreeze-secret').value = SHEET;
  const ending = $('unfreeze-form').fire('submit');
  await until(() => $('review-dialog').open, 'the review of ending the freeze');
  for (const fire of arming.splice(0)) fire();
  $('review-dialog').returnValue = 'confirm'; $('review-dialog').open = false; await $('review-dialog').fire('close'); await ending;
  await until(() => chain.posted.length > 0 || $('notice').className.includes('error'), 'the end of the freeze to be sent');
  assert.deepEqual([chain.posted.at(-1)?.kind, chain.posted.at(-1)?.payload.expires_elapsed_micros], [73, String(chain.now + F.APPROVAL_LIFETIME_MICROS)], $('notice').textContent);
  for (const key of Object.keys(storage.m).filter(k => k.startsWith('timecurrency.pending.v1:'))) storage.removeItem(key);
  chain.posted.length = 0; set({}); await refreshNow();
});

test('a website\'s sign-in is refused while the clock of the waits says frozen (security-ui.mjs, loginRefusal)', async () => {
  set({ frozen_until_elapsed_micros: String(W() + 2n * HOUR), freezes: '1' });
  const website = { postMessage(message, origin) { answered.push({ message, origin }); } };
  await freshPage({ pathname: '/approve', opener: website }); await unlock();
  for (const listener of windowListeners.message) listener({ data: { type: 'time:request', version: 1, id: 'request-login-1', request: { type: 'login', challenge: { origin: SHOP, networkId: NET, expiresAt: Date.now() + 60000, nonce: 'ab'.repeat(16) } } }, source: website, origin: SHOP });
  assert.equal($('approval-title').textContent, 'Sign in to this website?');
  const asked = await answerTo(() => $('approve-request').fire('click'));
  assert.deepEqual([asked.review, asked.error, asked.notice], [null, true, 'The account is frozen: nobody signs in until the freeze ends or its keys are replaced']);
  // A website's payment (security-ui.mjs, payWebsite): refused too, before its review.
  await freshPage({ pathname: '/approve', opener: website }); await unlock();
  const carol = chain.accounts.find(a => a.name === 'carol_p'), orderId = SDK.orderReference({ nonce: (BigInt(carol.nonce) + 1n).toString(), expiresElapsedMicros: (chain.now + 600000000n).toString() });
  for (const listener of windowListeners.message) listener({ data: { type: 'time:request', version: 1, id: 'request-pay-1', request: { type: 'payment', networkId: NET, to: '2', amount: '100000', orderId } }, source: website, origin: SHOP });
  assert.equal($('approval-title').textContent, 'Pay this website?');
  $('approval-payment').value = PAYMENT;
  const paid = await answerTo(() => $('approve-request').fire('click'));
  assert.deepEqual([paid.review, paid.error, paid.notice], [null, true, 'Your account is frozen, so payments with your payment password alone are refused until the freeze ends. See Home.']);
  await freshPage();
});

test('a recovery on a new browser waits for the clock of the waits, and a browser whose login was removed is told the account is frozen', async () => {
  // This browser started a recovery of carol_p with its recovery papers: its new keys wait in a replacement of all keys.
  const newSignin = await newDevice(), newSpend = await newDevice();
  const ready = W() + 2n * HOUR;
  set({ pending_root: { devices: [{ public_key: newSignin.publicKey, can_manage: false, can_spend: false }, { public_key: newSpend.publicKey, can_manage: false, can_spend: true }, { public_key: sheet.publicKey, can_manage: true, can_spend: false }, { public_key: phrase.publicKey, can_manage: true, can_spend: false }], policy: freshRow().policy, ready_elapsed_micros: String(ready), expires_elapsed_micros: String(ready + 7n * DAY), approvals: [] } });
  storage.setItem(F.progressKey(NET, 'carol_p'), JSON.stringify(F.progressRecord({ networkId: NET, account: chain.accounts.find(a => a.name === 'carol_p'), signin: newSignin.publicKey, spend: newSpend.publicKey })));
  await freshPage();
  await until(() => !$('security-recover-panel').hidden && $('lost-status-text').textContent !== '', 'the recovery shown');
  assert.equal($('lost-status-text').textContent, `Recovery of @carol_p is waiting. You can finish it not before ${date(ready)} (about 2 hours). The account is frozen until then.`);
  assert.equal($('lost-finish-form').hidden, true, 'finishing is not offered before its time');
  // Its wait over and its claim window still open by the clock of the waits (by the chain's time it would have closed):
  // it can be finished, and what this browser keeps for it is not thrown away.
  const root = chain.security['14'].pending_root;
  set({ pending_root: { ...root, ready_elapsed_micros: String(W() - HOUR), expires_elapsed_micros: String(W() + HOUR) } });
  await $('lost-check').fire('click');
  await until(() => /waiting period is over/.test($('lost-status-text').textContent), 'the recovery ready');
  assert.deepEqual([$('lost-finish-form').hidden, $('lost-restart').hidden], [false, true]);
  $('notice').textContent = ''; await $('lost-restart').fire('click');
  assert.deepEqual([$('notice').textContent, storage.getItem(F.progressKey(NET, 'carol_p')) !== null], ['The recovery is still waiting. Refresh first.', true]);
  storage.removeItem(F.progressKey(NET, 'carol_p')); set({});
  // dave_p: this browser holds its payment key, and its login key was removed. While frozen no new login key is offered.
  set({ frozen_until_elapsed_micros: String(W() + 2n * HOUR), freezes: '1' }, '15');
  await freshPage(); await unlock('dave_p', () => !$('security-removed-panel').hidden && $('removed-status').textContent !== '');
  assert.equal($('removed-status').textContent, 'The account is frozen. A new login key can be made when the freeze ends.');
  // And a new login key is refused while frozen, before any review.
  $('removed-login-new').value = $('removed-login-confirm').value = 'violet otters dance beneath moonlight 41'; $('removed-payment').value = PAYMENT;
  const made = await answerTo(() => $('removed-login-form').fire('submit'));
  assert.deepEqual([made.review, made.notice], [null, 'The account is frozen. Try again when the freeze ends, or recover with your recovery sheet.']);
  set({}, '15'); await freshPage();
});

test('the account security functions compare with the clock of the waits and date what is signed on the chain\'s time', async () => {
  const flows = F.createSecurityFlows({ security });
  const account = chain.accounts.find(a => a.name === 'carol_p'), now = 100n * DAY, waitsNow = now - STOPPED;
  const signer = { publicKey: spend.publicKey, privateKey: spend.privateKey };
  // A freeze in its first half by the clock of the waits (26 of 48 hours left), past it by the chain's time.
  const first = { ...freshRow(), frozen_until_elapsed_micros: String(waitsNow + 26n * HOUR), freezes: '1' };
  assert.throws(() => flows.freezePayload({ security: first, now, waitsNow }), /The account is already frozen/);
  // Placed again in its second half: the freeze's own expiry is five minutes after the chain's time.
  const second = { ...first, frozen_until_elapsed_micros: String(waitsNow + 20n * HOUR) };
  assert.equal(flows.freezePayload({ security: second, now, waitsNow }).expires_elapsed_micros, String(now + 5n * 60000000n));
  assert.equal((await flows.buildFreeze({ networkId: NET, account, security: second, signer, now, waitsNow })).payload.expires_elapsed_micros, String(now + 5n * 60000000n));
  // A freeze that the chain's time would call over is still on: it can be ended, and nothing is paused or raised on top of it.
  const frozen = { ...freshRow(), frozen_until_elapsed_micros: String(waitsNow + 2n * HOUR), freezes: '1' }, recovery = { publicKey: sheet.publicKey, privateKey: sheet.privateKey };
  const ended = await flows.buildUnfreeze({ networkId: NET, account, security: frozen, spend: signer, recovery, now, waitsNow });
  assert.equal(ended.payload.expires_elapsed_micros, String(now + F.APPROVAL_LIFETIME_MICROS), 'the approvals are dated on the chain\'s time');
  await assert.rejects(flows.buildPause({ networkId: NET, account, security: frozen, spend: signer, feeMicros: FEE, now, waitsNow }), /The account is frozen/);
  await assert.rejects(flows.buildLimitNow({ networkId: NET, account, security: frozen, spend: signer, recovery, dailyLimitMicros: '700000000', feeMicros: FEE, now, waitsNow }), /The account is frozen/);
  // A raise not yet in force by the clock of the waits: the limit compared with is the old one.
  const raising = { ...freshRow(), pending_limit: { id: '3', daily_limit_micros: '1200000000', ready_elapsed_micros: String(waitsNow + 3n * HOUR) } };
  await assert.rejects(flows.buildLimit({ networkId: NET, account, security: raising, spend: signer, dailyLimitMicros: LIMIT.toString(), feeMicros: FEE, now, waitsNow }), /already has this value/);
  assert.equal((await flows.buildLimit({ networkId: NET, account, security: raising, spend: signer, dailyLimitMicros: '1200000000', feeMicros: FEE, now, waitsNow })).raise, true);
  // A replacement of all keys whose wait is not over by the clock of the waits cannot be finished.
  const newSpend = await newDevice();
  const waiting = { ...freshRow(), pending_root: { devices: [{ public_key: newSpend.publicKey, can_manage: false, can_spend: true }], policy: freshRow().policy, ready_elapsed_micros: String(waitsNow + 2n * HOUR), expires_elapsed_micros: String(waitsNow + 9n * DAY), approvals: [] } };
  await assert.rejects(flows.buildFinalize({ networkId: NET, account, security: waiting, spend: { publicKey: newSpend.publicKey, privateKey: newSpend.privateKey }, now, waitsNow }), /The waiting period is not over yet/);
  // The dates: the stops added, and "not before" while the moment has not come; exact, and no "not before", without the rule.
  const state = stateFor({}), moment = waitsNow + 2n * HOUR, at = F.momentOf(SDK, state, moment);
  assert.deepEqual([F.waitsOf(SDK, state), at.date.getTime(), at.later], [waitsNow, Number((GENESIS + moment + STOPPED) / 1000n), true]);
  chain.rule = false; const plain = stateFor({}), exact = F.momentOf(SDK, plain, moment); chain.rule = true;
  assert.deepEqual([F.waitsOf(SDK, plain), exact.date.getTime(), exact.later], [now, F.dateOf(plain, moment).getTime(), false]);
});

test('on a network without the setting nothing changes: the chain\'s time is the clock of the waits, and every date is exact', async () => {
  chain.rule = false;
  try {
    await freshPage(); await unlock();
    set({ frozen_until_elapsed_micros: String(chain.now + 2n * HOUR), freezes: '1', pending_payments: [{ id: '5', to: '2', amount: '2000000', ready_elapsed_micros: String(chain.now + 2n * HOUR) }], next_id: '6' }); await refreshNow();
    const ends = new Date(Number((GENESIS + chain.now + 2n * HOUR) / 1000n)).toLocaleString();
    assert.deepEqual([card().status, $('security-detail').textContent], [`Your account is frozen until ${ends} (about 2 hours).`, `No payments and no logins until ${ends}.`]);
    // The same row six hours on: by the chain's time the freeze is over, and the payment is ready.
    set({ frozen_until_elapsed_micros: String(chain.now - 4n * HOUR), freezes: '1', pending_payments: [{ id: '5', to: '2', amount: '2000000', ready_elapsed_micros: String(chain.now - 4n * HOUR) }], next_id: '6' }); await refreshNow();
    assert.deepEqual([card().status, card().freeze], ['Your account is protected.', [false, 'Off']]);
    assert.deepEqual(inbox(), [{ title: 'Waiting payment: 2 seconds to account 2', detail: 'Ready to send.', buttons: ['Send now', 'Cancel'] }]);
  } finally { chain.rule = true; set({}); await freshPage(); }
});
