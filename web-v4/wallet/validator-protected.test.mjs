// A protected account runs its validator from the wallet (More, Validator operator: pos-ui.mjs; security-ui.mjs, stakeLimit
// and stakeAction; protection.mjs, validatorLimit): it registers the validator from a registration text, adds to its bond,
// takes the bond out, withdraws what was taken out and retires it, each with its payment password, each through the review,
// and each told beforehand what it does to the daily limit; an account with one key does all of it as before.
//
// The real app.js on the stand-in page of protection-card.test.mjs (copied from there): a page that makes its elements on
// demand, a browser storage, the real SDK and wallet modules, a stand-in for the compiled verifier, and a gateway in front
// of a stand-in chain. That chain applies the engine's rules to these actions, as read on 2026-11-23:
// - v5/src/engine.rs, `apply`, the branch of kinds 5 to 7 and 17 to 24 (lines 2954 to 3052): the account's nonce and
//   authority epoch; a key with `can_spend` ("spending device required"); for a protected account the row brought up to
//   date on the clock of the waits (`security.spend(0, now)`, `now` = `Meta::active_micros`); the action; the fee; and then
//   what the balance went down by, fee included, charged with `security.spend(before.saturating_sub(balance), now)`;
// - v5/src/security.rs, `Security::spend`, `charge`, `level`, `settle`, `frozen` (lines 403 to 475): nothing is charged
//   for an action that did not lower the balance, frozen or not; else refused while frozen, refused above what is left,
//   and taken from what is left. `level`, `settle` and `frozen` are those of tests/mock-security-chain.mjs;
// - v5/src/pos_adapter.rs, `apply` (lines 637 to 880) and pos/src/lib.rs: a registration takes the network's least bond
//   (`Profile::min_self_bond`: one second on a laboratory network, a day of seconds on a production one), an addition
//   its amount, taking out makes an exit and takes nothing, a withdrawal brings an exit back once it has waited 14 days
//   after the validator left, and retiring archives a validator that is in no set.
// Left out: the validator key's signature in the registration text (it is checked by pos::register, not here), slashing,
// the reward, the hold of a validator safety hold, and the order in which the engine checks what fails first.
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
const { level, settle, frozen } = await import(new URL('web-v4/wallet/tests/mock-security-chain.mjs', root).href);
const umdSource = await readFile(new URL('web-v4/wallet/vendor/argon2-4.12.0.umd.min.js', root), 'utf8'), umd = { exports: {} };
new Function('module', 'exports', umdSource)(umd, umd.exports);
const argon2id = umd.exports.argon2id;
const page = await readFile(new URL('./index.html', import.meta.url), 'utf8');

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
  async fire(type) { const list = this.listeners[type] || []; this.listeners[type] = list.filter(item => !item.once); await Promise.all(list.map(item => item.fn({ preventDefault() {}, data: null }))); }
}
const dom = new Map(), storage = new Storage(), intervals = [];
const $ = id => { if (!dom.has(id)) dom.set(id, new El(id)); return dom.get(id); };
const textOf = el => [el.textContent, ...(el.children || []).map(textOf)].filter(Boolean).join(' ');
const PANELS = [...page.matchAll(/<section class="workspace-panel" id="panel-([a-z]+)"/g)].map(found => found[1]);
const HIDDEN = [...page.matchAll(/<[a-z0-9]+\b[^>]*>/g)].map(found => found[0]).filter(tag => /\shidden(?=[\s>])/.test(tag)).map(tag => /\bid="([^"]+)"/.exec(tag)?.[1]).filter(Boolean);
for (const id of HIDDEN) $(id).hidden = true;
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
assert.ok(ARM_MS > 0, 'app.js names the delay of a review');
const arming = [];
globalThis.setTimeout = (fn, ms, ...given) => { if (ms === ARM_MS) { arming.push(() => fn(...given)); return null; } const timer = realTimeout(fn, ms, ...given); if (ms >= 60000) timer.unref(); return timer; };
const until = async (condition, what) => { for (let turn = 0; turn < 4000; turn++) { if (await condition()) return; await new Promise(resolve => realTimeout(resolve, 5)); } assert.fail(`waited in vain for: ${what} (the wallet's notice: ${$('notice').textContent})`); };

// ------------------------------------------------------------------ the stand-in chain
const NET = 'c6'.repeat(32), GENESIS = 1700000000000000n, HOUR = 3600000000n, DAY = 24n * HOUR, FEE = 1000n, S = 1000000n;
const PASSWORD = 'correct horse battery staple 41', PAYMENT = 'quiet harbour lanterns at dawn 77', LIMIT = 600n * S;
const BOND = { laboratory: S, production: 86400n * S };
// `rule`: the genesis has `waits_survive_stops`, and `stopped` is the total of the chain's stops. `now`: the chain's time.
const chain = { height: 900, now: 100n * DAY, rule: false, stopped: 0n, profile: 'laboratory', accounts: [], security: {}, candidates: {}, owners: {}, released: {}, active: [{ owner: '1', consensus_key: '11'.repeat(32), power: '1000' }], posted: [], refused: [], included: new Map(), nextExit: 1 };
chain.candidates['1'] = { owner: '1', consensus_key: '11'.repeat(32), jailed: false, archived: false, self_bond: BOND.production.toString(), pool_shares: '0', pool_assets: '0', commission_bps: 0, last_active_end: '0' };
/// The clock of the waits (`Meta::active_micros`).
const W = () => chain.now - (chain.rule ? chain.stopped : 0n);
const find = id => chain.accounts.find(item => item.id === String(id));
function stateFor(query) {
  const ids = query.ids || [], names = query.names || [], owners = query.owners || [];
  const exits = owners.flatMap(id => chain.owners[id]?.exits || []);
  return structuredClone({ protocol_version: '4', network_id: NET, height: String(chain.height), time_micros: (GENESIS + chain.now).toString(), genesis: { genesis_time_micros: GENESIS.toString() },
    config: { recovery_min_delay_micros: '30000000', recovery_approval_window_micros: '86400000000', all_new_time_to_validators: true, ...(chain.rule ? { waits_survive_stops: true } : {}) },
    ...(chain.rule ? { stopped_micros: chain.stopped.toString() } : {}),
    bank: '0', auction_epoch: '1', earning_epochs: {}, earning_bids: {}, name_commits: [], recovery_cases: [],
    accounts: chain.accounts.filter(item => ids.includes(item.id) || names.includes(item.name)),
    stake_owners: Object.fromEntries(owners.filter(id => chain.owners[id]).map(id => [id, chain.owners[id]])),
    release_times: Object.fromEntries(exits.map(exit => [exit.release_height, (GENESIS + chain.released[exit.id]).toString()])),
    candidates: Object.fromEntries((query.candidates || []).map(id => [id, chain.candidates[id] ?? null])),
    ...(query.include_security ? { security: chain.accounts.filter(item => ids.includes(item.id) || names.includes(item.name)).map(item => chain.security[item.id]).filter(Boolean) } : {}),
    ...(query.include_pos ? { pos: { profile: chain.profile, candidate_ids: Object.keys(chain.candidates).filter(id => !chain.candidates[id].archived), active: chain.active, scheduled: [], safety_hold: false, bootstrap_ended: true } } : {}),
    ...(query.include_upgrade ? { upgrade: null } : {}) });
}
const refuse = message => { throw new Error(message); };
/// One block that holds this action, by the rules above, or the refusal in the engine's words. Nothing changes on a refusal.
async function include(tx) {
  const action = SDK.decodeAction(tx), account = find(action.from);
  const key = await crypto.subtle.importKey('raw', SDK.hexToBytes(action.publicKey, 32), 'Ed25519', false, ['verify']);
  if (!await crypto.subtle.verify('Ed25519', key, tx.slice(-64), tx.slice(0, -64))) refuse('invalid action signature');
  if (!account || BigInt(action.nonce) !== BigInt(account.nonce) + 1n || action.authEpoch !== account.auth_epoch) refuse('stale authority or incorrect nonce');
  if (!account.devices.some(d => d.public_key === action.publicKey && d.can_spend)) refuse('spending device required');
  const now = W(), id = account.id, p = action.payload;
  const row = chain.security[id] ? structuredClone(chain.security[id]) : null;
  if (row) settle(row, now);
  const candidates = structuredClone(chain.candidates), owners = structuredClone(chain.owners), released = { ...chain.released };
  let debit = 0n, credit = 0n;
  const own = candidates[id], inSet = chain.active.some(v => v.owner === id);
  switch (action.kind) {
    case 17: {
      if (own) refuse('existing candidate/archive must settle before re-registration');
      if (Object.values(candidates).some(c => c.consensus_key === p.consensus_key)) refuse('consensus key was already reserved');
      debit = BOND[chain.profile];
      candidates[id] = { owner: id, consensus_key: p.consensus_key, jailed: false, archived: false, self_bond: debit.toString(), pool_shares: '0', pool_assets: '0', commission_bps: p.commission_bps, last_active_end: '0' };
      break;
    }
    case 18: if (!own) refuse('not a candidate'); if (own.jailed || own.archived || BigInt(p.amount) === 0n) refuse('jailed or zero self bond'); debit = BigInt(p.amount); own.self_bond = (BigInt(own.self_bond) + debit).toString(); break;
    case 19: {
      if (!own) refuse('unknown candidate'); if (BigInt(p.amount) > BigInt(own.self_bond)) refuse('unbond exceeds the bond');
      own.self_bond = (BigInt(own.self_bond) - BigInt(p.amount)).toString();
      const exit = { id: String(chain.nextExit), candidate: id, kind: 'self_bond', units: p.amount, requested_height: String(chain.height + 1), release_height: String(chain.height + 3) };
      (owners[id] ??= { owner: id, positions: [], exits: [] }).exits.push(exit); released[exit.id] = chain.now;
      break;
    }
    case 21: {
      const exit = owners[id]?.exits.find(e => e.id === p.entry); if (!exit) refuse('unknown exit');
      if (chain.now < released[exit.id] + 14n * DAY || inSet) refuse('unbond slash-exposure delay incomplete');
      owners[id].exits = owners[id].exits.filter(e => e !== exit); credit = BigInt(exit.units);
      break;
    }
    case 24: if (!own || own.archived) refuse('not a candidate'); if (inSet) refuse('candidate still has active/scheduled authority'); own.archived = true; break;
    default: refuse('this stand-in chain takes the actions of a validator\'s owner only');
  }
  const before = BigInt(account.balance), after = before - debit - FEE + credit;
  if (before < debit + FEE) refuse('insufficient balance');
  if (row) {
    const outflow = before > after ? before - after : 0n;
    if (outflow > 0n) {
      if (frozen(row, now)) refuse('account is frozen');
      const left = level(row, now);
      if (outflow > left) refuse('over the daily limit of this account: use a payment that waits, or a second proof');
      row.allowance_micros = (left - outflow).toString(); row.allowance_elapsed_micros = now.toString();
    }
    chain.security[id] = row;
  }
  Object.assign(chain, { candidates, owners, released }); account.balance = after.toString(); account.nonce = action.nonce;
  // The block's time is the time of the chain now: a test moves it on itself, so that what is left of the limit is exact.
  chain.height += 1;
  chain.included.set(await SDK.transactionHash(tx), { height: String(chain.height), rawHex: SDK.bytesToHex(tx) });
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
  const address = new URL(String(url), location.origin), route = address.pathname, trust = { app_version: '4', network_id: NET, chain_id: 'time-devnet-v4-test' };
  if (route === '/trust-manifest.json') return { ok: true, status: 200, json: async () => trust, text: async () => JSON.stringify(trust) };
  let answer;
  if (route === '/api/network') answer = { protocolVersion: '4', networkId: NET, chainId: trust.chain_id, mode: 'local-devnet', publicLaunchAllowed: false };
  else if (route === '/api/light-block') answer = block(address.searchParams.get('height') || chain.height);
  else if (route === '/api/view-proof') answer = { light_block: block(chain.height) };
  else if (route === '/api/submit') {
    const tx = new Uint8Array(Buffer.from(JSON.parse(options.body).tx, 'base64')), action = SDK.decodeAction(tx);
    chain.posted.push(action);
    try { await include(tx); answer = { hash: await SDK.transactionHash(tx) }; } catch (error) { chain.refused.push(error.message); answer = { error: error.message }; }
  } else if (route === '/api/receipt') { const hash = address.searchParams.get('hash'), found = chain.included.get(hash); answer = found ? { hash, ...found, anchor: { light_block: block(chain.height) } } : { error: 'no such transaction' }; }
  else if (route === '/api/notifications') answer = { items: [] };
  else answer = { error: 'not served by this stand-in gateway' };
  return { ok: !answer.error, status: answer.error ? 400 : 200, text: async () => JSON.stringify(answer), json: async () => answer };
};

// ------------------------------------------------------------------ carol_p, protected; dan, an account with one key
const { newDevice, hex } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const { sealLegacy } = await import(new URL('web-v4/wallet/tests/legacy-vault.mjs', root).href);
const login = await newDevice(), spend = await newDevice(), sheet = await newDevice(), phrase = await newDevice(), dan = await newDevice();
chain.accounts.push({ id: '14', name: 'carol_p', public_key: 'ee'.repeat(32), balance: (200000n * S).toString(), nonce: '7', auth_epoch: '2', recovery_policy: null, devices: [{ public_key: login.publicKey, can_manage: false, can_spend: false }, { public_key: spend.publicKey, can_manage: false, can_spend: true }, { public_key: sheet.publicKey, can_manage: true, can_spend: false }, { public_key: phrase.publicKey, can_manage: true, can_spend: false }] });
chain.accounts.push({ id: '15', name: 'dan', public_key: dan.publicKey, balance: (10n * S).toString(), nonce: '3', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: dan.publicKey, can_manage: true, can_spend: true }] });
const freshRow = () => ({ account: '14', version: '1', policy: { threshold: '2', daily_limit_micros: LIMIT.toString(), delay_seconds: '172800', freeze_seconds: '172800' }, allowance_micros: LIMIT.toString(), allowance_elapsed_micros: '0', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null });
chain.security['14'] = freshRow();
const vault = async (name, device) => storage.setItem(`timecurrency.vault.v1:${NET}:${name}`, JSON.stringify(await sealLegacy({ ...device.secret, nameSalt: hex(crypto.getRandomValues(new Uint8Array(32))), intent: 'device' }, PASSWORD, { networkId: NET, name, publicKey: device.publicKey }, argon2id)));
await vault('carol_p', login); await vault('dan', dan);
storage.setItem(`timecurrency.spend-vault.v1:${NET}:carol_p`, JSON.stringify(await sealLegacy({ pkcs8: spend.secret.pkcs8 }, PAYMENT, { networkId: NET, name: 'carol_p', publicKey: spend.publicKey }, argon2id, globalThis.crypto, 'spend')));

await import(new URL('web-v4/wallet/app.js', root).href);
await until(() => /^Connected to the Time test network/.test($('notice').textContent) || $('notice').className.includes('error'), 'the wallet to start');

async function unlock(name) {
  if ($('dashboard').hidden === false) await $('lock-button').fire('click');
  await $('mode-unlock').fire('click');
  $('username').value = name; $('password').value = PASSWORD; await $('auth-form').fire('submit');
  await until(() => $('dashboard').hidden === false && $('account-name').textContent === '@' + name && $('account-verification').textContent === 'Checked by this browser', `the account ${name} open`);
}
const refreshNow = () => $('refresh').fire('click');
/// The fields of the open review.
function fieldsOf() {
  const list = $('review-body').children.find(item => item.id === 'dl'), fields = {};
  for (let at = 0; at + 1 < (list?.children.length ?? 0); at += 2) fields[list.children[at].textContent] = list.children[at + 1].textContent;
  return fields;
}
/// A press, and the wallet's answer: the review it opened (confirmed, or cancelled), and then its notice.
async function press(fire, { confirm = true } = {}) {
  $('notice').textContent = ''; $('notice').className = 'notice';
  const running = fire();
  await until(() => $('review-dialog').open || ($('notice').textContent !== '' && !$('notice').className.includes('busy')), 'an answer or a review');
  let review = null;
  if ($('review-dialog').open) {
    review = { title: $('review-title').textContent, fields: fieldsOf(), asked: $('review-ack-wrap').hidden === false, lines: $('review-body').children.length };
    for (const fire of arming.splice(0)) fire();
    $('review-dialog').returnValue = confirm ? 'confirm' : 'cancel'; $('review-dialog').open = false; await $('review-dialog').fire('close');
  }
  await running;
  await until(() => !$('notice').className.includes('busy'), 'the action to end');
  return { review, notice: $('notice').textContent, error: $('notice').className.includes('error') };
}
/// A registration text as testnet/join.sh prints it (its proof is not checked by this chain), for an account and a validator key.
const text = (owner, key) => JSON.stringify({ commission_bps: 1000, consensus_key: key, networkId: NET, owner: String(owner), proof: '44'.repeat(64) });
const register = (owner, key = '3c'.repeat(32)) => { $('validator-enrollment').value = text(owner, key); return $('validator-register-form').fire('submit'); };
const bond = amount => { $('self-bond-amount').value = amount; return $('self-bond-form').fire('submit'); };
const unbond = amount => { $('self-unbond-amount').value = amount; return $('self-unbond-form').fire('submit'); };
/// The "Withdraw" of an exit listed under Validator operator (`validator-exits`).
const withdrawButton = () => $('validator-exits').children.map(row => row.children[1]).find(button => button?.textContent === 'Withdraw');
const posted = () => chain.posted.map(action => [action.kind, action.publicKey === spend.publicKey ? 'payment key' : action.publicKey === login.publicKey ? 'login key' : action.publicKey === dan.publicKey ? 'dan\'s key' : 'another key']);
const row = () => chain.security['14'], allowance = () => level(row(), W());
const SIGNED_BY = 'Your payment key, with your payment password';
const reset = () => { chain.posted.length = 0; chain.refused.length = 0; };

test('a protected account is offered the Validator operator: the payment password field, and every button', async () => {
  await unlock('carol_p');
  assert.equal($('validator-payment-wrap').hidden, false, 'the payment password is asked on the screen');
  assert.deepEqual(['validator-register-form', 'self-bond-form', 'self-unbond-form'].map(id => $(id).querySelector().disabled).concat($('validator-retire').disabled), [false, false, false, false]);
  assert.match(page, /<div id="validator-payment-wrap" hidden><label for="validator-payment">Payment password<\/label><input id="validator-payment" type="password" autocomplete="one-time-code" [^>]*maxlength="2048">/);
  assert.match(page, /<div id="validator-exits"><\/div>/);
});

test('registered from a registration text with the payment password: the review says what it takes of the daily limit, and the chain charges that', async () => {
  reset(); chain.profile = 'laboratory';
  const before = allowance(), balance = BigInt(find('14').balance);
  $('validator-payment').value = PAYMENT;
  const done = await press(() => register('14'));
  assert.equal(done.review.title, 'Register my validator');
  assert.deepEqual(done.review.fields, { 'Validator key': '3c'.repeat(32), Commission: '10%', Bond: '1 seconds, the network\'s least bond, taken from your balance now. It is lost if the validator signs two different blocks at one height.',
    'Daily limit': 'The bond and the fee, 1.001 seconds, count against your daily limit: 600 seconds is left today, 598.999 seconds after this.', 'Signed by': SIGNED_BY });
  // No name is in this review, so no likeness of names is looked for (names.mjs), and no box is asked.
  assert.deepEqual([done.review.asked, done.review.lines], [false, 1]);
  assert.deepEqual([done.notice, done.error, chain.refused], ['Register my validator finalized and verified.', false, []]);
  assert.deepEqual(posted(), [[17, 'payment key']]);
  assert.deepEqual([balance - BigInt(find('14').balance), before - allowance(), chain.candidates['14'].self_bond], [1001000n, 1001000n, '1000000']);
  assert.equal($('validator-payment').value, '', 'the payment password left the page');
  await until(() => $('validator-summary').textContent.includes('3c'.repeat(32)), 'the panel to show the validator');
  assert.equal($('validator-summary').textContent, `Validator key ${'3c'.repeat(32)} · your bond 1 s · in line for the set`);
});

test('added to, taken out, withdrawn and retired with the payment password, each charged as the engine charges it', async () => {
  reset();
  // An addition: the amount and the fee.
  let before = allowance(); $('validator-payment').value = PAYMENT;
  let done = await press(() => bond('5'));
  assert.deepEqual([done.review.title, done.review.fields['Daily limit'], done.review.fields['Signed by'], done.notice], ['Add to my validator\'s bond', 'The amount and the fee, 5.001 seconds, count against your daily limit: 598.999 seconds is left today, 593.998 seconds after this.', SIGNED_BY, 'Add to my validator\'s bond finalized and verified.']);
  assert.deepEqual([before - allowance(), chain.candidates['14'].self_bond], [5001000n, '6000000']);
  // Taking it out: the fee only.
  before = allowance(); $('validator-payment').value = PAYMENT;
  done = await press(() => unbond('6'));
  assert.deepEqual([done.review.title, done.review.fields['Daily limit'], done.notice], ['Take out of my validator\'s bond', 'The fee, 0.001 seconds, counts against your daily limit: 593.998 seconds is left today, 593.997 seconds after this.', 'Take out of my validator\'s bond finalized and verified.']);
  assert.deepEqual([before - allowance(), chain.candidates['14'].self_bond, chain.owners['14'].exits.length], [1000n, '0', 1]);
  // Fourteen days later the bond can be withdrawn, from the Validator operator: the engine charges nothing for it (it
  // brings back more than the fee), and the review says so.
  chain.now += 15n * DAY; await refreshNow();
  before = allowance(); const balance = BigInt(find('14').balance);
  assert.ok(withdrawButton(), 'the panel lists the bond taken out, with "Withdraw"');
  $('validator-payment').value = PAYMENT;
  done = await press(() => withdrawButton().fire('click'));
  assert.deepEqual([done.review.title, done.review.fields['Daily limit'], done.review.fields['Signed by'], done.notice], ['Withdraw mature stake', 'The seconds come back to your balance: nothing of your daily limit is used, unless less than the fee comes back.', SIGNED_BY, 'Withdraw mature stake finalized and verified.']);
  assert.deepEqual([before - allowance(), BigInt(find('14').balance) - balance, chain.owners['14'].exits.length], [0n, 6n * S - FEE, 0]);
  // Retired: the fee only.
  before = allowance(); $('validator-payment').value = PAYMENT;
  done = await press(() => $('validator-retire').fire('click'));
  // Fifteen days on, the limit has filled up again.
  assert.equal(before, LIMIT);
  assert.deepEqual([done.review.title, done.review.fields['Daily limit'], done.notice], ['Retire my validator', 'The fee, 0.001 seconds, counts against your daily limit: 600 seconds is left today, 599.999 seconds after this.', 'Retire my validator finalized and verified.']);
  assert.deepEqual([before - allowance(), chain.candidates['14'].archived], [FEE, true]);
  assert.deepEqual(posted(), [[18, 'payment key'], [19, 'payment key'], [21, 'payment key'], [24, 'payment key']]);
  assert.deepEqual(chain.refused, []);
});

test('above what is left of the daily limit, or above the limit itself: refused in words before any review, nothing unlocked or signed', async () => {
  reset(); delete chain.candidates['14']; chain.security['14'] = { ...freshRow(), allowance_micros: (100n * S).toString(), allowance_elapsed_micros: W().toString() };
  // An addition of 150 seconds while 100 are left: when enough has come back (the limit refills 600 seconds in 24 hours).
  chain.candidates['14'] = { owner: '14', consensus_key: '3c'.repeat(32), jailed: false, archived: false, self_bond: S.toString(), pool_shares: '0', pool_assets: '0', commission_bps: 1000, last_active_end: '0' };
  const back = W() + (150n * S + FEE - 100n * S) * DAY / LIMIT;
  const date = moment => new Date(Number((GENESIS + moment + (chain.rule ? chain.stopped : 0n)) / 1000n)).toLocaleString();
  $('validator-payment').value = PAYMENT;
  let done = await press(() => bond('150'));
  assert.deepEqual([done.review, done.error, done.notice], [null, true, `The amount and the fee, 150.001 seconds, are more than the 100 seconds left of your daily limit today, and the network lets none of it wait or be paid with a recovery paper: try again after ${date(back)}, when enough of it has come back.`]);
  assert.equal($('validator-payment').value, '', 'the payment password left the page');
  // A registration on a production network: its bond is a day of seconds, more than the limit itself.
  delete chain.candidates['14']; chain.profile = 'production'; chain.security['14'] = freshRow();
  $('validator-payment').value = PAYMENT;
  done = await press(() => register('14'));
  assert.deepEqual([done.review, done.error, done.notice], [null, true, 'The bond and the fee, 86400.001 seconds, are more than your daily limit of 600 seconds, and the network lets none of it wait or be paid with a recovery paper: raise the limit on Home to at least 86401 seconds (it waits 48 hours, or applies at once with a recovery paper), then try again once it has filled up, within a day.']);
  assert.deepEqual([posted(), chain.candidates['14']], [[], undefined]);
  // With a limit above it, and the allowance full, it goes through: the engine takes it.
  chain.security['14'] = { ...freshRow(), policy: { ...freshRow().policy, daily_limit_micros: (90000n * S).toString() }, allowance_micros: (90000n * S).toString() };
  $('validator-payment').value = PAYMENT;
  done = await press(() => register('14'));
  assert.deepEqual([done.review.fields['Daily limit'], done.notice], ['The bond and the fee, 86400.001 seconds, count against your daily limit: 90000 seconds is left today, 3599.999 seconds after this.', 'Register my validator finalized and verified.']);
  assert.deepEqual([posted(), chain.refused, chain.candidates['14'].self_bond], [[[17, 'payment key']], [], (86400n * S).toString()]);
  chain.profile = 'laboratory'; chain.security['14'] = freshRow();
});

test('frozen: each is refused in words before any review; without the payment password nothing is signed', async () => {
  reset(); chain.security['14'] = { ...freshRow(), frozen_until_elapsed_micros: (W() + HOUR).toString(), freezes: '1' }; await refreshNow();
  const said = {};
  for (const [name, fire] of [['register', () => { delete chain.candidates['14']; return register('14'); }], ['bond', () => { chain.candidates['14'] = { owner: '14', consensus_key: '3c'.repeat(32), jailed: false, archived: false, self_bond: S.toString(), pool_shares: '0', pool_assets: '0', commission_bps: 1000, last_active_end: '0' }; return bond('1'); }], ['unbond', () => unbond('1')], ['retire', () => $('validator-retire').fire('click')]]) {
    $('validator-payment').value = PAYMENT;
    const done = await press(fire);
    assert.equal(done.review, null, name); said[name] = done.notice;
  }
  assert.deepEqual(said, { register: 'Your account is frozen, so registering a validator is refused until the freeze ends. See Home.', bond: 'Your account is frozen, so adding to a validator\'s bond is refused until the freeze ends. See Home.', unbond: 'Your account is frozen, so taking a validator\'s bond out is refused until the freeze ends. See Home.', retire: 'Your account is frozen, so retiring a validator is refused until the freeze ends. See Home.' });
  assert.deepEqual(posted(), []);
  // Not frozen, and no payment password: the review, and then nothing is signed.
  chain.security['14'] = freshRow(); await refreshNow();
  $('validator-payment').value = '';
  const done = await press(() => bond('1'));
  assert.deepEqual([done.review.title, done.notice, posted()], ['Add to my validator\'s bond', 'Enter your payment password.', []]);
  // A review cancelled: nothing is signed, and the password typed for it is not left on the page.
  $('validator-payment').value = PAYMENT;
  const cancelled = await press(() => bond('1'), { confirm: false });
  assert.deepEqual([cancelled.review.title, posted(), $('validator-payment').value], ['Add to my validator\'s bond', [], '']);
});

test('on a network whose waits survive a stop, what is left and the freeze are read on the clock of the waits', async () => {
  reset(); chain.rule = true; chain.stopped = 6n * HOUR;
  try {
    const date = moment => new Date(Number((GENESIS + moment + chain.stopped) / 1000n)).toLocaleString();
    // Nothing was left an hour ago by the clock of the waits: 25 seconds have come back since. By the chain's time it
    // would be seven hours, 175 seconds, and the addition of 100 seconds would fit.
    chain.security['14'] = { ...freshRow(), allowance_micros: '0', allowance_elapsed_micros: (W() - HOUR).toString() };
    const back = W() + (100n * S + FEE - 25n * S) * DAY / LIMIT;
    $('validator-payment').value = PAYMENT;
    let done = await press(() => bond('100'));
    assert.deepEqual([done.review, done.notice], [null, `The amount and the fee, 100.001 seconds, are more than the 25 seconds left of your daily limit today, and the network lets none of it wait or be paid with a recovery paper: try again not before ${date(back)}, when enough of it has come back.`]);
    // Frozen for another hour by the clock of the waits, over five hours ago by the chain's time.
    chain.security['14'] = { ...freshRow(), frozen_until_elapsed_micros: (W() + HOUR).toString(), freezes: '1' };
    $('validator-payment').value = PAYMENT;
    done = await press(() => unbond('1'));
    assert.deepEqual([done.review, done.notice], [null, 'Your account is frozen, so taking a validator\'s bond out is refused until the freeze ends. See Home.']);
    assert.deepEqual(posted(), []);
  } finally { chain.rule = false; chain.stopped = 0n; chain.security['14'] = freshRow(); }
});

test('an account with one key: no payment password, the reviews as before, and its own key signs', async () => {
  reset(); await unlock('dan');
  assert.equal($('validator-payment-wrap').hidden, true);
  assert.deepEqual(['validator-register-form', 'self-bond-form', 'self-unbond-form'].map(id => $(id).querySelector().disabled).concat($('validator-retire').disabled), [false, false, false, false]);
  const done = await press(() => register('15', '5d'.repeat(32)));
  // The bond is named in the review of an account with one key too (web audit of November 2026, W-7).
  assert.deepEqual(done.review.fields, { 'Validator key': '5d'.repeat(32), Commission: '10%', Bond: '1 seconds, the network\'s least bond, taken from your balance now. It is lost if the validator signs two different blocks at one height.' });
  assert.deepEqual([done.notice, posted(), find('15').balance], ['Register my validator finalized and verified.', [[17, 'dan\'s key']], (9n * S - FEE).toString()]);
  const out = await press(() => unbond('1'));
  assert.deepEqual([Object.keys(out.review.fields), out.notice, posted().at(-1)], [['Amount', 'What happens'], 'Take out of my validator\'s bond finalized and verified.', [19, 'dan\'s key']]);
  await $('lock-button').fire('click');
});
