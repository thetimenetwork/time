// The Validator signal tab: a validator owner's upgrade signal in the browser wallet
// (docs/design/upgrade-mechanism.md). Two parts.
//
// 1. upgrade-signal.mjs, which only computes: what the owner typed, how it relates to what is
//    proven, and every sentence of the tab.
// 2. The real upgrade-signal-ui.mjs (and, for a secured account, the real security-ui.mjs) on a
//    fake page and a mock chain, in the way security-review-ui.test.mjs runs the Security tab.
//    The mock chain takes a signal roughly as the engine does and has a node with its own
//    policy. app.js itself cannot be loaded outside a browser: its `sendSigned` is stood in for
//    here by a function that keeps the same pending record around a submission.
//
// Not exercised here: a browser. Layout, the dialog, the checkbox and the tab as a browser shows
// them are listed in the wallet's README as things a person must check.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { registerHooks } from 'node:module';

const root = new URL('../../', import.meta.url);
registerHooks({ resolve(s, context, next) { return next(s === '/sdk/account-security.mjs' ? new URL('client-v4/account-security.mjs', root).href : s, context); } });
await import(new URL('client-v4/time-sdk.js', root).href);
const SDK = globalThis.TimeSDK;
const umdSource = await readFile(new URL('web-v4/wallet/vendor/argon2-4.12.0.umd.min.js', root), 'utf8'), umd = { exports: {} };
new Function('module', 'exports', umdSource)(umd, umd.exports);
const argon2id = umd.exports.argon2id;

// ------------------------------------------------------------------ fake page
class Storage { m = new Map(); getItem(k) { return this.m.has(k) ? this.m.get(k) : null; } setItem(k, v) { this.m.set(k, String(v)); } removeItem(k) { this.m.delete(k); } }
let runs = [];
class El {
  constructor(id) { Object.assign(this, { id, value: '', hidden: false, textContent: '', disabled: false, checked: false, dataset: {}, type: 'text', children: [], listeners: {}, className: '', classList: { add() {}, remove() {}, toggle() {} } }); }
  addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn); }
  querySelectorAll() { return [this.querySelector()]; } querySelector() { return this.button ??= new El(this.id + '-button'); }
  replaceChildren(...c) { this.children = c; } append(...c) { this.children.push(...c); }
  async fire(type) { await Promise.all((this.listeners[type] || []).map(fn => fn({ preventDefault() {} }))); while (runs.length) await runs.shift(); }
}
let dom = new Map();
globalThis.document = { getElementById: id => { if (!dom.has(id)) dom.set(id, new El(id)); return dom.get(id); }, createElement: tag => new El(tag), querySelectorAll: () => [], body: { classList: { add() {}, remove() {} } } };
const storage = new Storage();
Object.defineProperty(globalThis, 'localStorage', { value: new Proxy(storage, { ownKeys: t => [...t.m.keys()], getOwnPropertyDescriptor: (t, k) => t.m.has(k) ? { enumerable: true, configurable: true, value: t.m.get(k) } : Reflect.getOwnPropertyDescriptor(t, k), get: (t, k) => typeof t[k] === 'function' ? t[k].bind(t) : t[k] }) });
Object.defineProperty(globalThis, 'navigator', { value: { locks: { request: (name, options, fn) => fn() } } });
globalThis.window = { print() {} };
const $ = id => document.getElementById(id);
/// All the text below an element of the fake page.
const textOf = el => [el.textContent, ...(el.children || []).map(textOf)].filter(Boolean).join(' ');

const U = await import(new URL('web-v4/wallet/upgrade-signal.mjs', root).href);
const { createSignalUI } = await import(new URL('web-v4/wallet/upgrade-signal-ui.mjs', root).href);
const { createSecurityUI } = await import(new URL('web-v4/wallet/security-ui.mjs', root).href);
const F = await import(new URL('web-v4/wallet/security-flows.mjs', root).href);
const { accountActionHeader } = await import(new URL('web-v4/wallet/actions.mjs', root).href);
const { newDevice, sealVault, b64 } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const { PendingReservations, formatSeconds } = await import(new URL('web-v4/wallet/guards.mjs', root).href);

// ------------------------------------------------------------------ a mock chain
const networkId = 'c6'.repeat(32), GENESIS = 1700000000000000n, DAY = 86400000000n, FEE = '1000';
const SPEC = 'a3b1c5d7'.repeat(8), OTHER = 'a3b1c5d7'.repeat(7) + 'a3b1c5d8';
const REFUSED_BY_NODE = 'this node does not implement that version under that specification hash and neither admits nor proposes signals for it';
let chain;
const validator = (owner, power = '1000') => ({ owner: String(owner), consensus_key: '11'.repeat(32), power: String(power) });
const candidate = (owner, more = {}) => ({ owner: String(owner), consensus_key: '11'.repeat(32), jailed: false, archived: false, self_bond: '86400000000', ...more });
const entry = (owner, plan, changed = '0') => ({ activate_elapsed_micros: plan.activate_elapsed_micros, changed_elapsed_micros: String(changed), owner: String(owner), spec: plan.spec, version: plan.version });
const byOwner = (a, b) => (BigInt(a.owner) < BigInt(b.owner) ? -1 : 1);
function stateOf() {
  return structuredClone({ protocol_version: '4', network_id: networkId, height: String(chain.height), time_micros: (GENESIS + chain.now).toString(), genesis: { genesis_time_micros: GENESIS.toString() }, config: { recovery_min_delay_micros: '30000000' },
    accounts: chain.accounts, recovery_cases: chain.recovery, security: Object.values(chain.rows), candidates: chain.candidates,
    upgrade: chain.signals.length || chain.plan ? { ...(chain.plan ? { plan: chain.plan } : {}), signals: [...chain.signals].sort(byOwner) } : null,
    pos: { profile: 'production', candidate_ids: Object.keys(chain.candidates), active: chain.active, scheduled: [], safety_hold: chain.hold } });
}
const statusFor = (id, state = stateOf()) => ({ ...SDK.signalStatusOf(state, { account: String(id), facts: SDK.signalFactsOf(state, chain.accounts.map(a => a.id)) }), heights: { first: state.height, last: state.height } });
/// What the SDK throws for a request the gateway refused.
const fromGateway = text => Object.assign(new Error(text), { gateway: true });
/// One block that holds this signal, roughly as the engine takes it: the node's own policy at
/// admission, the rules, the entry, and scheduling at four fifths.
function applySignal(action) {
  const account = chain.accounts.find(a => a.id === action.from), device = account?.devices.find(d => d.public_key === action.publicKey);
  if (!device?.can_spend) throw fromGateway('spending device required');
  if (BigInt(action.nonce) !== BigInt(account.nonce) + 1n || action.authEpoch !== account.auth_epoch) throw fromGateway('stale authority or incorrect nonce');
  const plan = Object.keys(action.payload).length ? action.payload : null;
  if (plan && !chain.implemented.some(known => known.version === plan.version && known.spec === plan.spec)) throw fromGateway(chain.nodeWords ?? REFUSED_BY_NODE);
  const judged = SDK.judgeSignal(statusFor(action.from), plan ? { version: plan.version, spec: plan.spec, activateElapsedMicros: plan.activate_elapsed_micros } : { withdraw: true });
  if (!judged.ok) throw fromGateway('refused by the rules: ' + judged.refusal);
  chain.height += 1; chain.now += 1000000n;
  account.nonce = action.nonce; account.balance = String(BigInt(account.balance) - BigInt(FEE));
  chain.signals = chain.signals.filter(item => item.owner !== action.from).concat([plan ? entry(action.from, plan, chain.now) : { changed_elapsed_micros: String(chain.now), owner: action.from }]);
  const after = statusFor(action.from);
  if (chain.plan && !after.plans.find(item => item.scheduled)?.tally.keep) chain.plan = null;
  const winner = after.plans.find(item => item.tally.schedule);
  if (!chain.plan && winner && !chain.hold) chain.plan = { activate_elapsed_micros: winner.activate_elapsed_micros, scheduled_elapsed_micros: String(chain.now), spec: winner.spec, version: winner.version };
}
const client = {
  getSignalStatus: async id => { client.reads += 1; if (client.failRead) throw client.failRead; return statusFor(id, client.stale?.shift() ?? stateOf()); },
  submit: async tx => { const action = SDK.decodeAction(tx); client.submitted.push(action); if (client.failSubmit) throw client.failSubmit; applySignal(action); return { verified: true, hash: await SDK.transactionHash(tx), height: String(chain.height), action }; },
  waitReceipt: async () => { throw new Error('none'); }, reads: 0, submitted: [],
};

// ------------------------------------------------------------------ a wallet tab
let errors, reviews, notices, recorded, tab;
const pending = new PendingReservations(localStorage);
const ownAccount = (state = stateOf()) => state.accounts.find(a => a.name === 'alice');
/// What app.js `sendSigned` does around a submission, with the same checks of the key and the same pending record.
async function sendSigned(kind, payload, label, { signer } = {}) {
  if (signer) F.assertSpendKeySigns(kind);
  const account = ownAccount(), key = signer || { publicKey: tab.session.binding.publicKey, privateKey: tab.session.privateKey };
  const args = accountActionHeader({ account, publicKey: key.publicKey, networkId, kind, payload });
  assert.equal(pending.get(networkId, account.id), null, 'A signed action is already pending.');
  const tx = await SDK.signAction(args, key.privateKey), hash = await SDK.transactionHash(tx);
  pending.put(networkId, account.id, { hash, tx: b64(tx), nonce: args.nonce, authEpoch: args.authEpoch, kind, label, at: Date.now() });
  const receipt = await client.submit(tx);
  pending.clear(networkId, account.id, hash); recorded.push(label);
  return receipt;
}
const PLAN = () => ({ version: '5', spec: SPEC, activate_elapsed_micros: (chain.now + 30n * DAY).toString() });
/// A fresh world: alice (account 5) owns one of five equal validators; this tab is unlocked with her key.
async function world({ secured = false } = {}) {
  storage.m.clear(); dom = new Map(); runs = []; errors = []; reviews = []; notices = []; recorded = [];
  Object.assign(client, { reads: 0, submitted: [], failRead: null, failSubmit: null, stale: null });
  const full = await newDevice();
  chain = { height: 900, now: 100n * DAY, recovery: [], rows: {}, signals: [], plan: null, hold: false, nodeWords: null, implemented: [{ version: '5', spec: SPEC }],
    accounts: [1, 2, 3, 4].map(id => ({ id: String(id), name: 'owner_' + id, balance: '5000000', nonce: '0', auth_epoch: '0', devices: [{ public_key: '2' + String(id).repeat(63), can_manage: true, can_spend: true }] })),
    candidates: Object.fromEntries([1, 2, 3, 4, 5].map(id => [String(id), candidate(id)])), active: [1, 2, 3, 4, 5].map(id => validator(id)) };
  chain.accounts.push({ id: '5', name: 'alice', balance: '5000000', nonce: '3', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: full.publicKey, can_manage: true, can_spend: true }] });
  tab = { session: { binding: { networkId, name: 'alice', publicKey: full.publicKey }, privateKey: full.privateKey }, full, review: true };
  const c = {
    sdk: SDK, client: () => client, network: () => ({ networkId }), session: () => tab.session, state: () => stateOf(), ownAccount, verifiedState: async () => stateOf(), refresh: async () => {},
    review: async (title, fields, confirm, options) => { reviews.push({ title, fields, confirm, options }); if (tab.whileReviewing) await tab.whileReviewing(); return tab.review; }, notice: (text, type = '') => notices.push({ text, type }),
    run: fn => { const p = (async () => { try { await fn(); } catch (error) { errors.push(error); } })(); runs.push(p); return p; }, setBusy() {}, capture: () => () => {},
    seconds: v => formatSeconds(String(v)), fee: () => FEE, pending, record() {}, lock() {}, argon2id: () => argon2id, showUnlock() {}, sendSigned,
  };
  if (secured) {
    // The account as the Security tab leaves it: a login key (this browser's session), a payment key under the payment password, two recovery keys.
    const signin = await newDevice(), spend = await newDevice(), sheet = await newDevice(), phrase = await newDevice(), alice = chain.accounts.at(-1);
    alice.devices = [{ public_key: signin.publicKey, can_manage: false, can_spend: false }, { public_key: spend.publicKey, can_manage: false, can_spend: true }, { public_key: sheet.publicKey, can_manage: true, can_spend: false }, { public_key: phrase.publicKey, can_manage: true, can_spend: false }];
    chain.rows['5'] = { account: '5', version: '1', policy: { threshold: '2', daily_limit_micros: '60000000', delay_seconds: '172800', freeze_seconds: '172800' }, allowance_micros: '60000000', allowance_elapsed_micros: '0', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null };
    storage.setItem(`timecurrency.spend-vault.v1:${networkId}:alice`, JSON.stringify(await sealVault({ pkcs8: spend.secret.pkcs8 }, PAYMENT, { networkId, name: 'alice', publicKey: spend.publicKey }, argon2id, globalThis.crypto, 'spend')));
    tab.session = { binding: { networkId, name: 'alice', publicKey: signin.publicKey }, privateKey: signin.privateKey }; tab.spend = spend;
    tab.security = createSecurityUI(c);
  }
  // `storage` is the browser's storage of this world: what the tab remembers of the account's signal outlives a page.
  tab.make = (store = storage) => createSignalUI({ ...c, storage: store, pause: async ms => { tab.paused = (tab.paused || 0) + ms; }, secured: () => secured, spendRefusal: async () => (secured ? tab.security.signalRefusal() : null), sign: (payload, label) => (secured ? tab.security.signalAction(payload, label) : sendSigned('upgrade_signal', payload, label)) });
  tab.ui = tab.make();
  return tab;
}
const PAYMENT = 'quiet harbour lanterns at dawn 77';
/// Shows the tab for alice and waits for its first reading.
async function open() { tab.ui.render(ownAccount(), stateOf()); await tab.ui.load().catch(() => {}); errors.length = 0; }
function type(plan, { tick = true } = {}) { $('signal-version').value = plan.version; $('signal-spec').value = plan.spec; $('signal-start').value = plan.activate_elapsed_micros; $('signal-node-ready').checked = tick; }
const submit = () => $('signal-form').fire('submit');
const reviewed = name => reviews.at(-1).fields.find(([key]) => key === name)?.[1];
const utc = elapsed => U.utc(GENESIS.toString(), elapsed);

// ================================================================== 1. what only computes

test('what the owner typed: three values in their one form; a hash with a space, as this page shows hashes, is not taken', () => {
  const good = { version: '5', spec: SPEC, start: '1814400000000' };
  assert.deepEqual(U.parsePlanInput(good), { version: '5', spec: SPEC, activateElapsedMicros: '1814400000000' });
  // Space around a value is dropped, and a hash in capital letters is the same hash.
  assert.deepEqual(U.parsePlanInput({ version: ' 5 ', spec: `\t${SPEC.toUpperCase()}\n`, start: ' 1814400000000' }), { version: '5', spec: SPEC, activateElapsedMicros: '1814400000000' });
  for (const version of ['', '0', '05', '5.0', 'v5', '-5', '5 6', '18446744073709551616', 5, null, undefined]) assert.throws(() => U.parsePlanInput({ ...good, version }), /Enter the version as the release announcement gives it/, String(version));
  for (const start of ['', '0', '01', '2027-03-01', '1e12', '1814400000000.0', '18446744073709551616', 1814400000000, null]) assert.throws(() => U.parsePlanInput({ ...good, start }), /Enter the start time as the release announcement gives it/, String(start));
  assert.throws(() => U.parsePlanInput({ ...good, spec: '' }), /Enter the specification hash from the release announcement/);
  // The grouped form in which the page shows proven hashes, and any other spacing.
  for (const spec of [U.groupHash(SPEC), SPEC.slice(0, 32) + ' ' + SPEC.slice(32), SPEC.slice(0, 32) + '\n' + SPEC.slice(32)]) assert.throws(() => U.parsePlanInput({ ...good, spec }), /one run of 64 characters, with no spaces\. Do not copy it from this page\./, spec);
  for (const spec of ['0x' + SPEC.slice(2), SPEC.slice(0, 63) + 'g', SPEC.slice(0, 63) + '…', 'sha256:' + SPEC]) assert.throws(() => U.parsePlanInput({ ...good, spec }), /only the characters 0 to 9 and a to f/, spec);
  assert.throws(() => U.parsePlanInput({ ...good, spec: SPEC.slice(1) }), /has 64 characters\. You entered 63\./);
  assert.throws(() => U.parsePlanInput({ ...good, spec: SPEC + 'a3' }), /You entered 66\./);
  assert.equal(U.groupHash(SPEC), 'a3b1c5d7 a3b1c5d7 a3b1c5d7 a3b1c5d7 a3b1c5d7 a3b1c5d7 a3b1c5d7 a3b1c5d7');
});

test('how values are shown: times in UTC, shares rounded down, lengths of time in words', () => {
  assert.equal(U.utc('1700000000000000', '0'), '2023-11-14 22:13:20 UTC');
  assert.equal(U.utc('1700000000000000', '1814400000000'), '2023-12-05 22:13:20 UTC');
  assert.equal(U.utc('1700000000000000', '18446744073709551615'), 'a date beyond the calendar');
  // A share just under a threshold is never shown as the threshold.
  assert.deepEqual([U.share('4000', '5000'), U.share('3999', '5000'), U.share('79999', '100000'), U.share('3', '4'), U.share('0', '7'), U.share('1', '3'), U.share('5', '5'), U.share('1', '0')], ['80.00%', '79.98%', '79.99%', '75.00%', '0.00%', '33.33%', '100.00%', '0.00%']);
  assert.deepEqual(['1814400000000', '10368000000000', '600000000', '3600000000', '120000000', '1000000', '60000000', '86400000000', '90000000'].map(U.duration), ['21 days', '120 days', '10 minutes', '1 hour', '2 minutes', '1 second', '1 minute', '1 day', '90 seconds']);
});

test('the plan against what is proven: the scheduled plan, a plan others signalled, a new one, and a plan that is close but not the same', async () => {
  await world();
  const plan = PLAN(), typed = { version: plan.version, spec: plan.spec, activateElapsedMicros: plan.activate_elapsed_micros };
  // Nobody has signalled.
  let status = statusFor('5'), match = U.planMatch(status, typed);
  assert.deepEqual([match.kind, match.plan, match.near], ['new', null, []]);
  assert.equal(U.matchText(status, match), 'No validator of the current validator sets has signalled exactly this plan.');
  // Two validators support exactly it.
  chain.signals = [entry(1, plan), entry(2, plan)]; status = statusFor('5'); match = U.planMatch(status, typed);
  assert.equal(match.kind, 'signalled');
  assert.equal(U.matchText(status, match), '2 validators with 40.00% of the votes support exactly this plan. It is scheduled at four fifths (80%).');
  // The same version and start with another hash: the case to stop at.
  const typo = U.planMatch(status, { ...typed, spec: OTHER });
  assert.deepEqual([typo.kind, typo.near.map(item => item.differs)], ['new', [['specification hash']]]);
  assert.deepEqual(U.nearTexts(status, typo), [`A plan that 2 validators with 40.00% of the votes support differs from what you entered in the specification hash: it is version 5, start ${utc(plan.activate_elapsed_micros)}, specification hash ${U.groupHash(SPEC)}. If you meant that plan, cancel, and compare what you entered with the release announcement. If the announcement gives what you entered, go on: your signal then counts for your plan only.`]);
  // Only that case is called similar. Another start time, also under the same hash, is another plan, and so is
  // another version: whoever signals cannot put a warning into the review of every owner.
  assert.deepEqual(U.planMatch(status, { ...typed, activateElapsedMicros: (BigInt(plan.activate_elapsed_micros) + 1n).toString() }).near, []);
  assert.deepEqual(U.planMatch(status, { ...typed, spec: OTHER, activateElapsedMicros: (BigInt(plan.activate_elapsed_micros) + 1n).toString() }).near, []);
  assert.deepEqual(U.planMatch(status, { version: '6', spec: OTHER, activateElapsedMicros: '1' }).near, []);
  // Scheduled.
  chain.signals = [1, 2, 3, 4].map(owner => entry(owner, plan)); chain.plan = { ...plan, scheduled_elapsed_micros: String(chain.now) }; status = statusFor('5'); match = U.planMatch(status, typed);
  assert.equal(match.kind, 'scheduled');
  assert.equal(U.matchText(status, match), 'This is the scheduled plan. 4 validators with 80.00% of the votes support it.');
  assert.match(U.nearTexts(status, U.planMatch(status, { ...typed, spec: OTHER }))[0], /^The scheduled plan \(4 validators with 80\.00% of the votes\) differs from what you entered in the specification hash/);
});

test('the status in words: the version, the plan, the hold, the validator, its signal, and when it may change', async () => {
  await world();
  const plan = PLAN();
  let lines = U.statusLines(statusFor('5'));
  assert.deepEqual(lines.summary, ['The network runs version 4 of its rules.', 'No change of the rules is scheduled.']);
  assert.deepEqual(lines.own, ['Your validator holds 1000 of 5000 votes in the validator set in force (20.00%).', 'Your validator has not signalled.']);
  assert.deepEqual(lines.plans, []);
  assert.equal(lines.note, `Read from proven state of block 900, dated ${utc(chain.now)}. The validator sets and the signals are those of block 900.`);
  assert.deepEqual(lines.validators[4], { title: 'Validator of account 5 (yours)', detail: '1000 votes · no signal' });
  // Three validators and alice support the plan; it is scheduled; one of them is frozen.
  chain.signals = [1, 2, 3, 5].map(owner => entry(owner, plan, chain.now - 60000000n)); chain.plan = { ...plan, scheduled_elapsed_micros: String(chain.now) }; chain.hold = true;
  lines = U.statusLines(statusFor('5'));
  assert.equal(lines.summary[1], `Version 5 is scheduled. It starts on ${utc(plan.activate_elapsed_micros)} at the earliest, if it keeps three quarters (75%) of the votes in every block until then. This app does not know that version: update it before then.`);
  assert.match(lines.summary[2], /^A validator safety hold is on.*Nothing is scheduled and nothing starts while it lasts\. Signals are still taken\.$/);
  assert.equal(lines.own[1], `Your validator supports version 5, start ${utc(plan.activate_elapsed_micros)}, specification hash ${U.groupHash(SPEC)}. It signalled this on ${utc(chain.now - 60000000n)}.`);
  assert.equal(lines.own[2], `The network takes one change of a validator's signal every 10 minutes. You can change yours again after ${utc(chain.now + 540000000n)}.`);
  assert.deepEqual(lines.plans, [{ title: `Version 5, start ${utc(plan.activate_elapsed_micros)}`, hash: U.groupHash(SPEC), lines: ['Supported by 4 of 5 validators: 4000 of 5000 votes (80.00%).', 'Scheduled. It keeps the three quarters (75%) it needs.'] }]);
  assert.equal(lines.validators[0].detail, `1000 votes · supports version 5, start ${utc(plan.activate_elapsed_micros)}, hash ${U.groupHash(SPEC)}`);
  // Not scheduled, below four fifths; and a tally this wallet could not complete says so.
  chain.plan = null; chain.hold = false; chain.signals = [entry(1, plan), entry(2, plan)];
  assert.deepEqual(U.statusLines(statusFor('5')).plans[0].lines, ['Supported by 2 of 5 validators: 2000 of 5000 votes (40.00%).', 'Not scheduled. It needs four fifths (80%) of the votes.']);
  const partial = SDK.signalStatusOf({ ...stateOf(), accounts: [ownAccount()] }, { account: '5' }); // the other owners' accounts are not in this proof
  assert.deepEqual(U.statusLines(partial).plans[0].lines.slice(0, 2), ['Supported by 2 of 5 validators: 2000 of 5000 votes (40.00%).', 'Not scheduled. A plan is scheduled at four fifths (80%) of the votes the network counts. This wallet could not check that count.']);
  assert.match(U.statusLines(partial).plans[0].lines[2], /could not read whether the owner account is frozen or in a recovery.*the share the network counts can be lower or higher than shown\./);
  // Every other sentence that states that share carries the same caveat: the line under the form, the review, the results.
  const typed = { version: plan.version, spec: plan.spec, activateElapsedMicros: plan.activate_elapsed_micros };
  const unchecked = '2 validators with 40.00% of the votes (not checked: this wallet could not read whether each of these signals counts, or which validators are jailed, so the share the network counts can be lower or higher)';
  assert.equal(U.matchText(partial, U.planMatch(partial, typed)), `${unchecked} support exactly this plan. It is scheduled at four fifths (80%).`);
  assert.equal(U.nearTexts(partial, U.planMatch(partial, { ...typed, spec: OTHER }))[0].startsWith(`A plan that ${unchecked} support differs from what you entered in the specification hash`), true);
  // A scheduled plan whose count was not checked: "scheduled" is proven; whether it keeps its three quarters is not said.
  const scheduledPartial = SDK.signalStatusOf({ ...stateOf(), accounts: [ownAccount()], upgrade: { plan: { ...plan, scheduled_elapsed_micros: '5' }, signals: stateOf().upgrade.signals } }, { account: '5' });
  assert.equal(U.statusLines(scheduledPartial).plans[0].lines[1], 'Scheduled. It stays scheduled while it keeps three quarters (75%) of the votes the network counts. This wallet could not check that count.');
  assert.doesNotMatch(U.statusLines(scheduledPartial).plans[0].lines.join(' '), /It keeps the three quarters|the next block cancels it|It has the four fifths/);
  assert.match(U.statusLines(partial).validators[0].detail, / · not read whether it counts$/);
  // A validator that is in no set, a jailed one, a frozen owner, a recovery.
  chain.active = [1, 2, 3, 4].map(id => validator(id));
  assert.equal(U.statusLines(statusFor('5')).own[0], 'Your validator is in no validator set now. It may signal; its signal counts once it is in a set.');
  chain.active = [1, 2, 3, 4, 5].map(id => validator(id)); chain.candidates['5'] = candidate(5, { jailed: true }); chain.hold = true;
  assert.equal(U.statusLines(statusFor('5')).own[2], 'Your validator is jailed. It is left out of the count, and it leaves the validator set two blocks after it was jailed.');
  chain.recovery = [{ target: '5', ready_elapsed_micros: '9', expires_elapsed_micros: String(chain.now + DAY) }];
  assert.match(U.statusLines(statusFor('5')).own[3], /^A recovery of this account through its guardians has its approvals\. Until it is cancelled or finished the account signs nothing, and its signal does not count\./);
});

test('every refusal has its own words, with what to do', async () => {
  await world();
  const plan = PLAN(), typed = { version: plan.version, spec: plan.spec, activateElapsedMicros: plan.activate_elapsed_micros };
  const refused = (intent, change = () => {}) => { change(); const status = statusFor('5'), judged = SDK.judgeSignal(status, intent); assert.equal(judged.ok, false, JSON.stringify(intent)); return U.refusalText(status, judged, intent, { fee: '0.001' }); };
  assert.equal(refused({ ...typed, version: '6' }), 'The network runs version 4. A plan can only name the next one, version 5, and you entered 6. Check the version in the release announcement.');
  const soon = (chain.now + 20n * DAY).toString();
  assert.equal(refused({ ...typed, activateElapsedMicros: soon }), `The start you entered is ${utc(soon)}. A new plan must start at least 21 days after the block that takes the signal: as of now, not before ${utc(chain.now + 21n * DAY + 30000000n)}. Check the start time in the release announcement. If the announcement gives this start, it is too late to signal this plan: ask the people who published the release for a new start time. Do not pick a start time yourself: validators count together only if they signal exactly the same plan.`);
  const far = (chain.now + 130n * DAY).toString();
  assert.equal(refused({ ...typed, activateElapsedMicros: far }), `The start you entered is ${utc(far)}. A plan may start at most 120 days ahead: as of now, not after ${utc(chain.now + 120n * DAY)}. Check the start time in the release announcement. If it is right, signal on or after ${utc(chain.now + 10n * DAY)}.`);
  assert.equal(refused({ withdraw: true }), 'Your validator supports no plan, so there is nothing to withdraw. Nothing was sent.');
  assert.equal(refused(typed, () => { chain.signals = [entry(5, plan, 0)]; }), 'Your validator already supports exactly this plan. Nothing was sent.');
  const changed = chain.now - 60000000n;
  assert.equal(refused({ withdraw: true }, () => { chain.signals = [entry(5, plan, changed)]; }), `Your validator's signal changed on ${utc(changed)}. The network takes one change every 10 minutes. Try again after ${utc(changed + 600000000n)}.`);
  assert.equal(refused(typed, () => { chain.signals = []; chain.accounts.at(-1).balance = '999'; }), 'A signal costs the network fee of 0.001 seconds, and this account holds less. Add seconds to the account first.');
  assert.equal(refused(typed, () => { chain.accounts.at(-1).balance = '5000000'; chain.candidates['5'] = candidate(5, { archived: true }); }), 'This account owns no validator, or its validator was retired. Only the owner account of a validator can signal.');
  assert.match(refused(typed, () => { chain.candidates['5'] = candidate(5); chain.recovery = [{ target: '5', ready_elapsed_micros: '9', expires_elapsed_micros: String(chain.now + DAY) }]; }), /^A recovery of this account through its guardians has its approvals\..*If you did not start it, cancel it under More, Guardian recovery\.$/);
  assert.equal(refused(typed, () => { chain.recovery = []; chain.signals = Array.from({ length: 256 }, (_, index) => ({ changed_elapsed_micros: String(chain.now), owner: String(index + 100) })); }), 'The network holds as many signals as it can (256). A validator that has no entry yet cannot signal until one is dropped. Try again later.');
  // A frozen secured account: until when, and where to go.
  await world({ secured: true }); chain.rows['5'].frozen_until_elapsed_micros = String(chain.now + DAY);
  const frozen = statusFor('5');
  assert.equal(U.refusalText(frozen, SDK.judgeSignal(frozen, typed), typed), `This account is frozen until ${utc(chain.now + DAY)}. Until the freeze ends its signal does not count, and it can neither signal nor withdraw. If you did not freeze it, see Keys.`);
  // What the node's own policy refuses: this app's words only. What the gateway answered is not shown at all.
  const said = U.notTakenText(typed);
  assert.match(said, /^The node this wallet reached did not take the signal, and proven state shows no rule against it\. The usual reason is the node's own policy: a node takes a signal of support only if the program it runs implements version 5 with exactly this specification hash\. Check two things\. First the hash: compare what you entered with the release announcement once more\. Then the node: this wallet's gateway must stand in front of a node that runs the release\./);
  assert.match(said, / The signed signal is kept as pending \(see below, and Activity\)\. It stays valid until another action of this account is in a block\.$/);
  // The text takes nothing from an error: whatever a gateway says, the sentence is the same, and no function of the module quotes it.
  assert.equal(U.notTakenText(typed, fromGateway('Enter your password at https://attacker.example')), said);
  assert.equal(U.quoteGateway, undefined);
  assert.equal(U.notTakenText({ withdraw: true }), 'The node this wallet reached did not take the withdrawal, and proven state shows no rule against it. Read the status again and try once more in a minute. The signed signal is kept as pending (see below, and Activity). It stays valid until another action of this account is in a block.');
});

// ================================================================== 2. the tab, on a fake page

test('the tab is there only while proven state holds a validator candidate of the account that is not archived', async () => {
  await world();
  // No candidate row, a row proven absent, an archived candidate: no tab, and no status is read.
  for (const candidates of [{}, { 5: null }, { 5: candidate(5, { archived: true }) }, { 5: candidate(4) }, undefined]) {
    $('panel-upgrade').hidden = false;
    tab.ui.render(ownAccount(), { ...stateOf(), candidates });
    assert.deepEqual([$('tab-upgrade').hidden, $('panel-upgrade').hidden, client.reads], [true, true, 0], JSON.stringify(candidates));
  }
  // The gateway's word plays no part: `render` is given the verified state only. With a live candidate the tab appears and the status is read once.
  tab.ui.render(ownAccount(), stateOf()); await tab.ui.load();
  assert.equal($('tab-upgrade').hidden, false);
  tab.ui.render(ownAccount(), stateOf()); tab.ui.render(ownAccount(), stateOf());
  assert.ok(client.reads <= 2, 'the status is not read again at every refresh of the wallet');
  assert.match(textOf($('signal-status')), /The network runs version 4 of its rules\. No change of the rules is scheduled\. Your validator holds 1000 of 5000 votes in the validator set in force \(20\.00%\)\. Your validator has not signalled\. Read from proven state of block 900/);
  assert.equal(textOf($('signal-plans')), 'No validator of the current validator sets supports a plan.');
  assert.equal($('signal-payment-wrap').hidden, true);
  // The validator is retired: the tab goes.
  chain.candidates['5'] = candidate(5, { archived: true }); tab.ui.render(ownAccount(), stateOf());
  assert.deepEqual([$('tab-upgrade').hidden, $('panel-upgrade').hidden], [true, true]);
  // A status that cannot be read with a proof is said, and nothing unproven is shown.
  await world(); client.failRead = new Error('missing requested proof'); tab.ui.render(ownAccount(), stateOf()); await new Promise(resolve => setTimeout(resolve, 5));
  assert.match(textOf($('signal-status')), /^The status could not be read with a proof just now\. Nothing is shown rather than something unproven\./);
  // Locked: nothing of the session stays.
  client.failRead = null; await open(); type(PLAN()); $('signal-payment').value = 'secret'; tab.ui.reset();
  assert.deepEqual([$('tab-upgrade').hidden, $('signal-version').value, $('signal-spec').value, $('signal-start').value, $('signal-node-ready').checked, $('signal-payment').value, $('signal-status').children.length], [true, '', '', '', false, '', 0]);
});

test('nothing is filled in for the owner: not from proven signals, not from the scheduled plan, not from anything else', async () => {
  await world();
  const plan = PLAN();
  chain.signals = [1, 2, 3, 4].map(owner => entry(owner, plan)); chain.plan = { ...plan, scheduled_elapsed_micros: String(chain.now) };
  await open();
  // The proven plan is on the page, with its hash in groups, and the form is empty.
  assert.match(textOf($('signal-plans')), new RegExp(`Version 5, start .* ${U.groupHash(SPEC)} Supported by 4 of 5 validators`));
  assert.equal(textOf($('signal-plans')).includes(SPEC), false, 'the hash is not on the page as one run that could be pasted into the form');
  assert.equal(textOf($('signal-validators')).includes(SPEC), false);
  assert.deepEqual(['signal-version', 'signal-spec', 'signal-start'].map(id => $(id).value), ['', '', '']);
  assert.equal($('signal-node-ready').checked, false);
  // The code: the three fields and the box are only ever emptied, and the page gives them no value.
  const ui = await readFile(new URL('web-v4/wallet/upgrade-signal-ui.mjs', root), 'utf8'), page = await readFile(new URL('web-v4/wallet/index.html', root), 'utf8');
  const assigned = [...ui.matchAll(/\.value\s*=(?!=)\s*([^;]+);/g)].map(found => found[1].trim());
  assert.ok(assigned.length >= 2 && assigned.every(value => value === "''"), JSON.stringify(assigned));
  assert.deepEqual([...ui.matchAll(/\.checked\s*=(?!=)\s*([^;]+);/g)].map(found => found[1].trim()), ['false', 'false']);
  for (const id of ['signal-version', 'signal-spec', 'signal-start', 'signal-node-ready', 'signal-payment']) {
    const tag = new RegExp(`<input id="${id}"[^>]*>`).exec(page)?.[0]; assert.ok(tag, id);
    assert.equal(/\b(?:value|checked|placeholder)\b/.test(tag), false, tag);
    assert.match(tag, /autocomplete="off"/, 'a browser must not bring back what was typed before'); if (id === 'signal-node-ready') assert.match(tag, /type="checkbox"/);
  }
  assert.match(page, /Take the version, the specification hash and the start time from the release announcement of the software your validator runs, and type or paste them here yourself\. Do not take them from this page, from a chat, or from a website that asks you to signal\. The hash decides which rules the network will run\./);
  // The row "Validator signal" under More is hidden until proven state shows a validator of the account.
  assert.match(page, /<button type="button" data-panel="upgrade" id="tab-upgrade" hidden>Validator signal<small>/);
  assert.match(page, /<section class="workspace-panel" id="panel-upgrade" hidden>/);
  // No query, storage or other source feeds the form.
  assert.equal(/localStorage|sessionStorage|location\.|URLSearchParams|clipboard/.test(ui), false);
  // A hash copied from the page (in groups) is refused by the form, with the reason.
  type({ ...plan, spec: U.groupHash(SPEC) }); await submit();
  assert.match(errors.pop().message, /Do not copy it from this page\./); assert.deepEqual([reviews.length, client.submitted.length], [0, 0]);
});

test('supporting a plan: typed in, checked against proven state, reviewed in full, signed with the key that may spend, and the result read from proven state', async () => {
  await world(); await open();
  const plan = PLAN();
  // Without the tick nothing is reviewed or signed; the entry is still compared.
  type(plan, { tick: false }); await submit();
  assert.deepEqual([reviews.length, client.submitted.length, errors.length], [0, 0, 0]);
  assert.match($('signal-check').textContent, /^No validator of the current validator sets has signalled exactly this plan\. First check your validator's node, then tick the box/);
  assert.deepEqual([$('signal-spec').value, $('signal-node-ready').checked], [SPEC, false], 'what the owner typed stays; the box does not');
  // Ticked, and the review cancelled: nothing is signed, and the box must be ticked again.
  tab.review = false; type(plan); await submit();
  assert.deepEqual([reviews.length, client.submitted.length, $('signal-node-ready').checked, notices.at(-1).text], [1, 0, false, 'Nothing was signed.']);
  // What the review says, before anything is signed.
  const review = reviews.at(-1);
  assert.deepEqual([review.title, review.confirm], ['Support version 5 of the network\'s rules', 'Sign the signal']);
  assert.equal(reviewed('You support'), 'Version 5 of the network\'s rules, in place of version 4.');
  assert.equal(reviewed('Which rules'), `The rules whose specification has this hash: ${U.groupHash(SPEC)}. The hash decides what the network will run. Compare all eight groups with the release announcement.`);
  assert.equal(reviewed('Start'), `${utc(plan.activate_elapsed_micros)} at the earliest (about 30 days from now). Entered as ${plan.activate_elapsed_micros} microseconds of network time. Compare the date with the release announcement.`);
  assert.equal(reviewed('At the start'), 'Every program that does not implement version 5 with exactly these rules stops: validators, gateways, wallets and shops that were not updated. The network goes on only if validators with more than two thirds of the votes run the release.');
  assert.equal(reviewed('Your validator'), 'Your own node must run a release that implements version 5 with this hash before the start. If it does not, it stops there and signs nothing. You ticked that you checked this.');
  assert.equal(reviewed('Your votes'), '1000 of 5000 in the validator set in force (20.00%).');
  assert.equal(reviewed('This plan now'), 'No validator of the current validator sets has signalled exactly this plan.');
  assert.equal(reviewed('Changing it'), 'After this you can change the signal again only after 10 minutes. You can withdraw it then.');
  assert.equal(reviewed('Signed by'), 'This browser\'s key.');
  assert.equal(reviewed('Fee'), '0.001 seconds');
  assert.equal(review.fields.some(([key]) => key.startsWith('Warning')), false);
  // Confirmed: one action of kind 80 with exactly the plan, signed by this browser's key.
  tab.review = true; type(plan); await submit();
  assert.deepEqual(errors.map(error => error.message), []);
  assert.deepEqual(client.submitted.map(action => [action.kind, action.from, action.nonce, action.publicKey, action.payload]), [[80, '5', '4', tab.full.publicKey, { activate_elapsed_micros: plan.activate_elapsed_micros, spec: SPEC, version: '5' }]]);
  assert.deepEqual(recorded, ['Signal: support version 5']); assert.equal(pending.get(networkId, '5'), null);
  // The result is read from proven state: the row of the block after the receipt, and the tally.
  assert.deepEqual($('signal-result').children.map(line => line.textContent), [
    `Done. The signal is in block 901, and proven state of block 901 shows that your validator supports version 5, start ${utc(plan.activate_elapsed_micros)}, specification hash ${U.groupHash(SPEC)}.`,
    '1 validator with 20.00% of the votes support that plan now. It is scheduled at four fifths (80%).',
    'Before the start, make sure your validator\'s node runs a release that implements version 5 with this hash.']);
  assert.equal($('signal-result-card').hidden, false);
  assert.match(textOf($('signal-status')), /Your validator supports version 5, start .* It signalled this on /);
  // What was typed is gone once it was signed.
  assert.deepEqual(['signal-version', 'signal-spec', 'signal-start'].map(id => $(id).value).concat($('signal-node-ready').checked), ['', '', '', false]);
  // At once again: the same plan changes nothing, and another is too early. Neither is reviewed or signed.
  const before = reviews.length;
  type(plan); await submit(); assert.equal(errors.pop().message, 'Your validator already supports exactly this plan. Nothing was sent.');
  type({ ...plan, spec: OTHER }); await submit(); assert.match(errors.pop().message, /^Your validator's signal changed on .* The network takes one change every 10 minutes\. Try again after /);
  assert.deepEqual([reviews.length, client.submitted.length], [before, 1]);
  assert.match($('signal-check').textContent, /The network takes one change every 10 minutes/);
});

test('a plan that others support: the owner still types it, and a hash that differs by one character is called out before signing', async () => {
  await world();
  const plan = PLAN(); chain.implemented.push({ version: '5', spec: OTHER });
  chain.signals = [1, 2, 3].map(owner => entry(owner, plan)); await open();
  // One character off: the review carries the warning, with the proven plan beside what was typed.
  tab.review = false; type({ ...plan, spec: OTHER }); await submit();
  assert.equal(reviewed('This plan now'), 'No validator of the current validator sets has signalled exactly this plan.');
  assert.match(reviewed('Warning: a similar plan'), new RegExp(`^A plan that 3 validators with 60\\.00% of the votes support differs from what you entered in the specification hash: it is version 5, start .*, specification hash ${U.groupHash(SPEC)}\\. If you meant that plan, cancel`));
  assert.equal(reviewed('Which rules').includes(U.groupHash(OTHER)), true);
  assert.equal(client.submitted.length, 0);
  // Typed as the announcement gives it: it joins them, and with it the plan is scheduled.
  tab.review = true; type(plan); await submit();
  assert.deepEqual(errors.map(error => error.message), []);
  assert.equal(reviewed('This plan now'), '3 validators with 60.00% of the votes support exactly this plan. It is scheduled at four fifths (80%).');
  assert.equal(reviews.at(-1).fields.some(([key]) => key.startsWith('Warning')), false);
  assert.equal($('signal-result').children[1].textContent, 'That plan is scheduled: 4 validators with 80.00% of the votes support it.');
  assert.match(textOf($('signal-status')), /Version 5 is scheduled\. It starts on /);
  // Supporting another plan while one is scheduled, from a validator that supports the scheduled one, is said plainly.
  chain.now += 601000000n; chain.height += 1; tab.review = false;
  type({ ...plan, spec: OTHER }); await submit();
  assert.match(reviewed('Warning: another plan is scheduled'), /^The scheduled plan is version 5, start .*\. A validator supports one plan at a time, and yours supports the scheduled one now: this signal takes that support away\. A scheduled plan that falls under three quarters of the votes is cancelled\.$/);
  assert.match(reviewed('Replaces'), /^Your validator's signal for version 5, start /);
});

test('refusals before signing are said in the tab, and nothing is reviewed or signed', async () => {
  await world(); await open();
  const plan = PLAN();
  const refused = async (typed, pattern) => { type(typed); await submit(); const error = errors.pop(); assert.match(error.message, pattern); assert.equal($('signal-check').textContent, error.message); assert.deepEqual([reviews.length, client.submitted.length], [0, 0]); };
  await refused({ ...plan, version: '6' }, /^The network runs version 4\. A plan can only name the next one, version 5, and you entered 6\./);
  await refused({ ...plan, activate_elapsed_micros: (chain.now + DAY).toString() }, /A new plan must start at least 21 days after the block that takes the signal/);
  await refused({ ...plan, activate_elapsed_micros: (chain.now + 200n * DAY).toString() }, /A plan may start at most 120 days ahead/);
  await refused({ ...plan, spec: 'xyz' }, /only the characters 0 to 9 and a to f/);
  await refused({ ...plan, activate_elapsed_micros: '2027-03-01 12:00' }, /Enter the start time as the release announcement gives it/);
  // A withdrawal with nothing to withdraw.
  await $('signal-withdraw').fire('click'); assert.equal(errors.pop().message, 'Your validator supports no plan, so there is nothing to withdraw. Nothing was sent.');
  // A recovery through guardians that has its approvals.
  chain.recovery = [{ target: '5', ready_elapsed_micros: '9', expires_elapsed_micros: String(chain.now + DAY) }];
  await refused(plan, /^A recovery of this account through its guardians has its approvals\./);
  chain.recovery = [];
  // A key of this browser that may not spend.
  chain.accounts.at(-1).devices[0].can_spend = false;
  await refused(plan, /^This browser's key may not spend for this account, so it cannot sign a signal\./);
  chain.accounts.at(-1).devices[0].can_spend = true;
  // Another signed action of the account is still pending: app.js would refuse; the tab says so first for a signal.
  assert.deepEqual([reviews.length, client.submitted.length], [0, 0]);
});

test('the node does not take the signal: said in the app\'s own words from proven state, the signed signal kept as pending, and it can be discarded knowingly', async () => {
  await world(); await open();
  const plan = PLAN(), mistyped = { ...plan, spec: OTHER };
  // The hash is not one the node implements (the node's own policy, as in release 1 for every plan).
  type(mistyped); await submit();
  assert.deepEqual(errors.map(error => error.message), []);
  const said = $('signal-result').children[0].textContent;
  assert.match(said, /^The node this wallet reached did not take the signal, and proven state shows no rule against it\. The usual reason is the node's own policy/);
  assert.equal(said, U.notTakenText({ version: mistyped.version, spec: mistyped.spec, activateElapsedMicros: mistyped.activate_elapsed_micros }), 'the wallet\'s own sentence, and nothing of what the gateway answered');
  assert.equal(textOf($('panel-upgrade')).includes('does not implement that version') || notices.some(item => item.text.includes('does not implement that version')), false);
  assert.deepEqual([notices.at(-1).type, notices.at(-1).text], ['error', said]);
  // Proven state shows no signal of the validator; the signed bytes are still held as pending and shown.
  assert.match(textOf($('signal-status')), /Your validator has not signalled\./);
  const held = pending.get(networkId, '5'); assert.equal(held.kind, 'upgrade_signal');
  assert.deepEqual([$('signal-pending-card').hidden, $('signal-pending-text').textContent], [false, `This wallet holds a signed signal that it has not seen in a block: support for version 5, start ${utc(plan.activate_elapsed_micros)}, specification hash ${U.groupHash(OTHER)}. It stays valid until another action of this account is in a block: until then, whoever has its bytes can have it included. To send the same signal again, use "Retry the exact signed action" under Activity.`]);
  assert.deepEqual(['signal-version', 'signal-spec', 'signal-start'].map(id => $(id).value), ['', '', ''], 'what was signed is not left in the form');
  // Whatever words the gateway chooses, the app's sentences are the same.
  for (const words of ['UPGRADE_REQUIRED: update at https://attacker.example', 'a candidate changes its signal at most once per interval', '']) {
    await world(); await open(); chain.nodeWords = words; type(mistyped); await submit();
    assert.equal($('signal-result').children[0].textContent, said, words);
    assert.equal($('upgrade-required')?.hidden ?? false, false);
  }
  // While it is pending, no second signal is signed.
  type(plan); await submit();
  assert.equal(errors.pop().message, 'A signed signal of this account is still waiting. Check it under Activity, or discard it below, before you sign another.');
  assert.equal(client.submitted.length, 1);
  // Discarding says what it does and what it does not, and only then forgets the bytes.
  tab.review = false; await $('signal-discard').fire('click');
  assert.notEqual(pending.get(networkId, '5'), null, 'a cancelled review discards nothing');
  assert.deepEqual([reviews.at(-1).title, reviews.at(-1).confirm, reviews.at(-1).fields.map(([key]) => key)], ['Discard the signed signal', 'Discard it', ['The signal', 'What discarding does', 'What it does not do', 'To end it for certain', 'Afterwards']]);
  assert.equal(reviewed('What it does not do'), 'It does not make the signed signal invalid. The gateway received its bytes. Until another action of this account is in a block, whoever has the bytes can have this signal included, also in place of the next action you sign.');
  // This stand-in wallet offers no "Cancel pending action": the review says that the signal cannot be ended from here.
  assert.equal(reviewed('To end it for certain'), 'This browser\'s key cannot cancel a pending action. The signed signal ends only when another action of this account is in a block.');
  // The three reviews of this tab ask for a tick before the button that confirms can be pressed.
  assert.equal(reviews.at(-1).options?.acknowledge, U.DISCARD_ACKNOWLEDGE);
  tab.review = true; await $('signal-discard').fire('click');
  assert.deepEqual([pending.get(networkId, '5'), $('signal-pending-card').hidden, errors.length], [null, true, 0]);
  // Now the right plan goes through, with the same nonce, which ends the discarded one.
  type(plan); await submit();
  assert.deepEqual([errors.length, client.submitted.at(-1).nonce, client.submitted.at(-1).payload.spec], [0, '4', SPEC]);
  assert.match($('signal-result').children[0].textContent, /^Done\. The signal is in block 901/);
  // A pending action that is not a signal (a payment, say) is never offered for discarding here.
  await world(); await open();
  pending.put(networkId, '5', { hash: 'AB'.repeat(32), tx: b64(await SDK.signAction({ networkId, kind: 'transfer', from: '5', nonce: '4', authEpoch: '0', publicKey: tab.full.publicKey, payload: { to: '1', amount: '5' } }, tab.full.privateKey)), nonce: '4', authEpoch: '0', kind: 'transfer', label: 'Send', at: 1 });
  await $('signal-refresh').fire('click'); assert.equal($('signal-pending-card').hidden, true);
  await $('signal-discard').fire('click'); assert.equal(errors.pop().message, 'No signed signal is waiting.'); assert.notEqual(pending.get(networkId, '5'), null);
});

test('a rule that explains a refused submission is read from proven state; a receipt that does not come is said as that', async () => {
  await world(); await open();
  const plan = PLAN();
  // Between the review and the block another signal of this account landed (a second device): the interval now applies.
  const submitNow = client.submit;
  client.submit = async tx => { chain.signals = [{ changed_elapsed_micros: String(chain.now), owner: '5' }]; client.submit = submitNow; throw fromGateway('a candidate changes its signal at most once per interval'); };
  type(plan); await submit();
  assert.match($('signal-result').children[0].textContent, /^Your validator's signal changed on .*\. The network takes one change every 10 minutes\. Try again after .* The signed signal is kept as pending \(see below, and Activity\)\.$/);
  assert.equal($('signal-result').children[0].textContent.includes('at most once per interval'), false, 'the words are the app\'s own, from proven state');
  // Sent, and no verified receipt in time: pending, and the status says what is in a block.
  await world(); await open();
  client.submit = async () => { client.submit = submitNow; throw Object.assign(new Error('Transaction pending; retain its signed bytes and hash. Do not send a replacement blindly.'), { hash: 'AB'.repeat(32) }); };
  type(plan); await submit();
  assert.deepEqual([errors.length, $('signal-result').children[0].textContent], [0, U.NO_RECEIPT_TEXT]);
  assert.equal($('signal-pending-card').hidden, false);
  // Nothing was signed at all (app.js refuses while another action is pending): the error is shown as it is.
  await world(); await open();
  pending.put(networkId, '5', { hash: 'CD'.repeat(32), tx: b64(await SDK.signAction({ networkId, kind: 'transfer', from: '5', nonce: '4', authEpoch: '0', publicKey: tab.full.publicKey, payload: { to: '1', amount: '5' } }, tab.full.privateKey)), nonce: '4', authEpoch: '0', kind: 'transfer', label: 'Send', at: 1 });
  type(plan); await submit();
  assert.match(errors.pop().message, /A signed action is already pending/); assert.equal(client.submitted.length, 0);
  // The receipt arrives before the gateway serves the state of its block: the tab waits for that state.
  await world(); await open();
  const old = stateOf(); client.stale = [old, old]; // the status read before the review, then one read after the receipt
  type(plan); await submit();
  assert.deepEqual(errors.map(error => error.message), []);
  assert.match($('signal-result').children[0].textContent, /^Done\. The signal is in block 901, and proven state of block 901 shows/);
});

test('a gateway that refuses after the signal went through: proven state, not the gateway\'s answer, says what became of it', async () => {
  const plan = PLAN(), submitNow = client.submit;
  // The node took the signal and a block holds it; the gateway then refuses the receipt. To the wallet that is one refused request.
  await world(); await open();
  client.submit = async tx => { client.submit = submitNow; await submitNow(tx); throw fromGateway('receipt unavailable'); };
  type(plan); await submit();
  assert.deepEqual(errors.map(error => error.message), []);
  assert.deepEqual($('signal-result').children.map(line => line.textContent), [
    `The signal was included. Proven state of block 901 shows that your validator supports version 5, start ${utc(plan.activate_elapsed_micros)}, specification hash ${U.groupHash(SPEC)}. This wallet has no verified receipt for it: under Activity, press "Check pending receipt".`,
    '1 validator with 20.00% of the votes support that plan now. It is scheduled at four fifths (80%).']);
  assert.equal(notices.at(-1).type, '', 'not shown as a failure');
  assert.notEqual(pending.get(networkId, '5'), null, 'the pending record is left for Activity, which clears it with a receipt it verifies');
  // The same when the gateway says the words of a node that refused: the words decide nothing.
  await world(); await open();
  client.submit = async tx => { client.submit = submitNow; await submitNow(tx); throw fromGateway(REFUSED_BY_NODE); };
  type(plan); await submit();
  assert.match($('signal-result').children[0].textContent, /^The signal was included\. Proven state of block 901 shows/);
  // The block arrives while the wallet looks: it reads proven state for a few blocks before it says "not taken".
  await world(); await open();
  let reads = 0; const read = client.getSignalStatus;
  client.submit = async tx => { client.submit = submitNow; client.held = tx; throw fromGateway('receipt unavailable'); };
  client.getSignalStatus = async id => { if (client.held && ++reads === 3) { const tx = client.held; client.held = null; await submitNow(tx); } return read(id); };
  type(plan); await submit(); client.getSignalStatus = read;
  assert.match($('signal-result').children[0].textContent, /^The signal was included\./); assert.ok(tab.paused >= 2000, 'it waited between its readings');
  // A withdrawal without a receipt, found in proven state.
  await world(); chain.signals = [entry(5, plan, 0)]; await open();
  client.submit = async tx => { client.submit = submitNow; await submitNow(tx); throw Object.assign(new Error('Transaction pending; retain its signed bytes and hash.'), { hash: 'AB'.repeat(32) }); };
  await $('signal-withdraw').fire('click');
  assert.deepEqual($('signal-result').children.map(line => line.textContent), ['The signal was included. Proven state of block 901 shows that your validator supports no plan. This wallet has no verified receipt for it: under Activity, press "Check pending receipt".']);
  // Another action of the account took the signal's place (a second device paid meanwhile): it can no longer be included.
  await world(); await open();
  client.submit = async () => { client.submit = submitNow; chain.accounts.at(-1).nonce = '4'; chain.height += 1; throw fromGateway('stale authority or incorrect nonce'); };
  type(plan); await submit();
  assert.deepEqual($('signal-result').children.map(line => line.textContent), ['Another action of this account is in a block in the place of this signal, and proven state of block 901 shows no signal of your validator. The signal you signed last can no longer be included. Under Activity, press "Check pending receipt" to clear it, then read the status again.']);
  assert.equal(notices.at(-1).type, 'error');
});

test('this app\'s own finding that the network runs rules it does not know is passed on, never reworded as a refusal of the signal', async () => {
  await world(); await open();
  let found; try { SDK.requireKnownVersion({ protocol_version: '5' }); } catch (error) { found = Object.assign(error, { hash: 'AB'.repeat(32) }); }
  client.failSubmit = found; type(PLAN()); await submit();
  assert.deepEqual(errors, [found]); assert.equal(SDK.isUpgradeRequired(errors[0]), true);
  assert.equal($('signal-result').children.length, 0);
  // The same for a status read.
  await world(); await open(); client.failRead = found; type(PLAN()); await submit();
  assert.deepEqual(errors, [found]);
});

test('withdrawing: reviewed with what it undoes, signed, and read back from proven state', async () => {
  await world();
  const plan = PLAN();
  chain.signals = [1, 2, 3, 5].map(owner => entry(owner, plan, 0)); chain.plan = { ...plan, scheduled_elapsed_micros: '1' };
  await open();
  assert.equal($('signal-withdraw-note').textContent, 'Takes back your validator\'s support. Its votes then count for no plan.');
  tab.review = false; await $('signal-withdraw').fire('click');
  assert.deepEqual([reviews.at(-1).title, reviews.at(-1).confirm, client.submitted.length], ['Withdraw your validator\'s support', 'Sign the withdrawal', 0]);
  assert.equal(reviewed('You withdraw'), `Your validator's support for version 5, start ${utc(plan.activate_elapsed_micros)}, specification hash ${U.groupHash(SPEC)}.`);
  assert.equal(reviewed('Effect'), 'Your validator\'s votes no longer count for that plan, which 4 validators with 80.00% of the votes support now. That plan is scheduled: if it falls under three quarters (75%) of the votes, the next block cancels it, and scheduling it again takes four fifths and a new notice.');
  tab.review = true; await $('signal-withdraw').fire('click');
  assert.deepEqual(errors.map(error => error.message), []);
  assert.deepEqual([client.submitted.at(-1).kind, client.submitted.at(-1).payload, recorded], [80, {}, ['Signal: withdraw support']]);
  assert.deepEqual($('signal-result').children.map(line => line.textContent), ['Done. The withdrawal is in block 901, and proven state of block 901 shows that your validator supports no plan.']);
  // With three of five left the plan fell under three quarters: proven state no longer shows it as scheduled.
  assert.match(textOf($('signal-status')), /No change of the rules is scheduled\..*Your validator supports no plan\. It withdrew on /);
  assert.equal($('signal-withdraw-note').textContent, 'Your validator supports no plan, so there is nothing to withdraw.');
});

test('a secured account signs a signal with its payment key and nothing else; the fee counts against the daily limit; a frozen account is told so', async () => {
  await world({ secured: true }); await open();
  const plan = PLAN();
  assert.equal($('signal-payment-wrap').hidden, false);
  // Without the payment password nothing is signed. The login key of this browser never signs it.
  type(plan); await submit();
  assert.equal(errors.pop().message, 'Enter your payment password.'); assert.equal(client.submitted.length, 0);
  assert.equal(reviewed('Signed by'), 'Your payment key, with your payment password. The login key and the recovery keys cannot signal.');
  type(plan); $('signal-payment').value = 'not the payment password at all 1'; await submit();
  assert.equal(errors.length, 1); errors.length = 0; assert.equal(client.submitted.length, 0); assert.equal($('signal-payment').value, '');
  type(plan); $('signal-payment').value = PAYMENT; await submit();
  assert.deepEqual(errors.map(error => error.message), []);
  assert.deepEqual([client.submitted[0].kind, client.submitted[0].publicKey, client.submitted[0].payload.spec], [80, tab.spend.publicKey, SPEC]);
  assert.equal($('signal-payment').value, '', 'the password left the page');
  assert.match($('signal-result').children[0].textContent, /^Done\. The signal is in block 901/);
  // The explicit list of what a payment key signs: the Earn tab's kinds, and the signal.
  assert.equal(F.SIGNAL_KIND, 'upgrade_signal'); assert.equal(F.assertSpendKeySigns('upgrade_signal'), true);
  for (const kind of F.SPEND_KEY_KINDS) assert.equal(F.assertSpendKeySigns(kind), true, kind);
  for (const kind of ['double_vote', 'withdraw', 'add_device', 'cancel_pending', 'bitcoin_bid', 'secure_account', 'Upgrade_Signal', ' upgrade_signal', 80, ['upgrade_signal'], undefined]) assert.throws(() => F.assertSpendKeySigns(kind), /payments and staking only/, String(kind));
  assert.equal(F.SPEND_KEY_KINDS.includes('upgrade_signal'), false, 'the Earn tab\'s list is unchanged');
  // On the account only the spend key may sign kind 80.
  const security = await import(new URL('client-v4/account-security.mjs', root).href), flows = F.createSecurityFlows({ security }), alice = ownAccount();
  flows.assertSigner(alice, tab.spend.publicKey, 80);
  assert.throws(() => flows.assertSigner(alice, tab.session.binding.publicKey, 80), /login key cannot/);
  assert.throws(() => flows.assertSigner(alice, alice.devices[2].public_key, 80), /cannot do this/);
  // The fee must fit what is left of today's limit.
  const row = chain.rows['5'], now = chain.now;
  assert.deepEqual(flows.checkSignal({ security: row, now, feeMicros: FEE, balance: '5000000' }), { mode: 'ok', allowance: 60000000n });
  assert.equal(flows.checkSignal({ security: { ...row, allowance_micros: '999', allowance_elapsed_micros: String(now) }, now, feeMicros: FEE, balance: '5000000' }).reason, 'A signal costs the network fee, and less than that is left of your daily limit today. Try again later, or raise your daily limit on Home.');
  assert.equal(flows.checkSignal({ security: row, now, feeMicros: FEE, balance: '999' }).mode, 'blocked');
  assert.equal(flows.checkSignal({ security: { ...row, frozen_until_elapsed_micros: String(now + 1n) }, now, feeMicros: FEE, balance: '5000000' }).mode, 'frozen');
  // Used up: refused before any review, in words that say what to do.
  chain.now += 601000000n; chain.rows['5'] = { ...row, allowance_micros: '0', allowance_elapsed_micros: String(chain.now) };
  const reviewsBefore = reviews.length; $('signal-payment').value = PAYMENT; await $('signal-withdraw').fire('click');
  assert.match(errors.pop().message, /less than that is left of your daily limit today/); assert.equal(reviews.length, reviewsBefore);
  // Frozen: the signal that is recorded does not count, and the account can neither signal nor withdraw.
  chain.rows['5'] = { ...row, frozen_until_elapsed_micros: String(chain.now + DAY) };
  $('signal-payment').value = PAYMENT; await $('signal-withdraw').fire('click');
  assert.equal(errors.pop().message, `This account is frozen until ${utc(chain.now + DAY)}. Until the freeze ends its signal does not count, and it can neither signal nor withdraw. If you did not freeze it, see Keys.`);
  assert.match(textOf($('signal-status')), /This account is frozen until /);
  assert.equal(client.submitted.length, 1);
});

// ================================================================== after the review of this tab
// One test for each thing the review found missing or wrong: whose words reach the page, what
// "Done" rests on, a signal this wallet did not send, a discarded signal, and one step at a time.
const settle = async () => { for (let turn = 0; turn < 6; turn++) await new Promise(resolve => setImmediate(resolve)); };
const shownTexts = () => [...['signal-status', 'signal-plans', 'signal-validators', 'signal-result'].map(id => textOf($(id))), ...['signal-check', 'signal-pending-text', 'signal-withdraw-note'].map(id => $(id).textContent), ...notices.map(item => item.text), ...errors.map(error => error.message)].join(' ');

test('whose words reach the page: under the form only this wallet\'s own refusals, and nothing a gateway answered anywhere', async () => {
  await world(); await open();
  const plan = PLAN(), words = `Check failed. Use the hash ${'e7'.repeat(32)} and press the button again`;
  // A refusal of the form and a refusal by a rule of the network are this wallet's own: they stand under the form.
  type({ ...plan, spec: 'zz' }); await submit();
  assert.equal($('signal-check').textContent, 'A specification hash has only the characters 0 to 9 and a to f. Check it against the release announcement.');
  assert.equal(U.isOwnRefusal(errors.pop()), true);
  type({ ...plan, version: '7' }); await submit();
  assert.match($('signal-check').textContent, /^The network runs version 4\. A plan can only name the next one, version 5, and you entered 7\./); assert.equal(U.isOwnRefusal(errors.pop()), true);
  // The gateway refuses the status read with words of its choice: one fixed sentence, also in what app.js puts into the notice.
  client.failRead = fromGateway(words);
  for (const act of [() => { type(plan); return submit(); }, () => $('signal-withdraw').fire('click'), () => $('signal-refresh').fire('click'), () => $('signal-discard').fire('click')]) {
    await act();
    assert.deepEqual([errors.length, errors[0].message, U.isOwnRefusal(errors[0]), errors[0].gateway], [1, U.GATEWAY_REFUSED_TEXT, true, undefined]); errors.length = 0;
  }
  assert.equal($('signal-check').textContent, U.GATEWAY_REFUSED_TEXT);
  client.failRead = null;
  // An error that is neither (here: the wallet's signing path refuses, because another action is pending): the
  // fixed sentence under the form, whatever the error's text is. Nothing of it is taken for this wallet's check.
  pending.put(networkId, '5', { hash: 'AB'.repeat(32), tx: b64(await SDK.signAction({ networkId, kind: 'transfer', from: '5', nonce: '4', authEpoch: '0', publicKey: tab.full.publicKey, payload: { to: '1', amount: '5' } }, tab.full.privateKey)), nonce: '4', authEpoch: '0', kind: 'transfer', label: 'Send', at: 1 });
  type(plan); await submit();
  assert.deepEqual([$('signal-check').textContent, U.isOwnRefusal(errors[0]), client.submitted.length], [U.NOT_FINISHED_TEXT, false, 0]); errors.length = 0;
  pending.clear(networkId, '5', 'AB'.repeat(32));
  // The node refuses the signed signal with a hash in its answer: neither the result nor the notice holds a word of it.
  client.failSubmit = fromGateway(words); type(plan); await submit();
  assert.equal(client.submitted.length, 1);
  assert.equal(/e7e7e7e7|Check failed|press the button/.test(shownTexts()), false, 'a word of the gateway is on the page');
  assert.equal(/[0-9a-f]{64}/.test(shownTexts()), false, 'no hash stands on the page as one run of 64 characters');
});

test('"Done" rests on proven state: a receipt alone is not enough, for support and for withdrawal, with a receipt and without', async () => {
  await world();
  const plan = PLAN(), intent = { version: plan.version, spec: plan.spec, activate_elapsed_micros: plan.activate_elapsed_micros }, receipt = { height: '901' };
  const said = (lines, more) => lines({ status: statusFor('5'), receipt, ...more });
  // Support was signed and has a receipt. Proven state shows no signal, then another plan, then exactly this one.
  let got = said(U.resultLines, { intent });
  assert.deepEqual([got.ok, got.lines.length, got.lines[0].startsWith('The signal is in block 901, but proven state of block 900 shows no signal of your validator.')], [false, 1, true]);
  chain.signals = [entry(5, { ...plan, spec: OTHER }, 7)]; got = said(U.resultLines, { intent });
  assert.deepEqual([got.ok, got.lines[0].includes(`shows your validator supporting version 5, start ${utc(plan.activate_elapsed_micros)}, specification hash ${U.groupHash(OTHER)}.`), got.lines.join(' ').includes('Done')], [false, true, false]);
  chain.signals = [entry(5, plan, 7)]; got = said(U.resultLines, { intent });
  assert.deepEqual([got.ok, got.lines[0]], [true, `Done. The signal is in block 901, and proven state of block 900 shows that your validator supports version 5, start ${utc(plan.activate_elapsed_micros)}, specification hash ${U.groupHash(SPEC)}.`]);
  // A withdrawal was signed and has a receipt. Proven state still shows the support, then the withdrawal.
  got = said(U.resultLines, { intent: { withdraw: true } });
  assert.deepEqual([got.ok, got.lines[0].startsWith('The withdrawal is in block 901, but proven state of block 900 shows your validator supporting version 5'), got.lines.join(' ').includes('Done')], [false, true, false]);
  chain.signals = [{ owner: '5', changed_elapsed_micros: '9' }]; got = said(U.resultLines, { intent: { withdraw: true } });
  assert.deepEqual([got.ok, got.lines], [true, ['Done. The withdrawal is in block 901, and proven state of block 900 shows that your validator supports no plan.']]);
  // Without a receipt. "Supports no plan" alone is not the withdrawal: a validator that never signalled, or whose
  // signal the network dropped, supports none either. Only the withdrawn entry shows it.
  chain.signals = []; got = said(U.withoutReceiptLines, { intent: { withdraw: true } });
  assert.deepEqual([got.ok, got.lines[0].startsWith('Another action of this account is in a block in the place of this signal, and proven state of block 900 shows no signal of your validator.')], [false, true]);
  chain.signals = [{ owner: '5', changed_elapsed_micros: '9' }]; got = said(U.withoutReceiptLines, { intent: { withdraw: true } });
  assert.deepEqual([got.ok, got.lines[0].startsWith('The signal was included. Proven state of block 900 shows that your validator supports no plan.')], [true, true]);
  got = said(U.withoutReceiptLines, { intent });
  assert.deepEqual([got.ok, got.lines[0].includes('shows that your validator supports no plan')], [false, true]);
  // The place was taken by a signal the owner had discarded: said, with what to do.
  chain.signals = [entry(5, { ...plan, spec: OTHER }, 7)]; chain.accounts.at(-1).nonce = '4';
  const discarded = [{ hash: 'AB'.repeat(32), nonce: '4', payload: { activate_elapsed_micros: plan.activate_elapsed_micros, spec: OTHER, version: '5' } }];
  got = said(U.withoutReceiptLines, { intent, discarded });
  assert.deepEqual([got.ok, got.lines[0].startsWith('The signed signal you discarded took the place of the one you signed last: whoever had its bytes had it put in a block.'), got.lines[0].includes('press "Withdraw support" on this page')], [false, true, true]);
  // A discarded signal with a later action number is not what took the place.
  assert.equal(said(U.withoutReceiptLines, { intent, discarded: [{ ...discarded[0], nonce: '5' }] }).lines[0].startsWith('Another action of this account is in a block'), true);
});

test('what this wallet remembers of the signal: its own changes pass, any other change is told with what to do', async () => {
  await world();
  const plan = PLAN(), payload = SDK.signalSupport({ version: plan.version, spec: plan.spec, activateElapsedMicros: plan.activate_elapsed_micros }), mark = `5:${SPEC}:${plan.activate_elapsed_micros}@7`;
  // The first reading is taken as it is, with or without a signal: there is nothing to compare it with.
  const first = U.compareEntry(null, statusFor('5'));
  assert.deepEqual([first.change, first.memory], [null, { seen: true, entry: 'none', nonce: '3', expected: [], discarded: [], alert: null }]);
  chain.signals = [entry(5, plan, 7)];
  assert.deepEqual([U.compareEntry(null, statusFor('5')).change, U.compareEntry({ damaged: true }, statusFor('5')).change], [null, null]);
  // A signal signed in this wallet, or still held by it as pending: no warning, and the expectation is used up.
  const ours = U.compareEntry(U.expectSignal(first.memory, payload), statusFor('5'));
  assert.deepEqual([ours.change, ours.memory.expected, ours.memory.alert, ours.memory.entry], [null, [], null, mark]);
  assert.equal(U.compareEntry(first.memory, statusFor('5'), { pending: payload }).change, null);
  // The same entry, and this wallet signed nothing: told, and the warning stands while proven state shows that entry.
  const foreign = U.compareEntry(first.memory, statusFor('5'));
  assert.deepEqual([foreign.change, foreign.memory.alert], ['foreign', { kind: 'foreign', entry: mark }]);
  const again = U.compareEntry(foreign.memory, statusFor('5'));
  assert.deepEqual([again.change, again.memory.alert], [null, { kind: 'foreign', entry: mark }]);
  // Having signed another plan, or a withdrawal, excuses nothing; an attempt in which nothing was signed is taken back.
  assert.equal(U.compareEntry(U.expectSignal(first.memory, { ...payload, spec: OTHER }), statusFor('5')).change, 'foreign');
  assert.equal(U.compareEntry(U.expectSignal(first.memory, {}), statusFor('5'), { pending: {} }).change, 'foreign');
  assert.equal(U.compareEntry(U.unexpectSignal(U.expectSignal(first.memory, payload), payload), statusFor('5')).change, 'foreign');
  // A signal the owner discarded here, included after all: its action number is used.
  const forgotten = U.forgetSignal(U.expectSignal(first.memory, payload), { hash: 'AB'.repeat(32), nonce: '4', payload });
  assert.deepEqual([forgotten.expected, forgotten.discarded.length], [[], 1]);
  chain.accounts.at(-1).nonce = '4';
  const taken = U.compareEntry(forgotten, statusFor('5'));
  assert.deepEqual([taken.change, taken.memory.alert.kind, taken.memory.discarded], ['discarded', 'discarded', []]);
  // Signed again after discarding: whichever of the two is included, it is what the owner signed last.
  assert.equal(U.compareEntry(U.expectSignal(forgotten, payload), statusFor('5')).change, null);
  // A discarded signal is forgotten once another action has used its number; until then it is kept.
  chain.signals = [];
  assert.deepEqual([U.compareEntry(forgotten, statusFor('5')).memory.discarded, U.compareEntry({ ...forgotten, discarded: [{ ...forgotten.discarded[0], nonce: '5' }] }, statusFor('5')).memory.discarded.length], [[], 1]);
  // The entry is gone: the network dropped it. Said once, calmly; a warning that stood ends.
  const dropped = U.compareEntry(foreign.memory, statusFor('5'));
  assert.deepEqual([dropped.change, dropped.memory.alert, dropped.memory.entry], ['dropped', null, 'none']);
  // The words, for an account with one key and for a secured account, for support and for a withdrawal.
  chain.signals = [entry(5, plan, chain.now - 60000000n)];
  const lines = U.changeLines(statusFor('5'), 'foreign');
  assert.deepEqual(lines, [`Warning: your validator's signal changed on ${utc(chain.now - 60000000n)}, and this wallet did not send that change. Your validator now supports version 5, start ${utc(plan.activate_elapsed_micros)}, specification hash ${U.groupHash(SPEC)}.`,
    'If you sent it from another device or another wallet, nothing is wrong.',
    'If you did not, someone else holds a key of this account that may spend. Under More, Devices, remove every key you do not know, now.',
    `If your validator should not support that plan, press "Withdraw support" on this page: the network takes the next change of your signal after ${utc(chain.now + 540000000n)}.`]);
  assert.deepEqual(U.changeLines(statusFor('5'), 'discarded'), [`The signed signal you discarded was included after all, on ${utc(chain.now - 60000000n)}: whoever had its bytes had it put in a block. Your validator now supports version 5, start ${utc(plan.activate_elapsed_micros)}, specification hash ${U.groupHash(SPEC)}.`, lines[3]]);
  chain.signals = [{ owner: '5', changed_elapsed_micros: '9' }];
  const securedStatus = { ...statusFor('5') }; securedStatus.account = { ...securedStatus.account, secured: true };
  assert.deepEqual(U.changeLines(securedStatus, 'foreign').slice(2), ['If you did not, someone else holds your payment key. On Home, freeze the account now (the switch "Freeze" under Protection), then make a new payment password under Keys ("Change something", "New payment password"). A frozen account can neither signal nor withdraw: do the next step once the freeze has ended.',
    'If your validator should support a plan, signal it again on this page: the network takes the next change of your signal now.']);
  assert.match(U.changeLines(securedStatus, 'foreign')[0], / Your validator now supports no plan: its support was withdrawn\.$/);
});

test('the tab reads again when the account\'s action number moves, warns of a signal it did not send, and remembers across a restart', async () => {
  await world(); await open();
  const plan = PLAN(), alice = () => chain.accounts.at(-1);
  // The wallet's refresh hands every verified state to the tab. Nothing moved: nothing is read again.
  const reads = client.reads; tab.ui.render(ownAccount(), stateOf()); await settle();
  assert.equal(client.reads, reads);
  // A signal signed here is not a change to warn about.
  type(plan); await submit();
  assert.deepEqual([errors.length, notices.filter(item => /^Warning/.test(item.text)).length, /^Done\./.test(notices.at(-1).text), $('signal-status').children[0].textContent], [0, 0, true, 'The network runs version 4 of its rules.']);
  // Someone else signs for the account (a second key that may spend): the action number moves, the next refresh
  // makes the tab read the status with proofs, and the warning is in the notice and stands above the status.
  chain.now += 700000000n; chain.signals = [entry(5, { ...plan, spec: OTHER }, chain.now)]; alice().nonce = '5'; chain.height += 1;
  const before = client.reads; tab.ui.render(ownAccount(), stateOf()); await settle();
  const warning = `Warning: your validator's signal changed on ${utc(chain.now)}, and this wallet did not send that change. Your validator now supports version 5, start ${utc(plan.activate_elapsed_micros)}, specification hash ${U.groupHash(OTHER)}.`;
  assert.deepEqual([client.reads, notices.at(-1), $('signal-status').children.slice(0, 4).map(line => line.className), $('signal-status').children[0].textContent], [before + 1, { text: warning, type: 'error' }, ['warning', 'warning', 'warning', 'warning'], warning]);
  // Told once: the same state again says nothing new, and the warning stays above the status.
  const told = notices.length; await $('signal-refresh').fire('click');
  assert.deepEqual([notices.slice(told).map(item => item.text), $('signal-status').children[0].textContent], [['Read again from proven state.'], warning]);
  // A new page over the same browser storage (the wallet was closed and opened): the warning still stands, without a second notice.
  dom = new Map(); notices = []; tab.ui = tab.make(); await open();
  assert.deepEqual([$('signal-status').children[0].textContent, notices.length], [warning, 0]);
  // A change made while the wallet was closed is found at the first reading.
  chain.now += 700000000n; chain.signals = [{ owner: '5', changed_elapsed_micros: String(chain.now) }]; alice().nonce = '6'; chain.height += 1;
  dom = new Map(); notices = []; tab.ui = tab.make(); await open();
  assert.deepEqual(notices.map(item => [item.type, item.text]), [['error', `Warning: your validator's signal changed on ${utc(chain.now)}, and this wallet did not send that change. Your validator now supports no plan: its support was withdrawn.`]]);
  // The owner signals again in this wallet, once the network takes a change again: its own change ends the warning.
  chain.now += 700000000n; type(plan); await submit();
  assert.deepEqual([errors.length, /^Done\./.test(notices.at(-1).text), $('signal-status').children[0].textContent], [0, true, 'The network runs version 4 of its rules.']);
  // The network drops the entry (no action of the account): said once, as information.
  chain.signals = []; notices = []; await $('signal-refresh').fire('click');
  assert.deepEqual(notices.map(item => [item.type, item.text]), [['', U.DROPPED_TEXT], ['', 'Read again from proven state.']]);
});

test('a discarded signal: what the wallet says of it, what it does when the signal is included after all, and when discarding is refused', async () => {
  await world(); await open();
  const plan = PLAN(), first = { ...plan, spec: OTHER };
  // The node does not take the first signal; the owner discards it and signs the plan of the announcement, which
  // the gateway accepts and keeps to itself (no receipt comes).
  type(first); await submit();
  const refusedTx = client.submitted.at(-1);
  await $('signal-discard').fire('click');
  assert.deepEqual([errors.length, pending.get(networkId, '5'), notices.at(-1).text], [0, null, U.DISCARDED_NOTICE]);
  const submitNow = client.submit;
  client.submit = async tx => { client.submitted.push(SDK.decodeAction(tx)); throw Object.assign(new Error('Transaction pending; retain its signed bytes and hash.'), { hash: 'AB'.repeat(32) }); };
  type(plan); await submit();
  assert.deepEqual([errors.length, $('signal-result').children[0].textContent, client.submitted.at(-1).nonce, refusedTx.nonce], [0, U.NO_RECEIPT_TEXT, '4', '4']);
  // Whoever has the discarded bytes has them included: the chain takes them, the account's action number is used.
  chain.implemented.push({ version: '5', spec: OTHER }); applySignal(refusedTx); client.submit = submitNow;
  await $('signal-refresh').fire('click');
  const said = $('signal-status').children.map(line => line.textContent);
  assert.equal(said[0], `The signed signal you discarded was included after all, on ${utc(chain.now)}: whoever had its bytes had it put in a block. Your validator now supports version 5, start ${utc(plan.activate_elapsed_micros)}, specification hash ${U.groupHash(OTHER)}.`);
  assert.equal(said[1], `If your validator should not support that plan, press "Withdraw support" on this page: the network takes the next change of your signal after ${utc(chain.now + 600000000n)}.`);
  assert.deepEqual(notices.filter(item => item.type === 'error').at(-1).text, said[0]);
  // The signal signed last is still held as pending, and discarding it is refused: its place is taken.
  await $('signal-discard').fire('click');
  assert.deepEqual([errors.pop().message, reviews.filter(item => item.title === 'Discard the signed signal').length, pending.get(networkId, '5') === null], [U.ALREADY_PLACED_TEXT, 1, false]);
  // Where the wallet offers "Cancel pending action", the pending text and the review point to it.
  assert.match(U.pendingText(statusFor('5'), { payload: {} }, { canCancel: true }), /a withdrawal of your validator's support\. It stays valid until another action of this account is in a block: until then, whoever has its bytes can have it included\. .* To end it for certain, use "Cancel pending action" there\.$/);
  assert.deepEqual(U.discardReview({ canCancel: true })[2], ['To end it for certain', 'Do not discard it. Close this review and use "Cancel pending action" under Activity. That puts another action of this account in a block, and after that the signed signal can never be included.']);
});

test('one step at a time, a tick in every review, and a pending signal of another tab is not this attempt', async () => {
  await world(); await open();
  const plan = PLAN();
  // A key held down on the form sends the form many times: one step runs, one review is shown, one signal is signed.
  type(plan); await Promise.all([submit(), submit(), submit()]);
  assert.deepEqual([reviews.length, client.submitted.length, errors.length], [1, 1, 0]);
  assert.deepEqual([reviews[0].confirm, reviews[0].options], ['Sign the signal', { acknowledge: U.SUPPORT_ACKNOWLEDGE }]);
  chain.now += 700000000n; await $('signal-withdraw').fire('click');
  assert.deepEqual([reviews.at(-1).confirm, reviews.at(-1).options, errors.length], ['Sign the withdrawal', { acknowledge: U.WITHDRAW_ACKNOWLEDGE }, 0]);
  // While this tab's review is open, another tab of the wallet signs the same plan and keeps it as pending. This
  // tab's attempt then signs nothing (the wallet refuses a second pending action), and it says nothing about a
  // signal of its own: no result, and the form is not emptied as after a signature.
  await world(); await open();
  const other = await SDK.signAction(accountActionHeader({ account: ownAccount(), publicKey: tab.full.publicKey, networkId, kind: 'upgrade_signal', payload: SDK.signalSupport({ version: plan.version, spec: plan.spec, activateElapsedMicros: PLAN().activate_elapsed_micros }) }), tab.full.privateKey);
  tab.whileReviewing = async () => pending.put(networkId, '5', { hash: await SDK.transactionHash(other), tx: b64(other), nonce: '4', authEpoch: '0', kind: 'upgrade_signal', label: 'Signal: support version 5', at: Date.now() - 60000 });
  type(PLAN()); await submit();
  assert.deepEqual([reviews.length, client.submitted.length, errors.length, $('signal-result').children.length, $('signal-spec').value, $('signal-check').textContent], [1, 0, 1, 0, SPEC, U.NOT_FINISHED_TEXT]);
});

test('two tabs of the wallet: a signal signed in one is not a foreign signal to the other, and a storage that refuses writes loses nothing on the page', async () => {
  await world(); await open();
  const plan = PLAN(), first = dom, a = tab.ui;
  // A second tab of the same wallet: its own page, the same browser storage. It reads the status before anything is signed.
  dom = new Map(); const second = dom, b = tab.make(); await b.load();
  // The first tab signs and sees its signal included.
  dom = first; type(plan); await submit();
  assert.deepEqual([errors.length, /^Done\./.test(notices.at(-1).text)], [0, true]);
  // The second tab reads again: the entry changed, and this wallet made the change. No warning there.
  dom = second; notices = []; await b.load();
  assert.deepEqual([notices, $('signal-status').children[0].className, /Your validator supports version 5/.test(textOf($('signal-status')))], [[], '', true]);
  // And a change neither tab made is told in both, once each.
  chain.now += 700000000n; chain.signals = [{ owner: '5', changed_elapsed_micros: String(chain.now) }]; chain.accounts.at(-1).nonce = '5'; chain.height += 1;
  await b.load(); dom = first; notices = []; await a.load();
  assert.deepEqual([notices.length, $('signal-status').children[0].className], [0, 'warning'], 'the first tab shows the standing warning that the second tab found and told');
  // A storage that takes no write (full, or blocked): the page keeps what it knows, and its own signal still passes.
  await world(); dom = new Map(); const writes = { refused: 0 };
  const full = { getItem: key => storage.getItem(key), setItem: (key, value) => { if (key.startsWith('timecurrency.signal.')) { writes.refused += 1; throw new Error('QuotaExceededError'); } storage.setItem(key, value); } };
  tab.ui = tab.make(full); await open();
  type(PLAN()); await submit();
  assert.deepEqual([errors.length, writes.refused > 0, notices.filter(item => /^Warning/.test(item.text)).length, /^Done\./.test(notices.at(-1).text)], [0, true, 0, true]);
});
