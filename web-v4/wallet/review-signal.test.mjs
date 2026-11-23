// Independent review of the Validator signal tab (branch upgrade-signal, commit 35f080e).
//
// Each test states a property the tab must have and is expected to FAIL on the code under review:
// a failure here is a finding, not a broken test. Nothing of the code under review is changed.
//
// How these tests differ from upgrade-signal.test.mjs: the tab runs here against the real SDK
// client (client-v4/time-sdk.js `createClient`), so that what a gateway answers reaches the page
// the way it does in a browser: through `request`, `gatewayRefusal`, `getSignalStatus`, `submit`
// and `waitReceipt`. The gateway is a function that answers HTTP requests as it likes. The
// verifier is a stand-in that returns the state of a mock chain for whatever was asked, as the
// installed verifier would for an honest proof: a gateway cannot change it, only refuse to serve.
// The mock chain takes a signed action by the engine's rule for every account action
// (v5/src/engine.rs: the signature, a key that may spend, `owner.nonce + 1 == action.nonce`, the
// authority epoch) and judges a signal with the SDK's own `judgeSignal`.
//
// app.js cannot be loaded outside a browser. Its `sendSigned` is stood in for as in
// upgrade-signal.test.mjs: the same pending record around the submission. The one difference is
// the time limit of the receipt wait (1.5 s here, 45 s in the wallet), so that a test ends.
import test from 'node:test';
import assert from 'node:assert/strict';

const root = new URL('../../', import.meta.url);
await import(new URL('client-v4/time-sdk.js', root).href);
const SDK = globalThis.TimeSDK;

// ------------------------------------------------------------------ fake page
class Storage { m = new Map(); getItem(k) { return this.m.has(k) ? this.m.get(k) : null; } setItem(k, v) { this.m.set(k, String(v)); } removeItem(k) { this.m.delete(k); } }
let runs = [];
class El {
  constructor(id) { Object.assign(this, { id, value: '', hidden: false, textContent: '', disabled: false, checked: false, dataset: {}, type: 'text', children: [], listeners: {}, className: '', classList: { add() {}, remove() {}, toggle() {} } }); }
  addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn); }
  replaceChildren(...c) { this.children = c; } append(...c) { this.children.push(...c); }
  async fire(type) { await Promise.all((this.listeners[type] || []).map(fn => fn({ preventDefault() {} }))); while (runs.length) await runs.shift(); }
}
let dom = new Map();
globalThis.document = { getElementById: id => { if (!dom.has(id)) dom.set(id, new El(id)); return dom.get(id); }, createElement: tag => new El(tag), querySelectorAll: () => [] };
const $ = id => document.getElementById(id);
const textOf = el => [el.textContent, ...(el.children || []).map(textOf)].filter(Boolean).join(' ');

const U = await import(new URL('web-v4/wallet/upgrade-signal.mjs', root).href);
const { createSignalUI } = await import(new URL('web-v4/wallet/upgrade-signal-ui.mjs', root).href);
const { accountActionHeader } = await import(new URL('web-v4/wallet/actions.mjs', root).href);
const { newDevice, b64 } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const { PendingReservations, formatSeconds } = await import(new URL('web-v4/wallet/guards.mjs', root).href);

// ------------------------------------------------------------------ a mock chain
const networkId = 'c6'.repeat(32), GENESIS = 1700000000000000n, DAY = 86400000000n, FEE = '1000';
const SPEC = 'a3b1c5d7'.repeat(8), OTHER = 'a3b1c5d7'.repeat(7) + 'a3b1c5d8', EVIL = 'e71f09c2'.repeat(8);
const REFUSED_BY_NODE = 'this node does not implement that version under that specification hash and neither admits nor proposes signals for it';
let chain, g, tab, errors, reviews, notices;
const validator = (owner, power = '1000') => ({ owner: String(owner), consensus_key: '11'.repeat(32), power: String(power) });
const candidate = (owner, more = {}) => ({ owner: String(owner), consensus_key: '11'.repeat(32), jailed: false, archived: false, self_bond: '86400000000', ...more });
const entry = (owner, plan, changed = '0') => ({ activate_elapsed_micros: plan.activate_elapsed_micros, changed_elapsed_micros: String(changed), owner: String(owner), spec: plan.spec, version: plan.version });
const byOwner = (a, b) => (BigInt(a.owner) < BigInt(b.owner) ? -1 : 1);
/// The verified state for a selection, with what the installed verifier puts in for it and nothing else.
function stateFor(query) {
  const ids = query.ids || [];
  const state = { protocol_version: '4', network_id: networkId, height: String(chain.height), time_micros: (GENESIS + chain.now).toString(), genesis: { genesis_time_micros: GENESIS.toString() }, config: {},
    accounts: chain.accounts.filter(a => ids.includes(a.id)), recovery_cases: [], candidates: Object.fromEntries((query.candidates || []).map(id => [id, chain.candidates[id] ?? null])) };
  if (query.include_security) state.security = ids.map(id => chain.security[id]).filter(Boolean);
  if (query.include_pos) state.pos = { profile: 'production', candidate_ids: Object.keys(chain.candidates), active: chain.active, scheduled: [], safety_hold: false };
  if (query.include_upgrade) state.upgrade = chain.signals.length || chain.plan ? { ...(chain.plan ? { plan: chain.plan } : {}), signals: [...chain.signals].sort(byOwner) } : null;
  return structuredClone(state);
}
const everything = () => ({ ids: chain.accounts.map(a => a.id), candidates: Object.keys(chain.candidates), include_pos: true, include_upgrade: true, include_security: true });
/// The status with every fact known: what the engine counts.
function engineStatus(id) { const state = stateFor(everything()); return SDK.signalStatusOf(state, { account: String(id), facts: SDK.signalFactsOf(state, chain.accounts.map(a => a.id)) }); }
/// One block that holds this signed action, by the rules of the chain. Throws what a node would answer.
/// A proposer's own policy (does its program implement the plan?) is not among them: it is "not a
/// consensus rule" (v5/src/upgrade.rs, `Context::local`), and a block of any proposer is executed without it.
async function include(tx) {
  const action = SDK.decodeAction(tx);
  const key = await crypto.subtle.importKey('raw', SDK.hexToBytes(action.publicKey, 32), 'Ed25519', false, ['verify']);
  if (!await crypto.subtle.verify('Ed25519', key, tx.slice(-64), tx.slice(0, -64))) throw new Error('invalid action signature');
  const account = chain.accounts.find(a => a.id === action.from), device = account?.devices.find(d => d.public_key === action.publicKey);
  if (BigInt(action.nonce) !== BigInt(account.nonce) + 1n || action.authEpoch !== account.auth_epoch) throw new Error('stale authority or incorrect nonce');
  if (!device?.can_spend) throw new Error('spending device required');
  const plan = Object.keys(action.payload).length ? action.payload : null;
  const judged = SDK.judgeSignal(engineStatus(action.from), plan ? { version: plan.version, spec: plan.spec, activateElapsedMicros: plan.activate_elapsed_micros } : { withdraw: true });
  if (!judged.ok) throw new Error('refused by the rules: ' + judged.refusal);
  chain.height += 1; chain.now += 1000000n;
  account.nonce = action.nonce; account.balance = String(BigInt(account.balance) - BigInt(FEE));
  chain.signals = chain.signals.filter(item => item.owner !== action.from).concat([plan ? entry(action.from, plan, chain.now) : { changed_elapsed_micros: String(chain.now), owner: action.from }]);
  chain.included.set(await SDK.transactionHash(tx), { height: String(chain.height), rawHex: SDK.bytesToHex(tx) });
}

// ------------------------------------------------------------------ a gateway that answers as it likes
/// - `view(query)`: null to serve the proof, or the words of a refusal.
/// - `submit(tx)`: what the gateway does with a posted action; what it throws is what it answers.
function gateway() {
  const trust = { app_version: '4', network_id: networkId, chain_id: 'time-devnet-v4-test' };
  const it = { view: () => null, submit: tx => include(tx), posted: [] };
  const block = height => ({ signed_header: { header: { height: String(height) } } });
  const verifier = {
    verifyTrust: async () => ({}),
    verifyLightUpdate: async candidateBlock => ({ verified: true, status: 'VERIFIED', checkpoint: { height: candidateBlock.signed_header.header.height, block_hash: 'cd'.repeat(32), block: candidateBlock } }),
    verifyViewProof: async (_proof, _trust, query) => ({ verified: true, completeAccountSet: false, state: stateFor(query) }),
    verifyReceipt: async proof => ({ verified: true, executionVerified: true, hash: proof.hash, rawHex: proof.rawHex, height: proof.height }),
  };
  const fetcher = async (url, options = {}) => {
    const address = new URL(url), route = address.pathname;
    let answer;
    if (route === '/api/network') answer = { protocolVersion: '4', networkId, chainId: trust.chain_id };
    else if (route === '/api/light-block') answer = block(address.searchParams.get('height') || chain.height);
    else if (route === '/api/view-proof') { const words = it.view(JSON.parse(address.searchParams.get('query'))); answer = words ? { error: words } : { light_block: block(chain.height) }; }
    else if (route === '/api/submit') {
      const tx = new Uint8Array(Buffer.from(JSON.parse(options.body).tx, 'base64')); it.posted.push(tx);
      try { await it.submit(tx); answer = { hash: await SDK.transactionHash(tx) }; } catch (error) { answer = { error: error.message }; }
    } else if (route === '/api/receipt') { const hash = address.searchParams.get('hash'), found = chain.included.get(hash); answer = found ? { hash, ...found, anchor: { light_block: block(chain.height) } } : { pending: true }; }
    else answer = { error: 'unexpected request' };
    return { ok: !answer.error, status: answer.error ? 400 : 200, text: async () => JSON.stringify(answer) };
  };
  it.client = SDK.createClient({ gateway: 'https://rpc.example', trust, verifier, fetcher });
  return it;
}

// ------------------------------------------------------------------ a wallet tab
const pending = new PendingReservations(new Storage());
const ownAccount = () => structuredClone(chain.accounts.find(a => a.name === 'alice'));
/// What app.js `sendSigned` does around a submission: the pending record first, cleared by a verified receipt only.
async function sendSigned(kind, payload, label) {
  const account = ownAccount(), args = accountActionHeader({ account, publicKey: tab.key.publicKey, networkId, kind, payload });
  const old = pending.get(networkId, account.id);
  if (old) throw new Error(`A signed action is already pending (${old.hash}). Check its receipt before signing again.`);
  const tx = await SDK.signAction(args, tab.key.privateKey), hash = await SDK.transactionHash(tx);
  pending.put(networkId, account.id, { hash, tx: b64(tx), nonce: args.nonce, authEpoch: args.authEpoch, kind, label, at: Date.now() });
  await g.client.submit(tx, { wait: false });
  const receipt = await g.client.waitReceipt(hash, { timeoutMs: 1500, ownCheckMs: 1000 });
  pending.clear(networkId, account.id, hash);
  return receipt;
}
const PLAN = () => ({ version: '5', spec: SPEC, activate_elapsed_micros: (chain.now + 30n * DAY).toString() });
/// A fresh world: alice (account 5) owns one of five equal validators; this tab is unlocked with her one key.
async function world() {
  pending.storage.m.clear(); dom = new Map(); runs = []; errors = []; reviews = []; notices = [];
  const key = await newDevice();
  chain = { height: 900, now: 100n * DAY, security: {}, signals: [], plan: null, included: new Map(),
    accounts: [1, 2, 3, 4].map(id => ({ id: String(id), name: 'owner_' + id, balance: '5000000', nonce: '0', auth_epoch: '0', devices: [{ public_key: '2' + String(id).repeat(63), can_manage: true, can_spend: true }] })),
    candidates: Object.fromEntries([1, 2, 3, 4, 5].map(id => [String(id), candidate(id)])), active: [1, 2, 3, 4, 5].map(id => validator(id)) };
  chain.accounts.push({ id: '5', name: 'alice', balance: '5000000', nonce: '3', auth_epoch: '0', devices: [{ public_key: key.publicKey, can_manage: true, can_spend: true }] });
  g = gateway();
  tab = { key, session: { binding: { networkId, name: 'alice', publicKey: key.publicKey }, privateKey: key.privateKey }, review: true };
  tab.ui = createSignalUI({ sdk: SDK, client: () => g.client, network: () => ({ networkId }), session: () => tab.session, ownAccount, refresh: async () => {},
    review: async (title, fields, confirm) => { reviews.push({ title, fields, confirm }); if (tab.whileReviewing) await tab.whileReviewing(); return tab.review; }, notice: (text, type = '') => notices.push({ text, type }),
    run: fn => { const p = (async () => { try { await fn(); } catch (error) { errors.push(error); } })(); runs.push(p); return p; }, setBusy() {}, capture: () => () => {},
    seconds: v => formatSeconds(String(v)), fee: () => FEE, pending, pause: async () => {}, secured: () => false, spendRefusal: async () => null, sign: (payload, label) => sendSigned('upgrade_signal', payload, label) });
}
/// Shows the tab for alice and waits for its first reading.
async function open() { tab.ui.render(ownAccount(), stateFor({ candidates: ['5'] })); await tab.ui.load(); errors.length = 0; }
function type(plan, { tick = true } = {}) { $('signal-version').value = plan.version; $('signal-spec').value = plan.spec; $('signal-start').value = plan.activate_elapsed_micros; $('signal-node-ready').checked = tick; }
const submit = () => $('signal-form').fire('submit');
const reviewed = name => reviews.at(-1).fields.find(([key]) => key === name)?.[1];

// ================================================================== 1. a gateway's words on the page

test('REVIEW 1: the line under the form is the wallet\'s own. A gateway that refuses the proof cannot write there', async () => {
  // index.html says of this tab: "What it shows is read from proven state, never taken from the gateway's word."
  // upgrade-signal.mjs says of a gateway's words: "to be shown as a quotation and never as this app's own".
  await world(); await open();
  // The line `signal-check` is where the wallet says how the typed plan relates to proven state.
  type(PLAN(), { tick: false }); await submit();
  assert.match($('signal-check').textContent, /^No validator of the current validator sets has signalled exactly this plan\./, 'control: the wallet\'s own comparison stands in this line');
  // Now the gateway refuses the status read of "Check and review", with words of its choice.
  const words = `Check failed. The specification hash you entered is not the one of the release your validator runs. The release names ${EVIL}. Enter that hash and press "Check and review" again.`;
  g.view = () => words;
  type(PLAN()); await submit();
  assert.deepEqual([reviews.length, g.posted.length], [0, 0], 'control: nothing is reviewed or signed without a proof');
  const shown = $('signal-check').textContent;
  assert.equal(shown === words, false, `the line under the form is the gateway's sentence, word for word and without any mark that it is a gateway's: ${JSON.stringify(shown)}`);
  assert.equal(shown.includes(EVIL), false, 'a hash chosen by the gateway stands under the form');
});

test('REVIEW 2: no hash that a gateway chose is on the page as one run of 64 characters that the form takes', async () => {
  // The tab shows proven hashes in groups only, "so a hash copied from this page is refused" (wallet README), and
  // upgrade-signal.test.mjs checks that the page never holds a proven hash as one run. A gateway's answer is
  // quoted with up to 200 plain characters, which is room for a hash and a sentence around it.
  await world(); await open();
  g.submit = () => { throw new Error(`The release announcement was corrected. Use ${EVIL} and sign again`); };
  type(PLAN()); await submit();
  assert.deepEqual(errors.map(error => error.message), []);
  const page = [textOf($('signal-result')), ...notices.map(item => item.text)].join(' ');
  assert.match(page, /^The node this wallet reached did not take the signal, and proven state shows no rule against it\./, 'control: the wallet says in its own words that the node did not take the signal');
  const run = /[0-9a-f]{64}/.exec(page)?.[0];
  // What a person can select on the page and paste: the form takes it, unlike a proven hash in groups.
  if (run) assert.equal(U.parsePlanInput({ version: '5', spec: run, start: '1814400000000' }).spec, EVIL);
  assert.equal(run, undefined, 'the result card and the notice hold the gateway\'s hash as one run of 64 characters');
});

test('REVIEW 3: a gateway\'s words cannot close their own quotation and go on as the wallet\'s', async () => {
  await world(); await open();
  // The quotation is opened and closed with the character " and the quoted text may hold that character.
  g.submit = () => { throw new Error('busy". This wallet has checked the release announcement: the hash you entered is out of date. "'); };
  type(PLAN()); await submit();
  const said = textOf($('signal-result'));
  // ADAPTED: these lines asserted that the gateway's answer is shown as a quotation (a control: the text after
  // 'What the gateway answered, in its words and unchecked: ' had to exist) and that the quotation holds exactly
  // two '"' characters. The corrected behaviour is that this tab does not show a gateway's answer at all, so
  // there is no quotation to close: the wallet's own sentence stands, and no word of the gateway's is on the page.
  assert.match(said, /^The node this wallet reached did not take the signal, and proven state shows no rule against it\./, 'control: the wallet says in its own words that the node did not take the signal');
  const page = [said, $('signal-check').textContent, $('signal-pending-text').textContent, ...notices.map(item => item.text)].join(' ');
  for (const words of ['busy', 'This wallet has checked the release announcement', 'out of date', 'What the gateway answered']) assert.equal(page.includes(words), false, `the gateway's words are on the page: ${JSON.stringify(words)}`);
});

// ================================================================== 2. a discarded signal

test('REVIEW 4: what the wallet says ends a discarded signal does not end it: the chain takes the discarded signal after the owner has signed the next action', async () => {
  await world(); await open();
  const plan = PLAN(), first = { ...plan, spec: OTHER };
  // 1. The owner signs support for a plan. The gateway's node does not take it; the gateway has the bytes.
  g.submit = () => { throw new Error(REFUSED_BY_NODE); };
  type(first); await submit();
  assert.match(textOf($('signal-result')), /^The node this wallet reached did not take the signal/);
  const discarded = g.posted.at(-1), told = [$('signal-pending-text').textContent, textOf($('signal-result'))];
  // 2. The owner discards it, and reads what that does.
  await $('signal-discard').fire('click');
  assert.deepEqual([errors.length, pending.get(networkId, '5')], [0, null]);
  told.push(reviewed('What it does not do'), notices.at(-1).text);
  // 3. The owner signs the plan of the announcement: "the next action you sign". The gateway takes it,
  //    answers with its hash, and passes it to nobody.
  g.submit = () => {};
  type(plan); await submit();
  const second = g.posted.at(-1);
  assert.deepEqual([SDK.decodeAction(second).nonce, SDK.decodeAction(discarded).nonce, SDK.decodeAction(second).payload.spec, SDK.decodeAction(discarded).payload.spec], ['4', '4', SPEC, OTHER], 'both signed actions carry the same action number');
  // 4. Whoever has the first bytes has them put in a block now. By the chain's rule they are as good as
  //    on the day they were signed: the account's action number has not moved.
  await include(discarded);
  await assert.rejects(include(second), /stale authority or incorrect nonce/);
  await $('signal-refresh').fire('click');
  assert.equal((await g.client.getSignalStatus('5')).account.supports.spec, OTHER, 'the validator supports the plan its owner discarded');
  assert.match(textOf($('signal-status')), new RegExp(`Your validator supports version 5, start .*, specification hash ${U.groupHash(OTHER)}\\.`));
  // 5. What the wallet had told the owner, four times: that signing another action ends the old one.
  for (const text of told) assert.doesNotMatch(text, /stays valid until this account signs another action|until this account signs another action\. The next action you sign ends that/,
    'the wallet said that the signed signal is valid "until this account signs another action"; it was included after the account had signed another action');
});

// ================================================================== 3. a share the wallet could not check

test('REVIEW 5: where the wallet could not read whether signals count, the review before signing says so too, not only the list of plans', async () => {
  await world();
  const plan = PLAN();
  // Validators 1 to 4 signal the plan. The owner account of validator 4 is secured and frozen, so its signal
  // does not count (v5/src/engine.rs `signal_counts`): the network counts 3000 of 5000, and nothing is scheduled.
  chain.signals = [1, 2, 3, 4].map(owner => entry(owner, plan));
  chain.accounts[3].devices = [{ public_key: '31'.repeat(32), can_manage: false, can_spend: false }, { public_key: '32'.repeat(32), can_manage: false, can_spend: true }, { public_key: '33'.repeat(32), can_manage: true, can_spend: false }, { public_key: '34'.repeat(32), can_manage: true, can_spend: false }];
  chain.security['4'] = { account: '4', version: '1', policy: { threshold: '2', daily_limit_micros: '60000000', delay_seconds: '172800', freeze_seconds: '172800' }, allowance_micros: '60000000', allowance_elapsed_micros: '0', frozen_until_elapsed_micros: String(chain.now + DAY), freezes: '1', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null };
  const counted = engineStatus('5').plans[0].tally;
  assert.deepEqual([counted.lowest, counted.schedule, counted.exact], [{ support: '3000', total: '5000' }, false, true], 'control: what the network counts');
  // The gateway serves the first proof (the sets, the signals, alice) and refuses the others, which would show the freeze.
  g.view = query => (query.include_pos ? null : 'rate limited');
  await open();
  // ADAPTED: this control matched 'It has the four fifths (80%) that schedule a plan.' and '... can be lower than
  // shown.' in the list of plans. Both were part of finding L1: a count the wallet could not check stated a
  // threshold as reached, and named one direction only. The list now says what is proven (not scheduled), the
  // rule, that the count was not checked, and that the network's share can be lower or higher.
  assert.match(textOf($('signal-plans')), /Supported by 4 of 5 validators: 4000 of 5000 votes \(80\.00%\)\. Not scheduled\. A plan is scheduled at four fifths \(80%\) of the votes the network counts\. This wallet could not check that count\. For some of these validators this wallet could not read .* the share the network counts can be lower or higher than shown\./, 'control: the list of plans says that the share was not checked');
  assert.doesNotMatch(textOf($('signal-plans')), /It has the four fifths/);
  tab.review = false; type(plan); await submit();
  assert.deepEqual(errors.map(error => error.message), []);
  const now = reviewed('This plan now'), under = $('signal-check').textContent;
  // ADAPTED: this control asserted that the review's sentence is exactly '4 validators with 80.00% of the votes
  // support exactly this plan. It is scheduled at four fifths (80%).', which is the sentence without the caveat
  // that the next line asks for. It now asserts the unchecked figure, and the next line the caveat with it.
  assert.match(now, /^4 validators with 80\.00% of the votes \(not checked: /, 'control: the figure in the review is the unchecked one');
  for (const text of [now, under]) assert.match(text, /could not read|can be lower|not checked|at most/, `the review and the line under the form give 80.00% as the plan's share, with no word that the wallet could not check it (the network counts 60.00%): ${JSON.stringify(text)}`);
});

// ================================================================== 4. which plans are called similar

test('REVIEW 6: a plan with another hash and another start is not "a similar plan"; whoever signals cannot add a warning to every owner\'s review', async () => {
  // The wallet README: "If a proven plan agrees with yours in version and start time and differs in the hash,
  // the review shows a warning". The code calls a plan similar when it differs in at most two of the three
  // values. Every signal names the next version, so that is every plan anyone has signalled.
  await world(); await open();
  const plan = PLAN(), unrelated = [1, 2, 3].map(owner => ({ version: '5', spec: String(owner).repeat(64), activate_elapsed_micros: (chain.now + BigInt(40 + owner) * DAY).toString() }));
  chain.signals = unrelated.map((other, index) => entry(index + 1, other));
  tab.review = false; type(plan); await submit();
  assert.deepEqual(errors.map(error => error.message), []);
  const warnings = reviews.at(-1).fields.filter(([key]) => key === 'Warning: a similar plan');
  assert.equal(warnings.length, 0, `three validators that signalled three unrelated plans put ${warnings.length} warnings "a similar plan" into this owner's review, each with a hash of their choice: ${JSON.stringify(warnings[0]?.[1])}`);
});

// ================================================================== 5. another tab's signal

test('REVIEW 7: an attempt in which nothing was signed is not reported as "the signed signal was sent"', async () => {
  // The owner has the review of plan A open. In another tab of the same wallet a signal for another plan is
  // signed and stays pending (the pending record is in storage both tabs share). The owner confirms in this
  // tab: app.js refuses to sign while an action is pending, so nothing is signed here.
  await world(); await open();
  const plan = PLAN(), elsewhere = { ...plan, spec: OTHER };
  const other = await SDK.signAction(accountActionHeader({ account: ownAccount(), publicKey: tab.key.publicKey, networkId, kind: 'upgrade_signal', payload: SDK.signalSupport({ version: '5', spec: elsewhere.spec, activateElapsedMicros: elsewhere.activate_elapsed_micros }) }), tab.key.privateKey);
  // While the review of this tab is open, the other tab signs: its pending record appears in the shared storage.
  tab.whileReviewing = async () => pending.put(networkId, '5', { hash: await SDK.transactionHash(other), tx: b64(other), nonce: '4', authEpoch: '0', kind: 'upgrade_signal', label: 'Signal: support version 5', at: Date.now() });
  type(plan); await submit();
  assert.equal(reviews.length, 1, 'control: the review of this tab was shown and confirmed');
  assert.equal(g.posted.length, 0, 'control: this tab signed and sent nothing');
  const said = textOf($('signal-result'));
  assert.equal(said.includes('The signed signal was sent'), false, `nothing was signed or sent in this tab, and it says: ${JSON.stringify(said)}`);
});

// ================================================================== 6. a hold, and who is jailed

test('REVIEW 8: during a safety hold, a plan the network keeps is not announced as "the next block cancels it" because the wallet could not read who is jailed', () => {
  // Five equal validators. 1, 2 and 3 support the scheduled plan. Validator 5, which does not, has signed twice
  // and is jailed: a hold is on, and the engine leaves it out of the count (v5/src/upgrade.rs, `Block::jailed`).
  // The network counts 3000 of 4000: three quarters, the plan stays.
  const now = 100n * DAY, plan = { version: '5', spec: SPEC, activate_elapsed_micros: (now + 30n * DAY).toString() }, owners = ['1', '2', '3', '4', '5'];
  const state = { protocol_version: '4', network_id: networkId, height: '900', time_micros: (GENESIS + now).toString(), genesis: { genesis_time_micros: GENESIS.toString() }, config: {}, recovery_cases: [], security: [],
    accounts: owners.map(id => ({ id, name: 'owner_' + id, balance: '5000000', nonce: '0', auth_epoch: '0', devices: [{ public_key: '2' + id.repeat(63), can_manage: true, can_spend: true }] })),
    candidates: Object.fromEntries(owners.map(id => [id, candidate(id, { jailed: id === '5' })])),
    upgrade: { plan: { ...plan, scheduled_elapsed_micros: '5' }, signals: ['1', '2', '3'].map(owner => entry(owner, plan)) },
    pos: { profile: 'production', candidate_ids: owners, active: owners.map(id => validator(id)), scheduled: [], safety_hold: true } };
  const counted = SDK.signalStatusOf(state, { account: '1', facts: SDK.signalFactsOf(state, owners) }).plans[0].tally;
  assert.deepEqual([counted.lowest, counted.keep, counted.exact], [{ support: '3000', total: '4000' }, true, true], 'control: with every row read, the count is the network\'s: the plan keeps its three quarters');
  // The wallet after its first proof, when the gateway refuses the proofs with the candidate rows
  // (`getSignalStatus`: "a further read failed ... leaves facts out").
  const first = { ...state, accounts: [state.accounts[0]], candidates: { 1: state.candidates['1'] } };
  const lines = U.statusLines({ ...SDK.signalStatusOf(first, { account: '1', facts: SDK.signalFactsOf(first, ['1']), complete: false }), heights: { first: '900', last: '900' } }).plans[0].lines;
  assert.equal(lines[0], 'Supported by 3 of 5 validators: 3000 of 5000 votes (60.00%).', 'control: the wallet counts the jailed validator in the total');
  assert.doesNotMatch(lines.join(' '), /the next block cancels it/, `the wallet says of a plan the network keeps: ${JSON.stringify(lines.slice(1))}`);
});

// ================================================================== 7. "proven state shows" without a proof

test('REVIEW 9: the wallet does not say "proven state shows no rule against it" when it read no proven state, nor "the node did not take the signal" when the signal never left the wallet', async () => {
  await world(); await open();
  // The gateway serves every proof up to the review. From the moment the owner confirms, it refuses everything.
  tab.whileReviewing = async () => { g.view = () => 'service unavailable'; g.submit = () => { throw new Error('service unavailable'); }; };
  type(PLAN()); await submit();
  assert.deepEqual(errors.map(error => error.message), []);
  // The SDK reads the account with a proof before it posts an action (`submit`). That read was refused, so
  // nothing was posted, and none of the wallet's readings afterwards was answered either.
  assert.equal(g.posted.length, 0, 'control: the signed signal was never sent to the gateway');
  assert.notEqual(pending.get(networkId, '5'), null, 'control: it was signed, and is kept as pending');
  const said = textOf($('signal-result'));
  assert.equal(said.includes('proven state shows no rule against it'), false, `no proof was read after signing, and the wallet says: ${JSON.stringify(said.slice(0, 160))}`);
  assert.equal(said.includes('did not take the signal'), false, 'no node was offered the signal');
});

// ================================================================== 8. which validator supports which plan

test('REVIEW 10: the list of validators tells two plans apart whose hashes begin and end alike', async () => {
  // The list shows a validator's plan as version, start and the first and last eight characters of the hash.
  // Two hashes that agree in those sixteen characters (a search of 2^64, within reach of whoever wants a
  // look-alike of the announced hash) give two validators the same line, though they support different rules.
  await world();
  const plan = PLAN(), alike = { ...plan, spec: SPEC.slice(0, 8) + '0'.repeat(48) + SPEC.slice(-8) };
  chain.signals = [entry(1, plan), entry(2, alike)];
  await open();
  const lines = $('signal-validators').children.map(textOf);
  assert.equal(textOf($('signal-plans')).includes(U.groupHash(alike.spec)), true, 'control: the list of plans shows both hashes in full');
  assert.notEqual(lines[0].replace('account 1', ''), lines[1].replace('account 2', ''), `two validators that support different rules have the same line: ${JSON.stringify(lines[0])}`);
});

// ================================================================== 9. a signal the owner did not send

test('REVIEW 11: a signal of this account that this wallet did not send is brought to the owner\'s attention', async () => {
  // docs/design/upgrade-mechanism.md 5.2 answers a stolen spend key with "the owner freezes". For that the
  // owner must learn of the signal. Here a second key of the account that may spend (a stolen one) signals a
  // plan of its holder's choice while the owner's wallet is open on another tab of the wallet.
  await world(); await open();
  assert.match(textOf($('signal-status')), /Your validator has not signalled\./);
  const thief = await newDevice(), alice = chain.accounts.find(a => a.name === 'alice');
  alice.devices.push({ public_key: thief.publicKey, can_manage: false, can_spend: true });
  const stolen = { version: '5', spec: EVIL, activate_elapsed_micros: (chain.now + 30n * DAY).toString() };
  await include(await SDK.signAction(accountActionHeader({ account: ownAccount(), publicKey: thief.publicKey, networkId, kind: 'upgrade_signal', payload: SDK.signalSupport({ version: '5', spec: stolen.spec, activateElapsedMicros: stolen.activate_elapsed_micros }) }), thief.privateKey));
  assert.equal(engineStatus('5').account.supports.spec, EVIL, 'control: proven state shows the validator supporting the thief\'s plan');
  // The wallet refreshes every five seconds (app.js) and hands every verified state to the tab.
  for (let refresh = 0; refresh < 3; refresh++) { tab.ui.render(ownAccount(), stateFor({ candidates: ['5'] })); await new Promise(resolve => setTimeout(resolve, 20)); }
  const seen = [textOf($('signal-status')), ...notices.map(item => item.text)].join(' ');
  assert.equal(seen.includes('Your validator has not signalled.'), false, 'after three refreshes the tab still says that the validator has not signalled');
  assert.match(seen, new RegExp(U.groupHash(EVIL)), 'nothing on the page names the plan the validator now supports');
});
