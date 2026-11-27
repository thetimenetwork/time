// The screens for people on the test network: "Get test time", the Keys screen and "Sent".
//
// First the functions behind them (actions.mjs): what the wallet sends to the test faucet and what it takes from its
// answers, and what the Keys screen says for each state of an account. Then the real app.js on the stand-in page of
// app.test.mjs (copied from there: a page that makes its elements on demand, a browser storage, the real SDK and
// wallet modules, a stand-in for the compiled verifier and a gateway that answers from a mock chain), with a stand-in
// faucet on another origin. What a person must check in a browser is listed in the wallet's README.
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
const A = await import(new URL('web-v4/wallet/actions.mjs', root).href);
const umdSource = await readFile(new URL('web-v4/wallet/vendor/argon2-4.12.0.umd.min.js', root), 'utf8'), umd = { exports: {} };
new Function('module', 'exports', umdSource)(umd, umd.exports);
const argon2id = umd.exports.argon2id;

const networkId = 'c6'.repeat(32), FAUCET = 'https://faucet.example';

// ------------------------------------------------------------------ the request to the faucet (askFaucet)
/// A faucet that answers `facts` to GET /v1/faucet and `answer` with `status` to a grant; records every call.
function faucet({ facts = { network_id: networkId, account: '1', giving: true }, factsStatus = 200, status = 202, answer = { hash: 'AB'.repeat(32), status: 'submitted' }, factsBytes = null, answerBytes = null, factsDown = false, grantDown = false, grantHangs = false } = {}) {
  const calls = [];
  const fetch = async (url, options = {}) => {
    calls.push({ url: String(url), ...options });
    const grant = String(url).endsWith('/v1/faucet/grants');
    if ((grant && grantDown) || (!grant && factsDown)) throw new TypeError('Failed to fetch');
    if (grant && grantHangs) return new Promise((_, reject) => options.signal.addEventListener('abort', () => reject(options.signal.reason)));
    const text = grant ? (answerBytes ?? JSON.stringify(answer)) : (factsBytes ?? JSON.stringify(facts));
    return new Response(text, { status: grant ? status : factsStatus });
  };
  return { fetch, calls };
}
const ask = (service, extra = {}) => A.askFaucet({ origin: FAUCET, account: '5', networkId, fetch: service.fetch, ...extra });

test('Get test time sends the account number and nothing else, after reading the faucet\'s facts, without cookie, referrer or redirect', async () => {
  const service = faucet();
  assert.deepEqual(await ask(service), { hash: 'AB'.repeat(32), faucetAccount: '1' });
  assert.deepEqual(service.calls.map(c => [c.url, c.method ?? 'GET']), [[FAUCET + '/v1/faucet', 'GET'], [FAUCET + '/v1/faucet/grants', 'POST']]);
  const grant = service.calls[1];
  assert.equal(grant.body, '{"account":"5"}');
  assert.deepEqual(grant.headers, { 'Content-Type': 'application/json' });
  for (const call of service.calls) {
    assert.deepEqual([call.cache, call.credentials, call.redirect, call.referrerPolicy], ['no-store', 'omit', 'error', 'no-referrer']);
    assert.ok(call.signal instanceof AbortSignal, 'every answer is waited for a bounded time');
  }
  // A faucet that names no account of its own: the receipt is then not compared with a sender.
  assert.deepEqual(await ask(faucet({ facts: { network_id: networkId, giving: true } })), { hash: 'AB'.repeat(32), faucetAccount: null });
});

test('Get test time asks nothing of a faucet of another network, of one that is not giving, or of one that does not answer', async () => {
  for (const [service, words] of [
    [faucet({ facts: { network_id: 'd7'.repeat(32), account: '1', giving: true } }), /answers for another network\. Nothing was asked\./],
    [faucet({ facts: { network_id: networkId, account: '1', giving: false, reasons: ['daily_total_given'] } }), /^The test faucet is not giving test time right now\. Try again later\.$/],
    [faucet({ factsStatus: 503 }), /does not answer\. Nothing was asked\./],
    [faucet({ factsDown: true }), /does not answer\. Nothing was asked\./],
    [faucet({ factsBytes: 'not json' }), /does not answer\. Nothing was asked\./],
    [faucet({ factsBytes: JSON.stringify({ network_id: networkId, giving: true, pad: 'x'.repeat(70000) }) }), /does not answer\. Nothing was asked\./],
  ]) {
    await assert.rejects(ask(service), error => words.test(error.message) && error.faucet !== true);
    assert.equal(service.calls.length, 1, 'no grant was asked for');
  }
  // Nothing is asked without a faucet, or for something that is not an account number (a name of digits only would be read as a number).
  const unused = faucet();
  await assert.rejects(A.askFaucet({ origin: '', account: '5', networkId, fetch: unused.fetch }), /names no test faucet/);
  for (const account of ['alice', '@5', '05', '', null, undefined, '5 ']) await assert.rejects(A.askFaucet({ origin: FAUCET, account, networkId, fetch: unused.fetch }), /Open your account first/);
  assert.equal(unused.calls.length, 0);
});

test('Get test time waits a bounded time and reads a bounded answer: a faucet that holds or floods the request holds nothing', async () => {
  const at = Date.now();
  await assert.rejects(ask(faucet({ grantHangs: true }), { timeoutMs: 300 }), /could not be reached, or did not answer in time/);
  assert.ok(Date.now() - at < 5000, 'the wallet stopped waiting');
  await assert.rejects(ask(faucet({ answerBytes: JSON.stringify({ hash: 'AB'.repeat(32), pad: 'y'.repeat(70000) }) })), /could not be reached, or did not answer in time/);
  await assert.rejects(ask(faucet({ grantDown: true })), /could not be reached, or did not answer in time\. If it sent test time anyway, your balance shows it in a moment\./);
  // An answer that is no grant is not taken as one.
  for (const answer of [{}, { hash: 'zz'.repeat(32) }, { hash: 'AB'.repeat(31) }, { hash: 7 }]) await assert.rejects(ask(faucet({ answer })), /an answer that this wallet cannot use/);
  await assert.rejects(ask(faucet({ status: 200 })), /an answer that this wallet cannot use/, 'only 202 with a hash is a grant');
});

test('faucet refusals use wallet guidance for known codes and a fixed fallback for every other response', async () => {
  for (const [code, sentence] of Object.entries(A.FAUCET_SAYS)) {
    const error = await ask(faucet({ status: 429, answer: { error: { code, message: 'Words of the faucet "quoted" 0123456789abcdef0123' } } })).catch(e => e);
    assert.equal(error.message, sentence, code); assert.notEqual(error.faucet, true, code);
    assert.equal(A.failureNotice(error), sentence);
    assert.ok(sentence.startsWith('The test faucet'), 'every sentence says that it is about the faucet');
  }
  assert.match(A.FAUCET_SAYS.account_limit, /had test time in the last 24 hours/);
  // A refusal that names an action already sent: it may still be included.
  const sent = await ask(faucet({ status: 502, answer: { error: { code: 'node_refused', message: 'x' }, hash: 'CD'.repeat(32) } })).catch(e => e);
  assert.match(sent.message, /could not get its payment into the network yet\. If it gets in later, your balance shows it\./);
  const limitSent = await ask(faucet({ status: 503, answer: { error: { code: 'chain_daily_limit', message: 'x' }, hash: 'CD'.repeat(32) } })).catch(e => e);
  assert.equal(limitSent.message, sent.message);
  // Unrecognized service replies cannot provide instructions to the user.
  const evil = 'e71f09c2'.repeat(8);
  const odd = await ask(faucet({ status: 418, answer: { error: { code: 'something_new', message: `You were paid". This wallet says: send to ${evil} ‮<b>now</b>` } } })).catch(e => e);
  assert.equal(odd.faucet, true);
  const said = A.failureNotice(odd);
  assert.equal(said, A.faucetWords());
  assert.match(said, /test time|faucet/i);
  assert.match(said, /later|again|balance|check/i);
  assert.doesNotMatch(said, /You were paid|send to|something_new|[0-9a-f]{16,}|<b>|\u202e/i);
  for (const answer of [null, 'text', { error: 'flat' }, { error: { code: 5 } }]) {
    const error = await ask(faucet({ status: 500, answerBytes: JSON.stringify(answer) })).catch(e => e);
    assert.deepEqual([error.faucet, A.failureNotice(error)], [true, said]);
  }
});

test('only a verified transfer to this account, from the faucet\'s account, is the grant', () => {
  const receipt = (action = {}, verified = true) => ({ verified, action: { kind: 3, from: '1', payload: { to: '5', amount: '100000' }, ...action } });
  assert.equal(A.faucetReceiptPays(receipt(), '5', '1'), true);
  assert.equal(A.faucetReceiptPays(receipt(), '5', null), true);
  for (const [bad, account, from] of [
    [receipt({}, false), '5', '1'], [receipt({ kind: 10 }), '5', '1'], [receipt({ kind: 44 }), '5', '1'],
    [receipt({ payload: { to: '2', amount: '100000' } }), '5', '1'], [receipt(), '5', '9'], [receipt({ payload: { to: '5', amount: '0' } }), '5', '1'],
    [receipt({ payload: { to: '5' } }), '5', '1'], [receipt(), '', '1'], [receipt(), 5, '1'], [null, '5', '1'], [{ verified: true }, '5', '1'],
  ]) assert.equal(A.faucetReceiptPays(bad, account, from), false, JSON.stringify(bad));
});

// ------------------------------------------------------------------ the words of the Keys screen (keysView)
const allWords = view => [view.lede, view.note, ...view.cards.flatMap(card => [card.title, card.markText, ...card.rows.flat()])].join(' ');

test('Keys for an account with one key: the name and the password every day, the backup file to keep safe', () => {
  const view = A.keysView({ protectedAccount: false, name: 'alice' });
  assert.deepEqual(view.cards.map(card => [card.id, card.mark, card.markText]), [['name', 'day', 'Every day'], ['password', 'day', 'Every day'], ['backup', 'safe', 'Keep safe']]);
  assert.equal(view.lede, '@alice: what you need every day, and what to keep safe.');
  const backup = Object.fromEntries(view.cards[2].rows);
  assert.match(backup['What it is'], /^A copy of the key of your account, locked with your password\. It opens your account in another browser, or in this one after its data was cleared\.$/);
  assert.match(backup['Without it'], /the key in it is gone\. With no backup file, so is the account\.$/);
  assert.equal(backup['Why it is safe'], 'The file alone opens nothing: it needs your password. Your password alone opens nothing in another browser: it needs the file. Keep the two apart.');
  const password = Object.fromEntries(view.cards[1].rows);
  assert.match(password['Where it is'], /It is never sent anywhere\./);
  assert.match(password['If you forget it'], /^Nobody can reset it, and your backup file needs it too\. Without it, this account cannot be opened again\.$/);
  // With guardians, or another browser with a key of its own, the account is not lost with this browser.
  const guarded = A.keysView({ protectedAccount: false, name: 'alice', guardians: true }), twice = A.keysView({ protectedAccount: false, name: 'alice', otherKeys: 1 });
  assert.match(Object.fromEntries(guarded.cards[1].rows)['If you forget it'], /guardians you chose can approve a new key/);
  assert.match(Object.fromEntries(twice.cards[1].rows)['If you forget it'], /still open the account in your other browser/);
  for (const other of [guarded, twice]) assert.doesNotMatch(Object.fromEntries(other.cards[2].rows)['Without it'], /so is the account/);
  assert.equal(view.note, '');
});

test('Keys for a protected account: two passwords every day, the recovery words to keep safe (and the Recovery Kit of an account that has one), and this browser, with the account\'s own limit and waiting period', () => {
  const kindOf = recoveryKind => A.keysView({ protectedAccount: true, name: 'carol', limit: '30 seconds', waiting: '48 hours', recoveryKind });
  const rowsOf = view => Object.fromEntries(view.cards.map(card => [card.id, Object.fromEntries(card.rows)]));
  // Words only: one thing to keep safe, the words; both recovery keys come from them.
  const words = kindOf('words'), rows = rowsOf(words);
  assert.deepEqual(words.cards.map(card => [card.id, card.mark, card.markText, card.title]), [['login', 'day', 'Every day', 'Login password'], ['payment', 'day', 'When you pay', 'Payment password'], ['phrase', 'safe', 'Keep safe', 'Recovery words'], ['browser', 'day', 'Every day', 'This browser']]);
  assert.equal(rows.login['What it does'], 'Opens this wallet and signs you in to websites. It cannot pay.');
  assert.match(rows.login['If you forget it'], /In another browser, choose “Recover my account”\. It needs your recovery words, and the account waits 48 hours, frozen/);
  assert.match(rows.payment['What it does'], /^Pays up to 30 seconds at once, fees included/);
  assert.match(rows.payment['Where it is'], /unlocks the payment key that this browser keeps/);
  assert.match(rows.phrase['What it does'], /^Both recovery keys of your account come from them\. With them, lost passwords are replaced after 48 hours\./);
  assert.match(rows.phrase['If someone may have seen them'], /whoever has them can ask for your account: that waits 48 hours, frozen, and only these words can stop it\./);
  assert.match(rows.phrase['If you lose them'], /^New words cannot be made without them/);
  assert.match(rows.browser['If it is lost'], /Recover with your recovery words in another browser\. A backup file brings back the login key only\./);
  assert.match(words.note, /^Your recovery words, on paper, are all your account needs to be recovered: both recovery keys come from them\./);
  // Words and a Recovery Kit: the kit has a card of its own, and recovering needs both.
  const kit = kindOf('kit'), kitRows = rowsOf(kit);
  assert.deepEqual(kit.cards.map(card => card.id), ['login', 'payment', 'sheet', 'phrase', 'browser']);
  assert.match(kitRows.login['If you forget it'], /It needs your recovery words and your Recovery Kit, and the account waits 48 hours/);
  assert.match(kitRows.sheet['What it does'], /With your recovery words: replaces lost passwords, after 48 hours\. It holds your recovery sheet, locked with the words: alone it opens nothing\./);
  assert.match(kitRows.phrase['If you lose them'], /does not open without them\. If you printed it, make new words at once/);
  assert.match(kit.note, /Recovering needs both\./);
  // Not known in this browser (keys made in another one): what holds for both.
  const unknown = A.keysView({ protectedAccount: true, name: 'carol', limit: '30 seconds', waiting: '48 hours' }), unknownRows = rowsOf(unknown);
  assert.deepEqual(unknown.cards.map(card => card.id), ['login', 'payment', 'phrase', 'browser']);
  assert.match(unknownRows.login['If you forget it'], /It needs your recovery words, and your Recovery Kit if your account has one, and the account waits/);
  for (const view of [words, kit, unknown]) assert.match(view.note, /Lost (them|either)\? The account keeps working, but a lost password can no longer be replaced\./);
  // A browser that holds only the login key says so.
  const loginOnly = Object.fromEntries(A.keysView({ protectedAccount: true, name: 'carol', limit: '30 seconds', waiting: '48 hours', paymentKeyHere: false }).cards.map(card => [card.id, Object.fromEntries(card.rows)]));
  assert.match(loginOnly.payment['Where it is'], /kept in another browser of yours, not in this one/);
  assert.equal(loginOnly.browser['What it keeps'], 'Your login key, locked by your login password.');
  // While payments are paused the limit is no amount to name: the card says what the payment password does then.
  const paused = Object.fromEntries(A.keysView({ protectedAccount: true, name: 'carol', limit: '0.001 seconds', waiting: '48 hours', paused: true }).cards.map(card => [card.id, Object.fromEntries(card.rows)]));
  assert.equal(paused.payment['What it does'], 'Payments are paused (see Home): it pays nothing at once now. It can start a payment that waits, and it can freeze the account.');
  assert.match(rows.payment['If someone may know it'], /^Freeze the account at once, on Home\. Then make a new payment password under “Change something”/);
  // Without the policy's words, the sentences still read.
  assert.match(Object.fromEntries(A.keysView({ protectedAccount: true, name: 'carol' }).cards[0].rows)['If you forget it'], /waits the waiting period, frozen/);
});

test('the Keys screen names only places that exist, and none of the laboratory\'s words', () => {
  for (const view of [A.keysView({ protectedAccount: false, name: 'alice' }), A.keysView({ protectedAccount: true, name: 'carol', limit: '1 second', waiting: '1 hour' })]) {
    const words = allWords(view);
    assert.doesNotMatch(words, /Security tab|Activity tab|Devices tab|devnet|\bLAB\b|regtest|Lost your device/i);
    for (const card of view.cards) for (const [term, text] of card.rows) assert.ok(term && text && !/undefined|null/.test(text), `${card.id}: ${term}`);
  }
  assert.deepEqual(['172800', '3600', '7200', '60', '120', '90', '1'].map(A.durationWords), ['48 hours', '1 hour', '2 hours', '1 minute', '2 minutes', '90 seconds', '1 second']);
  assert.equal(A.sentNotice('bob', '1.5'), 'Sent. @bob has the 1.5 seconds now and needs to do nothing. This browser checked the network\'s receipt.');
});

// ------------------------------------------------------------------ the real app.js on a stand-in page, with a stand-in faucet
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
globalThis.setInterval = fn => { intervals.push(fn); return intervals.length; };
globalThis.clearInterval = id => { if (id) intervals[id - 1] = null; };
const realTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...given) => { const timer = realTimeout(fn, ms, ...given); if (ms >= 60000) timer.unref(); return timer; };
const until = async (condition, what) => { for (let turn = 0; turn < 1200; turn++) { if (await condition()) return; await new Promise(resolve => realTimeout(resolve, 5)); } assert.fail(`waited in vain for: ${what} (the wallet's notice: ${$('notice').textContent})`); };

const GENESIS = 1700000000000000n, DAY = 86400000000n, FEE = 1000n, PAYMENT = 'quiet harbour lanterns at dawn 77';
const faucetKey = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
const faucetPublic = Buffer.from(await crypto.subtle.exportKey('raw', faucetKey.publicKey)).toString('hex');
const chain = { height: 900, now: 100n * DAY, security: {}, included: new Map(), posted: [], faucet: { mode: 'grant', calls: [] },
  accounts: [{ id: '1', name: 'faucet', balance: '900000000', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: faucetPublic, can_manage: true, can_spend: true }] },
    { id: '2', name: 'bob', balance: '1000000', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: '2'.repeat(64), can_manage: true, can_spend: true }] }] };
const alice = () => chain.accounts.find(item => item.name === 'alice');
function stateFor(query) {
  const ids = query.ids || [], names = query.names || [];
  const state = { protocol_version: '4', network_id: networkId, height: String(chain.height), time_micros: (GENESIS + chain.now).toString(), genesis: { genesis_time_micros: GENESIS.toString() }, config: { recovery_min_delay_micros: '30000000', all_new_time_to_validators: true },
    bank: '0', auction_epoch: '1', earning_epochs: {}, earning_bids: {}, stake_owners: {}, name_commits: [],
    accounts: chain.accounts.filter(item => ids.includes(item.id) || names.includes(item.name)), recovery_cases: [], candidates: Object.fromEntries((query.candidates || []).map(id => [id, null])) };
  if (query.include_security) state.security = state.accounts.map(item => chain.security[item.id]).filter(Boolean);
  if (query.include_pos) state.pos = { profile: 'production', candidate_ids: [], active: [], scheduled: [], safety_hold: false, bootstrap_ended: true };
  if (query.include_upgrade) state.upgrade = null;
  return structuredClone(state);
}
/// One block that holds this signed transfer: the chain's rules for a transfer, as far as this test needs them.
async function include(tx) {
  const action = SDK.decodeAction(tx), from = chain.accounts.find(item => item.id === action.from), to = chain.accounts.find(item => item.id === action.payload.to);
  const key = await crypto.subtle.importKey('raw', SDK.hexToBytes(action.publicKey, 32), 'Ed25519', false, ['verify']);
  if (!await crypto.subtle.verify('Ed25519', key, tx.slice(-64), tx.slice(0, -64))) throw new Error('invalid action signature');
  if (action.kind !== 3 || !to || BigInt(action.nonce) !== BigInt(from.nonce) + 1n || !from.devices.some(d => d.public_key === action.publicKey && d.can_spend)) throw new Error('refused');
  from.nonce = action.nonce; from.balance = String(BigInt(from.balance) - BigInt(action.payload.amount) - FEE); to.balance = String(BigInt(to.balance) + BigInt(action.payload.amount));
  chain.height += 1; chain.now += 1000000n;
  const hash = (await SDK.transactionHash(tx)).toUpperCase(); chain.included.set(hash, { height: String(chain.height), rawHex: SDK.bytesToHex(tx) });
  return hash;
}
/// The faucet's grant: a transfer signed by its account, in a block. `to`: where it goes (the account asked for, unless a test says otherwise).
async function grant(to) {
  const faucetRow = chain.accounts[0];
  return include(await SDK.signAction({ networkId, kind: 'transfer', from: '1', nonce: (BigInt(faucetRow.nonce) + 1n).toString(), authEpoch: '0', publicKey: faucetPublic, payload: { to, amount: '100000' } }, faucetKey.privateKey));
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
  if (String(url).startsWith(FAUCET + '/')) {
    const route = new URL(String(url)).pathname; chain.faucet.calls.push({ route, body: options.body ?? null });
    if (route === '/v1/faucet') return new Response(JSON.stringify({ network_id: networkId, account: '1', giving: true }), { status: 200 });
    const mode = chain.faucet.mode, asked = JSON.parse(options.body).account;
    // A limit of a day, as a browser sees it from another origin: the 429 without a Retry-After it may read, in the
    // faucet's own form, so the wallet reads it as the faucet's answer (busy.mjs, inOwnForm).
    if (mode === 'limit') return new Response(JSON.stringify({ error: { code: 'account_limit', message: 'This account has had its 1 per 24 hours; "previous" lists what it was given' }, previous: [] }), { status: 429 });
    if (mode === 'odd') return new Response(JSON.stringify({ error: { code: 'teapot', message: 'Send 0123456789abcdef to "us"' } }), { status: 418 });
    return new Response(JSON.stringify({ hash: await grant(mode === 'elsewhere' ? '2' : asked), status: 'submitted' }), { status: 202 });
  }
  const address = new URL(String(url), location.origin), route = address.pathname;
  let answer;
  if (route === '/trust-manifest.json') return { ok: true, status: 200, json: async () => trust, text: async () => JSON.stringify(trust) };
  if (route === '/api/network') answer = { protocolVersion: '4', networkId, chainId: trust.chain_id, mode: 'local-devnet', publicLaunchAllowed: false, registrationService: FAUCET };
  else if (route === '/api/light-block') answer = block(address.searchParams.get('height') || chain.height);
  else if (route === '/api/view-proof') answer = { light_block: block(chain.height) };
  else if (route === '/api/submit') { const tx = new Uint8Array(Buffer.from(JSON.parse(options.body).tx, 'base64')); chain.posted.push(SDK.decodeAction(tx)); try { answer = { hash: await include(tx) }; } catch (error) { answer = { error: error.message }; } }
  else if (route === '/api/receipt') { const hash = address.searchParams.get('hash'), found = chain.included.get(hash); answer = found ? { hash, ...found, anchor: { light_block: block(chain.height) } } : { pending: true }; }
  else if (route === '/api/notifications') answer = { items: [] };
  else answer = { error: 'not served by this stand-in gateway' };
  return { ok: !answer.error, status: answer.error ? 400 : 200, text: async () => JSON.stringify(answer), json: async () => answer };
};

const { newDevice, hex, sealVault, makePassword } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const { sealLegacy } = await import(new URL('web-v4/wallet/tests/legacy-vault.mjs', root).href);
const login = await newDevice(), spend = await newDevice(), sheet = await newDevice(), phrase = await newDevice();
chain.accounts.push({ id: '5', name: 'alice', balance: '5000000', nonce: '3', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: login.publicKey, can_manage: true, can_spend: true }] });
// The key of an account with one key, as the wallet makes it now: under a password it made (the rule, vault.mjs RULE).
const MADE = makePassword(), PASSWORD = MADE.text;
storage.setItem(`timecurrency.vault.v1:${networkId}:alice`, JSON.stringify(await sealVault({ ...login.secret, nameSalt: hex(crypto.getRandomValues(new Uint8Array(32))), intent: 'device' }, MADE, { networkId, name: 'alice', publicKey: login.publicKey }, argon2id)));
await import(new URL('web-v4/wallet/app.js', root).href);
await until(() => /^Connected to the Time test network/.test($('notice').textContent) || $('notice').className.includes('error'), 'the wallet to start');
async function unlock() { $('username').value = 'alice'; $('password').value = PASSWORD; await $('auth-form').fire('submit'); await until(() => $('dashboard').hidden === false && $('account-verification').textContent === 'Checked by this browser', 'the dashboard'); }
const cards = () => $('keys-cards').children.map(card => [card.dataset.key, card.className, textOf(card.children[0])]);

test('on the stand-in page: the wallet offers "Get test time" because its service names a faucet, and Keys shows an account with one key', async () => {
  assert.equal($('faucet-button').hidden, false);
  await unlock();
  assert.deepEqual([$('balance').textContent, $('account-name').textContent, $('account-verification').className, $('proof-height').textContent], ['5', '@alice', 'badge ok', 'against the network at block 900']);
  assert.deepEqual(cards(), [['name', 'key-card day', 'Your name Every day'], ['password', 'key-card day', 'Your password Every day'], ['backup', 'key-card safe', 'Your backup file Keep safe']]);
  assert.deepEqual([$('keys-change').hidden, $('security-adopt').hidden, $('home-backup').hidden, $('security-inbox-card').hidden, $('backup-export-label').textContent], [true, false, false, true, 'Your password, to unlock the file once']);
  assert.equal($('keys-lede').textContent, '@alice: what you need every day, and what to keep safe.');
});

test('on the stand-in page: Get test time asks the faucet for this account by number, checks the receipt, and shows the balance it verified', async () => {
  chain.faucet.calls.length = 0;
  await $('faucet-button').fire('click');
  assert.deepEqual(chain.faucet.calls, [{ route: '/v1/faucet', body: null }, { route: '/v1/faucet/grants', body: '{"account":"5"}' }]);
  assert.equal($('notice').textContent, 'You received 0.1 seconds of test time. This browser checked that it arrived.');
  assert.equal($('balance').textContent, '5.1');
  assert.match(textOf($('home-activity')), /^Test time from the faucet Checked by this browser · block 901/);
  // A refusal the faucet's README lists: the wallet's sentence, as an error; nothing is recorded.
  chain.faucet.mode = 'limit'; await $('faucet-button').fire('click');
  assert.deepEqual([$('notice').textContent, $('notice').className.includes('error')], [A.FAUCET_SAYS.account_limit, true]);
  // Unknown faucet replies display the same fixed guidance in the actual wallet.
  chain.faucet.mode = 'odd'; await $('faucet-button').fire('click');
  assert.equal($('notice').textContent, A.faucetWords());
  assert.doesNotMatch($('notice').textContent, /Send 0123|to us/i);
  // A faucet that answers with the hash of a payment to someone else: the wallet does not say that anything arrived.
  chain.faucet.mode = 'elsewhere'; await $('faucet-button').fire('click');
  assert.equal($('notice').textContent, 'The test faucet says that it sent test time. This browser has not seen it arrive yet: your balance changes by itself when it does.');
  assert.equal($('balance').textContent, '5.1');
  chain.faucet.mode = 'grant';
});

test('on the stand-in page: a payment ends with "Sent" and what the other person has to do, in the notice and under the form', async () => {
  const bobBefore = BigInt(chain.accounts.find(item => item.name === 'bob').balance);
  $('recipient').value = 'bob'; $('amount').value = '1.5';
  const sending = $('send-form').fire('submit');
  await until(() => $('review-dialog').open, 'the review');
  assert.deepEqual([$('review-title').textContent, $('review-confirm').disabled], ['Send seconds', true]);
  await new Promise(resolve => realTimeout(resolve, 760));
  $('review-dialog').returnValue = 'confirm'; $('review-dialog').open = false; await $('review-dialog').fire('close'); await sending;
  assert.equal($('notice').textContent, 'Sent. @bob has the 1.5 seconds now and needs to do nothing. This browser checked the network\'s receipt.');
  assert.deepEqual([$('send-result').hidden, $('send-result-text').textContent], [false, '@bob has the 1.5 seconds now and needs to do nothing. This browser checked the network\'s receipt.']);
  assert.equal(BigInt(chain.accounts.find(item => item.name === 'bob').balance) - bobBefore, 1500000n);
  await $('send-form').fire('input');
  assert.equal($('send-result').hidden, true, 'the next payment starts without the last "Sent"');
});

test('on the stand-in page: two paid names that look alike are both marked under the name, where one is picked; the review of either says so, with the tick; a refresh does not draw the names again', async () => {
  // The list as an earlier version kept it, in the clear: the next unlock encrypts it (locked-store.mjs).
  storage.setItem(`timecurrency.names.v1:${networkId}:alice`, JSON.stringify({ paid: ['bob', 'b0b'] }));
  await $('lock-button').fire('click'); await unlock();
  assert.equal(storage.getItem(`timecurrency.names.v1:${networkId}:alice`), null, 'the list is no longer kept in the clear');
  await $('refresh').fire('click');
  assert.deepEqual($('paid-names').children.map(chip => [chip.textContent, chip.className]), [['@b0b', 'chip alike'], ['@bob', 'chip alike']]);
  assert.deepEqual([$('paid-names-wrap').hidden, $('paid-names-alike').hidden], [false, false]);
  const drawn = $('paid-names').children; await $('refresh').fire('click');
  assert.equal($('paid-names').children, drawn, 'the same chips: a refresh does not take the focus from one');
  $('recipient').value = 'bob'; $('amount').value = '0.1';
  const sending = $('send-form').fire('submit');
  await until(() => $('review-dialog').open, 'the review');
  // A paid name that looks like another paid name: the review says so, with the tick (web audit of November 2026, W-4:
  // one of the two may be written into this browser's list by someone else). It names the account it comes from and its
  // button what it does.
  assert.deepEqual([$('review-ack-wrap').hidden, $('review-ack-text').textContent, $('review-confirm').textContent], [false, 'I checked the name, letter by letter.', 'Send 0.1 seconds']);
  assert.match(textOf($('review-body')), /You have paid\s+@bob\s+before, and also\s+@b0b\s*, which looks like it\. One of them may not be who you think\. Check every letter\./);
  assert.match(textOf($('review-body')), /From @alice · account 5 To @bob · account 2/);
  $('review-dialog').returnValue = 'cancel'; $('review-dialog').open = false; await $('review-dialog').fire('close'); await sending;
  storage.removeItem(`timecurrency.names.v2:${networkId}:alice`);
});

test('on the stand-in page: a lock closes a review that is open, and leaves nothing of the account in Payments, Activity or Receive', async () => {
  $('recipient').value = 'bob'; $('amount').value = '0.2';
  const sending = $('send-form').fire('submit');
  await until(() => $('review-dialog').open, 'the review');
  await $('lock-button').fire('click');
  assert.equal($('review-dialog').open, false, 'the review of the locked account is closed');
  // The browser sends "close" when a dialog is closed; the stand-in page does not, so the test does.
  await $('review-dialog').fire('close'); await sending;
  assert.deepEqual([$('recipient').value, $('amount').value, $('send-payment').value, $('activity-list').children.length, $('pending-panel').children.length, $('receive-name').textContent, $('receive-number').textContent, $('paid-names').children.length, $('paid-names-wrap').hidden],
    ['', '', '', 0, 0, '@—', '', 0, true]);
  assert.equal(chain.posted.filter(action => action.payload?.amount === '200000').length, 0, 'nothing was signed');
});

test('on the stand-in page: locking empties Home; a protected account shows its things by the kind of its recovery keys, "Change something", and no backup suggestion', async () => {
  await $('lock-button').fire('click');
  assert.deepEqual([$('balance').textContent, $('account-name').textContent, $('account-verification').textContent, $('account-verification').className, $('approval-account').hidden], ['—', '@—', 'Not checked yet', 'badge', true]);
  assert.deepEqual([$('home-activity').children.length, $('keys-cards').children.length, $('keys-lede').textContent], [0, 0, ''], 'nothing of the last account is left on Home or Keys');
  // The account as "Protect my account" leaves it: this browser's key is the login key, a payment key is kept here under the payment password.
  alice().devices = [{ public_key: login.publicKey, can_manage: false, can_spend: false }, { public_key: spend.publicKey, can_manage: false, can_spend: true }, { public_key: sheet.publicKey, can_manage: true, can_spend: false }, { public_key: phrase.publicKey, can_manage: true, can_spend: false }];
  chain.security['5'] = { account: '5', version: '1', policy: { threshold: '2', daily_limit_micros: '30000000', delay_seconds: '172800', freeze_seconds: '172800' }, allowance_micros: '30000000', allowance_elapsed_micros: '0', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null };
  storage.setItem(`timecurrency.spend-vault.v1:${networkId}:alice`, JSON.stringify(await sealLegacy({ pkcs8: spend.secret.pkcs8 }, PAYMENT, { networkId, name: 'alice', publicKey: spend.publicKey }, argon2id, globalThis.crypto, 'spend')));
  await unlock();
  // This browser does not know the kind of the account's recovery keys: Keys says what holds for both.
  assert.deepEqual(cards().map(([id, className]) => [id, className]), [['login', 'key-card day'], ['payment', 'key-card day'], ['phrase', 'key-card safe'], ['browser', 'key-card day']]);
  assert.match(textOf($('keys-cards')), /your Recovery Kit if your account has one/);
  // Once it remembers them as words and a kit (security-flows.mjs, recoveryKindOf), the kit has its card.
  storage.setItem(`timecurrency.recovery-kind.v1:${networkId}:alice`, JSON.stringify({ kind: 'kit', keys: [sheet.publicKey, phrase.publicKey].sort() }));
  await $('lock-button').fire('click'); await unlock();
  assert.deepEqual(cards().map(([id, className]) => [id, className]), [['login', 'key-card day'], ['payment', 'key-card day'], ['sheet', 'key-card safe'], ['phrase', 'key-card safe'], ['browser', 'key-card day']]);
  // Remembered for other keys than the account's of now, the kind is not used.
  storage.setItem(`timecurrency.recovery-kind.v1:${networkId}:alice`, JSON.stringify({ kind: 'words', keys: [sheet.publicKey, login.publicKey].sort() }));
  await $('lock-button').fire('click'); await unlock();
  assert.deepEqual(cards().map(([id]) => id), ['login', 'payment', 'phrase', 'browser']);
  assert.match(textOf($('keys-cards')), /your Recovery Kit if your account has one/);
  assert.match(textOf($('keys-cards')), /Pays up to 30 seconds at once, fees included/);
  assert.match(textOf($('keys-cards')), /the account waits 48 hours, frozen/);
  assert.match(textOf($('keys-cards')), /Your login key and your payment key, each locked by its own password\./);
  assert.deepEqual([$('keys-change').hidden, $('security-adopt').hidden, $('security-dashboard').hidden, $('home-backup').hidden, $('keys-note').hidden, $('backup-export-label').textContent, $('tab-home').textContent, $('security-title').textContent],
    [false, true, false, true, false, 'Your login password, to unlock the file once', 'Home', 'Your account is protected.']);
  await $('lock-button').fire('click');
});
