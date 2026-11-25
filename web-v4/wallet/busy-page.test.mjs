// A network that is busy, on the real page (app.js and its modules, the real SDK) over a stand-in gateway that refuses
// some requests for load: 429 with a plain-text body, or 503 with the gateway's JSON, with or without Retry-After (the
// web audit's W-9; a trial network on 24 November 2026, where a proxy refused 9 requests of 1,130 and wallets stopped for
// them). The wallet starts, opens an account, reads again, pays, freezes and gets test time through such refusals: it
// says "busy" in its header, keeps signing on, sends the same signed bytes again, and asks for no second review. A check
// that truly fails (a proof that does not verify) still turns signing off.
//
// The page's waits are shortened a hundredfold (setTimeout below): a Retry-After of one second is a wait of about ten
// milliseconds here. The stand-in page is the one of waits-clock.test.mjs.
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
const page = await readFile(new URL('./index.html', import.meta.url), 'utf8');
const W = await import(new URL('web-v4/wallet/busy.mjs', root).href);

// ------------------------------------------------------------------ the stand-in page
class Storage { m = new Map(); getItem(k) { return this.m.has(k) ? this.m.get(k) : null; } setItem(k, v) { this.m.set(k, String(v)); } removeItem(k) { this.m.delete(k); } }
const reviews = [];
class El {
  #text = '';
  constructor(id) { Object.assign(this, { id, value: '', hidden: false, disabled: false, checked: false, open: false, returnValue: '', dataset: {}, type: 'text', children: [], listeners: {}, className: '', files: [], classList: { add() {}, remove() {}, toggle() {} } }); }
  // As in a browser, text set on an element replaces what it held.
  get textContent() { return this.#text; } set textContent(value) { this.#text = String(value); this.children = []; }
  addEventListener(type, fn, options) { (this.listeners[type] ??= []).push({ fn, once: options?.once === true }); }
  querySelectorAll() { return [this.querySelector()]; } querySelector() { return this.button ??= new El(this.id + '-button'); }
  replaceChildren(...c) { this.#text = ''; this.children = c; } append(...c) { this.children.push(...c); } remove() {} click() {}
  showModal() { this.open = true; reviews.push($('review-title').textContent); } close() { this.open = false; }
  setAttribute(name, value) { (this.attributes ??= {})[name] = String(value); } getAttribute(name) { return this.attributes?.[name] ?? null; } removeAttribute(name) { delete this.attributes?.[name]; }
  focus() {} select() {} scrollIntoView() {}
  async fire(type) { const list = this.listeners[type] || []; this.listeners[type] = list.filter(item => !item.once); await Promise.all(list.map(item => item.fn({ preventDefault() {}, data: null }))); }
}
let dom = new Map();
const storage = new Storage(), intervals = [], windowListeners = {};
const $ = id => { if (!dom.has(id)) dom.set(id, new El(id)); return dom.get(id); };
const textOf = el => [el.textContent, ...(el.children || []).map(textOf)].filter(Boolean).join(' ').trim();
const PANELS = [...page.matchAll(/<section class="workspace-panel" id="panel-([a-z]+)"/g)].map(found => found[1]);
const HIDDEN = [...page.matchAll(/<[a-z0-9]+\b[^>]*>/g)].map(found => found[0]).filter(tag => /\shidden(?=[\s>])/.test(tag)).map(tag => /\bid="([^"]+)"/.exec(tag)?.[1]).filter(Boolean);
const documentElement = { dataset: {} };
globalThis.document = { getElementById: $, createElement: tag => new El(tag), querySelectorAll: selector => (selector === '.workspace-panel' ? PANELS.map(name => $('panel-' + name)) : []), addEventListener() {}, body: { append() {}, classList: { add() {}, remove() {} } }, title: '', documentElement };
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
// The review arms when the test says; every other wait from one second to five minutes is a hundred times shorter.
globalThis.setTimeout = (fn, ms, ...given) => {
  if (ms === ARM_MS) { arming.push(() => fn(...given)); return null; }
  const timer = realTimeout(fn, ms >= 1000 && ms < 300000 ? Math.ceil(ms / 100) : ms, ...given); if (ms >= 300000) timer.unref(); return timer;
};
const until = async (condition, what) => { for (let turn = 0; turn < 4000; turn++) { if (await condition()) return; await new Promise(resolve => realTimeout(resolve, 5)); } assert.fail(`waited in vain for: ${what} (the notice: ${textOf($('notice'))}; the header: ${$('network-status').textContent})`); };

// ------------------------------------------------------------------ the stand-in chain and its gateway
const NET = 'c6'.repeat(32), GENESIS = 1700000000000000n, DAY = 24n * 3600000000n;
const PASSWORD = 'correct horse battery staple 41', PAYMENT = 'quiet harbour lanterns at dawn 77';
const FAUCET = 'https://faucet.example';
const other = (id, name) => ({ id: String(id), name, balance: '1000000000', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: String(id % 10).repeat(64), can_manage: true, can_spend: true }] });
// `sent`: every submit the gateway took (base64 bytes); `included`: hash to raw hex.
const chain = { height: 900, now: 100n * DAY, security: {}, accounts: [other(1, 'faucet'), other(2, 'bob')], included: new Map(), sent: [], badProof: false };
function stateFor(query) {
  const ids = query.ids || [], names = query.names || [];
  const state = { protocol_version: '4', network_id: NET, height: String(chain.height), time_micros: (GENESIS + chain.now).toString(), genesis: { genesis_time_micros: GENESIS.toString() },
    config: { recovery_min_delay_micros: '30000000', recovery_approval_window_micros: '86400000000', all_new_time_to_validators: true },
    bank: '0', auction_epoch: '1', earning_epochs: {}, earning_bids: {}, stake_owners: {}, name_commits: [],
    accounts: chain.accounts.filter(item => ids.includes(item.id) || names.includes(item.name)), recovery_cases: [], candidates: Object.fromEntries((query.candidates || []).map(id => [id, null])) };
  if (query.include_security) state.security = state.accounts.map(item => chain.security[item.id]).filter(Boolean);
  if (query.include_pos) state.pos = { profile: 'production', candidate_ids: [], active: [], scheduled: [], safety_hold: false, bootstrap_ended: true };
  if (query.include_upgrade) state.upgrade = null;
  return structuredClone(state);
}
const block = height => ({ signed_header: { header: { height: String(height) } } });
globalThis.standInVerifier = {
  verifyTrust: async () => ({}),
  verifyLightUpdate: async candidateBlock => ({ verified: true, status: 'VERIFIED', checkpoint: { height: candidateBlock.signed_header.header.height, block_hash: 'cd'.repeat(32), block: candidateBlock } }),
  verifyViewProof: async (_proof, _trust, query) => { if (chain.badProof) throw new Error('INVALID_LIGHT_BLOCK: the block does not check against the validators this client trusts'); return { verified: true, completeAccountSet: false, state: stateFor(query) }; },
  verifyReceipt: async () => { throw new Error('not used here'); },
  verifyFastReceipt: async ({ tx }) => ({ verified: true, executionVerified: true, hash: tx.hash, rawHex: tx.rawHex, height: String(chain.height) }),
};
// What the gateway refuses for load: the next `count` requests of `route` (every route when null; 'faucet': the faucet's),
// as `status` with `retryAfter` (null: no header). A 429 is plain text, as a proxy sends it; a 503 the gateway's JSON.
const load = { route: null, count: 0, status: 429, retryAfter: '1', refused: 0 };
const refuse = (route, count, { status = 429, retryAfter = '1' } = {}) => Object.assign(load, { route, count, status, retryAfter });
function busyAnswer() {
  load.count -= 1; load.refused += 1;
  const plain = load.status === 429, headers = { 'Content-Type': plain ? 'text/plain' : 'application/json', ...(load.retryAfter === null ? {} : { 'Retry-After': load.retryAfter }) };
  return new Response(plain ? 'Too many requests from your address. Wait a few seconds.' : JSON.stringify({ error: 'The gateway is busy. Try again in a few seconds.', code: 'GATEWAY_BUSY', retryAfterSeconds: 1 }), { status: load.status, headers });
}
const json = (answer, status = 200) => new Response(JSON.stringify(answer), { status, headers: { 'Content-Type': 'application/json' } });
globalThis.fetch = async (url, options = {}) => {
  const address = new URL(String(url), location.origin), route = address.pathname;
  if (load.count > 0 && (load.route === null || load.route === route || (load.route === 'faucet' && address.origin === FAUCET))) return busyAnswer();
  const trust = { app_version: '4', network_id: NET, chain_id: 'time-devnet-v4-test' };
  if (route === '/trust-manifest.json') return json(trust);
  if (address.origin === FAUCET) {
    if (route === '/v1/faucet') return json({ network_id: NET, giving: true, account: '1', registrations: { sponsored: false } });
    if (route === '/v1/faucet/grants') return json({ kind: 'grant', status: 'submitted', hash: await grant(JSON.parse(options.body).account) }, 202);
    return json({ error: { code: 'not_found', message: 'not served here' } }, 404);
  }
  if (route === '/api/network') return json({ protocolVersion: '4', networkId: NET, chainId: trust.chain_id, mode: 'local-devnet', publicLaunchAllowed: false, registrationService: FAUCET });
  if (route === '/api/light-block') return json(block(address.searchParams.get('height') || chain.height));
  if (route === '/api/view-proof') return json({ light_block: block(chain.height) });
  if (route === '/api/submit') {
    const bytes = JSON.parse(options.body).tx, tx = new Uint8Array(Buffer.from(bytes, 'base64')), hash = await SDK.transactionHash(tx);
    chain.sent.push(bytes);
    if (!chain.included.has(hash)) { chain.included.set(hash, Buffer.from(tx).toString('hex')); apply(SDK.decodeAction(tx)); }
    return json({ hash });
  }
  if (route === '/api/receipt') {
    const hash = address.searchParams.get('hash').toUpperCase(), raw = chain.included.get(hash);
    return json(raw ? { fast: true, light_block: block(chain.height), headers: [], tx: { hash, rawHex: raw } } : { pending: true });
  }
  if (route === '/api/notifications') return json({ items: [] });
  return json({ error: 'not served by this stand-in gateway' }, 400);
};
/// What an included action does to the stand-in chain, as far as these tests look: the block, the nonce, a freeze.
function apply(action) {
  chain.height += 1;
  const row = chain.accounts.find(item => item.id === action.from);
  if (row && BigInt(action.nonce) > BigInt(row.nonce)) row.nonce = action.nonce;
  const security = chain.security[action.from];
  if (action.kind === 72 && security) chain.security[action.from] = { ...security, freezes: String(Number(security.freezes) + 1), frozen_until_elapsed_micros: String(chain.now + 2n * DAY), version: String(Number(security.version) + 1) };
}
/// The faucet's grant: a transfer from its account, signed by a key of this test, included at once.
const faucetPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']), faucetPublic = Buffer.from(await crypto.subtle.exportKey('raw', faucetPair.publicKey)).toString('hex');
async function grant(to) {
  const payer = chain.accounts.find(item => item.id === '1'), nonce = (BigInt(payer.nonce) + 1n).toString();
  const tx = await SDK.signAction({ networkId: NET, kind: 'transfer', from: '1', nonce, authEpoch: payer.auth_epoch, publicKey: faucetPublic, payload: { to: String(to), amount: '100000' } }, faucetPair.privateKey);
  const hash = await SDK.transactionHash(tx); chain.included.set(hash, Buffer.from(tx).toString('hex')); payer.nonce = nonce; return hash.toLowerCase();
}

// ------------------------------------------------------------------ carol_p, protected, in this browser
const { newDevice, hex } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const { sealLegacy } = await import(new URL('web-v4/wallet/tests/legacy-vault.mjs', root).href);
const login = await newDevice(), spend = await newDevice(), sheet = await newDevice(), phrase = await newDevice();
const LIMIT = 600000000n;
chain.accounts.push({ id: '14', name: 'carol_p', balance: '900000000', nonce: '7', auth_epoch: '2', recovery_policy: null, devices: [{ public_key: login.publicKey, can_manage: false, can_spend: false }, { public_key: spend.publicKey, can_manage: false, can_spend: true }, { public_key: sheet.publicKey, can_manage: true, can_spend: false }, { public_key: phrase.publicKey, can_manage: true, can_spend: false }] });
chain.security['14'] = { account: '14', version: '1', policy: { threshold: '2', daily_limit_micros: LIMIT.toString(), delay_seconds: '172800', freeze_seconds: '172800' }, allowance_micros: LIMIT.toString(), allowance_elapsed_micros: '0', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null };
storage.setItem(`timecurrency.vault.v1:${NET}:carol_p`, JSON.stringify(await sealLegacy({ ...login.secret, nameSalt: hex(crypto.getRandomValues(new Uint8Array(32))), intent: 'device' }, PASSWORD, { networkId: NET, name: 'carol_p', publicKey: login.publicKey }, argon2id)));
storage.setItem(`timecurrency.spend-vault.v1:${NET}:carol_p`, JSON.stringify(await sealLegacy({ pkcs8: spend.secret.pkcs8 }, PAYMENT, { networkId: NET, name: 'carol_p', publicKey: spend.publicKey }, argon2id, globalThis.crypto, 'spend')));

let pages = 0;
async function freshPage() {
  if (pages > 0) await $('lock-button').fire('click');
  dom = new Map(); for (const type of Object.keys(windowListeners)) delete windowListeners[type];
  for (const id of HIDDEN) $(id).hidden = true;
  $('network-status').textContent = 'Connecting…';
  await import(new URL(`web-v4/wallet/app.js?busy=${++pages}`, root).href);
}
const started = () => /^Connected to the Time test network/.test($('notice').textContent);
async function unlock(name = 'carol_p') {
  await $('mode-unlock').fire('click');
  $('username').value = name; $('password').value = PASSWORD; await $('auth-form').fire('submit');
}
const opened = (name = 'carol_p') => $('dashboard').hidden === false && $('account-name').textContent === '@' + name && $('account-verification').textContent === 'Checked by this browser';
/// Whether the page lets this account sign: the button of Send (a protected account pays with its payment key).
const signing = () => $('send-form').querySelector().disabled === false;
/// The five-second read of an open account, as the page's timer runs it.
const readAgain = () => intervals.filter(fn => fn?.name === 'readAgain').at(-1)();
const header = () => $('network-status').textContent;
async function review() { await until(() => $('review-dialog').open, 'the review'); for (const fire of arming.splice(0)) fire(); return $('review-title').textContent; }
async function confirm() { $('review-ack').checked = true; $('review-dialog').returnValue = 'confirm'; $('review-dialog').open = false; await $('review-dialog').fire('close'); }
const pendingKeys = () => [...storage.m.keys()].filter(key => key.startsWith('timecurrency.pending.v1:'));
const sameBytes = (a, b) => Buffer.from(a, 'base64').equals(Buffer.from(b, 'base64'));
const quiet = () => { $('notice').textContent = ''; $('notice').className = 'notice'; };

// ------------------------------------------------------------------ the tests
test('the words of a busy end: nothing signed, a signed action kept, a kept cancellation whose button sends it again', async () => {
  const { failureNotice } = await import(new URL('web-v4/wallet/actions.mjs', root).href);
  const busy = (extra = {}) => Object.assign(new Error('BUSY: the service is busy; ask again later'), { code: 'BUSY', busy: true, status: 503, ...extra });
  assert.deepEqual([failureNotice(busy()), failureNotice(busy({ hash: 'AB'.repeat(32) })), failureNotice(busy({ hash: 'AB'.repeat(32), sameButton: true }))], [W.BUSY_NOTHING, W.BUSY_KEPT, W.BUSY_KEPT_PRESS_AGAIN]);
  // Not the body of the answer, not the SDK's own sentence: the wallet's words.
  for (const words of [W.BUSY_NOTHING, W.BUSY_KEPT, W.BUSY_KEPT_PRESS_AGAIN]) assert.doesNotMatch(words, /BUSY:|429|503|—/);
});

test('the start: busy answers keep "Connecting…" with the busy line, say nothing alarming, and the wallet is ready when the network answers, with no reload', async () => {
  refuse('/api/view-proof', 9);
  const seen = new Set(), notices = new Set();
  const loading = freshPage();
  await until(() => { seen.add(header()); notices.add(`${$('notice').className}|${$('notice').textContent}`); return started(); }, 'the wallet to start');
  await loading;
  assert.equal(load.count, 0, 'all nine refusals were met: four in a first read, four in a second, one in a third');
  assert.ok(seen.has(W.BUSY_CONNECTING), `the header said: ${[...seen].join(' | ')}`);
  assert.ok(notices.has(`notice busy|${W.BUSY_STARTING}`), 'the quiet notice of a start that waits');
  assert.ok(![...seen].some(line => /signing is off|Cannot check/.test(line)), 'never "signing is off"');
  assert.ok(![...notices].some(line => /notice error|SyntaxError|JSON|Too many requests/.test(line)), [...notices].join(' | '));
  assert.match(header(), /^Network checked · block 900$/);
  assert.equal($('auth-submit').disabled, false, 'ready to open an account');
  assert.equal(documentElement.dataset.busyAnswers, '9', 'each busy answer is counted on the page');
});

test('opening an account through busy answers: it opens, nothing is locked, and signing is on', async () => {
  refuse('/api/view-proof', 3, { status: 503 });
  await unlock();
  await until(() => opened(), 'the account open');
  assert.equal(load.count, 0);
  assert.doesNotMatch(textOf($('notice')), /encrypted vault is saved|could not|locked/i);
  assert.equal($('lock-button').hidden, false);
  assert.ok(signing(), 'signing is on');
});

test('a five-second read refused past its four tries: what was verified stays, signing stays on, the header says busy, no notice; the next read clears it', async () => {
  quiet();
  const before = load.refused;
  refuse('/api/view-proof', 1000);
  readAgain();
  // The next turns of the five-second read come while this one waits: they skip it, and nothing more is asked.
  readAgain(); readAgain();
  await until(() => header() === W.BUSY_STATUS, 'the busy line');
  await until(() => load.refused - before >= 4, 'four refusals');
  await new Promise(resolve => realTimeout(resolve, 150));
  assert.equal(load.refused - before, 4, 'one read: four sends, no more');
  assert.ok(signing(), 'signing stays on');
  assert.ok(opened(), 'the account stays shown, checked');
  assert.equal(textOf($('notice')), '', 'no notice: "Verification paused" is for a check that failed');
  assert.equal(header(), W.BUSY_STATUS);
  load.count = 0;
  await until(() => { readAgain(); return /^Network checked · block/.test(header()); }, 'the header back');
  assert.ok(signing());
});

test('a payment through busy answers: the same signed bytes are sent again after the wait, no second review, and it is verified', async () => {
  const sentBefore = chain.sent.length, reviewsBefore = reviews.length, nonce = chain.accounts.find(item => item.id === '14').nonce;
  refuse('/api/submit', 3, { status: 429, retryAfter: null });
  $('recipient').value = 'bob'; $('amount').value = '0.5'; $('send-payment').value = PAYMENT;
  const sending = $('send-form').fire('submit');
  assert.equal(await review(), 'Send seconds');
  await confirm(); await sending;
  await until(() => $('send-result').hidden === false, 'the payment shown as sent');
  assert.equal(load.count, 0, 'three plain-text 429s without Retry-After, then the same bytes again');
  assert.equal(chain.sent.length - sentBefore, 1, 'the gateway took one submit');
  assert.equal(chain.accounts.find(item => item.id === '14').nonce, String(BigInt(nonce) + 1n), 'one action on the chain');
  assert.deepEqual(reviews.slice(reviewsBefore), ['Send seconds'], 'one review');
  assert.deepEqual(pendingKeys(), [], 'the pending record cleared by the receipt');
  assert.ok(signing());
});

test('a payment whose network stays busy: kept and signed once, said in the wallet\'s words; "Retry the exact signed action" sends the same bytes', async () => {
  const sentBefore = chain.sent.length, reviewsBefore = reviews.length, refusedBefore = load.refused;
  refuse('/api/submit', 1000, { status: 503 });
  $('recipient').value = 'bob'; $('amount').value = '0.25'; $('send-payment').value = PAYMENT;
  const sending = $('send-form').fire('submit');
  await review(); await confirm(); await sending;
  await until(() => textOf($('notice')) === W.BUSY_KEPT, 'the words of a signed action kept');
  assert.equal(load.refused - refusedBefore, 10, 'sent ten times');
  const kept = pendingKeys(); assert.equal(kept.length, 1, 'the signed bytes are kept');
  const record = JSON.parse(storage.getItem(kept[0]));
  assert.equal(chain.sent.length, sentBefore, 'nothing reached the chain');
  assert.ok(signing(), 'signing is on');
  // The network answers again: the next read shows the kept action, and its button sends the same bytes.
  load.count = 0;
  await until(() => { readAgain(); return $('pending-panel').children.some(child => child.textContent === 'Retry the exact signed action'); }, 'the kept action shown');
  await $('pending-panel').children.find(child => child.textContent === 'Retry the exact signed action').fire('click');
  await until(() => pendingKeys().length === 0, 'the kept action sent and verified');
  assert.equal(chain.sent.length - sentBefore, 1);
  assert.ok(sameBytes(chain.sent.at(-1), record.tx), 'the bytes sent are the kept ones');
  assert.equal(reviews.length - reviewsBefore, 1, 'one review in all');
});

test('a freeze is sent with the longest patience; when the network stays busy, an urgent notice with "Try again" sends the same bytes', async () => {
  const refusedBefore = load.refused, sentBefore = chain.sent.length, freezes = chain.security['14'].freezes;
  refuse('/api/submit', 1000, { status: 429, retryAfter: '2' });
  $('freeze-method').value = 'payment'; $('freeze-secret').value = PAYMENT;
  await $('freeze-form').fire('submit');
  assert.equal(await review(), 'Freeze account');
  await confirm();
  await until(() => $('notice').children.some(child => child.id === 'notice-try-again'), 'the urgent notice');
  assert.equal($('notice').className, 'notice error');
  assert.equal(textOf($('notice').children[0]), W.busyProtective('Freeze account'));
  assert.equal(load.refused - refusedBefore, 10, 'ten sends of the same bytes');
  const kept = pendingKeys(); assert.equal(kept.length, 1); assert.match(kept[0], /:security-72-14$/, 'the freeze is kept in its own place');
  const bytes = JSON.parse(storage.getItem(kept[0])).tx;
  assert.ok(signing(), 'signing is on');
  // The network answers: "Try again" sends the same bytes, once, and the account is frozen.
  load.count = 0;
  await $('notice').children.find(child => child.id === 'notice-try-again').fire('click');
  await until(() => textOf($('notice')) === 'Freeze account: sent and verified.', 'the freeze verified');
  assert.equal(chain.security['14'].freezes, String(Number(freezes) + 1));
  assert.equal(chain.sent.length - sentBefore, 1);
  assert.ok(sameBytes(chain.sent.at(-1), bytes), 'the same signed bytes');
  assert.deepEqual(pendingKeys(), []);
});

test('the test faucet: a busy answer is waited for and asked again; a faucet that stays busy says so in plain words, and nothing more', async () => {
  refuse('faucet', 2, { status: 503 });
  await $('faucet-button').fire('click');
  await until(() => /^You received 0\.1 seconds of test time/.test(textOf($('notice'))), 'the grant');
  assert.equal(load.count, 0);
  const sentBefore = chain.sent.length;
  refuse('faucet', 1000, { status: 429 });
  await $('faucet-button').fire('click');
  await until(() => textOf($('notice')) === W.BUSY_FAUCET, 'the plain words');
  assert.equal(chain.sent.length, sentBefore);
  // The request for test time answered busy (the faucet's "the node refused it for now" is a 503 with Retry-After 30):
  // it may have acted, so the request is not sent again by itself, and the words say what may have happened.
  const refused = load.refused;
  refuse('/v1/faucet/grants', 1000, { status: 503, retryAfter: '30' });
  await $('faucet-button').fire('click');
  await until(() => textOf($('notice')) === W.BUSY_FAUCET_ASKED, 'the words of a request that may have been taken');
  assert.equal(load.refused - refused, 1, 'sent once');
  load.count = 0;
});

test('a check that truly fails (a proof that does not verify) still turns signing off, as before', async () => {
  assert.ok(signing());
  chain.badProof = true;
  readAgain();
  await until(() => /^Verification paused\./.test(textOf($('notice'))), 'verification paused');
  assert.equal(signing(), false, 'signing is off');
  assert.equal($('notice').className, 'notice error');
  chain.badProof = false;
});

test('a network busy beyond every budget while an account is opened: the session stays, and the account opens when the network answers', async () => {
  await freshPage(); await until(started, 'the wallet to start');
  // The state the page holds names the account (as after any read with its name typed), so opening it reads once.
  $('username').value = 'carol_p'; await $('refresh').fire('click'); await until(() => !$('notice').className.includes('busy'), 'the read');
  refuse(null, 1000, { status: 503 });
  await unlock();
  await until(() => textOf($('notice')) === W.BUSY_OPENING, 'the words of an opening that waits');
  assert.equal($('lock-button').hidden, false, 'still open: not locked');
  assert.equal(header(), W.BUSY_STATUS);
  load.count = 0;
  await until(() => { readAgain(); return opened(); }, 'the account open after the network answered');
  await until(() => textOf($('notice')) === 'Your account is open. This browser checked your balance with the network.', 'the words of an account opened');
  assert.ok(signing());
});

test('a network busy beyond every budget before an account could be read: locked again in plain words, and nothing else is said', async () => {
  await freshPage(); await until(started, 'the wallet to start');
  refuse(null, 1000, { status: 503 });
  await unlock();
  await until(() => textOf($('notice')) === W.BUSY_UNLOCK, 'the words');
  assert.equal($('notice').className, 'notice ');
  assert.equal($('lock-button').hidden, true, 'locked: open it again');
  load.count = 0;
  await unlock();
  await until(() => opened(), 'the account open at the next try');
});
