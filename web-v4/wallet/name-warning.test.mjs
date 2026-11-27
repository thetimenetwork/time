// The warning before a payment to a name that looks like a name this account has paid (names.mjs; app.js, `review`,
// `payeeLines` and `paidNamesNow`), and the plain words for a new name that the chain refuses as too close to another.
//
// The real app.js on the stand-in page of app.test.mjs and screens.test.mjs (copied from there: a page that makes its
// elements on demand, a browser storage, the real SDK and wallet modules, a stand-in for the compiled verifier and a
// gateway that answers from a mock chain). Two things are added here:
// - the page can be loaded again (`freshPage`): app.js is imported once more, as a browser does on a reload, onto new
//   elements and the same storage; also as the window a website opens (`/approve`), and for a second network;
// - the mock chain takes payments to websites, and its gateway can refuse an action with words of its choice.
// No browser runs here: that the two names are in fact drawn in a font that tells 1 from l is for a person to see.
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
const N = await import(new URL('web-v4/wallet/names.mjs', root).href);
const umdSource = await readFile(new URL('web-v4/wallet/vendor/argon2-4.12.0.umd.min.js', root), 'utf8'), umd = { exports: {} };
new Function('module', 'exports', umdSource)(umd, umd.exports);
const argon2id = umd.exports.argon2id;

// ------------------------------------------------------------------ a stand-in page, which can be loaded again
/// The browser's storage. `failNames`: writing the record of paid names fails, as a full or refused storage does.
class Storage {
  m = new Map(); failNames = false;
  getItem(k) { return this.m.has(k) ? this.m.get(k) : null; }
  setItem(k, v) { if (this.failNames && k.startsWith('timecurrency.names.v2:')) throw new Error('QuotaExceededError'); this.m.set(k, String(v)); }
  removeItem(k) { this.m.delete(k); }
}
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
globalThis.document = { getElementById: $, createElement: tag => new El(tag), querySelectorAll: () => [], addEventListener() {}, body: { append() {}, classList: { add() {}, remove() {} } }, title: '' };
Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: new Proxy(storage, { ownKeys: t => [...t.m.keys()], getOwnPropertyDescriptor: (t, k) => t.m.has(k) ? { enumerable: true, configurable: true, value: t.m.get(k) } : Reflect.getOwnPropertyDescriptor(t, k), get: (t, k) => typeof t[k] === 'function' ? t[k].bind(t) : t[k] }) });
Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { locks: { request: (name, options, fn) => fn() }, clipboard: { writeText: async () => {} } } });
// The website that opened the wallet's window: it hears what the wallet answers.
const website = { postMessage(message, origin) { answered.push({ message, origin }); } };
globalThis.window = { addEventListener(type, fn) { (windowListeners[type] ??= []).push(fn); }, opener: null };
globalThis.location = { origin: 'https://wallet.example', pathname: '/' };
globalThis.isSecureContext = true;
globalThis.hashwasm = { argon2id };
globalThis.BroadcastChannel = undefined;
globalThis.setInterval = fn => { intervals.push(fn); return intervals.length; };
globalThis.clearInterval = id => { if (id) intervals[id - 1] = null; };
const realTimeout = globalThis.setTimeout;
// The button of a review works only after a short delay (app.js, REVIEW_ARM_MS). Here the timer of that delay waits
// for the test (`armed`), so that nothing asserted about the button races a clock on a loaded machine. That the delay
// itself holds is tested where `review` runs alone (review-browser-review.test.mjs). No other timer of the wallet or
// of the SDK has that length.
const ARM_MS = Number(/\nconst REVIEW_ARM_MS = ([0-9]+);/.exec(await readFile(new URL('./app.js', import.meta.url), 'utf8'))?.[1]);
assert.ok(ARM_MS > 0, 'app.js names the delay of a review');
const arming = [];
globalThis.setTimeout = (fn, ms, ...given) => { if (ms === ARM_MS) { arming.push(() => fn(...given)); return null; } const timer = realTimeout(fn, ms, ...given); if (ms >= 60000) timer.unref(); return timer; };
const until = async (condition, what) => { for (let turn = 0; turn < 2400; turn++) { if (await condition()) return; await new Promise(resolve => realTimeout(resolve, 5)); } assert.fail(`waited in vain for: ${what} (the wallet's notice: ${$('notice').textContent})`); };

// ------------------------------------------------------------------ a mock chain behind a gateway, and a registration service
const NET1 = 'c6'.repeat(32), NET2 = 'd7'.repeat(32), FAUCET = 'https://faucet.example', SHOP = 'https://shop.example';
const GENESIS = 1700000000000000n, DAY = 86400000000n, FEE = 1000n, PASSWORD = 'correct horse battery staple 41', PAYMENT = 'quiet harbour lanterns at dawn 77';
const net = { id: NET1 };
const other = (id, name) => ({ id: String(id), name, balance: '1000000', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: String(id % 10).repeat(64), can_manage: true, can_spend: true }] });
// The names on this chain: some look like others. alice (5) and dana (13) are added below, with this browser's keys.
const chain = { height: 900, now: 100n * DAY, security: {}, included: new Map(), posted: [], commits: [], refusal: () => null,
  accounts: [other(1, 'faucet'), other(2, 'bob'), other(3, 'b0b'), other(4, 'carol'), other(6, 'karol'), other(7, 'mall'), other(8, 'mail'), other(9, 'erin'), other(10, 'er1n'), other(11, 'shop'), other(12, 'sh0p'), other(14, 'd4na')] };
const row = name => chain.accounts.find(item => item.name === name);
function stateFor(query) {
  const ids = query.ids || [], names = query.names || [];
  const state = { protocol_version: '4', network_id: net.id, height: String(chain.height), time_micros: (GENESIS + chain.now).toString(), genesis: { genesis_time_micros: GENESIS.toString() }, config: { recovery_min_delay_micros: '30000000', all_new_time_to_validators: true },
    bank: '0', auction_epoch: '1', earning_epochs: {}, earning_bids: {}, stake_owners: {}, name_commits: chain.commits,
    accounts: chain.accounts.filter(item => ids.includes(item.id) || names.includes(item.name)), recovery_cases: [], candidates: Object.fromEntries((query.candidates || []).map(id => [id, null])) };
  if (query.include_security) state.security = state.accounts.map(item => chain.security[item.id]).filter(Boolean);
  if (query.include_pos) state.pos = { profile: 'production', candidate_ids: [], active: [], scheduled: [], safety_hold: false, bootstrap_ended: true };
  if (query.include_upgrade) state.upgrade = null;
  return structuredClone(state);
}
/// One block that holds this signed payment (a transfer, or a payment to a website), or the guardian policy of an
/// account with one key: the chain's rules for it, as far as these tests need them.
async function include(tx) {
  const action = SDK.decodeAction(tx), from = chain.accounts.find(item => item.id === action.from), to = chain.accounts.find(item => item.id === action.payload.to);
  const key = await crypto.subtle.importKey('raw', SDK.hexToBytes(action.publicKey, 32), 'Ed25519', false, ['verify']);
  if (!await crypto.subtle.verify('Ed25519', key, tx.slice(-64), tx.slice(0, -64))) throw new Error('invalid action signature');
  if (action.kind === SDK.KINDS.set_recovery) {
    if (!from || BigInt(action.nonce) !== BigInt(from.nonce) + 1n || !from.devices.some(d => d.public_key === action.publicKey && d.can_manage && d.can_spend)) throw new Error('refused');
    from.nonce = action.nonce; from.balance = String(BigInt(from.balance) - FEE); from.recovery_version = '1';
    from.recovery_policy = { guardians: action.payload.guardians, threshold: action.payload.threshold, delay_seconds: action.payload.delay_seconds, accepted: [] };
  } else {
  if (![SDK.KINDS.transfer, SDK.KINDS.merchant_payment].includes(action.kind) || !from || !to || BigInt(action.nonce) !== BigInt(from.nonce) + 1n || !from.devices.some(d => d.public_key === action.publicKey && d.can_spend)) throw new Error('refused');
  from.nonce = action.nonce; from.balance = String(BigInt(from.balance) - BigInt(action.payload.amount) - FEE); to.balance = String(BigInt(to.balance) + BigInt(action.payload.amount));
  }
  chain.height += 1; chain.now += 1000000n;
  const hash = (await SDK.transactionHash(tx)).toUpperCase(); chain.included.set(hash, { height: String(chain.height), rawHex: SDK.bytesToHex(tx) });
  return hash;
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
  if (String(url).startsWith(FAUCET + '/')) {
    // The registration service: it sponsors, and to a request it answers that this very registration waits on the
    // chain already, which it then does (app.js, registrationSponsor: the wallet goes on from proven state).
    const route = new URL(String(url)).pathname;
    if (route === '/v1/faucet') return new Response(JSON.stringify({ network_id: net.id, account: '1', giving: true, registrations: { sponsored: true } }), { status: 200 });
    if (route !== '/v1/faucet/registrations') return new Response('{}', { status: 404 });
    const asked = JSON.parse(options.body);
    chain.commits.push({ public_key: asked.public_key, commitment: asked.commitment, height: String(chain.height), expires_elapsed_micros: asked.expires_elapsed_micros });
    chain.height += 1; chain.now += 1000000n;
    return new Response(JSON.stringify({ error: { code: 'already_committed', message: 'A registration of this key is waiting' }, same_commitment: true }), { status: 409 });
  }
  const address = new URL(String(url), location.origin), route = address.pathname;
  let answer;
  const trust = { app_version: '4', network_id: net.id, chain_id: 'time-devnet-v4-test' };
  if (route === '/trust-manifest.json') return { ok: true, status: 200, json: async () => trust, text: async () => JSON.stringify(trust) };
  if (route === '/api/network') answer = { protocolVersion: '4', networkId: net.id, chainId: trust.chain_id, mode: 'local-devnet', publicLaunchAllowed: false, registrationService: FAUCET };
  else if (route === '/api/light-block') answer = block(address.searchParams.get('height') || chain.height);
  else if (route === '/api/view-proof') answer = { light_block: block(chain.height) };
  else if (route === '/api/submit') {
    const tx = new Uint8Array(Buffer.from(JSON.parse(options.body).tx, 'base64')), action = SDK.decodeAction(tx), refused = chain.refusal(action);
    chain.posted.push(action);
    if (refused) answer = { error: refused }; else try { answer = { hash: await include(tx) }; } catch (error) { answer = { error: error.message }; }
  }
  else if (route === '/api/receipt') { const hash = address.searchParams.get('hash'), found = chain.included.get(hash); answer = found ? { hash, ...found, anchor: { light_block: block(chain.height) } } : { pending: true }; }
  else if (route === '/api/notifications') answer = { items: [] };
  else answer = { error: 'not served by this stand-in gateway' };
  return { ok: !answer.error, status: answer.error ? 400 : 200, text: async () => JSON.stringify(answer), json: async () => answer };
};

// ------------------------------------------------------------------ the wallet: alice and dana in one browser, alice on two networks
const { newDevice, hex, storageKeyFrom, fromB64 } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const { sealLegacy } = await import(new URL('web-v4/wallet/tests/legacy-vault.mjs', root).href);
const PS = await import(new URL('web-v4/wallet/locked-store.mjs', root).href);
const login = await newDevice(), danaKey = await newDevice(), spend = await newDevice(), sheet = await newDevice(), phrase = await newDevice();
chain.accounts.push({ id: '5', name: 'alice', balance: '9000000', nonce: '3', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: login.publicKey, can_manage: true, can_spend: true }] });
chain.accounts.push({ id: '13', name: 'dana', balance: '9000000', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: danaKey.publicKey, can_manage: true, can_spend: true }] });
const vault = async (networkId, name, device) => storage.setItem(`timecurrency.vault.v1:${networkId}:${name}`, JSON.stringify(await sealLegacy({ ...device.secret, nameSalt: hex(crypto.getRandomValues(new Uint8Array(32))), intent: 'device' }, PASSWORD, { networkId, name, publicKey: device.publicKey }, argon2id)));
await vault(NET1, 'alice', login); await vault(NET1, 'dana', danaKey); await vault(NET2, 'alice', login);
// What this browser kept of alice's activity before the record of paid names existed, in the clear as an earlier version
// kept it (encrypted at the first unlock: locked-store.mjs): a payment to erin, and an action that pays nobody.
const plainActivityKey = (name, networkId = NET1) => `timecurrency.activity.v1:${networkId}:${name}`;
const plainNamesKey = (name, networkId = NET1) => `timecurrency.names.v1:${networkId}:${name}`;
storage.setItem(plainActivityKey('alice'), JSON.stringify([{ hash: 'AB'.repeat(32), height: '800', label: 'Send 2 s to @erin', at: 0 }, { hash: 'CD'.repeat(32), height: '801', label: 'Test time from the faucet', at: 0 }]));
/// Where the activity and the record of paid names are kept, encrypted, for one account on one network.
const activityKey = (name, networkId = NET1) => PS.placeOf('activity', networkId, name);
const namesKey = (name, networkId = NET1) => PS.placeOf('names', networkId, name);
/// The record of paid names as the browser holds it, for one account on one network, read with the account's login key
/// (locked-store.mjs, peek) once what the page was writing is written; null when there is none.
const keyOf = { alice: login, dana: danaKey };
async function record(name, networkId = NET1) {
  const device = keyOf[name], storageKey = await storageKeyFrom(fromB64(device.secret.pkcs8, 256), { networkId, name, publicKey: device.publicKey });
  const read = async () => JSON.stringify((await PS.peek({ storage, networkId, name, publicKey: device.publicKey, storageKey }))?.names ?? null);
  let last = await read();
  for (let turn = 0; turn < 100; turn++) { await new Promise(resolve => realTimeout(resolve, 10)); const now = await read(); if (now === last) break; last = now; }
  assert.equal(storage.getItem(plainNamesKey(name, networkId)), null, 'no record of paid names is kept in the clear');
  return JSON.parse(last);
}

let pages = 0;
/// Loads the wallet's page again, as a reload does: the page before it is locked and its elements are gone; the storage stays.
async function freshPage({ pathname = '/', opener = null } = {}) {
  if (pages > 0) await $('lock-button').fire('click');
  dom = new Map(); for (const type of Object.keys(windowListeners)) delete windowListeners[type];
  location.pathname = pathname; window.opener = opener;
  // In the page the box of the review is hidden until a review asks for it.
  $('review-ack-wrap').hidden = true;
  await import(new URL(`web-v4/wallet/app.js?page=${++pages}`, root).href);
  await until(() => /^Connected to the Time test network/.test($('notice').textContent) || $('notice').className.includes('error'), 'the wallet to start');
  assert.match($('notice').textContent, /^Connected to the Time test network/);
}
async function unlock(name) {
  await $('mode-unlock').fire('click');
  $('username').value = name; $('password').value = PASSWORD; await $('auth-form').fire('submit');
  await until(() => $('dashboard').hidden === false && $('account-name').textContent === '@' + name && $('account-verification').textContent === 'Checked by this browser', `the dashboard of ${name}`);
}

// ------------------------------------------------------------------ a review, as a person meets it
const opened = () => until(() => $('review-dialog').open, 'the review');
/// The end of the first moments of a review, in which its button cannot be pressed: the delay's timer fires now.
const armed = async () => { assert.ok(arming.length > 0, 'a review set the timer of its delay'); for (const fire of arming.splice(0)) fire(); };
async function close(button) { $('review-dialog').returnValue = button; $('review-dialog').open = false; await $('review-dialog').fire('close'); }
async function tick() { $('review-ack').checked = true; await $('review-ack').fire('change'); }
/// What the open review says about the name the payment goes to, and its box and button.
function shown() {
  const body = $('review-body').children, notes = body.filter(item => /\bname-check\b/.test(item.className));
  return {
    title: $('review-title').textContent,
    // The lines about the name, each as the sentence its pieces make, and where they stand: before the fields.
    notes: notes.map(item => item.children.map(piece => piece.textContent).join('')), layout: body.map(item => (notes.includes(item) ? 'note' : item.id)),
    warning: notes.some(item => /\bwarning\b/.test(item.className)),
    // The names that are set in the font that tells 1 from l: elements <code>.
    names: notes.flatMap(item => item.children.filter(piece => piece.id === 'code').map(piece => piece.textContent)),
    asks: $('review-ack-wrap').hidden ? null : $('review-ack-text').textContent, disabled: $('review-confirm').disabled,
  };
}
const NOTHING_NEW = { notes: [], layout: ['dl'], warning: false, names: [], asks: null };
const about = seen => ({ notes: seen.notes, layout: seen.layout, warning: seen.warning, names: seen.names, asks: seen.asks });
const first = name => ({ notes: [`First payment to @${name}.`], layout: ['note', 'dl'], warning: false, names: ['@' + name], asks: null });
/// A name paid before that looks like another name paid before (web audit of November 2026, W-4).
const paidAlike = (name, known) => ({ notes: [`You have paid @${name} before, and also @${known}, which looks like it. One of them may not be who you think. Check every letter.`], layout: ['note', 'dl'], warning: true, names: ['@' + name, '@' + known], asks: 'I checked the name, letter by letter.' });
const alike = (name, known) => ({ notes: [`You have not paid @${name} before. It looks like @${known}, which you have paid. Check every letter.`], layout: ['note', 'dl'], warning: true, names: ['@' + name, '@' + known], asks: 'I checked the name, letter by letter.' });
/// Starts a payment from the Send screen and waits for its review. What it gives back waits for the end of the payment
/// when called (the promise itself would be waited for here, before the review is answered).
async function send(name, amount, payment = '') { $('recipient').value = name; $('amount').value = amount; $('send-payment').value = payment; const step = $('send-form').fire('submit'); await opened(); return () => step; }
/// The review of a payment, which is then cancelled: nothing is signed.
async function looked(name, payment = '') { const step = await send(name, '0.1', payment); const seen = shown(); await close('cancel'); await step(); return about(seen); }
/// A payment that is reviewed, ticked if the review asks for it, and confirmed once its button can be pressed.
async function pay(name, amount, payment = '') { const step = await send(name, amount, payment); const seen = shown(); if (seen.asks) await tick(); await armed(); await close('confirm'); await step(); return about(seen); }
const sentTo = name => new RegExp(`^Sent\\. @${name} has the `);

await freshPage();

test('at unlock the record of paid names is filled from the activity this browser kept: who a payment went to, and nothing else', async () => {
  assert.equal(storage.getItem(namesKey('alice')), null, 'no record before the account is opened');
  await unlock('alice');
  assert.deepEqual(await record('alice'), { paid: ['erin'] });
  // A name known from the activity is a name that was paid: its review says nothing new.
  assert.deepEqual(await looked('erin'), NOTHING_NEW);
});

test('a first payment to a name that looks like no paid name shows one plain line and asks for no tick; a repeat payment shows neither', async () => {
  const before = chain.posted.length, bob = BigInt(row('bob').balance);
  const step = await send('bob', '1.5'), seen = shown();
  assert.equal(seen.title, 'Send seconds');
  assert.deepEqual(about(seen), first('bob'));
  assert.equal(seen.disabled, true, 'the short delay on the button is as before');
  await armed();
  assert.equal($('review-confirm').disabled, false, 'no tick is asked for: the button works once the delay is over');
  await close('confirm'); await step();
  assert.match($('notice').textContent, sentTo('bob'));
  assert.deepEqual([chain.posted.length - before, chain.posted.at(-1).payload.to, BigInt(row('bob').balance) - bob], [1, '2', 1500000n]);
  // The name is recorded when the payment's receipt was verified, and the next review of a payment to it is as it always was.
  assert.deepEqual(await record('alice'), { paid: ['erin', 'bob'] });
  assert.deepEqual(await looked('bob'), NOTHING_NEW);
  assert.deepEqual(await pay('bob', '0.5'), NOTHING_NEW);
  assert.match($('notice').textContent, sentTo('bob'));
  assert.deepEqual(await record('alice'), { paid: ['erin', 'bob'] });
});

test('a first payment to a name that looks like a paid one shows a warning with both names and cannot be approved until the box is ticked', async () => {
  const before = chain.posted.length, b0b = row('b0b').balance;
  let step = await send('b0b', '1'), seen = shown();
  assert.deepEqual(about(seen), alike('b0b', 'bob'));
  assert.equal(seen.disabled, true);
  // The delay is over and the box is not ticked: the button stays disabled.
  await armed();
  assert.equal($('review-confirm').disabled, true, 'not without the tick');
  // Closed as confirmed all the same (a key held down, or a button that something enabled): it counts as cancelled.
  await close('confirm'); await step();
  assert.deepEqual([chain.posted.length, row('b0b').balance, await record('alice')], [before, b0b, { paid: ['erin', 'bob'] }], 'nothing was signed, and the name is not a paid one');
  assert.doesNotMatch($('notice').textContent, /^Sent/);
  // The next review starts with an empty box. Ticked at once, the button still waits for the delay; then it works.
  step = await send('b0b', '1');
  assert.deepEqual([$('review-ack').checked, $('review-confirm').disabled], [false, true]);
  await tick();
  assert.equal($('review-confirm').disabled, true, 'the tick does not shorten the delay');
  await armed();
  assert.equal($('review-confirm').disabled, false);
  await close('confirm'); await step();
  assert.match($('notice').textContent, sentTo('b0b'));
  assert.deepEqual([chain.posted.length - before, chain.posted.at(-1).payload.to, BigInt(row('b0b').balance) - BigInt(b0b)], [1, '3', 1000000n]);
  // The person has now paid both names. A payment to either says so again, with the tick: one of the two may be a name
  // that someone else wrote into this browser's list (web audit of November 2026, W-4).
  assert.deepEqual(await record('alice'), { paid: ['erin', 'bob', 'b0b'] });
  assert.deepEqual(await looked('b0b'), paidAlike('b0b', 'bob'));
  assert.deepEqual(await looked('bob'), paidAlike('bob', 'b0b'));
});

test('the softer tricks are warned about too: a digit written for a letter, and one changed letter', async () => {
  const before = chain.posted.length;
  // er1n has another skeleton than erin (erln, erin); with i read as l they are one name.
  assert.deepEqual([N.resembles('er1n', 'erin'), await looked('er1n')], ['loose', alike('er1n', 'erin')]);
  // carol looks like nobody alice has paid. Once she has paid carol, karol is one letter away.
  assert.deepEqual(await looked('karol'), first('karol'));
  assert.deepEqual(await pay('carol', '0.25'), first('carol'));
  assert.deepEqual([N.resembles('karol', 'carol'), await looked('karol')], ['edit', alike('karol', 'carol')]);
  assert.deepEqual([chain.posted.length - before, await record('alice')], [1, { paid: ['erin', 'bob', 'b0b', 'carol'] }]);
});

test('the record of paid names survives a reload of the page, also when the activity it was filled from is gone', async () => {
  storage.removeItem(activityKey('alice'));
  await freshPage(); await unlock('alice');
  assert.deepEqual(await record('alice'), { paid: ['erin', 'bob', 'b0b', 'carol'] });
  for (const name of ['erin', 'carol']) assert.deepEqual(await looked(name), NOTHING_NEW, name);
  assert.deepEqual([await looked('bob'), await looked('b0b')], [paidAlike('bob', 'b0b'), paidAlike('b0b', 'bob')]);
  assert.deepEqual(await looked('karol'), alike('karol', 'carol'));
  assert.deepEqual(await looked('mall'), first('mall'));
});

test('the record is one per account: what alice has paid says nothing about what dana has', async () => {
  await $('lock-button').fire('click');
  await unlock('dana');
  assert.equal(storage.getItem(namesKey('dana')), null);
  // dana has paid nobody: bob is a first payment for her, and so is b0b, which looks like nobody she has paid.
  assert.deepEqual(await looked('b0b'), first('b0b'));
  assert.deepEqual(await pay('bob', '0.5'), first('bob'));
  assert.deepEqual([await record('dana'), await record('alice')], [{ paid: ['bob'] }, { paid: ['erin', 'bob', 'b0b', 'carol'] }]);
  // Now b0b looks like a name dana has paid. carol, whom alice has paid, is new to dana.
  assert.deepEqual(await looked('b0b'), alike('b0b', 'bob'));
  assert.deepEqual(await looked('carol'), first('carol'));
  assert.deepEqual(await looked('karol'), first('karol'));
});

test('the record is one per network: a name paid on one network is not a paid name on another', async () => {
  net.id = NET2;
  await freshPage(); await unlock('alice');
  assert.equal(storage.getItem(namesKey('alice', NET2)), null);
  assert.deepEqual(await looked('bob'), first('bob'));
  assert.deepEqual(await looked('b0b'), first('b0b'));
  assert.deepEqual(await pay('mall', '0.25'), first('mall'));
  assert.deepEqual(await looked('mail'), alike('mail', 'mall'));
  assert.deepEqual([await record('alice', NET2), await record('alice', NET1)], [{ paid: ['mall'] }, { paid: ['erin', 'bob', 'b0b', 'carol'] }]);
  // Back on the first network, mall is a name alice has not paid there, and it looks like none she has.
  net.id = NET1;
  await freshPage(); await unlock('alice');
  assert.deepEqual(await looked('mall'), first('mall'));
  assert.deepEqual(await looked('bob'), paidAlike('bob', 'b0b'));
  assert.deepEqual(await record('alice', NET1), { paid: ['erin', 'bob', 'b0b', 'carol'] });
});

test('a protected account: the same line, warning and tick in the review of a payment with the payment password, and in both ways to pay above the limit', async () => {
  await $('lock-button').fire('click');
  // The account as "Protect my account" leaves it: this browser's key is the login key, a payment key is kept under the payment password.
  row('alice').devices = [{ public_key: login.publicKey, can_manage: false, can_spend: false }, { public_key: spend.publicKey, can_manage: false, can_spend: true }, { public_key: sheet.publicKey, can_manage: true, can_spend: false }, { public_key: phrase.publicKey, can_manage: true, can_spend: false }];
  chain.security['5'] = { account: '5', version: '1', policy: { threshold: '2', daily_limit_micros: '1000000', delay_seconds: '172800', freeze_seconds: '172800' }, allowance_micros: '1000000', allowance_elapsed_micros: '0', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null };
  storage.setItem(`timecurrency.spend-vault.v1:${NET1}:alice`, JSON.stringify(await sealLegacy({ pkcs8: spend.secret.pkcs8 }, PAYMENT, { networkId: NET1, name: 'alice', publicKey: spend.publicKey }, argon2id, globalThis.crypto, 'spend')));
  await unlock('alice');
  assert.equal($('send-payment-wrap').hidden, false, 'Send asks for the payment password');
  const before = chain.posted.length;
  // Within the limit. A name alice has paid; a first payment; then a name that looks like the one just paid.
  assert.deepEqual(await looked('bob', PAYMENT), paidAlike('bob', 'b0b'));
  assert.deepEqual(await pay('mail', '0.2', PAYMENT), first('mail'));
  assert.match($('notice').textContent, sentTo('mail'));
  assert.deepEqual([chain.posted.length - before, chain.posted.at(-1).publicKey === spend.publicKey, await record('alice')], [1, true, { paid: ['erin', 'bob', 'b0b', 'carol', 'mail'] }]);
  // Confirmed without the tick: nothing is signed, and the payment password is not left in its field.
  let step = await send('mall', '0.2', PAYMENT);
  assert.deepEqual(about(shown()), alike('mall', 'mail'));
  await armed(); assert.equal($('review-confirm').disabled, true);
  await close('confirm'); await step();
  assert.deepEqual([chain.posted.length - before, $('send-payment').value], [1, '']);
  // Ticked: the payment key signs.
  assert.deepEqual(await pay('mall', '0.2', PAYMENT), alike('mall', 'mail'));
  assert.match($('notice').textContent, sentTo('mall'));
  assert.deepEqual([chain.posted.length - before, chain.posted.at(-1).publicKey === spend.publicKey, chain.posted.at(-1).payload.to], [2, true, '7']);
  // Above what is left for today the wallet offers two ways to pay. Each has a review of its own, with the same warning.
  $('recipient').value = 'karol'; $('amount').value = '2'; $('send-payment').value = PAYMENT; await $('send-form').fire('submit');
  assert.deepEqual([$('send-over-limit').hidden, $('review-dialog').open], [false, false]);
  for (const [button, title] of [['send-wait', 'Pay after the waiting period'], ['send-now', 'Pay now with a recovery paper']]) {
    const running = $(button).fire('click'); step = () => running; await opened();
    const seen = shown();
    assert.deepEqual([seen.title, about(seen)], [title, alike('karol', 'carol')], button);
    await armed(); assert.equal($('review-confirm').disabled, true, button);
    await close('confirm'); await step();
  }
  assert.equal(chain.posted.length - before, 2, 'neither was signed without the tick');
  await $('send-over-cancel').fire('click');
});

test('a payment a website asks for: the name of the account it names is checked like a typed one, for an account with one key and for a protected one', async () => {
  let asked = 0;
  /// The website asks for a payment to an account, by its number, with a fresh order for the payer's next action.
  function ask(payer, to) {
    const orderId = SDK.orderReference({ nonce: (BigInt(row(payer).nonce) + 1n).toString(), expiresElapsedMicros: (chain.now + 600000000n).toString() });
    for (const listener of windowListeners.message) listener({ data: { type: 'time:request', version: 1, id: `request-${++asked}`, request: { type: 'payment', networkId: net.id, to: row(to).id, amount: '100000', orderId } }, source: website, origin: SHOP });
    assert.equal($('approval-title').textContent, 'Pay this website?', $('notice').textContent);
  }
  const approve = async () => { const step = $('approve-request').fire('click'); await opened(); return () => step; };
  await freshPage({ pathname: '/approve', opener: website }); await unlock('dana');
  const before = chain.posted.length;
  // A first payment to the account @shop: the plain line.
  ask('dana', 'shop'); let step = await approve(), seen = shown();
  assert.deepEqual([seen.title, about(seen)], ['Approve website payment', first('shop')]);
  await armed(); await close('confirm'); await step();
  assert.deepEqual([$('approval-title').textContent, chain.posted.length - before, chain.posted.at(-1).kind, chain.posted.at(-1).payload.to], ['Done', 1, SDK.KINDS.merchant_payment, '11']);
  assert.deepEqual([answered.at(-1).origin, answered.at(-1).message.result?.accountId], [SHOP, '13']);
  // The account that was paid is a paid name from then on, although the label of such a payment names an order only.
  assert.deepEqual(await record('dana'), { paid: ['bob', 'shop'] });
  ask('dana', 'shop'); step = await approve();
  assert.deepEqual(about(shown()), NOTHING_NEW);
  await close('cancel'); await step(); await $('deny-request').fire('click');
  // Another website names the account @sh0p: the warning, and no payment without the tick.
  ask('dana', 'sh0p'); step = await approve();
  assert.deepEqual(about(shown()), alike('sh0p', 'shop'));
  await armed(); assert.equal($('review-confirm').disabled, true);
  await close('confirm'); await step();
  assert.equal(chain.posted.length - before, 1, 'nothing was signed without the tick');
  // The same request, approved again and ticked this time: paid.
  step = await approve(); await tick(); await armed(); await close('confirm'); await step();
  assert.deepEqual([$('approval-title').textContent, chain.posted.length - before, chain.posted.at(-1).payload.to, await record('dana')], ['Done', 2, '12', { paid: ['bob', 'shop', 'sh0p'] }]);
  // A protected account (alice, who has paid carol): the review of the website's payment carries the warning too.
  await $('lock-button').fire('click'); await unlock('alice');
  ask('alice', 'karol'); $('approval-payment').value = PAYMENT; step = await approve(); seen = shown();
  assert.deepEqual([seen.title, about(seen)], ['Approve website payment', alike('karol', 'carol')]);
  await armed(); assert.equal($('review-confirm').disabled, true);
  await close('confirm'); await step();
  assert.deepEqual([chain.posted.length - before, $('approval-payment').value], [2, '']);
  await $('deny-request').fire('click');
});

test('a record that cannot be read or written costs the warning its memory and no payment', async () => {
  // dana's record is damaged, and the activity that could fill it again is gone.
  storage.removeItem(activityKey('dana')); storage.setItem(namesKey('dana'), '{"paid": not json');
  await freshPage(); await unlock('dana');
  assert.deepEqual(await looked('bob'), first('bob'), 'the wallet no longer knows that dana paid bob');
  // The browser refuses to store the record. The payment goes through, and this page remembers the name while it is open.
  storage.failNames = true;
  assert.deepEqual(await pay('bob', '0.1'), first('bob'));
  assert.match($('notice').textContent, sentTo('bob'));
  assert.deepEqual(await looked('bob'), NOTHING_NEW);
  assert.deepEqual(await looked('b0b'), alike('b0b', 'bob'));
  // The damaged record was dropped when the account was opened (it opens nothing), and none could be written since.
  assert.equal(storage.getItem(namesKey('dana')), null, 'nothing was written');
  storage.failNames = false;
  // Stored again at the next occasion. A stored value of another shape is an empty list, not an error.
  assert.deepEqual([await looked('bob'), await record('dana')], [NOTHING_NEW, { paid: ['bob'] }]);
  for (const stored of ['["bob"]', '"bob"', 'null', '{"paid":"bob"}', '{"paid":[7,null,"Bob","b","@bob"]}']) {
    // As an earlier version kept it, in the clear: the first unlock reads what it can and encrypts that.
    storage.removeItem(namesKey('dana')); storage.setItem(plainNamesKey('dana'), stored); storage.removeItem(activityKey('dana'));
    await freshPage(); await unlock('dana');
    assert.deepEqual(await looked('bob'), first('bob'), stored);
  }
});

test('creating an account: a name the chain refuses as too close to another is told in plain words, and the form for a new account is shown again', async () => {
  // The wallet makes the password of a new key and shows it before the key is kept (the rule, vault.mjs RULE): read from
  // its dialog, as a person writes it down, then "I have it".
  const made = {};
  const create = async name => {
    await $('mode-create').fire('click'); $('username').value = name;
    const sent = $('auth-form').fire('submit');
    await until(() => $('made-dialog').open, 'the password the wallet made');
    made[name] = $('made-login-shown').textContent;
    $('made-dialog').returnValue = 'done'; $('made-dialog').open = false; await $('made-dialog').fire('close');
    await sent;
  };
  await freshPage();
  // The chain refuses to reveal a name that looks like an existing one. Its words reach the wallet through the gateway.
  // They are the engine's sentence, as it stood in the engine's own branch when this test was written.
  chain.refusal = action => (action.kind === SDK.KINDS.reveal ? `the name ${action.payload.name} is too close to the existing name bob: choose a name that does not look like it` : null);
  await create('bob_');
  const said = 'That name is too close to @bob, which already exists. Choose another.';
  assert.deepEqual([$('notice').textContent, $('notice').className.includes('error')], [said, true]);
  assert.deepEqual([$('auth-heading').textContent, $('auth-submit').textContent, $('auth-panel').hidden, $('lock-button').hidden, $('password').value], ['Create your account', 'Create my account', false, true, '']);
  assert.equal(chain.posted.at(-1).kind, SDK.KINDS.reveal, 'the name was sent to the chain, which refused it');
  // The vault of that name is still in this browser. Opening it sends the same reveal again, and the answer is the same sentence.
  await $('mode-unlock').fire('click'); $('username').value = 'bob_'; $('password').value = made.bob_; await $('auth-form').fire('submit');
  assert.deepEqual([$('notice').textContent, $('auth-heading').textContent], [said, 'Create your account']);
  // The same with "an existing name" in the refusal, whatever stands around the words.
  chain.refusal = action => (action.kind === SDK.KINDS.reveal ? `reveal refused: name "${action.payload.name}" is too close to an existing name: erin` : null);
  await create('e_rin');
  assert.deepEqual([$('notice').textContent, $('notice').className.includes('error'), $('auth-heading').textContent], ['That name is too close to @erin, which already exists. Choose another.', true, 'Create your account']);
  // The gateway's word alone does not make the wallet say so. A name that does not look like the new one (zed_9, bob),
  // a look-alike that proven state does not hold (dav3, dave), or any other refusal cannot decide the name.
  assert.deepEqual([N.resembles('zed_9', 'bob'), N.resembles('dav3', 'dave'), row('dave')], [null, 'loose', undefined]);
  for (const [name, refusal] of [['zed_9', 'too close to an existing name: bob'], ['dav3', 'too close to an existing name: dave'], ['ole_7', 'stale authority or incorrect nonce']]) {
    chain.refusal = action => (action.kind === SDK.KINDS.reveal ? refusal : null);
    await create(name);
    assert.equal($('notice').textContent, 'The encrypted vault is saved. Unlock again to resume safely. ' + A.gatewayWords({ message: refusal }), name);
    assert.ok(!$('notice').textContent.includes(refusal), 'an unverified refusal cannot direct the user');
    assert.equal($('auth-heading').textContent, 'Open your account', name);
  }
  chain.refusal = () => null;
});

test('a payment refusal cannot point to a different name in the notice', async () => {
  await freshPage(); await unlock('dana');
  chain.refusal = action => (action.kind === SDK.KINDS.transfer ? 'too close to an existing name: b0b' : null);
  await pay('carol', '0.1');
  assert.equal($('notice').textContent, A.gatewayWords({ message: 'too close to an existing name: b0b' }));
  assert.doesNotMatch($('notice').textContent, /b0b|too close/);
  assert.equal($('notice').className.includes('error'), true);
  chain.refusal = () => null;
});

test('a payment to a name that looks like the account\'s own name is warned about like a look-alike of a paid name, and needs the tick', async () => {
  // dana has paid carol from this browser, and nobody else. The payment the gateway refused in the test before this
  // one is no longer kept as pending (it never reached a block, and its nonce is still the account's next).
  storage.removeItem(namesKey('dana')); storage.setItem(plainNamesKey('dana'), JSON.stringify({ paid: ['carol'] })); storage.removeItem(activityKey('dana')); storage.removeItem(`timecurrency.pending.v1:${NET1}:13`);
  await freshPage(); await unlock('dana');
  const before = chain.posted.length, held = row('d4na').balance;
  assert.equal(N.resembles('d4na', 'dana'), 'loose');
  const own = { notes: ['You have not paid @d4na before. It looks like @dana, your own name. Check every letter.'], layout: ['note', 'dl'], warning: true, names: ['@d4na', '@dana'], asks: 'I checked the name, letter by letter.' };
  const step = await send('d4na', '0.25'), seen = shown();
  assert.deepEqual([seen.title, about(seen), seen.disabled], ['Send seconds', own, true]);
  // Confirmed without the tick: it counts as cancelled, and nothing is signed.
  await armed(); assert.equal($('review-confirm').disabled, true, 'not without the tick');
  await close('confirm'); await step();
  assert.deepEqual([chain.posted.length, row('d4na').balance, await record('dana')], [before, held, { paid: ['carol'] }]);
  // Ticked: paid. From then on it is a name this account has paid, and is not warned about again.
  assert.deepEqual(await pay('d4na', '0.25'), own);
  assert.match($('notice').textContent, sentTo('d4na'));
  assert.deepEqual([chain.posted.length - before, chain.posted.at(-1).payload.to, await record('dana')], [1, '14', { paid: ['carol', 'd4na'] }]);
  assert.deepEqual(await looked('d4na'), NOTHING_NEW);
  // The other answers are as they were: a look-alike of a paid name, a first payment, and the own name itself refused before any review.
  assert.deepEqual(await looked('karol'), alike('karol', 'carol'));
  assert.deepEqual(await looked('erin'), first('erin'));
  $('recipient').value = 'dana'; $('amount').value = '0.1'; await $('send-form').fire('submit');
  assert.deepEqual([$('notice').textContent, $('review-dialog').open], ['That is your own name. Send to someone else.', false]);
});

test('the names typed for guardians: one that looks like the own name, like a paid name or like another guardian in the list is warned about, and the policy is not signed without the tick', async () => {
  const before = chain.posted.length;
  /// Sends the guardian form and waits for its review. What it gives back waits, when called, until the wallet has finished with the form.
  const ask = async (names, threshold) => {
    $('recovery-guardians').value = names; $('recovery-threshold').value = threshold; $('notice').textContent = ''; $('notice').className = 'notice';
    await $('recovery-policy-form').fire('submit'); await opened();
    return () => until(() => !$('review-dialog').open && $('notice').textContent !== '' && !$('notice').className.includes('busy'), 'the end of the guardian form');
  };
  // Names that look like nothing this browser knows: the review is as it always was, with no box.
  let step = await ask('bob, erin', '2'), seen = shown();
  assert.deepEqual([seen.title, about(seen)], ['Set guardian recovery policy', NOTHING_NEW]);
  await close('cancel'); await step();
  // d4na reads like dana (the own name), karol like carol (paid from this browser), b0b like bob (typed before it).
  const warned = { notes: ['@d4na looks like @dana, your own name. Check every letter.', '@karol looks like @carol, which you have paid. Check every letter.', '@b0b looks like @bob, another guardian in this list. Check every letter.'],
    layout: ['note', 'note', 'note', 'dl'], warning: true, names: ['@d4na', '@dana', '@karol', '@carol', '@b0b', '@bob'], asks: 'I checked the guardian names, letter by letter.' };
  step = await ask('bob, d4na, karol, b0b', '3'); seen = shown();
  assert.deepEqual([about(seen), seen.disabled], [warned, true]);
  // The delay is over and the box is not ticked: the button stays disabled, and a close as confirmed counts as cancelled.
  await armed(); assert.equal($('review-confirm').disabled, true, 'not without the tick');
  await close('confirm'); await step();
  assert.deepEqual([chain.posted.length, row('dana').recovery_policy], [before, null], 'nothing was signed without the tick');
  // Ticked: the policy is signed, for the accounts of the names that were typed.
  step = await ask('bob, d4na, karol, b0b', '3');
  assert.deepEqual([about(shown()), $('review-ack').checked], [warned, false], 'the next review starts with an empty box');
  await tick(); await armed(); assert.equal($('review-confirm').disabled, false);
  await close('confirm'); await step();
  assert.deepEqual([chain.posted.length - before, chain.posted.at(-1).kind, chain.posted.at(-1).payload.guardians, row('dana').recovery_policy?.threshold], [1, SDK.KINDS.set_recovery, ['2', '3', '6', '14'], '3']);
  assert.match($('notice').textContent, /^Recovery policy finalized\./);
});

test('the page draws the two names in its monospace font, on one line each', async () => {
  const styles = await readFile(new URL('./styles.css', import.meta.url), 'utf8');
  const rule = /^\.name-check code \{([^}]*)\}$/m.exec(styles)?.[1] ?? '';
  assert.match(rule, /font-family: var\(--mono\);/);
  assert.match(rule, /white-space: nowrap;/);
  assert.match(styles, /^  --mono: ui-monospace, /m);
});
