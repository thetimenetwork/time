// The pages of "Move my account to another device" (move-ui.mjs), both devices, on a fake page, as security-review-ui.test.mjs
// drives security-ui.mjs: the new device's request from the start screen (keys locked to the device from birth, declined,
// or under passwords the wallet makes), the old device's card on Keys with the real security-ui.mjs behind it (the payment
// key, the recovery words, the path for security actions), and the stand-in chain of device-move.test.mjs
// (tests/mock-security-chain.mjs, with each action's signature checked). Stood in for: the page (elements made on demand),
// the verifier (a state read straight from that chain), the device (the fake authenticator of device-lock.test.mjs),
// Argon2id (SHA-256 of the password and the salt). The old device keeps its keys in the page's localStorage (security-ui.mjs
// reads them there); the new device in a storage of its own.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash, createHmac, randomBytes, webcrypto } from 'node:crypto';
import { registerHooks } from 'node:module';

const root = new URL('../../', import.meta.url);
registerHooks({ resolve(s, context, next) { return next(s === '/sdk/account-security.mjs' ? new URL('client-v4/account-security.mjs', root).href : s, context); } });
await import(new URL('client-v4/time-sdk.js', root).href);
const SDK = globalThis.TimeSDK;

// ------------------------------------------------------------------ the fake page
class Storage {
  m = new Map();
  get length() { return this.m.size; }
  key(i) { return [...this.m.keys()][i] ?? null; }
  getItem(k) { return this.m.has(k) ? this.m.get(k) : null; }
  setItem(k, v) { this.m.set(k, String(v)); }
  removeItem(k) { this.m.delete(k); }
  keys() { return [...this.m.keys()]; }
}
let runs = [];
class El {
  constructor(id) { Object.assign(this, { id, value: '', hidden: false, textContent: '', disabled: false, checked: false, open: false, dataset: {}, type: 'text', children: [], listeners: {}, className: '', classList: { add() {}, remove() {}, toggle() {} } }); }
  addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn); }
  querySelectorAll() { return [this.querySelector()]; } querySelector() { return this.button ??= new El(this.id + '-button'); }
  replaceChildren(...c) { this.children = c; } append(...c) { this.children.push(...c); }
  focus() {} scrollIntoView() {} click() {}
  async fire(type) { await Promise.all((this.listeners[type] || []).map(fn => fn({ preventDefault() {} }))); while (runs.length) await runs.shift(); }
}
let dom = new Map();
globalThis.document = { getElementById: id => { if (!dom.has(id)) dom.set(id, new El(id)); return dom.get(id); }, createElement: tag => new El(tag), querySelectorAll: () => [], body: { classList: { add() {}, remove() {} } } };
const oldStore = new Storage();
Object.defineProperty(globalThis, 'localStorage', { value: new Proxy(oldStore, { ownKeys: t => [...t.m.keys()], getOwnPropertyDescriptor: (t, k) => t.m.has(k) ? { enumerable: true, configurable: true, value: t.m.get(k) } : Reflect.getOwnPropertyDescriptor(t, k), get: (t, k) => typeof t[k] === 'function' ? t[k].bind(t) : t[k] }) });
/// Web Locks, one queue per name.
const LOCKS = (() => { const tails = new Map(); return { request(name, options, work) { const run = (tails.get(name) ?? Promise.resolve()).then(() => work()); tails.set(name, run.catch(() => {})); return run; } }; })();
let clipboard = '';
Object.defineProperty(globalThis, 'navigator', { value: { locks: LOCKS, clipboard: { writeText: async text => { clipboard = text; } } } });
globalThis.window = { print() {} };
// The new device reads the network every MOVE_CHECK_MS while its request waits: the tests read when they choose.
const timers = []; globalThis.setInterval = fn => { timers.push(fn); return timers.length; }; globalThis.clearInterval = () => {};
const $ = id => document.getElementById(id);

const { createSecurityUI } = await import(new URL('web-v4/wallet/security-ui.mjs', root).href);
const { createMoveUI, MOVE_PAGE_WORDS, MOVE_FIELDS } = await import(new URL('web-v4/wallet/move-ui.mjs', root).href);
const M = await import(new URL('web-v4/wallet/device-move.mjs', root).href);
const F = await import(new URL('web-v4/wallet/security-flows.mjs', root).href);
const { openVault, vaultDevice } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const { turnOn, createLockAsker, LOCK_WORDS, deviceSecrets, saltOfRecord } = await import(new URL('web-v4/wallet/device-lock.mjs', root).href);
const { NOT_HAD } = await import(new URL('web-v4/wallet/made-dialog.mjs', root).href);
const { provenSeals } = await import(new URL('web-v4/wallet/tests/legacy-vault.mjs', root).href);
const { PendingReservations, formatSeconds } = await import(new URL('web-v4/wallet/guards.mjs', root).href);
const security = await import(new URL('client-v4/account-security.mjs', root).href);
const { createSecurityChain } = await import(new URL('web-v4/wallet/tests/mock-security-chain.mjs', root).href);

const quick = async ({ password, salt }) => new Uint8Array(createHash('sha256').update(Buffer.from(password)).update(Buffer.from(salt)).digest());
const NET = 'd7'.repeat(32), NAME = 'alice', MICROS = 1000000n, HOUR = 3600n * MICROS, GENESIS = 17n * 10n ** 14n, FEE = 1000n;
const CHOSEN = { login: 'copper kites drift over salt marsh 58', payment: 'seven lanterns guard the northern pier 23' };
const W = M.MOVE_WORDS, P = MOVE_PAGE_WORDS;
const until = async (condition, what) => { for (let i = 0; i < 400; i++) { if (await condition()) return; await new Promise(resolve => setTimeout(resolve, 5)); } assert.fail(`waited in vain for ${what}`); };

// ------------------------------------------------------------------ the stand-in chain (as in device-move.test.mjs)
const verifies = async (publicKey, signature, message) => webcrypto.subtle.verify('Ed25519', await webcrypto.subtle.importKey('raw', SDK.hexToBytes(publicKey, 32), 'Ed25519', false, ['verify']), SDK.hexToBytes(signature, 64), message);
const byKey = (a, b) => (a.public_key < b.public_key ? -1 : 1);
const deviceRow = (publicKey, role) => ({ public_key: publicKey, can_manage: role === 'recover', can_spend: role === 'spend' });
function standInChain() {
  const chain = { now: 240n * HOUR, height: 100, accounts: [], rows: {}, posted: [], refused: [], down: false };
  const rules = createSecurityChain({ sdk: SDK, security, networkId: NET, accounts: chain.accounts, rows: chain.rows, fee: FEE });
  async function signin(action) {
    const account = chain.accounts.find(a => a.id === action.from), signer = account.devices.find(d => d.public_key === action.publicKey);
    if (!signer || security.roleOf(signer) !== 'spend') throw new Error('a spend key is required');
    if (BigInt(action.nonce) !== BigInt(account.nonce) + 1n || action.authEpoch !== account.auth_epoch) throw new Error('stale authority or incorrect nonce');
    const devices = account.devices.filter(d => !(action.payload.remove.includes(d.public_key) && security.roleOf(d) === 'signin'));
    for (const add of action.payload.add) devices.push(deviceRow(add.public_key, 'signin'));
    account.devices = devices.sort(byKey); account.nonce = action.nonce; account.auth_epoch = String(BigInt(account.auth_epoch) + 1n);
  }
  chain.submit = async tx => {
    const action = SDK.decodeAction(tx); chain.posted.push(action);
    let refusal = null;
    if (action.networkId !== NET) refusal = 'wrong network';
    else if (!await verifies(action.publicKey, SDK.bytesToHex(tx.slice(-64)), tx.slice(0, -64))) refusal = 'invalid action signature';
    else { try { if (action.kind === 71) await signin(action); else await rules.apply(action, chain.now); } catch (error) { refusal = error.message; } }
    if (refusal) { chain.refused.push(refusal); return refusal; }
    chain.height += 1; chain.now += MICROS; return null;
  };
  chain.state = () => structuredClone({ network_id: NET, height: String(chain.height), time_micros: (GENESIS + chain.now).toString(), genesis: { genesis_time_micros: GENESIS.toString() }, config: { recovery_min_delay_micros: '30000000', recovery_approval_window_micros: '86400000000' }, accounts: chain.accounts, security: Object.values(chain.rows), recovery_cases: [] });
  chain.client = { submit: async tx => { const refusal = await chain.submit(tx); if (refusal) throw new Error(refusal); return { verified: true, hash: await SDK.transactionHash(tx), height: String(chain.height), rawHex: SDK.bytesToHex(tx) }; }, waitReceipt: async () => { throw new Error('no receipt'); } };
  return chain;
}

// ------------------------------------------------------------------ a device: what the person can do on it
const prfOf = (key, salt) => createHmac('sha256', key).update(createHash('sha256').update(Buffer.concat([Buffer.from('WebAuthn PRF'), Buffer.from([0]), Buffer.from(salt)])).digest()).digest();
const buffer = bytes => { const copy = new ArrayBuffer(bytes.length); new Uint8Array(copy).set(bytes); return copy; };
/// A device that checks the person and gives PRF secrets (device-lock.test.mjs, fakeDevice). `calls`: every request.
/// `getErrors`: the name of the error each request for secrets in turn ends with (none where null). `hold`: a promise the
/// browser's answers to what the device can do wait for (one that never settles: no answer).
function fakeDevice({ getErrors = [], hold = null } = {}) {
  const keys = [], calls = [];
  let gets = 0;
  const authData = () => { const b = new Uint8Array(37); b[32] = 0x05; return buffer(b); };
  class PublicKeyCredential { static async isUserVerifyingPlatformAuthenticatorAvailable() { await hold; return true; } static async getClientCapabilities() { await hold; return { userVerifyingPlatformAuthenticator: true, 'extension:prf': true }; } }
  const credentials = {
    async create(options) { calls.push('create'); const key = { id: randomBytes(32), secret: randomBytes(32), handle: Buffer.from(options.publicKey.user.id) }; keys.push(key); return { type: 'public-key', rawId: buffer(key.id), response: { getAuthenticatorData: () => authData() }, getClientExtensionResults: () => ({ prf: { enabled: true } }) }; },
    async get(options) { calls.push('get'); gets += 1; if (getErrors[gets - 1]) throw new DOMException('x', getErrors[gets - 1]); const key = keys.at(-1), salts = options.publicKey.extensions.prf.eval; return { type: 'public-key', rawId: buffer(key.id), response: { authenticatorData: authData() }, getClientExtensionResults: () => ({ prf: { results: { first: buffer(prfOf(key.secret, salts.first)), ...(salts.second ? { second: buffer(prfOf(key.secret, salts.second)) } : {}) } } }) }; },
  };
  return { env: { secureContext: true, credentials, PublicKeyCredential, crypto: webcrypto, phone: false }, calls };
}
let chain;
/// A device's page: its own elements, storage, session and wallet; `answer`: what a review answers; `holdMade`: the dialog of
/// the passwords the wallet made stays open until the test closes it (or the wallet locks). The dialog keeps the contract of
/// made-dialog.mjs: it goes on only with "I have them" (`closeMade(true)`); closed any other way it rejects with NOT_HAD.
function makeDevice({ storage, session = null, env = null, manager = { persisted: async () => true } }) {
  const d = { storage, session, env, manager, dom: new Map(), notices: [], errors: [], reviews: [], made: [], opened: [], unlocks: [], locked: [], fence: 0, answer: true, holdMade: false, latest: null };
  d.asker = env ? createLockAsker({ env }) : null;
  d.c = {
    sdk: SDK, client: () => chain.client, network: () => ({ networkId: NET }), session: () => d.session, state: () => d.latest,
    ownAccount: (state = d.latest) => state?.accounts.find(a => a.name === (d.session?.binding.name ?? NAME)),
    verifiedState: async () => { if (chain.down) throw new Error('the network cannot be read'); return (d.latest = chain.state()); },
    refresh: async () => {}, review: async (title, fields, confirm) => { d.reviews.push({ title, fields, confirm }); return d.answer; },
    notice: (text, kind) => d.notices.push([text, kind ?? '']), setBusy() {},
    run: fn => { const p = (async () => { try { await fn(); } catch (error) { d.errors.push(error.message); } })(); runs.push(p); return p; },
    capture: () => { const at = d.fence; return () => { if (d.fence !== at) throw new Error('The wallet was locked meanwhile.'); }; },
    seconds: v => formatSeconds(String(v)), fee: () => String(FEE), pending: new PendingReservations(storage), record: async () => {}, cleared() {},
    // Locking closes the dialog of the made passwords, as app.js does: the step that showed them stops at its next check.
    lock: message => { d.fence += 1; d.locked.push(message); d.session = null; d.closeMade?.(false); d.ui?.reset(); },
    argon2id: () => quick, storage, locks: () => LOCKS, env: () => d.env, storageManager: () => d.manager, lockAsker: () => d.asker,
    showMade: made => new Promise((resolve, reject) => {
      d.made.push(made);
      d.closeMade = had => { d.closeMade = null; if (had) resolve(); else reject(Object.assign(new Error(made.login && made.payment ? NOT_HAD.two : NOT_HAD.one), { notHad: true })); };
      if (!d.holdMade) d.closeMade(true);
    }),
    showUnlock: name => d.unlocks.push(name), opened: async opened => { d.opened.push(opened); }, download() {}, sendSigned: async () => { throw new Error('not on this page'); },
  };
  const previous = dom; dom = d.dom;
  d.security = createSecurityUI(d.c); d.c.tools = d.security.tools; d.ui = createMoveUI(d.c);
  dom = previous;
  return d;
}
/// Acts on a device's page.
async function on(d, work) { const previous = dom; dom = d.dom; try { return await work(); } finally { dom = previous; } }
const el = (d, id) => d.dom.get(id) ?? (d.dom.set(id, new El(id)), d.dom.get(id));

/// A protected account @alice on the chain, words only; its old device holds its login key and payment key (under passwords
/// the wallet made, or locked to the device with `oldLocked`), unlocked. A new device with nothing, and its own device
/// (`newDevice`: true, or the options of fakeDevice).
async function world({ oldLocked = false, newDevice = false } = {}) {
  oldStore.m.clear(); runs = []; timers.length = 0; dom = new Map(); clipboard = '';
  chain = standInChain();
  const words = F.generatePassphrase(), first = await F.passphraseKey({ passphrase: words, networkId: NET, accountId: '5', argon2id: quick }), second = await F.recoveryWordsSecondKey({ passphrase: words, networkId: NET, accountId: '5', argon2id: quick });
  const [signin, spend] = await F.sealedKeys({ wanted: [{ intent: 'signin' }, { intent: 'spend' }], networkId: NET, name: NAME, argon2id: quick, cryptoImpl: webcrypto });
  const live = F.vaultSlots(NET, NAME);
  oldStore.setItem(live.login, JSON.stringify(signin.record)); oldStore.setItem(live.spend, JSON.stringify(spend.record));
  chain.accounts.push({ id: '5', name: NAME, public_key: 'ab'.repeat(32), balance: '10000000', nonce: '3', auth_epoch: '1', recovery_policy: null,
    devices: [deviceRow(signin.key.publicKey, 'signin'), deviceRow(spend.key.publicKey, 'spend'), deviceRow(first.publicKey, 'recover'), deviceRow(second.publicKey, 'recover')].sort(byKey) });
  chain.accounts.push({ id: '6', name: 'bob', public_key: 'cd'.repeat(32), balance: '0', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [deviceRow('cd'.repeat(32), 'full')] });
  chain.rows['5'] = { account: '5', version: '1', policy: { threshold: '2', daily_limit_micros: '500000', delay_seconds: '60', freeze_seconds: '120' }, allowance_micros: '500000', allowance_elapsed_micros: chain.now.toString(),
    frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null };
  const oldEnv = oldLocked ? fakeDevice() : null;
  if (oldLocked) await turnOn({ storage: localStorage, slots: live, networkId: NET, name: NAME, login: signin.made, payment: spend.made, argon2id: quick, env: oldEnv.env, locks: LOCKS });
  const old = makeDevice({ storage: localStorage, session: { binding: { networkId: NET, name: NAME, publicKey: signin.key.publicKey }, privateKey: signin.key.privateKey }, env: oldEnv?.env ?? null });
  old.device = oldEnv; old.passwords = { login: signin.made, payment: spend.made };
  const newEnv = newDevice ? fakeDevice(newDevice === true ? {} : newDevice) : null;
  const fresh = makeDevice({ storage: new Storage(), env: newEnv?.env ?? null }); fresh.device = newEnv;
  return { old, fresh, words, live, first, oldKeys: { signin: signin.key.publicKey, spend: spend.key.publicKey } };
}
/// The old device shows its Keys (the account read in a verified state).
const drawKeys = async old => on(old, async () => { const state = await old.c.verifiedState(); old.ui.render(state.accounts.find(a => a.name === NAME), state); });
/// Where the new device can lock keys, the form shows the choice of how to lock the new keys (device-lock-ui.mjs,
/// wayChoice): waits until it is drawn, and checks that neither way is chosen and no field of a password is shown.
async function choiceShown() {
  await until(() => $('move-ways').hidden === false, 'the choice of how to lock the new keys');
  assert.deepEqual([$('move-way-device').checked, $('move-way-made').checked, $('move-seal-note').hidden, $('move-chosen').hidden], [false, false, true, true]);
}
/// The person picks a way ('device' or 'made'), as a click on its radio does.
async function chooseWay(way) {
  const picked = $(`move-way-${way}`), other = $(`move-way-${way === 'device' ? 'made' : 'device'}`);
  picked.checked = true; other.checked = false;
  await picked.fire('change');
  assert.equal($('move-chosen').hidden, way !== 'device', 'the fields of the passwords only once the lock is chosen');
}
/// The new device: "Move my account here", the name, and the request. With `device`, the form shows the choice, and the
/// person chooses the lock, with the passwords typed, or with `decline` the passwords the wallet makes; with `switched`, the
/// other way first.
async function newRequest(d, { name = NAME, device = false, decline = false, switched = false } = {}) {
  await on(d, async () => {
    await $('move-open').fire('click');
    // The form is drawn once the browser has said what the device can do: the choice, or the sentence of a device that
    // cannot lock keys (device-lock-ui.mjs, wayChoice).
    await until(() => $('move-ways').hidden === false || $('move-seal-note').hidden === false, 'the form drawn');
    if (device) {
      await choiceShown();
      if (switched) await chooseWay(decline ? 'device' : 'made');
      await chooseWay(decline ? 'made' : 'device');
    }
    $('move-name').value = name;
    if (device && !decline) { $('move-login').value = $('move-login-confirm').value = CHOSEN.login; $('move-payment').value = $('move-payment-confirm').value = CHOSEN.payment; }
    await $('move-form').fire('submit');
  });
  return { text: el(d, 'move-request').value, code: el(d, 'move-code').textContent, stage: el(d, 'move-stage').textContent };
}
/// The old device: the request pasted, the code typed, then the payment password and the recovery words.
async function oldMoves(old, text, { code, payment = old.passwords.payment, secret, until: stop = 'end' } = {}) {
  return on(old, async () => {
    $('move-old-request').value = text; await $('move-old-form').fire('submit');
    if (stop === 'checked') return;
    $('move-old-code').value = code; await $('move-old-next').fire('click');
    if (stop === 'code') return;
    $('move-old-payment').value = payment; $('move-old-secret').value = secret; await $('move-old-submit').fire('click');
  });
}
const look = d => on(d, () => d.ui.look());
const reload = d => { const again = makeDevice({ storage: d.storage, env: d.env, manager: d.manager }); again.device = d.device; return again; };
const keyRecords = storage => storage.keys().filter(k => /^timecurrency\.(vault\.v1|spend-vault\.v1|vault-next\.v1)/.test(k));

// ------------------------------------------------------------------ the whole move, through both pages
test('a move through both pages: the request and code on the new device, the old device checks and moves, the new device opens the account', async () => {
  const { old, fresh, words, live, oldKeys } = await world();
  const made = await newRequest(fresh);
  assert.deepEqual(fresh.errors, []);
  // The wallet made both passwords and showed them before anything was kept; then the request and its code.
  assert.equal(fresh.made.length, 1); assert.ok(fresh.made[0].login && fresh.made[0].payment); assert.equal(fresh.made[0].why, P.madeWhy);
  // This device cannot lock keys: no choice is shown, and the form says the wallet makes the passwords.
  assert.deepEqual([el(fresh, 'move-seal-note').textContent, el(fresh, 'move-seal-note').hidden, el(fresh, 'move-ways').hidden], [LOCK_WORDS.birthMade, false, true]);
  // Proven by opening them (tests/legacy-vault.mjs): the two records kept aside each open with a password shown, and
  // with nothing else.
  const shownPasswords = [fresh.made[0].login, fresh.made[0].payment];
  assert.equal([...fresh.storage.m.keys()].filter(k => /:move(signin|spend)$/.test(k)).length, 2);
  assert.deepEqual(await provenSeals({ entries: [...fresh.storage.m], shown: shownPasswords, typed: [CHOSEN.login, CHOSEN.payment], argon2id: quick }), []);
  assert.match(made.code, /^[0-9A-HJKMNP-TV-Z]{4}( [0-9A-HJKMNP-TV-Z]{4}){3}$/);
  assert.equal(JSON.parse(made.text).type, 'time-move-request');
  assert.match(made.stage, /^Waiting for your other device\. This request works until /);
  assert.deepEqual([el(fresh, 'move-form').hidden, el(fresh, 'move-step').hidden, el(fresh, 'move-withdraw').hidden], [true, false, false]);
  await on(fresh, () => $('move-copy').fire('click')); assert.equal(clipboard, made.text);
  // The old device: the card on Keys, the review from what was checked, the code, the passwords, the move.
  await drawKeys(old); assert.equal(el(old, 'move-card').hidden, false);
  await oldMoves(old, made.text, { until: 'checked' });
  assert.deepEqual(old.errors, []);
  const shown = el(old, 'move-old-shown').children.map(li => li.textContent);
  assert.deepEqual(shown.slice(0, 3), ['Your account @alice moves to your other device.', 'Every payment key and login key of your account stops working at once: 2 in all, this device\'s included.', 'Your recovery words stay, and so do your balance and your daily limit.']);
  assert.match(shown.at(-1), /^This request works until /);
  assert.equal(el(old, 'move-old-only').textContent, W.onlyYours);
  assert.equal(el(old, 'move-old-request').value, '', 'the request is not shown back');
  assert.equal(el(old, 'move-old-secrets').hidden, true, 'no password is asked before the code');
  await on(old, async () => { $('move-old-code').value = made.code.toLowerCase(); await $('move-old-next').fire('click'); });
  assert.equal(el(old, 'move-old-secrets').hidden, false);
  await on(old, async () => { $('move-old-payment').value = old.passwords.payment; $('move-old-secret').value = words; await $('move-old-submit').fire('click'); });
  assert.deepEqual(old.errors, []);
  // The review said what happens at once, in sentences.
  const final = old.reviews.at(-1);
  assert.equal(final.title, 'Move my account to another device');
  assert.deepEqual(final.fields.map(([k]) => k), ['At once', 'Websites', 'Dropped', 'Kept', 'Approved by', 'Fee']);
  assert.deepEqual(final.fields.slice(0, 3).map(([, v]) => v), ['Your account works on your other device, and this device\'s keys stop working.', 'They ask you to sign in again.', 'Nothing is waiting.']);
  // The chain moved the authority; the old device forgot its keys and locked, saying where the account is.
  const account = chain.accounts.find(a => a.name === NAME), request = JSON.parse(made.text);
  assert.ok(account.devices.some(d => d.public_key === request.spend.publicKey && d.can_spend));
  assert.ok(!account.devices.some(d => d.public_key === oldKeys.spend || d.public_key === oldKeys.signin));
  assert.deepEqual(old.locked, [P.done(NAME)]);
  assert.deepEqual(keyRecords(oldStore), []);
  // The new device reads the network (its timer): the account opens with the login key the page held.
  assert.ok(timers.length > 0);
  await look(fresh);
  assert.equal(fresh.opened.length, 1);
  assert.deepEqual([fresh.opened[0].name, fresh.opened[0].signin.publicKey, fresh.opened[0].said], [NAME, request.signin.publicKey, P.settled]);
  const sig = await webcrypto.subtle.sign('Ed25519', fresh.opened[0].signin.privateKey, new Uint8Array(4));
  assert.ok(await verifies(request.signin.publicKey, SDK.bytesToHex(new Uint8Array(sig)), new Uint8Array(4)), 'the held login key signs');
  assert.deepEqual(fresh.storage.keys().sort(), [live.login, live.spend].sort());
  assert.deepEqual(await provenSeals({ entries: [...fresh.storage.m], shown: shownPasswords, argon2id: quick }), [], 'the keys in their places, proven');
  assert.equal(el(fresh, 'move-panel').hidden, true);
});

test('the device on each side: the new device, the lock chosen (after the other way first), locks its keys from birth with three requests to it; the old device, whose keys are locked, asks it once', async () => {
  const { old, fresh, words } = await world({ oldLocked: true, newDevice: true });
  assert.equal(vaultDevice(JSON.parse(oldStore.getItem(F.vaultSlots(NET, NAME).spend))) !== null, true);
  const oldCallsBefore = old.device.calls.length;
  const made = await newRequest(fresh, { device: true, switched: true });
  assert.deepEqual(fresh.errors, []);
  assert.equal(fresh.made.length, 0, 'no password was made: the device locked the keys');
  // A key of the device made (none in use here), one request for both keys, a second that must open both: three.
  assert.deepEqual(fresh.device.calls, ['create', 'get', 'get']);
  for (const key of Object.values(M.moveSlots(NET, NAME).active)) assert.ok(vaultDevice(JSON.parse(fresh.storage.getItem(key))));
  await drawKeys(old);
  await oldMoves(old, made.text, { code: made.code, payment: old.passwords.payment, secret: words });
  assert.deepEqual(old.errors, []);
  // The old device's payment key, locked to its device: one request.
  assert.deepEqual(old.device.calls.slice(oldCallsBefore), ['get']);
  await look(fresh);
  assert.equal(fresh.opened.length, 1);
  assert.deepEqual(fresh.device.calls, ['create', 'get', 'get'], 'opening the account asked nothing more');
  // Proven by opening them: each key in its place opens only with the device's secret and a password typed (the proof
  // asks the device itself, after the counts above).
  const secretOf = async record => (await deviceSecrets(fresh.device.env, { credentialId: vaultDevice(record), salts: [saltOfRecord(record)] }))[0];
  assert.deepEqual(await provenSeals({ entries: [...fresh.storage.m], typed: [CHOSEN.login, CHOSEN.payment], device: secretOf, argon2id: quick }), []);
});

test('the new device chooses the passwords the wallet makes (after the lock, with passwords typed): the wallet makes them, as a sign-up does, and what was typed seals nothing', async () => {
  const { fresh } = await world({ newDevice: true });
  // The lock chosen and passwords typed, then the other way: the fields go, and what was typed with them.
  await on(fresh, async () => {
    await $('move-open').fire('click'); await choiceShown(); await chooseWay('device');
    $('move-login').value = $('move-login-confirm').value = CHOSEN.login; $('move-payment').value = $('move-payment-confirm').value = CHOSEN.payment;
    await chooseWay('made');
    assert.deepEqual(MOVE_FIELDS.slice(0, 4).map(id => $(id).value), ['', '', '', '']);
  });
  const made = await newRequest(fresh, { device: true, decline: true, switched: true });
  assert.deepEqual(fresh.errors, []);
  assert.equal(fresh.made.length, 1); assert.deepEqual(fresh.device.calls, []);
  assert.equal(fresh.made[0].why, P.madeWhy);
  assert.ok(made.code.length === 19);
  assert.deepEqual(await provenSeals({ entries: [...fresh.storage.m], shown: [fresh.made[0].login, fresh.made[0].payment], typed: [CHOSEN.login, CHOSEN.payment], argon2id: quick }), []);
});

test('the new device with no way chosen: the form does not go on and says so; nothing is asked, made or kept, and no request is shown', async () => {
  const { fresh } = await world({ newDevice: true });
  await on(fresh, async () => {
    await $('move-open').fire('click'); await choiceShown();
    assert.deepEqual(['move-ways-legend', 'move-way-device-title', 'move-way-device-note', 'move-way-made-title', 'move-way-made-note'].map(id => $(id).textContent), [LOCK_WORDS.ways.legend, LOCK_WORDS.ways.device.title, LOCK_WORDS.ways.device.note, LOCK_WORDS.ways.made.title, LOCK_WORDS.ways.made.note]);
    $('move-name').value = NAME;
    await $('move-form').fire('submit');
  });
  assert.deepEqual([fresh.errors, fresh.device.calls, fresh.made.length, fresh.reviews.length, fresh.storage.keys(), el(fresh, 'move-request').value, el(fresh, 'move-step').hidden, el(fresh, 'move-ways').hidden], [[LOCK_WORDS.ways.pick], [], 0, 0, [], '', true, false]);
  // A way chosen then, the same form goes on.
  await on(fresh, () => chooseWay('made'));
  await on(fresh, () => $('move-form').fire('submit'));
  assert.deepEqual([fresh.errors.slice(1), fresh.made.length, fresh.device.calls], [[], 1, []]);
  assert.ok(el(fresh, 'move-request').value.length > 100, 'the request is shown');
});

test('the new device before its browser has said what the device can do: neither the choice nor the sentence of a device that cannot lock keys, and a send is refused and makes nothing; the answer draws the choice and the request is made; an answer that never comes is taken as a device that cannot lock keys', async () => {
  const { WAY_ANSWER_MS } = await import(new URL('web-v4/wallet/device-lock-ui.mjs', root).href);
  const asking = () => assert.deepEqual([$('move-ways').hidden, $('move-seal-note').hidden, $('move-seal-note').textContent, $('move-chosen').hidden], [true, true, '', true], 'neither state is shown');
  let answer; const { fresh } = await world({ newDevice: { hold: new Promise(resolve => { answer = resolve; }) } });
  await on(fresh, async () => {
    await $('move-open').fire('click');
    asking();
    $('move-name').value = NAME;
    await $('move-form').fire('submit');
    asking();
  });
  assert.deepEqual([fresh.errors.splice(0), fresh.device.calls, fresh.made.length, fresh.reviews.length, fresh.storage.keys(), el(fresh, 'move-request').value], [[LOCK_WORDS.ways.asking], [], 0, 0, [], '']);
  // The answer: the choice; the lock chosen, the request is made with the keys locked from birth.
  answer();
  await on(fresh, async () => {
    await choiceShown(); await chooseWay('device');
    $('move-login').value = $('move-login-confirm').value = CHOSEN.login; $('move-payment').value = $('move-payment-confirm').value = CHOSEN.payment;
    await $('move-form').fire('submit');
  });
  assert.deepEqual([fresh.errors, fresh.made.length, fresh.device.calls], [[], 0, ['create', 'get', 'get']]);
  assert.ok(el(fresh, 'move-request').value.length > 100, 'the request is shown');
  // A browser that never answers: after WAY_ANSWER_MS the form of a device that cannot lock keys, and the request is made
  // under passwords the wallet makes.
  const silent = await world({ newDevice: { hold: new Promise(() => {}) } });
  await on(silent.fresh, async () => {
    await $('move-open').fire('click');
    asking();
    const since = Date.now();
    for (let turn = 0; turn < 1200 && $('move-seal-note').hidden; turn++) await new Promise(resolve => setTimeout(resolve, 5));
    assert.ok(Date.now() - since >= WAY_ANSWER_MS - 200, 'not before the few seconds');
    assert.deepEqual([$('move-seal-note').textContent, $('move-ways').hidden, $('move-chosen').hidden], [LOCK_WORDS.birthMade, true, true]);
    $('move-name').value = NAME;
    await $('move-form').fire('submit');
  });
  assert.deepEqual([silent.fresh.errors, silent.fresh.made.length, silent.fresh.device.calls], [[], 1, []]);
  assert.ok(el(silent.fresh, 'move-request').value.length > 100, 'the request is shown');
});

test('the new device whose device fails after the lock was chosen: the wallet makes the passwords instead, says what happened, and the request is made', async () => {
  // The person cancels the device's second request (a key made, the first request answered).
  const { fresh } = await world({ newDevice: { getErrors: [null, 'NotAllowedError'] } });
  const made = await newRequest(fresh, { device: true });
  assert.deepEqual(fresh.errors, []);
  assert.deepEqual(fresh.device.calls, ['create', 'get', 'get']);
  assert.equal(fresh.made.length, 1);
  assert.equal(fresh.made[0].why, `The device did not give its key, so your keys are not locked to it. ${LOCK_WORDS.fellBack}`);
  assert.ok(made.code.length === 19);
  assert.deepEqual(await provenSeals({ entries: [...fresh.storage.m], shown: [fresh.made[0].login, fresh.made[0].payment], typed: [CHOSEN.login, CHOSEN.payment], argon2id: quick }), []);
});

// ------------------------------------------------------------------ refused on the old device
test('a code typed wrong: nothing is asked or signed, and the secrets step stays closed', async () => {
  const { old, fresh, words } = await world();
  const made = await newRequest(fresh);
  await drawKeys(old);
  const chars = made.code.replace(/ /g, ''), wrong = chars.slice(0, 15) + (chars[15] === '0' ? '1' : '0');
  await oldMoves(old, made.text, { code: wrong, until: 'code' });
  assert.deepEqual(old.errors, [W.codeWrong]);
  assert.equal(el(old, 'move-old-secrets').hidden, true);
  // Typed again right, it goes on.
  await on(old, async () => { $('move-old-code').value = made.code; await $('move-old-next').fire('click'); });
  assert.equal(el(old, 'move-old-secrets').hidden, false);
  assert.equal(chain.posted.length, 0);
  // The code the old device expects is shown nowhere on its page.
  for (const [, node] of old.dom) assert.ok(![node.textContent, node.value].some(v => typeof v === 'string' && v.toUpperCase().replace(/ /g, '').includes(chars)), node.id);
  void words;
});

test('a wrong recovery word: said in the wallet\'s words, nothing signed, every key of the old device kept', async () => {
  const { old, fresh, words } = await world();
  const made = await newRequest(fresh);
  await drawKeys(old);
  const before = [...oldStore.m];
  const wrong = words.split(' ').map((w, i) => (i === 2 ? F.generatePassphrase().split(' ')[0] : w)).join(' ');
  await oldMoves(old, made.text, { code: made.code, secret: wrong });
  assert.equal(old.errors.length, 1); assert.match(old.errors[0], /These recovery words are not one of this account's recovery keys/);
  assert.equal(chain.posted.length, 0);
  assert.deepEqual([...oldStore.m], before);
  assert.equal(el(old, 'move-old-payment').value, ''); assert.equal(el(old, 'move-old-secret').value, '', 'the secrets were emptied');
  // The same request, the right words: it moves.
  await on(old, async () => { $('move-old-payment').value = old.passwords.payment; $('move-old-secret').value = words; await $('move-old-submit').fire('click'); });
  assert.equal(old.errors.length, 1);
  assert.deepEqual(old.locked, [P.done(NAME)]);
});

test('a request for another account, changed on its way, or pasted twice is refused on the old device; the card shows only with both keys here', async () => {
  const { old, fresh } = await world();
  const made = await newRequest(fresh);
  await drawKeys(old);
  const changed = JSON.parse(made.text); changed.expires = String(BigInt(changed.expires) - 1n);
  await oldMoves(old, JSON.stringify(changed), { until: 'checked' });
  assert.deepEqual(old.errors, [W.signatures]);
  await oldMoves(old, '', { until: 'checked' });
  assert.deepEqual(old.errors.at(-1), W.paste);
  // A browser with the login key only shows no card.
  const live = F.vaultSlots(NET, NAME), spend = oldStore.getItem(live.spend); oldStore.removeItem(live.spend);
  await drawKeys(old); assert.equal(el(old, 'move-card').hidden, true);
  oldStore.setItem(live.spend, spend); await drawKeys(old); assert.equal(el(old, 'move-card').hidden, false);
});

// ------------------------------------------------------------------ the new device: reloads, the lock, every stage
test('the new device reloaded at each step: before the request (nothing kept), with the request (shown again before any unlock), after the move (opened with the login password)', async () => {
  const { old, fresh, words } = await world();
  // The wallet locks while the dialog of the made passwords is open: the dialog closes without "I have them", the step
  // stops, nothing is kept.
  fresh.holdMade = true;
  const pending = newRequest(fresh);
  await until(() => fresh.made.length === 1, 'the dialog of the made passwords');
  assert.deepEqual(keyRecords(fresh.storage), []);
  fresh.c.lock('Locked.');
  await pending;
  assert.deepEqual(fresh.errors, [NOT_HAD.two]);
  assert.deepEqual(fresh.storage.keys(), [], 'nothing of the move was kept');
  assert.equal(el(fresh, 'move-request').value, '', 'no request is shown');
  // Reloaded then: nothing waits, nothing is said.
  let page = reload(fresh); await on(page, () => page.ui.start());
  assert.deepEqual([page.errors, page.notices, page.dom.has('move-request')], [[], [], false]);
  // The request made; the page closed and opened again: the same request and code, before any unlock.
  const made = await newRequest(page);
  assert.deepEqual(page.errors, []);
  page = reload(page); await on(page, () => page.ui.start());
  assert.deepEqual([el(page, 'move-panel').hidden, el(page, 'move-request').value, el(page, 'move-code').textContent], [false, made.text, made.code]);
  assert.match(el(page, 'move-stage').textContent, /^Waiting for your other device/);
  // Reloaded without the network: still shown, said so.
  chain.down = true; page = reload(page); await on(page, () => page.ui.start()); chain.down = false;
  assert.deepEqual([el(page, 'move-code').textContent, el(page, 'move-stage').textContent], [made.code, P.unread]);
  // The old device moves while the new one is closed; the new one opens again: the account is here, opened with the login password.
  await drawKeys(old); await oldMoves(old, made.text, { code: made.code, secret: words });
  assert.deepEqual(old.errors, []);
  page = reload(page); await on(page, () => page.ui.start());
  assert.deepEqual(page.unlocks, [NAME]); assert.deepEqual(page.notices.at(-1), [P.settledOpen(NAME), '']);
  assert.equal(page.opened.length, 0, 'no login key was held after the reload');
  // The old device opened again after the move: nothing of the account is left, nothing to resume.
  const back = makeDevice({ storage: localStorage }); await on(back, () => back.ui.start());
  assert.deepEqual(keyRecords(oldStore), []); assert.deepEqual(back.errors, []);
});

test('the old device closed after sending, before it read the status: opened again, it forgets its keys once the network shows the move, and says where the account is', async () => {
  // Sent as the page sends it (noted first, then sent); the page closed before it read the status.
  const again = await world();
  const made2 = await newRequest(again.fresh);
  await drawKeys(again.old);
  const state = chain.state(), account = state.accounts.find(a => a.name === NAME), row = security.securityOf(state, '5');
  const dm = M.createDeviceMove({ security, locks: LOCKS });
  const review = await dm.reviewMove({ text: made2.text, networkId: NET, account, security: row, now: F.elapsedOf(state), waitsNow: F.elapsedOf(state), feeMicros: FEE });
  const spendRecord = F.spendRecord(oldStore, again.live), spendOpened = await openVault(spendRecord, again.old.passwords.payment, quick, webcrypto, 'spend');
  const first = await F.passphraseKey({ passphrase: again.words, networkId: NET, accountId: '5', argon2id: quick });
  const built = await dm.buildMove({ networkId: NET, request: review.request, typedCode: made2.code, account, security: row, spend: { publicKey: spendRecord.binding.publicKey, privateKey: spendOpened.privateKey }, recovery: first, now: F.elapsedOf(state), waitsNow: F.elapsedOf(state), feeMicros: FEE });
  await dm.rememberMove({ storage: localStorage, networkId: NET, name: NAME, request: review.request, built });
  assert.equal(await chain.submit(built.tx), null);
  assert.equal(keyRecords(oldStore).length, 3, 'its two keys and the note are kept until the status is read');
  const opened = makeDevice({ storage: localStorage }); await on(opened, () => opened.ui.start());
  assert.deepEqual(opened.notices.at(-1), [P.done(NAME), '']);
  assert.deepEqual(keyRecords(oldStore), []);
});

test('every stage of the new device has its sentence; "Withdraw" keeps the keys while a move can still arrive, and a new request can be made at once', async () => {
  const { old, fresh, words } = await world();
  const made = await newRequest(fresh), request = JSON.parse(made.text);
  // Stale: the old device's keys changed (a new login key) after the request was made.
  const state = chain.state(), account = state.accounts.find(a => a.name === NAME);
  const spendRecord = F.spendRecord(oldStore, F.vaultSlots(NET, NAME)), opened = await openVault(spendRecord, old.passwords.payment, quick, webcrypto, 'spend');
  const fresher = await F.keyFromSeed(F.newSheetSeed());
  const change = await F.createSecurityFlows({ security }).buildReplaceSignin({ networkId: NET, account, spend: { publicKey: spendRecord.binding.publicKey, privateKey: opened.privateKey }, signin: fresher });
  assert.equal(await chain.submit(change.tx), null);
  await look(fresh); assert.equal(el(fresh, 'move-stage').textContent, P.stale);
  // Withdrawn while it could still arrive.
  await on(fresh, () => $('move-withdraw').fire('click'));
  assert.deepEqual(fresh.errors, []);
  assert.match(el(fresh, 'move-stage').textContent, /^You withdrew the request\. This browser keeps its new keys until /);
  assert.deepEqual([el(fresh, 'move-request-part').hidden, el(fresh, 'move-code-part').hidden, el(fresh, 'move-withdraw').hidden], [true, true, true]);
  // Closing, then expired: a second request, its time let pass.
  const second = await newRequest(fresh);
  chain.now = BigInt(JSON.parse(second.text).expires);
  await look(fresh); assert.match(el(fresh, 'move-stage').textContent, /^This request has expired\. If your other device sent the move just before/);
  chain.now = M.moveWindowEnd(JSON.parse(second.text));
  await look(fresh); assert.equal(el(fresh, 'move-stage').textContent, P.expired);
  assert.equal(fresh.storage.getItem(M.moveSlots(NET, NAME).note), null);
  // Damaged: a kept record unreadable under a request that can still be used.
  chain.now -= HOUR;
  const third = await newRequest(fresh);
  fresh.storage.setItem(M.moveSlots(NET, NAME).active.spend, '{}');
  await look(fresh); assert.equal(el(fresh, 'move-stage').textContent, P.damaged);
  assert.equal(el(fresh, 'move-request-part').hidden, true, 'a request whose keys are gone is not shown');
  void third; void request; void words;
});

test('mixed: a replacement that is not the move puts the new payment key in place and says so; storage that may not last is said, and the person chooses', async () => {
  const { old, fresh, first } = await world();
  // Storage the browser may clear: the review says it; declined, nothing is made.
  fresh.manager = { persisted: async () => false, persist: async () => false };
  fresh.answer = false;
  await newRequest(fresh);
  assert.deepEqual([fresh.reviews.at(-1).title, fresh.reviews.at(-1).fields[0][1]], [P.fleetingTitle, W.fleeting]);
  assert.deepEqual(fresh.storage.keys(), []); assert.equal(fresh.made.length, 0);
  fresh.answer = true;
  const made = await newRequest(fresh);
  assert.deepEqual(fresh.errors, []);
  const request = JSON.parse(made.text);
  // The old device's payment key and a recovery key put the new payment key in, and keep the old login key.
  const state = chain.state(), account = state.accounts.find(a => a.name === NAME), row = security.securityOf(state, '5');
  const spendRecord = F.spendRecord(oldStore, F.vaultSlots(NET, NAME)), opened = await openVault(spendRecord, old.passwords.payment, quick, webcrypto, 'spend');
  const signinKept = account.devices.find(d => security.roleOf(d) === 'signin').public_key;
  const keys = [{ public_key: request.spend.publicKey, role: 'spend', proof: request.spend.proof }, security.keepKey(signinKept, 'signin'), ...account.devices.filter(d => security.roleOf(d) === 'recover').map(d => security.keepKey(d.public_key, 'recover'))];
  const flows = F.createSecurityFlows({ security });
  // Two proofs: the payment key and the first recovery key of the words.
  const approvers = [{ publicKey: spendRecord.binding.publicKey, privateKey: opened.privateKey }, first];
  const other = await flows.buildRoot({ networkId: NET, account, security: row, operation: security.operations.replace(keys, row.policy), approvers, submitter: approvers[0], expiresElapsedMicros: chain.now + 600n * MICROS });
  assert.equal(await chain.submit(other.tx), null);
  await look(fresh);
  // The login key of the request is not on the account: no key of this browser opens it. No unlock screen that could only
  // fail; the panel says what is true, with nothing left to withdraw or check.
  assert.equal(fresh.opened.length, 0, 'the login key of the request is not on the account: nothing opens');
  assert.deepEqual(fresh.unlocks, []);
  assert.equal(el(fresh, 'move-stage').textContent, P.noLogin(NAME));
  assert.deepEqual([el(fresh, 'move-panel').hidden, el(fresh, 'move-request-part').hidden, el(fresh, 'move-code-part').hidden, el(fresh, 'move-withdraw').hidden, el(fresh, 'move-check').hidden], [false, true, true, true, true]);
  assert.equal(JSON.parse(fresh.storage.getItem(F.vaultSlots(NET, NAME).spend)).binding.publicKey, request.spend.publicKey);
});

test('mixed with the login key of the request on the account: opened with the key the page held and said, or after a reload with the login password', async () => {
  for (const reloaded of [false, true]) {
    const { old, fresh, first } = await world();
    const made = await newRequest(fresh), request = JSON.parse(made.text);
    // A replacement that puts the request's login key in and keeps the old payment key.
    const state = chain.state(), account = state.accounts.find(a => a.name === NAME), row = security.securityOf(state, '5');
    const spendRecord = F.spendRecord(oldStore, F.vaultSlots(NET, NAME)), opened = await openVault(spendRecord, old.passwords.payment, quick, webcrypto, 'spend');
    const keys = [{ public_key: request.signin.publicKey, role: 'signin', proof: request.signin.proof }, security.keepKey(spendRecord.binding.publicKey, 'spend'), ...account.devices.filter(d => security.roleOf(d) === 'recover').map(d => security.keepKey(d.public_key, 'recover'))];
    const approvers = [{ publicKey: spendRecord.binding.publicKey, privateKey: opened.privateKey }, first];
    const other = await F.createSecurityFlows({ security }).buildRoot({ networkId: NET, account, security: row, operation: security.operations.replace(keys, row.policy), approvers, submitter: approvers[0], expiresElapsedMicros: chain.now + 600n * MICROS });
    assert.equal(await chain.submit(other.tx), null);
    const page = reloaded ? reload(fresh) : fresh;
    if (reloaded) await on(page, () => page.ui.start()); else await look(page);
    if (reloaded) assert.deepEqual([page.opened.length, page.unlocks, page.notices.at(-1)], [0, [NAME], [P.mixedOpen(NAME), '']]);
    else assert.deepEqual([page.opened.length, page.opened[0].said, page.unlocks], [1, P.mixed, []]);
    assert.equal(JSON.parse(page.storage.getItem(F.vaultSlots(NET, NAME).login)).binding.publicKey, request.signin.publicKey);
  }
});

// ------------------------------------------------------------------ the page itself
test('the page: every element the move uses is in index.html; the request and the code are not offered for saving or corrected; the secrets are emptied after each step', async () => {
  const page = await readFile(new URL('web-v4/wallet/index.html', root), 'utf8'), code = await readFile(new URL('web-v4/wallet/move-ui.mjs', root), 'utf8');
  const ids = new Set([...code.matchAll(/\$\('([a-z0-9-]+)'\)/g)].map(m => m[1]));
  for (const id of ids) assert.ok(page.includes(`id="${id}"`), `index.html has no element ${id}`);
  for (const id of ['move-request', 'move-old-request', 'move-old-code']) {
    const tag = new RegExp(`<(?:input|textarea)[^>]*id="${id}"[^>]*>`).exec(page)?.[0] ?? '';
    for (const mark of ['autocomplete="off"', 'autocapitalize="off"', 'autocorrect="off"', 'spellcheck="false"', 'data-1p-ignore', 'data-lpignore="true"', 'data-bwignore', 'data-protonpass-ignore']) assert.ok(tag.includes(mark), `${id}: ${mark}`);
    assert.ok(!/type="password"/.test(tag), `${id} is not a secret`);
  }
  for (const id of MOVE_FIELDS) assert.match(new RegExp(`<input[^>]*id="${id}"[^>]*>`).exec(page)?.[0] ?? '', /type="password"/, id);
  // No inline style or script in what the move added.
  const added = page.slice(page.indexOf('<section id="move-panel"'), page.indexOf('</section>', page.indexOf('<section id="move-panel"')));
  assert.ok(added.length > 100 && !/style=|onclick=|<script/.test(added));
  // The lock's card and the backup card name the move as the way across while this device works.
  assert.match(LOCK_WORDS.facts[1], /To change devices while this one still works, move your account under Keys: nothing waits\./);
  assert.match(LOCK_WORDS.backup, /use “Move my account to another device”, below\./);
});
