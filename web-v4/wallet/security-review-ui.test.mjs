// The independent review's runs of the real security-ui.mjs (U1 to U7), on a fake page and a mock
// chain, adapted to the current screens, with scenarios for the fixes that followed (H3, M3, M4).
// Each asserts what the wallet should do; a failure is a defect.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { registerHooks } from 'node:module';

const root = new URL('../../', import.meta.url);
registerHooks({ resolve(s, context, next) { return next(s === '/sdk/account-security.mjs' ? new URL('client-v4/account-security.mjs', root).href : s, context); } });
await import(new URL('client-v4/time-sdk.js', root).href);
const SDK = globalThis.TimeSDK;
const source = await readFile(new URL('web-v4/wallet/vendor/argon2-4.12.0.umd.min.js', root), 'utf8'), umd = { exports: {} };
new Function('module', 'exports', source)(umd, umd.exports);
const argon2id = umd.exports.argon2id;

// ------------------------------------------------------------------ fake page, one DOM per tab
class Storage { m = new Map(); getItem(k) { return this.m.has(k) ? this.m.get(k) : null; } setItem(k, v) { this.m.set(k, String(v)); } removeItem(k) { this.m.delete(k); } }
let runs = [];
class El {
  constructor(id) { Object.assign(this, { id, value: '', hidden: false, textContent: '', disabled: false, open: false, returnValue: '', dataset: {}, type: 'text', children: [], listeners: {}, className: '', classList: { add() {}, remove() {}, toggle() {} } }); }
  addEventListener(type, fn, options) { (this.listeners[type] ??= []).push({ fn, once: options?.once === true }); }
  showModal() { this.open = true; } close() { this.open = false; }
  querySelectorAll() { return [this.querySelector()]; } querySelector() { return this.button ??= new El(this.id + '-button'); }
  replaceChildren(...c) { this.children = c; } append(...c) { this.children.push(...c); }
  async fire(type) { const list = this.listeners[type] || []; this.listeners[type] = list.filter(item => !item.once); await Promise.all(list.map(item => item.fn({ preventDefault() {} }))); while (runs.length) await runs.shift(); }
}
let dom = new Map();
globalThis.document = { getElementById: id => { if (!dom.has(id)) dom.set(id, new El(id)); return dom.get(id); }, createElement: tag => new El(tag), querySelectorAll: () => [], body: { classList: { add() {}, remove() {} } } };
const storage = new Storage();
Object.defineProperty(globalThis, 'localStorage', { value: new Proxy(storage, { ownKeys: t => [...t.m.keys()], getOwnPropertyDescriptor: (t, k) => t.m.has(k) ? { enumerable: true, configurable: true, value: t.m.get(k) } : Reflect.getOwnPropertyDescriptor(t, k), get: (t, k) => typeof t[k] === 'function' ? t[k].bind(t) : t[k] }) });
Object.defineProperty(globalThis, 'navigator', { value: { locks: { request: (name, options, fn) => fn() } } });
globalThis.window = { print() {} };
const $ = id => document.getElementById(id);

const { createSecurityUI } = await import(new URL('web-v4/wallet/security-ui.mjs', root).href);
const { newDevice, openVault, madeForm } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const { sealLegacy, breakingTheRule, sealsKept, provenSeals } = await import(new URL('web-v4/wallet/tests/legacy-vault.mjs', root).href);
const { madeDialog, NOT_HAD } = await import(new URL('web-v4/wallet/made-dialog.mjs', root).href);
const { PendingReservations, formatSeconds } = await import(new URL('web-v4/wallet/guards.mjs', root).href);
const security = await import(new URL('client-v4/account-security.mjs', root).href);

// ------------------------------------------------------------------ mock chain: kinds 70 to 77 roughly as the engine applies them
const networkId = 'c6'.repeat(32), fee = '1000';
let chain;
const stateOf = () => structuredClone({ network_id: networkId, height: String(chain.height), time_micros: chain.time.toString(), genesis: { genesis_time_micros: '0' }, config: { recovery_min_delay_micros: '30000000', recovery_approval_window_micros: '86400000000' }, accounts: chain.accounts, security: Object.values(chain.rows), recovery_cases: [] });
const role = r => ({ can_manage: r === 'recover', can_spend: r === 'spend' });
const bump = account => { account.auth_epoch = String(BigInt(account.auth_epoch) + 1n); };
function install(account, row, devices) { account.devices = devices; account.nonce = String(BigInt(account.nonce) + 1n); bump(account); row.pending_root = null; row.frozen_until_elapsed_micros = '0'; row.pending_payments = []; row.pending_limit = null; }
function apply(action) {
  chain.height++;
  const account = chain.accounts.find(a => a.id === action.from), p = action.payload, now = chain.time;
  if (action.kind === 70) { account.devices = p.keys.map(k => ({ public_key: k.public_key, ...role(k.role) })); account.nonce = action.nonce; bump(account); chain.rows[account.id] = { account: account.id, version: '1', policy: p.policy, allowance_micros: p.policy.daily_limit_micros, allowance_elapsed_micros: now.toString(), frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null }; return; }
  const row = chain.rows[account.id];
  if (action.kind === 71) { account.nonce = action.nonce; bump(account); account.devices = account.devices.filter(d => !p.remove.includes(d.public_key)).concat(p.add.map(k => ({ public_key: k.public_key, can_manage: false, can_spend: false }))); }
  if (action.kind === 73) {
    const votes = security.proofs(account, p.approvals.map(a => a.public_key));
    if (votes.count < Number(row.policy.threshold)) throw new Error('not enough proofs for a root operation');
    if (p.op.type === 'replace') {
      const devices = p.op.keys.map(k => ({ public_key: k.public_key, ...role(k.role) }));
      if (votes.spend) install(account, row, devices);
      else { if (row.pending_root) throw new Error('a replacement is already waiting'); row.pending_root = { devices, policy: p.op.policy, ready_elapsed_micros: (now + BigInt(row.policy.delay_seconds) * 1000000n).toString(), expires_elapsed_micros: (now + BigInt(row.policy.delay_seconds) * 1000000n + 86400000000n).toString() }; }
    }
    if (p.op.type === 'cancel') { if (!row.pending_root) throw new Error('no replacement is waiting'); row.pending_root = null; }
    row.version = String(BigInt(row.version) + 1n);
  }
  if (action.kind === 74) { if (!row.pending_root || now < BigInt(row.pending_root.ready_elapsed_micros)) throw new Error('not ready'); install(account, row, row.pending_root.devices); row.version = String(BigInt(row.version) + 1n); }
}
const client = { submit: async tx => { const action = SDK.decodeAction(tx); apply(action); return { verified: true, hash: await SDK.transactionHash(tx), height: String(chain.height), action }; }, waitReceipt: async () => { throw new Error('none'); } };

// ------------------------------------------------------------------ a wallet tab
let errors, reviews;
/// `dialog`: the passwords the wallet made are shown in the page's own dialog (made-dialog.mjs, on this tab's page), which
/// the test answers (answerMade); else they are taken at once, as a person who pressed "I have them".
function makeTab({ dialog = false } = {}) {
  // `made`: what the dialog of passwords the wallet made showed (made-dialog.mjs), each with the chain's height then, so
  // that a test sees they were shown before anything was sent. `env`: a device that can lock keys, or none.
  const tab = { session: null, latest: null, locked: null, onRecord: null, downloads: [], made: [], env: null };
  const page = dialog ? madeDialog($) : null;
  const ownAccount = (state = tab.latest) => state?.accounts.find(a => a.name === (tab.session?.binding.name || 'alice'));
  tab.c = {
    sdk: SDK, client: () => client, network: () => ({ networkId }), session: () => tab.session, state: () => tab.latest, ownAccount,
    verifiedState: async () => (tab.latest = stateOf()), refresh: async () => {}, review: async (title, fields) => { reviews.push({ title, fields }); return true; },
    notice() {}, run: fn => { const p = (async () => { try { await fn(); } catch (error) { errors.push(error.message); } })(); runs.push(p); return p; }, setBusy() {}, capture: () => () => {},
    seconds: v => formatSeconds(String(v)), fee: () => fee, pending: new PendingReservations(localStorage), record: (receipt, label) => tab.onRecord?.(label), lock: message => { tab.locked = message; tab.session = null; },
    argon2id: () => argon2id, showUnlock() {}, download: (text, name) => tab.downloads.push({ text, name }),
    showMade: async made => { tab.made.push({ ...made, height: chain.height, kept: [...storage.m.keys()].filter(k => /vault|login-request/.test(k)).length }); if (page) await page(made); }, env: () => tab.env,
    sendSigned: async (kind, payload, label, { signer }) => { const account = ownAccount(stateOf()); const tx = await SDK.signAction({ networkId, kind, from: account.id, nonce: String(BigInt(account.nonce) + 1n), authEpoch: account.auth_epoch, publicKey: signer.publicKey, payload }, signer.privateKey); return client.submit(tx); },
  };
  tab.ownAccount = ownAccount;
  return tab;
}
// The passwords of the account: where the device cannot lock keys (this stand-in has none, unless a test gives one), those
// the wallet made and showed when the account was protected (secure, below), read from what the dialog showed.
const CHOSEN = { login: 'violet otters dance beneath moonlight 41', payment: 'quiet harbour lanterns at dawn 77' };
let login = CHOSEN.login, payment = CHOSEN.payment;
const slot = kind => ({ login: `timecurrency.vault.v1:${networkId}:alice`, spend: `timecurrency.spend-vault.v1:${networkId}:alice` })[kind];

/// A fresh world: alice holds one protocol-4 key; one tab is unlocked with it. `dialog`: as makeTab.
async function world({ dialog = false } = {}) {
  storage.m.clear(); dom = new Map(); runs = []; errors = []; reviews = []; login = CHOSEN.login; payment = CHOSEN.payment;
  chain = { time: 1000000000n, height: 9, accounts: [], rows: {} };
  const full = await newDevice();
  chain.accounts.push({ id: '5', name: 'alice', balance: '100000000', nonce: '3', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: full.publicKey, can_manage: true, can_spend: true }] });
  chain.accounts.push({ id: '9', name: 'bob', balance: '0', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [] });
  storage.setItem(slot('login'), JSON.stringify(await sealLegacy(full.secret, 'an old protocol four password', { networkId, name: 'alice', publicKey: full.publicKey }, argon2id)));
  const tab = makeTab({ dialog }); tab.session = { binding: { networkId, name: 'alice', publicKey: full.publicKey }, privateKey: full.privateKey };
  tab.dom = dom; tab.ui = createSecurityUI(tab.c); tab.latest = stateOf(); tab.ui.render(tab.ownAccount(), tab.latest);
  await drawnForm('secure');
  return { tab, full };
}
/// A form that makes new keys is drawn once the browser has said what the device can do (device-lock-ui.mjs, wayChoice):
/// until then it shows neither the choice nor the sentence of a device that cannot lock keys. Waits for one of them.
async function drawnForm(prefix) {
  for (let turn = 0; turn < 1200 && $(`${prefix}-ways`).hidden !== false && $(`${prefix}-seal-note`).hidden !== false; turn++) await new Promise(resolve => setTimeout(resolve, 5));
  assert.ok($(`${prefix}-ways`).hidden === false || $(`${prefix}-seal-note`).hidden === false, `${prefix}: the form drawn`);
}
/// Secures the account through the screens: words only, the five words written down and the button pressed. Returns the
/// words, and no sheet (the account has none).
async function secure(tab) {
  for (const [id, v] of [['secure-login', login], ['secure-login-confirm', login], ['secure-payment', payment], ['secure-payment-confirm', payment], ['secure-limit', '60'], ['secure-delay', '48'], ['secure-freeze', '48'], ['secure-threshold', '2']]) $(id).value = v;
  await $('secure-form').fire('submit');
  const phrase = $('secure-phrase-shown').textContent;
  // Without a device that locks keys, the wallet made both passwords and showed them before the words: they are the account's.
  if (!tab.env) ({ login, payment } = tab.made.at(-1));
  await $('secure-submit').fire('click');
  assert.deepEqual(errors, [], 'securing ran');
  return { sheet: null, phrase, login, payment };
}
const opens = async (record, password, intent) => { try { await openVault(record, password, argon2id, globalThis.crypto, intent); return true; } catch { return false; } };
const unlockAsSignin = tab => { const r = JSON.parse(storage.getItem(slot('login'))); tab.session = { binding: { networkId, name: 'alice', publicKey: r.binding.publicKey }, privateKey: null }; tab.latest = stateOf(); tab.ui.render(tab.ownAccount(), tab.latest); };
const freshBrowser = tab => { storage.m.clear(); tab.session = null; tab.ui.reset(); errors.length = 0; };
async function lostRequest(sheet, phrase, login2 = 'brand new login words for alice 2026', payment2 = 'brand new payment words for alice 99') {
  $('lost-name').value = 'alice'; $('lost-sheet').value = sheet ?? ''; $('lost-phrase').value = phrase;
  for (const [id, v] of [['lost-login', login2], ['lost-login-confirm', login2], ['lost-payment', payment2], ['lost-payment-confirm', payment2]]) $(id).value = v;
  await $('lost-form').fire('submit');
}
/// "New recovery words" with "Words and a Recovery Kit", approved with `current` (the words of now). Returns the new words,
/// the kit that was downloaded, or with `print` the printed sheet.
async function withKit(tab, current, { print = false } = {}) {
  $('rr-kind-kit').checked = true;
  await $('rr-start').fire('click'); assert.deepEqual(errors, [], 'new keys made');
  const words = $('rr-phrase-shown').textContent;
  let kit = null, sheet = null;
  if (print) { await $('rr-print').fire('click'); sheet = $('rr-sheet').textContent; } else { await $('rr-kit-download').fire('click'); kit = tab.downloads.at(-1).text; }
  $('rr-payment').value = payment; $('rr-secret').value = current;
  await $('rr-form').fire('submit'); assert.deepEqual(errors, [], 'new keys sent');
  $('rr-kind-kit').checked = false;
  return { words, kit, sheet };
}

test('U1 two tabs: securing while another tab renders a state from before the block leaves the new keys usable', async () => {
  const { tab, full } = await world();
  const domA = dom; dom = new Map();
  const b = makeTab(); b.session = { ...tab.session }; b.ui = createSecurityUI(b.c); const domB = dom; dom = domA;
  const stale = stateOf(); // what tab B's refresh fetched just before the block with kind 70
  tab.onRecord = label => { if (label === 'Secure account') { dom = domB; b.ui.render(b.ownAccount(stale), stale); dom = domA; } };
  await secure(tab);
  const held = new Set(chain.accounts[0].devices.map(d => d.public_key));
  const stored = [...storage.m.entries()].filter(([k]) => k.includes('vault')).map(([k, v]) => [k, JSON.parse(v).binding?.publicKey]);
  assert.ok(stored.some(([, pk]) => held.has(pk)), 'a stored vault holds a key of the secured account');
  assert.ok(!stored.some(([, pk]) => pk === full.publicKey), 'the protocol-4 key is no longer stored');
  assert.ok(await opens(JSON.parse(storage.getItem(slot('login'))), login), 'the new login password unlocks this browser');
});

test('U1b a reload during securing settles the new keys before any unlock (L6)', async () => {
  const { tab } = await world();
  // The page closes after kind 70 is included but before it settles: simulate by dropping the settle.
  tab.onRecord = label => { if (label === 'Secure account') throw new Error('page closed'); };
  for (const [id, v] of [['secure-login', login], ['secure-login-confirm', login], ['secure-payment', payment], ['secure-payment-confirm', payment], ['secure-limit', '60'], ['secure-threshold', '2']]) $(id).value = v;
  await $('secure-form').fire('submit'); assert.deepEqual(errors, []);
  ({ login, payment } = tab.made.at(-1));
  await $('secure-submit').fire('click'); assert.match(errors.pop() || '', /page closed/);
  assert.ok(chain.rows['5'], 'the account is secured on the chain');
  assert.equal(await opens(JSON.parse(storage.getItem(slot('login'))), login), false, 'before the reload, the login slot still holds the old key');
  // Reload: a new page instance runs start() before anyone unlocks.
  dom = new Map(); const fresh = makeTab(); fresh.ui = createSecurityUI(fresh.c); await fresh.ui.start();
  assert.ok(await opens(JSON.parse(storage.getItem(slot('login'))), login), 'the login password chosen while securing unlocks after the reload');
});

test('the history this browser keeps (locked-store.mjs) survives a change of its login key made here: "Protect my account", then a new login password', async () => {
  const { storageKeyFrom, fromB64 } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
  const { createPrivateStore, withReceipt } = await import(new URL('web-v4/wallet/locked-store.mjs', root).href);
  const { tab, full } = await world();
  // The tab's session opened what the account keeps with its key (app.js, openPrivate), and holds one payment of it.
  const store = createPrivateStore({ storage }), place = { networkId, name: 'alice' };
  await store.open({ ...place, publicKey: full.publicKey, storageKey: await storageKeyFrom(fromB64(full.secret.pkcs8, 256), { ...place, publicKey: full.publicKey }) });
  const item = { hash: 'AB'.repeat(32), height: '8', label: 'Send 1 s to @bob', at: 1, nonce: '3' };
  await store.update('activity', kept => withReceipt(kept, item));
  tab.c.keepPrivate = key => store.adopt({ ...place, ...key });
  const reopened = async password => {
    store.close();
    const record = JSON.parse(storage.getItem(slot('login'))), opened = await openVault(record, password, argon2id);
    return { opened: await store.open({ ...place, publicKey: record.binding.publicKey, storageKey: opened.storageKey, keep: [] }), items: store.value('activity').items };
  };
  await secure(tab);
  assert.deepEqual(await reopened(login), { opened: { lost: false, memory: false }, items: [item] }, 'the new login key opens the history');
  unlockAsSignin(tab);
  $('replace-login-new').value = $('replace-login-confirm').value = 'amber rivers hum under copper skies 8'; $('replace-login-payment').value = payment;
  await $('replace-login-form').fire('submit'); assert.deepEqual(errors, [], 'the login was replaced');
  const newLogin = tab.made.at(-1).login;
  assert.deepEqual(await reopened(newLogin), { opened: { lost: false, memory: false }, items: [item] }, 'and so does the next one');
  assert.equal(Object.keys(JSON.parse(storage.getItem('timecurrency.store-key.v1:' + networkId + ':alice')).wraps).length, 1, 'the keys this browser no longer holds lost their wrap');
  store.close();
});

test('keys locked to this device (device-lock.mjs): a new login password made here is sealed with the device too, and paying asks the device once', async () => {
  const { createHash, createHmac, randomBytes } = await import('node:crypto');
  const { turnOn, createLockAsker, lockOf, LOCK_WORDS } = await import(new URL('web-v4/wallet/device-lock.mjs', root).href);
  const { vaultDevice } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
  // A device that checks the person and gives PRF secrets (as in device-lock.test.mjs).
  const keys = [], buffer = b => { const c = new ArrayBuffer(b.length); new Uint8Array(c).set(b); return c; }, data = () => { const b = new Uint8Array(37); b[32] = 0x05; return buffer(b); };
  const prf = (key, salt) => buffer(createHmac('sha256', key).update(createHash('sha256').update(Buffer.concat([Buffer.from('WebAuthn PRF'), Buffer.from([0]), Buffer.from(salt)])).digest()).digest());
  let gets = 0;
  const env = { secureContext: true, crypto: globalThis.crypto, phone: false,
    PublicKeyCredential: class { static async isUserVerifyingPlatformAuthenticatorAvailable() { return true; } },
    credentials: {
      async create(o) { const key = { id: randomBytes(32), secret: randomBytes(32) }; keys.push(key); return { type: 'public-key', rawId: buffer(key.id), response: { getAuthenticatorData: data }, getClientExtensionResults: () => ({ prf: { enabled: true } }) }; },
      async get(o) { gets += 1; const key = keys.at(-1), e = o.publicKey.extensions.prf.eval; return { type: 'public-key', rawId: buffer(key.id), response: { authenticatorData: data() }, getClientExtensionResults: () => ({ prf: { results: { first: prf(key.secret, e.first), ...(e.second ? { second: prf(key.secret, e.second) } : {}) } } }) }; },
    } };
  const { tab } = await world(); await secure(tab);
  const slots = { login: slot('login'), spend: slot('spend'), nextLogin: `timecurrency.vault-next.v1:${networkId}:alice:signin`, nextSpend: `timecurrency.vault-next.v1:${networkId}:alice:spend`, request: `timecurrency.login-request.v1:${networkId}:alice` };
  await turnOn({ storage: localStorage, slots, networkId, name: 'alice', login, payment, argon2id, env });
  assert.equal(lockOf(localStorage, slots).on, true);
  const said = []; tab.c.lockAsker = (() => { const asker = createLockAsker({ env, say: text => said.push(text) }); return () => asker; })();
  unlockAsSignin(tab);
  const before = gets, newLogin = 'amber rivers hum under copper skies 8';
  $('replace-login-new').value = $('replace-login-confirm').value = newLogin; $('replace-login-payment').value = payment;
  await $('replace-login-form').fire('submit'); assert.deepEqual(errors, [], 'the login was replaced');
  // The payment key opened with the device (one request), the new login key sealed with it (one request): no password-only copy.
  assert.equal(gets - before, 2);
  assert.deepEqual(said, [LOCK_WORDS.before, LOCK_WORDS.before]);
  const now = JSON.parse(storage.getItem(slot('login')));
  assert.deepEqual([now.version, vaultDevice(now) === lockOf(localStorage, slots).credential], [3, true]);
  assert.equal(await opens(now, newLogin), false, 'the new login password alone opens nothing');
  for (const [key, value] of storage.m) if (/vault|login-request/.test(key)) assert.equal((JSON.parse(value).record ?? JSON.parse(value)).version, 3, key);
});

test('U2 "Someone has my login": the wallet makes the new login password, so nothing typed (the payment password neither) seals it, and no single password opens both keys', async () => {
  const { tab } = await world(); await secure(tab); unlockAsSignin(tab);
  // Without the device the fields of a new login password are not asked (the rule); what is typed there is not used.
  assert.deepEqual([$('replace-login-chosen').hidden, $('replace-login-made-note').hidden], [true, false]);
  $('replace-login-new').value = payment.toUpperCase(); $('replace-login-confirm').value = payment.toUpperCase(); $('replace-login-payment').value = payment;
  await $('replace-login-form').fire('submit'); assert.deepEqual(errors, []);
  const made = tab.made.at(-1);
  assert.deepEqual([madeForm(made.login), made.payment, made.login === payment], [made.login, null, false]);
  const loginRecord = JSON.parse(storage.getItem(slot('login'))), spendRecord = JSON.parse(storage.getItem(slot('spend')));
  assert.deepEqual([await opens(loginRecord, made.login), await opens(loginRecord, payment), await opens(spendRecord, made.login, 'spend')], [true, false, false]);
  assert.equal($('replace-login-new').value + $('replace-login-payment').value, '', 'the passwords left the page');
  assert.deepEqual(breakingTheRule([...storage.m]), []);
});

test('U3 "Someone has my payment key": the wallet makes both new passwords, and no single password ends up opening both keys', async () => {
  const { tab, } = await world(); const { phrase } = await secure(tab); unlockAsSignin(tab);
  assert.deepEqual([$('replace-spend-chosen').hidden, $('replace-spend-made-note').hidden], [true, false]);
  // The old login password typed as the new payment password: not used; the wallet makes both, and the login key is replaced too.
  for (const [id, v] of [['replace-spend-payment', payment], ['replace-spend-new', login], ['replace-spend-confirm', login], ['replace-spend-login', login], ['replace-spend-login-confirm', login], ['replace-spend-secret', phrase]]) $(id).value = v;
  await $('replace-spend-form').fire('submit'); assert.deepEqual(errors, []);
  const made = tab.made.at(-1), loginRecord = JSON.parse(storage.getItem(slot('login'))), spendRecord = JSON.parse(storage.getItem(slot('spend')));
  assert.ok(madeForm(made.login) && madeForm(made.payment) && made.login !== made.payment);
  for (const candidate of [login, payment, made.login, made.payment]) assert.ok(!(await opens(loginRecord, candidate) && await opens(spendRecord, candidate, 'spend')), candidate);
  assert.deepEqual([await opens(loginRecord, made.login), await opens(spendRecord, made.payment, 'spend')], [true, true]);
  assert.ok(chain.accounts[0].devices.some(d => d.public_key === loginRecord.binding.publicKey && !d.can_spend && !d.can_manage));
  assert.deepEqual(breakingTheRule([...storage.m]), []);
});

test('U4 the lost-device review states who can cancel: two proofs', async () => {
  const { tab } = await world(); const { sheet, phrase } = await secure(tab);
  freshBrowser(tab); await lostRequest(sheet, phrase);
  const shown = reviews.find(r => r.title.startsWith('Recover @alice')).fields.find(([k]) => k === 'Old devices')[1];
  assert.doesNotMatch(shown, /old payment key or a recovery key can cancel/);
  assert.match(shown, /payment password together with a recovery key, or by both recovery keys/);
});

test('U5 a thief with the spend key removes the owner\'s sign-in key: the owner is shown what is true, with ways back', async () => {
  const { tab } = await world(); await secure(tab); unlockAsSignin(tab);
  const thief = await newDevice(), alice = chain.accounts[0];
  alice.devices = alice.devices.filter(d => d.public_key !== tab.session.binding.publicKey).concat([{ public_key: thief.publicKey, can_manage: false, can_spend: false }]);
  const state = stateOf();
  assert.equal(await tab.ui.withoutDevice(tab.ownAccount(state), state), true);
  assert.equal($('security-removed-panel').hidden, false); assert.equal($('removed-login-form').hidden, false);
  assert.match($('removed-title').textContent, /was removed/);
});

test('U6 secrets typed into the lost-device form leave the page when the name is mistyped', async () => {
  await world(); const sheetText = '000G 40R4 0M30 E209 185G R38E 1W81 24GK 2GAH C5RR 34D1 P70X 3RFM VEE0';
  $('lost-name').value = 'Alice!'; $('lost-sheet').value = sheetText; $('lost-phrase').value = 'kerine netoji nesimo vebine'; $('lost-login').value = login;
  await $('lost-form').fire('submit');
  assert.ok(errors.length);
  assert.equal($('lost-sheet').value + $('lost-phrase').value + $('lost-login').value, '');
  // And when a review is cancelled.
  const { tab } = await world(); const { phrase } = await secure(tab); unlockAsSignin(tab);
  tab.c.review = async () => false; $('freeze-method').value = 'paper'; $('freeze-secret').value = phrase;
  await $('freeze-form').fire('submit'); assert.equal($('freeze-secret').value, '');
});

test('U7 lost device: a finish (kind 74) whose submission was lost is sent again and completes', async () => {
  const { tab } = await world(); const { sheet, phrase } = await secure(tab);
  freshBrowser(tab);
  await lostRequest(sheet, phrase); assert.deepEqual(errors, []);
  // The wallet made the new passwords and showed them before the request was sent.
  const payment2 = tab.made.at(-1).payment;
  chain.time += 48n * 3600n * 1000000n; await $('lost-check').fire('click');
  assert.equal($('lost-finish-form').hidden, false);
  const submit = client.submit; client.submit = async () => { client.submit = submit; throw new Error('network error'); };
  $('lost-finish-payment').value = payment2; await $('lost-finish-form').fire('submit');
  await $('lost-check').fire('click');
  assert.ok($('lost-pending').children.length, 'the signed finish is listed, with Check receipt and Send again');
  $('lost-finish-payment').value = payment2; await $('lost-finish-form').fire('submit');
  assert.ok(chain.accounts[0].devices.some(d => d.can_spend && d.public_key === JSON.parse(storage.getItem(slot('spend'))).binding.publicKey), 'the recovery finished');
});

test('H3 leaked recovery words: a waiting change someone else started is ended by replacing them, and the old ones stop working', async () => {
  const w = await world(); const keys1 = await secure(w.tab); unlockAsSignin(w.tab);
  // Thief's request with the leaked words alone (the account is words only), from elsewhere (submitted directly).
  const saved = new Map(storage.m); freshBrowser(w.tab); await lostRequest(null, keys1.phrase); assert.deepEqual(errors, []); assert.ok(chain.rows['5'].pending_root, 'the words alone asked for the account');
  storage.m = saved; errors.length = 0;
  unlockAsSignin(w.tab);
  assert.ok($('security-inbox').children.some(r => r.children[0].children[0].textContent === 'Waiting change of all your keys'));
  const replaceButton = $('security-inbox').children.find(r => r.children[0].children[0].textContent === 'Waiting change of all your keys').children.find(b => b.textContent === 'Make new recovery words');
  await replaceButton.fire('click'); assert.deepEqual(errors, []);
  // "Words only", selected at first: the new words, the tip, the warning and the button that goes on, from the start.
  const newPhrase = $('rr-phrase-shown').textContent;
  assert.match(newPhrase, /^[a-z]{6}( [a-z]{6}){4}$/);
  assert.deepEqual([$('rr-submit').hidden, $('rr-words-only').hidden, $('rr-with-kit').hidden, $('rr-tip').hidden, $('rr-paper-warning').hidden, $('rr-kinds').hidden, $('rr-start').hidden], [false, false, true, false, false, true, true]);
  for (const [id, v] of [['rr-payment', payment], ['rr-secret', keys1.phrase]]) $(id).value = v;
  await $('rr-form').fire('submit'); assert.deepEqual(errors, []);
  assert.equal(reviews.at(-1).title, 'Replace my recovery words');
  const row = chain.rows['5'], alice = chain.accounts[0];
  assert.equal(row.pending_root, null, 'the waiting change ended');
  // The old words stop working; both new recovery keys come from the new words.
  const F = await import(new URL('web-v4/wallet/security-flows.mjs', root).href);
  const both = async words => [(await F.passphraseKey({ passphrase: words, networkId, accountId: '5', argon2id })).publicKey, (await F.recoveryWordsSecondKey({ passphrase: words, networkId, accountId: '5', argon2id })).publicKey].sort();
  const recover = alice.devices.filter(d => d.can_manage).map(d => d.public_key).sort();
  assert.deepEqual(recover, await both(newPhrase));
  assert.ok(!(await both(keys1.phrase)).some(key => recover.includes(key)), 'the old words');
  assert.equal($('rr-payment').value + $('rr-secret').value, '');
  assert.deepEqual([$('rr-sheet-step').hidden, $('rr-phrase-shown').textContent, $('rr-start').hidden, $('rr-kinds').hidden], [true, '', false, false]);
  assert.equal(JSON.parse(storage.getItem(F.recoveryKindKey(networkId, 'alice'))).kind, 'words');
});

test('New recovery words with a Recovery Kit: the words and the kit, the button only once the kit was downloaded or printed; the kit opens with the new words to the account\'s other key', async () => {
  const { tab } = await world(); const first = await secure(tab); unlockAsSignin(tab);
  const { openRecoveryKit, readRecoveryKit } = await import(new URL('web-v4/wallet/recovery-file.mjs', root).href);
  const F = await import(new URL('web-v4/wallet/security-flows.mjs', root).href);
  // Before anything is made, the two kinds and what each means; words only is selected.
  const page = await readFile(new URL('web-v4/wallet/index.html', root), 'utf8');
  for (const words of ['<input id="rr-kind-words" name="rr-kind" type="radio" value="words" checked><span><strong>Words only</strong><span class="field-note">One paper. Recovering needs the words.</span>', '<input id="rr-kind-kit" name="rr-kind" type="radio" value="kit"><span><strong>Words and a Recovery Kit</strong><span class="field-note">Stronger: recovering then needs the file too, so the paper alone is not enough. Losing either one ends recovery.</span>']) assert.ok(page.includes(words), words);
  $('rr-kind-kit').checked = true;
  await $('rr-start').fire('click'); assert.deepEqual(errors, []);
  const words = $('rr-phrase-shown').textContent;
  assert.deepEqual([$('rr-with-kit').hidden, $('rr-words-only').hidden, $('rr-tip').hidden, $('rr-paper-warning').hidden, $('rr-submit').hidden, $('rr-sheet').textContent, $('rr-printed').hidden], [false, true, true, true, true, '', true]);
  // Approving before the kit was saved (the Enter key in a field of the form) is refused, and nothing is sent.
  $('rr-payment').value = payment; $('rr-secret').value = first.phrase;
  await $('rr-form').fire('submit');
  assert.deepEqual(errors.splice(0), ['Save your new Recovery Kit first: download it, or print it.']);
  await $('rr-kit-download').fire('click'); assert.deepEqual(errors, []);
  const name = `time-recovery-kit-alice-${networkId.slice(0, 8)}.json`;
  assert.deepEqual([tab.downloads.map(d => d.name), $('rr-kit-saved').hidden, $('rr-submit').hidden, $('rr-sheet').textContent], [[name], false, false, '']);
  const kit = tab.downloads[0].text;
  assert.equal(readRecoveryKit(kit).accountName, 'alice');
  $('rr-payment').value = payment; $('rr-secret').value = first.phrase;
  await $('rr-form').fire('submit'); assert.deepEqual(errors, []);
  assert.equal(reviews.at(-1).title, 'Replace my recovery words and Recovery Kit');
  // The account's two recovery keys: the first key of the new words, and the sheet in the kit, which the words open.
  const { sheetText } = await openRecoveryKit(kit, words, { argon2id, expect: { networkId, name: 'alice' } });
  const recover = chain.accounts[0].devices.filter(d => d.can_manage).map(d => d.public_key).sort();
  assert.deepEqual(recover, [(await F.passphraseKey({ passphrase: words, networkId, accountId: '5', argon2id })).publicKey, (await F.sheetKey(sheetText)).publicKey].sort());
  assert.equal(JSON.parse(storage.getItem(F.recoveryKindKey(networkId, 'alice'))).kind, 'kit');
  assert.ok(![...storage.m.values()].some(v => v.includes(words) || v.includes(JSON.parse(kit).ciphertext)));
});

test('H3 a fresh browser cancels a waiting change with both recovery keys', async () => {
  const { tab } = await world(); const { sheet, phrase } = await secure(tab);
  freshBrowser(tab); await lostRequest(sheet, phrase); assert.ok(chain.rows['5'].pending_root);
  storage.m.clear(); tab.ui.reset(); errors.length = 0;
  $('lost-name').value = 'alice'; $('lost-sheet').value = sheet ?? ''; $('lost-phrase').value = phrase;
  await $('lost-cancel-waiting').fire('click'); assert.deepEqual(errors, []);
  assert.equal(chain.rows['5'].pending_root, null);
  assert.equal($('lost-sheet').value + $('lost-phrase').value, '');
});

test('M3 a second browser becomes a login: it asks, the payment key adds it, and it settles there', async () => {
  const { tab } = await world(); await secure(tab); unlockAsSignin(tab);
  // Browser B: its own storage and page; a key that is not on the account (the "New device" mode).
  const storeA = new Map(storage.m), domA = dom; storage.m = new Map(); dom = new Map(); runs = [];
  const b = makeTab(), bKey = await newDevice();
  storage.setItem(slot('login'), JSON.stringify(await sealLegacy(bKey.secret, 'browser b first password 123', { networkId, name: 'alice', publicKey: bKey.publicKey }, argon2id)));
  b.session = { binding: { networkId, name: 'alice', publicKey: bKey.publicKey }, privateKey: bKey.privateKey }; b.ui = createSecurityUI(b.c);
  let state = stateOf(); assert.equal(await b.ui.withoutDevice(b.ownAccount(state), state), true);
  assert.match($('removed-title').textContent, /not a login of @alice yet/);
  $('newlogin-password').value = $('newlogin-confirm').value = 'browser b login password 456'; await $('newlogin-form').fire('submit'); assert.deepEqual(errors, []);
  const request = $('newlogin-code').value; assert.ok(request.includes('"signin-key"'));
  // The login password of browser B was made by the wallet and shown before the request; what was typed is not used.
  const madeB = b.made.at(-1).login;
  assert.deepEqual([madeForm(madeB), b.made.at(-1).payment], [madeB, null]);
  assert.deepEqual(breakingTheRule([...storage.m].filter(([k]) => k.includes('login-request'))), []);
  const storeB = new Map(storage.m), domB = dom;
  // Browser A adds it with the payment password.
  storage.m = storeA; dom = domA;
  $('add-login-request').value = request; $('add-login-payment').value = payment; await $('add-login-form').fire('submit'); assert.deepEqual(errors, []);
  assert.ok(reviews.at(-1).fields.some(([k, v]) => k.startsWith('New login key') && v === JSON.parse(request).publicKey));
  // Browser B refreshes: the key is promoted and the page asks for its login password.
  storage.m = storeB; dom = domB; state = stateOf();
  assert.equal(await b.ui.withoutDevice(b.ownAccount(state), state), true); assert.match(b.locked, /Unlock/);
  assert.ok(await opens(JSON.parse(storage.getItem(slot('login'))), madeB));
  assert.equal(await opens(JSON.parse(storage.getItem(slot('login'))), 'browser b login password 456'), false);
});

test('M4 replacing a stolen payment key removes the thief\'s login key', async () => {
  const { tab } = await world(); const { phrase } = await secure(tab); unlockAsSignin(tab);
  const thief = await newDevice(); chain.accounts[0].devices.push({ public_key: thief.publicKey, can_manage: false, can_spend: false });
  tab.latest = stateOf(); tab.ui.render(tab.ownAccount(), tab.latest);
  const p2 = 'a new payment password for alice 8', l2 = 'a new login password for alice 9';
  for (const [id, v] of [['replace-spend-payment', payment], ['replace-spend-new', p2], ['replace-spend-confirm', p2], ['replace-spend-login', l2], ['replace-spend-login-confirm', l2], ['replace-spend-secret', phrase]]) $(id).value = v;
  await $('replace-spend-form').fire('submit'); assert.deepEqual(errors, []);
  assert.ok(!chain.accounts[0].devices.some(d => d.public_key === thief.publicKey));
  assert.match(tab.locked, /new login password/);
});

// ------------------------------------------------------------------ second review (N1, N2), as written by the review, with the request now dated
test('N1 a login request that is never added does not block "Someone has my login" on that browser', async () => {
  const { tab } = await world(); const { sheet, phrase } = await secure(tab);
  storage.m.clear(); dom = new Map(); runs = []; errors.length = 0;
  const b = makeTab(), bKey = await newDevice();
  storage.setItem(slot('login'), JSON.stringify(await sealLegacy(bKey.secret, 'phone first password 123', { networkId, name: 'alice', publicKey: bKey.publicKey }, argon2id)));
  b.session = { binding: { networkId, name: 'alice', publicKey: bKey.publicKey }, privateKey: bKey.privateKey }; b.ui = createSecurityUI(b.c);
  let state = stateOf(); await b.ui.withoutDevice(b.ownAccount(state), state);
  $('newlogin-password').value = $('newlogin-confirm').value = 'phone login password 456'; await $('newlogin-form').fire('submit');
  assert.deepEqual(errors, []);
  assert.match($('newlogin-fingerprint').textContent, /^Fingerprint: [0-9a-f]{4}( [0-9a-f]{4}){3}\./); assert.equal($('newlogin-withdraw').hidden, false);
  b.session = null; b.ui.reset();
  $('lost-name').value = 'alice'; $('lost-sheet').value = sheet ?? ''; $('lost-phrase').value = phrase;
  const login2 = 'brand new login words for alice 2026', payment2 = 'brand new payment words for alice 99';
  for (const [id, v] of [['lost-login', login2], ['lost-login-confirm', login2], ['lost-payment', payment2], ['lost-payment-confirm', payment2]]) $(id).value = v;
  await $('lost-form').fire('submit'); assert.deepEqual(errors, [], 'recovery request');
  // The wallet made the new passwords: the typed ones are not used.
  const made = b.made.at(-1); assert.notEqual(made.payment, payment2);
  chain.time += 48n * 3600n * 1000000n; await $('lost-check').fire('click');
  $('lost-finish-payment').value = made.payment; await $('lost-finish-form').fire('submit'); assert.deepEqual(errors, [], 'recovery finished');
  const r = JSON.parse(storage.getItem(slot('login'))); b.session = { binding: { networkId, name: 'alice', publicKey: r.binding.publicKey }, privateKey: null };
  b.latest = stateOf(); b.ui.render(b.ownAccount(), b.latest);
  assert.equal([...storage.m.keys()].filter(k => k.includes('login-request') || k.includes('vault-next')).length, 0, 'the void request is gone');
  $('replace-login-new').value = $('replace-login-confirm').value = 'a third login password for alice 7'; $('replace-login-payment').value = made.payment;
  await $('replace-login-form').fire('submit');
  assert.deepEqual(errors, [], 'the emergency flow works');
});

test('N1b a login request can be withdrawn, and an old one pasted later never replaces a live login', async () => {
  const { tab } = await world(); await secure(tab); unlockAsSignin(tab);
  const storeA = new Map(storage.m), domA = dom; storage.m = new Map(); dom = new Map(); runs = [];
  const b = makeTab(), bKey = await newDevice();
  storage.setItem(slot('login'), JSON.stringify(await sealLegacy(bKey.secret, 'phone first password 123', { networkId, name: 'alice', publicKey: bKey.publicKey }, argon2id)));
  b.session = { binding: { networkId, name: 'alice', publicKey: bKey.publicKey }, privateKey: bKey.privateKey }; b.ui = createSecurityUI(b.c);
  let state = stateOf(); await b.ui.withoutDevice(b.ownAccount(state), state);
  $('newlogin-password').value = $('newlogin-confirm').value = 'phone login password 456'; await $('newlogin-form').fire('submit');
  await $('newlogin-withdraw').fire('click'); assert.deepEqual(errors, []);
  assert.equal([...storage.m.keys()].filter(k => k.includes('login-request')).length, 0); assert.equal($('newlogin-form').hidden, false);
  // Ask again; meanwhile this browser holds a live login (here: its login record is replaced by one the account holds).
  $('newlogin-password').value = $('newlogin-confirm').value = 'phone login password 456'; await $('newlogin-form').fire('submit');
  const request = $('newlogin-code').value, storeB = new Map(storage.m), domB = dom;
  storage.m = storeA; dom = domA; const liveLogin = storage.getItem(slot('login'));
  $('add-login-request').value = request; $('add-login-payment').value = payment; await $('add-login-form').fire('submit'); assert.deepEqual(errors, []);
  storage.m = storeB; dom = domB; storage.setItem(slot('login'), liveLogin);
  state = stateOf(); b.session = { binding: { networkId, name: 'alice', publicKey: JSON.parse(liveLogin).binding.publicKey }, privateKey: null }; b.latest = state; b.ui.render(b.ownAccount(), state);
  assert.equal(storage.getItem(slot('login')), liveLogin, 'the live login record was not overwritten');
  assert.equal([...storage.m.keys()].filter(k => k.includes('login-request')).length, 0, 'the request is void');
});

test('N2 a stale login request cannot re-add a key the owner removed', async () => {
  const { tab } = await world(); await secure(tab); unlockAsSignin(tab);
  const flows = (await import(new URL('web-v4/wallet/security-flows.mjs', root).href)).createSecurityFlows({ security });
  const laptop = await newDevice(), state0 = stateOf();
  const request = JSON.stringify(await flows.signinRequest({ networkId, account: tab.ownAccount(state0), key: laptop, now: BigInt(state0.time_micros) }));
  $('add-login-request').value = request; $('add-login-payment').value = payment; await $('add-login-form').fire('submit'); assert.deepEqual(errors, []);
  assert.ok(chain.accounts[0].devices.some(d => d.public_key === laptop.publicKey));
  tab.latest = stateOf(); tab.ui.render(tab.ownAccount(), tab.latest);
  $('replace-login-new').value = $('replace-login-confirm').value = 'a second login password for alice 5'; $('replace-login-payment').value = payment;
  await $('replace-login-form').fire('submit'); assert.deepEqual(errors, []);
  assert.ok(!chain.accounts[0].devices.some(d => d.public_key === laptop.publicKey), 'stolen laptop removed');
  const r = JSON.parse(storage.getItem(slot('login'))); tab.session = { binding: { networkId, name: 'alice', publicKey: r.binding.publicKey }, privateKey: null };
  tab.latest = stateOf(); tab.ui.render(tab.ownAccount(), tab.latest);
  $('add-login-request').value = request; $('add-login-payment').value = payment; await $('add-login-form').fire('submit');
  assert.ok(!chain.accounts[0].devices.some(d => d.public_key === laptop.publicKey), 'a request made before the owner removed that key is refused');
  assert.match(errors.pop() || '', /before the account's keys last changed/);
  // And one older than a few hours is refused too.
  const fresh = await newDevice(), state1 = stateOf();
  const late = JSON.stringify(await flows.signinRequest({ networkId, account: tab.ownAccount(state1), key: fresh, now: BigInt(state1.time_micros) }));
  chain.time += 7n * 3600n * 1000000n;
  $('add-login-request').value = late; $('add-login-payment').value = payment; await $('add-login-form').fire('submit');
  assert.match(errors.pop() || '', /expired/);
});

test('L-b the review of new recovery words names what the immediate change cancels', async () => {
  const { tab } = await world(); await secure(tab); unlockAsSignin(tab);
  chain.rows['5'].pending_payments = [{ id: '1', to: '9', amount: '5', ready_elapsed_micros: '0' }]; chain.rows['5'].pending_limit = { id: '2', daily_limit_micros: '9', ready_elapsed_micros: '99999999999999' };
  tab.latest = stateOf(); tab.ui.render(tab.ownAccount(), tab.latest);
  await $('rr-start').fire('click'); assert.equal($('rr-submit').hidden, false);
  tab.c.review = async (title, fields) => { reviews.push({ title, fields }); return false; };
  await $('rr-form').fire('submit'); assert.deepEqual(errors, []);
  const also = reviews.at(-1).fields.find(([k]) => k === 'Also')[1];
  assert.match(also, /1 waiting payment is cancelled/); assert.match(also, /waiting raise of the daily limit is cancelled/);
});

test('Protect my account: one step, five words on paper and the button from the start; nothing to download or print; both recovery keys come from the words', async () => {
  const { tab } = await world();
  const F = await import(new URL('web-v4/wallet/security-flows.mjs', root).href);
  for (const [id, v] of [['secure-login', login], ['secure-login-confirm', login], ['secure-payment', payment], ['secure-payment-confirm', payment], ['secure-limit', '60'], ['secure-delay', '48'], ['secure-freeze', '48'], ['secure-threshold', '2']]) $(id).value = v;
  await $('secure-form').fire('submit'); assert.deepEqual(errors, []);
  const words = $('secure-phrase-shown').textContent;
  assert.match(words, /^[a-z]{6}( [a-z]{6}){4}$/);
  assert.deepEqual([$('secure-sheet-step').hidden, $('secure-form').hidden, $('secure-submit').hidden, $('secure-tip').hidden], [false, true, false, false]);
  // The step offers nothing to download or print.
  const page = await readFile(new URL('web-v4/wallet/index.html', root), 'utf8'), at = page.indexOf('<div id="secure-sheet-step"'), step = page.slice(at, page.indexOf('</div></div>', at));
  for (const gone of ['secure-kit-download', 'secure-print', 'id="secure-sheet"', 'Recovery Kit']) assert.ok(!step.includes(gone), gone);
  assert.ok(step.includes('<button id="secure-submit" type="button">I wrote them down. Review and protect</button>'));
  await $('secure-submit').fire('click'); assert.deepEqual(errors, []);
  assert.deepEqual(tab.downloads, []);
  const review = Object.fromEntries(reviews.at(-1).fields);
  assert.match(review.Recovery, /^Your recovery words, on paper: both recovery keys come from them\./);
  // Both recovery keys come from the words, by the account's number.
  const recover = chain.accounts[0].devices.filter(d => d.can_manage).map(d => d.public_key).sort();
  assert.deepEqual(recover, [(await F.passphraseKey({ passphrase: words, networkId, accountId: '5', argon2id })).publicKey, (await F.recoveryWordsSecondKey({ passphrase: words, networkId, accountId: '5', argon2id })).publicKey].sort());
  assert.deepEqual([$('secure-sheet-step').hidden, $('secure-phrase-shown').textContent], [true, '']);
  assert.deepEqual(JSON.parse(storage.getItem(F.recoveryKindKey(networkId, 'alice'))), { kind: 'words', keys: recover });
  assert.ok(![...storage.m.values()].some(v => v.includes(words)), 'the words are stored nowhere');
});

test('Protect my account: "Start over" takes the words away, and the next attempt shows new ones', async () => {
  await world();
  for (const [id, v] of [['secure-login', login], ['secure-login-confirm', login], ['secure-payment', payment], ['secure-payment-confirm', payment], ['secure-limit', '60'], ['secure-delay', '48'], ['secure-freeze', '48'], ['secure-threshold', '2']]) $(id).value = v;
  await $('secure-form').fire('submit');
  const words = $('secure-phrase-shown').textContent;
  await $('secure-cancel').fire('click');
  assert.deepEqual([$('secure-phrase-shown').textContent, $('secure-sheet-step').hidden, $('secure-submit').hidden, $('secure-form').hidden], ['', true, true, false]);
  for (const [id, v] of [['secure-login', login], ['secure-login-confirm', login], ['secure-payment', payment], ['secure-payment-confirm', payment]]) $(id).value = v;
  await $('secure-form').fire('submit');
  assert.deepEqual([$('secure-submit').hidden, $('secure-phrase-shown').textContent === words, errors], [false, false, []]);
});

test('recover with the Recovery Kit: read when chosen, it fills the name and says whose it is; a kit of another account is refused before anything is asked or derived; with the words it gives the sheet, and the recovery is asked for', async () => {
  const { tab } = await world();
  const { WRONG_RECOVERY_WORDS } = await import(new URL('web-v4/wallet/recovery-file.mjs', root).href);
  // Protected with words only, then given a kit under "New recovery words".
  const first = await secure(tab); unlockAsSignin(tab);
  const { words, kit } = await withKit(tab, first.phrase);
  freshBrowser(tab);
  // The page reads the kit when it is chosen (a change of the field), without waiting for anything else.
  const choose = async text => { $('lost-file').files = text === null ? [] : [{ size: Buffer.byteLength(text), text: async () => text }]; await $('lost-file').fire('change'); await new Promise(resolve => setTimeout(resolve, 20)); };
  $('lost-name').value = '';
  await choose(kit);
  assert.deepEqual([$('lost-name').value, $('lost-file-status').textContent, $('lost-file-status').hidden], ['alice', 'This is the Recovery Kit of @alice.', false]);
  // Another name typed: the panel says that the kit is not that account's.
  $('lost-name').value = 'bob'; await $('lost-name').fire('input'); await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal($('lost-file-status').textContent, 'This is the Recovery Kit of @alice, not of @bob.');
  // Sent so: refused before the network is asked and before anything is derived.
  let derived = 0, reads = 0;
  tab.c.argon2id = () => async input => { derived += 1; return argon2id(input); };
  const read = tab.c.verifiedState; tab.c.verifiedState = async input => { reads += 1; return read(input); };
  const fill = (name, typed) => { $('lost-name').value = name; $('lost-phrase').value = typed; for (const [id, v] of [['lost-login', 'brand new login words for alice 2026'], ['lost-login-confirm', 'brand new login words for alice 2026'], ['lost-payment', 'brand new payment words for alice 99'], ['lost-payment-confirm', 'brand new payment words for alice 99']]) $(id).value = v; };
  fill('bob', words); await $('lost-form').fire('submit');
  assert.deepEqual([errors.splice(0), derived, reads, $('lost-phrase').value], [['This is the Recovery Kit of @alice, not of @bob.'], 0, 0, '']);
  // A file that is not a kit is said so when it is chosen.
  await choose('{"format":"timecurrency-encrypted-vault","version":1,"vault":{}}');
  assert.deepEqual([$('lost-file-status').textContent, $('lost-file-status').className], ['This file is not a Recovery Kit of the Time wallet.', 'field-note warning']);
  // Other words do not open the kit; nothing is sent.
  await choose(kit); fill('alice', 'bababa bababa bababa bababa bababa'); await $('lost-form').fire('submit');
  assert.deepEqual([errors.splice(0), chain.rows['5'].pending_root], [[WRONG_RECOVERY_WORDS], null]);
  // The kit and the words: the recovery is asked for with the sheet in the kit and the words, and the kit is forgotten.
  fill('alice', words.toUpperCase()); await $('lost-form').fire('submit');
  assert.deepEqual(errors, []);
  assert.ok(chain.rows['5'].pending_root, 'the change of keys waits on the chain');
  assert.equal(reviews.at(-1).fields.find(([k]) => k === 'Approved by')[1], 'Your Recovery Kit and your recovery words');
  assert.deepEqual([$('lost-file').value, $('lost-file-status').hidden, $('lost-phrase').value, $('lost-sheet').value], ['', true, '', '']);
});

test('recover with the name and the words alone: enough for an account that is words only; an account that also has a Recovery Kit is told so, and its printed sheet does it too', async () => {
  // Words only: the name and the words.
  let { tab } = await world(); let first = await secure(tab);
  freshBrowser(tab); $('lost-file').files = [];
  await lostRequest(null, first.phrase); assert.deepEqual(errors, []);
  assert.ok(chain.rows['5'].pending_root);
  assert.equal(reviews.at(-1).fields.find(([k]) => k === 'Approved by')[1], 'Your recovery words');
  // Words and a printed kit: the words alone are not enough, and the panel says what else to give.
  ({ tab } = await world()); first = await secure(tab); unlockAsSignin(tab);
  const { words, sheet } = await withKit(tab, first.phrase, { print: true });
  freshBrowser(tab); $('lost-file').files = [];
  await lostRequest(null, words);
  assert.deepEqual([errors.splice(0), chain.rows['5'].pending_root], [['This account also needs its Recovery Kit. Choose the file, or type the printed sheet.'], null]);
  // Words that are not the account's are said so, also for an account with a kit.
  await lostRequest(null, 'bababa bababa bababa bababa bababa');
  assert.deepEqual(errors.splice(0), ['These recovery words are not one of this account\'s recovery keys. Check them against what you wrote down.']);
  await lostRequest(sheet, words); assert.deepEqual(errors, []);
  assert.ok(chain.rows['5'].pending_root);
  assert.equal(reviews.at(-1).fields.find(([k]) => k === 'Approved by')[1], 'Your printed recovery sheet and your recovery words');
});

test('one field takes the recovery words or a printed recovery sheet: the wallet tells which by itself, and names what was typed when it is not a key of the account', async () => {
  // An account with words and a printed kit: the words give their key, the printed sheet its own.
  const { tab } = await world(); const first = await secure(tab); unlockAsSignin(tab);
  const { words: phrase, sheet } = await withKit(tab, first.phrase, { print: true });
  const F = await import(new URL('web-v4/wallet/security-flows.mjs', root).href);
  const keys = { words: (await F.passphraseKey({ passphrase: phrase, networkId, accountId: '5', argon2id })).publicKey, sheet: (await F.sheetKey(sheet)).publicKey };
  // The page has one field and no choice between the two (freeze keeps a choice: the payment password, or the words).
  const page = await readFile(new URL('web-v4/wallet/index.html', root), 'utf8');
  for (const gone of ['unfreeze-method', 'limit-method', 'resume-method', 'inbox-method', 'send-recovery-method', 'rr-method', 'replace-spend-method', 'Recovery passphrase</option>']) assert.ok(!page.includes(gone), gone);
  assert.ok(page.includes('<option value="payment">Payment password</option><option value="paper">Recovery words</option>'));
  // Eight: with the field of "Move my account to another device" (move-ui.mjs).
  assert.equal(page.split('Your recovery words. A printed recovery sheet works too.').length - 1, 8);
  const signedBy = [], submit = client.submit;
  client.submit = async tx => { signedBy.push(SDK.decodeAction(tx).publicKey); return submit(tx); };
  try {
    for (const [typed, key] of [[phrase, keys.words], [`  ${phrase.toUpperCase().replace(/ /g, '-')} `, keys.words], [sheet, keys.sheet], [sheet.toLowerCase().replace(/ /g, '-'), keys.sheet]]) {
      $('freeze-method').value = 'paper'; $('freeze-secret').value = typed; await $('freeze-form').fire('submit');
      assert.deepEqual([errors.splice(0), signedBy.pop(), $('freeze-secret').value], [[], key, ''], typed);
    }
    // What is not a key of this account is named for what it is; a typo in the words names the word.
    const otherSheet = await F.encodeSheet(F.newSheetSeed());
    for (const [typed, said] of [
      ['bababa bababa bababa bababa bababa', 'These recovery words are not one of this account\'s recovery keys. Check them against what you wrote down.'],
      [phrase.replace(/^(\S+ \S+ )\S/, '$1u'), /^Word 3 of your recovery words is not one the wallet makes\./],
      [phrase.split(' ').slice(0, 3).join(' '), 'Your recovery words are words of six letters: five of them, or four on an older account. Check them against what you wrote down.'],
      [otherSheet, 'This printed recovery sheet is not one of this account\'s recovery keys. Check it against the paper, or type your recovery words instead.'],
      [otherSheet.slice(0, -1) + (otherSheet.endsWith('0') ? '1' : '0'), /typo/],
    ]) {
      $('freeze-method').value = 'paper'; $('freeze-secret').value = typed; await $('freeze-form').fire('submit');
      const error = errors.splice(0);
      if (typeof said === 'string') assert.deepEqual(error, [said], typed); else assert.match(error[0] ?? '', said, typed);
      assert.equal(signedBy.length, 0, 'nothing was signed');
    }
  } finally { client.submit = submit; }
});

// ------------------------------------------------------------------ the rule (vault.mjs, RULE), flow by flow
/// A device that locks keys (the fake authenticator of device-lock.test.mjs), counting what it is asked. `getErrors`: the
/// name of the error each request in turn ends with (none where null). `hold`: a promise the browser's answers to what the
/// device can do wait for (one that never settles: no answer).
async function deviceEnv({ getErrors = [], hold = null } = {}) {
  const { createHash, createHmac, randomBytes } = await import('node:crypto');
  const keys = [], buffer = b => { const c = new ArrayBuffer(b.length); new Uint8Array(c).set(b); return c; }, data = () => { const b = new Uint8Array(37); b[32] = 0x05; return buffer(b); };
  const prf = (key, salt) => buffer(createHmac('sha256', key).update(createHash('sha256').update(Buffer.concat([Buffer.from('WebAuthn PRF'), Buffer.from([0]), Buffer.from(salt)])).digest()).digest());
  const asked = { create: 0, get: 0 };
  return { asked, env: { secureContext: true, crypto: globalThis.crypto, phone: false,
    PublicKeyCredential: class { static async isUserVerifyingPlatformAuthenticatorAvailable() { await hold; return true; } static async getClientCapabilities() { await hold; return { userVerifyingPlatformAuthenticator: true, 'extension:prf': true }; } },
    credentials: {
      async create() { asked.create += 1; const key = { id: randomBytes(32), secret: randomBytes(32) }; keys.push(key); return { type: 'public-key', rawId: buffer(key.id), response: { getAuthenticatorData: data }, getClientExtensionResults: () => ({ prf: { enabled: true } }) }; },
      async get(o) { asked.get += 1; if (getErrors[asked.get - 1]) throw new DOMException('x', getErrors[asked.get - 1]); const key = keys.at(-1), e = o.publicKey.extensions.prf.eval; return { type: 'public-key', rawId: buffer(key.id), response: { authenticatorData: data() }, getClientExtensionResults: () => ({ prf: { results: { first: prf(key.secret, e.first), ...(e.second ? { second: prf(key.secret, e.second) } : {}) } } }) }; },
    } } };
}
/// The places of the vault records this browser keeps, with how each is sealed.
const kept = () => sealsKept([...storage.m]).map(s => `${s.place} ${s.version} ${s.seal}`).sort();
/// The passwords the wallet made were shown before the flow's action reached the chain (one action each here).
const shownFirst = (tab, before) => { const m = tab.made.at(-1); assert.ok(m && m.height === before, `shown at height ${m?.height}, before the action at ${before}`); return m; };

test('the rule, flow by flow, where the device cannot lock keys: "Protect my account", a new login password, a new payment password, a new login after this browser\'s was removed and "Recover my account" make the passwords, show them before anything is sent, and keep nothing a chosen password opens alone', async () => {
  const { tab } = await world();
  assert.deepEqual(kept(), ['timecurrency.vault.v1 1 chosen'], 'a key from before the rule opens as before');
  // Protect my account: the form says the wallet makes both passwords, asks for none, and shows no choice.
  assert.deepEqual([$('secure-chosen').hidden, $('secure-seal-note').textContent, $('secure-seal-note').hidden, $('secure-ways').hidden], [true, (await import(new URL('web-v4/wallet/device-lock.mjs', root).href)).LOCK_WORDS.birthMade, false, true]);
  let height = chain.height; const { phrase } = await secure(tab);
  shownFirst(tab, height); assert.deepEqual(kept(), ['timecurrency.spend-vault.v1 2 made', 'timecurrency.vault.v1 2 made']);
  // A new login password.
  unlockAsSignin(tab); height = chain.height;
  $('replace-login-payment').value = payment; await $('replace-login-form').fire('submit'); assert.deepEqual(errors, []);
  login = shownFirst(tab, height).login; assert.deepEqual(kept(), ['timecurrency.spend-vault.v1 2 made', 'timecurrency.vault.v1 2 made']);
  // A new payment password (with a new login key).
  unlockAsSignin(tab); height = chain.height;
  $('replace-spend-payment').value = payment; $('replace-spend-secret').value = phrase; await $('replace-spend-form').fire('submit'); assert.deepEqual(errors, []);
  ({ login, payment } = shownFirst(tab, height)); assert.deepEqual(kept(), ['timecurrency.spend-vault.v1 2 made', 'timecurrency.vault.v1 2 made']);
  // This browser's login key removed from the account (by its payment key elsewhere): a new one with the payment password.
  unlockAsSignin(tab);
  const alice = chain.accounts[0]; alice.devices = alice.devices.filter(d => d.public_key !== tab.session.binding.publicKey);
  let state = stateOf(); assert.equal(await tab.ui.withoutDevice(tab.ownAccount(state), state), true);
  assert.deepEqual([$('removed-login-form').hidden, $('removed-login-chosen').hidden, $('removed-login-made-note').hidden], [false, true, false]);
  height = chain.height; $('removed-payment').value = payment; await $('removed-login-form').fire('submit'); assert.deepEqual(errors, []);
  login = shownFirst(tab, height).login; assert.equal(tab.made.at(-1).payment, null);
  assert.deepEqual(kept(), ['timecurrency.spend-vault.v1 2 made', 'timecurrency.vault.v1 2 made']);
  assert.ok(await opens(JSON.parse(storage.getItem(slot('login'))), login));
  // "Recover my account" in a browser that never saw the account.
  freshBrowser(tab); height = chain.height;
  await lostRequest(null, phrase); assert.deepEqual(errors, []);
  shownFirst(tab, height); assert.ok(chain.rows['5'].pending_root, 'the recovery waits');
  assert.deepEqual(kept(), ['timecurrency.spend-vault.v1 2 made', 'timecurrency.vault.v1 2 made']);
  assert.match(reviews.at(-1).fields.find(([k]) => k === 'New keys')[1], /under passwords the wallet makes and shows you before anything is sent/);
  assert.deepEqual(breakingTheRule([...storage.m]), []);
});

/// What the browser says it can do comes a moment after a form is drawn: waits until the form of `prefix` shows the choice
/// of how to lock the new keys (device-lock-ui.mjs, wayChoice), and checks that neither way is chosen.
async function choiceShown(prefix) {
  for (let turn = 0; turn < 400 && $(`${prefix}-ways`).hidden !== false; turn++) await new Promise(resolve => setTimeout(resolve, 5));
  assert.deepEqual([$(`${prefix}-ways`).hidden, $(`${prefix}-way-device`).checked, $(`${prefix}-way-made`).checked, $(`${prefix}-seal-note`).hidden, $(`${prefix}-chosen`).hidden], [false, false, false, true, true], `${prefix}: the choice, neither way chosen, and no field of a password`);
}
/// The person picks a way ('device' or 'made') in the form of `prefix`, as a click on its radio does.
async function chooseWay(prefix, way) {
  const picked = $(`${prefix}-way-${way}`), other = $(`${prefix}-way-${way === 'device' ? 'made' : 'device'}`);
  picked.checked = true; other.checked = false;
  await picked.fire('change');
  assert.equal($(`${prefix}-chosen`).hidden, way !== 'device', `${prefix}: the fields of the passwords only once the lock is chosen`);
}

test('the rule where the device can lock keys: "Protect my account" and "Recover my account" show one choice of two ways, neither chosen; with none chosen they do not go on and say so; the lock chosen (after a change), the new keys are locked to it from birth (the passwords chosen, the device asked three times); the passwords the wallet makes chosen, the device is asked nothing', async () => {
  const { LOCK_WORDS } = await import(new URL('web-v4/wallet/device-lock.mjs', root).href);
  const device = await deviceEnv(), { tab } = await world();
  tab.env = device.env; tab.ui.reset(); tab.ui.render(tab.ownAccount(), tab.latest);
  await choiceShown('secure');
  assert.deepEqual(['secure-ways-legend', 'secure-way-device-title', 'secure-way-device-note', 'secure-way-made-title', 'secure-way-made-note'].map(id => $(id).textContent), [LOCK_WORDS.ways.legend, LOCK_WORDS.ways.device.title, LOCK_WORDS.ways.device.note, LOCK_WORDS.ways.made.title, LOCK_WORDS.ways.made.note]);
  // Sent with no way chosen: one sentence; nothing made, kept or sent, and the device is asked nothing.
  let height = chain.height, before = JSON.stringify([...storage.m]);
  for (const [id, v] of [['secure-limit', '60'], ['secure-delay', '48'], ['secure-freeze', '48'], ['secure-threshold', '2']]) $(id).value = v;
  await $('secure-form').fire('submit');
  assert.deepEqual([errors.splice(0), chain.height, JSON.stringify([...storage.m]) === before, tab.made.length, device.asked.create, device.asked.get, $('secure-form').hidden], [[LOCK_WORDS.ways.pick], height, true, 0, 0, 0, false]);
  // The lock, then the passwords the wallet makes: what was typed for the lock goes with its fields; then the lock again.
  await chooseWay('secure','device'); $('secure-login').value = $('secure-login-confirm').value = CHOSEN.login;
  await chooseWay('secure','made');
  assert.deepEqual(['secure-login', 'secure-login-confirm'].map(id => $(id).value), ['', '']);
  await chooseWay('secure','device');
  const { phrase } = await secure(tab);
  assert.deepEqual(tab.made, [], 'no password was made');
  assert.deepEqual([device.asked.create, device.asked.get], [1, 2]);
  assert.deepEqual(kept(), ['timecurrency.spend-vault.v1 3 device', 'timecurrency.vault.v1 3 device']);
  assert.equal(await opens(JSON.parse(storage.getItem(slot('login'))), CHOSEN.login), false, 'the password alone opens nothing');
  // Proven: each record opens with the device's secret and a password typed, and with no other secret.
  const { deviceSecrets, saltOfRecord } = await import(new URL('web-v4/wallet/device-lock.mjs', root).href), { vaultDevice } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
  const secretOf = async record => (await deviceSecrets(device.env, { credentialId: vaultDevice(record), salts: [saltOfRecord(record)] }))[0];
  assert.deepEqual(await provenSeals({ entries: [...storage.m], typed: [CHOSEN.login, CHOSEN.payment], device: secretOf, argon2id }), []);
  // "Recover my account" in a fresh browser of the same device: the choice, under "3."; with none chosen, refused before
  // anything is read or asked; the lock chosen, locked from birth again (its device key not in use: made again).
  freshBrowser(tab); $('lost-name').value = 'alice'; await $('lost-open').fire('click'); await choiceShown('lost');
  assert.equal($('lost-ways-legend').textContent, `3. ${LOCK_WORDS.ways.legend}`);
  let asked = { ...device.asked }; height = chain.height; const reviewed = reviews.length;
  await lostRequest(null, phrase);
  assert.deepEqual([errors.splice(0), chain.height, chain.rows['5'].pending_root, reviews.length - reviewed, device.asked.create - asked.create, device.asked.get - asked.get, storage.m.size], [[LOCK_WORDS.ways.pick], height, null, 0, 0, 0, 0]);
  assert.deepEqual(['lost-phrase', 'lost-login', 'lost-payment'].map(id => $(id).value), ['', '', ''], 'the fields of secrets emptied, as after any step that stops');
  await chooseWay('lost','device');
  await lostRequest(null, phrase); assert.deepEqual(errors, []);
  assert.deepEqual([device.asked.create - asked.create, device.asked.get - asked.get, tab.made.length], [1, 2, 0]);
  assert.ok(chain.rows['5'].pending_root);
  assert.deepEqual(kept(), ['timecurrency.spend-vault.v1 3 device', 'timecurrency.vault.v1 3 device']);
  // The passwords the wallet makes chosen (after the lock): the device is asked nothing.
  const declining = await world(); declining.tab.env = device.env; declining.tab.ui.reset(); declining.tab.ui.render(declining.tab.ownAccount(), declining.tab.latest);
  await choiceShown('secure');
  await chooseWay('secure','device'); await chooseWay('secure','made');
  assert.deepEqual([$('secure-chosen').hidden, $('secure-seal-note').hidden, $('secure-way-made').checked], [true, true, true]);
  asked = { ...device.asked };
  declining.tab.env = null; const { phrase: declinedPhrase } = await secure(declining.tab); declining.tab.env = device.env;
  assert.deepEqual([device.asked.create, device.asked.get], [asked.create, asked.get]);
  assert.deepEqual(kept(), ['timecurrency.spend-vault.v1 2 made', 'timecurrency.vault.v1 2 made']);
  // And "Recover my account" with the passwords the wallet makes chosen: made, shown before the request; the device asked nothing.
  freshBrowser(declining.tab); $('lost-name').value = 'alice'; await $('lost-open').fire('click'); await choiceShown('lost');
  await chooseWay('lost','made'); height = chain.height;
  await lostRequest(null, declinedPhrase); assert.deepEqual(errors, []);
  shownFirst(declining.tab, height); assert.ok(chain.rows['5'].pending_root);
  assert.deepEqual([device.asked.create, device.asked.get], [asked.create, asked.get]);
  assert.deepEqual(kept(), ['timecurrency.spend-vault.v1 2 made', 'timecurrency.vault.v1 2 made']);
});

test('the rule where the device fails after the lock was chosen: "Protect my account" and "Recover my account" go on with passwords the wallet makes, say what happened, and nothing typed seals anything', async () => {
  const { LOCK_WORDS } = await import(new URL('web-v4/wallet/device-lock.mjs', root).href);
  // The person cancels the device's second request (a key made, the first request answered).
  const device = await deviceEnv({ getErrors: [null, 'NotAllowedError'] }), { tab } = await world();
  tab.env = device.env; tab.ui.reset(); tab.ui.render(tab.ownAccount(), tab.latest);
  await choiceShown('secure'); await chooseWay('secure','device');
  let height = chain.height;
  for (const [id, v] of [['secure-login', CHOSEN.login], ['secure-login-confirm', CHOSEN.login], ['secure-payment', CHOSEN.payment], ['secure-payment-confirm', CHOSEN.payment], ['secure-limit', '60'], ['secure-delay', '48'], ['secure-freeze', '48'], ['secure-threshold', '2']]) $(id).value = v;
  await $('secure-form').fire('submit');
  const said = `The device did not give its key, so your keys are not locked to it. ${LOCK_WORDS.fellBack}`;
  let made = shownFirst(tab, height);
  assert.deepEqual([errors.splice(0), made.why, device.asked.create, device.asked.get], [[], said, 1, 2]);
  ({ login, payment } = made);
  const phrase = $('secure-phrase-shown').textContent;
  await $('secure-submit').fire('click'); assert.deepEqual(errors, []);
  assert.deepEqual(kept(), ['timecurrency.spend-vault.v1 2 made', 'timecurrency.vault.v1 2 made']);
  assert.deepEqual(await provenSeals({ entries: [...storage.m], shown: [login, payment], typed: [CHOSEN.login, CHOSEN.payment], argon2id }), []);
  // "Recover my account": the lock chosen, the device fails again (its first request this time): the recovery goes on.
  const failing = await deviceEnv({ getErrors: ['NotAllowedError'] }); tab.env = failing.env;
  freshBrowser(tab); $('lost-name').value = 'alice'; await $('lost-open').fire('click'); await choiceShown('lost'); await chooseWay('lost','device');
  height = chain.height;
  await lostRequest(null, phrase, CHOSEN.login, CHOSEN.payment);
  made = shownFirst(tab, height);
  assert.deepEqual([errors, made.why], [[], said]);
  assert.ok(chain.rows['5'].pending_root, 'the recovery waits');
  assert.deepEqual(kept(), ['timecurrency.spend-vault.v1 2 made', 'timecurrency.vault.v1 2 made']);
  assert.deepEqual(await provenSeals({ entries: [...storage.m], shown: [made.login, made.payment], typed: [CHOSEN.login, CHOSEN.payment], argon2id }), []);
});

test('until the browser has said what the device can do, "Protect my account" and "Recover my account" show neither the choice nor the sentence of a device that cannot lock keys, and a send is refused and makes nothing; the answer draws the choice and the form goes on; an answer that never comes is taken as a device that cannot lock keys', async () => {
  const { LOCK_WORDS } = await import(new URL('web-v4/wallet/device-lock.mjs', root).href), { WAY_ANSWER_MS } = await import(new URL('web-v4/wallet/device-lock-ui.mjs', root).href);
  const asking = prefix => assert.deepEqual([$(`${prefix}-ways`).hidden, $(`${prefix}-seal-note`).hidden, $(`${prefix}-seal-note`).textContent, $(`${prefix}-chosen`).hidden], [true, true, '', true], `${prefix}: neither state is shown`);
  const fill = () => { for (const [id, v] of [['secure-limit', '60'], ['secure-delay', '48'], ['secure-freeze', '48'], ['secure-threshold', '2']]) $(id).value = v; };
  let answer; const device = await deviceEnv({ hold: new Promise(resolve => { answer = resolve; }) }), { tab } = await world();
  tab.env = device.env; tab.ui.reset(); tab.ui.render(tab.ownAccount(), tab.latest);
  asking('secure');
  // Protect my account, sent before the answer: one sentence; nothing made, kept or sent, and the device asked nothing.
  let height = chain.height; const before = JSON.stringify([...storage.m]);
  fill(); await $('secure-form').fire('submit');
  assert.deepEqual([errors.splice(0), chain.height, JSON.stringify([...storage.m]) === before, tab.made.length, device.asked.create, device.asked.get], [[LOCK_WORDS.ways.asking], height, true, 0, 0, 0]);
  asking('secure');
  // The answer: the choice, neither way chosen; the passwords the wallet makes chosen, the account is protected.
  answer(); await choiceShown('secure'); await chooseWay('secure', 'made');
  tab.env = null; const { phrase } = await secure(tab); tab.env = device.env;
  assert.deepEqual([device.asked.create, device.asked.get, kept()], [0, 0, ['timecurrency.spend-vault.v1 2 made', 'timecurrency.vault.v1 2 made']]);
  // Recover my account in a fresh browser whose device has not answered yet: refused, nothing asked, read or sent.
  let late; const slow = await deviceEnv({ hold: new Promise(resolve => { late = resolve; }) }); tab.env = slow.env;
  freshBrowser(tab); $('lost-name').value = 'alice'; await $('lost-open').fire('click');
  asking('lost');
  height = chain.height;
  await lostRequest(null, phrase);
  assert.deepEqual([errors.splice(0), chain.height, chain.rows['5'].pending_root, storage.m.size, slow.asked.create + slow.asked.get], [[LOCK_WORDS.ways.asking], height, null, 0, 0]);
  late(); await choiceShown('lost'); await chooseWay('lost', 'made');
  await lostRequest(null, phrase); assert.deepEqual(errors, []);
  shownFirst(tab, height); assert.ok(chain.rows['5'].pending_root, 'the recovery waits');
  // A browser that never answers: after WAY_ANSWER_MS, "Protect my account" is the form of a device that cannot lock keys,
  // and goes on.
  const silent = await deviceEnv({ hold: new Promise(() => {}) }), other = await world(); other.tab.env = silent.env; other.tab.ui.reset(); other.tab.ui.render(other.tab.ownAccount(), other.tab.latest);
  asking('secure');
  const since = Date.now(); await drawnForm('secure');
  assert.ok(Date.now() - since >= WAY_ANSWER_MS - 200, 'not before the few seconds');
  assert.deepEqual([$('secure-seal-note').textContent, $('secure-ways').hidden, $('secure-chosen').hidden], [LOCK_WORDS.birthMade, true, true]);
  other.tab.env = null; await secure(other.tab);
  assert.deepEqual([silent.asked.create, silent.asked.get, kept()], [0, 0, ['timecurrency.spend-vault.v1 2 made', 'timecurrency.vault.v1 2 made']]);
});

/// The dialog of the passwords the wallet made, on the page (made-dialog.mjs): once it is open, what it shows, then closed
/// `how`: 'done' ("I have them": the button's value) or 'escape' (the browser's cancel event, then the close it makes).
async function answerMade(how = 'done') {
  for (let turn = 0; turn < 6000 && !$('made-dialog').open; turn++) await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal($('made-dialog').open, true, `the passwords the wallet made (errors: ${errors.join(' | ')})`);
  const shown = { login: $('made-login-shown').textContent, payment: $('made-payment-shown').textContent };
  if (how === 'done') $('made-dialog').returnValue = 'done';
  if (how === 'escape') { await $('made-dialog').fire('cancel'); assert.equal($('made-dialog').open, false, 'Escape closes the dialog'); }
  $('made-dialog').open = false; await $('made-dialog').fire('close');
  return shown;
}
/// The vault records this browser keeps at the places named (`timecurrency.<name>:`), as [key, value] pairs.
const at = (...names) => [...storage.m].filter(([key]) => names.some(name => key.startsWith(`timecurrency.${name}:`)));
const everythingKept = () => JSON.stringify([...storage.m].filter(([key]) => /vault|login-request|security-recovery/.test(key)).sort());

test('the rule, flow by flow, with the dialog of the page: closed by Escape, a flow keeps and sends nothing and says so; with "I have them", each record it made opens with the passwords shown and with nothing typed', async () => {
  const { tab } = await world({ dialog: true });
  const proven = async (entries, shown, typed) => assert.deepEqual(await provenSeals({ entries, shown, typed, argon2id }), []);
  /// A flow started by `start` (not awaited: its step waits for the dialog), its dialog closed by Escape: nothing kept or
  /// sent, and the words of made-dialog.mjs; then started again and closed by "I have them". Returns what was shown.
  async function escapeThenDone(start, words) {
    const before = everythingKept(), height = chain.height;
    let running = start(); await answerMade('escape'); await running;
    assert.deepEqual([errors.splice(0), everythingKept() === before, chain.height], [[words], true, height], 'closed by Escape: nothing kept or sent');
    running = start(); const shown = await answerMade('done'); await running;
    assert.deepEqual(errors, []);
    return shown;
  }
  // Protect my account: both passwords made; the recovery words come after "I have them".
  const fill = () => { for (const [id, v] of [['secure-limit', '60'], ['secure-delay', '48'], ['secure-freeze', '48'], ['secure-threshold', '2']]) $(id).value = v; };
  let shown = await escapeThenDone(() => { fill(); return $('secure-form').fire('submit'); }, NOT_HAD.two);
  ({ login, payment } = shown);
  const phrase = $('secure-phrase-shown').textContent;
  await $('secure-submit').fire('click'); assert.deepEqual(errors, []);
  assert.deepEqual(kept(), ['timecurrency.spend-vault.v1 2 made', 'timecurrency.vault.v1 2 made']);
  await proven(at('vault.v1', 'spend-vault.v1'), [login, payment], []);
  // A new login password: the payment password typed opens nothing new.
  unlockAsSignin(tab);
  shown = await escapeThenDone(() => { $('replace-login-payment').value = payment; return $('replace-login-form').fire('submit'); }, NOT_HAD.one);
  login = shown.login; await proven(at('vault.v1'), [login], [payment]);
  // A new payment password, and a new login key with it.
  unlockAsSignin(tab);
  const typedPayment = payment;
  shown = await escapeThenDone(() => { $('replace-spend-payment').value = payment; $('replace-spend-secret').value = phrase; return $('replace-spend-form').fire('submit'); }, NOT_HAD.two);
  ({ login, payment } = shown); await proven(at('vault.v1', 'spend-vault.v1'), [login, payment], [typedPayment]);
  // This browser's login key removed from the account: a new one, with the payment password.
  unlockAsSignin(tab);
  const alice = chain.accounts[0]; alice.devices = alice.devices.filter(d => d.public_key !== tab.session.binding.publicKey);
  const state = stateOf(); assert.equal(await tab.ui.withoutDevice(tab.ownAccount(state), state), true);
  shown = await escapeThenDone(() => { $('removed-payment').value = payment; return $('removed-login-form').fire('submit'); }, NOT_HAD.one);
  login = shown.login; await proven(at('vault.v1'), [login], [payment]);
  // "Recover my account" in a browser that never saw the account: the review comes first, then the passwords.
  freshBrowser(tab);
  shown = await escapeThenDone(() => { $('lost-name').value = 'alice'; $('lost-sheet').value = ''; $('lost-phrase').value = phrase; return $('lost-form').fire('submit'); }, NOT_HAD.two);
  assert.ok(chain.rows['5'].pending_root, 'the recovery waits');
  await proven(at('vault.v1', 'spend-vault.v1'), [shown.login, shown.payment], [phrase]);
  // A login for another browser: its own storage and page; the login password made there, shown before the request.
  storage.m = new Map(); dom = new Map(); runs = []; errors.length = 0;
  const b = makeTab({ dialog: true }), bKey = await newDevice();
  storage.setItem(slot('login'), JSON.stringify(await sealLegacy(bKey.secret, 'browser b first password 123', { networkId, name: 'alice', publicKey: bKey.publicKey }, argon2id)));
  b.session = { binding: { networkId, name: 'alice', publicKey: bKey.publicKey }, privateKey: bKey.privateKey }; b.ui = createSecurityUI(b.c);
  const bState = stateOf(); assert.equal(await b.ui.withoutDevice(b.ownAccount(bState), bState), true);
  shown = await escapeThenDone(() => $('newlogin-form').fire('submit'), NOT_HAD.one);
  assert.ok($('newlogin-code').value.includes('"signin-key"'));
  await proven(at('login-request.v1'), [shown.login], ['browser b first password 123']);
});
