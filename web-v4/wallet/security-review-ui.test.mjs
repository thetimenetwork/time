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
  constructor(id) { Object.assign(this, { id, value: '', hidden: false, textContent: '', disabled: false, dataset: {}, type: 'text', children: [], listeners: {}, className: '', classList: { add() {}, remove() {}, toggle() {} } }); }
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

const { createSecurityUI } = await import(new URL('web-v4/wallet/security-ui.mjs', root).href);
const { newDevice, sealVault, openVault } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
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
function makeTab() {
  const tab = { session: null, latest: null, locked: null, onRecord: null };
  const ownAccount = (state = tab.latest) => state?.accounts.find(a => a.name === (tab.session?.binding.name || 'alice'));
  tab.c = {
    sdk: SDK, client: () => client, network: () => ({ networkId }), session: () => tab.session, state: () => tab.latest, ownAccount,
    verifiedState: async () => (tab.latest = stateOf()), refresh: async () => {}, review: async (title, fields) => { reviews.push({ title, fields }); return true; },
    notice() {}, run: fn => { const p = (async () => { try { await fn(); } catch (error) { errors.push(error.message); } })(); runs.push(p); return p; }, setBusy() {}, capture: () => () => {},
    seconds: v => formatSeconds(String(v)), fee: () => fee, pending: new PendingReservations(localStorage), record: (receipt, label) => tab.onRecord?.(label), lock: message => { tab.locked = message; tab.session = null; },
    argon2id: () => argon2id, showUnlock() {},
    sendSigned: async (kind, payload, label, { signer }) => { const account = ownAccount(stateOf()); const tx = await SDK.signAction({ networkId, kind, from: account.id, nonce: String(BigInt(account.nonce) + 1n), authEpoch: account.auth_epoch, publicKey: signer.publicKey, payload }, signer.privateKey); return client.submit(tx); },
  };
  tab.ownAccount = ownAccount;
  return tab;
}
const login = 'violet otters dance beneath moonlight 41', payment = 'quiet harbour lanterns at dawn 77';
const slot = kind => ({ login: `timecurrency.vault.v1:${networkId}:alice`, spend: `timecurrency.spend-vault.v1:${networkId}:alice` })[kind];

/// A fresh world: alice holds one protocol-4 key; one tab is unlocked with it.
async function world() {
  storage.m.clear(); dom = new Map(); runs = []; errors = []; reviews = [];
  chain = { time: 1000000000n, height: 9, accounts: [], rows: {} };
  const full = await newDevice();
  chain.accounts.push({ id: '5', name: 'alice', balance: '100000000', nonce: '3', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: full.publicKey, can_manage: true, can_spend: true }] });
  chain.accounts.push({ id: '9', name: 'bob', balance: '0', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [] });
  storage.setItem(slot('login'), JSON.stringify(await sealVault(full.secret, 'an old protocol four password', { networkId, name: 'alice', publicKey: full.publicKey }, argon2id)));
  const tab = makeTab(); tab.session = { binding: { networkId, name: 'alice', publicKey: full.publicKey }, privateKey: full.privateKey };
  tab.dom = dom; tab.ui = createSecurityUI(tab.c); tab.latest = stateOf(); tab.ui.render(tab.ownAccount(), tab.latest);
  return { tab, full };
}
/// Secures the account through the screens; returns the sheet and the passphrase the wallet made.
async function secure(tab) {
  for (const [id, v] of [['secure-login', login], ['secure-login-confirm', login], ['secure-payment', payment], ['secure-payment-confirm', payment], ['secure-limit', '60'], ['secure-delay', '48'], ['secure-freeze', '48'], ['secure-threshold', '2']]) $(id).value = v;
  await $('secure-form').fire('submit');
  const sheet = $('secure-sheet').textContent, phrase = $('secure-phrase-shown').textContent;
  await $('secure-sheet-done').fire('click');
  const groups = sheet.split(' '), pick = id => groups[Number($(id + '-label').textContent.replace('Group ', '')) - 1];
  $('secure-confirm-a').value = pick('secure-confirm-a'); $('secure-confirm-b').value = pick('secure-confirm-b'); $('secure-confirm-phrase').value = phrase.toUpperCase();
  await $('secure-submit').fire('click');
  assert.deepEqual(errors, [], 'securing ran');
  return { sheet, phrase };
}
const opens = async (record, password, intent) => { try { await openVault(record, password, argon2id, globalThis.crypto, intent); return true; } catch { return false; } };
const unlockAsSignin = tab => { const r = JSON.parse(storage.getItem(slot('login'))); tab.session = { binding: { networkId, name: 'alice', publicKey: r.binding.publicKey }, privateKey: null }; tab.latest = stateOf(); tab.ui.render(tab.ownAccount(), tab.latest); };
const freshBrowser = tab => { storage.m.clear(); tab.session = null; tab.ui.reset(); errors.length = 0; };
async function lostRequest(sheet, phrase, login2 = 'brand new login words for alice 2026', payment2 = 'brand new payment words for alice 99') {
  $('lost-name').value = 'alice'; $('lost-sheet').value = sheet; $('lost-phrase').value = phrase;
  for (const [id, v] of [['lost-login', login2], ['lost-login-confirm', login2], ['lost-payment', payment2], ['lost-payment-confirm', payment2]]) $(id).value = v;
  await $('lost-form').fire('submit');
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
  const sheet = $('secure-sheet').textContent, phrase = $('secure-phrase-shown').textContent;
  await $('secure-sheet-done').fire('click');
  const groups = sheet.split(' '), pick = id => groups[Number($(id + '-label').textContent.replace('Group ', '')) - 1];
  $('secure-confirm-a').value = pick('secure-confirm-a'); $('secure-confirm-b').value = pick('secure-confirm-b'); $('secure-confirm-phrase').value = phrase;
  await $('secure-submit').fire('click'); assert.match(errors.pop() || '', /page closed/);
  assert.ok(chain.rows['5'], 'the account is secured on the chain');
  assert.equal(await opens(JSON.parse(storage.getItem(slot('login'))), login), false, 'before the reload, the login slot still holds the old key');
  // Reload: a new page instance runs start() before anyone unlocks.
  dom = new Map(); const fresh = makeTab(); fresh.ui = createSecurityUI(fresh.c); await fresh.ui.start();
  assert.ok(await opens(JSON.parse(storage.getItem(slot('login'))), login), 'the login password chosen while securing unlocks after the reload');
});

test('U2 "Someone has my login" refuses the payment password as the new login password', async () => {
  const { tab } = await world(); await secure(tab); unlockAsSignin(tab);
  $('replace-login-new').value = payment.toUpperCase(); $('replace-login-confirm').value = payment.toUpperCase(); $('replace-login-payment').value = payment;
  await $('replace-login-form').fire('submit');
  assert.match(errors.pop() || '', /differ/);
  const both = await opens(JSON.parse(storage.getItem(slot('login'))), payment) && await opens(JSON.parse(storage.getItem(slot('spend'))), payment, 'spend');
  assert.ok(!both);
  assert.equal($('replace-login-new').value + $('replace-login-payment').value, '', 'the passwords left the page');
});

test('U3 "Someone has my payment key": no single password ends up opening both keys', async () => {
  const { tab, } = await world(); const { phrase } = await secure(tab); unlockAsSignin(tab);
  // Same new login and payment password: refused.
  for (const [id, v] of [['replace-spend-payment', payment], ['replace-spend-new', login], ['replace-spend-confirm', login], ['replace-spend-login', login], ['replace-spend-login-confirm', login], ['replace-spend-method', 'phrase'], ['replace-spend-secret', phrase]]) $(id).value = v;
  await $('replace-spend-form').fire('submit'); assert.match(errors.pop() || '', /differ/);
  // The old login password as the new payment password: the login key is replaced too, so the old password opens nothing.
  const newLogin = 'a fresh login password for alice 3';
  for (const [id, v] of [['replace-spend-payment', payment], ['replace-spend-new', login], ['replace-spend-confirm', login], ['replace-spend-login', newLogin], ['replace-spend-login-confirm', newLogin], ['replace-spend-method', 'phrase'], ['replace-spend-secret', phrase]]) $(id).value = v;
  await $('replace-spend-form').fire('submit'); assert.deepEqual(errors, []);
  const loginRecord = JSON.parse(storage.getItem(slot('login'))), spendRecord = JSON.parse(storage.getItem(slot('spend')));
  for (const candidate of [login, payment, newLogin]) assert.ok(!(await opens(loginRecord, candidate) && await opens(spendRecord, candidate, 'spend')), candidate);
  assert.ok(chain.accounts[0].devices.some(d => d.public_key === loginRecord.binding.publicKey && !d.can_spend && !d.can_manage));
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
  tab.c.review = async () => false; $('freeze-method').value = 'phrase'; $('freeze-secret').value = phrase;
  await $('freeze-form').fire('submit'); assert.equal($('freeze-secret').value, '');
});

test('U7 lost device: a finish (kind 74) whose submission was lost is sent again and completes', async () => {
  const { tab } = await world(); const { sheet, phrase } = await secure(tab);
  freshBrowser(tab); const payment2 = 'brand new payment words for alice 99';
  await lostRequest(sheet, phrase, undefined, payment2); assert.deepEqual(errors, []);
  chain.time += 48n * 3600n * 1000000n; await $('lost-check').fire('click');
  assert.equal($('lost-finish-form').hidden, false);
  const submit = client.submit; client.submit = async () => { client.submit = submit; throw new Error('network error'); };
  $('lost-finish-payment').value = payment2; await $('lost-finish-form').fire('submit');
  await $('lost-check').fire('click');
  assert.ok($('lost-pending').children.length, 'the signed finish is listed, with Check receipt and Send again');
  $('lost-finish-payment').value = payment2; await $('lost-finish-form').fire('submit');
  assert.ok(chain.accounts[0].devices.some(d => d.can_spend && d.public_key === JSON.parse(storage.getItem(slot('spend'))).binding.publicKey), 'the recovery finished');
});

test('H3 leaked recovery keys: a waiting change someone else started is ended by replacing them, and the old ones stop working', async () => {
  const w = await world(); const keys1 = await secure(w.tab); unlockAsSignin(w.tab);
  // Thief's request with the leaked keys, from elsewhere (submitted directly).
  const saved = new Map(storage.m); freshBrowser(w.tab); await lostRequest(keys1.sheet, keys1.phrase); storage.m = saved; errors.length = 0;
  unlockAsSignin(w.tab);
  assert.ok($('security-inbox').children.some(r => r.children[0].children[0].textContent === 'Waiting change of all your keys'));
  const replaceButton = $('security-inbox').children.find(r => r.children[0].children[0].textContent === 'Waiting change of all your keys').children.find(b => b.textContent === 'Replace recovery keys');
  await replaceButton.fire('click'); assert.deepEqual(errors, []);
  const newSheet = $('rr-sheet').textContent, newPhrase = $('rr-phrase-shown').textContent;
  assert.match(newSheet, /^([0-9A-Z]{4} ){13}[0-9A-Z]{4}$/); assert.match(newPhrase, /^[a-z]{6}( [a-z]{6}){3}$/);
  await $('rr-shown-done').fire('click');
  const groups = newSheet.split(' '), pick = id => groups[Number($(id + '-label').textContent.replace(/^Group (\d+).*$/, '$1')) - 1];
  for (const [id, v] of [['rr-confirm-a', pick('rr-confirm-a')], ['rr-confirm-b', pick('rr-confirm-b')], ['rr-confirm-phrase', newPhrase], ['rr-payment', payment], ['rr-method', 'sheet'], ['rr-secret', keys1.sheet]]) $(id).value = v;
  await $('rr-form').fire('submit'); assert.deepEqual(errors, []);
  const row = chain.rows['5'], alice = chain.accounts[0];
  assert.equal(row.pending_root, null, 'the waiting change ended');
  // The old recovery keys stop working; the new ones are the account's.
  const { sheetKey, passphraseKey } = await import(new URL('web-v4/wallet/security-flows.mjs', root).href);
  const recover = new Set(alice.devices.filter(d => d.can_manage).map(d => d.public_key));
  assert.ok(!recover.has((await sheetKey(keys1.sheet)).publicKey), 'old sheet');
  assert.ok(recover.has((await sheetKey(newSheet)).publicKey), 'new sheet');
  assert.ok(recover.has((await passphraseKey({ passphrase: newPhrase, networkId, accountId: '5', argon2id })).publicKey), 'new passphrase');
  assert.equal($('rr-payment').value + $('rr-secret').value + $('rr-confirm-phrase').value, '');
});

test('H3 a fresh browser cancels a waiting change with both recovery keys', async () => {
  const { tab } = await world(); const { sheet, phrase } = await secure(tab);
  freshBrowser(tab); await lostRequest(sheet, phrase); assert.ok(chain.rows['5'].pending_root);
  storage.m.clear(); tab.ui.reset(); errors.length = 0;
  $('lost-name').value = 'alice'; $('lost-sheet').value = sheet; $('lost-phrase').value = phrase;
  await $('lost-cancel-waiting').fire('click'); assert.deepEqual(errors, []);
  assert.equal(chain.rows['5'].pending_root, null);
  assert.equal($('lost-sheet').value + $('lost-phrase').value, '');
});

test('M3 a second browser becomes a login: it asks, the payment key adds it, and it settles there', async () => {
  const { tab } = await world(); await secure(tab); unlockAsSignin(tab);
  // Browser B: its own storage and page; a key that is not on the account (the "New device" mode).
  const storeA = new Map(storage.m), domA = dom; storage.m = new Map(); dom = new Map(); runs = [];
  const b = makeTab(), bKey = await newDevice();
  storage.setItem(slot('login'), JSON.stringify(await sealVault(bKey.secret, 'browser b first password 123', { networkId, name: 'alice', publicKey: bKey.publicKey }, argon2id)));
  b.session = { binding: { networkId, name: 'alice', publicKey: bKey.publicKey }, privateKey: bKey.privateKey }; b.ui = createSecurityUI(b.c);
  let state = stateOf(); assert.equal(await b.ui.withoutDevice(b.ownAccount(state), state), true);
  assert.match($('removed-title').textContent, /not a login of @alice yet/);
  $('newlogin-password').value = $('newlogin-confirm').value = 'browser b login password 456'; await $('newlogin-form').fire('submit'); assert.deepEqual(errors, []);
  const request = $('newlogin-code').value; assert.ok(request.includes('"signin-key"'));
  const storeB = new Map(storage.m), domB = dom;
  // Browser A adds it with the payment password.
  storage.m = storeA; dom = domA;
  $('add-login-request').value = request; $('add-login-payment').value = payment; await $('add-login-form').fire('submit'); assert.deepEqual(errors, []);
  assert.ok(reviews.at(-1).fields.some(([k, v]) => k.startsWith('New login key') && v === JSON.parse(request).publicKey));
  // Browser B refreshes: the key is promoted and the page asks for its login password.
  storage.m = storeB; dom = domB; state = stateOf();
  assert.equal(await b.ui.withoutDevice(b.ownAccount(state), state), true); assert.match(b.locked, /Unlock/);
  assert.ok(await opens(JSON.parse(storage.getItem(slot('login'))), 'browser b login password 456'));
});

test('M4 replacing a stolen payment key removes the thief\'s login key', async () => {
  const { tab } = await world(); const { phrase } = await secure(tab); unlockAsSignin(tab);
  const thief = await newDevice(); chain.accounts[0].devices.push({ public_key: thief.publicKey, can_manage: false, can_spend: false });
  tab.latest = stateOf(); tab.ui.render(tab.ownAccount(), tab.latest);
  const p2 = 'a new payment password for alice 8', l2 = 'a new login password for alice 9';
  for (const [id, v] of [['replace-spend-payment', payment], ['replace-spend-new', p2], ['replace-spend-confirm', p2], ['replace-spend-login', l2], ['replace-spend-login-confirm', l2], ['replace-spend-method', 'phrase'], ['replace-spend-secret', phrase]]) $(id).value = v;
  await $('replace-spend-form').fire('submit'); assert.deepEqual(errors, []);
  assert.ok(!chain.accounts[0].devices.some(d => d.public_key === thief.publicKey));
  assert.match(tab.locked, /new login password/);
});

// ------------------------------------------------------------------ second review (N1, N2), as written by the review, with the request now dated
test('N1 a login request that is never added does not block "Someone has my login" on that browser', async () => {
  const { tab } = await world(); const { sheet, phrase } = await secure(tab);
  storage.m.clear(); dom = new Map(); runs = []; errors.length = 0;
  const b = makeTab(), bKey = await newDevice();
  storage.setItem(slot('login'), JSON.stringify(await sealVault(bKey.secret, 'phone first password 123', { networkId, name: 'alice', publicKey: bKey.publicKey }, argon2id)));
  b.session = { binding: { networkId, name: 'alice', publicKey: bKey.publicKey }, privateKey: bKey.privateKey }; b.ui = createSecurityUI(b.c);
  let state = stateOf(); await b.ui.withoutDevice(b.ownAccount(state), state);
  $('newlogin-password').value = $('newlogin-confirm').value = 'phone login password 456'; await $('newlogin-form').fire('submit');
  assert.deepEqual(errors, []);
  assert.match($('newlogin-fingerprint').textContent, /^Fingerprint: [0-9a-f]{4}( [0-9a-f]{4}){3}\./); assert.equal($('newlogin-withdraw').hidden, false);
  b.session = null; b.ui.reset();
  $('lost-name').value = 'alice'; $('lost-sheet').value = sheet; $('lost-phrase').value = phrase;
  const login2 = 'brand new login words for alice 2026', payment2 = 'brand new payment words for alice 99';
  for (const [id, v] of [['lost-login', login2], ['lost-login-confirm', login2], ['lost-payment', payment2], ['lost-payment-confirm', payment2]]) $(id).value = v;
  await $('lost-form').fire('submit'); assert.deepEqual(errors, [], 'recovery request');
  chain.time += 48n * 3600n * 1000000n; await $('lost-check').fire('click');
  $('lost-finish-payment').value = payment2; await $('lost-finish-form').fire('submit'); assert.deepEqual(errors, [], 'recovery finished');
  const r = JSON.parse(storage.getItem(slot('login'))); b.session = { binding: { networkId, name: 'alice', publicKey: r.binding.publicKey }, privateKey: null };
  b.latest = stateOf(); b.ui.render(b.ownAccount(), b.latest);
  assert.equal([...storage.m.keys()].filter(k => k.includes('login-request') || k.includes('vault-next')).length, 0, 'the void request is gone');
  $('replace-login-new').value = $('replace-login-confirm').value = 'a third login password for alice 7'; $('replace-login-payment').value = payment2;
  await $('replace-login-form').fire('submit');
  assert.deepEqual(errors, [], 'the emergency flow works');
});

test('N1b a login request can be withdrawn, and an old one pasted later never replaces a live login', async () => {
  const { tab } = await world(); await secure(tab); unlockAsSignin(tab);
  const storeA = new Map(storage.m), domA = dom; storage.m = new Map(); dom = new Map(); runs = [];
  const b = makeTab(), bKey = await newDevice();
  storage.setItem(slot('login'), JSON.stringify(await sealVault(bKey.secret, 'phone first password 123', { networkId, name: 'alice', publicKey: bKey.publicKey }, argon2id)));
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

test('L-b the review of a new recovery sheet and passphrase names what the immediate change cancels', async () => {
  const { tab } = await world(); await secure(tab); unlockAsSignin(tab);
  chain.rows['5'].pending_payments = [{ id: '1', to: '9', amount: '5', ready_elapsed_micros: '0' }]; chain.rows['5'].pending_limit = { id: '2', daily_limit_micros: '9', ready_elapsed_micros: '99999999999999' };
  tab.latest = stateOf(); tab.ui.render(tab.ownAccount(), tab.latest);
  await $('rr-start').fire('click');
  const newSheet = $('rr-sheet').textContent, newPhrase = $('rr-phrase-shown').textContent;
  await $('rr-shown-done').fire('click');
  const groups = newSheet.split(' '), pick = id => groups[Number($(id + '-label').textContent.replace(/^Group (\d+).*$/, '$1')) - 1];
  $('rr-confirm-a').value = pick('rr-confirm-a'); $('rr-confirm-b').value = pick('rr-confirm-b'); $('rr-confirm-phrase').value = newPhrase;
  tab.c.review = async (title, fields) => { reviews.push({ title, fields }); return false; };
  await $('rr-form').fire('submit'); assert.deepEqual(errors, []);
  const also = reviews.at(-1).fields.find(([k]) => k === 'Also')[1];
  assert.match(also, /1 waiting payment is cancelled/); assert.match(also, /waiting raise of the daily limit is cancelled/);
});
