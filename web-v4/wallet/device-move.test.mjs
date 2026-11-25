// "Move my account to another device" (device-move.mjs), on both devices.
//
// What runs as it is: device-move.mjs, security-flows.mjs, vault.mjs, device-lock.mjs, the SDK and its account security
// library, WebCrypto of Node. What stands in: the chain (tests/mock-security-chain.mjs, the reading of v5/src/security.rs
// that the wallet's other tests use, with each action's signature and network checked here, and kind 71 added here), the
// verifier (a state is read straight from that chain), the storage (in memory; it can fail on a chosen write, as a page
// that closes), and Argon2id (SHA-256 of the password and the salt; the real one in one test).
//
// That the engine takes these bytes, and not only the stand-in: the first test builds the replacement from the keys of
// client-v4/device-move.fixture.json, which v5/tests/security.rs wrote from the action the engine accepted, and the bytes
// must be the same; that test checks on every run that it builds and the engine takes bytes of the digest held here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash, webcrypto } from 'node:crypto';
import '../../client-v4/time-sdk.js';
import * as security from '../../client-v4/account-security.mjs';
import * as F from './security-flows.mjs';
import * as M from './device-move.mjs';
import { openVault, sealVault, makePassword, b64, vaultDevice } from './vault.mjs';
import { credentialInUse } from './device-lock.mjs';
import { createSecurityChain } from './tests/mock-security-chain.mjs';

const SDK = globalThis.TimeSDK;
const quick = async ({ password, salt }) => new Uint8Array(createHash('sha256').update(Buffer.from(password)).update(Buffer.from(salt)).digest());
// The passwords chosen with the device, where a test locks keys to it (the rule: vault.mjs, RULE). Without the device the
// wallet makes the passwords (sealedKeys gives them as `made`), and the tests read them from there.
const NEW_LOGIN = 'copper kites drift over salt marsh 58', NEW_PAYMENT = 'seven lanterns guard the northern pier 23';
/// The password each key the tests made opens with: the one the wallet made for it, or the one chosen with the device.
const madeTexts = new Map();
const passwordOf = record => madeTexts.get(record.binding.publicKey) ?? (record.intent === 'spend' ? NEW_PAYMENT : NEW_LOGIN);
const NET = 'd7'.repeat(32), MICROS = 1000000n, MINUTE = 60n * MICROS, HOUR = 60n * MINUTE, GENESIS = 17n * 10n ** 14n, FEE = 1000n, NAME = 'alice';
/// Web Locks as navigator.locks gives them, for one page or several: one queue per name; `held` lists what is held now.
function queueLocks() {
  const tails = new Map(), held = [];
  return { held, request(name, options, work) {
    const run = (tails.get(name) ?? Promise.resolve()).then(async () => { held.push(name); try { return await work(); } finally { held.splice(held.indexOf(name), 1); } });
    tails.set(name, run.catch(() => {}));
    return run;
  } };
}
const LOCKS = queueLocks();
const dm = M.createDeviceMove({ security, locks: LOCKS });
const flows = F.createSecurityFlows({ security });
const W = M.MOVE_WORDS;
const text = message => new RegExp(message.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));

class Storage {
  m = new Map(); failAt = null; writes = 0;
  get length() { return this.m.size; }
  key(i) { return [...this.m.keys()][i] ?? null; }
  getItem(k) { return this.m.has(k) ? this.m.get(k) : null; }
  setItem(k, v) { this.writes += 1; if (this.failAt !== null && this.writes === this.failAt) throw new Error('the page closed'); this.m.set(k, String(v)); }
  removeItem(k) { this.m.delete(k); }
  copy() { const c = new Storage(); for (const [k, v] of this.m) c.m.set(k, v); return c; }
  keys() { return [...this.m.keys()]; }
}
const verifies = async (publicKey, signature, message) => webcrypto.subtle.verify('Ed25519', await webcrypto.subtle.importKey('raw', SDK.hexToBytes(publicKey, 32), 'Ed25519', false, ['verify']), SDK.hexToBytes(signature, 64), message);
const byKey = (a, b) => (a.public_key < b.public_key ? -1 : 1);
const device = (publicKey, role) => ({ public_key: publicKey, can_manage: role === 'recover', can_spend: role === 'spend' });
const importSeed = seed => webcrypto.subtle.importKey('pkcs8', SDK.hexToBytes('302e020100300506032b657004220420' + seed), { name: 'Ed25519' }, false, ['sign']);
async function stranger() { const k = await F.keyFromSeed(F.newSheetSeed()); return k; }

// ------------------------------------------------------------------ a stand-in chain
function standInChain() {
  const chain = { now: 240n * HOUR, height: 100, accounts: [], rows: {}, posted: [], refused: [] };
  const rules = createSecurityChain({ sdk: SDK, security, networkId: NET, accounts: chain.accounts, rows: chain.rows, fee: FEE });
  /// Kind 71 (v5/src/security.rs, SIGNIN), which the shared stand-in leaves out: the spend key adds and removes login keys at
  /// once, and the authority epoch moves on; the security version does not.
  async function signin(action) {
    const account = chain.accounts.find(a => a.id === action.from), row = chain.rows[account.id];
    const signer = account.devices.find(d => d.public_key === action.publicKey);
    if (!signer || security.roleOf(signer) !== 'spend') throw new Error('a spend key is required');
    if (BigInt(action.nonce) !== BigInt(account.nonce) + 1n || action.authEpoch !== account.auth_epoch) throw new Error('stale authority or incorrect nonce');
    if (security.frozen(row, chain.now)) throw new Error('account is frozen');
    const devices = account.devices.filter(d => !(action.payload.remove.includes(d.public_key) && security.roleOf(d) === 'signin'));
    for (const add of action.payload.add) {
      if (!await verifies(add.public_key, add.proof, security.keyMessage({ networkId: NET, accountId: account.id, role: 'signin', publicKey: add.public_key }))) throw new Error('signature does not verify');
      devices.push(device(add.public_key, 'signin'));
    }
    account.devices = devices.sort(byKey); account.nonce = action.nonce; account.auth_epoch = String(BigInt(account.auth_epoch) + 1n); account.balance = String(BigInt(account.balance) - FEE);
  }
  /// What a node does with signed bytes: null when a block took them, otherwise the refusal.
  chain.submit = async tx => {
    const action = SDK.decodeAction(tx); chain.posted.push(action);
    let refusal = null;
    if (action.networkId !== NET) refusal = 'wrong network';
    else if (!await verifies(action.publicKey, SDK.bytesToHex(tx.slice(-64)), tx.slice(0, -64))) refusal = 'invalid action signature';
    else { try { if (action.kind === 71) await signin(action); else await rules.apply(action, chain.now); } catch (error) { refusal = error.message; } }
    if (refusal) { chain.refused.push(refusal); return refusal; }
    chain.height += 1; chain.now += MICROS;
    return null;
  };
  /// A verified state, as the light client gives one: the accounts and their security rows, at the chain's time.
  chain.state = () => structuredClone({ network_id: NET, height: String(chain.height), time_micros: (GENESIS + chain.now).toString(), genesis: { genesis_time_micros: GENESIS.toString() }, accounts: chain.accounts, security: Object.values(chain.rows) });
  return chain;
}

/// A protected account @alice on the stand-in chain; its old device holds its login key and payment key; a new device
/// holds nothing yet. Recovery keys: a sheet and a second key, as words-only or a kit would give.
async function world({ newStore = new Storage() } = {}) {
  const chain = standInChain(), oldStore = new Storage(), live = F.vaultSlots(NET, NAME);
  const [signin, spend] = await F.sealedKeys({ wanted: [{ intent: 'signin' }, { intent: 'spend' }], networkId: NET, name: NAME, argon2id: quick, cryptoImpl: webcrypto });
  for (const one of [signin, spend]) madeTexts.set(one.key.publicKey, one.made);
  oldStore.setItem(live.login, JSON.stringify(signin.record)); oldStore.setItem(live.spend, JSON.stringify(spend.record));
  const sheet = await F.keyFromSeed(F.newSheetSeed()), phrase = await F.keyFromSeed(F.newSheetSeed());
  chain.accounts.push({ id: '5', name: NAME, public_key: 'ab'.repeat(32), balance: '10000000', nonce: '3', auth_epoch: '1', recovery_policy: null,
    devices: [device(signin.key.publicKey, 'signin'), device(spend.key.publicKey, 'spend'), device(sheet.publicKey, 'recover'), device(phrase.publicKey, 'recover')].sort(byKey) });
  chain.accounts.push({ id: '6', name: 'bob', public_key: 'cd'.repeat(32), balance: '0', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [device('cd'.repeat(32), 'full')] });
  chain.rows['5'] = { account: '5', version: '1', policy: { threshold: '2', daily_limit_micros: '500000', delay_seconds: '60', freeze_seconds: '120' }, allowance_micros: '500000', allowance_elapsed_micros: chain.now.toString(),
    frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null };
  return { chain, oldStore, newStore, live, oldKeys: { signin: signin.key.publicKey, spend: spend.key.publicKey }, sheet, phrase };
}
const alice = state => state.accounts.find(a => a.name === NAME);
const rowOf = state => security.securityOf(state, '5');
/// The new device's sealing, by the rule: with the device and chosen passwords when `lock` is given, else under passwords
/// the wallet makes (kept in madeTexts for the tests to open them).
const sealNew = (extra = {}) => async wanted => {
  const made = await F.sealedKeys({ wanted: extra.lock ? wanted.map(w => ({ ...w, password: w.intent === 'spend' ? NEW_PAYMENT : NEW_LOGIN })) : wanted.map(w => ({ intent: w.intent })), networkId: NET, name: NAME, argon2id: quick, cryptoImpl: webcrypto, ...extra });
  for (const one of made) if (one.made) madeTexts.set(one.key.publicKey, one.made);
  return made;
};
const openNew = (secretFor = () => null, argon2id = quick) => record => openVault(record, passwordOf(record), argon2id, webcrypto, record.intent, secretFor(record));
const prepare = (w, extra = {}) => dm.prepareMove({ storage: w.newStore, networkId: NET, state: w.chain.state(), name: NAME, waitsNow: w.chain.now, lasting: { lasting: true, asked: false }, seal: sealNew(), open: openNew(), ...extra });
const resume = (w, extra = {}) => dm.resumeMove({ storage: w.newStore, networkId: NET, name: NAME, state: w.chain.state(), ...extra });
const withdraw = (w, extra = {}) => dm.withdrawMove({ storage: w.newStore, networkId: NET, name: NAME, state: w.chain.state(), ...extra });
const oldStatus = (w, extra = {}) => dm.oldDeviceStatus({ storage: w.oldStore, networkId: NET, name: NAME, state: w.chain.state(), ...extra });
/// The old device's payment key, opened with its password.
async function oldSpend(w) {
  const record = F.spendRecord(w.oldStore, w.live), opened = await openVault(record, passwordOf(record), quick, webcrypto, 'spend');
  return { publicKey: record.binding.publicKey, privateKey: opened.privateKey };
}
/// What the old device does with a request text: review on a state read now, then the code, then signing on another
/// state read just before.
async function oldDevice(w, requestText, { code, recovery = w.sheet, spend } = {}) {
  let state = w.chain.state();
  const review = await dm.reviewMove({ text: requestText, networkId: NET, account: alice(state), security: rowOf(state), now: F.elapsedOf(state), waitsNow: F.elapsedOf(state), feeMicros: FEE });
  state = w.chain.state();
  const built = await dm.buildMove({ networkId: NET, request: review.request, typedCode: code, account: alice(state), security: rowOf(state), spend: spend ?? await oldSpend(w), recovery, now: F.elapsedOf(state), waitsNow: F.elapsedOf(state), feeMicros: FEE });
  return { review, built };
}
/// A whole move: the new device's request, the old device's replacement, its note, and the chain.
async function move(w) {
  const made = await prepare(w);
  const { review, built } = await oldDevice(w, made.text, { code: made.code });
  await dm.rememberMove({ storage: w.oldStore, networkId: NET, name: NAME, request: review.request, built });
  const refusal = await w.chain.submit(built.tx);
  return { made, review, built, refusal };
}
const transfer = async (state, key, amount = '1000') => { const a = alice(state); return SDK.signAction({ networkId: NET, kind: 'transfer', from: a.id, nonce: String(BigInt(a.nonce) + 1n), authEpoch: a.auth_epoch, publicKey: key.publicKey, payload: { to: '6', amount } }, key.privateKey); };
const vaultKeys = storage => storage.keys().filter(k => /^timecurrency\.(vault\.v1|spend-vault\.v1|vault-next\.v1|login-request\.v1|vault-lock\.v1):/.test(k));
/// For each payment and login key the account has now: which of `stores` keeps a sound record of it.
function holders(state, stores) {
  const out = {};
  for (const d of alice(state).devices) {
    const role = security.roleOf(d); if (role === 'recover') continue;
    out[role] = [...(out[role] ?? []), Object.entries(stores).filter(([, s]) => s.keys().some(k => { try { return JSON.parse(s.getItem(k))?.binding?.publicKey === d.public_key; } catch { return false; } })).map(([n]) => n)];
  }
  return out;
}
/// A request made and signed by keys of somebody else's: everything checks, except what the person read on their screen.
async function forged(request, { signin, spend } = {}) {
  const fields = { ...request, signin: { publicKey: (signin ?? request.signin).publicKey }, spend: { publicKey: (spend ?? request.spend).publicKey } };
  const message = M.moveRequestMessage(fields), part = async (key, role, kept) => {
    if (!key) return kept;
    return { publicKey: key.publicKey, proof: (await security.acceptRole({ networkId: request.networkId, accountId: request.accountId, role, ...key })).proof, requestProof: SDK.bytesToHex(new Uint8Array(await webcrypto.subtle.sign('Ed25519', key.privateKey, message))) };
  };
  return { ...fields, signin: await part(signin, 'signin', request.signin), spend: await part(spend, 'spend', request.spend) };
}

// ------------------------------------------------------------------ the real engine
test('the engine took these bytes: the replacement built from the keys of client-v4/device-move.fixture.json is the action v5/tests/security.rs accepted', async () => {
  const fx = JSON.parse(await readFile(new URL('../../client-v4/device-move.fixture.json', import.meta.url), 'utf8'));
  // The digest the engine's test checks on every run (MOVE_ACTION_SHA256 in v5/tests/security.rs): the file holds the bytes it took.
  assert.equal(createHash('sha256').update(Buffer.from(fx.action_hex, 'hex')).digest('hex'), '8949e25cebdc960f92ef2f9150229b929580c031e57b40c7d43338827c8df23e');
  const keys = {};
  for (const s of fx.seeds) { keys[s.name] = { publicKey: s.public_key, privateKey: await importSeed(s.seed_hex) }; assert.equal((await F.keyFromSeed(SDK.hexToBytes(s.seed_hex, 32))).publicKey, s.public_key); }
  const roleOfName = n => (n === 'signin' ? 'signin' : n === 'spend' ? 'spend' : 'recover');
  const account = { id: fx.account.id, name: NAME, balance: fx.account.balance, nonce: fx.account.nonce, auth_epoch: fx.account.auth_epoch, recovery_policy: null, devices: ['signin', 'spend', 'sheet', 'phrase', 'friend'].map(n => device(keys[n].publicKey, roleOfName(n))).sort(byKey) };
  const row = { account: fx.account.id, version: fx.version, policy: fx.policy, allowance_micros: fx.policy.daily_limit_micros, allowance_elapsed_micros: '0', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null };
  const now = BigInt(fx.chain_elapsed_micros);
  // The other device's request for the two moved keys, its text, its code; the old device's review and replacement.
  const request = await dm.moveRequest({ networkId: fx.network_id, account, signin: keys.moved_signin, spend: keys.moved_spend, now });
  const requestText = M.moveRequestText(request), code = await M.moveCode(request);
  const review = await dm.reviewMove({ text: requestText, networkId: fx.network_id, account, security: row, now, waitsNow: now, feeMicros: '1000' });
  const built = await dm.buildMove({ networkId: fx.network_id, request: review.request, typedCode: code, account, security: row, spend: keys.spend, recovery: keys.sheet, now, waitsNow: now, feeMicros: '1000' });
  assert.equal(SDK.bytesToHex(built.tx), fx.action_hex);
  assert.deepEqual(built.payload.op, fx.operation);
  assert.deepEqual([built.kind, built.nonce, built.authEpoch, built.version, built.payload.expires_elapsed_micros], [73, '0', '0', fx.version, fx.expires_elapsed_micros]);
  // With the account as the engine left it, the old device may forget its keys; before, it may not.
  const oldStore = new Storage(), live = F.vaultSlots(fx.network_id, NAME), pkcs8 = seed => b64(SDK.hexToBytes('302e020100300506032b657004220420' + seed));
  const seedOf = n => fx.seeds.find(s => s.name === n).seed_hex;
  oldStore.setItem(live.login, JSON.stringify(await sealVault({ pkcs8: pkcs8(seedOf('signin')) }, makePassword(), { networkId: fx.network_id, name: NAME, publicKey: keys.signin.publicKey }, quick, webcrypto, 'signin')));
  oldStore.setItem(live.spend, JSON.stringify(await sealVault({ pkcs8: pkcs8(seedOf('spend')) }, makePassword(), { networkId: fx.network_id, name: NAME, publicKey: keys.spend.publicKey }, quick, webcrypto, 'spend')));
  const stateWith = a => ({ network_id: fx.network_id, accounts: [a], security: [row] });
  await assert.rejects(dm.forgetOldDevice({ storage: oldStore, networkId: fx.network_id, name: NAME, state: stateWith(account), request }), text(W.notMovedYet));
  assert.equal(oldStore.m.size, 2);
  const after = { ...account, nonce: fx.after.nonce, auth_epoch: fx.after.auth_epoch, devices: fx.after.devices };
  assert.equal(dm.shapeOf(after, request), 'exact');
  assert.deepEqual((await dm.forgetOldDevice({ storage: oldStore, networkId: fx.network_id, name: NAME, state: stateWith(after), request })).sort(), [live.login, live.spend].sort());
  assert.equal(oldStore.m.size, 0);
  // The request is now worth nothing: the epoch moved on and its keys are the account's.
  await assert.rejects(dm.reviewMove({ text: requestText, networkId: fx.network_id, account: after, security: { ...row, version: fx.after.version }, now, waitsNow: now, feeMicros: '1000' }), text(W.epoch));
});

// ------------------------------------------------------------------ the whole move
test('a move from start to end: the new device keeps its keys before it shows anything, the old one signs once, the chain moves the authority, each side settles', async () => {
  const w = await world();
  const made = await prepare(w), slots = M.moveSlots(NET, NAME);
  // The text form: one line, its fields in their order, public data only.
  assert.ok(!made.text.includes('\n'));
  assert.deepEqual(Object.keys(JSON.parse(made.text)), ['type', 'version', 'networkId', 'accountId', 'name', 'authEpoch', 'expires', 'signin', 'spend']);
  assert.deepEqual(Object.keys(JSON.parse(made.text).signin), ['publicKey', 'proof', 'requestProof']);
  assert.equal(made.request.type, 'time-move-request'); assert.equal(made.request.expires, String(w.chain.now + HOUR));
  for (const secret of [...madeTexts.values(), 'pkcs8', 'ciphertext']) assert.ok(!made.text.includes(secret));
  assert.match(made.code, /^[0-9A-HJKMNP-TV-Z]{4}( [0-9A-HJKMNP-TV-Z]{4}){3}$/);
  // Each key accepted its role and signed the request.
  for (const role of ['signin', 'spend']) {
    assert.ok(await verifies(made.request[role].publicKey, made.request[role].proof, security.keyMessage({ networkId: NET, accountId: '5', role, publicKey: made.request[role].publicKey })));
    assert.ok(await verifies(made.request[role].publicKey, made.request[role].requestProof, M.moveRequestMessage(made.request)));
  }
  // What the new device keeps: the two sealed records and the note, nothing in the live places.
  // Its bound, written before the records: until when a move on this request can land.
  assert.deepEqual(w.newStore.keys().sort(), [slots.bound, slots.active.signin, slots.active.spend, slots.note].sort());
  assert.deepEqual(JSON.parse(w.newStore.getItem(slots.bound)), { version: 1, until: String(M.moveWindowEnd(made.request)) });
  assert.equal(JSON.parse(w.newStore.getItem(slots.active.spend)).binding.publicKey, made.request.spend.publicKey);
  // The old device: review, the code typed in lower case with dashes, the replacement.
  const typed = made.code.toLowerCase().replace(/ /g, '-');
  const { review, built } = await oldDevice(w, made.text, { code: typed });
  assert.deepEqual(review.shown, { account: NAME, removes: 2, keeps: 2, cancelsPayments: 0, cancelsLimit: false, expires: made.request.expires, feeMicros: '1000' });
  const op = built.payload.op;
  assert.deepEqual(op.keys.map(k => [k.public_key, k.role, Boolean(k.proof)]).sort(), [[made.request.signin.publicKey, 'signin', true], [made.request.spend.publicKey, 'spend', true], [w.sheet.publicKey, 'recover', false], [w.phrase.publicKey, 'recover', false]].sort());
  assert.deepEqual(op.policy, rowOf(w.chain.state()).policy);
  assert.deepEqual(built.payload.approvals.map(a => a.public_key).sort(), [w.oldKeys.spend, w.sheet.publicKey].sort());
  assert.equal(SDK.decodeAction(built.tx).publicKey, w.oldKeys.spend);
  assert.equal(BigInt(built.payload.expires_elapsed_micros), w.chain.now + F.APPROVAL_LIFETIME_MICROS);
  await dm.rememberMove({ storage: w.oldStore, networkId: NET, name: NAME, request: review.request, built });
  assert.deepEqual(await oldStatus(w), { stage: 'waiting' });
  // The chain: at once, every other payment and login key gone, the recovery keys kept, the epoch on.
  assert.equal(await w.chain.submit(built.tx), null);
  let state = w.chain.state();
  assert.deepEqual(alice(state).devices.map(d => [d.public_key, security.roleOf(d)]).sort(), [[made.request.signin.publicKey, 'signin'], [made.request.spend.publicKey, 'spend'], [w.sheet.publicKey, 'recover'], [w.phrase.publicKey, 'recover']].sort());
  assert.equal(alice(state).auth_epoch, '2');
  assert.equal(await w.chain.submit(await transfer(state, await oldSpend(w))), 'device is not authorized');
  // The new device puts its keys in place; they open with the new passwords and pay.
  assert.deepEqual(await resume(w), { stage: 'settled', settled: ['signin', 'spend'], others: 0, withdrawn: false });
  assert.deepEqual(w.newStore.keys().sort(), [w.live.login, w.live.spend].sort());
  const spendNow = await openVault(F.spendRecord(w.newStore, w.live), passwordOf(F.spendRecord(w.newStore, w.live)), quick, webcrypto, 'spend');
  const loginNow = JSON.parse(w.newStore.getItem(w.live.login));
  assert.equal((await openVault(loginNow, passwordOf(loginNow), quick, webcrypto, 'signin')).binding.publicKey, made.request.signin.publicKey);
  assert.equal(await w.chain.submit(await transfer(w.chain.state(), { publicKey: made.request.spend.publicKey, privateKey: spendNow.privateKey })), null);
  // The old device forgets its keys of the account: nothing of them is left.
  const forgotten = await oldStatus(w);
  assert.equal(forgotten.stage, 'forgotten');
  assert.deepEqual(forgotten.removed.sort(), [w.live.login, w.live.spend, slots.sent].sort());
  assert.deepEqual(vaultKeys(w.oldStore), []);
  assert.deepEqual(await oldStatus(w), { stage: 'none' });
});

test('the real Argon2id: the new device seals, opens again and keeps its keys with the wallet\'s own derivation', async () => {
  const source = await readFile(new URL('./vendor/argon2-4.12.0.umd.min.js', import.meta.url), 'utf8'), umd = { exports: {} };
  new Function('module', 'exports', source)(umd, umd.exports);
  const argon2id = umd.exports.argon2id, w = await world();
  const made = await prepare(w, { seal: sealNew({ argon2id }), open: openNew(() => null, argon2id) });
  const record = JSON.parse(w.newStore.getItem(M.moveSlots(NET, NAME).active.spend));
  assert.equal((await openVault(record, passwordOf(record), argon2id, webcrypto, 'spend')).binding.publicKey, made.request.spend.publicKey);
  await assert.rejects(openVault(record, passwordOf(record), quick, webcrypto, 'spend'), /Could not unlock/);
});

// ------------------------------------------------------------------ refused: what the request says
test('refused: a request whose payment key or login key was swapped, by its signatures or, when the swapped request is whole, by the code', async () => {
  const w = await world(), made = await prepare(w), state = w.chain.state(), base = { networkId: NET, account: alice(state), security: rowOf(state), now: F.elapsedOf(state), waitsNow: F.elapsedOf(state), feeMicros: FEE };
  const thief = { signin: await stranger(), spend: await stranger() };
  // One key swapped, the rest left: the other key's signature names the genuine pair.
  for (const swap of [{ spend: thief.spend }, { signin: thief.signin }]) await assert.rejects(dm.reviewMove({ ...base, text: JSON.stringify(await forged(made.request, swap)) }), text(W.signatures));
  // A key swapped and nothing re-signed.
  const bare = JSON.parse(made.text); bare.spend.publicKey = thief.spend.publicKey;
  await assert.rejects(dm.reviewMove({ ...base, text: JSON.stringify(bare) }), text(W.signatures));
  // A proof taken from the other key, or an acceptance for the other role.
  const crossed = JSON.parse(made.text); [crossed.signin.proof, crossed.spend.proof] = [crossed.spend.proof, crossed.signin.proof];
  await assert.rejects(dm.reviewMove({ ...base, text: JSON.stringify(crossed) }), text(W.signatures));
  // Both swapped, every signature the thief's own and valid: only the code the person reads on their own new device stops it.
  for (const swap of [{ spend: thief.spend, signin: thief.signin }]) {
    const whole = JSON.stringify(await forged(made.request, swap)), review = await dm.reviewMove({ ...base, text: whole });
    await assert.rejects(dm.checkCode(review.request, made.code), text(W.codeWrong));
    let touched = false; const spend = await oldSpend(w), guarded = { publicKey: spend.publicKey, get privateKey() { touched = true; return spend.privateKey; } };
    await assert.rejects(dm.buildMove({ ...base, request: review.request, typedCode: made.code, spend: guarded, recovery: w.sheet }), text(W.codeWrong));
    assert.equal(touched, false, 'the payment key was not used');
  }
  assert.equal(w.chain.posted.length, 0);
});

test('refused: a request for another account, for another network, made before the keys last changed, expired, or dated too far ahead', async () => {
  const w = await world(), made = await prepare(w);
  let state = w.chain.state();
  const base = { text: made.text, networkId: NET, account: alice(state), security: rowOf(state), now: F.elapsedOf(state), waitsNow: F.elapsedOf(state), feeMicros: FEE };
  // Another account: shown to @bob's wallet; or its name or number changed.
  await assert.rejects(dm.reviewMove({ ...base, account: state.accounts.find(a => a.name === 'bob') }), text(W.otherAccount));
  for (const change of [{ name: 'carol' }, { accountId: '6' }]) await assert.rejects(dm.reviewMove({ ...base, text: JSON.stringify({ ...JSON.parse(made.text), ...change }) }), text(W.otherAccount));
  // Another network: read on a wallet of another network, or the field changed.
  await assert.rejects(dm.reviewMove({ ...base, text: made.text, networkId: 'e8'.repeat(32) }), text(W.otherNetwork));
  await assert.rejects(dm.reviewMove({ ...base, text: JSON.stringify({ ...JSON.parse(made.text), networkId: 'e8'.repeat(32) }) }), text(W.otherNetwork));
  // Expired, and too far ahead (the old device's view of the chain lags by more than five minutes).
  const expires = BigInt(made.request.expires);
  await assert.rejects(dm.reviewMove({ ...base, text: made.text, now: expires }), text(W.expired));
  assert.ok(await dm.reviewMove({ ...base, text: made.text, now: expires - 1n }));
  await assert.rejects(dm.reviewMove({ ...base, text: made.text, now: expires - HOUR - 5n * MINUTE - 1n }), text(W.ahead));
  // A field changed within its form is caught by the signatures, out of its form by the form.
  await assert.rejects(dm.reviewMove({ ...base, text: JSON.stringify({ ...JSON.parse(made.text), expires: String(expires - 1n) }) }), text(W.signatures));
  for (const broken of [{ version: 2 }, { type: 'signin-key' }, { extra: 1 }, { expires: 12 }, { expires: '012' }, { name: 'Alice' }]) await assert.rejects(dm.reviewMove({ ...base, text: JSON.stringify({ ...JSON.parse(made.text), ...broken }) }), /not a move request|damaged/);
  for (const broken of ['', 'x', '[]', made.text.replace('"proof"', '"Proof"'), made.text.toUpperCase(), made.text + ' '.repeat(4096)]) await assert.rejects(dm.reviewMove({ ...base, text: broken }), /Paste the move request|not a move request|damaged/);
  // Made before the keys last changed: a login key replaced by the payment key (kind 71) moves the epoch on.
  const fresh = await F.keyFromSeed(F.newSheetSeed());
  const change = await flows.buildReplaceSignin({ networkId: NET, account: alice(state), spend: await oldSpend(w), signin: fresh });
  assert.equal(await w.chain.submit(change.tx), null);
  state = w.chain.state();
  await assert.rejects(dm.reviewMove({ ...base, account: alice(state), security: rowOf(state), now: F.elapsedOf(state) }), text(W.epoch));
  await assert.rejects(dm.buildMove({ ...base, account: alice(state), security: rowOf(state), now: F.elapsedOf(state), request: made.request, typedCode: made.code, spend: await oldSpend(w), recovery: w.sheet }), text(W.epoch));
  // The new device no longer shows it, and keeps its keys until it can no longer land.
  assert.equal((await resume(w)).stage, 'stale');
});

test('refused: one key in both roles, or a key the account has already', async () => {
  const w = await world(), state = w.chain.state(), account = alice(state), base = { networkId: NET, account, security: rowOf(state), now: F.elapsedOf(state), waitsNow: F.elapsedOf(state), feeMicros: FEE };
  const one = await stranger(), other = await stranger();
  await assert.rejects(dm.moveRequest({ networkId: NET, account, signin: one, spend: one, now: base.now }), text(W.sameKey));
  // Made by hand, both roles accepted and signed by the one key.
  const twice = await forged(await dm.moveRequest({ networkId: NET, account, signin: one, spend: other, now: base.now }), { spend: one, signin: one });
  await assert.rejects(dm.reviewMove({ ...base, text: JSON.stringify(twice) }), text(W.sameKey));
  // A key of the account: the old device's own login key, or a recovery key, accepted for the role in the request.
  const signinRecord = JSON.parse(w.oldStore.getItem(w.live.login)), opened = await openVault(signinRecord, passwordOf(signinRecord), quick, webcrypto, 'signin');
  const own = await dm.moveRequest({ networkId: NET, account, signin: { publicKey: signinRecord.binding.publicKey, privateKey: opened.privateKey }, spend: other, now: base.now });
  await assert.rejects(dm.reviewMove({ ...base, text: M.moveRequestText(own) }), text(W.onAccount));
  const recovery = await dm.moveRequest({ networkId: NET, account, signin: one, spend: w.sheet, now: base.now });
  await assert.rejects(dm.reviewMove({ ...base, text: M.moveRequestText(recovery) }), text(W.onAccount));
  // buildMove checks them again on the state it signs on.
  await assert.rejects(dm.buildMove({ ...base, request: twice, typedCode: await M.moveCode(twice), spend: await oldSpend(w), recovery: w.sheet }), text(W.sameKey));
  await assert.rejects(dm.buildMove({ ...base, request: own, typedCode: await M.moveCode(own), spend: await oldSpend(w), recovery: w.sheet }), text(W.onAccount));
});

test('refused: a code typed wrong signs nothing, and the code cannot be read from anything the old device shows', async () => {
  const w = await world(), made = await prepare(w), state = w.chain.state(), base = { networkId: NET, account: alice(state), security: rowOf(state), now: F.elapsedOf(state), waitsNow: F.elapsedOf(state), feeMicros: FEE };
  const review = await dm.reviewMove({ ...base, text: made.text });
  const chars = made.code.replace(/ /g, ''), wrongOne = chars.slice(0, 15) + (chars[15] === '0' ? '1' : '0');
  let touched = false; const spend = await oldSpend(w), guarded = { publicKey: spend.publicKey, get privateKey() { touched = true; return spend.privateKey; } };
  for (const typed of [wrongOne, chars.slice(1) + chars[0], '0000 0000 0000 0000']) {
    await assert.rejects(dm.checkCode(review.request, typed), text(W.codeWrong));
    await assert.rejects(dm.buildMove({ ...base, request: review.request, typedCode: typed, spend: guarded, recovery: w.sheet }), text(W.codeWrong));
  }
  for (const typed of [chars.slice(1), chars + '0', chars.slice(0, 15) + 'U', '', undefined, 'x'.repeat(65)]) await assert.rejects(dm.buildMove({ ...base, request: review.request, typedCode: typed, spend: guarded, recovery: w.sheet }), text(W.codeForm));
  assert.equal(touched, false); assert.equal(w.chain.posted.length, 0);
  // Read forgivingly, as a recovery sheet is: case, spaces, dashes, O for 0, I and L for 1.
  assert.equal(await dm.checkCode(review.request, ` ${chars.toLowerCase().replace(/0/g, 'o').replace(/1/g, 'l')} `), true);
  // What the old device has to show: no code, none of its groups, no key and no signature to work it out from.
  const groups = made.code.split(' '), shownText = JSON.stringify(review.shown).toUpperCase();
  assert.deepEqual(Object.keys(review).sort(), ['request', 'shown']);
  for (const group of groups) assert.ok(!shownText.includes(group), `the review shows ${group}`);
  for (const value of [made.request.signin.publicKey, made.request.spend.publicKey, made.request.signin.proof]) assert.ok(!JSON.stringify(review.shown).includes(value));
  assert.ok(!JSON.stringify(review).toUpperCase().includes(chars));
  const built = await dm.buildMove({ ...base, request: review.request, typedCode: made.code, spend, recovery: w.sheet });
  assert.ok(!JSON.stringify({ ...built, tx: SDK.bytesToHex(built.tx) }).toUpperCase().includes(chars));
  // The sentence the page says against a code that somebody sent.
  assert.match(W.onlyYours, /own new device/); assert.match(W.onlyYours, /sent you/);
});

test('refused: the payment password without a recovery key (one proof only), or two recovery keys without the payment key', async () => {
  const w = await world(), made = await prepare(w), state = w.chain.state(), base = { networkId: NET, account: alice(state), security: rowOf(state), now: F.elapsedOf(state), waitsNow: F.elapsedOf(state), feeMicros: FEE };
  const request = (await dm.reviewMove({ ...base, text: made.text })).request, spend = await oldSpend(w), other = await stranger();
  const build = extra => dm.buildMove({ ...base, request, typedCode: made.code, spend, recovery: w.sheet, ...extra });
  await assert.rejects(build({ recovery: undefined }), /one of your recovery keys as well/);
  await assert.rejects(build({ recovery: spend }), /does not belong to @alice/);
  await assert.rejects(build({ recovery: other }), /does not belong to @alice/);
  await assert.rejects(build({ spend: w.phrase }), /payment key of this browser/);
  await assert.rejects(build({ spend: undefined }), /payment key of this browser/);
  assert.equal(w.chain.posted.length, 0);
  // Under all of it, the wallet signs no root operation on the payment key alone (security-flows.mjs, buildRoot).
  await assert.rejects(flows.buildRoot({ networkId: NET, account: base.account, security: base.security, operation: security.operations.cancel(), approvers: [spend], expiresElapsedMicros: base.now + MINUTE }), /needs 2 proofs/);
  // With both, it is built and the chain takes it.
  assert.equal(await w.chain.submit((await build({})).tx), null);
});

test('refused: a frozen account, and an account where a replacement of the keys waits; the new device says so before it makes anything', async () => {
  // Frozen by a recovery key.
  let w = await world();
  const made = await prepare(w);
  assert.equal(await w.chain.submit((await flows.buildFreeze({ networkId: NET, account: alice(w.chain.state()), security: rowOf(w.chain.state()), signer: w.phrase, now: w.chain.now })).tx), null);
  let state = w.chain.state(), base = { networkId: NET, account: alice(state), security: rowOf(state), now: F.elapsedOf(state), waitsNow: F.elapsedOf(state), feeMicros: FEE };
  await assert.rejects(dm.reviewMove({ ...base, text: made.text }), text(W.frozen));
  await assert.rejects(dm.buildMove({ ...base, request: made.request, typedCode: made.code, spend: await oldSpend(w), recovery: w.sheet }), text(W.frozen));
  await assert.rejects(prepare({ ...w, newStore: new Storage() }), text(W.frozen));
  // A replacement asked for by the two recovery keys, waiting.
  w = await world();
  const made2 = await prepare(w), lost = await flows.buildLostDeviceRequest({ networkId: NET, account: alice(w.chain.state()), security: rowOf(w.chain.state()), sheet: w.sheet, phrase: w.phrase, signin: await stranger(), spend: await stranger(), now: w.chain.now });
  assert.equal(await w.chain.submit(lost.tx), null);
  state = w.chain.state(); base = { networkId: NET, account: alice(state), security: rowOf(state), now: F.elapsedOf(state), waitsNow: F.elapsedOf(state), feeMicros: FEE };
  assert.ok(rowOf(state).pending_root);
  await assert.rejects(dm.reviewMove({ ...base, text: made2.text }), text(W.replacing));
  await assert.rejects(dm.buildMove({ ...base, request: made2.request, typedCode: made2.code, spend: await oldSpend(w), recovery: w.sheet }), text(W.replacing));
  await assert.rejects(prepare({ ...w, newStore: new Storage() }), text(W.replacing));
  // Not enough for the fee; not protected.
  await assert.rejects(dm.reviewMove({ ...base, account: { ...base.account, balance: '999' }, security: { ...base.security, pending_root: null }, text: made2.text }), text(W.fee));
  await assert.rejects(dm.reviewMove({ ...base, security: null, text: made2.text }), text(W.notProtected));
  assert.equal(w.chain.posted.filter(a => a.kind === 73).length, 1);
});

test('refused: a request replayed after the move, on any device, and the replacement sent to the chain again', async () => {
  const w = await world(), { made, built, refusal } = await move(w);
  assert.equal(refusal, null);
  const state = w.chain.state(), base = { networkId: NET, account: alice(state), security: rowOf(state), now: F.elapsedOf(state), waitsNow: F.elapsedOf(state), feeMicros: FEE };
  await assert.rejects(dm.reviewMove({ ...base, text: made.text }), text(W.epoch));
  // Even with the epoch it named, its keys are the account's now.
  await assert.rejects(dm.reviewMove({ ...base, account: { ...base.account, auth_epoch: made.request.authEpoch }, text: made.text }), text(W.onAccount));
  // The same bytes: their submitter left the account. Signed again by keys that stayed, for the version it named: gone.
  assert.equal(await w.chain.submit(built.tx), 'a spend or recovery key of this account is required');
  const again = await flows.buildRoot({ networkId: NET, account: alice(state), security: { ...rowOf(state), version: built.version }, operation: built.payload.op, approvers: [w.sheet, w.phrase], submitter: w.sheet, expiresElapsedMicros: w.chain.now + MINUTE });
  assert.match(await w.chain.submit(again.tx), /signature does not verify|key is already/);
  assert.deepEqual(alice(w.chain.state()).devices, alice(state).devices);
});

// ------------------------------------------------------------------ the new device: closed, reopened, withdrawn
test('the new device\'s storage closed and reopened at each step: nothing shown is lost, nothing unshown is kept', async () => {
  const w = await world(), slots = M.moveSlots(NET, NAME);
  // Closed on each write of the request's bound, records and note: nothing is kept, so nothing was shown.
  for (const at of [1, 2, 3, 4]) {
    w.newStore.failAt = w.newStore.writes + at;
    await assert.rejects(prepare(w), /the page closed/);
    w.newStore.failAt = null;
    assert.deepEqual(await resume(w), { stage: 'none' }); assert.deepEqual(w.newStore.keys(), []);
  }
  // Closed after the records and before the note, without the clean-up a page that closes does not run.
  const made = await prepare(w), half = w.newStore.copy(); half.removeItem(slots.note);
  assert.deepEqual(await dm.resumeMove({ storage: half, networkId: NET, name: NAME, state: w.chain.state() }), { stage: 'none' });
  assert.deepEqual(half.keys(), []);
  // Closed once the request was shown: a fresh page gives the same request and code again; without the network too.
  const page2 = M.createDeviceMove({ security, locks: queueLocks() });
  const again = await page2.resumeMove({ storage: w.newStore, networkId: NET, name: NAME, state: w.chain.state() });
  assert.deepEqual([again.stage, again.text, again.code], ['waiting', made.text, made.code]);
  const unread = await page2.resumeMove({ storage: w.newStore, networkId: NET, name: NAME, state: null });
  assert.deepEqual([unread.stage, unread.code], ['unread', made.code]);
  await assert.rejects(prepare(w), text(W.alreadyWaiting));
  // The old device signs and the chain takes it while the new device is closed; it settles on its next look, and a page
  // that closes half way through settling settles on the one after.
  const { built } = await oldDevice(w, made.text, { code: made.code });
  assert.equal(await w.chain.submit(built.tx), null);
  w.newStore.failAt = w.newStore.writes + 2;
  await assert.rejects(resume(w), /the page closed/);
  w.newStore.failAt = null;
  assert.equal((await page2.resumeMove({ storage: w.newStore, networkId: NET, name: NAME, state: w.chain.state() })).stage, 'settled');
  assert.equal(JSON.parse(w.newStore.getItem(w.live.spend)).binding.publicKey, made.request.spend.publicKey);
  assert.equal(JSON.parse(w.newStore.getItem(w.live.login)).binding.publicKey, made.request.signin.publicKey);
  assert.deepEqual(w.newStore.keys().sort(), [w.live.login, w.live.spend].sort());
});

test('the old device closed after signing: it forgets its keys once the chain shows the move, and keeps them when the move never lands', async () => {
  // Landed while closed.
  let w = await world();
  const { refusal } = await move(w);
  assert.equal(refusal, null);
  assert.equal((await oldStatus(w, { state: null })).stage, 'unread');
  assert.equal(vaultKeys(w.oldStore).length, 3);
  assert.equal((await oldStatus(w)).stage, 'forgotten');
  // Signed and noted, never sent: kept while it could land, then the note goes and the keys stay.
  w = await world();
  const made = await prepare(w), { review, built } = await oldDevice(w, made.text, { code: made.code });
  await dm.rememberMove({ storage: w.oldStore, networkId: NET, name: NAME, request: review.request, built });
  await assert.rejects(dm.rememberMove({ storage: w.oldStore, networkId: NET, name: NAME, request: review.request, built }), text(W.sentWaiting));
  assert.deepEqual(await oldStatus(w), { stage: 'waiting' });
  assert.deepEqual(await oldStatus(w, { now: BigInt(built.payload.expires_elapsed_micros) }), { stage: 'void' });
  assert.deepEqual(vaultKeys(w.oldStore).sort(), [w.live.login, w.live.spend].sort());
  // Void as well once the security version moved past the one it signed (here: a limit set at once by two proofs).
  const made2 = await prepare({ ...w, newStore: new Storage() }), signed = await oldDevice(w, made2.text, { code: made2.code });
  await dm.rememberMove({ storage: w.oldStore, networkId: NET, name: NAME, request: signed.review.request, built: signed.built });
  const state = w.chain.state(), limit = await flows.buildLimitNow({ networkId: NET, account: alice(state), security: rowOf(state), spend: await oldSpend(w), recovery: w.sheet, dailyLimitMicros: '400000', feeMicros: FEE, now: w.chain.now });
  assert.equal(await w.chain.submit(limit.tx), null);
  assert.deepEqual(await oldStatus(w), { stage: 'void' });
  assert.notEqual(await w.chain.submit(signed.built.tx), null, 'the move signed before cannot land after the version moved on');
  assert.deepEqual(vaultKeys(w.oldStore).sort(), [w.live.login, w.live.spend].sort());
});

test('the old device asked to forget before the chain shows the move: refused, and every record kept', async () => {
  const w = await world(), made = await prepare(w), { review, built } = await oldDevice(w, made.text, { code: made.code });
  const before = w.oldStore.copy();
  await assert.rejects(dm.forgetOldDevice({ storage: w.oldStore, networkId: NET, name: NAME, state: w.chain.state(), request: review.request }), text(W.notMovedYet));
  await assert.rejects(dm.forgetOldDevice({ storage: w.oldStore, networkId: NET, name: NAME, state: null, request: review.request }), text(W.notFound));
  await assert.rejects(dm.forgetOldDevice({ storage: w.oldStore, networkId: NET, name: NAME, state: { accounts: [] }, request: review.request }), text(W.notFound));
  assert.deepEqual([...w.oldStore.m], [...before.m]);
  // Sent, but the state read is from before its block: still refused.
  const earlier = w.chain.state();
  assert.equal(await w.chain.submit(built.tx), null);
  await assert.rejects(dm.forgetOldDevice({ storage: w.oldStore, networkId: NET, name: NAME, state: earlier, request: review.request }), text(W.notMovedYet));
  assert.deepEqual([...w.oldStore.m], [...before.m]);
  assert.equal((await dm.forgetOldDevice({ storage: w.oldStore, networkId: NET, name: NAME, state: w.chain.state(), request: review.request })).length, 2);
});

test('"cancel" on the new device after the move has landed: nothing is forgotten, the keys are put in place', async () => {
  const w = await world(), { made, refusal } = await move(w);
  assert.equal(refusal, null);
  const answer = await withdraw(w);
  assert.deepEqual(answer, { stage: 'settled', settled: ['signin', 'spend'], others: 0, withdrawn: false, refused: true });
  assert.equal(JSON.parse(w.newStore.getItem(w.live.spend)).binding.publicKey, made.request.spend.publicKey);
});

test('withdrawing on the new device: without the network nothing goes; a request that could still land is held, not shown, and settles if it lands; then it is forgotten', async () => {
  const w = await world(), slots = M.moveSlots(NET, NAME), made = await prepare(w);
  // The old device signed it already (the person withdraws on the new device meanwhile).
  const { built } = await oldDevice(w, made.text, { code: made.code });
  await assert.rejects(withdraw(w, { state: null }), text(W.unread));
  assert.equal(w.newStore.m.size, 4);
  const held = await withdraw(w);
  assert.deepEqual(held, { stage: 'withdrawn', until: M.moveWindowEnd(made.request) });
  assert.equal(held.until, BigInt(made.request.expires) + 10n * MINUTE);
  assert.deepEqual(w.newStore.keys().sort(), [slots.bound, slots.held.signin, slots.held.spend, slots.note].sort());
  assert.deepEqual(await resume(w), { stage: 'withdrawn', until: held.until });
  // A new request can be made at once; a second withdrawal waits for the first one's time.
  const second = await prepare(w);
  assert.notEqual(second.request.spend.publicKey, made.request.spend.publicKey);
  await assert.rejects(withdraw(w), error => /could still be used until [^0-9]*[0-9]/.test(error.message) && error.until === held.until);
  // The first one lands after all: its keys are put in place, and the second request's keys go (it can no longer land).
  assert.equal(await w.chain.submit(built.tx), null);
  const settled = await resume(w);
  assert.deepEqual(settled, { stage: 'settled', settled: ['signin', 'spend'], others: 0, withdrawn: true });
  assert.equal(JSON.parse(w.newStore.getItem(w.live.spend)).binding.publicKey, made.request.spend.publicKey);
  assert.deepEqual(w.newStore.keys().sort(), [w.live.login, w.live.spend].sort());

  // Another account's device: withdrawn while it could land, never used, forgotten once a state past its time shows it off the account.
  const v = await world(), first = await prepare(v);
  assert.equal((await withdraw(v)).stage, 'withdrawn');
  assert.equal((await resume(v, { now: M.moveWindowEnd(first.request) - 1n })).stage, 'withdrawn');
  assert.deepEqual(await resume(v, { now: M.moveWindowEnd(first.request) }), { stage: 'none' });
  assert.deepEqual(v.newStore.keys(), []);
  // Past its time already: forgotten at once.
  const late = await prepare(v);
  assert.deepEqual(await withdraw(v, { now: M.moveWindowEnd(late.request) }), { stage: 'forgotten' });
  assert.deepEqual(v.newStore.keys(), []);
  // Expired but still able to land: not shown, kept; past its time: forgotten without being asked.
  const third = await prepare(v);
  assert.deepEqual(await resume(v, { now: BigInt(third.request.expires) }), { stage: 'closing', until: M.moveWindowEnd(third.request) });
  assert.deepEqual(await resume(v, { now: M.moveWindowEnd(third.request) }), { stage: 'expired' });
  assert.deepEqual(v.newStore.keys(), []);
});

test('withdrawing, closed half way: one copy of the keys survives every interruption', async () => {
  const w = await world(), slots = M.moveSlots(NET, NAME), made = await prepare(w);
  const start = w.newStore.copy();
  // After the copy to the held place, before the note: the request is still the one shown.
  const a = start.copy(); a.setItem(slots.held.signin, start.getItem(slots.active.signin)); a.setItem(slots.held.spend, start.getItem(slots.active.spend));
  assert.equal((await dm.resumeMove({ storage: a, networkId: NET, name: NAME, state: w.chain.state() })).stage, 'waiting');
  assert.deepEqual(a.keys().sort(), [slots.bound, slots.active.signin, slots.active.spend, slots.note].sort());
  // After the note, before the active place is emptied: withdrawn, one copy kept.
  const b = a.copy(); b.setItem(slots.held.signin, start.getItem(slots.active.signin)); b.setItem(slots.held.spend, start.getItem(slots.active.spend));
  b.setItem(slots.note, JSON.stringify({ version: 1, active: null, held: made.request }));
  assert.equal((await dm.resumeMove({ storage: b, networkId: NET, name: NAME, state: w.chain.state() })).stage, 'withdrawn');
  assert.deepEqual(b.keys().sort(), [slots.bound, slots.held.signin, slots.held.spend, slots.note].sort());
  // A note that cannot be read: nothing is guessed and nothing the account does not hold is deleted before the bound.
  const c = start.copy(); c.setItem(slots.note, '{broken');
  assert.deepEqual(await dm.resumeMove({ storage: c, networkId: NET, name: NAME, state: null }), { stage: 'damaged' });
  assert.deepEqual(await dm.resumeMove({ storage: c, networkId: NET, name: NAME, state: w.chain.state() }), { stage: 'damaged', settled: [], until: M.moveWindowEnd(made.request) });
  assert.deepEqual(await dm.withdrawMove({ storage: c, networkId: NET, name: NAME, state: w.chain.state() }), { stage: 'damaged', settled: [], until: M.moveWindowEnd(made.request) });
  assert.equal(c.m.size, 4);
  assert.deepEqual(await dm.withdrawMove({ storage: c, networkId: NET, name: NAME, state: w.chain.state(), now: M.moveWindowEnd(made.request) }), { stage: 'forgotten', damaged: true, settled: [] });
  assert.deepEqual(c.keys(), []);
  // A record lost or damaged under a request that was shown: said, and forgotten only once the request cannot land.
  const d = start.copy(); d.setItem(slots.active.spend, '{}');
  assert.equal((await dm.resumeMove({ storage: d, networkId: NET, name: NAME, state: w.chain.state() })).stage, 'damaged');
  assert.equal((await dm.resumeMove({ storage: d, networkId: NET, name: NAME, state: w.chain.state(), now: M.moveWindowEnd(made.request) })).stage, 'expired');
  assert.deepEqual(d.keys(), []);
});

// ------------------------------------------------------------------ review of 24 November: keys nobody holds
test('review 1: the move landed and one kept record cannot be read here: the sound one is put in place, nothing is deleted, and it is said', async () => {
  const w = await world(), slots = M.moveSlots(NET, NAME), made = await prepare(w), { built } = await oldDevice(w, made.text, { code: made.code });
  assert.equal(await w.chain.submit(built.tx), null);
  // The login record in a format of a later wallet.
  const record = JSON.parse(w.newStore.getItem(slots.active.signin)), later = JSON.stringify({ ...record, version: 4 });
  w.newStore.setItem(slots.active.signin, later);
  for (let look = 0; look < 2; look++) {
    assert.deepEqual(await resume(w), { stage: 'damaged', landed: true, settled: ['spend'], unplaced: ['signin'], others: 0, withdrawn: false });
    assert.equal(F.spendRecord(w.newStore, w.live).binding.publicKey, made.request.spend.publicKey);
    assert.equal(w.newStore.getItem(slots.active.signin), later);
    assert.ok(w.newStore.getItem(slots.note));
  }
  assert.deepEqual(holders(w.chain.state(), { new: w.newStore }), { signin: [['new']], spend: [['new']] });
  // A wallet that reads the record puts it in place, and only then does the move go.
  w.newStore.setItem(slots.active.signin, JSON.stringify(record));
  assert.deepEqual(await resume(w), { stage: 'settled', settled: ['signin', 'spend'], others: 0, withdrawn: false });
  assert.deepEqual(w.newStore.keys().sort(), [w.live.login, w.live.spend].sort());
  // Withdrawn while a record is unreadable and the request could still land: kept; once it cannot land, forgotten.
  const v = await world(), second = await prepare(v), unreadable = '{"version":9}';
  v.newStore.setItem(slots.active.spend, unreadable);
  assert.deepEqual(await withdraw(v), { stage: 'damaged', until: M.moveWindowEnd(second.request) });
  assert.equal(v.newStore.getItem(slots.active.spend), unreadable); assert.ok(v.newStore.getItem(slots.active.signin));
  assert.deepEqual(await withdraw(v, { now: M.moveWindowEnd(second.request) }), { stage: 'forgotten' });
  assert.deepEqual(v.newStore.keys(), []);
});

test('review 2: a note this wallet cannot read, then "Withdraw": nothing the account does not hold is deleted before the bound kept beside it; the move lands and is put in place', async () => {
  for (const variant of ['extra field', 'version 2', 'request of a newer format', 'no bound kept', 'unreadable, no bound']) {
    const w = await world(), slots = M.moveSlots(NET, NAME), made = await prepare(w), until = M.moveWindowEnd(made.request);
    const { review, built } = await oldDevice(w, made.text, { code: made.code });
    await dm.rememberMove({ storage: w.oldStore, networkId: NET, name: NAME, request: review.request, built });
    const note = JSON.parse(w.newStore.getItem(slots.note));
    if (variant === 'extra field') note.createdAt = '1';
    if (variant === 'version 2') note.version = 2;
    if (variant === 'request of a newer format') note.active.version = 2;
    if (variant === 'no bound kept') { note.version = 2; w.newStore.removeItem(slots.bound); }
    w.newStore.setItem(slots.note, variant === 'unreadable, no bound' ? '{broken' : JSON.stringify(note));
    if (variant === 'unreadable, no bound') w.newStore.removeItem(slots.bound);
    // The bound: kept beside the records, or read leniently from the note; none at all, and nothing is ever deleted.
    const bound = variant === 'unreadable, no bound' ? null : until;
    assert.deepEqual(await withdraw(w), { stage: 'damaged', settled: [], until: bound }, variant);
    assert.deepEqual(await withdraw(w, { now: until - 1n }), { stage: 'damaged', settled: [], until: bound }, variant);
    assert.ok(w.newStore.getItem(slots.active.signin) && w.newStore.getItem(slots.active.spend), variant);
    await assert.rejects(prepare(w), text(W.alreadyWaiting));
    // The move signed before lands: the new device puts both keys in place; the old device forgets; the new one holds them.
    assert.equal(await w.chain.submit(built.tx), null, variant);
    assert.deepEqual(await resume(w), { stage: 'damaged', settled: ['signin', 'spend'], until: bound }, variant);
    assert.equal((await oldStatus(w)).stage, 'forgotten');
    assert.deepEqual(holders(w.chain.state(), { new: w.newStore, old: w.oldStore }), { signin: [['new']], spend: [['new']] }, variant);
    // Past the bound, what is left goes and the keys in place stay; without a bound, nothing goes, however late.
    const late = await resume(w, { now: until + HOUR });
    if (bound === null) assert.deepEqual(late, { stage: 'damaged', settled: ['signin', 'spend'], until: null }, variant);
    else { assert.deepEqual(late, { stage: 'forgotten', damaged: true, settled: ['signin', 'spend'] }, variant); assert.deepEqual(w.newStore.keys().sort(), [w.live.login, w.live.spend].sort(), variant); }
  }
});

test('review 3: two tabs of the new device make a request at once: the second is refused under the lock and writes nothing; the lock is not held while the person types', async () => {
  const w = await world(), slots = M.moveSlots(NET, NAME), tabLocks = queueLocks(), tabs = M.createDeviceMove({ security, locks: tabLocks });
  const gate = () => { let open; const promise = new Promise(resolve => { open = resolve; }); return { promise, open }; };
  const a = gate(), b = gate(), heldWhileSealing = [];
  const slow = g => async wanted => { heldWhileSealing.push(tabLocks.held.length); await g.promise; return sealNew()(wanted); };
  const tab = g => tabs.prepareMove({ storage: w.newStore, networkId: NET, state: w.chain.state(), name: NAME, waitsNow: w.chain.now, lasting: { lasting: true }, seal: slow(g), open: openNew() });
  const tabA = tab(a), tabB = tab(b);
  // While both tabs wait for their passwords, another tab still gets the account's lock.
  await new Promise(resolve => setTimeout(resolve, 20));
  const other = tabs.resumeMove({ storage: w.newStore, networkId: NET, name: NAME, state: w.chain.state() });
  assert.deepEqual(await Promise.race([other, new Promise(resolve => setTimeout(() => resolve('the lock is held while the person types'), 2000))]), { stage: 'none' });
  a.open(); const shownA = await tabA;
  b.open(); await assert.rejects(tabB, text(W.alreadyWaiting));
  assert.deepEqual(heldWhileSealing, [0, 0]);
  assert.equal(JSON.parse(w.newStore.getItem(slots.note)).active.spend.publicKey, shownA.request.spend.publicKey);
  assert.equal(JSON.parse(w.newStore.getItem(slots.active.spend)).binding.publicKey, shownA.request.spend.publicKey);
  // The request tab A shows is the one kept: carried and signed, it lands on keys this browser holds.
  const { built } = await oldDevice(w, shownA.text, { code: shownA.code });
  assert.equal(await w.chain.submit(built.tx), null);
  assert.equal((await tabs.resumeMove({ storage: w.newStore, networkId: NET, name: NAME, state: w.chain.state() })).stage, 'settled');
  assert.deepEqual(holders(w.chain.state(), { new: w.newStore }), { signin: [['new']], spend: [['new']] });
});

test('review 3: no function that writes what a browser keeps for a move runs without Web Locks', async () => {
  const w = await world(), bare = M.createDeviceMove({ security }), made = await prepare(w), { review, built } = await oldDevice(w, made.text, { code: made.code });
  const base = { networkId: NET, name: NAME, state: w.chain.state() }, before = [w.newStore.copy().m, w.oldStore.copy().m];
  for (const call of [
    () => bare.prepareMove({ ...base, storage: new Storage(), waitsNow: w.chain.now, lasting: { lasting: true }, seal: sealNew(), open: openNew() }),
    () => bare.resumeMove({ ...base, storage: w.newStore }), () => bare.withdrawMove({ ...base, storage: w.newStore }),
    () => bare.rememberMove({ storage: w.oldStore, networkId: NET, name: NAME, request: review.request, built }),
    () => bare.oldDeviceStatus({ ...base, storage: w.oldStore }), () => bare.forgetOldDevice({ ...base, storage: w.oldStore, request: review.request }),
    () => dm.resumeMove({ ...base, storage: w.newStore, locks: {} }),
  ]) await assert.rejects(call(), text(W.locks));
  assert.deepEqual([[...w.newStore.m], [...w.oldStore.m]], [[...before[0]], [...before[1]]]);
});

test('review, lesser notes: no move is built but through the code; the clock of the waits is required; an account that needs more than two proofs is refused before anything is asked', async () => {
  // security-flows.mjs offers no builder of a move that a page could call instead of device-move.mjs, buildMove.
  assert.equal(F.createSecurityFlows({ security }).buildMove, undefined);
  const w = await world(), made = await prepare(w), state = w.chain.state(), now = F.elapsedOf(state);
  const base = { networkId: NET, account: alice(state), security: rowOf(state), now, feeMicros: FEE };
  const review = await dm.reviewMove({ ...base, waitsNow: now, text: made.text });
  // Without the clock of the waits, nothing is checked against a freeze or a waiting replacement, and nothing is signed.
  await assert.rejects(dm.reviewMove({ ...base, text: made.text }), text(W.waits));
  await assert.rejects(dm.buildMove({ ...base, request: review.request, typedCode: made.code, spend: await oldSpend(w), recovery: w.sheet }), text(W.waits));
  await assert.rejects(prepare({ ...w, newStore: new Storage() }, { waitsNow: undefined }), text(W.waits));
  // On a network whose waits survive stops, a freeze that the chain's time says is over can still be in force.
  const frozen = { ...base.security, frozen_until_elapsed_micros: String(now - MICROS) };
  assert.ok(await dm.reviewMove({ ...base, security: frozen, waitsNow: now, text: made.text }));
  await assert.rejects(dm.reviewMove({ ...base, security: frozen, waitsNow: now - 10n * MICROS, text: made.text }), text(W.frozen));
  // Three proofs needed: a move gives two (the payment key and one recovery key); refused at the review, and on the new device.
  const third = await stranger(), three = { ...base.account, devices: [...base.account.devices, device(third.publicKey, 'recover')].sort(byKey) };
  const strict = { ...base.security, policy: { ...base.security.policy, threshold: '3' } };
  await assert.rejects(dm.reviewMove({ ...base, account: three, security: strict, waitsNow: now, text: made.text }), text(W.threshold));
  w.chain.accounts[0].devices = three.devices; w.chain.rows['5'].policy.threshold = '3';
  await assert.rejects(prepare({ ...w, newStore: new Storage() }), text(W.threshold));
});

test('storage that may not last: the new device asks the browser (navigator.storage), and makes no request on storage it may delete unless the person chose to go on; what it wrote must read back', async () => {
  // What the browser says, through its StorageManager.
  const manager = (persisted, persist) => ({ persisted: async () => { if (persisted instanceof Error) throw persisted; return persisted; }, ...(persist === undefined ? {} : { persist: async () => persist }) });
  assert.deepEqual(await M.lastingStorage(manager(true, false)), { lasting: true, asked: false });
  assert.deepEqual(await M.lastingStorage(manager(false, true)), { lasting: true, asked: true });
  assert.deepEqual(await M.lastingStorage(manager(false, false)), { lasting: false, asked: true });
  assert.deepEqual(await M.lastingStorage(manager(false, true), { ask: false }), { lasting: false, asked: false });
  assert.deepEqual(await M.lastingStorage(manager(false)), { lasting: false, asked: false });
  for (const none of [undefined, null, {}, manager(new Error('blocked'))]) assert.deepEqual(await M.lastingStorage(none), { lasting: null, asked: false });
  // The new device: the answer is required; storage that may not last, or of which nothing is known, makes no request.
  const w = await world();
  await assert.rejects(prepare(w, { lasting: undefined }), /lastingStorage/);
  for (const lasting of [{ lasting: false, asked: true }, { lasting: null, asked: false }]) await assert.rejects(prepare(w, { lasting }), text(W.fleeting));
  assert.deepEqual(w.newStore.keys(), []);
  assert.ok(await prepare(w, { lasting: { lasting: false, asked: true, accepted: true } }));
  // A storage that takes a write and does not keep it: no request, nothing left.
  class Forgetful extends Storage { setItem(k, v) { if (!k.endsWith(':movespend')) super.setItem(k, v); } }
  const v = await world({ newStore: new Forgetful() });
  await assert.rejects(prepare(v), text(W.notKept));
  assert.deepEqual(v.newStore.keys(), []);
});

test('review 4: without the network, a request whose kept records are gone or unreadable is not shown', async () => {
  const w = await world(), slots = M.moveSlots(NET, NAME), made = await prepare(w);
  const offline = () => resume(w, { state: null });
  assert.equal((await offline()).code, made.code);
  for (const damage of [() => w.newStore.removeItem(slots.active.spend), () => w.newStore.setItem(slots.active.spend, '{}'), () => w.newStore.setItem(slots.active.signin, JSON.stringify({ ...JSON.parse(w.newStore.getItem(slots.active.signin)), binding: { networkId: NET, name: NAME, publicKey: made.request.spend.publicKey } }))]) {
    const kept = w.newStore.copy(); damage();
    const answer = await offline();
    assert.deepEqual([answer.stage, answer.damaged, answer.code, answer.text], ['unread', true, undefined, undefined]);
    w.newStore.m = kept.m;
  }
});

test('review 5: after the move, the new device replaced its login key or added a second login: the old device, none of whose keys is on the account, forgets them', async () => {
  for (const change of ['replace the login key', 'add a second login', 'replace, then forgetOldDevice']) {
    const w = await world(), { made, review, refusal } = await move(w);
    assert.equal(refusal, null);
    assert.equal((await resume(w)).stage, 'settled');
    const opened = await openVault(F.spendRecord(w.newStore, w.live), passwordOf(F.spendRecord(w.newStore, w.live)), quick, webcrypto, 'spend');
    const spend = { publicKey: made.request.spend.publicKey, privateKey: opened.privateKey }, fresh = await stranger(), account = alice(w.chain.state());
    const tx = change === 'add a second login'
      ? (await flows.buildAddSignin({ networkId: NET, account, spend, request: F.parseSigninRequest(JSON.stringify(await flows.signinRequest({ networkId: NET, account, key: fresh, now: w.chain.now })), { networkId: NET, account, now: w.chain.now }) })).tx
      : (await flows.buildReplaceSignin({ networkId: NET, account, spend, signin: fresh })).tx;
    assert.equal(await w.chain.submit(tx), null, change);
    assert.equal(dm.shapeOf(alice(w.chain.state()), review.request), 'mixed');
    if (change.endsWith('forgetOldDevice')) assert.equal((await dm.forgetOldDevice({ storage: w.oldStore, networkId: NET, name: NAME, state: w.chain.state(), request: review.request })).length, 3);
    else assert.equal((await oldStatus(w)).stage, 'forgotten', change);
    assert.deepEqual(vaultKeys(w.oldStore), [], change);
    assert.deepEqual(await oldStatus(w), { stage: 'none' });
  }
});

test('review 6: a page closed after settling copied both records and emptied the move\'s places, before the note went: the next look says settled', async () => {
  const w = await world(), slots = M.moveSlots(NET, NAME), made = await prepare(w), { built } = await oldDevice(w, made.text, { code: made.code });
  assert.equal(await w.chain.submit(built.tx), null);
  w.newStore.setItem(w.live.login, w.newStore.getItem(slots.active.signin)); w.newStore.setItem(w.live.spend, w.newStore.getItem(slots.active.spend));
  for (const key of [...Object.values(slots.active), ...Object.values(slots.held)]) w.newStore.removeItem(key);
  assert.deepEqual(await resume(w), { stage: 'settled', settled: ['signin', 'spend'], others: 0, withdrawn: false });
  assert.deepEqual(w.newStore.keys().sort(), [w.live.login, w.live.spend].sort());
  // Truly gone (not in place either): said, and the note kept, so that every look says it.
  const v = await world(), lost = await prepare(v), signed = await oldDevice(v, lost.text, { code: lost.code });
  assert.equal(await v.chain.submit(signed.built.tx), null);
  v.newStore.removeItem(slots.active.spend);
  assert.deepEqual(await resume(v), { stage: 'damaged', landed: true, settled: ['signin'], unplaced: ['spend'], others: 0, withdrawn: false });
  assert.ok(v.newStore.getItem(slots.note));
});

test('the new device makes no request when its keys do not open again, when the page sealed something else, or when this browser is not a new device', async () => {
  const w = await world(), slots = M.moveSlots(NET, NAME), other = await stranger();
  // What opened signs for another key; opening fails; the page's sealing gives a record of another account or one record.
  await assert.rejects(prepare(w, { open: async () => ({ privateKey: other.privateKey }) }), text(W.notOpened));
  await assert.rejects(prepare(w, { open: async () => { throw new Error('Could not unlock this vault.'); } }), /Could not unlock/);
  await assert.rejects(prepare(w, { seal: async wanted => (await F.sealedKeys({ wanted: wanted.map(x => ({ intent: x.intent })), networkId: NET, name: 'bob', argon2id: quick, cryptoImpl: webcrypto })) }), text(W.notSealed));
  await assert.rejects(prepare(w, { seal: async wanted => (await sealNew()(wanted)).slice(0, 1) }), text(W.notSealed));
  await assert.rejects(prepare(w, { seal: async wanted => { const made = await sealNew()(wanted); return [made[1], made[0]]; } }), text(W.notSealed));
  assert.deepEqual(w.newStore.keys(), []);
  // A browser that holds the account's payment key; one with keys kept aside or a login request waiting.
  await assert.rejects(prepare({ ...w, newStore: w.oldStore }), text(W.hasPayment));
  const busy = new Storage(); busy.setItem(w.live.request, JSON.stringify({ record: JSON.parse(w.oldStore.getItem(w.live.login)), request: { x: 1 } }));
  await assert.rejects(prepare({ ...w, newStore: busy }), text(W.otherChange));
  // An account that is not on the network, or a state without its security rows.
  await assert.rejects(prepare(w, { name: 'nobody' }), text(W.notFound));
  const bare = w.chain.state(); delete bare.security;
  await assert.rejects(prepare(w, { state: bare }), /not proven/);
  // A browser with a login key of the account (from "Using a second browser") is a new device: the move replaces that key.
  const withLogin = new Storage(); withLogin.setItem(w.live.login, w.oldStore.getItem(w.live.login));
  const made = await prepare({ ...w, newStore: withLogin });
  assert.ok(withLogin.getItem(slots.note));
  assert.equal(JSON.parse(withLogin.getItem(w.live.login)).binding.publicKey, w.oldKeys.signin, 'its login key stays until the chain shows the move');
  const { built } = await oldDevice(w, made.text, { code: made.code });
  assert.equal(await w.chain.submit(built.tx), null);
  assert.equal((await resume({ ...w, newStore: withLogin })).stage, 'settled');
  assert.equal(JSON.parse(withLogin.getItem(w.live.login)).binding.publicKey, made.request.signin.publicKey);
});

test('keys locked to the new device: the move keeps version-3 records, the device key they use counts as in use, and they settle as they are', async () => {
  const w = await world(), credential = Buffer.alloc(32, 7).toString('base64url'), secrets = new Map();
  const secretOf = publicKey => { if (!secrets.has(publicKey)) secrets.set(publicKey, new Uint8Array(createHash('sha256').update(publicKey).digest())); return new Uint8Array(secrets.get(publicKey)); };
  const lock = async keys => ({ credential, secrets: keys.map(k => secretOf(k.publicKey)) });
  const made = await prepare(w, { seal: sealNew({ lock }), open: openNew(record => secretOf(record.binding.publicKey)) });
  const slots = M.moveSlots(NET, NAME);
  for (const key of Object.values(slots.active)) assert.equal(vaultDevice(JSON.parse(w.newStore.getItem(key))), credential);
  assert.equal(credentialInUse(w.newStore, credential), true, 'device-lock.mjs sees the move\'s records, and makes no new device key over them');
  // Without the device's secret the records do not open; the page's opening without it makes no request.
  await assert.rejects(prepare({ ...w, newStore: new Storage() }, { seal: sealNew({ lock }), open: openNew() }), /locked to a device/);
  const { built } = await oldDevice(w, made.text, { code: made.code });
  assert.equal(await w.chain.submit(built.tx), null);
  assert.equal((await resume(w)).stage, 'settled');
  assert.equal(vaultDevice(F.spendRecord(w.newStore, w.live)), credential);
  assert.equal(credentialInUse(w.newStore, credential), true);
});

// ------------------------------------------------------------------ what the epoch does not stop, and a replacement that is not the move
test('a move signed before a login was added still lands (the epoch moves, the security version does not): why the new device keeps its keys by time', async () => {
  const w = await world(), made = await prepare(w), { built } = await oldDevice(w, made.text, { code: made.code });
  const change = await flows.buildReplaceSignin({ networkId: NET, account: alice(w.chain.state()), spend: await oldSpend(w), signin: await stranger() });
  assert.equal(await w.chain.submit(change.tx), null);
  assert.equal((await resume(w)).stage, 'stale');
  // Withdrawn now, it is held, not forgotten, and it lands.
  assert.equal((await withdraw(w)).stage, 'withdrawn');
  assert.equal(await w.chain.submit(built.tx), null);
  assert.equal((await resume(w)).stage, 'settled');
  assert.equal(JSON.parse(w.newStore.getItem(w.live.spend)).binding.publicKey, made.request.spend.publicKey);
});

test('a replacement that takes the new payment key but keeps an old login key: the new device puts in place what the account holds and says it is mixed; the old device forgets nothing', async () => {
  const w = await world(), made = await prepare(w), state = w.chain.state(), spend = await oldSpend(w);
  const review = await dm.reviewMove({ text: made.text, networkId: NET, account: alice(state), security: rowOf(state), now: F.elapsedOf(state), waitsNow: F.elapsedOf(state), feeMicros: FEE });
  await dm.rememberMove({ storage: w.oldStore, networkId: NET, name: NAME, request: review.request, built: { version: '1', payload: { expires_elapsed_micros: String(w.chain.now + 10n * MINUTE) } } });
  const keys = [{ public_key: made.request.spend.publicKey, role: 'spend', proof: made.request.spend.proof }, security.keepKey(w.oldKeys.signin, 'signin'), security.keepKey(w.sheet.publicKey, 'recover'), security.keepKey(w.phrase.publicKey, 'recover')];
  const other = await flows.buildRoot({ networkId: NET, account: alice(state), security: rowOf(state), operation: security.operations.replace(keys, rowOf(state).policy), approvers: [spend, w.sheet], submitter: spend, expiresElapsedMicros: w.chain.now + 10n * MINUTE });
  assert.equal(await w.chain.submit(other.tx), null);
  assert.deepEqual(await oldStatus(w), { stage: 'mixed' });
  await assert.rejects(dm.forgetOldDevice({ storage: w.oldStore, networkId: NET, name: NAME, state: w.chain.state(), request: review.request }), text(W.mixedKeep));
  assert.equal(vaultKeys(w.oldStore).length, 3);
  assert.deepEqual(await resume(w), { stage: 'mixed', settled: ['spend'], others: 1, withdrawn: false });
  assert.equal(JSON.parse(w.newStore.getItem(w.live.spend)).binding.publicKey, made.request.spend.publicKey);
  assert.equal(w.newStore.getItem(w.live.login), null);
});

test('the request\'s signed message and code: their domains, their fields in order, and 80 bits in 16 characters', async () => {
  const request = { networkId: NET, accountId: '5', authEpoch: '7', expires: '9', signin: { publicKey: '11'.repeat(32) }, spend: { publicKey: '22'.repeat(32) } };
  const be = n => n.toString(16).padStart(16, '0'), enc = s => Buffer.from(s).toString('hex');
  const fields = NET + be(5) + be(7) + be(9) + '11'.repeat(32) + '22'.repeat(32);
  assert.equal(SDK.bytesToHex(M.moveRequestMessage(request)), enc('TCDEVNET-WALLET-MOVE-REQUEST-V1\0') + fields);
  const digest = createHash('sha256').update(Buffer.from(enc('TCDEVNET-WALLET-MOVE-CODE-V1\0') + fields, 'hex')).digest();
  let bits = ''; for (const byte of digest.subarray(0, 10)) bits += byte.toString(2).padStart(8, '0');
  const expected = bits.match(/.{5}/g).map(b => F.SHEET_ALPHABET[parseInt(b, 2)]).join('').match(/.{4}/g).join(' ');
  assert.equal(await M.moveCode(request), expected);
  // Any one field changed changes the code.
  const codes = new Set([await M.moveCode(request)]);
  for (const change of [{ networkId: 'e8'.repeat(32) }, { accountId: '6' }, { authEpoch: '8' }, { expires: '10' }, { signin: { publicKey: '33'.repeat(32) } }, { spend: { publicKey: '33'.repeat(32) } }]) codes.add(await M.moveCode({ ...request, ...change }));
  assert.equal(codes.size, 7);
  assert.equal(M.MOVE_REQUEST_LIFETIME_MICROS, HOUR);
});
