// The independent review's library-level tests (A1 to A8), adapted to the current API. Each asserts
// the property the wallet should have; a failure is a defect.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import '../../client-v4/time-sdk.js';
import * as security from '../../client-v4/account-security.mjs';
import { newDevice, sealVault, checkPassword } from './vault.mjs';
import * as F from './security-flows.mjs';

const SDK = globalThis.TimeSDK;
const source = await readFile(new URL('./vendor/argon2-4.12.0.umd.min.js', import.meta.url), 'utf8'), umd = { exports: {} };
new Function('module', 'exports', source)(umd, umd.exports);
const { argon2id } = umd.exports;
const fixture = JSON.parse(await readFile(new URL('../../client-v4/account-security.fixture.json', import.meta.url), 'utf8'));
const networkId = fixture.network_id, accountId = fixture.account.id;
const keys = {};
for (const entry of fixture.seeds) keys[entry.name] = { publicKey: entry.public_key, privateKey: await crypto.subtle.importKey('pkcs8', SDK.hexToBytes('302e020100300506032b657004220420' + entry.seed_hex), { name: 'Ed25519' }, false, ['sign']) };
const flows = F.createSecurityFlows({ security });
const rules = { threshold: '2', daily_limit_micros: '500000', delay_seconds: '60', freeze_seconds: '120' };
const device = (key, role) => ({ public_key: keys[key]?.publicKey || key, can_manage: role === 'recover' || role === 'full', can_spend: role === 'spend' || role === 'full' });
const sortDevices = list => list.sort((a, b) => a.public_key < b.public_key ? -1 : 1);
const securedAccount = (devices = [device('signin', 'signin'), device('spend', 'spend'), device('sheet', 'recover'), device('phrase', 'recover')]) => ({ id: accountId, name: 'alice', balance: '10000000', nonce: '7', auth_epoch: '2', recovery_policy: null, devices: sortDevices(devices) });
const row = (extra = {}) => ({ account: accountId, version: '1', policy: { ...rules }, allowance_micros: '500000', allowance_elapsed_micros: '1000000000', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null, ...extra });
class Storage { entries = new Map(); getItem(k) { return this.entries.has(k) ? this.entries.get(k) : null; } setItem(k, v) { this.entries.set(k, String(v)); } removeItem(k) { this.entries.delete(k); } }

test('A1 passphrase rule: one code point that NFKC-expands is refused', () => {
  const phrase = 'ﷺ'; // 1 code point, 18 characters after NFKC
  assert.throws(() => checkPassword(phrase, 'alice'), /15 characters/, 'the raw password rule refuses it');
  // The recovery passphrase is made by the wallet; anything else is refused, whatever its length.
  assert.throws(() => F.checkPassphrase(phrase, { passwords: [] }), /4 words|not one the wallet makes/);
});

test('A2 passphrase rule: guessable strings are refused for a key anyone can attack offline', () => {
  for (const phrase of ['abcdefghijklmno', 'qwertyuiopasdfg', '123456789abcdef', 'password password password password', 'bababa bababa bababa']) {
    assert.throws(() => F.checkPassphrase(phrase, { passwords: [] }), undefined, `accepted as recovery passphrase: ${phrase}`);
  }
  assert.equal(F.PASSPHRASE.bits >= 72, true);
});

test('A3 staged keys: a render from a state read before the block keeps keys the chain now holds', async () => {
  const storage = new Storage(), slots = F.vaultSlots(networkId, 'alice');
  const old = await newDevice(webcrypto), signin = await newDevice(webcrypto), spend = await newDevice(webcrypto);
  const binding = publicKey => ({ networkId, name: 'alice', publicKey });
  storage.setItem(slots.login, JSON.stringify(await sealVault(old.secret, 'an old protocol four password', binding(old.publicKey), argon2id, webcrypto)));
  F.stageVaults(storage, slots, { signin: await sealVault({ pkcs8: signin.secret.pkcs8 }, 'violet otters dance beneath moonlight 41', binding(signin.publicKey), argon2id, webcrypto, 'signin'), spend: await sealVault({ pkcs8: spend.secret.pkcs8 }, 'quiet harbour lanterns at dawn 77', binding(spend.publicKey), argon2id, webcrypto, 'spend') }, { kind: 70, nonce: '4', authEpoch: '0' });
  // Tab B renders a state fetched just before the block with kind 70: nonce 3, the old key.
  const stale = { nonce: '3', auth_epoch: '0', devices: [{ public_key: old.publicKey, can_manage: true, can_spend: true }] };
  F.discardStaged(storage, slots, stale, { security: null, state: { height: '9', time_micros: '1', genesis: { genesis_time_micros: '0' } } });
  F.discardStaged(storage, slots, stale); // and once without any state at all
  // Tab A reads the new state and settles.
  const fresh = { devices: [device(signin.publicKey, 'signin'), device(spend.publicKey, 'spend'), device('sheet', 'recover'), device('phrase', 'recover')] };
  assert.deepEqual(F.settleStaged(storage, slots, fresh), ['signin', 'spend']);
});

test('A4 replacing a stolen spend key drops every sign-in key, including one the thief added', async () => {
  const thief = await newDevice(webcrypto);
  const account = securedAccount([device(thief.publicKey, 'signin'), device('spend', 'spend'), device('sheet', 'recover'), device('phrase', 'recover')]);
  const fresh = await newDevice(webcrypto), login = await newDevice(webcrypto);
  const built = await flows.buildReplaceSpend({ networkId, account, security: row(), spend: keys.spend, recovery: keys.sheet, newSpend: fresh, newSignin: login, now: 5000000000n });
  const kept = built.payload.op.keys.filter(k => k.role === 'signin').map(k => k.public_key);
  assert.deepEqual(kept, [login.publicKey], 'only this browser\'s new sign-in key remains');
});

test('A5 cancelling a waiting replacement needs two proofs', async () => {
  const account = securedAccount(), waiting = row({ pending_root: { devices: [], policy: rules, ready_elapsed_micros: '9', expires_elapsed_micros: '99999999999' } });
  for (const [label, approvers] of [['old payment key alone', [keys.spend]], ['one recovery key alone', [keys.sheet]]]) {
    await assert.rejects(flows.buildCancelReplacement({ networkId, account, security: waiting, approvers, now: 1n }), /needs 2 proofs/, label);
  }
  // Both recovery keys together can (a fresh browser with the sheet and passphrase).
  const both = await flows.buildCancelReplacement({ networkId, account, security: waiting, approvers: [keys.sheet, keys.phrase], now: 1n });
  assert.deepEqual(SDK.decodeAction(both.tx).payload.op, { type: 'cancel' });
});

test('A6 the wallet states the real exposure: almost twice the limit within 24 hours', () => {
  const limit = 500000n, t0 = 1000000000n, day = 86400000000n;
  const first = security.allowance(row({ allowance_micros: String(limit), allowance_elapsed_micros: String(t0) }), t0);
  const second = security.allowance(row({ allowance_micros: '0', allowance_elapsed_micros: String(t0) }), t0 + day - 1n);
  assert.ok(first + second > limit, 'the engine lets a spend key move more than the limit in 24 h');
  const exposure = F.limitExposure(limit);
  assert.equal(exposure.atOnce, limit);
  assert.ok(exposure.within24h >= first + second, `stated ${exposure.within24h}, possible ${first + second}`);
});

test('A7 leaked recovery keys can be replaced at once, which also ends a waiting replacement', async () => {
  const account = securedAccount(), waiting = row({ pending_root: { devices: [], policy: rules, ready_elapsed_micros: '9', expires_elapsed_micros: '99999999999' } });
  const newSheet = await newDevice(webcrypto), newPhrase = await newDevice(webcrypto);
  const replace = await flows.buildReplaceRecovery({ networkId, account, security: waiting, spend: keys.spend, recovery: keys.sheet, newSheet, newPhrase, now: 3n });
  const action = SDK.decodeAction(replace.tx);
  assert.deepEqual([action.kind, action.publicKey, replace.spend], [73, keys.spend.publicKey, true], 'signed and approved with the spend key: immediate');
  const recover = action.payload.op.keys.filter(k => k.role === 'recover').map(k => k.public_key).sort();
  assert.deepEqual(recover, [newSheet.publicKey, newPhrase.publicKey].sort(), 'the old recovery keys are gone');
  assert.deepEqual(action.payload.op.keys.filter(k => k.role !== 'recover').map(k => [k.role, Boolean(k.proof)]).sort(), [['signin', false], ['spend', false]]);
  for (const k of action.payload.op.keys.filter(k => k.proof)) {
    const pub = await crypto.subtle.importKey('raw', SDK.hexToBytes(k.public_key), 'Ed25519', false, ['verify']);
    assert.ok(await crypto.subtle.verify('Ed25519', pub, SDK.hexToBytes(k.proof), security.keyMessage({ networkId, accountId, role: 'recover', publicKey: k.public_key })));
  }
  await assert.rejects(flows.buildReplaceRecovery({ networkId, account, security: row(), spend: keys.spend, recovery: keys.next, newSheet, newPhrase, now: 3n }), /does not belong/);
});

test('A8 a website payment while frozen is refused as frozen, not as over the limit', () => {
  const choice = flows.choosePayment({ security: row({ frozen_until_elapsed_micros: '2000000000' }), now: 1000000000n, amount: '1', feeMicros: '1000', balance: '10000000' });
  assert.equal(choice.mode, 'frozen'); assert.match(choice.reason, /frozen/);
});

test('M3/N2 a login request from another browser: the bytes the engine verifies, for this account, its current keys, and a few hours', async () => {
  const account = securedAccount(), other = await newDevice(webcrypto), now = 7000000000n;
  const request = await flows.signinRequest({ networkId, account, key: other, now });
  assert.deepEqual([request.version, request.authEpoch, BigInt(request.expires) - now], [2, account.auth_epoch, F.LOGIN_REQUEST_LIFETIME_MICROS]);
  const parsed = F.parseSigninRequest(JSON.stringify(request), { networkId, account, now });
  const built = await flows.buildAddSignin({ networkId, account, spend: keys.spend, request: parsed });
  const action = SDK.decodeAction(built.tx);
  assert.deepEqual([action.kind, action.publicKey, action.payload], [71, keys.spend.publicKey, { add: [{ public_key: other.publicKey, proof: request.proof }], remove: [] }]);
  // The engine's acceptance bytes are the ones of account-security.mjs.
  const pub = await crypto.subtle.importKey('raw', SDK.hexToBytes(other.publicKey), 'Ed25519', false, ['verify']);
  assert.ok(await crypto.subtle.verify('Ed25519', pub, SDK.hexToBytes(request.proof), security.keyMessage({ networkId, accountId, role: 'signin', publicKey: other.publicKey })));
  const parse = (r, a = account, at = now) => F.parseSigninRequest(JSON.stringify(r), { networkId, account: a, now: at });
  assert.throws(() => parse({ ...request, accountId: '6' }), /another account/);
  assert.throws(() => parse({ ...request, extra: 1 }), /not a login request/);
  assert.throws(() => parse({ ...request, version: 1 }), /older version/);
  assert.throws(() => parse({ ...request, publicKey: keys.signin.publicKey }), /already on the account/);
  // The keys of the account changed since (a removal bumps the authority epoch): refused.
  assert.throws(() => parse(request, { ...account, auth_epoch: String(BigInt(account.auth_epoch) + 1n) }), /before the account's keys last changed/);
  // Expired, or dated too far ahead: refused.
  assert.throws(() => parse(request, account, BigInt(request.expires)), /expired/);
  assert.throws(() => parse(request, account, now - 3600000000n), /expired/);
  // Either signature forged, or the epoch or expiry edited after signing: refused before anything is signed with the spend key.
  for (const forged of [{ ...request, proof: 'ab'.repeat(64) }, { ...request, requestProof: 'ab'.repeat(64) }, { ...request, expires: String(BigInt(request.expires) - 1n) }]) {
    await assert.rejects(flows.buildAddSignin({ networkId, account, spend: keys.spend, request: parse(forged) }), /proof does not check/);
  }
  assert.match(await F.fingerprint(other.publicKey), /^[0-9a-f]{4}( [0-9a-f]{4}){3}$/);
  assert.notEqual(await F.fingerprint(other.publicKey), await F.fingerprint(keys.spend.publicKey));
});

test('N1 a login request lives in its own slot: it blocks nothing, is void once this browser holds a live key, never overwrites one', async () => {
  const storage = new Storage(), slots = F.vaultSlots(networkId, 'alice'), binding = publicKey => ({ networkId, name: 'alice', publicKey });
  const asked = await newDevice(webcrypto), live = await newDevice(webcrypto);
  const record = await sealVault({ pkcs8: asked.secret.pkcs8 }, 'phone login password 456', binding(asked.publicKey), argon2id, webcrypto, 'signin');
  F.storeLoginRequest(storage, slots, record, { publicKey: asked.publicKey });
  assert.equal(F.hasStaged(storage, slots), false, 'a request does not block other changes of keys');
  assert.throws(() => F.storeLoginRequest(storage, slots, record, {}), /Withdraw/);
  assert.deepEqual(F.stagedNames(storage, [...storage.entries.keys()], networkId), ['alice']);
  // Not added yet, nothing live here: kept.
  assert.equal(F.settleLoginRequest(storage, slots, securedAccount()), null); assert.ok(F.loginRequestOf(storage, slots));
  // Added, and this browser holds nothing live: it becomes the login.
  const added = securedAccount([...securedAccount().devices, device(asked.publicKey, 'signin')]);
  const copy = new Storage(); for (const [k, v] of storage.entries) copy.setItem(k, v);
  assert.equal(F.settleLoginRequest(copy, slots, added), 'promoted'); assert.equal(JSON.parse(copy.getItem(slots.login)).binding.publicKey, asked.publicKey); assert.equal(F.loginRequestOf(copy, slots), null);
  // This browser recovered meanwhile and holds a live login key: the request is void and never overwrites it, even if added later.
  const liveRecord = JSON.stringify(await sealVault({ pkcs8: live.secret.pkcs8 }, 'recovered login password 789', binding(live.publicKey), argon2id, webcrypto, 'signin'));
  storage.setItem(slots.login, liveRecord);
  const both = securedAccount([...securedAccount().devices, device(asked.publicKey, 'signin'), device(live.publicKey, 'signin')]);
  assert.equal(F.settleLoginRequest(storage, slots, both), 'dropped');
  assert.equal(storage.getItem(slots.login), liveRecord); assert.equal(F.loginRequestOf(storage, slots), null);
  // Withdrawing deletes it.
  F.storeLoginRequest(storage, slots, record, { publicKey: asked.publicKey }); F.withdrawLoginRequest(storage, slots); assert.equal(F.loginRequestOf(storage, slots), null);
});

test('H2 two passwords that differ only in case or spacing count as the same', () => {
  assert.throws(() => F.checkPasswords({ login: 'violet otters dance beneath moonlight 41', payment: 'Violet Otters  dance beneath moonlight 41' }), /differ/);
  assert.equal(F.samePassword('quiet harbour lanterns at dawn 77', 'violet otters dance beneath moonlight 41'), false);
});

// ------------------------------------------------------------------ second review (N3, G1, S1), as written by the review
test('N3 stagedVoid: a state with no security proof counts as proof that a staged kind-73 replacement is void', () => {
  const note = { kind: 73, version: '4', expires: '999999999999' };
  const state = { height: '20', time_micros: '1000', genesis: { genesis_time_micros: '0' } }; // read without include_security
  const account = { nonce: '9', auth_epoch: '3', devices: [] };
  assert.equal(F.stagedVoid(note, { account, security: null, state }), false, 'unproven row is treated as void: staged keys would be dropped');
  // With the rows proven (and this account's absent), the missing row is proof; an expired note is void either way.
  assert.equal(F.stagedVoid(note, { account, security: null, state: { ...state, security: [] } }), true);
  assert.equal(F.stagedVoid({ ...note, expires: '1000' }, { account, security: null, state }), true);
});

test('G1 generated passphrase: uniform syllables, 72 bits, canonical typed-back forms', () => {
  const counts = new Map(); const N = 20000;
  for (let i = 0; i < N; i++) for (const w of F.generatePassphrase().split(' ')) for (const s of w.match(/../g)) counts.set(s, (counts.get(s) || 0) + 1);
  assert.equal(counts.size, 64);
  const expected = N * 12 / 64; let chi = 0; for (const v of counts.values()) chi += (v - expected) ** 2 / expected;
  assert.ok(chi < 120, `chi-square ${chi.toFixed(1)} over 63 dof`);
  const p = F.generatePassphrase();
  for (const typed of [p.toUpperCase(), '  ' + p.replace(/ /g, ' - ') + ' ', p.replace(/ /g, '\u3000'), p.normalize('NFKD')]) assert.equal(F.parsePassphrase(typed), p);
  assert.throws(() => F.parsePassphrase(p.replace(/ /g, '')), /4 words/);
  assert.equal(F.parsePassphrase([...p].map(c => c === ' ' ? ' ' : String.fromCharCode(c.charCodeAt(0) + 0xFEE0)).join('')), p);
});

test('S1 staking allowlist: nothing but payments, the three staking kinds and the four of a validator\'s operation reaches the spend key', () => {
  for (const kind of ['double_vote', 'withdraw', ' self_bond', 'Retire_validator', 'bitcoin_bid', 'claim_auction', 'cancel_pending', 'add_device', 'revoke_device', 'set_recovery', ' delegate', 'Delegate', ['delegate'], { toString: () => 'delegate' }, ['register_validator'], 5, 17, undefined])
    assert.throws(() => F.assertSpendKeyKind(kind), /payments and staking only/, String(kind));
  assert.throws(() => F.stakeOutflow('transfer', { amount: '1' }, '1000'), /Not a staking action/);
  assert.equal(F.stakeOutflow('delegate', { amount: '5' }, '1000'), 1005n);
  assert.throws(() => F.stakeOutflow('delegate', { amount: '-5' }, '1000'));
  assert.throws(() => F.stakeOutflow('delegate', { amount: '05' }, '1000'));
});
