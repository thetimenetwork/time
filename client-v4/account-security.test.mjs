// The wallet library must produce exactly the bytes the engine rules verify. The fixture was
// written by the engine's own test (v5/tests/security.rs, run with V5_EXPORT_SECURITY_FIXTURE=1),
// from actions the engine accepted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { generateKeyPairSync, sign } from 'node:crypto';
import './time-sdk.js';
import * as security from './account-security.mjs';
import { createLoginService } from './server-auth.mjs';

const SDK = globalThis.TimeSDK;
const fixture = JSON.parse(await readFile(new URL('./account-security.fixture.json', import.meta.url), 'utf8'));
const networkId = fixture.network_id, accountId = fixture.account.id;
const keys = {};
for (const entry of fixture.seeds) {
  keys[entry.name] = {
    publicKey: entry.public_key,
    privateKey: await crypto.subtle.importKey('pkcs8', SDK.hexToBytes('302e020100300506032b657004220420' + entry.seed_hex), { name: 'Ed25519' }, false, ['sign']),
  };
}
const hex = (bytes) => SDK.bytesToHex(bytes);
const rules = security.policy({ threshold: 2, dailyLimitMicros: 500000, delaySeconds: 60, freezeSeconds: 120 });
const join = (name, role) => security.acceptRole({ networkId, accountId, role, ...keys[name] });

test('a key accepts its role with the bytes the engine verifies', async () => {
  for (const expected of fixture.acceptances) {
    const key = Object.values(keys).find((k) => k.publicKey === expected.public_key);
    assert.equal(hex(security.keyMessage({ networkId, accountId, role: expected.role, publicKey: key.publicKey })), expected.message);
    assert.equal((await security.acceptRole({ networkId, accountId, role: expected.role, ...key })).proof, expected.proof);
  }
  assert.throws(() => security.keyMessage({ networkId, accountId, role: 'owner', publicKey: keys.spend.publicKey }), /Unknown role/);
});

test('adopting the rules: the same payload and the same signed action', async () => {
  const payload = security.payloads.secure([
    await join('friend', 'recover'), await join('signin', 'signin'), await join('spend', 'spend'), await join('sheet', 'recover'), await join('phrase', 'recover'),
  ], rules);
  assert.deepEqual(payload, fixture.secure.payload);
  const action = await security.signSecurityAction({
    networkId, kind: security.KIND.secure, payload, ...keys.old,
    account: { id: accountId, nonce: fixture.account.before_secure.nonce, auth_epoch: fixture.account.before_secure.auth_epoch },
  });
  assert.equal(hex(action), fixture.secure.action_hex);
  // The SDK reads its own action back.
  const decoded = SDK.decodeAction(action);
  assert.equal(decoded.kind, 70);
  assert.deepEqual(decoded.payload, fixture.secure.payload);
});

test('a root operation: the approval bytes name the operation and everyone who approves', async () => {
  const operation = security.operations.replace([
    security.keepKey(keys.signin.publicKey, 'signin'), await join('next', 'spend'),
    security.keepKey(keys.sheet.publicKey, 'recover'), security.keepKey(keys.phrase.publicKey, 'recover'), security.keepKey(keys.friend.publicKey, 'recover'),
  ], rules);
  assert.deepEqual(operation, fixture.root.operation);
  const common = { networkId, accountId, version: fixture.root.version, expiresElapsedMicros: fixture.root.expires_elapsed_micros, operation, approvers: fixture.root.approvers };
  assert.equal(hex(await security.rootMessage(common)), fixture.root.message_hex);
  // Any other set of approvers gives other bytes, so an approval cannot be reused with fewer or other keys.
  assert.notEqual(hex(await security.rootMessage({ ...common, approvers: [keys.sheet.publicKey] })), fixture.root.message_hex);
  assert.notEqual(hex(await security.rootMessage({ ...common, approvers: [...fixture.root.approvers, keys.phrase.publicKey] })), fixture.root.message_hex);
  await assert.rejects(security.approve({ ...common, ...keys.phrase }), /not in the list of approvers/);
  const approvals = [await security.approve({ ...common, ...keys.spend }), await security.approve({ ...common, ...keys.sheet })];
  const action = await security.signSecurityAction({
    networkId, kind: security.KIND.root, ...keys.sheet, account: { id: accountId, nonce: '999', auth_epoch: '999' },
    payload: security.payloads.root(operation, fixture.root.expires_elapsed_micros, approvals),
  });
  assert.equal(hex(action), fixture.root.action_hex);
  const decoded = SDK.decodeAction(action);
  assert.equal(decoded.nonce, '0');
  assert.equal(decoded.authEpoch, '0');
});

test('a freeze carries no nonce and names the freeze count; a limit change takes the next nonce', async () => {
  const stop = security.payloads.freeze({ freezes: '0', version: '1' }, fixture.freeze.payload.expires_elapsed_micros);
  assert.deepEqual(stop, fixture.freeze.payload);
  assert.equal(hex(await security.signSecurityAction({ networkId, kind: security.KIND.freeze, payload: stop, ...keys.sheet, account: { id: accountId, nonce: '5', auth_epoch: '5' } })), fixture.freeze.action_hex);
  const lower = security.payloads.limit(fixture.limit.daily_limit_micros);
  const action = await security.signSecurityAction({ networkId, kind: security.KIND.limit, payload: lower, ...keys.spend, account: { id: accountId, ...fixture.account.after_secure } });
  assert.equal(hex(action), fixture.limit.action_hex);
  assert.equal(SDK.decodeAction(action).nonce, (BigInt(fixture.account.after_secure.nonce) + 1n).toString());
});

test('the wallet reads the remaining allowance as the engine computes it', () => {
  for (const reading of fixture.allowance.readings) {
    assert.equal(security.allowance(fixture.allowance.security, reading.now_elapsed_micros).toString(), reading.allowance_micros, 'at ' + reading.now_elapsed_micros);
  }
});

test('roles, proofs and the freeze state are read from the rows', () => {
  const account = { devices: [
    { public_key: keys.signin.publicKey, can_manage: false, can_spend: false },
    { public_key: keys.spend.publicKey, can_manage: false, can_spend: true },
    { public_key: keys.next.publicKey, can_manage: false, can_spend: true },
    { public_key: keys.sheet.publicKey, can_manage: true, can_spend: false },
    { public_key: keys.phrase.publicKey, can_manage: true, can_spend: false },
  ] };
  assert.deepEqual(account.devices.map(security.roleOf), ['signin', 'spend', 'spend', 'recover', 'recover']);
  assert.equal(security.roleOf({ can_manage: true, can_spend: true }), null);
  // Two spend keys are one proof; a recovery key is one each.
  assert.deepEqual(security.proofs(account, [keys.spend.publicKey, keys.next.publicKey]), { count: 1, spend: true });
  assert.deepEqual(security.proofs(account, [keys.spend.publicKey, keys.sheet.publicKey]), { count: 2, spend: true });
  assert.deepEqual(security.proofs(account, [keys.sheet.publicKey, keys.phrase.publicKey]), { count: 2, spend: false });
  assert.throws(() => security.proofs(account, [keys.signin.publicKey]), /Only spend and recovery keys/);
  assert.throws(() => security.proofs(account, [keys.friend.publicKey]), /not a key of the account/);
  const row = { frozen_until_elapsed_micros: '500', pending_root: null };
  assert.equal(security.frozen(row, 499), true);
  assert.equal(security.frozen(row, 500), false);
  assert.equal(security.frozen({ frozen_until_elapsed_micros: '0', pending_root: { expires_elapsed_micros: '900' } }, 900), true);
  assert.equal(security.frozen({ frozen_until_elapsed_micros: '0', pending_root: { expires_elapsed_micros: '900' } }, 901), false);
  assert.deepEqual(security.securityOf({ security: [{ account: '5', version: '1' }] }, 5), { account: '5', version: '1' });
  assert.equal(security.securityOf({}, 5), null);
  assert.throws(() => security.sortByKey([{ public_key: 'aa' }, { public_key: 'aa' }]), /twice/);
});

test('the login rule: a sign-in key only, and nobody while the account is frozen', () => {
  const key = (n) => String(n).repeat(64);
  const account = { devices: [{ public_key: key(1), can_manage: false, can_spend: false }, { public_key: key(2), can_manage: false, can_spend: true }, { public_key: key(3), can_manage: true, can_spend: false }] };
  const row = { frozen_until_elapsed_micros: '0', pending_root: null };
  const rule = (publicKey, rowOrNull = row, now = 10) => security.signInRefusal({ account, security: rowOrNull, publicKey, nowElapsedMicros: now });
  assert.equal(rule(key(1)), null);
  assert.match(rule(key(2)), /sign-in key/);
  assert.match(rule(key(3)), /sign-in key/);
  assert.match(rule(key(4)), /not a key of the account/);
  assert.match(rule(key(1), { ...row, frozen_until_elapsed_micros: '11' }), /frozen/);
  assert.equal(rule(key(1), { ...row, frozen_until_elapsed_micros: '10' }), null);
  assert.match(rule(key(1), { ...row, pending_root: { expires_elapsed_micros: '10' } }), /frozen/);
  assert.equal(rule(key(1), { ...row, pending_root: { expires_elapsed_micros: '9' } }), null);
  // No security row: any key of the account, as in protocol 4.
  assert.equal(rule(key(2), null), null);
  assert.match(rule(key(4), null), /not a key of the account/);
});

test('a website accepts a login of a secured account from a sign-in key only, and not while it is frozen', async () => {
  const origin = 'https://merchant.example';
  const make = () => { const pair = generateKeyPairSync('ed25519'); return { pair, key: pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex') }; };
  const signin = make(), spend = make(), recover = make(), full = make();
  const secured = { id: '7', name: 'bob', auth_epoch: '2', devices: [
    { public_key: signin.key, can_manage: false, can_spend: false }, { public_key: spend.key, can_manage: false, can_spend: true }, { public_key: recover.key, can_manage: true, can_spend: false },
  ] };
  const classic = { id: '8', name: 'carol', auth_epoch: '0', devices: [{ public_key: full.key, can_manage: true, can_spend: true }, { public_key: spend.key, can_manage: false, can_spend: true }] };
  // A protocol-4 account can have keys with one power each without having adopted the rules.
  const split = { id: '9', name: 'dave', auth_epoch: '0', devices: [{ public_key: recover.key, can_manage: true, can_spend: false }, { public_key: spend.key, can_manage: false, can_spend: true }] };
  const rules = security.policy({ threshold: 2, dailyLimitMicros: 5, delaySeconds: 60, freezeSeconds: 120 });
  const row = { account: '7', version: '1', policy: rules, allowance_micros: '5', allowance_elapsed_micros: '0', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null };
  let rows = [row], provesRows = true;
  const queries = [];
  const service = createLoginService({ origin, networkId, verifiedState: async (query) => {
    queries.push(query);
    const state = { network_id: networkId, height: '9', genesis: { genesis_time_micros: '0' }, time_micros: '100', accounts: [secured, classic, split], recovery_cases: [] };
    if (query.include_security && provesRows) state.security = rows;
    return { verified: true, state };
  } });
  const login = async (account, who) => {
    const issued = service.issue(), message = SDK.loginMessage(issued.challenge, { account, publicKey: who.key });
    return service.finish(issued.cookie, { message, signature: sign(null, SDK.loginBytes(message), who.pair.privateKey).toString('hex') });
  };
  const open = await login(secured, signin);
  assert.equal(open.session.name, 'bob');
  assert.deepEqual(queries, [{ ids: ['7'] }, { ids: ['7'], include_security: true }]);
  await assert.rejects(login(secured, spend), /sign in with a sign-in key/);
  await assert.rejects(login(secured, recover), /sign in with a sign-in key/);
  // Frozen (the state is at elapsed time 100): nobody signs in, and open sessions end.
  assert.equal((await service.current(open.cookie)).account.name, 'bob');
  rows = [{ ...row, frozen_until_elapsed_micros: '500' }];
  await assert.rejects(login(secured, signin), /frozen/);
  assert.equal(await service.current(open.cookie), null);
  rows = [{ ...row, frozen_until_elapsed_micros: '100' }];
  assert.equal((await login(secured, signin)).session.name, 'bob');
  // The same while a replacement of the keys waits.
  rows = [{ ...row, pending_root: { devices: secured.devices, policy: rules, ready_elapsed_micros: '150', expires_elapsed_micros: '900' } }];
  await assert.rejects(login(secured, signin), /frozen/);
  // Without proof of the security row, or of its absence, nobody signs in to such an account.
  rows = [row]; provesRows = false;
  await assert.rejects(login(secured, signin), /security state unavailable/);
  await assert.rejects(login(split, spend), /security state unavailable/);
  provesRows = true;
  // Keys with one power each but no security row: protocol-4 rules.
  rows = [];
  assert.equal((await login(split, spend)).session.name, 'dave');
  rows = [row];
  // An account with a full key cannot have adopted the rules: one read, as before.
  queries.length = 0;
  assert.equal((await login(classic, full)).session.name, 'carol');
  assert.deepEqual(queries, [{ ids: ['8'] }]);
  // An account that has not adopted the rules signs in with any of its keys, as before.
  assert.equal((await login(classic, full)).session.name, 'carol');
  assert.equal((await login(classic, spend)).session.name, 'carol');
});
