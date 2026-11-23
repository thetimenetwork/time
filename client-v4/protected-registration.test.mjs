// A registration that creates its account protected (kind 45, on a network with `protected_registration`).
// The SDK must produce exactly the bytes the engine verifies. The fixture was written by the engine's own
// test (v5/tests/protected_registration.rs, run with V5_EXPORT_REGISTRATION_FIXTURE=1), from actions the
// engine accepted: a sponsor's commitment and the registration that used it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import './time-sdk.js';
import * as security from './account-security.mjs';

const SDK = globalThis.TimeSDK;
const fixture = JSON.parse(await readFile(new URL('./protected-registration.fixture.json', import.meta.url), 'utf8'));
const networkId = fixture.network_id, { name, salt } = fixture;
const keys = {};
for (const entry of fixture.seeds) {
  keys[entry.name] = {
    publicKey: entry.public_key,
    privateKey: await crypto.subtle.importKey('pkcs8', SDK.hexToBytes('302e020100300506032b657004220420' + entry.seed_hex), { name: 'Ed25519' }, false, ['sign']),
  };
}
const hex = (bytes) => SDK.bytesToHex(bytes);
const registrationKey = keys.registration.publicKey;
const rules = security.policy({ threshold: 2, dailyLimitMicros: 500000, delaySeconds: 60, freezeSeconds: 120 });
const accept = (who, role, forKey = registrationKey) => security.acceptRegistrationRole({ networkId, registrationKey: forKey, role, ...keys[who] });
/// The set of the fixture, in the order a wallet happens to collect it.
const collected = async () => ({ keys: [await accept('spend', 'spend'), await accept('phrase', 'recover'), await accept('signin', 'signin'), await accept('sheet', 'recover')], policy: rules });

test('the rule is read from a verified state, and the action has its number', () => {
  assert.equal(SDK.REGISTER_PROTECTED_KIND, 45);
  // A named kind, under one name: the HTTP API gives it as `kind_name`, and the explorer puts it into words.
  assert.deepEqual(Object.entries(SDK.KINDS).filter(([, kind]) => kind === 45), [['register_protected', 45]]);
  assert.equal(SDK.protectedRegistration({ config: {} }), false);
  assert.equal(SDK.protectedRegistration({ config: { protected_registration: true } }), true);
  for (const written of [false, 'true', 1, null, {}]) assert.throws(() => SDK.protectedRegistration({ config: { protected_registration: written } }), /Unsupported setting for registrations/);
  assert.throws(() => SDK.protectedRegistration({}), /carries the network configuration/);
  assert.throws(() => SDK.protectedRegistration(null), /A verified state is required/);
});

test('a key accepts its role for the registration key, with the bytes the engine verifies', async () => {
  assert.deepEqual(rules, fixture.policy);
  for (const expected of fixture.acceptances) {
    const key = Object.values(keys).find((k) => k.publicKey === expected.public_key);
    assert.equal(hex(SDK.registrationRoleBytes({ networkId, registrationKey, role: expected.role, publicKey: key.publicKey })), expected.message);
    assert.deepEqual(await security.acceptRegistrationRole({ networkId, registrationKey, role: expected.role, ...key }), { public_key: expected.public_key, role: expected.role, proof: expected.proof });
  }
  const mine = { networkId, registrationKey, role: 'spend', publicKey: keys.spend.publicKey };
  // The acceptance names the registration key, the role and the key: any other gives other bytes.
  for (const other of [{ registrationKey: keys.sheet.publicKey }, { role: 'recover' }, { role: 'signin' }, { publicKey: keys.sheet.publicKey }, { networkId: 'cd'.repeat(32) }]) {
    assert.notEqual(hex(SDK.registrationRoleBytes({ ...mine, ...other })), hex(SDK.registrationRoleBytes(mine)));
  }
  // And it is no acceptance for an existing account, whatever its number: another domain, another length.
  const forAccount = security.keyMessage({ networkId, accountId: '12', role: 'spend', publicKey: keys.spend.publicKey });
  assert.notEqual(forAccount.length, SDK.registrationRoleBytes(mine).length);
  assert.equal(new TextDecoder().decode(SDK.registrationRoleBytes(mine).slice(0, 25)), 'TCDEVNET-REGISTER-KEY-V1\0');
  assert.throws(() => SDK.registrationRoleBytes({ ...mine, role: 'owner' }), /Unknown role/);
  assert.throws(() => SDK.registrationRoleBytes({ ...mine, registrationKey: 'AB'.repeat(32) }), /Invalid canonical hexadecimal/);
});

test('the set has one form, and the commitment names it', async () => {
  const setup = SDK.protectedSetup(await collected());
  assert.deepEqual(setup, fixture.security);
  // The engine hashes the set as JSON with sorted keys and no spaces.
  assert.equal(JSON.stringify(setup), JSON.stringify(fixture.security));
  assert.ok(JSON.stringify(setup).startsWith('{"keys":[{"proof":"'));
  const committed = { networkId, publicKey: registrationKey, name, salt, security: await collected() };
  assert.equal(await SDK.protectedNameCommitment(committed), fixture.commitment);
  // It is not the commitment of a protocol-4 registration of the same name, key and salt.
  assert.equal(await SDK.nameCommitment({ networkId, publicKey: registrationKey, name, salt }), fixture.protocol_4_commitment);
  assert.notEqual(fixture.commitment, fixture.protocol_4_commitment);
  // Another key in the set, another role, another limit, another wait, another name, salt, key or network:
  // another commitment. Nobody takes the name with anything but what was committed to.
  const base = await collected();
  const withKeys = (list) => ({ ...committed, security: { keys: list, policy: rules } });
  const others = [
    withKeys([await accept('sponsor', 'spend'), ...base.keys.filter((entry) => entry.role !== 'spend')]),
    withKeys([...base.keys, await accept('sponsor', 'recover')]),
    withKeys(base.keys.filter((entry) => entry.role !== 'signin')),
    withKeys([await accept('spend', 'signin'), await accept('signin', 'spend'), ...base.keys.filter((entry) => entry.role === 'recover')]),
    { ...committed, security: { keys: base.keys, policy: { ...rules, daily_limit_micros: '500000000' } } },
    { ...committed, security: { keys: base.keys, policy: { ...rules, delay_seconds: '30' } } },
    { ...committed, name: 'alicia' },
    { ...committed, salt: 'ab'.repeat(32) },
    { ...committed, publicKey: keys.sheet.publicKey },
    { ...committed, networkId: 'cd'.repeat(32) },
  ];
  const seen = new Set([fixture.commitment]);
  for (const other of others) seen.add(await SDK.protectedNameCommitment(other));
  assert.equal(seen.size, others.length + 1);
  await assert.rejects(SDK.protectedNameCommitment({ ...committed, name: 'Alice' }), /Invalid name/);
});

test('the sponsor pays for that commitment with the action of any registration', async () => {
  const sponsor = fixture.sponsor, expires = sponsor.expires_elapsed_micros;
  const consent = SDK.sponsorConsentBytes({ networkId, sponsorAccount: sponsor.account.id, publicKey: registrationKey, commitment: fixture.commitment, expiresElapsedMicros: expires });
  const proof = hex(new Uint8Array(await crypto.subtle.sign('Ed25519', keys.registration.privateKey, consent)));
  const action = await SDK.signAction({
    networkId, kind: 'sponsor_registration', from: sponsor.account.id, nonce: (BigInt(sponsor.account.nonce) + 1n).toString(), authEpoch: sponsor.account.auth_epoch,
    publicKey: keys.sponsor.publicKey, payload: { public_key: registrationKey, commitment: fixture.commitment, expires_elapsed_micros: expires, proof },
  }, keys.sponsor.privateKey);
  assert.equal(hex(action), sponsor.action_hex);
});

test('the registration: the same signed action, read back by the SDK', async () => {
  const action = await SDK.signProtectedRegistration({ networkId, ...keys.registration, name, salt, security: await collected() });
  assert.equal(hex(action), fixture.registration.action_hex);
  const decoded = SDK.decodeAction(action);
  assert.deepEqual(decoded, { networkId, kind: 45, from: SDK.MAX_U64, nonce: '0', authEpoch: '0', publicKey: registrationKey, payload: { name, salt, security: fixture.security } });
  // By its number, with the header of a reveal: no account, no nonce, no authority epoch.
  const built = SDK.buildAction({ networkId, kind: SDK.REGISTER_PROTECTED_KIND, from: SDK.MAX_U64, nonce: '0', authEpoch: '0', publicKey: registrationKey, payload: decoded.payload });
  assert.equal(hex(built), hex(action.slice(0, action.length - 64)));
  // By its name, the same bytes.
  assert.equal(hex(SDK.buildAction({ networkId, kind: 'register_protected', from: SDK.MAX_U64, nonce: '0', authEpoch: '0', publicKey: registrationKey, payload: decoded.payload })), hex(built));
  await assert.rejects(SDK.signProtectedRegistration({ networkId, ...keys.registration, name: 'a', salt, security: await collected() }), /Invalid name/);
  await assert.rejects(SDK.signProtectedRegistration({ networkId, ...keys.registration, name, salt: 'ab', security: await collected() }), /Invalid canonical hexadecimal/);
});

test('a set the engine would refuse is refused before a sponsor pays', async () => {
  const base = await collected();
  const refused = (change, why, state) => assert.throws(() => SDK.protectedSetup(change(structuredClone(base)), state), why);
  const without = (role) => (setup) => ({ ...setup, keys: setup.keys.filter((entry) => entry.role !== role) });
  refused(without('spend'), /At least one spend key is required/);
  refused((setup) => ({ ...setup, policy: { ...setup.policy, threshold: '1' } }), /threshold is at least two/);
  refused((setup) => ({ ...setup, policy: { ...setup.policy, threshold: '3' } }), /at most the number of recovery keys/);
  refused(without('recover'), /at most the number of recovery keys/);
  refused((setup) => ({ ...setup, keys: [...setup.keys, setup.keys[0]] }), /A key appears twice/);
  refused((setup) => ({ ...setup, keys: Array.from({ length: 9 }, () => setup.keys[0]) }), /one to eight keys/);
  refused((setup) => ({ ...setup, keys: [] }), /one to eight keys/);
  // Every key of a first set carries its acceptance: there is no account yet on which it could already be.
  refused((setup) => ({ ...setup, keys: setup.keys.map(({ public_key, role }) => ({ public_key, role })) }), /every key carries its acceptance/);
  refused((setup) => ({ ...setup, keys: setup.keys.map((entry) => ({ ...entry, note: 'x' })) }), /every key carries its acceptance/);
  refused((setup) => ({ ...setup, keys: setup.keys.map((entry) => ({ ...entry, role: 'owner' })) }), /Unknown role/);
  refused((setup) => ({ ...setup, keys: setup.keys.map((entry) => ({ ...entry, proof: 'ab' })) }), /Invalid canonical hexadecimal/);
  refused((setup) => ({ ...setup, memo: 'x' }), /A security setup is \{keys, policy\}/);
  refused((setup) => ({ keys: setup.keys }), /A security setup is \{keys, policy\}/);
  refused((setup) => ({ ...setup, policy: { ...setup.policy, daily_limit_micros: 5 } }), /canonical u64/);
  refused((setup) => ({ ...setup, policy: { threshold: '2', daily_limit_micros: '5', delay_seconds: '60' } }), /A policy is/);
  refused((setup) => ({ ...setup, policy: { ...setup.policy, freeze_seconds: '2592001' } }), /at most 30 days/);
  // With a verified state of the network, its minimum wait is known as well: two days on a production network.
  const lab = { config: { recovery_min_delay_micros: '30000000' } }, production = { config: { recovery_min_delay_micros: (172800n * 1000000n).toString() } };
  assert.deepEqual(SDK.protectedSetup(base, lab), fixture.security);
  refused((setup) => setup, /at least the minimum of the network/, production);
  refused((setup) => ({ ...setup, policy: { ...setup.policy, delay_seconds: '29' } }), /at least the minimum of the network/, lab);
  const twoDays = { ...base, policy: { ...rules, delay_seconds: '172800', freeze_seconds: '172800' } };
  assert.deepEqual(SDK.protectedSetup(twoDays, production).policy, { daily_limit_micros: '500000', delay_seconds: '172800', freeze_seconds: '172800', threshold: '2' });
});
