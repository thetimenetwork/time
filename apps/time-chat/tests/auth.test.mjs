import { publicKeyStart, publicKeyEnd } from '../public/armor.mjs';
import assert from 'node:assert/strict';
import test from 'node:test';
import { createAuth, keyCommitment } from '../auth.mjs';
import { isChatLoginNonce } from '../public/login-nonce.mjs';

const origin = 'http://127.0.0.1:8840';
// The auth layer commits to the exact public armor. Encryption tests exercise real OpenPGP packets.
const publicArmor = [publicKeyStart, '', 'aGVsbG8=', publicKeyEnd, ''].join('\n');

async function makeFixture() {
  const clock = { time: Date.now() };
  const key = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const walletKey = Buffer.from(await crypto.subtle.exportKey('raw', key.publicKey)).toString('hex');
  const account = { id: '7', name: 'alice', auth_epoch: '0', devices: [{ public_key: walletKey, can_manage: true, can_spend: true }] };
  const chain = { accounts: [account], time_micros: '10000000', genesis: { genesis_time_micros: '1000000' }, recovery_cases: [], security: [], protocol_version: '4', height: '12' };
  const fixture = { verified: true, reads: 0, wait: null };
  const auth = await createAuth({ origin, now: () => clock.time, verifiedState: async () => {
    fixture.reads++;
    if (fixture.wait) await fixture.wait;
    return { verified: fixture.verified, state: chain };
  } });
  chain.network_id = auth.networkId;
  const sign = challenge => globalThis.TimeSDK.signLogin(challenge, { account, publicKey: walletKey, privateKey: key.privateKey });
  async function login() {
    const entry = auth.issue();
    return auth.finish(entry.token, await sign(entry.challenge));
  }
  async function enroll() {
    const session = await login();
    const binding = auth.issue(publicArmor,session.token);
    return auth.finish(binding.token, await sign(binding.challenge), session.token);
  }
  return { auth, chain, fixture, account, clock, sign, login, enroll };
}

test('wallet login creates a revocable session and checks current chain authority', async () => {
  const { auth, chain, fixture, account, login } = await makeFixture();
  const result = await login();
  assert.equal(result.name, 'alice');
  assert.equal(result.attestation, null);
  assert.equal((await auth.current(result.token)).accountId, '7');
  assert.deepEqual(await auth.resolveName('alice'), { accountId: '7', name: 'alice' });
  fixture.verified = false;
  await assert.rejects(auth.current(result.token), /verified/);
  fixture.verified = true;
  account.auth_epoch = '1';
  assert.equal(await auth.current(result.token), null);
  chain.network_id = '0'.repeat(64);
  await assert.rejects(login(), /verified/);
});

test('parallel reads share only in-flight authority verification and respect logout', async () => {
  const { auth, fixture, login } = await makeFixture();
  const session = await login();
  let finish;
  fixture.wait = new Promise(resolve => { finish = resolve; });
  const readsBefore = fixture.reads;
  const a = auth.current(session.token), b = auth.current(session.token);
  assert.equal(fixture.reads, readsBefore + 1);
  auth.logout(session.token);
  finish();
  assert.deepEqual(await Promise.all([a,b]), [null,null]);
  assert.equal(await auth.current(session.token),null);
});

test('wallet login proof is single-use, origin-bound, and separate from key enrollment', async () => {
  const { auth, clock, sign, login } = await makeFixture();
  const entry = auth.issue();
  assert.equal(await isChatLoginNonce(entry.challenge.nonce,origin),true);
  assert.equal(await isChatLoginNonce(entry.challenge.nonce,'https://other.example'),false);
  assert.notEqual(entry.challenge.nonce,auth.issue().challenge.nonce);
  const signed = await sign(entry.challenge);
  const otherOrigin = await sign({ ...entry.challenge, origin: 'https://other.example' });
  await assert.rejects(auth.finish(entry.token, otherOrigin), /scope|binding/);
  await auth.finish(entry.token, signed);
  await assert.rejects(auth.finish(entry.token, signed), /expired|consumed/);
  assert.throws(() => auth.issue(publicArmor),/Sign in/);
  const owner = await login();
  const bound = auth.issue(publicArmor, owner.token);
  assert.equal(await isChatLoginNonce(bound.challenge.nonce,origin),false);
  const signedBinding=await sign(bound.challenge);
  await assert.rejects(auth.finish(bound.token,signedBinding,(await login()).token), /same signed-in session/);
  assert.equal((await auth.finish(bound.token,signedBinding,owner.token)).accountId,owner.accountId);
  const expired = auth.issue();
  const previous = await sign(expired.challenge);
  clock.time = expired.challenge.expiresAt;
  await assert.rejects(auth.finish(expired.token, previous), /expired/);
});

test('historical wallet signature authenticates the chat key after the live login expires', async t => {
  const { auth, account, clock, enroll } = await makeFixture();
  const result = await enroll();
  const input = { accountId: '7', publicKey: publicArmor, attestation: result.attestation };
  const { salt, proof } = input.attestation;
  assert.equal(keyCommitment(salt, publicArmor.replaceAll('\n', '\r\n')), proof.message.nonce);
  clock.time = result.expiresAt + 1;
  t.mock.method(Date, 'now', () => clock.time);
  assert.equal(await auth.current(result.token), null);
  assert.throws(() => globalThis.TimeSDK.loginBytes(proof.message), /expired/i);
  assert.deepEqual(await auth.verifyAttestation(input), { accountId: '7', name: 'alice' });
  await assert.rejects(auth.verifyAttestation({ ...input, accountId: '8' }));
  await assert.rejects(auth.verifyAttestation({ ...input, publicKey: publicArmor.replace('aGVsbG8=', 'aGk=') }));
  const tampered = structuredClone(input);
  tampered.attestation.proof.signature = '00'.repeat(64);
  await assert.rejects(auth.verifyAttestation(tampered), /signature/);
  account.devices = [];
  await assert.rejects(auth.verifyAttestation(input), /authorize/);
});

test('protected roles, epoch and a pending guardian freeze apply to saved attestations', async () => {
  const { auth, account, chain, enroll } = await makeFixture();
  const bound = await enroll();
  const input = { accountId: '7', publicKey: publicArmor, attestation: bound.attestation };
  account.auth_epoch = '1';
  await assert.rejects(auth.verifyAttestation(input), /changed/);
  account.auth_epoch = '0';
  chain.recovery_cases = [{ target: '7', ready_elapsed_micros: '5000000', expires_elapsed_micros: '20000000' }];
  await assert.rejects(auth.verifyAttestation(input), /authorize/);
  chain.recovery_cases = [];
  account.devices[0].can_manage = false;
  chain.security = [{ account: '7', frozen_until_elapsed_micros: '0', pending_root: null }];
  await assert.rejects(auth.verifyAttestation(input), /authorize/);
  account.devices[0].can_spend = false;
  assert.equal((await auth.verifyAttestation(input)).accountId, '7');
  chain.security[0].frozen_until_elapsed_micros = '20000000';
  await assert.rejects(auth.verifyAttestation(input), /authorize/);
});
