import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash, argon2Sync, webcrypto } from 'node:crypto';
import { KDF, newDevice, sealVault, openVault, checkPassword, validateName, hex, forgetSecret } from './vault.mjs';
import { GenerationFence, PendingReservations, PaymentMarkers, withSigningLock, parseSeconds, formatSeconds, acceptApprovalEvent } from './guards.mjs';
import { accountActionHeader, pendingIsObsolete, poolSharesForDeposit, leastSureStake, registrationPendingDisposition, emergencyCancelSlot, nonceCancelSlot, recoveryFrozen, authorityReservationObsolete, emergencyReservationObsolete } from './actions.mjs';
import { validateRecoveryClaim, recoveryCaseReady } from './recovery.mjs';
const source = await readFile(new URL('./vendor/argon2-4.12.0.umd.min.js', import.meta.url), 'utf8');
const module = { exports: {} };
// The published browser UMD is evaluated unchanged in Node for these tests, not a browser substitute.
new Function('module', 'exports', source)(module, module.exports);
const { argon2id } = module.exports;
const password = 'violet otters dance beneath moonlight 41';
const networkId = 'ab'.repeat(32);
let device, binding, encrypted;
test('pinned Argon2 asset matches the recorded SHA-256', () => {
  assert.equal(createHash('sha256').update(source).digest('hex'), 'dcec617a2e1b700fa132d1583a186cb70611113395e869f2dd6cc82b415d3094');
});
test('Argon2id 64MiB t3 p1 agrees with independent native Node implementation', async () => {
  const actual = await argon2id({ password: 'password', salt: 'somesalt', memorySize: KDF.memoryKiB, iterations: KDF.iterations, parallelism: KDF.parallelism, hashLength: 32, outputType: 'hex' });
  const expected = argon2Sync('argon2id', { message: Buffer.from('password'), nonce: Buffer.from('somesalt'), parallelism: 1, tagLength: 32, memory: 65536, passes: 3 });
  assert.equal(actual, expected.toString('hex'));
  assert.equal(actual, '9e8789c8b42834220afc00085ac73acc308651216994abbfddd69b2592032efd');
});
test('random Ed25519 key is imported nonextractable and vault roundtrips', async () => {
  device = await newDevice(webcrypto); binding = { networkId, name: 'alice', publicKey: device.publicKey };
  assert.equal(device.privateKey.extractable, false);
  assert.equal(device.publicKey.length, 64);
  encrypted = await sealVault(device.secret, password, binding, argon2id, webcrypto);
  const serialized = JSON.stringify(encrypted);
  assert.ok(!serialized.includes(password)); assert.ok(!serialized.includes(device.secret.pkcs8));
  const opened = await openVault(encrypted, password, argon2id, webcrypto);
  assert.equal(opened.secret.pkcs8, device.secret.pkcs8); assert.equal(opened.privateKey.extractable, false);
  await assert.rejects(webcrypto.subtle.exportKey('pkcs8', opened.privateKey));
});
test('each encryption gets a fresh 128-bit salt and 96-bit IV', async () => {
  const other = await sealVault(device.secret, password, binding, argon2id, webcrypto);
  assert.notEqual(other.salt, encrypted.salt); assert.notEqual(other.iv, encrypted.iv); assert.notEqual(other.ciphertext, encrypted.ciphertext);
});
test('wrong password, ciphertext, network, name and device binding fail closed', async () => {
  await assert.rejects(openVault(encrypted, password + 'wrong', argon2id, webcrypto), /Could not unlock/);
  for (const key of ['networkId', 'name', 'publicKey']) {
    const altered = structuredClone(encrypted); altered.binding[key] = key === 'name' ? 'bob' : 'cd'.repeat(32);
    await assert.rejects(openVault(altered, password, argon2id, webcrypto), /Could not unlock/);
  }
  const altered = structuredClone(encrypted); altered.ciphertext = (altered.ciphertext[0] === 'A' ? 'B' : 'A') + altered.ciphertext.slice(1);
  await assert.rejects(openVault(altered, password, argon2id, webcrypto), /Could not unlock/);
});
test('untrusted KDF cost, wrong salt/IV length and unknown envelope fields rejected before work', async () => {
  let calls = 0; const maliciousKdf = async () => { calls++; throw new Error('should not derive'); };
  const bad = structuredClone(encrypted); bad.kdf.memoryKiB = 8;
  await assert.rejects(openVault(bad, password, maliciousKdf, webcrypto), /Unsupported/);
  const oversized = structuredClone(encrypted); oversized.kdf.memoryKiB = 4294967295;
  await assert.rejects(openVault(oversized, password, maliciousKdf, webcrypto), /Unsupported/);
  await assert.rejects(openVault({ ...encrypted, unknown: true }, password, maliciousKdf, webcrypto), /Unsupported/);
  await assert.rejects(openVault({ ...encrypted, iv: 'AA==' }, password, maliciousKdf, webcrypto), /Invalid vault/);
  assert.equal(calls, 0);
});
test('password policy accepts Unicode, spaces, paste-equivalent long text; does not trim', async () => {
  assert.equal(checkPassword('a unique 🔐 sentence with space'), true);
  assert.equal(checkPassword('  our lovely summer forest  '), true);
  assert.equal(checkPassword('🦦'.repeat(12) + 'pine tree forest'), true);
  assert.throws(() => checkPassword('short'), /15/); assert.throws(() => checkPassword('password123456789'), /easy/);
  assert.throws(() => checkPassword('aaaaaaaaaaaaaaaa'), /easy/); assert.throws(() => checkPassword('abc\ud800long password'), /Unicode/);
  assert.equal(validateName('@alice_12'), 'alice_12'); assert.throws(() => validateName('ALICE'));
  const trailing = await sealVault(device.secret, password + ' ', binding, argon2id, webcrypto);
  await assert.rejects(openVault(trailing, password, argon2id, webcrypto));
});
test('missing Argon2 has no silent PBKDF or weak fallback', async () => {
  await assert.rejects(openVault(encrypted, password, undefined, webcrypto), /Argon2id/);
});
test('generation fence rejects work after lock or network/session change', () => {
  const fence = new GenerationFence(), check = fence.capture(); check(); fence.bump(); assert.throws(check, /Session changed/);
  fence.capture()();
});
test('Web Locks serializes same account actions and rejects unsupported browsers', async () => {
  let tail = Promise.resolve(), overlap = 0, maximum = 0; const names = [];
  const locks = { request(name, options, callback) { names.push(name); const next = tail.then(callback); tail = next.catch(() => {}); return next; } };
  await Promise.all(Array.from({ length: 8 }, () => withSigningLock(locks, networkId, '42', async () => { overlap++; maximum = Math.max(maximum, overlap); await new Promise(resolve => setTimeout(resolve, 2)); overlap--; })));
  assert.equal(maximum, 1); assert.equal(new Set(names).size, 1);
  await assert.rejects(withSigningLock(null, networkId, '42', () => {}), /Web Locks/);
});
test('durable pending reservation prevents duplicate signing and survives a new instance', () => {
  const map = new Map(); const storage = { getItem: k => map.get(k) || null, setItem: (k, v) => map.set(k, v), removeItem: k => map.delete(k) };
  const a = new PendingReservations(storage), b = new PendingReservations(storage);
  const record = { hash: 'AB'.repeat(32), nonce: '7', authEpoch: '2', tx: 'dHg=' };
  a.put(networkId, '42', record); assert.deepEqual(b.get(networkId, '42'), record);
  assert.throws(() => b.put(networkId, '42', record), /already pending/);
  assert.throws(() => b.clear(networkId, '42', 'cc'.repeat(32)), /changed/);
  b.clear(networkId, '42', record.hash); assert.equal(a.get(networkId, '42'), null);
  storage.setItem(a.key(networkId, '42'), 'broken'); assert.throws(() => a.get(networkId, '42'), /damaged/);
});
test('all monetary amounts use exact BigInt microseconds including large values', () => {
  assert.equal(parseSeconds('0.000001'), '1'); assert.equal(parseSeconds('1.100001'), '1100001');
  assert.equal(parseSeconds('9007199254.740993'), '9007199254740993');
  assert.equal(formatSeconds('9007199254740993'), '9007199254.740993');
  for (const s of ['1e3', '0', '-1', '1.0000001', ' 1', '01', 'NaN']) assert.throws(() => parseSeconds(s));
});
test('action header uses NEXT nonce, current authority epoch and exact permission', () => {
  const account = { id: '9', nonce: '9007199254740992', auth_epoch: '3', devices: [{ public_key: device.publicKey, can_spend: true, can_manage: false }] };
  assert.equal(accountActionHeader({ account, publicKey: device.publicKey, networkId, kind: 'transfer', payload: {} }).nonce, '9007199254740993');
  assert.throws(() => accountActionHeader({ account, publicKey: device.publicKey, networkId, kind: 'add_device', payload: {} }), /permission/);
  assert.throws(() => accountActionHeader({ account, publicKey: 'ff'.repeat(32), networkId, kind: 'transfer', payload: {} }), /permission/);
});
test('pending action only released with proof nonce consumed, epoch revoked, or bid expired', () => {
  const item = { nonce: '8', authEpoch: '2' }, action = { kind: 3, payload: {} }, state = { auction_epoch: '7' };
  assert.equal(pendingIsObsolete({ nonce: '7', auth_epoch: '2' }, item, action, state), false);
  assert.equal(pendingIsObsolete({ nonce: '8', auth_epoch: '2' }, item, action, state), true);
  assert.equal(pendingIsObsolete({ nonce: '7', auth_epoch: '3' }, item, action, state), true);
  assert.equal(pendingIsObsolete({ nonce: '7', auth_epoch: '2' }, item, { kind: 4, payload: { epoch: '6' } }, state), true);
});
test('staking uses minimum shares with integer precision and rejects rounding-to-zero', () => {
  assert.equal(poolSharesForDeposit({ assets: '0', total_shares: '0' }, '100'), '100');
  assert.equal(poolSharesForDeposit({ assets: '300', total_shares: '200' }, '150'), '100');
  assert.throws(() => poolSharesForDeposit({ assets: '1000000000', total_shares: '1' }, '1'), /too small/);
});
test('staking preflight rejects a nonzero share deposit with excessive partial rounding loss', () => {
  assert.throws(() => poolSharesForDeposit({ assets: '3', total_shares: '2' }, '2'), /0.1%/);
  assert.equal(poolSharesForDeposit({ assets: '1001', total_shares: '1000' }, '1000'), '999');
});
test('a stake that is too small for a pool is refused with the amount that the pool always takes', () => {
  // The pool of a trial network 25 minutes after a first stake of 0.02 seconds: a share costs 248 microseconds.
  const pool = { assets: '5888066', total_shares: '23759' };
  assert.equal(leastSureStake(pool), 247825n);
  assert.throws(() => poolSharesForDeposit(pool, '20000'), /A stake of 0\.247825 seconds or more is always taken\. Stake more, or choose another validator\./);
  assert.throws(() => poolSharesForDeposit(pool, '100'), /A stake of 0\.247825 seconds or more is always taken/, 'also when the stake is less than one share');
  // What it names is taken, and so is everything above it, whatever the remainder.
  for (const amount of [247825n, 247826n, 300001n, 999999n, 60000000n]) assert.match(poolSharesForDeposit(pool, amount.toString()), /^[1-9][0-9]*$/);
  for (const sample of [{ assets: '1001', total_shares: '1000' }, { assets: '7', total_shares: '3' }, { assets: '4660000000000', total_shares: '2000000000' }]) {
    const least = leastSureStake(sample);
    for (let extra = 0n; extra < 50n; extra++) assert.match(poolSharesForDeposit(sample, (least + extra * 7n).toString()), /^[1-9][0-9]*$/);
  }
  assert.equal(leastSureStake({ assets: '0', total_shares: '0' }), 1n, 'an empty pool takes anything');
});
test('popup rejects foreign source, null origin, insecure site and forged login audience', () => {
  const opener = {}, challenge = { origin: 'https://shop.example' };
  const event = { source: opener, origin: 'https://shop.example', data: { type: 'time:request', version: 1, id: 'abcdefgh1234', request: { type: 'login', challenge } } };
  assert.equal(acceptApprovalEvent(event, opener).origin, 'https://shop.example');
  assert.throws(() => acceptApprovalEvent({ ...event, source: {} }, opener), /opening/);
  assert.throws(() => acceptApprovalEvent({ ...event, origin: 'null' }, opener), /opening/);
  assert.throws(() => acceptApprovalEvent({ ...event, origin: 'http://shop.example' }, opener), /HTTPS/);
  assert.throws(() => acceptApprovalEvent({ ...event, data: { ...event.data, request: { type: 'login', challenge: { origin: 'https://other.example' } } } }, opener), /audience/);
  assert.equal(acceptApprovalEvent({ ...event, origin: 'http://localhost:8788', data: { ...event.data, request: { type: 'payment' } } }, opener).request.type, 'payment');
});
test('forgetSecret drops plaintext key and registration salt references', () => {
  const secret = { pkcs8: 'secret', nameSalt: 'secret' }; forgetSecret(secret); assert.deepEqual(secret, { pkcs8: null, nameSalt: null });
});
test('lost or expired anonymous registration can resume without an impossible account nonce', () => {
  const state = { accounts: [], time_micros: '100000000', genesis: { genesis_time_micros: '0' }, name_commits: [] };
  const binding = { networkId, name: 'alice', publicKey: 'ab'.repeat(32) };
  const commit = { networkId, publicKey: binding.publicKey, kind: 1, payload: { commitment: 'ef'.repeat(32), expires_elapsed_micros: '90000000' } };
  assert.equal(registrationPendingDisposition(state, binding, commit), 'expired');
  commit.payload.expires_elapsed_micros = '180000000'; assert.equal(registrationPendingDisposition(state, binding, commit), 'retry_exact');
  state.name_commits = [{ public_key: binding.publicKey, commitment: commit.payload.commitment, expires_elapsed_micros: '180000000' }];
  assert.equal(registrationPendingDisposition(state, binding, commit), 'known_commit');
  const reveal = { networkId, publicKey: binding.publicKey, kind: 2, payload: { name: 'alice', salt: 'ff'.repeat(32) } };
  assert.equal(registrationPendingDisposition(state, binding, reveal), 'retry_exact'); state.name_commits = [];
  assert.equal(registrationPendingDisposition(state, binding, reveal), 'expired');
  state.accounts = [{ name: 'alice', devices: [{ public_key: binding.publicKey }] }];
  assert.equal(registrationPendingDisposition(state, binding, reveal), 'known_account');
  assert.throws(() => registrationPendingDisposition(state, { ...binding, publicKey: 'cd'.repeat(32) }, reveal), /does not match/);
});
test('guardian recovery claims bind current policy, authority, network, new key and bounded deadline', () => {
  const target = { id: '1', auth_epoch: '2', recovery_version: '3', recovery_policy: { delay_seconds: '30' }, devices: [{ public_key: 'aa'.repeat(32) }] };
  const state = { config:{recovery_approval_window_micros:'604800000000'},network_id: networkId, time_micros: '100000000', genesis: { genesis_time_micros: '0' }, accounts: [target] };
  const claim = { version: 1, networkId, target: '1', auth_epoch: '2', policy_version: '3', new_public_key: 'bb'.repeat(32), recovery_id: 'cc'.repeat(32), expires_elapsed_micros: '730000000', proof: 'dd'.repeat(64) };
  assert.equal(validateRecoveryClaim(claim, state), target);
  assert.equal(validateRecoveryClaim({...claim,expires_elapsed_micros:'86400000000'},state),target);
  assert.throws(() => validateRecoveryClaim({ ...claim, auth_epoch: '1' }, state), /authority changed/);
  assert.throws(() => validateRecoveryClaim({ ...claim, policy_version: '2' }, state), /authority changed/);
  assert.throws(() => validateRecoveryClaim({ ...claim, networkId: 'ff'.repeat(32) }, state), /network/);
  assert.throws(() => validateRecoveryClaim({ ...claim, new_public_key: 'aa'.repeat(32) }, state), /already/);
  assert.throws(() => validateRecoveryClaim({ ...claim, expires_elapsed_micros: '100000000' }, state), /expired/);
  assert.throws(() => validateRecoveryClaim({ ...claim, expires_elapsed_micros: '604930000001' }, state), /window/);
  assert.throws(() => validateRecoveryClaim({ ...claim, unknown: true }, state), /Unknown/);
});
test('quorum freezes immediately but new key cannot finalize until full recovery delay', () => {
  const state = { time_micros: '100000000', genesis: { genesis_time_micros: '0' }, recovery_cases: [] };
  const record = { target: '1', ready_elapsed_micros: null, expires_elapsed_micros: '700000000' };
  state.recovery_cases.push(record); assert.equal(recoveryFrozen(state, '1'), false); assert.equal(recoveryCaseReady(record, state), false);
  record.ready_elapsed_micros = '130000000'; assert.equal(recoveryFrozen(state, '1'), true); assert.equal(recoveryCaseReady(record, state), false);
  state.time_micros = '130000000'; assert.equal(recoveryCaseReady(record, state), true);
  state.time_micros = '700000001'; assert.equal(recoveryFrozen(state, '1'), false); assert.equal(recoveryCaseReady(record, state), false);
});
test('paused transfer and separate emergency cancel both survive timeout until certified authority advance', () => {
  const map = new Map(), storage = { getItem: k => map.get(k) || null, setItem: (k, v) => map.set(k, v), removeItem: k => map.delete(k) }, reservations = new PendingReservations(storage);
  const transfer = { hash: 'aa'.repeat(32), tx: 'dHg=', nonce: '5', authEpoch: '2' }, cancel = { hash: 'bb'.repeat(32), tx: 'eXo=', nonce: '5', authEpoch: '2' };
  reservations.put(networkId, '1', transfer);
  const state = { time_micros: '100000000', genesis: { genesis_time_micros: '0' }, recovery_cases: [{ target: '1', ready_elapsed_micros: '130000000', expires_elapsed_micros: '700000000' }] };
  assert.equal(recoveryFrozen(state, '1'), true); reservations.put(networkId, emergencyCancelSlot('1'), cancel);
  // An unconfirmed request timeout proves no authority change: preserve both exact signed actions.
  const unchanged = { auth_epoch: '2' }; assert.equal(authorityReservationObsolete(unchanged, transfer), false); assert.equal(authorityReservationObsolete(unchanged, cancel), false);
  assert.deepEqual(reservations.get(networkId, '1'), transfer); assert.deepEqual(reservations.get(networkId, emergencyCancelSlot('1')), cancel);
  const certifiedAfterCancel = { auth_epoch: '3' };
  for (const slot of ['1', emergencyCancelSlot('1')]) { const item = reservations.get(networkId, slot); assert.equal(authorityReservationObsolete(certifiedAfterCancel, item), true); reservations.clear(networkId, slot, item.hash); }
  assert.equal(reservations.get(networkId, '1'), null); assert.equal(reservations.get(networkId, emergencyCancelSlot('1')), null);
});
test('order markers persist before broadcast and block a second payment across popup, reload or changed merchant origin', () => {
  const map = new Map(), storage = { getItem: k => map.get(k) || null, setItem: (k, v) => map.set(k, v), removeItem: k => map.delete(k) };
  const first = new PaymentMarkers(storage), ref = 'ee'.repeat(32), hash = 'aa'.repeat(32);
  first.reserve(networkId, '1', ref, hash, 'https://merchant.example');
  const afterReload = new PaymentMarkers(storage); assert.equal(afterReload.get(networkId, '1', ref).status, 'pending');
  assert.throws(() => afterReload.reserve(networkId, '1', ref, 'bb'.repeat(32), 'https://other-origin.example'), /different signed payment/);
  assert.equal(afterReload.reserve(networkId, '1', ref, hash).hash, hash.toUpperCase());
  afterReload.markVerified(networkId, '1', ref, hash); assert.equal(first.get(networkId, '1', ref).status, 'verified');
  assert.throws(() => first.reserve(networkId, '1', ref, 'cc'.repeat(32), 'https://merchant.example'), /different signed payment/);
  assert.equal(first.get(networkId, '2', ref), null);
  storage.setItem(first.key(networkId, '1', ref), 'corrupt'); assert.throws(() => afterReload.get(networkId, '1', ref), /damaged/);
  storage.setItem(first.key(networkId, '1', ref), JSON.stringify({ hash, status: 'verified' })); assert.throws(() => afterReload.get(networkId, '1', ref), /invalid/);
});
test('another device consuming a failed cancel nonce cannot permanently block a new emergency cancellation', () => {
  const failedCancel = { authEpoch: '2', nonce: '7' }, proof = { auth_epoch: '2', nonce: '7' };
  assert.equal(emergencyReservationObsolete(proof, failedCancel), true);
  assert.equal(authorityReservationObsolete(proof, failedCancel), false);
  assert.equal(emergencyReservationObsolete({ auth_epoch: '2', nonce: '6' }, failedCancel), false);
});
test('ordinary nonce cancellation requires management and has its own durable slot', () => {
  const spendOnly = { id: '1', nonce: '4', auth_epoch: '2', devices: [{ public_key: device.publicKey, can_spend: true, can_manage: false }] };
  assert.throws(() => accountActionHeader({ account: spendOnly, publicKey: device.publicKey, networkId, kind: 'cancel_pending', payload: {} }), /permission/);
  spendOnly.devices[0].can_manage = true;
  const header = accountActionHeader({ account: spendOnly, publicKey: device.publicKey, networkId, kind: 'cancel_pending', payload: {} });
  assert.equal(header.nonce, '5'); assert.equal(header.authEpoch, '2'); assert.notEqual(nonceCancelSlot('1'), emergencyCancelSlot('1')); assert.notEqual(nonceCancelSlot('1'), '1');
});
test('only V4 nonce-bound merchant quotes become obsolete after proved chain expiry',()=>{
  const account={nonce:'0',auth_epoch:'0'},pending={nonce:'1',authEpoch:'0'};
  const reference='0000000000000001'+'0000000000000064'+'ab'.repeat(16),action={kind:10,payload:{reference}};
  const state={protocol_version:'4',time_micros:'101',genesis:{genesis_time_micros:'0'}};
  assert.equal(pendingIsObsolete(account,pending,action,state),true);
  assert.equal(pendingIsObsolete(account,pending,action,{...state,time_micros:'100'}),false);
  assert.equal(pendingIsObsolete(account,pending,action,{...state,protocol_version:'2'}),false);
});
