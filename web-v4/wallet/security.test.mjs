// The wallet's account-security flows. Where bytes matter, the builders are checked against the
// fixture the engine wrote from actions it accepted (client-v4/account-security.fixture.json).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { argon2Sync, webcrypto } from 'node:crypto';
import '../../client-v4/time-sdk.js';
import * as security from '../../client-v4/account-security.mjs';
import { KDF, newDevice, openVault, validateVaultRecord, vaultIntent } from './vault.mjs';
import { sealLegacy } from './tests/legacy-vault.mjs';
import { PendingReservations } from './guards.mjs';
import { accountActionHeader } from './actions.mjs';
import { importEncryptedBackup, BACKUP_FORMAT } from './vault-backup.mjs';
import * as F from './security-flows.mjs';
import { recoveryKitSalt } from './recovery-file.mjs';

const SDK = globalThis.TimeSDK;
const source = await readFile(new URL('./vendor/argon2-4.12.0.umd.min.js', import.meta.url), 'utf8'), umd = { exports: {} };
new Function('module', 'exports', source)(umd, umd.exports);
const { argon2id } = umd.exports;
const fixture = JSON.parse(await readFile(new URL('../../client-v4/account-security.fixture.json', import.meta.url), 'utf8'));
const networkId = fixture.network_id, accountId = fixture.account.id;
const keys = {};
for (const entry of fixture.seeds) keys[entry.name] = { publicKey: entry.public_key, privateKey: await crypto.subtle.importKey('pkcs8', SDK.hexToBytes('302e020100300506032b657004220420' + entry.seed_hex), { name: 'Ed25519' }, false, ['sign']) };
const flows = F.createSecurityFlows({ security });
const hex = bytes => SDK.bytesToHex(bytes);
const rules = { threshold: '2', daily_limit_micros: '500000', delay_seconds: '60', freeze_seconds: '120' };
const device = (key, role) => ({ public_key: keys[key]?.publicKey || key, can_manage: role === 'recover' || role === 'full', can_spend: role === 'spend' || role === 'full' });
const securedAccount = (extra = {}) => ({ id: accountId, name: 'alice', balance: '10000000', nonce: fixture.account.after_secure.nonce, auth_epoch: fixture.account.after_secure.auth_epoch, recovery_policy: null,
  devices: [device('signin', 'signin'), device('spend', 'spend'), device('sheet', 'recover'), device('phrase', 'recover'), device('friend', 'recover')].sort((a, b) => a.public_key < b.public_key ? -1 : 1), ...extra });
const row = (extra = {}) => ({ account: accountId, version: '1', policy: { ...rules }, allowance_micros: '500000', allowance_elapsed_micros: '1000000000', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null, ...extra });
async function verifies(publicKey, signature, message) {
  const key = await crypto.subtle.importKey('raw', SDK.hexToBytes(publicKey), 'Ed25519', false, ['verify']);
  return crypto.subtle.verify('Ed25519', key, SDK.hexToBytes(signature), message);
}
class Storage { entries = new Map(); getItem(k) { return this.entries.has(k) ? this.entries.get(k) : null; } setItem(k, v) { this.entries.set(k, String(v)); } removeItem(k) { this.entries.delete(k); } }
const password = 'violet otters dance beneath moonlight 41', payment = 'quiet harbour lanterns at dawn 77';

// ------------------------------------------------------------------ recovery sheet
test('recovery sheet: 14 groups of 4, round trip, forgiving reading, pinned encoding', async () => {
  const seed = Uint8Array.from({ length: 32 }, (_, i) => i);
  const text = await F.encodeSheet(seed);
  assert.match(text, /^([0-9A-HJKMNP-TV-Z]{4} ){13}[0-9A-HJKMNP-TV-Z]{4}$/);
  assert.equal(text, '000G 40R4 0M30 E209 185G R38E 1W81 24GK 2GAH C5RR 34D1 P70X 3RFM VEE0');
  assert.deepEqual(await F.decodeSheet(text), seed);
  // Case, spacing and dashes do not matter; O is read as 0 and I or L as 1.
  assert.deepEqual(await F.decodeSheet(text.toLowerCase().replace(/ /g, '-')), seed);
  assert.deepEqual(await F.decodeSheet(text.replace(/ /g, '').replace(/0/g, 'O').replace(/1/g, 'l')), seed);
  // The key comes from the 32 bytes.
  const random = F.newSheetSeed(), sheet = await F.encodeSheet(random);
  assert.equal((await F.sheetKey(sheet)).publicKey, (await F.keyFromSeed(random)).publicKey);
  assert.equal((await F.sheetKey(sheet)).privateKey.extractable, false);
});

test('recovery sheet: every single typo and swap is caught, and a wrong length is named', async () => {
  const text = await F.encodeSheet(F.newSheetSeed()), chars = F.sheetCharacters(text);
  let caught = 0, tried = 0;
  for (let i = 0; i < chars.length; i++) for (const other of F.SHEET_ALPHABET) {
    if (other === chars[i]) continue; tried++;
    try { await F.decodeSheet(chars.slice(0, i) + other + chars.slice(i + 1)); } catch (error) { assert.match(error.message, /typo/); caught++; }
  }
  assert.equal(caught, tried);
  for (let i = 0; i + 1 < chars.length; i++) if (chars[i] !== chars[i + 1]) await assert.rejects(F.decodeSheet(chars.slice(0, i) + chars[i + 1] + chars[i] + chars.slice(i + 2)), /typo/);
  await assert.rejects(F.decodeSheet(chars.slice(1)), /14 groups of 4/);
  await assert.rejects(F.decodeSheet(chars + 'A'), /14 groups of 4/);
  await assert.rejects(F.decodeSheet(chars.slice(1) + 'U'), /wrong character/);
});

// ------------------------------------------------------------------ recovery passphrase
test('recovery passphrase: made by the wallet, 90 bits; the same key every time, another per network and per account, as native Argon2id computes it', async () => {
  const phrase = 'kerine netoji nesimo vebine';
  assert.ok(F.PASSPHRASE_KDF.memoryKiB >= KDF.memoryKiB && F.PASSPHRASE_KDF.iterations >= KDF.iterations && F.PASSPHRASE_KDF.parallelism === KDF.parallelism);
  // Generated: four words of three syllables, 6 bits each (16 consonants x 4 vowels): 72 bits, all values reachable.
  assert.equal(F.PASSPHRASE.bits, F.PASSPHRASE.words * F.PASSPHRASE.syllablesPerWord * 6);
  const seen = new Set();
  for (let i = 0; i < 200; i++) { const p = F.generatePassphrase(); assert.match(p, /^([bdfghjklmnprstvz][aeio]){3}( ([bdfghjklmnprstvz][aeio]){3}){4}$/); assert.equal(F.parsePassphrase(p), p); seen.add(p); }
  assert.equal(seen.size, 200);
  const zeros = F.generatePassphrase({ getRandomValues: b => b.fill(0) }), ones = F.generatePassphrase({ getRandomValues: b => b.fill(255) });
  assert.deepEqual([zeros, ones], ['bababa bababa bababa bababa bababa', 'zozozo zozozo zozozo zozozo zozozo']);
  // Five words are made; four (the words of an account made before) and five are read; any other count is refused.
  assert.deepEqual([F.PASSPHRASE.words, F.PASSPHRASE.bits, [...F.PASSPHRASE.readWords]], [5, 90, [4, 5]]);
  assert.equal(F.parsePassphrase('kerine netoji nesimo vebine'), 'kerine netoji nesimo vebine');
  assert.equal(F.parsePassphrase('KERINE netoji nesimo vebine bipori'), 'kerine netoji nesimo vebine bipori');
  for (const count of [3, 6]) assert.throws(() => F.parsePassphrase('kerine netoji nesimo vebine bipori nofoze'.split(' ').slice(0, count).join(' ')), /five of them, or four on an older account/);
  const a = await F.passphraseKey({ passphrase: phrase, networkId, accountId, argon2id });
  const again = await F.passphraseKey({ passphrase: ' KERINE  netoji-nesimo\tVebine ', networkId, accountId, argon2id });
  assert.equal(a.publicKey, again.publicKey);
  assert.equal(a.privateKey.extractable, false);
  const otherNetwork = await F.passphraseKey({ passphrase: phrase, networkId: 'ab'.repeat(32), accountId, argon2id });
  const otherAccount = await F.passphraseKey({ passphrase: phrase, networkId, accountId: '6', argon2id });
  assert.equal(new Set([a.publicKey, otherNetwork.publicKey, otherAccount.publicKey]).size, 3);
  // The salt names the network and the account, and an independent implementation gives the same seed.
  const salt = F.passphraseSalt(networkId, accountId);
  assert.equal(hex(salt), hex(new TextEncoder().encode('TCDEVNET-RECOVERY-PASSPHRASE-V1\0')) + networkId + '0000000000000005');
  const native = argon2Sync('argon2id', { message: Buffer.from(phrase), nonce: Buffer.from(salt), parallelism: 1, tagLength: 32, memory: F.PASSPHRASE_KDF.memoryKiB, passes: F.PASSPHRASE_KDF.iterations });
  assert.equal((await F.keyFromSeed(new Uint8Array(native))).publicKey, a.publicKey);
  // Chosen passphrases are refused however long; a typo is named by its word.
  assert.equal(F.checkPassphrase(phrase, { passwords: [password, payment] }), true);
  for (const chosen of [password, 'Seven lanterns over the quiet harbour', 'kerine netoji nesimo', 'kerine netoji nesimo vebine extra']) assert.throws(() => F.checkPassphrase(chosen), /five of them|not one the wallet makes/);
  assert.throws(() => F.parsePassphrase('kerine netoji nesumo vebine'), /Word 3/);
  await assert.rejects(F.passphraseKey({ passphrase: 'Seven lanterns over the quiet harbour', networkId, accountId, argon2id: async () => { throw new Error('must not derive'); } }), /five of them/);
});

// ------------------------------------------------------------------ vault intents
test('vault intents: login and payment keys in separate records, checked before any derivation', async () => {
  const signin = await newDevice(webcrypto), spend = await newDevice(webcrypto), old = await newDevice(webcrypto);
  const binding = publicKey => ({ networkId, name: 'alice', publicKey });
  const login = await sealLegacy({ pkcs8: signin.secret.pkcs8 }, password, binding(signin.publicKey), argon2id, webcrypto, 'signin');
  const pay = await sealLegacy({ pkcs8: spend.secret.pkcs8 }, payment, binding(spend.publicKey), argon2id, webcrypto, 'spend');
  const legacy = await sealLegacy({ ...old.secret, nameSalt: 'cd'.repeat(32), intent: 'device' }, password, binding(old.publicKey), argon2id, webcrypto);
  assert.deepEqual(Object.keys(pay).sort(), ['binding', 'ciphertext', 'intent', 'iv', 'kdf', 'salt', 'version']);
  assert.equal(pay.version, 2); assert.equal(vaultIntent(pay), 'spend'); assert.equal(vaultIntent(legacy), 'device'); assert.equal(legacy.version, 1);
  // Each opens for what it is.
  assert.equal((await openVault(pay, payment, argon2id, webcrypto, 'spend')).intent, 'spend');
  assert.equal((await openVault(login, password, argon2id, webcrypto)).intent, 'signin');
  assert.equal((await openVault(legacy, password, argon2id, webcrypto)).intent, 'device');
  // The default (unlock, backups) never opens a payment key, and a payment key is never read from a login record. No derivation is tried.
  let derived = 0; const counting = async () => { derived++; throw new Error('must not derive'); };
  await assert.rejects(openVault(pay, payment, counting, webcrypto), /another kind of key/);
  await assert.rejects(openVault(login, password, counting, webcrypto, 'spend'), /another kind of key/);
  await assert.rejects(openVault(legacy, password, counting, webcrypto, 'spend'), /another kind of key/);
  assert.equal(derived, 0);
  // The intent is authenticated: relabelling a record breaks it.
  await assert.rejects(openVault({ ...pay, intent: 'signin' }, payment, argon2id, webcrypto, 'signin'), /Could not unlock/);
  // No weaker or looser form: unknown intents, a version 2 without intent, a weaker KDF, extra plaintext.
  for (const bad of [{ ...pay, intent: 'device' }, { ...pay, intent: 'admin' }, (({ intent, ...rest }) => rest)(pay), { ...legacy, intent: 'spend' }, { ...pay, kdf: { ...pay.kdf, memoryKiB: 1024 } }, { ...pay, version: 3 }]) assert.throws(() => validateVaultRecord(bad), /Unsupported/);
  await assert.rejects(openVault(pay, payment, argon2id, webcrypto, 'owner'), /Invalid vault intent/);
  await assert.rejects(sealLegacy({ pkcs8: spend.secret.pkcs8, nameSalt: 'cd'.repeat(32) }, payment, binding(spend.publicKey), argon2id, webcrypto, 'spend'), /contents/);
  await assert.rejects(openVault(pay, password, argon2id, webcrypto, 'spend'), /Could not unlock/);
  // A backup file cannot carry a payment key into the login slot.
  const storage = new Storage();
  await assert.rejects(importEncryptedBackup({ text: JSON.stringify({ format: BACKUP_FORMAT, version: 1, vault: pay }), password: payment, networkId, argon2id: counting, storage, locks: { request: (n, o, f) => f() }, client: {} }), /another kind of key/);
  assert.equal(storage.entries.size, 0); assert.equal(derived, 0);
});

// ------------------------------------------------------------------ policy and passwords
test('policy defaults: 48 hours, the network minimum as a lower bound, threshold within the recovery keys', () => {
  const state = { config: { recovery_min_delay_micros: '30000000' } };
  assert.equal(F.defaultHours(state), '48'); assert.equal(F.defaultHours({ config: { recovery_min_delay_micros: String(72n * 3600n * 1000000n) } }), '72');
  assert.deepEqual(F.choosePolicy({ dailyLimitMicros: '60000000', feeMicros: '1000', minDelayMicros: '30000000' }), { threshold: '2', daily_limit_micros: '60000000', delay_seconds: '172800', freeze_seconds: '172800' });
  const production = String(2n * 86400n * 1000000n);
  assert.throws(() => F.choosePolicy({ dailyLimitMicros: '60000000', delayHours: '47', feeMicros: '1000', minDelayMicros: production }), /at least 48 hours/);
  assert.throws(() => F.choosePolicy({ dailyLimitMicros: '60000000', freezeHours: '721', feeMicros: '1000', minDelayMicros: '0' }), /30 days/);
  assert.throws(() => F.choosePolicy({ dailyLimitMicros: '60000000', threshold: '3', recoveryKeys: 2, feeMicros: '1000', minDelayMicros: '0' }), /at most 2/);
  assert.throws(() => F.choosePolicy({ dailyLimitMicros: '1000', feeMicros: '1000', minDelayMicros: '0' }), /above the network fee/);
  assert.throws(() => F.checkPasswords({ login: password, payment: password, name: 'alice' }), /differ/);
  assert.equal(F.checkPasswords({ login: password, payment, name: 'alice' }), true);
});

// ------------------------------------------------------------------ securing the account
test('securing: the same bytes the engine accepted, and the protocol-4 key is forgotten once the chain has the new keys', async () => {
  const before = { id: accountId, name: 'alice', balance: '5000000', nonce: fixture.account.before_secure.nonce, auth_epoch: fixture.account.before_secure.auth_epoch, recovery_policy: null, devices: [device('old', 'full')] };
  const built = await flows.buildSecure({ networkId, account: before, fullKey: keys.old, signin: keys.signin, spend: keys.spend, recovery: [keys.sheet, keys.phrase, keys.friend], policy: rules, feeMicros: '1000' });
  assert.deepEqual(built.payload, fixture.secure.payload);
  assert.equal(hex(built.tx), fixture.secure.action_hex);
  assert.equal(built.nonce, '1'); assert.equal(built.sequenced, true);
  await assert.rejects(flows.buildSecure({ networkId, account: before, fullKey: keys.old, signin: keys.signin, spend: keys.spend, recovery: [keys.sheet, keys.phrase], policy: rules, feeMicros: '1000' }).then(() => flows.buildSecure({ networkId, account: { ...before, recovery_policy: { guardians: [] } }, fullKey: keys.old, signin: keys.signin, spend: keys.spend, recovery: [keys.sheet, keys.phrase], policy: rules, feeMicros: '1000' })), /guardian recovery/);
  await assert.rejects(flows.buildSecure({ networkId, account: securedAccount(), fullKey: keys.spend, signin: keys.next, spend: keys.old, recovery: [keys.sheet, keys.phrase], policy: rules, feeMicros: '1000' }), /both pay and manage/);
  // Storage: the protocol-4 key's vault stays until the chain shows the new keys, then it is replaced.
  const storage = new Storage(), slots = F.vaultSlots(networkId, 'alice');
  const oldDevice = await newDevice(webcrypto), signin = await newDevice(webcrypto), spend = await newDevice(webcrypto);
  const binding = publicKey => ({ networkId, name: 'alice', publicKey });
  storage.setItem(slots.login, JSON.stringify(await sealLegacy(oldDevice.secret, password, binding(oldDevice.publicKey), argon2id, webcrypto)));
  const records = { signin: await sealLegacy({ pkcs8: signin.secret.pkcs8 }, password, binding(signin.publicKey), argon2id, webcrypto, 'signin'), spend: await sealLegacy({ pkcs8: spend.secret.pkcs8 }, payment, binding(spend.publicKey), argon2id, webcrypto, 'spend') };
  F.stageVaults(storage, slots, records);
  assert.throws(() => F.stageVaults(storage, slots, records), /earlier attempt/);
  const notYet = { devices: [{ public_key: oldDevice.publicKey, can_manage: true, can_spend: true }] };
  assert.deepEqual(F.settleStaged(storage, slots, notYet), []);
  assert.equal(JSON.parse(storage.getItem(slots.login)).binding.publicKey, oldDevice.publicKey);
  const after = { devices: [device(signin.publicKey, 'signin'), device(spend.publicKey, 'spend'), device('sheet', 'recover'), device('phrase', 'recover')] };
  assert.deepEqual(F.settleStaged(storage, slots, after), ['signin', 'spend']);
  const stored = [...storage.entries.values()].map(v => JSON.parse(v));
  assert.ok(stored.every(r => r.binding.publicKey !== oldDevice.publicKey), 'no stored record holds the protocol-4 key');
  assert.equal(vaultIntent(JSON.parse(storage.getItem(slots.login))), 'signin');
  assert.equal(F.spendRecord(storage, slots).binding.publicKey, spend.publicKey);
  assert.equal(F.hasStaged(storage, slots), false);
  // The old key signs nothing for the secured account, and websites refuse its login.
  const secured = securedAccount();
  for (const kind of [3, 10, 71, 72, 73, 75, 76, 77]) assert.throws(() => flows.assertSigner(secured, keys.old.publicKey, kind), /no longer a key/);
  assert.throws(() => flows.assertSigner(secured, keys.signin.publicKey, 3), /login key cannot/);
  assert.match(security.signInRefusal({ account: secured, security: row(), publicKey: keys.old.publicKey, nowElapsedMicros: '1' }), /not a key of the account/);
  // Staged keys go only on proof that the action is void: a state where its nonce is used and the keys are absent.
  const other = new Storage(); other.setItem(slots.login, 'kept');
  const state = (height, nonce) => ({ height: String(height), time_micros: '5', genesis: { genesis_time_micros: '0' }, account: { nonce } });
  F.stageVaults(other, slots, records, { kind: 70, nonce: '4', authEpoch: '0' });
  assert.deepEqual(F.discardStaged(other, slots, { ...notYet, nonce: '3', auth_epoch: '0' }, { state: state(9, '3') }), [], 'a state from before the block proves nothing');
  assert.deepEqual(F.discardStaged(other, slots, { ...notYet, nonce: '4', auth_epoch: '0' }), [], 'no state, no proof');
  F.stagedSeenAt(other, slots, 12);
  assert.deepEqual(F.discardStaged(other, slots, { ...notYet, nonce: '4', auth_epoch: '0' }, { state: state(11, '4') }), [], 'below the height where it was seen, nothing goes');
  assert.deepEqual(F.discardStaged(other, slots, { ...notYet, nonce: '4', auth_epoch: '0' }, { state: state(12, '4') }), ['signin', 'spend']);
  assert.equal(F.hasStaged(other, slots), false); assert.equal(other.getItem(slots.login), 'kept'); assert.equal(F.stagedNote(other, slots), null);
  // Keys staged without a note (an older wallet) are never dropped automatically.
  const legacy = new Storage(); F.stageVaults(legacy, slots, records);
  assert.deepEqual(F.discardStaged(legacy, slots, { ...notYet, nonce: '99', auth_epoch: '9' }, { state: state(99, '99') }), []);
});

// ------------------------------------------------------------------ paying
test('a payment goes as a normal transfer within the allowance, else waits or needs a recovery proof', async () => {
  const now = 1000000000n, choose = (amount, extra = {}, balance = '10000000') => flows.choosePayment({ security: row(extra), now, amount, feeMicros: '1000', balance });
  assert.equal(choose('499000').mode, 'transfer');
  const over = choose('499001');
  assert.equal(over.mode, 'over'); assert.equal(over.waitPossible, true); assert.equal(over.allowance, 500000n); assert.equal(over.total, 500001n);
  assert.equal(choose('499001', {}, '400000').mode, 'blocked');
  // Frozen: no transfer and no waiting payment, but two proofs can still pay.
  // Frozen comes first: not "over the limit", and a payment with a recovery proof stays possible.
  const frozen = choose('1', { frozen_until_elapsed_micros: String(now + 1n) });
  assert.equal(frozen.mode, 'frozen'); assert.equal(frozen.waitPossible, false); assert.match(frozen.reason, /frozen/);
  assert.equal(choose('1', { pending_root: { devices: [], policy: rules, ready_elapsed_micros: '0', expires_elapsed_micros: String(now) } }).mode, 'blocked');
  assert.equal(choose('600000', { allowance_micros: '999', allowance_elapsed_micros: String(now) }).waitPossible, false);
  assert.match(choose('600000', { pending_payments: [1, 2, 3, 4].map(id => ({ id: String(id), to: '9', amount: '1', ready_elapsed_micros: '0' })) }).waitReason, /Four/);
  // The allowance refills over 24 hours: half a day later half the limit is back.
  assert.equal(flows.choosePayment({ security: row({ allowance_micros: '0' }), now: now + 43200000000n, amount: '249000', feeMicros: '1000', balance: '10000000' }).mode, 'transfer');
  // What each choice signs.
  const account = securedAccount();
  const wait = await flows.buildWaitingPayment({ networkId, account, spend: keys.spend, to: '9', amount: '499001' });
  const decoded = SDK.decodeAction(wait.tx);
  assert.deepEqual([decoded.kind, decoded.nonce, decoded.publicKey, decoded.payload], [75, '2', keys.spend.publicKey, { type: 'request', to: '9', amount: '499001' }]);
  const now2 = 5000000000n, payNow = await flows.buildPayNow({ networkId, account, security: row(), spend: keys.spend, recovery: keys.sheet, to: '9', amount: '499001', now: now2 });
  const root = SDK.decodeAction(payNow.tx);
  assert.deepEqual([root.kind, root.nonce, root.authEpoch, root.publicKey], [73, '0', '0', keys.spend.publicKey]);
  assert.deepEqual(root.payload.op, { type: 'pay', to: '9', amount: '499001' });
  assert.ok(BigInt(root.payload.expires_elapsed_micros) - now2 <= 3600000000n);
  const message = await security.rootMessage({ networkId, accountId, version: '1', expiresElapsedMicros: root.payload.expires_elapsed_micros, operation: root.payload.op, approvers: [keys.spend.publicKey, keys.sheet.publicKey] });
  for (const approval of root.payload.approvals) assert.ok(await verifies(approval.public_key, approval.signature, message));
  await assert.rejects(flows.buildPayNow({ networkId, account, security: row(), spend: keys.spend, recovery: keys.next, to: '9', amount: '1', now: now2 }), /does not belong/);
  await assert.rejects(flows.buildWaitingPayment({ networkId, account, spend: keys.signin, to: '9', amount: '1' }), /login key cannot/);
});

test('other actions sign the bytes the engine accepted: a new spend key, a freeze, a limit change', async () => {
  const account = securedAccount();
  // The engine's root operation (a new spend key approved by spend + sheet) through the same builder every replacement uses.
  const op = security.operations.replace([security.keepKey(keys.signin.publicKey, 'signin'), await security.acceptRole({ networkId, accountId, role: 'spend', ...keys.next }), security.keepKey(keys.sheet.publicKey, 'recover'), security.keepKey(keys.phrase.publicKey, 'recover'), security.keepKey(keys.friend.publicKey, 'recover')], { ...rules });
  const replace = await flows.buildRoot({ networkId, account, security: row({ version: fixture.root.version }), operation: op, approvers: [keys.spend, keys.sheet], submitter: keys.sheet, expiresElapsedMicros: fixture.root.expires_elapsed_micros });
  assert.deepEqual(replace.payload.op, fixture.root.operation);
  assert.equal(hex(replace.tx), fixture.root.action_hex);
  assert.equal(replace.version, fixture.root.version);
  // Replacing a stolen spend key: a new spend key and a new login key; every other spend and login key goes.
  const newSignin = await newDevice(webcrypto);
  const stolen = await flows.buildReplaceSpend({ networkId, account, security: row(), spend: keys.spend, recovery: keys.sheet, newSpend: keys.next, newSignin, now: 5000000000n });
  assert.deepEqual(stolen.payload.op.keys.map(k => [k.public_key, k.role, Boolean(k.proof)]).sort(), [[keys.next.publicKey, 'spend', true], [newSignin.publicKey, 'signin', true], [keys.sheet.publicKey, 'recover', false], [keys.phrase.publicKey, 'recover', false], [keys.friend.publicKey, 'recover', false]].sort());
  await assert.rejects(flows.buildReplaceSpend({ networkId, account, security: row(), spend: keys.spend, recovery: keys.sheet, newSpend: keys.next, now: 1n }), /new login key/);
  const freeze = await flows.buildFreeze({ networkId, account: { ...account, nonce: '5', auth_epoch: '5' }, security: row(), signer: keys.sheet, now: BigInt(fixture.freeze.payload.expires_elapsed_micros) - F.FREEZE_LIFETIME_MICROS });
  assert.deepEqual(freeze.payload, fixture.freeze.payload);
  assert.equal(hex(freeze.tx), fixture.freeze.action_hex);
  assert.throws(() => flows.freezePayload({ security: row({ frozen_until_elapsed_micros: '200000000' }), now: 100000000n }), /already frozen/);
  assert.ok(flows.freezePayload({ security: row({ frozen_until_elapsed_micros: '160000000' }), now: 100000000n }));
  await assert.rejects(flows.buildFreeze({ networkId, account, security: row(), signer: keys.signin, now: 1n }), /login key cannot/);
  const limit = await flows.buildLimit({ networkId, account, security: row(), spend: keys.spend, dailyLimitMicros: fixture.limit.daily_limit_micros, feeMicros: '1000' });
  assert.equal(hex(limit.tx), fixture.limit.action_hex); assert.equal(limit.raise, true);
  assert.equal((await flows.buildLimit({ networkId, account, security: row(), spend: keys.spend, dailyLimitMicros: '400000', feeMicros: '1000' })).raise, false);
  await assert.rejects(flows.buildLimit({ networkId, account, security: row(), spend: keys.spend, dailyLimitMicros: '500000', feeMicros: '1000' }), /already has/);
  // A stolen login: the spend key adds this device's new sign-in key and removes every other one.
  const fresh = await newDevice(webcrypto), signin = await flows.buildReplaceSignin({ networkId, account, spend: keys.spend, signin: fresh });
  assert.deepEqual(signin.payload.remove, [keys.signin.publicKey]);
  assert.equal(signin.payload.add[0].public_key, fresh.publicKey);
  assert.ok(await verifies(fresh.publicKey, signin.payload.add[0].proof, security.keyMessage({ networkId, accountId, role: 'signin', publicKey: fresh.publicKey })));
  assert.equal(SDK.decodeAction(signin.tx).kind, 71);
});

// ------------------------------------------------------------------ inbox
test('the security inbox lists what waits, the freeze and the sign-in keys, with what cancels each', () => {
  const now = 10000000000n, account = securedAccount({ devices: [...securedAccount().devices, device('old', 'signin')] });
  const events = flows.inboxEvents({ account, now, ownKeys: [keys.signin.publicKey], security: row({
    pending_payments: [{ id: '3', to: '9', amount: '700000', ready_elapsed_micros: String(now - 1n) }, { id: '5', to: '8', amount: '1', ready_elapsed_micros: String(now + 60000000n) }],
    pending_limit: { id: '4', daily_limit_micros: '900000', ready_elapsed_micros: String(now + 1n) },
    pending_root: { devices: [device('next', 'spend'), device('sheet', 'recover')], policy: rules, ready_elapsed_micros: String(now + 5n), expires_elapsed_micros: String(now + 100n) },
    frozen_until_elapsed_micros: String(now + 120000000n),
  }) });
  const byType = type => events.filter(e => e.type === type);
  assert.deepEqual(byType('payment').map(e => [e.id, e.readyNow, e.cancel.kind, e.cancel.payload]), [['3', true, 76, { type: 'payment', id: '3' }], ['5', false, 76, { type: 'payment', id: '5' }]]);
  assert.deepEqual(byType('payment')[0].execute, { kind: 75, payload: { type: 'execute', id: '3' } });
  assert.deepEqual(byType('limit').map(e => [e.id, e.dailyLimit, e.cancel.payload]), [['4', '900000', { type: 'limit', id: '4' }]]);
  const [replacement] = byType('replacement');
  assert.equal(replacement.readyNow, false); assert.deepEqual(replacement.cancel, { kind: 73, operation: { type: 'cancel' } });
  assert.deepEqual(replacement.keys.map(k => [k.role, k.known]), [['spend', false], ['recover', true]]);
  assert.deepEqual(byType('frozen').map(e => [e.frozen, e.until, e.canFreeze]), [[true, now + 120000000n, false]]);
  assert.deepEqual(byType('signin').map(e => [e.publicKey, e.mine]).sort(), [[keys.old.publicKey, false], [keys.signin.publicKey, true]].sort());
  // A raise whose wait is over has applied, and an expired replacement is gone.
  const later = flows.inboxEvents({ account, now: now + 200n, security: row({ pending_limit: { id: '4', daily_limit_micros: '900000', ready_elapsed_micros: String(now + 1n) }, pending_root: { devices: [], policy: rules, ready_elapsed_micros: String(now), expires_elapsed_micros: String(now + 100n) } }) });
  assert.deepEqual(later.map(e => e.type).filter(t => t !== 'signin'), ['frozen']);
  assert.equal(later.find(e => e.type === 'frozen').frozen, false);
});

// ------------------------------------------------------------------ lost device
test('lost device: the two recovery keys ask for new sign-in and spend keys, and the new spend key finishes', async () => {
  const account = securedAccount(), now = 7000000000n, security1 = row();
  const signin = await newDevice(webcrypto), spend = await newDevice(webcrypto);
  const request = await flows.buildLostDeviceRequest({ networkId, account, security: security1, sheet: keys.sheet, phrase: keys.phrase, signin, spend, now });
  const action = SDK.decodeAction(request.tx);
  assert.deepEqual([action.kind, action.from, action.nonce, action.authEpoch, action.publicKey], [73, accountId, '0', '0', keys.sheet.publicKey]);
  const op = action.payload.op;
  assert.equal(op.type, 'replace'); assert.deepEqual(op.policy, rules);
  // New sign-in and spend keys with their acceptances; every recovery key kept; the lost keys gone.
  const entry = key => op.keys.find(k => k.public_key === key);
  assert.equal(entry(keys.signin.publicKey), undefined); assert.equal(entry(keys.spend.publicKey), undefined);
  for (const name of ['sheet', 'phrase', 'friend']) assert.deepEqual(entry(keys[name].publicKey), { public_key: keys[name].publicKey, role: 'recover' });
  for (const [key, role] of [[signin, 'signin'], [spend, 'spend']]) assert.ok(await verifies(key.publicKey, entry(key.publicKey).proof, security.keyMessage({ networkId, accountId, role, publicKey: key.publicKey })));
  assert.deepEqual(op.keys.map(k => k.public_key), [...op.keys.map(k => k.public_key)].sort());
  const message = await security.rootMessage({ networkId, accountId, version: '1', expiresElapsedMicros: action.payload.expires_elapsed_micros, operation: op, approvers: [keys.sheet.publicKey, keys.phrase.publicKey] });
  assert.equal(action.payload.approvals.length, 2);
  for (const approval of action.payload.approvals) assert.ok(await verifies(approval.public_key, approval.signature, message));
  assert.equal(BigInt(action.payload.expires_elapsed_micros) - now, F.APPROVAL_LIFETIME_MICROS);
  // Refused: a sheet of another account, the same key twice, a replacement already waiting, an account that is not secured.
  await assert.rejects(flows.buildLostDeviceRequest({ networkId, account, security: security1, sheet: keys.next, phrase: keys.phrase, signin, spend, now }), /recovery sheet does not belong/);
  await assert.rejects(flows.buildLostDeviceRequest({ networkId, account, security: security1, sheet: keys.sheet, phrase: keys.spend, signin, spend, now }), /recovery passphrase does not belong/);
  await assert.rejects(flows.buildLostDeviceRequest({ networkId, account, security: security1, sheet: keys.sheet, phrase: keys.sheet, signin, spend, now }), /different keys/);
  await assert.rejects(flows.buildLostDeviceRequest({ networkId, account, security: row({ pending_root: {} }), sheet: keys.sheet, phrase: keys.phrase, signin, spend, now }), /already waiting/);
  await assert.rejects(flows.buildLostDeviceRequest({ networkId, account, security: null, sheet: keys.sheet, phrase: keys.phrase, signin, spend, now }), /not secured/);
  // What survives a reload: public keys and counters, nothing secret.
  const progress = F.progressRecord({ networkId, account, signin: signin.publicKey, spend: spend.publicKey });
  assert.deepEqual(F.parseProgress(JSON.stringify(progress)), progress);
  assert.deepEqual(Object.keys(progress).sort(), ['accountId', 'name', 'networkId', 'signin', 'spend', 'version']);
  assert.throws(() => F.parseProgress(JSON.stringify({ ...progress, sheet: 'ABCD' })), /damaged/);
  assert.equal(F.parseProgress(null), null);
  // The chain now waits; the account is frozen meanwhile.
  const ready = now + 60000000n, newSet = op.keys.map(k => ({ public_key: k.public_key, can_manage: k.role === 'recover', can_spend: k.role === 'spend' }));
  const waiting = row({ version: '2', pending_root: { devices: newSet, policy: rules, ready_elapsed_micros: String(ready), expires_elapsed_micros: String(ready + 86400000000n) } });
  assert.equal(security.frozen(waiting, now), true);
  const status = F.recoveryStatus({ progress, account, security: waiting, now: now + 1n });
  assert.equal(status.stage, 'waiting'); assert.equal(status.remainingMicros, ready - now - 1n);
  await assert.rejects(flows.buildFinalize({ networkId, account, security: waiting, spend, now: ready - 1n }), /not over/);
  assert.equal(F.recoveryStatus({ progress, account, security: waiting, now: ready }).stage, 'ready');
  const finish = await flows.buildFinalize({ networkId, account, security: waiting, spend, now: ready });
  const finished = SDK.decodeAction(finish.tx);
  assert.deepEqual([finished.kind, finished.nonce, finished.publicKey, finished.payload], [74, '0', spend.publicKey, { version: '2' }]);
  await assert.rejects(flows.buildFinalize({ networkId, account, security: waiting, spend: signin, now: ready }), /does not name/);
  assert.equal(F.recoveryStatus({ progress, account: { ...account, devices: newSet }, security: row({ version: '3' }), now: ready }).stage, 'done');
  assert.equal(F.recoveryStatus({ progress, account, security: row({ version: '3' }), now: ready }).stage, 'none');
  assert.equal(F.recoveryStatus({ progress, account, security: waiting, now: ready + 86400000001n }).stage, 'none');
  // Its reservation has no nonce: it is retired when the version moves on or its approvals expire.
  const pendingStore = new PendingReservations(new Storage()), slot = F.protectiveSlot(73, accountId), hash = await SDK.transactionHash(request.tx);
  pendingStore.put(networkId, slot, { hash, tx: 'dHg=', nonce: request.nonce, authEpoch: request.authEpoch, kind: 73, version: request.version });
  assert.equal(pendingStore.get(networkId, slot).version, '1');
  const reservation = { kind: 73, payload: action.payload, version: request.version };
  assert.equal(F.protectiveObsolete(reservation, security1, now), false);
  assert.equal(F.protectiveObsolete(reservation, waiting, now), true);
  assert.equal(F.protectiveObsolete(reservation, security1, BigInt(action.payload.expires_elapsed_micros)), true);
  assert.equal(F.protectiveObsolete({ kind: 72, payload: fixture.freeze.payload }, row(), 1n), false);
  assert.equal(F.protectiveObsolete({ kind: 72, payload: fixture.freeze.payload }, row({ freezes: '1' }), 1n), true);
  assert.equal(F.protectiveObsolete({ kind: 76, payload: { type: 'payment', id: '3' } }, row({ pending_payments: [{ id: '3' }] }), 1n), false);
  assert.equal(F.protectiveObsolete({ kind: 76, payload: { type: 'payment', id: '3' } }, row(), 1n), true);
  assert.equal(F.protectiveObsolete({ kind: 74, payload: { version: '2' } }, waiting, 1n), false);
});

test('an account without a full key is read with its security row', () => {
  assert.equal(F.needsSecurityRow(securedAccount()), true);
  assert.equal(F.needsSecurityRow({ devices: [device('old', 'full'), device('spend', 'spend')] }), false);
  assert.equal(F.needsSecurityRow(undefined), false);
  assert.throws(() => flows.rowOf({ accounts: [] }, securedAccount()), /not proven/);
  assert.equal(flows.rowOf({ security: [] }, securedAccount()), null);
});

// ------------------------------------------------------------------ a removed login key, the other tabs, one inbox
test('this browser\'s login key was removed: the payment key can make a new one unless frozen; old records give way to a recovery', async () => {
  const account = securedAccount(), now = 1000000000n;
  assert.deepEqual(flows.removedLogin({ account, security: row(), spendKey: keys.spend.publicKey, now }), { spendUsable: true, frozen: false, replacing: false, canReplaceLogin: true });
  assert.equal(flows.removedLogin({ account, security: row({ frozen_until_elapsed_micros: String(now + 1n) }), spendKey: keys.spend.publicKey, now }).canReplaceLogin, false);
  const replacing = flows.removedLogin({ account, security: row({ pending_root: { devices: [], policy: rules, ready_elapsed_micros: String(now), expires_elapsed_micros: String(now + 5n) } }), spendKey: keys.spend.publicKey, now });
  assert.deepEqual([replacing.replacing, replacing.frozen, replacing.canReplaceLogin], [true, true, false]);
  assert.equal(flows.removedLogin({ account, security: row(), spendKey: keys.next.publicKey, now }).spendUsable, false);
  assert.equal(flows.removedLogin({ account, security: row(), spendKey: null, now }).canReplaceLogin, false);
  // Before a recovery on this browser: a removed login key's record is replaced; a live key's record never is.
  const storage = new Storage(), slots = F.vaultSlots(networkId, 'alice'), binding = publicKey => ({ networkId, name: 'alice', publicKey });
  const gone = await newDevice(webcrypto), spend = await newDevice(webcrypto);
  assert.deepEqual(F.lostDeviceSlots(storage, slots, account), { stale: [], blocked: null });
  storage.setItem(slots.login, JSON.stringify(await sealLegacy({ pkcs8: gone.secret.pkcs8 }, password, binding(gone.publicKey), argon2id, webcrypto, 'signin')));
  storage.setItem(slots.spend, JSON.stringify(await sealLegacy({ pkcs8: spend.secret.pkcs8 }, payment, binding(spend.publicKey), argon2id, webcrypto, 'spend')));
  assert.deepEqual(F.lostDeviceSlots(storage, slots, account), { stale: [slots.login, slots.spend], blocked: null });
  const withSpend = { ...account, devices: [...account.devices, device(spend.publicKey, 'spend')] };
  assert.match(F.lostDeviceSlots(storage, slots, withSpend).blocked, /still holds a payment key/);
  const withLogin = { ...account, devices: [...account.devices, device(gone.publicKey, 'signin')] };
  assert.match(F.lostDeviceSlots(storage, slots, withLogin).blocked, /can still unlock @alice/);
  storage.setItem(slots.login, '{broken');
  assert.match(F.lostDeviceSlots(storage, slots, account).blocked, /damaged/);
});

test('on a secured account no protocol-4 device or guardian action is offered, and keys are named by what they do', () => {
  const classic = { devices: [device('old', 'full')] };
  const all = F.protocol4Actions(classic, keys.old.publicKey, false);
  assert.ok(Object.values(all).every(Boolean));
  for (const [account, key] of [[securedAccount(), keys.signin.publicKey], [securedAccount(), keys.spend.publicKey], [securedAccount(), keys.sheet.publicKey], [classic, keys.old.publicKey]]) {
    assert.ok(Object.values(F.protocol4Actions(account, key, true)).every(v => v === false), 'nothing offered for ' + key);
  }
  // A protocol-4 account with a spend-only device: no management.
  assert.deepEqual(Object.entries(F.protocol4Actions({ devices: [device('spend', 'spend')] }, keys.spend.publicKey, false)).filter(([, v]) => v).map(([k]) => k), ['stakeAndEarn']);
  const rows = F.deviceRows(securedAccount(), [keys.signin.publicKey, keys.spend.publicKey]);
  assert.deepEqual(rows.map(r => [r.role, r.title]).sort(), [['recover', 'Recovery key'], ['recover', 'Recovery key'], ['recover', 'Recovery key'], ['signin', 'Login key of this browser'], ['spend', 'Payment key of this browser']].sort());
  assert.ok(rows.every(r => !/revoke|manage devices/i.test(r.title + r.detail)));
});

test('one inbox count: waiting items, a freeze, and guardian recoveries of the account', () => {
  const now = 10000000000n, account = securedAccount();
  const events = flows.inboxEvents({ account, now, security: row({ pending_payments: [{ id: '3', to: '9', amount: '1', ready_elapsed_micros: '0' }], pending_limit: { id: '4', daily_limit_micros: '900000', ready_elapsed_micros: String(now + 1n) }, frozen_until_elapsed_micros: String(now + 1n) }) });
  assert.equal(flows.inboxCount({ events, accountId }), 3);
  assert.equal(flows.inboxCount({ events: flows.inboxEvents({ account, now, security: row() }), accountId }), 0);
  // A waiting replacement freezes the account: counted once.
  const waiting = flows.inboxEvents({ account, now, security: row({ pending_root: { devices: [], policy: rules, ready_elapsed_micros: String(now + 1n), expires_elapsed_micros: String(now + 2n) } }) });
  assert.equal(flows.inboxCount({ events: waiting, accountId }), 1);
  assert.equal(flows.inboxCount({ recoveryCases: [{ target: accountId }, { target: '99' }], accountId }), 1);
});

test('a device that cannot run the 256 MiB passphrase calculation is told to use a computer; nothing lighter is tried', async () => {
  const calls = [];
  const failing = async options => { calls.push(options.memorySize); throw new RangeError('WebAssembly.Memory(): could not allocate memory'); };
  await assert.rejects(F.passphraseKey({ passphrase: F.generatePassphrase(), networkId, accountId, argon2id: failing }), error => error.message === F.PASSPHRASE_TOO_HEAVY);
  assert.deepEqual(calls, [262144]);
  assert.match(F.PASSPHRASE_TOO_HEAVY, /256 MiB.*computer.*no lighter version/s);
});

// ------------------------------------------------------------------ staking from a secured account
test('the payment key signs an explicit list: payments, Staking\'s staking and the operation of a validator, nothing else', () => {
  for (const kind of ['transfer', 'merchant_payment', 'delegate', 'undelegate', 'withdraw_stake', 'register_validator', 'self_bond', 'self_unbond', 'retire_validator']) assert.equal(F.assertSpendKeyKind(kind), true);
  for (const kind of ['add_device', 'revoke_device', 'set_recovery', 'consent_recovery', 'cancel_pending', 'reveal', 'bid', 'bitcoin_bid', 'claim_auction', 'double_vote', 'withdraw', 'secure_account', 'root_operation', 5, 17, 'DELEGATE', 'Register_validator', undefined]) assert.throws(() => F.assertSpendKeyKind(kind), /payments and staking only/, String(kind));
  // On the account, only the spend key may sign staking kinds; never the login key, a recovery key or the old full key
  // (v5/src/engine.rs, `apply`: "spending device required").
  const account = securedAccount();
  for (const kind of [5, 6, 17, 18, 19, 21, 24]) {
    flows.assertSigner(account, keys.spend.publicKey, kind);
    assert.throws(() => flows.assertSigner(account, keys.signin.publicKey, kind), /login key cannot/);
    assert.throws(() => flows.assertSigner(account, keys.sheet.publicKey, kind), /cannot do this/);
    assert.throws(() => flows.assertSigner(account, keys.old.publicKey, kind), /no longer a key/);
  }
});

test('a stake must fit today\'s allowance, fee included; above it the person raises the limit or stakes in parts; frozen means refused', () => {
  const now = 1000000000n, check = (amount, extra = {}, balance = '10000000') => flows.checkStake({ security: row(extra), now, outflowMicros: F.stakeOutflow('delegate', { amount }, '1000'), feeMicros: '1000', balance });
  assert.equal(F.stakeOutflow('delegate', { amount: '7' }, '1000'), 1007n);
  assert.equal(F.stakeOutflow('undelegate', { operator: '9', shares: '5', min_amount: '5' }, '1000'), 1000n);
  assert.equal(F.stakeOutflow('withdraw_stake', { entry: '3' }, '1000'), 1000n);
  // A validator's operation: an addition to its bond takes the amount and the fee, a registration the bond (the network's
  // least, or the one its payload names) and the fee, taking out and retiring the fee only (v5/src/pos_adapter.rs).
  assert.equal(F.stakeOutflow('self_bond', { amount: '7' }, '1000'), 1007n);
  assert.equal(F.stakeOutflow('register_validator', { commission_bps: 0, consensus_key: 'ab'.repeat(32), proof: 'ab'.repeat(64) }, '1000', { bondMicros: 1000000n }), 1001000n);
  assert.equal(F.stakeOutflow('register_validator', { self_bond: '2000000' }, '1000', { bondMicros: 1000000n }), 2001000n);
  assert.throws(() => F.stakeOutflow('register_validator', {}, '1000'), /whole number/);
  assert.equal(F.stakeOutflow('self_unbond', { amount: '5', min_amount: '5' }, '1000'), 1000n);
  assert.equal(F.stakeOutflow('retire_validator', {}, '1000'), 1000n);
  assert.throws(() => F.stakeOutflow('withdraw', { entry: '3' }, '1000'), /payments and staking only/);
  assert.deepEqual([F.minSelfBond({ pos: { profile: 'laboratory' } }), F.minSelfBond({ pos: { profile: 'production' } })], [1000000n, 86400000000n]);
  for (const state of [{}, { pos: { profile: 'other' } }, { pos: { profile: 'toString' } }]) assert.throws(() => F.minSelfBond(state), /does not know the least bond/);
  assert.deepEqual(check('499000'), { allowance: 500000n, total: 500000n, mode: 'ok' });
  const over = check('499001');
  assert.equal(over.mode, 'over'); assert.equal(over.fitsToday, 499000n); assert.equal(over.dailyLimit, 500000n); assert.equal(over.delaySeconds, 60n);
  assert.equal(check('1', { allowance_micros: '500', allowance_elapsed_micros: String(now) }).fitsToday, 0n);
  // Frozen by a freeze, or while a change of keys waits: refused, whatever the amount.
  for (const extra of [{ frozen_until_elapsed_micros: String(now + 1n) }, { pending_root: { devices: [], policy: rules, ready_elapsed_micros: String(now + 1n), expires_elapsed_micros: String(now + 2n) } }]) {
    const frozen = check('1', extra);
    assert.equal(frozen.mode, 'frozen'); assert.match(frozen.reason, /frozen.*See Home\./);
  }
  assert.equal(check('1', { frozen_until_elapsed_micros: String(now) }).mode, 'ok');
  assert.equal(check('5000', {}, '5999').mode, 'blocked');
});

test('a stake signed by the spend key has the form the engine checks: next nonce, current epoch, a key that can spend', async () => {
  const account = securedAccount();
  const header = accountActionHeader({ account, publicKey: keys.spend.publicKey, networkId, kind: 'delegate', payload: { operator: '9', amount: '2000000', min_shares: '1' } });
  const tx = await SDK.signAction(header, keys.spend.privateKey), action = SDK.decodeAction(tx);
  assert.deepEqual([action.kind, action.from, action.nonce, action.authEpoch, action.publicKey], [5, accountId, String(BigInt(account.nonce) + 1n), account.auth_epoch, keys.spend.publicKey]);
  assert.deepEqual(action.payload, { operator: '9', amount: '2000000', min_shares: '1' });
  assert.ok(account.devices.find(d => d.public_key === action.publicKey).can_spend, 'the engine requires a device with can_spend');
  const signingBytes = tx.slice(0, tx.length - 64);
  assert.ok(await verifies(keys.spend.publicKey, SDK.bytesToHex(tx.slice(tx.length - 64)), signingBytes));
  const withdraw = SDK.decodeAction(await SDK.signAction(accountActionHeader({ account, publicKey: keys.spend.publicKey, networkId, kind: 'withdraw_stake', payload: { entry: '3' } }), keys.spend.privateKey));
  assert.deepEqual([withdraw.kind, withdraw.payload], [21, { entry: '3' }]);
  // The login key has no can_spend: no staking header is built for it.
  assert.throws(() => accountActionHeader({ account, publicKey: keys.signin.publicKey, networkId, kind: 'delegate', payload: {} }), /permission/);
});

test('a field that takes either recovery key tells the four words from a printed sheet by the text alone', async () => {
  const sheet = await F.encodeSheet(F.newSheetSeed()), words = F.generatePassphrase();
  for (const typed of [words, words.toUpperCase(), ` ${words.replace(/ /g, ' - ')} `, 'kerine netoji nesumo vebine', 'kerine netoji nesimo', 'kerinenetojinesimovebine']) assert.equal(F.recoveryPaperKind(typed), 'words', typed);
  for (const typed of [sheet, sheet.toLowerCase(), sheet.replace(/ /g, ''), sheet.replace(/ /g, '-'), 'ABCD EFGH', '000G 40R4', '', '12345678']) assert.equal(F.recoveryPaperKind(typed), 'sheet', typed);
  assert.equal(F.recoveryPaperKind(undefined), 'sheet');
});

test('words only: the words give two recovery keys of their own, neither of them the key of a Recovery Kit, as an independent Argon2id computes them', async () => {
  const words = 'kerine netoji nesimo vebine bipori', registrationKey = 'ab'.repeat(32), enc = text => hex(new TextEncoder().encode(text));
  // The salts: a domain of their own, the network, and the account's number or its registration key, as the first's.
  const salt = F.secondWordsSalt(networkId, accountId), regSalt = F.secondWordsRegistrationSalt(networkId, registrationKey);
  assert.equal(hex(salt), enc('TCDEVNET-RECOVERY-WORDS-SECOND-V1\0') + networkId + BigInt(accountId).toString(16).padStart(16, '0'));
  assert.equal(hex(regSalt), enc('TCDEVNET-RECOVERY-WORDS-SECOND-REGISTRATION-V1\0') + networkId + registrationKey);
  const first = await F.passphraseKey({ passphrase: words, networkId, accountId, argon2id }), second = await F.recoveryWordsSecondKey({ passphrase: words, networkId, accountId, argon2id });
  const native = nonce => argon2Sync('argon2id', { message: Buffer.from(words), nonce: Buffer.from(nonce), parallelism: 1, tagLength: 32, memory: F.PASSPHRASE_KDF.memoryKiB, passes: F.PASSPHRASE_KDF.iterations });
  const secondSeed = native(salt);
  assert.equal((await F.keyFromSeed(new Uint8Array(secondSeed))).publicKey, second.publicKey);
  assert.equal((await F.keyFromSeed(new Uint8Array(native(regSalt)))).publicKey, (await F.recoveryWordsSecondKey({ passphrase: ' ' + words.toUpperCase(), networkId, registrationKey, argon2id })).publicKey);
  // Two keys, each its own, and none the key that locks a Recovery Kit of the same words.
  const kitKey = native(recoveryKitSalt(new Uint8Array(16)));
  assert.notEqual(first.publicKey, second.publicKey);
  assert.equal(new Set([hex(native(F.passphraseSalt(networkId, accountId))), hex(secondSeed), hex(kitKey)]).size, 3);
});

test('the kind of an account\'s recovery keys is told from its words: both keys from the words is "words only"; a first key without its second is an account with a sheet', async () => {
  const quick = async ({ password, salt }) => new Uint8Array(await webcrypto.subtle.digest('SHA-256', new Uint8Array([...password, ...salt])));
  const words = 'kerine netoji nesimo vebine bipori', registrationKey = 'cd'.repeat(32), sheet = await newDevice(webcrypto);
  const key = async (args, second = false) => (await F.passphraseKey({ passphrase: words, networkId, argon2id: quick, second, ...args })).publicKey;
  const byNumber = [await key({ accountId }), await key({ accountId }, true)], byRegistration = [await key({ registrationKey }), await key({ registrationKey }, true)];
  const kindOf = async (recover, registered = false) => {
    const found = await F.accountWordsKeys({ passphrase: words, networkId, account: { id: accountId, public_key: registrationKey }, registered, isRecovery: k => recover.includes(k.publicKey), argon2id: quick });
    return [found.first.publicKey, found.second?.publicKey ?? null];
  };
  assert.deepEqual(await kindOf(byNumber), byNumber, 'words only, by the account number');
  assert.deepEqual(await kindOf([byNumber[0], sheet.publicKey]), [byNumber[0], null], 'words and a sheet');
  assert.deepEqual(await kindOf(byRegistration, true), byRegistration, 'words only, from a protected sign-up');
  assert.deepEqual(await kindOf([byRegistration[0], sheet.publicKey], true), [byRegistration[0], null]);
  // Words that are not the account's: the first key by number is returned, to be refused, and nothing more is computed.
  assert.deepEqual(await kindOf([sheet.publicKey]), [byNumber[0], null]);
});
