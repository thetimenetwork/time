// "Lock my keys to this device" (device-lock.mjs, vault.mjs version 3) against a fake authenticator: a device that makes
// keys, checks the person and gives PRF secrets the way CTAP2 hmac-secret does, for one or two salts in a request (as the
// fake of device-key.test.mjs, with the second salt). Stand-ins only: a storage in memory, a quick stand-in for Argon2id
// (SHA-256 of the password and the salt: vault.mjs fixes the parameters it asks for; the real Argon2id runs in the other
// vault tests), WebCrypto of Node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes, webcrypto } from 'node:crypto';
import { newDevice, sealVault, openVault, validateVaultRecord, vaultDevice, DEVICE_NEEDED } from './vault.mjs';
import { turnOn, turnOff, remakePasswords, lockOf, lockSalt, settleSwap, lockPlaces, createLockAsker, deviceSecrets, credentialInUse, LOCK_WORDS, LOCK_LABEL, DEVICE_KEY_PLACE } from './device-lock.mjs';
import { vaultSlots, sealsOf, sealedKeys, stageVaults, settleStaged, storeLoginRequest, settleLoginRequest, lostDeviceSlots } from './security-flows.mjs';
import { createPrivateStore, withReceipt } from './locked-store.mjs';
import { sealLegacy } from './tests/legacy-vault.mjs';

const NET = 'c6'.repeat(32), LOGIN = 'violet otters dance beneath moonlight 41', PAYMENT = 'quiet harbour lanterns at dawn 77';
const argon2id = async ({ password, salt }) => new Uint8Array(createHash('sha256').update(Buffer.from(password)).update(Buffer.from(salt)).digest());
let argonCalls = 0;
const countingArgon = async input => { argonCalls += 1; return argon2id(input); };

class Storage {
  m = new Map(); failAt = null; writes = 0;
  get length() { return this.m.size; }
  key(i) { return [...this.m.keys()][i] ?? null; }
  getItem(k) { return this.m.has(k) ? this.m.get(k) : null; }
  setItem(k, v) { this.writes += 1; if (this.failAt !== null && this.writes === this.failAt) throw new Error('the page closed'); this.m.set(k, String(v)); }
  removeItem(k) { this.m.delete(k); }
  copy() { const c = new Storage(); for (const [k, v] of this.m) c.m.set(k, v); return c; }
}

// ------------------------------------------------------------------ a device
const prfOf = (key, salt) => createHmac('sha256', key).update(createHash('sha256').update(Buffer.concat([Buffer.from('WebAuthn PRF'), Buffer.from([0]), Buffer.from(salt)])).digest()).digest();
const buffer = bytes => { const copy = new ArrayBuffer(bytes.length); new Uint8Array(copy).set(bytes); return copy; };
/// `s`: switches. createError / getErrors (one error name per request, in order) / secondDiffers (the n-th request
/// answers from another secret) / noPrf.
function fakeDevice(s = {}) {
  const keys = [], calls = [];
  let gets = 0;
  const authData = () => { const b = new Uint8Array(37); b[32] = 0x05; return buffer(b); };
  class PublicKeyCredential { static async isUserVerifyingPlatformAuthenticatorAvailable() { return true; } static async getClientCapabilities() { return { userVerifyingPlatformAuthenticator: true, 'extension:prf': !s.noPrf }; } }
  const credentials = {
    async create(options) {
      calls.push(['create', options]);
      if (s.createError) throw new DOMException('x', s.createError);
      const handle = Buffer.from(options.publicKey.user.id);
      for (let i = keys.length - 1; i >= 0; i--) if (keys[i].handle.equals(handle)) keys.splice(i, 1);
      const key = { id: randomBytes(32), secret: randomBytes(32), handle };
      keys.push(key);
      return { type: 'public-key', rawId: buffer(key.id), response: { getAuthenticatorData: () => authData() }, getClientExtensionResults: () => ({ prf: { enabled: !s.noPrf } }) };
    },
    async get(options) {
      calls.push(['get', options]); gets += 1;
      const error = s.getErrors?.[gets - 1]; if (error) throw new DOMException('x', error);
      if (!keys.length) throw new DOMException('x', 'NotAllowedError');
      const key = keys.at(-1), salts = options.publicKey.extensions.prf.eval, secret = s.secondDiffers === gets ? randomBytes(32) : key.secret;
      const results = { first: buffer(prfOf(secret, salts.first)), ...(salts.second ? { second: buffer(prfOf(secret, salts.second)) } : {}) };
      return { type: 'public-key', rawId: buffer(key.id), response: { authenticatorData: authData() }, getClientExtensionResults: () => ({ prf: { results } }) };
    },
  };
  return { env: { secureContext: true, credentials, PublicKeyCredential, crypto: webcrypto, phone: false }, keys, calls, remove: () => keys.splice(0), gets: () => gets };
}
const creates = device => device.calls.filter(([kind]) => kind === 'create');
const getsOf = device => device.calls.filter(([kind]) => kind === 'get');

/// A browser that holds a protected account's login key and payment key, sealed with their passwords alone: as a browser
/// kept them before the rule (vault.mjs, RULE), when the person chose them (tests/legacy-vault.mjs).
async function account(storage, name = 'alice') {
  const slots = vaultSlots(NET, name), [signin, spend] = [await newDevice(webcrypto), await newDevice(webcrypto)];
  storage.setItem(slots.login, JSON.stringify(await sealLegacy({ pkcs8: signin.secret.pkcs8 }, LOGIN, { networkId: NET, name, publicKey: signin.publicKey }, argon2id, webcrypto, 'signin')));
  storage.setItem(slots.spend, JSON.stringify(await sealLegacy({ pkcs8: spend.secret.pkcs8 }, PAYMENT, { networkId: NET, name, publicKey: spend.publicKey }, argon2id, webcrypto, 'spend')));
  return { slots, name, signin: signin.publicKey, spend: spend.publicKey, login: LOGIN, payment: PAYMENT };
}
// The passwords of an account now: those it was made with, and after the lock was turned off, those the wallet made then.
const on = (storage, device, a, extra = {}) => turnOn({ storage, slots: a.slots, networkId: NET, name: a.name, login: a.login, payment: a.payment, argon2id, env: device.env, cryptoImpl: webcrypto, ...extra });
const off = async (storage, device, a, extra = {}) => { const done = await turnOff({ storage, slots: a.slots, networkId: NET, name: a.name, login: a.login, payment: a.payment, argon2id, env: device.env, cryptoImpl: webcrypto, ...extra }); a.login = done.made.login; a.payment = done.made.payment; return done; };
const record = (storage, key) => JSON.parse(storage.getItem(key));
/// The device's answer for a record, as the wallet asks it (one request).
const secretFor = async (device, r) => (await deviceSecrets(device.env, { credentialId: vaultDevice(r), salts: [lockSalt({ purpose: r.intent === 'spend' ? 'spend' : 'login', networkId: NET, name: r.binding.name, publicKey: r.binding.publicKey })] }))[0];
/// Every vault-like record this browser keeps, by place.
const vaults = storage => [...storage.m].filter(([k]) => /^timecurrency\.(vault\.v1|spend-vault\.v1|vault-next\.v1|login-request\.v1|vault-lock\.v1):/.test(k)).map(([k, v]) => [k, JSON.parse(v)]).map(([k, v]) => [k, v.record ?? v]).filter(([, v]) => v && v.version);

test('the vault of version 3: the device\'s secret and the password together; without the secret it is refused before any derivation, and tampered it opens for nobody', async () => {
  const key = await newDevice(webcrypto), binding = { networkId: NET, name: 'alice', publicKey: key.publicKey }, secret = new Uint8Array(randomBytes(32)), credential = Buffer.from(randomBytes(32)).toString('base64url');
  const r = await sealVault({ pkcs8: key.secret.pkcs8 }, LOGIN, binding, argon2id, webcrypto, 'signin', { credential, secret });
  assert.deepEqual(Object.keys(r).sort(), ['binding', 'ciphertext', 'device', 'intent', 'iv', 'kdf', 'salt', 'version']);
  assert.deepEqual([r.version, r.intent, r.device], [3, 'signin', { credential }]);
  assert.equal(vaultDevice(r), credential);
  assert.equal((await openVault(r, LOGIN, argon2id, webcrypto, 'signin', secret)).binding.publicKey, key.publicKey);
  // Without the device: refused at once, nothing derived.
  argonCalls = 0;
  await assert.rejects(openVault(r, LOGIN, countingArgon, webcrypto, 'signin'), error => error.deviceNeeded === true && error.message === DEVICE_NEEDED);
  assert.equal(argonCalls, 0);
  // Another device's secret, or the wrong password: the same refusal as a wrong password.
  await assert.rejects(openVault(r, LOGIN, argon2id, webcrypto, 'signin', new Uint8Array(randomBytes(32))), /Could not unlock/);
  await assert.rejects(openVault(r, `${LOGIN}x`, argon2id, webcrypto, 'signin', secret), /Could not unlock/);
  // Made to look password-only (version 2, no device): it does not open with the password alone.
  const { device, ...rest } = r;
  await assert.rejects(openVault({ ...rest, version: 2 }, LOGIN, argon2id, webcrypto, 'signin'), /Could not unlock/);
  // Another device key named in it: refused (the header is the authenticated data and the HKDF info).
  await assert.rejects(openVault({ ...r, device: { credential: Buffer.from(randomBytes(32)).toString('base64url') } }, LOGIN, argon2id, webcrypto, 'signin', secret), /Could not unlock/);
  // A client from before version 3 knows versions 1 and 2 and their exact fields only: this record is neither.
  assert.equal([1, 2].includes(r.version), false); assert.notEqual(Object.keys(r).sort().join(','), 'binding,ciphertext,intent,iv,kdf,salt,version');
  // Only login and payment keys are locked; the fields are as strict as ever.
  await assert.rejects(sealVault({ pkcs8: key.secret.pkcs8, nameSalt: 'aa'.repeat(32) }, LOGIN, binding, argon2id, webcrypto, 'device', { credential, secret }), /login key or a payment key/);
  assert.throws(() => validateVaultRecord({ ...r, device: { credential, extra: 1 } }, 'signin'), /Invalid vault device/);
  assert.throws(() => validateVaultRecord({ ...r, device: { credential: 'not base64url!' } }, 'signin'), /Invalid vault device/);
});

test('turning it on: both passwords, then the device made and asked twice; both records replaced only once both open with the second answer; no password-only copy stays', async () => {
  const storage = new Storage(), device = fakeDevice(), a = await account(storage), said = [];
  const result = await on(storage, device, a, { say: text => said.push(text) });
  assert.equal(result.made, true);
  // One key on the device, under the fixed label, with a random handle; kept as this browser's and site's.
  assert.equal(creates(device).length, 1);
  const made = creates(device)[0][1].publicKey;
  assert.deepEqual([made.user.name, made.user.displayName, made.user.id.length, made.rp.id, made.extensions], [LOCK_LABEL, LOCK_LABEL, 16, undefined, { prf: {} }]);
  const kept = JSON.parse(storage.getItem(DEVICE_KEY_PLACE));
  assert.deepEqual(Object.keys(kept).sort(), ['credential', 'handle', 'v']); assert.equal(kept.credential, result.credential);
  // Asked twice after it was made, each time for both keys in one request, with the network, the account and the key in the salts.
  assert.equal(getsOf(device).length, 2);
  for (const [, options] of getsOf(device)) {
    const evaluate = options.publicKey.extensions.prf.eval;
    assert.equal(Buffer.from(evaluate.first).toString(), `TIME-DEVICE-LOCK-V1\0login\0${NET}\0alice\0${a.signin}`);
    assert.equal(Buffer.from(evaluate.second).toString(), `TIME-DEVICE-LOCK-V1\0spend\0${NET}\0alice\0${a.spend}`);
    assert.equal(options.publicKey.userVerification, 'required');
  }
  assert.ok(said.includes(LOCK_WORDS.beforeOn) && said.indexOf(LOCK_WORDS.checking) < said.indexOf(LOCK_WORDS.beforeOn), 'the passwords are checked first, and the page says before the device asks');
  // Both places hold version 3, with this device's key; nothing else is left.
  assert.deepEqual(vaults(storage).map(([k, v]) => [k.split(':')[0], v.version, vaultDevice(v)]), [['timecurrency.vault.v1', 3, result.credential], ['timecurrency.spend-vault.v1', 3, result.credential]]);
  assert.deepEqual(lockOf(storage, a.slots), { on: true, credential: result.credential, waiting: false, both: true });
  // Both open with the device and the passwords.
  for (const [key, intent, password] of [[a.slots.login, 'signin', LOGIN], [a.slots.spend, 'spend', PAYMENT]]) {
    const r = record(storage, key);
    assert.equal((await openVault(r, password, argon2id, webcrypto, intent, await secretFor(device, r))).intent, intent);
  }
  await assert.rejects(on(storage, device, a), new RegExp(LOCK_WORDS.alreadyOn));
});

test('a copy of the storage with the right passwords opens nothing without the device: not here, not on another device', async () => {
  const storage = new Storage(), device = fakeDevice(), a = await account(storage);
  await on(storage, device, a);
  const copy = storage.copy();
  for (const [key, intent, password] of [[a.slots.login, 'signin', LOGIN], [a.slots.spend, 'spend', PAYMENT]]) {
    await assert.rejects(openVault(record(copy, key), password, argon2id, webcrypto, intent), error => error.deviceNeeded === true);
  }
  // Another device (another browser profile, a phone that never had the key): it has no key of this site, or another one.
  const other = fakeDevice(), asker = createLockAsker({ env: other.env });
  await assert.rejects(asker.secretsFor([record(copy, a.slots.login)]), error => error.deviceLock === true && error.message === LOCK_WORDS.notGiven && error.wayBack === true);
  await other.env.credentials.create({ publicKey: { user: { id: new Uint8Array(16) } } });
  await assert.rejects(asker.secretsFor([record(copy, a.slots.login)]), error => error.message === LOCK_WORDS.keyGone && error.outcome === 7);
});

test('turning it on fails safely at each step: nothing is changed', async () => {
  const cases = [
    ['the passwords are wrong (the device is not asked)', {}, { login: `${LOGIN}x` }, LOCK_WORDS.loginWrong, 0],
    ['the payment password is wrong', {}, { payment: `${PAYMENT}x` }, LOCK_WORDS.paymentWrong, 0],
    ['the device refuses to make its key', { createError: 'NotAllowedError' }, {}, LOCK_WORDS.notChanged, 0],
    ['the browser says the key gives no secret', { noPrf: true }, {}, LOCK_WORDS.noPrf, 0],
    ['the person cancels the first request', { getErrors: ['NotAllowedError'] }, {}, LOCK_WORDS.notChanged, 1],
    ['the person cancels the second request', { getErrors: [null, 'NotAllowedError'] }, {}, LOCK_WORDS.notChanged, 2],
    ['the second answer differs from the first', { secondDiffers: 2 }, {}, LOCK_WORDS.differs, 2],
  ];
  for (const [what, switches, extra, words, gets] of cases) {
    const storage = new Storage(), device = fakeDevice(switches), a = await account(storage), before = [storage.getItem(a.slots.login), storage.getItem(a.slots.spend)];
    await assert.rejects(on(storage, device, a, extra), error => error.message === words, what);
    assert.deepEqual([storage.getItem(a.slots.login), storage.getItem(a.slots.spend)], before, what);
    assert.equal(lockOf(storage, a.slots).on, false, what);
    assert.equal(device.gets(), gets, what);
  }
});

test('a page that closes half way through the swap: both records or neither', async () => {
  // Closed while the new records were being put aside (the second one never written): nothing is swapped, and the one put aside goes.
  let storage = new Storage(), device = fakeDevice(), a = await account(storage);
  const before = [storage.getItem(a.slots.login), storage.getItem(a.slots.spend)];
  storage.failAt = storage.writes + 3; // the device key kept, then the first record put aside, then the second fails
  await assert.rejects(on(storage, device, a), /the page closed/);
  storage.failAt = null; settleSwap(storage, a.slots, lockPlaces(NET, 'alice'));
  assert.deepEqual([storage.getItem(a.slots.login), storage.getItem(a.slots.spend)], before);
  assert.equal([...storage.m.keys()].some(k => k.startsWith('timecurrency.vault-lock.v1:')), false);
  // Closed after the login place was replaced and before the payment place: the next start finishes it.
  storage = new Storage(); device = fakeDevice(); a = await account(storage);
  storage.failAt = storage.writes + 5; // kept key, two put aside, the login place, then the payment place fails
  await assert.rejects(on(storage, device, a), /the page closed/);
  assert.deepEqual([record(storage, a.slots.login).version, record(storage, a.slots.spend).version], [3, 2], 'half way');
  storage.failAt = null; settleSwap(storage, a.slots, lockPlaces(NET, 'alice'));
  assert.deepEqual([record(storage, a.slots.login).version, record(storage, a.slots.spend).version], [3, 3]);
  assert.equal(lockOf(storage, a.slots).on, true);
});

test('"Let the wallet make my passwords" on a protected account whose login key is of version 1, stopped after the login place was replaced: the next start finishes it', async () => {
  // Such an account, as preview-server.mjs keeps carol: a key of both powers in the login place, a payment key beside it.
  const storage = new Storage(), slots = vaultSlots(NET, 'carol'), places = lockPlaces(NET, 'carol'), login = await newDevice(webcrypto), spend = await newDevice(webcrypto);
  storage.setItem(slots.login, JSON.stringify(await sealLegacy({ ...login.secret, nameSalt: 'ab'.repeat(32), intent: 'device' }, LOGIN, { networkId: NET, name: 'carol', publicKey: login.publicKey }, argon2id, webcrypto)));
  storage.setItem(slots.spend, JSON.stringify(await sealLegacy({ pkcs8: spend.secret.pkcs8 }, PAYMENT, { networkId: NET, name: 'carol', publicKey: spend.publicKey }, argon2id, webcrypto, 'spend')));
  let shown = null;
  storage.failAt = storage.writes + 4; // both put aside, the login place, then the payment place fails
  await assert.rejects(remakePasswords({ storage, slots, networkId: NET, name: 'carol', login: LOGIN, payment: PAYMENT, argon2id, cryptoImpl: webcrypto, show: async made => { shown = made; } }), /the page closed/);
  assert.deepEqual([record(storage, slots.login).password, record(storage, slots.spend).password], ['made', undefined], 'half way');
  storage.failAt = null; settleSwap(storage, slots, places);
  assert.deepEqual(sealsOf(storage, slots), { login: 'made', spend: 'made', loginIntent: 'device', chosen: [] });
  assert.equal([...storage.m.keys()].some(k => k.startsWith('timecurrency.vault-lock.v1:')), false);
  assert.equal((await openVault(record(storage, slots.spend), shown.payment, argon2id, webcrypto, 'spend')).binding.publicKey, spend.publicKey);
  assert.equal((await openVault(record(storage, slots.login), shown.login, argon2id, webcrypto)).secret.nameSalt, 'ab'.repeat(32));
});

test('the card of chosen passwords names only what Keys offers: the lock to this device where its card offers it, else the passwords the wallet makes', async () => {
  const els = new Map(), $ = id => { if (!els.has(id)) els.set(id, { id, hidden: false, textContent: '', value: '', children: [], addEventListener() {}, replaceChildren(...c) { this.children = c; } }); return els.get(id); };
  const before = globalThis.document;
  globalThis.document = { getElementById: $, createElement: () => ({ textContent: '' }) };
  try {
    const { createLockUI, LEGACY_WORDS } = await import('./device-lock-ui.mjs');
    let env = fakeDevice().env, name = '';
    const storage = new Storage(), c = { network: () => ({ networkId: NET }), session: () => ({ binding: { name } }), storage, locks: () => null, env: () => env, argon2id: () => argon2id, run() {}, notice() {}, setBusy() {}, capture: () => () => {}, refresh: async () => {}, review: async () => false, showMade: async () => {} };
    const ui = createLockUI(c), settled = () => new Promise(resolve => setTimeout(resolve, 20));
    const card = () => [$('legacy-ways').textContent, $('legacy-past').textContent];
    // A protected account whose login key is of version 1: the lock is never offered for it, and the card does not name it.
    name = 'carol'; const s = vaultSlots(NET, 'carol'), key = await newDevice(webcrypto), pay = await newDevice(webcrypto);
    storage.setItem(s.login, JSON.stringify(await sealLegacy({ ...key.secret, nameSalt: 'ab'.repeat(32), intent: 'device' }, LOGIN, { networkId: NET, name: 'carol', publicKey: key.publicKey }, argon2id, webcrypto)));
    storage.setItem(s.spend, JSON.stringify(await sealLegacy({ pkcs8: pay.secret.pkcs8 }, PAYMENT, { networkId: NET, name: 'carol', publicKey: pay.publicKey }, argon2id, webcrypto, 'spend')));
    ui.render({ name: 'carol' }, true); await settled();
    assert.deepEqual([$('legacy-card').hidden, $('lock-card').hidden, ...card()], [false, true, LEGACY_WORDS.wayRemake, LEGACY_WORDS.pastRemake]);
    // Both keys of version 2: the card names the lock once the browser said its card may offer it.
    name = 'alice'; await account(storage); ui.render({ name: 'alice' }, true);
    assert.deepEqual(card(), [LEGACY_WORDS.wayRemake, LEGACY_WORDS.pastRemake], 'before the browser said what it can do');
    await settled();
    assert.deepEqual([$('lock-card').hidden, ...card()], [false, LEGACY_WORDS.ways, LEGACY_WORDS.past]);
    // A browser that cannot lock keys: the lock is not named.
    env = { secureContext: false }; ui.render({ name: 'alice' }, true); await settled();
    assert.deepEqual([$('lock-card').hidden, ...card()], [true, LEGACY_WORDS.wayRemake, LEGACY_WORDS.pastRemake]);
    // An account with one key: one way, said as one.
    name = 'quin'; const q = vaultSlots(NET, 'quin'), one = await newDevice(webcrypto);
    storage.setItem(q.login, JSON.stringify(await sealLegacy({ ...one.secret, nameSalt: 'cd'.repeat(32), intent: 'device' }, LOGIN, { networkId: NET, name: 'quin', publicKey: one.publicKey }, argon2id, webcrypto)));
    ui.render({ name: 'quin' }, false); await settled();
    assert.deepEqual(card(), [LEGACY_WORDS.wayOne, LEGACY_WORDS.pastOne]);
    for (const text of [LEGACY_WORDS.wayRemake, LEGACY_WORDS.pastRemake, LEGACY_WORDS.wayOne, LEGACY_WORDS.pastOne]) assert.doesNotMatch(text, /lock|[Nn]either/, 'one way is said as one, and the lock is not named');
  } finally { globalThis.document = before; }
});

test('turning it off: the device asked once, both passwords; the keys then open with passwords the wallet made, not with those of before', async () => {
  const storage = new Storage(), device = fakeDevice(), a = await account(storage);
  await on(storage, device, a);
  const asked = device.gets();
  await assert.rejects(off(storage, device, a, { payment: `${PAYMENT}x` }), new RegExp(LOCK_WORDS.paymentWrong));
  assert.equal(lockOf(storage, a.slots).on, true, 'a wrong password changes nothing');
  await off(storage, device, a);
  assert.equal(device.gets() - asked, 2, 'one request per attempt');
  assert.deepEqual(vaults(storage).map(([, v]) => [v.version, v.password]), [[2, 'made'], [2, 'made']]);
  assert.equal((await openVault(record(storage, a.slots.spend), a.payment, argon2id, webcrypto, 'spend')).intent, 'spend');
  await assert.rejects(openVault(record(storage, a.slots.spend), PAYMENT, argon2id, webcrypto, 'spend'), error => error.madeForm === true, 'the payment password of before opens nothing');
  await assert.rejects(off(storage, device, a), new RegExp(LOCK_WORDS.alreadyOff));
  // With the device's key gone it cannot be turned off here: the words say the way back.
  await on(storage, device, a); device.remove();
  await assert.rejects(off(storage, device, a), error => error.message === LOCK_WORDS.notGiven && error.wayBack === true);
  assert.equal(lockOf(storage, a.slots).on, true);
});

test('while a change of keys waits, or a login is asked of another device, the lock is neither turned on nor off', async () => {
  const storage = new Storage(), device = fakeDevice(), a = await account(storage);
  const [next] = await sealedKeys({ wanted: [{ intent: 'signin' }], networkId: NET, name: 'alice', argon2id, cryptoImpl: webcrypto });
  stageVaults(storage, a.slots, { signin: next.record }, { kind: 71, nonce: '9', authEpoch: '1', hash: 'AB'.repeat(32) });
  await assert.rejects(on(storage, device, a), new RegExp(LOCK_WORDS.waiting));
  assert.equal(device.calls.length, 0);
});

test('every new key of the account made here while the lock is on is sealed with the device too, in one request; and moved as it is', async () => {
  const storage = new Storage(), device = fakeDevice(), a = await account(storage);
  await on(storage, device, a);
  const status = lockOf(storage, a.slots), asker = createLockAsker({ env: device.env }), asked = device.gets();
  const lock = async keys => ({ credential: status.credential, secrets: await asker.forNew(status.credential, keys.map(k => ({ ...k, networkId: NET, name: 'alice' }))) });
  // A new payment password with a new login key (two keys, one request), a new login password, a login asked of another device.
  const [spend, signin] = await sealedKeys({ wanted: [{ password: `${PAYMENT} new`, intent: 'spend' }, { password: `${LOGIN} new`, intent: 'signin' }], networkId: NET, name: 'alice', argon2id, cryptoImpl: webcrypto, lock });
  assert.equal(device.gets() - asked, 1);
  assert.deepEqual([spend.record.version, signin.record.version, vaultDevice(spend.record), vaultDevice(signin.record)], [3, 3, status.credential, status.credential]);
  stageVaults(storage, a.slots, { signin: signin.record, spend: spend.record }, { kind: 73, version: '1', expires: '9', hash: 'AB'.repeat(32) });
  const account4 = { devices: [{ public_key: signin.key.publicKey, can_manage: false, can_spend: false }, { public_key: spend.key.publicKey, can_manage: false, can_spend: true }] };
  assert.deepEqual(settleStaged(storage, a.slots, account4), ['signin', 'spend']);
  assert.deepEqual([record(storage, a.slots.login).version, record(storage, a.slots.spend).version], [3, 3]);
  assert.equal((await openVault(record(storage, a.slots.login), `${LOGIN} new`, argon2id, webcrypto, 'signin', await secretFor(device, record(storage, a.slots.login)))).intent, 'signin');
  const [asking] = await sealedKeys({ wanted: [{ password: `${LOGIN} asked`, intent: 'signin' }], networkId: NET, name: 'alice', argon2id, cryptoImpl: webcrypto, lock });
  storeLoginRequest(storage, a.slots, asking.record, { publicKey: asking.key.publicKey });
  assert.equal(vaultDevice(JSON.parse(storage.getItem(a.slots.request)).record), status.credential);
  // No record of the account in any place is one the password alone opens.
  assert.deepEqual(vaults(storage).filter(([, v]) => v.version !== 3).map(([k]) => k), []);
  // Recovery on this browser with the recovery words (the way back when the device lost its key): the locked records go.
  const live = { name: 'alice', devices: account4.devices };
  assert.deepEqual(lostDeviceSlots(storage, a.slots, live), { stale: [a.slots.login, a.slots.spend], blocked: null });
  assert.equal(settleLoginRequest(storage, a.slots, live), 'dropped');
});

test('the device\'s answer is kept a minute for a password typed again, and wiped once the key opened, on Lock and when it is old', async () => {
  const storage = new Storage(), device = fakeDevice(), a = await account(storage);
  await on(storage, device, a);
  let now = 1000; const said = [], asker = createLockAsker({ env: device.env, say: text => said.push(text), now: () => now }), r = record(storage, a.slots.login), asked = device.gets();
  const first = await asker.secretsFor([r]);
  await assert.rejects(openVault(r, `${LOGIN}x`, argon2id, webcrypto, 'signin', first[0]), /Could not unlock/);
  const again = await asker.secretsFor([r]);
  assert.equal(device.gets() - asked, 1, 'the password typed again costs no second request');
  assert.deepEqual(said, [LOCK_WORDS.before]);
  await openVault(r, LOGIN, argon2id, webcrypto, 'signin', again[0]); asker.release([r]);
  assert.equal(asker.holding(), 0);
  await asker.secretsFor([r]); asker.forgetAll(); assert.equal(asker.holding(), 0);
  await asker.secretsFor([r]); now += 61000; assert.equal(asker.holding(), 0);
  assert.equal(device.gets() - asked, 3);
});

test('two accounts in one browser: one device key, an answer of one account opens nothing of the other', async () => {
  const storage = new Storage(), device = fakeDevice(), alice = await account(storage, 'alice'), bob = await account(storage, 'bob');
  const one = await on(storage, device, alice), two = await on(storage, device, bob);
  assert.deepEqual([one.made, two.made, one.credential === two.credential, creates(device).length], [true, false, true, 1]);
  assert.ok(credentialInUse(storage, one.credential));
  const aliceLogin = record(storage, alice.slots.login), bobLogin = record(storage, bob.slots.login);
  await assert.rejects(openVault(bobLogin, LOGIN, argon2id, webcrypto, 'signin', await secretFor(device, aliceLogin)), /Could not unlock/);
  assert.equal((await openVault(bobLogin, LOGIN, argon2id, webcrypto, 'signin', await secretFor(device, bobLogin))).binding.name, 'bob');
  // Once nothing uses the kept key (both turned off), the next turn-on makes a new one with the same handle: the device replaces it.
  await off(storage, device, alice); await off(storage, device, bob);
  const handle = JSON.parse(storage.getItem(DEVICE_KEY_PLACE)).handle, three = await on(storage, device, alice);
  assert.equal(three.made, true); assert.equal(device.keys.length, 1);
  assert.equal(Buffer.from(creates(device).at(-1)[1].publicKey.user.id).toString('base64url'), handle);
});

test('what the account keeps privately (locked-store.mjs) opens the same through turning the lock on and off: the login key stays the same', async () => {
  const storage = new Storage(), device = fakeDevice(), a = await account(storage);
  const openStore = async (secret = null) => {
    const opened = await openVault(record(storage, a.slots.login), a.login, argon2id, webcrypto, 'signin', secret);
    const store = createPrivateStore({ storage, cryptoImpl: webcrypto });
    return { store, result: await store.open({ networkId: NET, name: 'alice', publicKey: opened.binding.publicKey, storageKey: opened.storageKey }) };
  };
  const first = await openStore();
  await first.store.update('activity', kept => withReceipt(kept, { hash: 'AB'.repeat(32), height: '9', label: 'Send 1 s to @bob', at: 1, nonce: '4' }));
  first.store.close(); await first.store.flushed();
  await on(storage, device, a);
  const locked = await openStore(await secretFor(device, record(storage, a.slots.login)));
  assert.deepEqual([locked.result, locked.store.value('activity').items.map(i => i.nonce)], [{ lost: false, memory: false }, ['4']]);
  locked.store.close(); await locked.store.flushed();
  await off(storage, device, a);
  const unlocked = await openStore();
  assert.deepEqual(unlocked.store.value('activity').items.map(i => i.nonce), ['4']);
});
