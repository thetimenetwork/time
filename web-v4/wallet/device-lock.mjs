// "Lock my keys to this device" (Keys): an account's login key and payment key open only with the device's own check
// of the person (fingerprint, face or screen lock: WebAuthn PRF, device-key.mjs) AND the password. A copy of this
// browser's data is then worth nothing on another machine, whatever the password: the passwords a person chooses can be
// guessed offline, the device's secret cannot. Off by default, offered on a protected account whose login key and
// payment key are both in this browser, where the device can do it.
//
// How (vault.mjs, version 3): the vault key is HKDF-SHA-256 of the Argon2id output of the password and the 32 bytes the
// device gives for that vault, with the record's random salt, and the record's header (which names the device's key) as
// info and as authenticated data. The device's 32 bytes come from one key of the device per browser and site, for all
// accounts there (DEVICE_KEY_PLACE: its id and its random user handle, nothing about an account; its label a fixed
// text), asked with a salt per account and per key (lockSalt: the purpose, the network, the account's name and the
// vault's public key), so that one account's answer opens nothing of another's (web audit, K-8).
//
// While the lock is on, no copy of either key that the password alone opens stays in this browser: the login place and
// the payment place hold version-3 records, and every new key this browser makes for the account (a new login or payment
// password, a login asked of another device) is sealed with the device too (security-flows.mjs, sealedKeys; security-ui
// asks for the lock through `lockFor`). Turning it on or off is refused while a change of keys is kept aside or a login
// is asked of another device, so that nothing staged stays sealed the other way.
//
// No network access in this module. The storage is the caller's (`storage`), and the device is reached through `env`
// (device-key.mjs, browserEnv), so that the tests drive it with a fake authenticator.
//
// The rule (vault.mjs, RULE) gives this module three more jobs: keys locked from birth (sealAtBirth, newKeysByRule: a
// sign-up, "Protect my account", "Recover my account"); turning the lock off seals the keys under passwords the wallet
// makes, shown before anything is replaced (turnOff); and "Let the wallet make my passwords" for keys kept from before
// the rule under passwords a person chose (remakePasswords).
import { deviceSupport, deviceError, DeviceKeyError, makeDeviceKey, fromBase64url, base64url, forget, authenticatorFlags } from './device-key.mjs';
import { openVault, sealVault, validateVaultRecord, vaultDevice, vaultIntent, vaultMade, sealOf, makePassword, readMadePassword, forgetSecret } from './vault.mjs';
import { sealedKeys } from './security-flows.mjs';
import { readyToMake } from './entropy.mjs';

const encoder = new TextEncoder();
/// The device's key for this browser and site: `{"v":1,"credential":<id>,"handle":<user handle>}`, base64url.
export const DEVICE_KEY_PLACE = 'timecurrency.device-key.v1';
/// The name the device lists the key under: a fixed text, never a person's or an account's name.
export const LOCK_LABEL = 'Time wallet';
export const LOCK_SALT_PREFIX = 'TIME-DEVICE-LOCK-V1';
/// How long the device's answer stays in this page's memory after a password that did not open the key, so that the
/// person can type it again without a new request to the device. Wiped earlier on success, on Lock and when the page hides.
export const HOLD_MS = 60000;
const TIMEOUT_MS = 120000;

/// What the person reads.
export const LOCK_WORDS = Object.freeze({
  facts: Object.freeze([
    "A copy of this browser's data will no longer open your keys, even with your passwords.",
    "If this device loses that key (after a reset, or when it is removed in the device's settings), you get back in with your recovery words, and that waits the waiting period. To change devices while this one still works, move your account under Keys: nothing waits.",
    'On phones, Apple or Google keep that key in your account with them and bring it to your other devices.',
    'This browser then makes no backup file of your keys: a file would open with a password alone.',
  ]),
  before: 'Your device will now ask for your fingerprint, face or screen lock.',
  beforeOn: 'Your device will now ask for your fingerprint, face or screen lock, two or three times.',
  checking: 'Checking both passwords. This takes a few seconds…',
  sealing: 'Locking your keys with your passwords and this device. This takes a few seconds…',
  on: 'Your keys are locked to this device. Your passwords alone no longer open them here.',
  offFacts: 'The wallet then makes new passwords for your keys and shows them to you once. Your passwords of now stop opening them, and the backup file is offered again.',
  off: 'Your keys are no longer locked to this device. They open with the passwords the wallet just made.',
  offMade: 'Your keys are no longer locked to this device. The wallet made new passwords for them: write them down now.',
  notGiven: 'Nothing was opened: the device did not give its key. Try again. If this device no longer has that key (after a reset, or when it was removed in its settings), recover your account with your recovery words.',
  keyGone: 'This device no longer has the key your keys here are locked to, or it answered with another one. Your passwords alone cannot open them. Recover your account with your recovery words (it waits the waiting period), or use it on another device where it is open.',
  noDevice: "This browser cannot use this device's fingerprint, face or screen lock, and your keys here are locked to it. Open the wallet in the browser where you locked them, or recover your account with your recovery words.",
  noPrf: 'This device or this browser cannot lock keys with your fingerprint, face or screen lock yet. Nothing was changed.',
  notChanged: 'Nothing was changed: the device did not give its key. You can try again.',
  otherKey: "Nothing was changed: the device answered with another key. If it lists 'Time wallet' for this site, choose that one.",
  other: 'The device did not finish its check. Nothing was changed. Try again.',
  differs: 'The device gave another answer the second time, so nothing was changed.',
  waiting: 'A change of keys from this browser is still waiting for the network. Check it under Keys first.',
  needsBoth: 'Your login key and your payment key must both be in this browser to lock them to it.',
  loginWrong: 'That is not the login password of this browser. Nothing was changed.',
  paymentWrong: 'That is not the payment password of this browser. Nothing was changed.',
  alreadyOn: 'Your keys are already locked to this device.',
  alreadyOff: 'Your keys are not locked to this device.',
  backup: 'Your keys are locked to this device, so this browser makes no backup file of them: a file would open with a password alone. To change devices while this one still works, use “Move my account to another device”, below. If this device loses its key, recover your account with your recovery words.',
  recover: 'Recover my account',
  lost: 'Your keys of this account in this browser were locked to this device. Your new keys are made by the rule of this wallet: locked to this device again where it can, else under passwords the wallet makes.',
  // Keys locked from birth (sealAtBirth): what the page says before the device asks; and where the device cannot lock
  // keys, what the form says in place of the choice below.
  birth: 'Your device will lock your new keys: it asks for your fingerprint, face or screen lock, two or three times. You choose the passwords.',
  birthMade: 'The wallet makes your passwords and shows them to you, because this device cannot lock your keys.',
  // Where the device can lock keys, the person chooses how the new keys are locked, and neither way is chosen beforehand
  // (the owner's decision of 25 November 2026: "up to the user to decide"). The form of a sign-up, of "Protect my
  // account", of "Recover my account" and of "Move my account here" shows the two ways in these words
  // (device-lock-ui.mjs, wayChoice), and refuses to go on with `pick` while none is chosen.
  ways: Object.freeze({
    legend: 'Choose how to lock your new keys',
    device: Object.freeze({
      title: 'Lock them to this device',
      note: 'They open with your fingerprint, face or screen lock and passwords you choose. If this device loses its key, your recovery words get you back in after the waiting period; to change devices, use “Move my account to another device”.',
    }),
    made: Object.freeze({
      title: 'Let the wallet make the passwords',
      note: 'Nothing of this device is used. The wallet makes two passwords and shows them to you once: keep both, and type the payment password at each payment.',
    }),
    pick: 'First choose how to lock your new keys: to this device, or with passwords the wallet makes.',
    // A form sent in the moment before the browser has said what the device can do: nothing is made.
    asking: 'One moment: checking what this device can do.',
  }),
  // A device that failed at any step while keys were made: what happened, then that the wallet made the passwords.
  fellBack: 'The wallet made your passwords instead, and shows them to you now.',
  // "Let the wallet make my passwords" (remakePasswords).
  remaking: 'Making new passwords for your keys. This takes a few seconds…',
  remade: 'Your keys now open with the passwords the wallet made. The passwords you chose no longer open them in this browser.',
  notChosen: 'The wallet made the passwords of your keys in this browser already.',
  // The keys of the account changed in this browser (another tab) while the new passwords were shown: nothing is replaced.
  changed: 'Nothing was changed: the keys of this account in this browser changed while the new passwords were shown. The passwords just shown open nothing.',
});
/// Why a device did not lock keys made at birth, in the person's words, before LOCK_WORDS.fellBack.
export function birthWords(error) {
  const n = error?.outcome ?? deviceError(error).outcome;
  const why = error?.differs ? 'The device gave another answer the second time, so your keys are not locked to it.'
    : n === 6 ? 'The device did not give its key, so your keys are not locked to it.'
    : n === 7 ? 'The device answered with another key, so your keys are not locked to it.'
    : [2, 3, 4, 5].includes(n) ? 'This device or this browser cannot lock keys with your fingerprint, face or screen lock.'
    : 'The device did not finish its check, so your keys are not locked to it.';
  return `${why} ${LOCK_WORDS.fellBack}`;
}
/// Whether keys can be locked to this device from birth here: the browser does not say that it cannot (deviceSupport:
/// a secure page, WebAuthn, a built-in authenticator not refused, PRF not refused). Nothing is asked of the person.
export async function birthLockable(env) {
  try { const s = await deviceSupport(env); return s.outcome === null && s.prf !== 'no'; } catch { return false; }
}

// ---- the salts and the device ---------------------------------------------------------------------------------------
/// What a vault's key is asked for: its purpose ('login' or 'spend'), the network, the account and the vault's key.
export const purposeOf = intent => (intent === 'spend' ? 'spend' : 'login');
export function lockSalt({ purpose, networkId, name, publicKey }) {
  if (!['login', 'spend'].includes(purpose) || !/^[0-9a-f]{64}$/.test(networkId) || !/^[a-z0-9_]{2,15}$/.test(name) || !/^[0-9a-f]{64}$/.test(publicKey)) throw new TypeError('Invalid lock salt');
  return encoder.encode(`${LOCK_SALT_PREFIX}\0${purpose}\0${networkId}\0${name}\0${publicKey}`);
}
/// The salt of a vault record (its binding and intent).
export const saltOfRecord = record => lockSalt({ purpose: purposeOf(vaultIntent(record)), networkId: record.binding.networkId, name: record.binding.name, publicKey: record.binding.publicKey });

const bytesOf = value => (value instanceof Uint8Array ? value : value instanceof ArrayBuffer ? new Uint8Array(value) : ArrayBuffer.isView(value) ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength) : null);
const hasWebAuthn = env => env?.secureContext === true && typeof env?.PublicKeyCredential === 'function' && typeof env?.credentials?.get === 'function' && typeof env?.credentials?.create === 'function';
const extensionsOf = credential => { try { const r = credential.getClientExtensionResults?.(); return r && typeof r === 'object' ? r : {}; } catch { return {}; } };

/// One request to the device for one or two salts (WebAuthn PRF evaluates two in one request), after it checked the
/// person. As device-key.mjs (deviceSecret): no key named in the request, the key that answered compared with
/// `credentialId` (another one: outcome 7), the person checked (the UV flag), 32 bytes each. Returns copies, which the
/// caller wipes (forget); the browser's buffers are wiped here.
export async function deviceSecrets(env, { credentialId, salts }) {
  if (!hasWebAuthn(env)) throw new DeviceKeyError(2, 'NotSupportedError');
  const wanted = fromBase64url(credentialId);
  if (!wanted) throw new TypeError('A credential id is 16 to 1023 bytes in canonical base64url');
  if (!Array.isArray(salts) || salts.length < 1 || salts.length > 2) throw new TypeError('One or two salts');
  const options = { publicKey: { challenge: env.crypto.getRandomValues(new Uint8Array(32)), timeout: TIMEOUT_MS, userVerification: 'required', hints: ['client-device'],
    extensions: { prf: { eval: { first: salts[0], ...(salts[1] ? { second: salts[1] } : {}) } } } } };
  let assertion;
  try { assertion = await env.credentials.get(options); } catch (error) { throw deviceError(error); }
  const id = bytesOf(assertion?.rawId);
  if (!assertion || assertion.type !== 'public-key' || !id) throw new DeviceKeyError(8, 'NoCredential');
  const results = extensionsOf(assertion).prf?.results, given = [bytesOf(results?.first), bytesOf(results?.second)];
  try {
    if (id.length !== wanted.length || id.some((b, i) => b !== wanted[i])) throw new DeviceKeyError(7, 'OtherKey');
    let data = null; try { data = assertion.response?.authenticatorData ?? null; } catch { data = null; }
    if (!authenticatorFlags(data)?.uv) throw new DeviceKeyError(8, 'NotVerified');
    const out = salts.map((_, i) => given[i]);
    if (out.some(b => !b)) throw new DeviceKeyError(5, 'NoPrfResult');
    if (out.some(b => b.length !== 32)) throw new DeviceKeyError(8, 'BadSecretLength');
    return out.map(b => new Uint8Array(b));
  } finally { forget(...given.filter(Boolean)); }
}

/// A failure of the device in the person's words: an Error with `deviceLock` (and `wayBack` where "Recover my account"
/// is the way on), `outcome` and `errorClass` (device-key.mjs). `turning`: while the lock is turned on or off, when
/// nothing is locked to the device yet or still (the words then say that nothing was changed).
export function lockError(error, { turning = false } = {}) {
  if (error?.deviceLock === true) return error;
  const e = deviceError(error), n = e.outcome;
  let words;
  if (turning) words = n === 6 ? LOCK_WORDS.notChanged : n === 7 ? LOCK_WORDS.otherKey : [2, 3, 4, 5].includes(n) ? LOCK_WORDS.noPrf : LOCK_WORDS.other;
  else words = n === 7 ? LOCK_WORDS.keyGone : n === 6 ? LOCK_WORDS.notGiven : [2, 3, 4, 5].includes(n) ? LOCK_WORDS.noDevice : LOCK_WORDS.other;
  return Object.assign(new Error(words), { deviceLock: true, wayBack: !turning && n !== 8, outcome: n, errorClass: e.errorClass });
}
/// Whether the device can be asked at all here; a lockError when it cannot (nothing is asked).
async function ableOrThrow(env, { turning = false } = {}) {
  const support = await deviceSupport(env);
  if (support.outcome !== null) throw lockError(new DeviceKeyError(support.outcome), { turning });
  return support;
}

// ---- what this browser keeps ------------------------------------------------------------------------------------------
const read = (storage, key) => { try { const text = storage.getItem(key); return text === null ? null : JSON.parse(text); } catch { return null; } };
/// Whether the lock is on for an account in this browser (its login or payment place holds a version-3 record), which
/// device key it uses, and whether a change of keys is kept aside or a login is asked of another device (`waiting`).
export function lockOf(storage, slots) {
  const login = read(storage, slots.login), spend = read(storage, slots.spend), nextLogin = read(storage, slots.nextLogin), nextSpend = read(storage, slots.nextSpend), request = read(storage, slots.request)?.record ?? null;
  const credential = vaultDevice(login) ?? vaultDevice(spend) ?? vaultDevice(nextLogin) ?? vaultDevice(nextSpend) ?? vaultDevice(request);
  return { on: Boolean(vaultDevice(login) || vaultDevice(spend)), credential, waiting: Boolean(nextLogin || nextSpend || request), both: Boolean(login?.version >= 2 && spend) };
}
function keysOf(storage) {
  try {
    if (typeof storage.key === 'function' && Number.isInteger(storage.length)) { const keys = []; for (let i = 0; i < storage.length; i++) { const k = storage.key(i); if (k !== null) keys.push(k); } return keys; }
    return Object.keys(storage);
  } catch { return []; }
}
/// Whether a record of any account in this browser is locked with this device key. `except`: places not counted (the
/// records of an account that a recovery on this browser replaces).
export function credentialInUse(storage, credential, except = []) {
  for (const key of keysOf(storage)) {
    if (!/^timecurrency\.(vault\.v1|spend-vault\.v1|vault-next\.v1|login-request\.v1|vault-lock\.v1):/.test(key) || except.includes(key)) continue;
    const value = read(storage, key);
    if (vaultDevice(value) === credential || vaultDevice(value?.record) === credential) return true;
  }
  return false;
}
/// The device key of this browser and site for new keys:
/// - the kept one, when a record of this browser still uses it, but those at `except`;
/// - the kept one set `aside`, when only the records at `except` still use it: a recovery replaces them, but only once its
///   new records are written, and they must open until then. sealAtBirth asks the device for it first, and makes a new key
///   only when the device does not give it (review of 24 November 2026, finding 2);
/// - else a new one, made with the kept user handle so that most devices replace their earlier key instead of listing one
///   more: no record uses that key.
async function deviceKeyFor(storage, env, except = []) {
  const kept = read(storage, DEVICE_KEY_PLACE);
  const credential = kept && typeof kept.credential === 'string' && fromBase64url(kept.credential) ? kept.credential : null;
  const keptHandle = typeof kept?.handle === 'string' ? fromBase64url(kept.handle, 16, 64) : null;
  if (credential && credentialInUse(storage, credential, except)) return { credential, made: false, aside: false };
  if (credential && except.length && credentialInUse(storage, credential)) return { credential, made: false, aside: true };
  return newDeviceKey(storage, env, keptHandle ?? env.crypto.getRandomValues(new Uint8Array(16)));
}
/// A new device key, made with the user handle `handle`, and kept in DEVICE_KEY_PLACE. A device replaces an earlier key of
/// the same handle: a key that records still use is never made again with its handle.
async function newDeviceKey(storage, env, handle) {
  let made;
  try { made = await makeDeviceKey(env, { label: LOCK_LABEL, userHandle: handle }); } catch (error) { throw lockError(error, { turning: true }); }
  if (made.prfEnabled === false) throw lockError(new DeviceKeyError(5, 'NoPrfResult'), { turning: true });
  storage.setItem(DEVICE_KEY_PLACE, JSON.stringify({ v: 1, credential: made.credentialId, handle: base64url(handle) }));
  return { credential: made.credentialId, made: true, aside: false };
}

// ---- turning it on and off: both records or neither ---------------------------------------------------------------------
/// Where a swap of the login and payment records is written first: a page that closes half way through the swap leaves
/// both new records here, and settleSwap finishes it; one record alone here means nothing was swapped yet, and it goes.
export const lockPlaces = (networkId, name) => ({ login: `timecurrency.vault-lock.v1:${networkId}:${name}:login`, spend: `timecurrency.vault-lock.v1:${networkId}:${name}:spend` });
function swap(storage, slots, places, next) {
  storage.setItem(places.login, JSON.stringify(next.login)); storage.setItem(places.spend, JSON.stringify(next.spend));
  storage.setItem(slots.login, JSON.stringify(next.login)); storage.setItem(slots.spend, JSON.stringify(next.spend));
  storage.removeItem(places.login); storage.removeItem(places.spend);
}
export function settleSwap(storage, slots, places) {
  const login = storage.getItem(places.login), spend = storage.getItem(places.spend);
  if (login !== null && spend !== null) {
    // The login place of a protected account may hold a key of version 1 (a key of both powers, from before the payment
    // key was its own): "Let the wallet make my passwords" swaps it with the payment key all the same (review of 24
    // November 2026, finding 3).
    try { validateVaultRecord(JSON.parse(login), ['device', 'signin']); validateVaultRecord(JSON.parse(spend), 'spend'); storage.setItem(slots.login, login); storage.setItem(slots.spend, spend); } catch { /* not ours: dropped below */ }
  }
  if (login !== null) storage.removeItem(places.login);
  if (spend !== null) storage.removeItem(places.spend);
}
function liveRecords(storage, slots) {
  const login = read(storage, slots.login), spend = read(storage, slots.spend);
  try { validateVaultRecord(login, 'signin'); validateVaultRecord(spend, 'spend'); } catch { throw new Error(LOCK_WORDS.needsBoth); }
  return { login, spend };
}
async function opened(record, password, argon2id, cryptoImpl, intent, secret, wrong) {
  // A password the wallet made, typed in a form it cannot have: said as such (vault.mjs, readMadePassword).
  try { return await openVault(record, password, argon2id, cryptoImpl, intent, secret); } catch (error) { throw error?.madeForm ? error : new Error(wrong); }
}
/// What a record was sealed with, as sealVault takes it again with the device: the typed text, or for a record whose
/// password the wallet made, that password in its canonical form (the new record keeps the mark).
const againWith = (record, typed) => (vaultMade(record) ? readMadePassword(typed, vaultIntent(record)) : typed);
/// The Web Lock of an account's vaults, as everywhere else that writes them.
const underLock = (locks, networkId, name, work) => (locks?.request ? locks.request(`timecurrency:vault:${networkId}:${name}`, { mode: 'exclusive' }, work) : work());
/// What this browser keeps of an account's keys, as stored: the places a flow that shows passwords before it replaces the
/// records reads before it lets go of the lock, and finds the same once it holds the lock again (`unchanged`).
const keptNow = (storage, slots) => [slots.login, slots.spend, slots.nextLogin, slots.nextSpend, slots.request].map(key => storage.getItem(key));
function unchanged(storage, slots, before) {
  const now = keptNow(storage, slots);
  if (now.some((value, i) => value !== before[i])) throw new Error(LOCK_WORDS.changed);
}

/// Turns the lock on for one account: both passwords open both keys; the device's key (kept, or made); the device asked
/// for both secrets in one request; both keys sealed with them; the device asked AGAIN, and both new records must open
/// with that second answer; only then are both places replaced, both or neither. `say(text)`: what the page shows before
/// each step. Returns { credential, made } (made: a new device key was made).
export async function turnOn({ storage, slots, networkId, name, login, payment, argon2id, env, cryptoImpl = globalThis.crypto, locks = null, say = () => {} }) {
  return underLock(locks, networkId, name, async () => {
    settleSwap(storage, slots, lockPlaces(networkId, name));
    const status = lockOf(storage, slots);
    if (status.on) throw new Error(LOCK_WORDS.alreadyOn);
    if (status.waiting) throw new Error(LOCK_WORDS.waiting);
    const live = liveRecords(storage, slots);
    if (live.login.version !== 2 || live.spend.version !== 2) throw new Error(LOCK_WORDS.needsBoth);
    const held = []; let a = null, b = null;
    try {
      say(LOCK_WORDS.checking);
      a = await opened(live.login, login, argon2id, cryptoImpl, 'signin', null, LOCK_WORDS.loginWrong);
      b = await opened(live.spend, payment, argon2id, cryptoImpl, 'spend', null, LOCK_WORDS.paymentWrong);
      await ableOrThrow(env, { turning: true });
      say(LOCK_WORDS.beforeOn);
      const key = await deviceKeyFor(storage, env), salts = [saltOfRecord(live.login), saltOfRecord(live.spend)];
      let first;
      try { first = await deviceSecrets(env, { credentialId: key.credential, salts }); } catch (error) { throw lockError(error, { turning: true }); }
      held.push(...first);
      say(LOCK_WORDS.sealing);
      const next = {
        login: await sealVault({ pkcs8: a.secret.pkcs8 }, againWith(live.login, login), live.login.binding, argon2id, cryptoImpl, 'signin', { credential: key.credential, secret: first[0] }),
        spend: await sealVault({ pkcs8: b.secret.pkcs8 }, againWith(live.spend, payment), live.spend.binding, argon2id, cryptoImpl, 'spend', { credential: key.credential, secret: first[1] }),
      };
      // The device's secret can be had again, and the new records open with it: asked a second time, not taken from the first.
      say(LOCK_WORDS.before);
      let second;
      try { second = await deviceSecrets(env, { credentialId: key.credential, salts }); } catch (error) { throw lockError(error, { turning: true }); }
      held.push(...second);
      const proofs = [await opened(next.login, login, argon2id, cryptoImpl, 'signin', second[0], LOCK_WORDS.differs), await opened(next.spend, payment, argon2id, cryptoImpl, 'spend', second[1], LOCK_WORDS.differs)];
      for (const proof of proofs) { forgetSecret(proof.secret); proof.privateKey = null; }
      swap(storage, slots, lockPlaces(networkId, name), next);
      return { credential: key.credential, made: key.made };
    } finally {
      forget(...held);
      for (const o of [a, b]) if (o) { forgetSecret(o.secret); o.privateKey = null; }
    }
  });
}

/// Turns the lock off: the device asked once for both secrets; both passwords with them open both keys; both sealed under
/// passwords the wallet makes now (the rule: "your passwords alone" is not a state the wallet makes); both new records
/// opened with them. Then the device's secrets and both opened keys are wiped and the Web Lock is let go, and only then
/// are the new passwords shown (`show({ login, payment })`, awaited: nothing is replaced before the person has had them;
/// review of 24 November 2026, finding 4). Under the lock again, and only if this browser still keeps the account's keys
/// as they were (else LOCK_WORDS.changed, and nothing is replaced), both places are replaced, both or neither. Returns
/// { credential, made: { login, payment } }.
export async function turnOff({ storage, slots, networkId, name, login, payment, argon2id, env, cryptoImpl = globalThis.crypto, locks = null, say = () => {}, show = async () => {} }) {
  const places = lockPlaces(networkId, name);
  // The person may add their own randomness to the two passwords the wallet will make (entropy.mjs): asked first, before
  // the lock is taken and before the device or a key is asked for anything.
  await readyToMake(2);
  const sealed = await underLock(locks, networkId, name, async () => {
    settleSwap(storage, slots, places);
    const status = lockOf(storage, slots);
    if (!status.on) throw new Error(LOCK_WORDS.alreadyOff);
    if (status.waiting) throw new Error(LOCK_WORDS.waiting);
    const live = liveRecords(storage, slots), credential = vaultDevice(live.login), before = keptNow(storage, slots);
    if (!credential || vaultDevice(live.spend) !== credential) throw new Error(LOCK_WORDS.needsBoth);
    const held = []; let a = null, b = null;
    try {
      // Turning off needs the device: a key that is gone cannot be turned off here (lockError says the way back).
      await ableOrThrow(env);
      say(LOCK_WORDS.before);
      let secrets;
      try { secrets = await deviceSecrets(env, { credentialId: credential, salts: [saltOfRecord(live.login), saltOfRecord(live.spend)] }); } catch (error) { throw lockError(error); }
      held.push(...secrets);
      say(LOCK_WORDS.checking);
      a = await opened(live.login, login, argon2id, cryptoImpl, 'signin', secrets[0], LOCK_WORDS.loginWrong);
      b = await opened(live.spend, payment, argon2id, cryptoImpl, 'spend', secrets[1], LOCK_WORDS.paymentWrong);
      const made = { login: makePassword(), payment: makePassword() };
      const next = {
        login: await sealVault({ pkcs8: a.secret.pkcs8 }, made.login, live.login.binding, argon2id, cryptoImpl, 'signin'),
        spend: await sealVault({ pkcs8: b.secret.pkcs8 }, made.payment, live.spend.binding, argon2id, cryptoImpl, 'spend'),
      };
      const proofs = [await opened(next.login, made.login.text, argon2id, cryptoImpl, 'signin', null, LOCK_WORDS.loginWrong), await opened(next.spend, made.payment.text, argon2id, cryptoImpl, 'spend', null, LOCK_WORDS.paymentWrong)];
      for (const proof of proofs) { forgetSecret(proof.secret); proof.privateKey = null; }
      return { credential, next, before, words: { login: made.login.text, payment: made.payment.text } };
    } finally {
      forget(...held);
      for (const o of [a, b]) if (o) { forgetSecret(o.secret); o.privateKey = null; }
    }
  });
  await show(sealed.words);
  return underLock(locks, networkId, name, async () => {
    settleSwap(storage, slots, places);
    unchanged(storage, slots, sealed.before);
    swap(storage, slots, places, sealed.next);
    return { credential: sealed.credential, made: sealed.words };
  });
}

// ---- keys locked from birth, or under passwords the wallet makes (the rule) ---------------------------------------------
/// New keys of an account locked to this device from birth (a sign-up, "Protect my account", "Recover my account"):
/// `wanted` ([{ intent, password }], the passwords the person chose, held to checkPasswords by the caller). The device's
/// key (kept, or made: one request more), ONE request for the new keys' secrets, the keys sealed with them and the
/// passwords (security-flows.mjs, sealedKeys), and a SECOND request, whose answers must open every new record before
/// anything is returned: a device whose answer cannot be had again locks nothing. `except`: places whose records do not
/// count as using the kept device key (deviceKeyFor): the kept key, still used by them, is asked first; when the device
/// does not give it (it answers with another key, or with nothing), a new key is made with a fresh user handle, so that
/// it replaces nothing those records still use. `under`: as sealedKeys. Any failure of the device is an error with
/// `deviceLock` (lockError) or `differs`; nothing is kept here in any case but the device's key in DEVICE_KEY_PLACE.
export async function sealAtBirth({ storage, env, wanted, networkId, name, argon2id, cryptoImpl = globalThis.crypto, say = () => {}, under = null, except = [] }) {
  const held = [];
  let made = null;
  try {
    await ableOrThrow(env, { turning: true });
    say(LOCK_WORDS.birth);
    let key = await deviceKeyFor(storage, env, except);
    const sealWith = k => sealedKeys({ wanted, networkId, name, argon2id, cryptoImpl, under, lock: async keys => {
      try { return { credential: k.credential, secrets: await deviceSecrets(env, { credentialId: k.credential, salts: keys.map(item => lockSalt({ purpose: purposeOf(item.intent), networkId, name, publicKey: item.publicKey })) }) }; }
      catch (error) { throw lockError(error, { turning: true }); }
    } });
    try { made = await sealWith(key); }
    catch (error) {
      // The kept key, set aside only because the records that use it are being replaced, was not given (another key
      // answered, or none: WebAuthn does not tell a key that is gone from a request the person stopped). A new key, with a
      // fresh user handle: should the device still hold the kept key, the records of now keep opening with it.
      if (!key.aside || ![6, 7].includes(error?.outcome)) throw error;
      key = await newDeviceKey(storage, env, env.crypto.getRandomValues(new Uint8Array(16)));
      made = await sealWith(key);
    }
    // The device's secret can be had again, and the new records open with it: asked a second time, not taken from the first.
    say(LOCK_WORDS.before);
    let second;
    try { second = await deviceSecrets(env, { credentialId: key.credential, salts: made.map(entry => saltOfRecord(entry.record)) }); } catch (error) { throw lockError(error, { turning: true }); }
    held.push(...second);
    for (let i = 0; i < made.length; i++) {
      let proof;
      try { proof = await openVault(made[i].record, wanted[i].password, argon2id, cryptoImpl, wanted[i].intent, second[i]); }
      catch { throw Object.assign(new Error(LOCK_WORDS.differs), { deviceLock: true, differs: true, outcome: 8 }); }
      forgetSecret(proof.secret); proof.privateKey = null;
    }
    const done = made; made = null;
    return { keys: done, credential: key.credential, madeKey: key.made };
  } finally {
    forget(...held);
    for (const entry of made ?? []) { entry.key.privateKey = null; entry.storageKey = null; }
  }
}
/// The new keys of a flow that makes an account's keys anew, by the rule: locked to this device from birth when
/// `byDevice` (the device can, and the person did not decline: sealAtBirth); else, or when the device fails at any step,
/// under passwords the wallet makes (sealedKeys without a lock). A failure of the device never ends the flow: it comes
/// back as `fallback`, the words that say what happened. The passwords in `wanted` are used only with the device.
/// Returns { keys, locked, fallback }: `keys` as sealedKeys gives them (each with `made` when the wallet made its password).
export async function newKeysByRule({ byDevice, storage, env, wanted, networkId, name, argon2id, cryptoImpl = globalThis.crypto, say = () => {}, under = null, except = [] }) {
  let fallback = null;
  if (byDevice) {
    try { return { ...(await sealAtBirth({ storage, env, wanted, networkId, name, argon2id, cryptoImpl, say, under, except })), locked: true, fallback: null }; }
    catch (error) { if (error?.deviceLock !== true) throw error; fallback = birthWords(error); }
  }
  const keys = await sealedKeys({ wanted: wanted.map(w => ({ intent: w.intent })), networkId, name, argon2id, cryptoImpl, under });
  return { keys, locked: false, fallback };
}

/// "Let the wallet make my passwords" (Keys): the keys an account keeps in this browser under passwords a person chose
/// (records from before the rule) are sealed again, the same keys, under passwords the wallet makes now, and each new
/// record opened with its password. The opened keys are then wiped and the Web Lock let go, and only then are the new
/// passwords shown (`show`, awaited: review of 24 November 2026, finding 4). Under the lock again, and only if this browser
/// still keeps the account's keys as they were (else LOCK_WORDS.changed, and nothing is replaced), the places are replaced
/// together (both or neither, as turning the lock on does), or the one place of an account with one key. `login`,
/// `payment`: the passwords of now, of the places whose record is of a chosen password (vault.mjs, sealOf). Returns the
/// made passwords, by place. What this does not undo: copies of this browser's data and backup files made before still
/// open with the old passwords.
export async function remakePasswords({ storage, slots, networkId, name, login, payment, argon2id, cryptoImpl = globalThis.crypto, locks = null, say = () => {}, show = async () => {} }) {
  const journal = lockPlaces(networkId, name);
  // As turning the lock off: the person's own randomness first, before anything is opened.
  await readyToMake(2);
  const sealed = await underLock(locks, networkId, name, async () => {
    settleSwap(storage, slots, journal);
    const status = lockOf(storage, slots);
    if (status.on) throw new Error(LOCK_WORDS.alreadyOn);
    if (status.waiting) throw new Error(LOCK_WORDS.waiting);
    const before = keptNow(storage, slots);
    const places = [['login', slots.login, ['device', 'signin'], login, LOCK_WORDS.loginWrong], ['spend', slots.spend, ['spend'], payment, LOCK_WORDS.paymentWrong]]
      .map(([place, key, intents, typed, wrong]) => { const raw = read(storage, key); if (raw === null) return null; const record = validateVaultRecord(raw, intents); return { place, key, record, typed, wrong }; })
      .filter(item => item && sealOf(item.record) === 'chosen');
    if (!places.length) throw new Error(LOCK_WORDS.notChosen);
    const open = [];
    try {
      say(LOCK_WORDS.checking);
      for (const item of places) open.push({ ...item, opened: await opened(item.record, item.typed, argon2id, cryptoImpl, vaultIntent(item.record), null, item.wrong) });
      say(LOCK_WORDS.remaking);
      const next = {}, made = {};
      for (const item of open) {
        const password = makePassword(), intent = vaultIntent(item.record);
        next[item.place] = await sealVault(intent === 'device' ? { ...item.opened.secret } : { pkcs8: item.opened.secret.pkcs8 }, password, item.record.binding, argon2id, cryptoImpl, intent);
        const proof = await opened(next[item.place], password.text, argon2id, cryptoImpl, intent, null, item.wrong);
        forgetSecret(proof.secret); proof.privateKey = null;
        made[item.place === 'login' ? 'login' : 'payment'] = password.text;
      }
      return { next, made, before, keys: open.map(item => [item.place, item.key]) };
    } finally { for (const item of open) { forgetSecret(item.opened.secret); item.opened.privateKey = null; } }
  });
  await show(sealed.made);
  return underLock(locks, networkId, name, async () => {
    settleSwap(storage, slots, journal);
    unchanged(storage, slots, sealed.before);
    if (sealed.next.login && sealed.next.spend) swap(storage, slots, journal, sealed.next);
    else for (const [place, key] of sealed.keys) storage.setItem(key, JSON.stringify(sealed.next[place]));
    return sealed.made;
  });
}

// ---- opening and sealing while the lock is on --------------------------------------------------------------------------
/// What the page asks the device for while the lock is on. `say(text)`: shown before each request.
/// - `secretsFor(records)`: the secrets of one or two locked records (one request), held in this page's memory for
///   HOLD_MS so that a password typed wrong does not cost a new request; `release(records)` wipes them once the record
///   opened, `forgetAll()` on Lock and when the page hides. The values returned are copies, for the caller to wipe.
/// - `forNew(credential, keys)`: the secrets of one or two new keys (`{ networkId, name, publicKey, intent }`), one
///   request, nothing held.
export function createLockAsker({ env, say = () => {}, now = Date.now, holdMs = HOLD_MS }) {
  const held = new Map();
  const keyOf = (credential, salt) => `${credential}|${new TextDecoder().decode(salt)}`;
  function purge() { for (const [k, v] of held) if (v.until <= now()) { v.secret.fill(0); held.delete(k); } }
  async function ask(credential, salts) {
    await ableOrThrow(env);
    say(LOCK_WORDS.before);
    try { return await deviceSecrets(env, { credentialId: credential, salts }); } catch (error) { throw lockError(error); }
  }
  async function secretsFor(records) {
    purge();
    const credential = vaultDevice(records[0]);
    if (!credential || records.some(r => vaultDevice(r) !== credential)) throw new TypeError('Records locked to one device key');
    const salts = records.map(saltOfRecord), keys = salts.map(salt => keyOf(credential, salt));
    if (keys.every(k => held.has(k))) return keys.map(k => new Uint8Array(held.get(k).secret));
    const secrets = await ask(credential, salts);
    keys.forEach((k, i) => { held.get(k)?.secret.fill(0); held.set(k, { secret: new Uint8Array(secrets[i]), until: now() + holdMs }); });
    return secrets;
  }
  function release(records) {
    for (const record of records) { const credential = vaultDevice(record); if (!credential) continue; const k = keyOf(credential, saltOfRecord(record)); held.get(k)?.secret.fill(0); held.delete(k); }
  }
  function forgetAll() { for (const v of held.values()) v.secret.fill(0); held.clear(); }
  async function forNew(credential, keys) {
    return ask(credential, keys.map(k => lockSalt({ purpose: purposeOf(k.intent), networkId: k.networkId, name: k.name, publicKey: k.publicKey })));
  }
  return { secretsFor, release, forgetAll, forNew, holding: () => (purge(), held.size) };
}
