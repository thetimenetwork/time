// The device's own check of a person (fingerprint, face, or the device's screen lock), reached from a web page through
// WebAuthn, and a secret that only that check gives out. device-check.html is the page that tries it on a visitor's
// device and says, in plain words, what that device can do. The wallet uses makeDeviceKey, deviceSupport, deviceError
// and the outcomes below for "Lock my keys to this device" (device-lock.mjs: its own salts, which name the network, the
// account and the key, K-8), off by default; the record and salts of steps 2 and 3 are the trial's. No network or storage
// access is permitted in this module: every browser object comes in through `env` (browserEnv below), so that the tests
// drive it with a fake authenticator (device-key.test.mjs).
//
// How a secret is locked to a device
//   1. makeDeviceKey: the device's built-in authenticator makes a key of its own after it checked the person
//      (WebAuthn calls it a credential; browsers list it as a passkey), and the browser says whether that key can give
//      out a secret (the PRF extension of WebAuthn Level 3: `prf.enabled`).
//   2. deviceSecret: the device checks the person again and gives the page 32 bytes, an HMAC-SHA-256 of a salt under a
//      key that never leaves the device (CTAP2 hmac-secret; the browser first hashes the page's salt with "WebAuthn PRF"
//      and a zero byte, so that a page cannot ask for a value of another protocol). The salt is fixed per purpose
//      (saltFor: TIME-DEVICE-KEY-V1, a zero byte, the purpose): the same key and purpose always give the same 32 bytes,
//      another purpose other bytes. On hmac-secret the bytes with the person checked differ from those without; WebAuthn
//      requires the first ones for PRF, and every request here requires the check (userVerification: 'required') and
//      refuses an answer whose authenticator data does not say the person was checked (the UV flag).
//   3. wrapWithDevice / unwrapWithDevice: those 32 bytes, through HKDF-SHA-256 with a random salt of the record and the
//      purpose in its info, become an AES-256-GCM key, with a random 96-bit IV and the record's format, version, purpose
//      and credential id as additional authenticated data. The record is strict JSON and is refused on anything
//      unexpected, as vault.mjs refuses a vault. Without the device and its check the record opens for nobody.
// In the trial, passwords stay the other way in (vault.mjs): a key that is removed from the device, or a device that
// cannot do this, loses nothing. With the lock of device-lock.mjs on, they do not: a removed key leaves the recovery
// words as the way back (device-lock.mjs, LOCK_WORDS.keyGone).
//
// Which site the key belongs to: the relying party id (rp.id)
//   This trial leaves rp.id out of every request, so the browser takes the page's own host. A key works ONLY on the site
//   that made it: a wallet at another address, or at the same address under another rp.id, cannot ask for it, and what
//   it locked cannot be opened there. A production wallet has to choose this id deliberately, once, and keep it:
//   - the exact host of the wallet (e.g. wallet.example.org): only pages of that host can ask for the key; moving the
//     wallet to another address loses every device key (the passwords still open the account);
//   - a parent domain (example.org): the key then also works on every other host under it (a blog, a faucet, a shop of
//     the same domain), and any page of any of those hosts can ask the person's device for the wallet's secret. Not
//     acceptable unless every host under that domain is the wallet's.
//   Whatever the id, every page of the wallet's origin can ask for the key: a script that runs there by mistake (a
//   cross-site scripting flaw) gets the secret as soon as the person accepts the prompt, as it would get a typed
//   password. The strict Content-Security-Policy of the gateway (client-v4/server.mjs) is what keeps such scripts out.
//
// What a page can and cannot tell
//   - Support is uneven: the browser may say before trying whether it can do PRF (getClientCapabilities,
//     'extension:prf'), or say nothing; the key may say at creation (prf.enabled) or say nothing. Nothing here assumes:
//     deviceSupport reports 'yes', 'no' or 'unknown', and only a real request settles it.
//   - A request the person cancels, one that timed out, and one for a key the device no longer holds all end in the same
//     NotAllowedError in today's browsers, after the browser itself told the person there is no key. So deviceSecret
//     names no key in its request (a discoverable request: the device offers the keys it holds for this site) and
//     compares the key that answered with the one asked for: another key means the one asked for is gone (outcome 7).
//     A device that holds no key at all for the site ends as a cancel (outcome 6).
//   - isUserVerifyingPlatformAuthenticatorAvailable() says false both on a device without any screen lock and in a
//     browser without a built-in authenticator: outcome 4 covers both.
//   - Nothing in this module identifies the person: the key's user handle is random bytes and its name is a fixed label.
//     The browser's own error text never leaves here: an error is mapped to an outcome and to the name of its class.
//   - Nothing is checked on a server: the challenges are random and the signatures are not verified. The secret's
//     protection is the device's check, not the assertion; a wallet that also logs in to a server with the key would
//     need a server-side verification that this trial does not have.

const encoder = new TextEncoder();

export const DEVICE_KEY_LABEL = 'Time device check';
export const SALT_PREFIX = 'TIME-DEVICE-KEY-V1';
export const RECORD_FORMAT = 'time-device-key';
export const RECORD_VERSION = 1;
/// The purpose of the trial page's own secret. The wallet's purposes, later, are others (e.g. 'login', 'spend'): a key
/// asked for one purpose gives nothing usable for another.
export const CHECK_PURPOSE = 'device-check';
const PURPOSE = /^[a-z][a-z0-9-]{0,31}$/;
const TIMEOUT_MS = 120000;
const ASK_MS = 10000;
const MAX_PLAINTEXT = 4096;
const RECORD_FIELDS = 'ciphertext,credential,format,iv,purpose,salt,version';

/// What the person reads: one constant each, so that the wallet later says the same words.
export const DEVICE_MESSAGES = Object.freeze({
  works: 'This device can open and approve with your fingerprint or face.',
  noSupport: 'This browser cannot use fingerprint or face. Use your passwords.',
  inApp: 'If you opened this page from inside another app, open it in Chrome or Safari and try again.',
  noLock: "This device has no fingerprint, face or screen lock set up. Set one in the device's settings and try again.",
  noPrf: 'This device can check your fingerprint or face, but this browser cannot lock a key with it yet. Use your passwords here. Updating the browser or the system may change this.',
  cancelled: 'Nothing was changed. You can try again.',
  keyGone: "The key this device made is gone. It may have been removed in the device's settings. Use your passwords, and turn fingerprint or face on again if you want it.",
  other: 'This device did not finish the check. Use your passwords.',
  instead: 'Your passwords keep working. You open your account and approve payments with them, as before.',
  removeTestKey: "In your device's settings, under passwords or passkeys, remove 'Time device check' for this site.",
});

/// The closed list of outcomes. `says`: the sentences the person reads, in order.
export const OUTCOMES = Object.freeze({
  1: Object.freeze({ number: 1, name: 'works', says: ['works'] }),
  2: Object.freeze({ number: 2, name: 'no-support', says: ['noSupport'] }),
  3: Object.freeze({ number: 3, name: 'in-app', says: ['noSupport', 'inApp'] }),
  4: Object.freeze({ number: 4, name: 'no-lock', says: ['noLock'] }),
  5: Object.freeze({ number: 5, name: 'no-prf', says: ['noPrf'] }),
  6: Object.freeze({ number: 6, name: 'cancelled', says: ['cancelled'] }),
  7: Object.freeze({ number: 7, name: 'key-gone', says: ['keyGone'] }),
  8: Object.freeze({ number: 8, name: 'other', says: ['other'] }),
});

/// One outcome as the person reads it: the sentences, and what happens instead (every outcome but the first).
/// On a phone a browser without support may be an app's own window (outcome 2 becomes 3), and a phone that says it has
/// no screen lock may be one too: outcome 4 then also says to open the page in Chrome or Safari.
export function outcomeOf(number, { phone = false, errorClass = null } = {}) {
  let n = Number(number);
  if (!OUTCOMES[n]) n = 8;
  if (n === 2 && phone) n = 3;
  const keys = n === 4 && phone ? ['noLock', 'inApp'] : OUTCOMES[n].says;
  return { number: n, name: OUTCOMES[n].name, says: keys.map((key) => DEVICE_MESSAGES[key]), instead: n === 1 ? null : DEVICE_MESSAGES.instead, errorClass: errorClass === null ? null : errorClassOf({ name: errorClass }) };
}

/// The names of error classes a report may carry. Anything else is reported as 'Error'; no message text ever is.
const ERROR_CLASSES = new Set(['NotAllowedError', 'AbortError', 'TimeoutError', 'ConstraintError', 'InvalidStateError', 'NotSupportedError', 'SecurityError',
  'TypeError', 'UnknownError', 'NotReadableError', 'OperationError', 'DataError', 'SyntaxError', 'EncodingError', 'InvalidAccessError', 'NetworkError', 'RangeError',
  // This module's own: another key answered, the answer did not say the person was checked, no secret came, a secret of
  // the wrong length, two answers that differ, a locked record refused, no key in the answer.
  'OtherKey', 'NotVerified', 'NoPrfResult', 'BadSecretLength', 'SecretsDiffer', 'RecordRefused', 'NoCredential']);
export function errorClassOf(error) {
  let name = '';
  try { name = typeof error?.name === 'string' ? error.name : ''; } catch { name = ''; }
  return ERROR_CLASSES.has(name) ? name : 'Error';
}

/// An error of this module: an outcome and an error class, with the outcome's first sentence as its message.
export class DeviceKeyError extends Error {
  constructor(outcome, errorClass = null) {
    const n = OUTCOMES[outcome] ? outcome : 8;
    super(DEVICE_MESSAGES[OUTCOMES[n].says[0]]);
    this.name = 'DeviceKeyError'; this.outcome = n; this.errorClass = errorClass === null ? null : errorClassOf({ name: errorClass });
  }
}
/// A browser error mapped to an outcome. Cancel, timeout and abort: 6. A device that cannot check the person or keep a
/// key (ConstraintError, at creation): 4. A request the browser cannot do at all (NotSupportedError): 2. Anything else,
/// an address the browser refuses (SecurityError) included: 8.
export function deviceError(error) {
  if (error instanceof DeviceKeyError) return error;
  const errorClass = errorClassOf(error);
  const n = { NotAllowedError: 6, AbortError: 6, TimeoutError: 6, ConstraintError: 4, NotSupportedError: 2 }[errorClass] ?? 8;
  return new DeviceKeyError(n, errorClass);
}

// ---- bytes ---------------------------------------------------------------------------------------------------------
const view = (value) => (value instanceof Uint8Array ? value : value instanceof ArrayBuffer ? new Uint8Array(value) : ArrayBuffer.isView(value) ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength) : null);
/// Overwrites secret bytes in place (a Uint8Array, an ArrayBuffer or another view of one).
export function forget(...values) { for (const value of values) { const bytes = view(value); if (bytes) bytes.fill(0); } }
export function sameBytes(a, b) {
  const x = view(a), y = view(b);
  if (!x || !y || x.length !== y.length) return false;
  let diff = 0; for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}
function b64(bytes) { let s = ''; for (const b of view(bytes)) s += String.fromCharCode(b); return btoa(s); }
function fromB64(text, min, max) {
  if (typeof text !== 'string' || text.length > Math.ceil(max / 3) * 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) throw new DeviceKeyError(8, 'RecordRefused');
  let raw; try { raw = atob(text); } catch { throw new DeviceKeyError(8, 'RecordRefused'); }
  const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0));
  if (bytes.length < min || bytes.length > max || b64(bytes) !== text) throw new DeviceKeyError(8, 'RecordRefused');
  return bytes;
}
export const base64url = (bytes) => b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
/// A credential id or a user handle as base64url without padding, canonical, of `min` to `max` bytes; null if it is not.
export function fromBase64url(text, min = 16, max = 1023) {
  if (typeof text !== 'string' || text.length > Math.ceil(max / 3) * 4 || !/^[A-Za-z0-9_-]+$/.test(text)) return null;
  let raw; try { raw = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4)); } catch { return null; }
  const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0));
  return bytes.length >= min && bytes.length <= max && base64url(bytes) === text ? bytes : null;
}
function checkPurpose(purpose) { if (typeof purpose !== 'string' || !PURPOSE.test(purpose)) throw new TypeError('A purpose is 1 to 32 lowercase letters, digits or hyphens, starting with a letter'); return purpose; }
/// The salt the device's key is asked with: TIME-DEVICE-KEY-V1, a zero byte, the purpose.
export function saltFor(purpose) {
  const prefix = encoder.encode(SALT_PREFIX), tail = encoder.encode(checkPurpose(purpose)), salt = new Uint8Array(prefix.length + 1 + tail.length);
  salt.set(prefix, 0); salt.set(tail, prefix.length + 1);
  return salt;
}
/// The flags byte of WebAuthn authenticator data (after the 32-byte hash of the rp id): the person was present (UP),
/// checked (UV), the key may be copied to a backup (BE), the key is copied to a backup now (BS). Null if unreadable.
export function authenticatorFlags(data) {
  const bytes = view(data);
  if (!bytes || bytes.length < 37) return null;
  const f = bytes[32];
  return { up: (f & 0x01) !== 0, uv: (f & 0x04) !== 0, be: (f & 0x08) !== 0, bs: (f & 0x10) !== 0 };
}

// ---- the browser -----------------------------------------------------------------------------------------------------
/// What this module needs of a browser window, taken from it once. `phone`: a phone or a tablet, as the browser
/// describes itself (only used to add the sentence about apps' own windows).
export function browserEnv(win) {
  const nav = win?.navigator, agent = String(nav?.userAgent ?? '');
  const phone = nav?.userAgentData?.mobile === true || /Android|iPhone|iPad|iPod|Mobile/i.test(agent) || (nav?.platform === 'MacIntel' && Number(nav?.maxTouchPoints) > 1);
  return { secureContext: win?.isSecureContext === true, credentials: nav?.credentials, PublicKeyCredential: win?.PublicKeyCredential, crypto: win?.crypto, phone };
}
const hasWebAuthn = (env) => typeof env?.PublicKeyCredential === 'function' && typeof env?.credentials?.create === 'function' && typeof env?.credentials?.get === 'function';
/// A promise that may never settle in some browsers is given ASK_MS.
const within = (promise, ms = ASK_MS) => Promise.race([promise, new Promise((resolve) => { const t = setTimeout(() => resolve(undefined), ms); t.unref?.(); })]);
const yesNo = (value) => (value === true ? 'yes' : value === false ? 'no' : 'unknown');

/// What the browser says it can do, before anything is tried: a secure page; WebAuthn there; a built-in authenticator
/// that checks the person ('yes', 'no', 'unknown'); PRF ('yes', 'no', 'unknown': only getClientCapabilities says, where
/// it exists). `outcome`: 2, 3 or 4 when trying is pointless, else null. Nothing that identifies the person.
export async function deviceSupport(env) {
  const secureContext = env?.secureContext === true, webAuthn = hasWebAuthn(env), phone = env?.phone === true;
  let builtIn = 'unknown', prf = 'unknown', capabilities = false;
  if (secureContext && webAuthn) {
    const PKC = env.PublicKeyCredential;
    let caps = null;
    if (typeof PKC.getClientCapabilities === 'function') {
      try { caps = await within(PKC.getClientCapabilities()); } catch { caps = null; }
      if (caps && typeof caps === 'object') { capabilities = true; prf = yesNo(caps['extension:prf']); }
    }
    if (typeof PKC.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
      try { builtIn = yesNo(await within(PKC.isUserVerifyingPlatformAuthenticatorAvailable())); } catch { builtIn = 'unknown'; }
    }
    if (builtIn === 'unknown' && capabilities) builtIn = yesNo(caps.userVerifyingPlatformAuthenticator);
  }
  const outcome = !secureContext || !webAuthn ? (phone ? 3 : 2) : builtIn === 'no' ? 4 : null;
  return { secureContext, webAuthn, builtIn, prf, capabilities, phone, outcome };
}
function requireWebAuthn(env) { if (env?.secureContext !== true || !hasWebAuthn(env)) throw new DeviceKeyError(2, 'NotSupportedError'); }
function extensionsOf(credential) { try { const r = credential.getClientExtensionResults?.(); return r && typeof r === 'object' ? r : {}; } catch { return {}; } }

/// Makes a key on the device's built-in authenticator, after the device checked the person. `label`: the name the
/// device lists it under (fixed, never a person's name). `userHandle`: the key's user handle, 16 to 64 random bytes
/// (a new one when left out); the same handle again on the same site replaces the earlier key on most devices.
/// Returns the key's id (base64url), whether the browser says it can give out a secret ('prfEnabled': true, false, or
/// null when it said nothing), and what the device says of a backup copy of the key.
export async function makeDeviceKey(env, { label = DEVICE_KEY_LABEL, userHandle } = {}) {
  requireWebAuthn(env);
  if (typeof label !== 'string' || !/^[\x20-\x7e]{1,64}$/.test(label)) throw new TypeError('A label is 1 to 64 printable characters');
  const handle = userHandle === undefined ? env.crypto.getRandomValues(new Uint8Array(16)) : view(userHandle);
  if (!handle || handle.length < 16 || handle.length > 64) throw new TypeError('A user handle is 16 to 64 bytes');
  const options = { publicKey: {
    rp: { name: 'Time' }, // no id: the page's own host (see the top of this file)
    user: { id: new Uint8Array(handle), name: label, displayName: label },
    challenge: env.crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [{ type: 'public-key', alg: -8 }, { type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
    hints: ['client-device'], attestation: 'none', timeout: TIMEOUT_MS,
    extensions: { prf: {} },
  } };
  let credential;
  try { credential = await env.credentials.create(options); } catch (error) { throw deviceError(error); }
  if (!credential || credential.type !== 'public-key' || !view(credential.rawId)) throw new DeviceKeyError(8, 'NoCredential');
  const prf = extensionsOf(credential).prf;
  // A secret given at creation (fewer devices do) is not used: deviceSecret asks for it as the wallet would.
  if (prf?.results) forget(prf.results.first, prf.results.second);
  let data = null; try { data = credential.response?.getAuthenticatorData?.() ?? null; } catch { data = null; }
  const flags = authenticatorFlags(data);
  return { credentialId: base64url(view(credential.rawId)), prfEnabled: typeof prf?.enabled === 'boolean' ? prf.enabled : null, userVerified: flags ? flags.uv : null, backupEligible: flags ? flags.be : null, backedUp: flags ? flags.bs : null };
}

/// Asks the device for the 32 bytes of `purpose` under the key `credentialId`, after it checked the person. The request
/// names no key (see the top of this file); an answer from another key is outcome 7, an answer without the person
/// checked is outcome 8, an answer without a secret is outcome 5. The caller wipes `secret` after use (forget).
export async function deviceSecret(env, { credentialId, purpose }) {
  requireWebAuthn(env);
  const wanted = fromBase64url(credentialId);
  if (!wanted) throw new TypeError('A credential id is 16 to 1023 bytes in canonical base64url');
  const options = { publicKey: {
    challenge: env.crypto.getRandomValues(new Uint8Array(32)), timeout: TIMEOUT_MS, userVerification: 'required', hints: ['client-device'],
    extensions: { prf: { eval: { first: saltFor(purpose) } } },
  } };
  let assertion;
  try { assertion = await env.credentials.get(options); } catch (error) { throw deviceError(error); }
  if (!assertion || assertion.type !== 'public-key' || !view(assertion.rawId)) throw new DeviceKeyError(8, 'NoCredential');
  const results = extensionsOf(assertion).prf?.results, first = results?.first;
  try {
    if (!sameBytes(view(assertion.rawId), wanted)) throw new DeviceKeyError(7, 'OtherKey');
    let data = null; try { data = assertion.response?.authenticatorData ?? null; } catch { data = null; }
    if (!authenticatorFlags(data)?.uv) throw new DeviceKeyError(8, 'NotVerified');
    const bytes = view(first);
    if (!bytes) throw new DeviceKeyError(5, 'NoPrfResult');
    if (bytes.length !== 32) throw new DeviceKeyError(8, 'BadSecretLength');
    return { secret: new Uint8Array(bytes), credentialId };
  } finally { forget(first, results?.second); }
}

// ---- the locked record -----------------------------------------------------------------------------------------------
function checkSecret(secret) { const s = view(secret); if (!s || s.length !== 32) throw new TypeError('A device secret is 32 bytes'); return s; }
function checkCredential(id) { if (!fromBase64url(id)) throw new TypeError('A credential id is 16 to 1023 bytes in canonical base64url'); return id; }
function info(purpose) { const a = encoder.encode(SALT_PREFIX), b = encoder.encode('wrap'), c = encoder.encode(purpose), out = new Uint8Array(a.length + b.length + c.length + 2); out.set(a, 0); out.set(b, a.length + 1); out.set(c, a.length + b.length + 2); return out; }
async function wrapKey(secret, salt, purpose, cryptoImpl) {
  const base = await cryptoImpl.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  return cryptoImpl.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: info(purpose) }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
const headerOf = ({ purpose, credential }) => ({ format: RECORD_FORMAT, version: RECORD_VERSION, purpose, credential });
const aad = (head) => encoder.encode(JSON.stringify(head));

/// Locks `plaintext` (1 to 4096 bytes) with a device secret. Returns the record:
/// { format: 'time-device-key', version: 1, purpose, credential, salt, iv, ciphertext } (the last three in base64).
export async function wrapWithDevice({ secret, credentialId, purpose, plaintext }, cryptoImpl = globalThis.crypto) {
  const s = checkSecret(secret), head = headerOf({ purpose: checkPurpose(purpose), credential: checkCredential(credentialId) }), plain = view(plaintext);
  if (!plain || plain.length < 1 || plain.length > MAX_PLAINTEXT) throw new TypeError('What is locked is 1 to 4096 bytes');
  const salt = cryptoImpl.getRandomValues(new Uint8Array(16)), iv = cryptoImpl.getRandomValues(new Uint8Array(12));
  const key = await wrapKey(s, salt, head.purpose, cryptoImpl);
  const ciphertext = await cryptoImpl.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(head), tagLength: 128 }, key, plain);
  return { ...head, salt: b64(salt), iv: b64(iv), ciphertext: b64(ciphertext) };
}
/// The record as it must be, field by field; anything else is refused (outcome 8, 'RecordRefused').
export function validateDeviceRecord(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record) || Object.getPrototypeOf(record) !== Object.prototype || Object.keys(record).sort().join(',') !== RECORD_FIELDS
    || record.format !== RECORD_FORMAT || record.version !== RECORD_VERSION || typeof record.purpose !== 'string' || !PURPOSE.test(record.purpose) || !fromBase64url(record.credential)) throw new DeviceKeyError(8, 'RecordRefused');
  fromB64(record.salt, 16, 16); fromB64(record.iv, 12, 12); fromB64(record.ciphertext, 17, MAX_PLAINTEXT + 16);
  return { ...headerOf(record), salt: record.salt, iv: record.iv, ciphertext: record.ciphertext };
}
/// Opens a record with a device secret, for `purpose` and the key `credentialId` only. A record of another purpose or
/// key, a changed record and a wrong secret are all refused alike. The caller wipes what it returns (forget).
export async function unwrapWithDevice({ secret, credentialId, purpose, record }, cryptoImpl = globalThis.crypto) {
  const s = checkSecret(secret), r = validateDeviceRecord(record);
  if (r.purpose !== checkPurpose(purpose) || r.credential !== checkCredential(credentialId)) throw new DeviceKeyError(8, 'RecordRefused');
  const salt = fromB64(r.salt, 16, 16), iv = fromB64(r.iv, 12, 12), ciphertext = fromB64(r.ciphertext, 17, MAX_PLAINTEXT + 16);
  try {
    const key = await wrapKey(s, salt, r.purpose, cryptoImpl);
    return new Uint8Array(await cryptoImpl.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad(headerOf(r)), tagLength: 128 }, key, ciphertext));
  } catch { throw new DeviceKeyError(8, 'RecordRefused'); }
}

// ---- the trial: device-check.html ---------------------------------------------------------------------------------------
/// The steps of a check, each 'yes', 'no', 'unknown' or 'not run'. Fixed fields: the report holds these and no others.
export const STEP_FIELDS = Object.freeze(['secure', 'webAuthn', 'builtIn', 'prfBefore', 'keyMade', 'prfAtCreation', 'backedUp', 'firstAnswer', 'secondAnswer', 'same', 'opened']);
const freshSteps = () => Object.fromEntries(STEP_FIELDS.map((field) => [field, 'not run']));

async function supportStep(env, steps, onStep) {
  const support = await deviceSupport(env);
  Object.assign(steps, { secure: yesNo(support.secureContext), webAuthn: yesNo(support.webAuthn), builtIn: support.webAuthn && support.secureContext ? support.builtIn : 'not run', prfBefore: support.webAuthn && support.secureContext ? support.prf : 'not run' });
  onStep('support', { ...steps });
  return support;
}

/// The whole check of device-check.html: what the browser says; a test key made; the device asked twice, and the two
/// secrets compared; a random value locked with the first and opened with the second. `onStep(name, steps)` after each
/// step. Returns { outcome (outcomeOf), steps, keyMade, kept }: `kept` is what the page may keep to try the same key
/// again later (checkEarlierKey): the key's id, its user handle and a record locked with it. Every secret is wiped.
export async function checkDevice(env, { onStep = () => {}, userHandle, purpose = CHECK_PURPOSE } = {}) {
  const steps = freshSteps(), held = [];
  let keyMade = false, kept = null;
  const finish = (number, errorClass = null) => ({ outcome: outcomeOf(number, { phone: env?.phone === true, errorClass }), steps: { ...steps }, keyMade, kept });
  try {
    const support = await supportStep(env, steps, onStep);
    if (support.outcome !== null) return finish(support.outcome);
    const handle = userHandle === undefined ? env.crypto.getRandomValues(new Uint8Array(16)) : view(userHandle);
    let made;
    try { made = await makeDeviceKey(env, { userHandle: handle }); } catch (error) { steps.keyMade = 'no'; onStep('made', { ...steps }); const e = deviceError(error); return finish(e.outcome, e.errorClass); }
    keyMade = true;
    Object.assign(steps, { keyMade: 'yes', prfAtCreation: yesNo(made.prfEnabled), backedUp: yesNo(made.backedUp) });
    onStep('made', { ...steps });
    // The browser said plainly that this key gives out no secret: asking the device twice more would only bother the person.
    if (made.prfEnabled === false) return finish(5, 'NoPrfResult');
    const ask = async (field) => {
      try { const answer = await deviceSecret(env, { credentialId: made.credentialId, purpose }); held.push(answer.secret); steps[field] = 'yes'; onStep(field, { ...steps }); return answer.secret; }
      catch (error) { steps[field] = 'no'; onStep(field, { ...steps }); throw deviceError(error); }
    };
    let first, second;
    try { first = await ask('firstAnswer'); second = await ask('secondAnswer'); } catch (error) { return finish(error.outcome, error.errorClass); }
    steps.same = sameBytes(first, second) ? 'yes' : 'no';
    onStep('same', { ...steps });
    if (steps.same !== 'yes') return finish(8, 'SecretsDiffer');
    const value = env.crypto.getRandomValues(new Uint8Array(32)); held.push(value);
    let record, opened;
    try {
      record = await wrapWithDevice({ secret: first, credentialId: made.credentialId, purpose, plaintext: value }, env.crypto);
      opened = await unwrapWithDevice({ secret: second, credentialId: made.credentialId, purpose, record }, env.crypto); held.push(opened);
    } catch (error) { steps.opened = 'no'; onStep('opened', { ...steps }); const e = deviceError(error); return finish(e.outcome, e.errorClass); }
    steps.opened = sameBytes(opened, value) ? 'yes' : 'no';
    onStep('opened', { ...steps });
    if (steps.opened !== 'yes') return finish(8, 'RecordRefused');
    kept = { credentialId: made.credentialId, userHandle: base64url(handle), record };
    return finish(1);
  } catch (error) { const e = deviceError(error); return finish(e.outcome, e.errorClass); }
  finally { forget(...held); }
}

/// The same key again, later (after a restart of the device, an update, or its removal in the settings): the device is
/// asked once, and the record locked with it when it was made must open. Steps that this run does not do stay 'not run';
/// `keyMade` is 'earlier'.
export async function checkEarlierKey(env, { credentialId, record, onStep = () => {}, purpose = CHECK_PURPOSE } = {}) {
  const steps = freshSteps(), held = [];
  const finish = (number, errorClass = null) => ({ outcome: outcomeOf(number, { phone: env?.phone === true, errorClass }), steps: { ...steps }, keyMade: false, kept: null });
  try {
    const support = await supportStep(env, steps, onStep);
    if (support.outcome !== null) return finish(support.outcome);
    // A kept record that is not one, or not of this key and purpose, is refused before the person is asked anything.
    try { const r = validateDeviceRecord(record); if (r.credential !== credentialId || r.purpose !== purpose) throw new DeviceKeyError(8, 'RecordRefused'); }
    catch (error) { const e = deviceError(error); return finish(e.outcome, e.errorClass); }
    steps.keyMade = 'earlier';
    let secret;
    try { secret = (await deviceSecret(env, { credentialId, purpose })).secret; held.push(secret); steps.firstAnswer = 'yes'; onStep('firstAnswer', { ...steps }); }
    catch (error) { steps.firstAnswer = 'no'; onStep('firstAnswer', { ...steps }); const e = deviceError(error); return finish(e.outcome, e.errorClass); }
    try { const opened = await unwrapWithDevice({ secret, credentialId, purpose, record }, env.crypto); held.push(opened); steps.opened = 'yes'; }
    catch (error) { steps.opened = 'no'; onStep('opened', { ...steps }); const e = deviceError(error); return finish(e.outcome, e.errorClass); }
    onStep('opened', { ...steps });
    return finish(1);
  } catch (error) { const e = deviceError(error); return finish(e.outcome, e.errorClass); }
  finally { forget(...held); }
}

/// The report the person may send: fixed fields only. `userAgent` and `host` are the browser's, cut to printable text.
export function deviceReport(result, { userAgent = '', host = '' } = {}) {
  const clean = (text, max) => String(text).replace(/[^\x20-\x7e]/g, '?').slice(0, max);
  const steps = { ...freshSteps(), ...(result?.steps ?? {}) };
  const value = (field) => (['yes', 'no', 'unknown', 'not run', 'earlier'].includes(steps[field]) ? steps[field] : 'unknown');
  return [
    'Time device check, report 1',
    `outcome: ${result?.outcome?.number ?? 'none'}`,
    ...STEP_FIELDS.map((field) => `${field}: ${value(field)}`),
    `error: ${result?.outcome?.errorClass ?? 'none'}`,
    `browser: ${clean(userAgent, 400)}`,
    `address: ${clean(host, 253)}`,
  ].join('\n');
}
