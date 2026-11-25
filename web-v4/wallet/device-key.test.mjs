// The device's own check (device-key.mjs) against a fake authenticator: a device that makes keys, checks the person,
// and gives out a PRF secret the way CTAP2 hmac-secret does (HMAC-SHA-256 under a key of each credential, of the salt
// the browser makes: SHA-256 of "WebAuthn PRF", a zero byte and the page's salt). Its switches stand for the devices
// and browsers the trial page meets: no WebAuthn, not a secure page, no built-in authenticator, a key without PRF, a key
// that says nothing, a key with PRF that gives no secret, a person who cancels, a key that is gone, and odd errors.
// Each of the eight outcomes is reached and mapped; what a real browser does is device-check.html's to find out.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import * as D from './device-key.mjs';

const prfOf = (key, salt) => createHmac('sha256', key).update(createHash('sha256').update(Buffer.concat([Buffer.from('WebAuthn PRF'), Buffer.from([0]), Buffer.from(salt)])).digest()).digest();
const buffer = (bytes) => { const copy = new ArrayBuffer(bytes.length); new Uint8Array(copy).set(bytes); return copy; };
// The browser's own words, which must never reach what the person reads or the report.
const BROWSER_WORDS = 'zq-the-browser-own-words';
const domError = (name, message = `${BROWSER_WORDS}: details the browser gives`) => new DOMException(message, name);

/// A device. `s`: the switches. `keys`: what it holds, newest last. `given`: every PRF buffer it handed out (to see
/// that the module wipes them).
function fakeDevice(s = {}) {
  const keys = [], calls = [], given = [];
  const authData = ({ uv = true } = {}) => { const b = new Uint8Array(37); b.set(createHash('sha256').update('wallet.example').digest()); b[32] = 0x01 | (uv ? 0x04 : 0) | (s.backup ? 0x18 : 0); return buffer(b); };
  class PublicKeyCredential {
    static async isUserVerifyingPlatformAuthenticatorAvailable() { return !s.noBuiltIn; }
  }
  if (s.capabilities !== false) PublicKeyCredential.getClientCapabilities = async () => ({ userVerifyingPlatformAuthenticator: !s.noBuiltIn, ...(s.capabilities === 'silent' ? {} : { 'extension:prf': !s.prfNotEnabled && !s.prfSilent }) });
  const credentials = {
    async create(options) {
      calls.push(['create', options]);
      if (s.createError) throw domError(s.createError);
      const p = options.publicKey, handle = Buffer.from(p.user.id);
      // A key made again with the same user handle replaces the earlier one, as most devices do.
      for (let i = keys.length - 1; i >= 0; i--) if (keys[i].handle.equals(handle)) keys.splice(i, 1);
      const key = { id: randomBytes(32), secret: randomBytes(32), handle };
      keys.push(key);
      const prf = s.prfNotEnabled ? { enabled: false } : s.prfSilent ? undefined : { enabled: true };
      return { type: 'public-key', rawId: buffer(key.id), response: { getAuthenticatorData: () => authData() }, getClientExtensionResults: () => (prf ? { prf } : {}) };
    },
    async get(options) {
      calls.push(['get', options]);
      if (s.getError) throw domError(s.getError);
      const p = options.publicKey;
      // A discoverable request: the device offers what it holds for the site; the person takes the newest one.
      if (!keys.length) throw domError('NotAllowedError');
      const key = keys.at(-1), salt = p.extensions?.prf?.eval?.first;
      let results;
      if (salt && !s.prfNotEnabled && !s.prfSilent && !s.noResultAtGet) {
        const out = prfOf(key.secret, salt), first = buffer(s.shortSecret ? out.subarray(0, 16) : out);
        given.push(first); results = { prf: { results: { first } } };
      }
      return { type: 'public-key', rawId: buffer(key.id), response: { authenticatorData: authData({ uv: !s.noUv }) }, getClientExtensionResults: () => results ?? (s.prfSilent ? {} : { prf: {} }) };
    },
  };
  const env = { secureContext: !s.insecure, credentials: s.noWebAuthn ? undefined : credentials, PublicKeyCredential: s.noWebAuthn ? undefined : PublicKeyCredential, crypto: globalThis.crypto, phone: s.phone === true };
  return { env, keys, calls, given, remove: () => keys.splice(0) };
}
const creates = (device) => device.calls.filter(([kind]) => kind === 'create');
const gets = (device) => device.calls.filter(([kind]) => kind === 'get');

test('outcome 1: a device that checks the person and gives a secret; the requests are the ones the trial means', async () => {
  const device = fakeDevice({ backup: true }), seen = [];
  const result = await D.checkDevice(device.env, { onStep: (name) => seen.push(name) });
  assert.equal(result.outcome.number, 1);
  assert.deepEqual(result.outcome.says, [D.DEVICE_MESSAGES.works]);
  assert.equal(result.outcome.instead, null);
  assert.equal(result.outcome.errorClass, null);
  assert.deepEqual(result.steps, { secure: 'yes', webAuthn: 'yes', builtIn: 'yes', prfBefore: 'yes', keyMade: 'yes', prfAtCreation: 'yes', backedUp: 'yes', firstAnswer: 'yes', secondAnswer: 'yes', same: 'yes', opened: 'yes' });
  assert.deepEqual(seen, ['support', 'made', 'firstAnswer', 'secondAnswer', 'same', 'opened']);
  assert.equal(result.keyMade, true);
  // The key is made on the device's own authenticator, kept on it, after the person was checked, with PRF asked for.
  assert.equal(creates(device).length, 1);
  const made = creates(device)[0][1].publicKey;
  assert.deepEqual(made.authenticatorSelection, { authenticatorAttachment: 'platform', residentKey: 'required', requireResidentKey: true, userVerification: 'required' });
  assert.deepEqual(made.extensions, { prf: {} });
  assert.equal(made.rp.id, undefined, 'the relying party id is the page\'s own host');
  // No name of a person: a fixed label, and a random handle.
  assert.equal(made.user.name, D.DEVICE_KEY_LABEL); assert.equal(made.user.displayName, D.DEVICE_KEY_LABEL);
  assert.equal(made.user.id.length, 16);
  assert.equal(made.challenge.length, 32);
  // Asked twice, each time with the person checked and the salt of the purpose; no key named in the request.
  assert.equal(gets(device).length, 2);
  for (const [, options] of gets(device)) {
    assert.equal(options.publicKey.userVerification, 'required');
    assert.equal(options.publicKey.allowCredentials, undefined);
    assert.deepEqual(Buffer.from(options.publicKey.extensions.prf.eval.first), Buffer.concat([Buffer.from('TIME-DEVICE-KEY-V1'), Buffer.from([0]), Buffer.from('device-check')]));
  }
  // What the page may keep: the key's id, the handle, and a record that opens only with the device.
  assert.equal(result.kept.credentialId, D.base64url(device.keys[0].id));
  assert.equal(result.kept.userHandle, D.base64url(made.user.id));
  assert.deepEqual(Object.keys(result.kept.record).sort(), ['ciphertext', 'credential', 'format', 'iv', 'purpose', 'salt', 'version']);
  // Every secret the device gave out was wiped once used.
  assert.equal(device.given.length, 2);
  for (const first of device.given) assert.ok(new Uint8Array(first).every((b) => b === 0), 'a PRF buffer of the browser is wiped');
});

test('outcome 1 again later: the key made earlier answers and the record it locked opens; the same handle replaces a key', async () => {
  const device = fakeDevice();
  const first = await D.checkDevice(device.env);
  const later = await D.checkEarlierKey(device.env, { credentialId: first.kept.credentialId, record: first.kept.record });
  assert.equal(later.outcome.number, 1);
  assert.equal(later.steps.keyMade, 'earlier'); assert.equal(later.steps.firstAnswer, 'yes'); assert.equal(later.steps.opened, 'yes');
  assert.equal(later.steps.secondAnswer, 'not run');
  // A new check with the handle kept: the device holds one test key, not two.
  const again = await D.checkDevice(device.env, { userHandle: D.fromBase64url(first.kept.userHandle, 16, 64) });
  assert.equal(again.outcome.number, 1);
  assert.equal(device.keys.length, 1);
  assert.notEqual(again.kept.credentialId, first.kept.credentialId);
});

test('outcome 2 and 3: no WebAuthn or not a secure page; on a phone the sentence about apps\' own windows is added', async () => {
  for (const s of [{ noWebAuthn: true }, { insecure: true }]) {
    const device = fakeDevice(s), result = await D.checkDevice(device.env);
    assert.equal(result.outcome.number, 2, JSON.stringify(s));
    assert.deepEqual(result.outcome.says, [D.DEVICE_MESSAGES.noSupport]);
    assert.equal(result.outcome.instead, D.DEVICE_MESSAGES.instead);
    assert.equal(device.calls.length, 0, 'nothing is tried');
    assert.equal(result.steps.keyMade, 'not run');
  }
  const support = await D.deviceSupport(fakeDevice({ insecure: true }).env);
  assert.deepEqual(support, { secureContext: false, webAuthn: true, builtIn: 'unknown', prf: 'unknown', capabilities: false, phone: false, outcome: 2 });
  const phone = await D.checkDevice(fakeDevice({ noWebAuthn: true, phone: true }).env);
  assert.equal(phone.outcome.number, 3);
  assert.deepEqual(phone.outcome.says, [D.DEVICE_MESSAGES.noSupport, D.DEVICE_MESSAGES.inApp]);
  // A request the browser cannot do at all (no algorithm it supports) is outcome 2 as well.
  const unsupported = await D.checkDevice(fakeDevice({ createError: 'NotSupportedError' }).env);
  assert.equal(unsupported.outcome.number, 2); assert.equal(unsupported.outcome.errorClass, 'NotSupportedError');
});

test('outcome 4: no built-in check of the person, before anything is tried, or refused by the device when the key is made', async () => {
  const device = fakeDevice({ noBuiltIn: true }), result = await D.checkDevice(device.env);
  assert.equal(result.outcome.number, 4);
  assert.deepEqual(result.outcome.says, [D.DEVICE_MESSAGES.noLock]);
  assert.equal(result.steps.builtIn, 'no');
  assert.equal(creates(device).length, 0, 'no key is made');
  const phone = await D.checkDevice(fakeDevice({ noBuiltIn: true, phone: true }).env);
  assert.deepEqual(phone.outcome.says, [D.DEVICE_MESSAGES.noLock, D.DEVICE_MESSAGES.inApp]);
  const refused = await D.checkDevice(fakeDevice({ createError: 'ConstraintError' }).env);
  assert.equal(refused.outcome.number, 4); assert.equal(refused.outcome.errorClass, 'ConstraintError'); assert.equal(refused.steps.keyMade, 'no');
});

test('outcome 5: a key that cannot lock a secret, said at creation, said by nobody, or said and not done', async () => {
  // Said plainly when the key is made: the device is not asked again.
  const said = fakeDevice({ prfNotEnabled: true }), a = await D.checkDevice(said.env);
  assert.equal(a.outcome.number, 5); assert.deepEqual(a.outcome.says, [D.DEVICE_MESSAGES.noPrf]);
  assert.equal(a.steps.prfAtCreation, 'no'); assert.equal(a.steps.prfBefore, 'no'); assert.equal(gets(said).length, 0);
  assert.equal(a.keyMade, true, 'the test key was made: the page says how to remove it');
  // The browser says nothing, before or at creation: only asking settles it.
  const silent = fakeDevice({ prfSilent: true, capabilities: 'silent' }), b = await D.checkDevice(silent.env);
  assert.equal(b.outcome.number, 5); assert.equal(b.steps.prfBefore, 'unknown'); assert.equal(b.steps.prfAtCreation, 'unknown'); assert.equal(b.steps.firstAnswer, 'no');
  assert.equal(gets(silent).length, 1);
  // Enabled when made, and no secret when asked.
  const c = await D.checkDevice(fakeDevice({ noResultAtGet: true }).env);
  assert.equal(c.outcome.number, 5); assert.equal(c.outcome.errorClass, 'NoPrfResult'); assert.equal(c.steps.prfAtCreation, 'yes'); assert.equal(c.steps.firstAnswer, 'no');
  // A browser without getClientCapabilities: what it can do is not known before trying.
  const old = await D.deviceSupport(fakeDevice({ capabilities: false }).env);
  assert.equal(old.prf, 'unknown'); assert.equal(old.capabilities, false); assert.equal(old.builtIn, 'yes'); assert.equal(old.outcome, null);
});

test('outcome 6: the person cancels, or the prompt times out, when the key is made or when it is asked', async () => {
  for (const [s, made] of [[{ createError: 'NotAllowedError' }, 'no'], [{ createError: 'AbortError' }, 'no'], [{ getError: 'NotAllowedError' }, 'yes'], [{ getError: 'TimeoutError' }, 'yes']]) {
    const result = await D.checkDevice(fakeDevice(s).env);
    assert.equal(result.outcome.number, 6, JSON.stringify(s));
    assert.deepEqual(result.outcome.says, [D.DEVICE_MESSAGES.cancelled]);
    assert.equal(result.outcome.errorClass, s.createError ?? s.getError);
    assert.equal(result.steps.keyMade, made);
  }
});

test('outcome 7: the key made earlier is gone; a device that holds no key at all ends as a cancel, as in browsers', async () => {
  const device = fakeDevice(), first = await D.checkDevice(device.env);
  // Removed in the device's settings, and another key of the site made since: the device answers with that one.
  device.remove();
  await D.makeDeviceKey(device.env);
  const gone = await D.checkEarlierKey(device.env, { credentialId: first.kept.credentialId, record: first.kept.record });
  assert.equal(gone.outcome.number, 7);
  assert.deepEqual(gone.outcome.says, [D.DEVICE_MESSAGES.keyGone]);
  assert.equal(gone.outcome.errorClass, 'OtherKey');
  assert.equal(gone.steps.firstAnswer, 'no');
  assert.ok(device.given.at(-1) && new Uint8Array(device.given.at(-1)).every((b) => b === 0), 'the other key\'s secret is wiped unused');
  // deviceSecret alone says the same.
  await assert.rejects(D.deviceSecret(device.env, { credentialId: first.kept.credentialId, purpose: 'login' }), (error) => error instanceof D.DeviceKeyError && error.outcome === 7);
  // No key at all: the browser tells the person there is none and the page gets NotAllowedError.
  device.remove();
  const none = await D.checkEarlierKey(device.env, { credentialId: first.kept.credentialId, record: first.kept.record });
  assert.equal(none.outcome.number, 6); assert.equal(none.outcome.errorClass, 'NotAllowedError');
});

test('outcome 8: anything else, mapped to the class of the error and never to the browser\'s words', async () => {
  for (const [s, errorClass] of [[{ createError: 'SecurityError' }, 'SecurityError'], [{ createError: 'InvalidStateError' }, 'InvalidStateError'], [{ createError: 'SomethingNewError' }, 'Error'], [{ getError: 'UnknownError' }, 'UnknownError'], [{ noUv: true }, 'NotVerified'], [{ shortSecret: true }, 'BadSecretLength']]) {
    const result = await D.checkDevice(fakeDevice(s).env);
    assert.equal(result.outcome.number, 8, JSON.stringify(s));
    assert.deepEqual(result.outcome.says, [D.DEVICE_MESSAGES.other]);
    assert.equal(result.outcome.errorClass, errorClass);
    const text = JSON.stringify(result) + D.deviceReport(result, { userAgent: 'Test', host: 'wallet.example' });
    for (const word of [BROWSER_WORDS, 'details the browser gives']) assert.ok(!text.includes(word), `the browser's words reach the result: ${word}`);
  }
  // An error that is not even an Error.
  assert.equal(D.deviceError('a string').errorClass, 'Error');
  assert.equal(D.deviceError({ get name() { throw new Error('no'); } }).outcome, 8);
  assert.equal(D.outcomeOf(99).number, 8);
});

test('the same purpose gives the same secret; another purpose, another secret; secrets are 32 bytes', async () => {
  const device = fakeDevice(), made = await D.makeDeviceKey(device.env);
  assert.equal(made.prfEnabled, true); assert.equal(made.userVerified, true);
  const a = await D.deviceSecret(device.env, { credentialId: made.credentialId, purpose: 'login' });
  const b = await D.deviceSecret(device.env, { credentialId: made.credentialId, purpose: 'login' });
  const c = await D.deviceSecret(device.env, { credentialId: made.credentialId, purpose: 'spend' });
  assert.equal(a.secret.length, 32);
  assert.ok(D.sameBytes(a.secret, b.secret));
  assert.ok(!D.sameBytes(a.secret, c.secret));
  // The secret is what the device computes for the salt of the purpose.
  assert.deepEqual(Buffer.from(a.secret), prfOf(device.keys[0].secret, D.saltFor('login')));
  for (const purpose of ['', 'Login', 'a b', 'x'.repeat(33), '-x', 'é']) await assert.rejects(D.deviceSecret(device.env, { credentialId: made.credentialId, purpose }), TypeError, purpose);
  for (const id of ['', 'AAAA', 'not base64!', made.credentialId + '=']) await assert.rejects(D.deviceSecret(device.env, { credentialId: id, purpose: 'login' }), TypeError, id);
  D.forget(a.secret, b.secret, c.secret);
  assert.ok(a.secret.every((x) => x === 0));
});

test('wrap and unwrap: a record opens with the secret, its key and its purpose, and with nothing else', async () => {
  const secret = new Uint8Array(randomBytes(32)), other = new Uint8Array(randomBytes(32)), credentialId = D.base64url(randomBytes(32)), otherId = D.base64url(randomBytes(32));
  const plaintext = new Uint8Array(randomBytes(48));
  const record = await D.wrapWithDevice({ secret, credentialId, purpose: 'spend', plaintext });
  assert.equal(record.format, 'time-device-key'); assert.equal(record.version, 1); assert.equal(record.purpose, 'spend'); assert.equal(record.credential, credentialId);
  assert.equal(Buffer.from(record.iv, 'base64').length, 12); assert.equal(Buffer.from(record.salt, 'base64').length, 16);
  assert.equal(Buffer.from(record.ciphertext, 'base64').length, 48 + 16);
  const again = await D.wrapWithDevice({ secret, credentialId, purpose: 'spend', plaintext });
  assert.notEqual(again.iv, record.iv, 'a random IV for each record'); assert.notEqual(again.ciphertext, record.ciphertext);
  assert.deepEqual(await D.unwrapWithDevice({ secret, credentialId, purpose: 'spend', record: JSON.parse(JSON.stringify(record)) }), plaintext);
  const refused = (promise) => assert.rejects(promise, (error) => error instanceof D.DeviceKeyError && error.outcome === 8 && error.errorClass === 'RecordRefused');
  // Another secret, another key, another purpose.
  await refused(D.unwrapWithDevice({ secret: other, credentialId, purpose: 'spend', record }));
  await refused(D.unwrapWithDevice({ secret, credentialId: otherId, purpose: 'spend', record }));
  await refused(D.unwrapWithDevice({ secret, credentialId, purpose: 'login', record }));
  // The record relabelled to another key or purpose does not open either: both are authenticated.
  await refused(D.unwrapWithDevice({ secret, credentialId: otherId, purpose: 'spend', record: { ...record, credential: otherId } }));
  await refused(D.unwrapWithDevice({ secret, credentialId, purpose: 'login', record: { ...record, purpose: 'login' } }));
  // Every field changed, one at a time.
  const flip = (text) => { const b = Buffer.from(text, 'base64'); b[b.length - 1] ^= 1; return b.toString('base64'); };
  for (const changed of [{ salt: flip(record.salt) }, { iv: flip(record.iv) }, { ciphertext: flip(record.ciphertext) }, { ciphertext: record.ciphertext.slice(0, 20) }, { format: 'time-device-key-2' }, { version: 2 }, { version: '1' },
    { salt: record.salt + '=' }, { iv: Buffer.alloc(16).toString('base64') }, { credential: credentialId + 'A' }, { purpose: 'Spend' }, { extra: 1 }]) {
    await refused(D.unwrapWithDevice({ secret, credentialId, purpose: 'spend', record: { ...record, ...changed } }));
  }
  for (const key of Object.keys(record)) { const missing = { ...record }; delete missing[key]; await refused(D.unwrapWithDevice({ secret, credentialId, purpose: 'spend', record: missing })); }
  for (const bad of [null, [], 'text', Object.assign(Object.create({ evil: true }), record)]) await refused(D.unwrapWithDevice({ secret, credentialId, purpose: 'spend', record: bad }));
  // What is locked, and with what.
  await assert.rejects(D.wrapWithDevice({ secret: secret.subarray(0, 31), credentialId, purpose: 'spend', plaintext }), TypeError);
  await assert.rejects(D.wrapWithDevice({ secret, credentialId, purpose: 'spend', plaintext: new Uint8Array(0) }), TypeError);
  await assert.rejects(D.wrapWithDevice({ secret, credentialId, purpose: 'spend', plaintext: new Uint8Array(4097) }), TypeError);
});

test('a kept record of another key or purpose is refused before the person is asked', async () => {
  const device = fakeDevice(), first = await D.checkDevice(device.env), before = gets(device).length;
  const other = await D.checkEarlierKey(device.env, { credentialId: first.kept.credentialId, record: { ...first.kept.record, purpose: 'login' } });
  assert.equal(other.outcome.number, 8); assert.equal(other.outcome.errorClass, 'RecordRefused');
  const broken = await D.checkEarlierKey(device.env, { credentialId: first.kept.credentialId, record: { nonsense: true } });
  assert.equal(broken.outcome.number, 8);
  assert.equal(gets(device).length, before);
});

test('the sentences: plain, one each, the fallback said in every outcome but the first, the report with fixed fields only', () => {
  for (const [key, text] of Object.entries(D.DEVICE_MESSAGES)) {
    assert.match(text, /^[A-Z][^\u2014\u2013]*\.$/u, key);
    // "passkey" only where the device's own settings are named ("passwords or passkeys").
    if (key !== 'removeTestKey') assert.doesNotMatch(text, /passkey/i, key);
  }
  assert.match(D.DEVICE_MESSAGES.instead, /^Your passwords keep working\./);
  for (let n = 1; n <= 8; n++) { const o = D.outcomeOf(n); assert.equal(o.number, n); assert.equal(o.instead === null, n === 1); assert.ok(o.says.length >= 1); }
  const report = D.deviceReport({ outcome: D.outcomeOf(8, { errorClass: 'NotAllowedError' }), steps: { secure: 'yes', keyMade: 'nonsense' } }, { userAgent: 'Mozilla/5.0 (X)\nInjected: line', host: 'wallet.example' });
  const lines = report.split('\n');
  assert.deepEqual(lines.map((line) => line.split(':')[0]), ['Time device check, report 1', 'outcome', ...D.STEP_FIELDS, 'error', 'browser', 'address']);
  assert.ok(lines.includes('error: NotAllowedError')); assert.ok(lines.includes('keyMade: unknown')); assert.ok(lines.includes('firstAnswer: not run'));
  assert.equal(lines.at(-2), 'browser: Mozilla/5.0 (X)?Injected: line');
});
