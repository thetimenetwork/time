// The Recovery Kit: a file that holds the recovery sheet of an account, locked with the account's recovery words.
// The person saves two things when the recovery keys are made (papers.mjs): this file, anywhere they will find it again,
// and the words, on paper. Recovering needs both: the words open the kit, and the sheet in it and the words are
// the account's two recovery keys. The format is in RECOVERY_FILE_FORMAT.md, with a test vector.
//
// The key that locks the kit is not the recovery key the words give on the chain: both come from the words, through
// Argon2id with salts of different domains (security-flows.mjs, passphraseSalt and registrationPassphraseSalt).
//
// No network or storage access is permitted in this module: the caller hands the file's text in and takes it out.
import { validateName, b64, fromB64 } from './vault.mjs';
import { PASSPHRASE_KDF, decodeSheet, parsePassphrase } from './security-flows.mjs';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const fail = message => { throw new Error(message); };
const assert = (value, message) => { if (!value) fail(message); };

export const RECOVERY_KIT_FORMAT = 'time-recovery-kit';
export const RECOVERY_KIT_VERSION = 1;
/// The largest file this wallet reads, in bytes. A kit it writes is about 800.
export const MAX_RECOVERY_KIT_BYTES = 4096;
/// For a person who opens the file in a text editor.
export const RECOVERY_KIT_NOTE = 'This is the Recovery Kit of one Time account. It opens only with the recovery words that were shown with it. To use it, open the Time wallet, press Recover my account, and choose this file.';
const FIELDS = ['format', 'version', 'note', 'networkId', 'accountName', 'kdf', 'salt', 'iv', 'ciphertext'];
const KDF_FIELDS = Object.keys(PASSPHRASE_KDF);
// The key is Argon2id of the words with this salt: the domain, one zero byte, and the 16 random bytes of the file.
export const RECOVERY_KIT_DOMAIN = 'TIME-RECOVERY-KIT-WORDS-V1';
const DOMAIN = encoder.encode(RECOVERY_KIT_DOMAIN + '\0');
const SALT_BYTES = 16, IV_BYTES = 12, TAG_BYTES = 16;
// The plaintext has one length: {"sheet":"<69 characters>"} is 81 bytes, and the tag 16 more.
const PLAINTEXT_BYTES = 81, CIPHERTEXT_BYTES = PLAINTEXT_BYTES + TAG_BYTES;
// The sheet as it is printed: 14 groups of 4 characters of its alphabet (security-flows.mjs, SHEET_ALPHABET), one space between.
const PRINTED_SHEET = /^[0-9A-HJKMNP-TV-Z]{4}(?: [0-9A-HJKMNP-TV-Z]{4}){13}$/;

export const WRONG_RECOVERY_WORDS = 'These recovery words do not open this Recovery Kit, or the file is damaged.';
export const RECOVERY_KIT_TOO_HEAVY = 'This device could not do the calculation of a Recovery Kit: it needs 256 MiB of memory. Do this on a computer instead. There is no lighter version, because it would give a different key.';
export const NOT_A_RECOVERY_KIT = 'This file is not a Recovery Kit of the Time wallet.';
const DAMAGED = 'This Recovery Kit is damaged or was changed, so this wallet does not open it.';

/// The name a kit is downloaded under: it says what it is, whose it is and of which network, so that a search for
/// "time-recovery-kit" finds it in a mailbox or a folder.
export function recoveryKitName({ name, networkId }) {
  assert(validateName(name) === name && /^[0-9a-f]{64}$/.test(String(networkId)), 'A Recovery Kit names an account and a network.');
  return `time-recovery-kit-${name}-${networkId.slice(0, 8)}.json`;
}

/// The data the cipher authenticates: the header's fields in this order, as compact JSON. A kit whose network, name or
/// way of locking was changed does not open.
const additionalData = ({ networkId, accountName }) => encoder.encode(JSON.stringify({ format: RECOVERY_KIT_FORMAT, version: RECOVERY_KIT_VERSION, networkId, accountName, kdf: { ...PASSPHRASE_KDF } }));
/// The salt Argon2id is given: the domain, one zero byte, the file's 16 bytes.
export const recoveryKitSalt = salt => { const out = new Uint8Array(DOMAIN.length + salt.length); out.set(DOMAIN); out.set(salt, DOMAIN.length); return out; };

/// The AES-256-GCM key of the words and the kit's salt: Argon2id with exactly PASSPHRASE_KDF, of the words' canonical
/// form in UTF-8. Nothing lighter is tried.
async function kitKey(words, salt, argon2id, cryptoImpl) {
  assert(typeof argon2id === 'function', 'Local Argon2id is unavailable.');
  const wordBytes = encoder.encode(words);
  let derived;
  try {
    try {
      derived = await argon2id({ password: wordBytes, salt: recoveryKitSalt(salt), parallelism: PASSPHRASE_KDF.parallelism, iterations: PASSPHRASE_KDF.iterations, memorySize: PASSPHRASE_KDF.memoryKiB, hashLength: PASSPHRASE_KDF.hashLength, outputType: 'binary' });
    } catch { fail(RECOVERY_KIT_TOO_HEAVY); }
    assert(derived instanceof Uint8Array && derived.length === 32, 'Argon2id returned an unexpected result');
    return await cryptoImpl.subtle.importKey('raw', derived, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  } finally { wordBytes.fill(0); if (derived?.fill) derived.fill(0); }
}

/// The sheet in the one form a kit holds it: as printed, with a checksum that holds. Anything else is refused.
async function checkSheet(sheetText, cryptoImpl) {
  assert(typeof sheetText === 'string' && PRINTED_SHEET.test(sheetText), 'The recovery sheet is not in its printed form.');
  const seed = await decodeSheet(sheetText, cryptoImpl); seed.fill(0);
}

/// A new Recovery Kit of the sheet, locked with the account's recovery words. Returns the file's text.
export async function sealRecoveryKit({ networkId, name, sheetText, words, argon2id, cryptoImpl = globalThis.crypto }) {
  recoveryKitName({ name, networkId });
  const canonical = parsePassphrase(words);
  await checkSheet(sheetText, cryptoImpl);
  const salt = cryptoImpl.getRandomValues(new Uint8Array(SALT_BYTES)), iv = cryptoImpl.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await kitKey(canonical, salt, argon2id, cryptoImpl);
  const plaintext = encoder.encode(JSON.stringify({ sheet: sheetText }));
  try {
    assert(plaintext.length === PLAINTEXT_BYTES, 'The recovery sheet is not in its printed form.');
    const ciphertext = new Uint8Array(await cryptoImpl.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: additionalData({ networkId, accountName: name }), tagLength: TAG_BYTES * 8 }, key, plaintext));
    const kit = { format: RECOVERY_KIT_FORMAT, version: RECOVERY_KIT_VERSION, note: RECOVERY_KIT_NOTE, networkId, accountName: name, kdf: { ...PASSPHRASE_KDF }, salt: b64(salt), iv: b64(iv), ciphertext: b64(ciphertext) };
    return JSON.stringify(kit, null, 2) + '\n';
  } finally { plaintext.fill(0); }
}

/// Refuses a JSON text in which an object names a field twice (JSON.parse keeps the last one silently).
function rejectDuplicateFields(text) {
  const stack = [];
  for (const [token] of text.matchAll(/"(?:\\[\s\S]|[^"\\])*"|[{}[\]:,]/g)) {
    if (token === '{') stack.push({ object: true, keys: new Set(), key: true });
    else if (token === '[') stack.push({ object: false });
    else if (token === '}' || token === ']') stack.pop();
    else if (token === ':' && stack.at(-1)?.object) stack.at(-1).key = false;
    else if (token === ',' && stack.at(-1)?.object) stack.at(-1).key = true;
    else if (token.startsWith('"') && stack.at(-1)?.object && stack.at(-1).key) {
      const object = stack.at(-1), key = JSON.parse(token);
      if (object.keys.has(key)) fail(DAMAGED);
      object.keys.add(key);
    }
  }
}
const sameFields = (object, fields) => Boolean(object) && typeof object === 'object' && !Array.isArray(object) && Object.keys(object).length === fields.length && fields.every(field => Object.hasOwn(object, field));
function bytesOf(text, length) {
  let bytes; try { bytes = fromB64(text, length); } catch { fail(DAMAGED); }
  assert(bytes.length === length, DAMAGED);
  return bytes;
}
/// The kit read and checked, before anything is derived: its header, and its salt, IV and ciphertext as bytes.
function parse(text) {
  assert(typeof text === 'string' && encoder.encode(text).byteLength <= MAX_RECOVERY_KIT_BYTES, 'This file is too large to be a Recovery Kit.');
  let kit; try { kit = JSON.parse(text); } catch { fail(NOT_A_RECOVERY_KIT); }
  assert(kit && typeof kit === 'object' && !Array.isArray(kit) && kit.format === RECOVERY_KIT_FORMAT, NOT_A_RECOVERY_KIT);
  rejectDuplicateFields(text);
  assert(kit.version === RECOVERY_KIT_VERSION, 'This Recovery Kit is of a version this wallet does not know. Open it with a newer wallet.');
  assert(sameFields(kit, FIELDS) && kit.note === RECOVERY_KIT_NOTE, DAMAGED);
  // Another way of locking is refused before anything is derived: no other profile, and none weaker, is ever tried.
  assert(sameFields(kit.kdf, KDF_FIELDS) && KDF_FIELDS.every(field => kit.kdf[field] === PASSPHRASE_KDF[field]), 'This Recovery Kit is locked in another way than this wallet locks one, so it was not opened.');
  assert(typeof kit.networkId === 'string' && /^[0-9a-f]{64}$/.test(kit.networkId), DAMAGED);
  let named = null; try { named = validateName(kit.accountName); } catch { named = null; }
  assert(typeof kit.accountName === 'string' && named === kit.accountName, DAMAGED);
  const salt = bytesOf(kit.salt, SALT_BYTES), iv = bytesOf(kit.iv, IV_BYTES), ciphertext = bytesOf(kit.ciphertext, CIPHERTEXT_BYTES);
  return { header: Object.freeze({ format: kit.format, version: kit.version, networkId: kit.networkId, accountName: kit.accountName, kdf: Object.freeze({ ...PASSPHRASE_KDF }), salt: kit.salt, iv: kit.iv, ciphertext: kit.ciphertext }), salt, iv, ciphertext };
}

/// The header of a Recovery Kit, checked as `openRecoveryKit` checks it. It holds nothing secret: the wallet shows whose
/// kit it is, and fills the name from it.
export function readRecoveryKit(text) { return parse(text).header; }

/// Why a kit with this header is not the one expected ({ networkId, name }), in the person's words; null if it is. A
/// name left out (`name` empty) is not compared.
export function recoveryKitMismatch(header, { networkId, name = '' }) {
  if (header.networkId !== networkId) return `This is the Recovery Kit of @${header.accountName} on another network (${header.networkId.slice(0, 12)}), not on this one (${String(networkId).slice(0, 12)}). It cannot recover an account here.`;
  if (name && header.accountName !== name) return `This is the Recovery Kit of @${header.accountName}, not of @${name}.`;
  return null;
}

/// The sheet in a Recovery Kit: `{ sheetText }`. `expect` is the network and the account name the caller expects
/// ({ networkId, name }): a kit of another one is refused, before anything is derived, with the words of which one it is.
/// So are words that are not words the wallet makes (five, or four on an older account) (security-flows.mjs, parsePassphrase).
export async function openRecoveryKit(text, words, { argon2id, cryptoImpl = globalThis.crypto, expect } = {}) {
  const { header, salt, iv, ciphertext } = parse(text);
  assert(expect && typeof expect.networkId === 'string' && typeof expect.name === 'string' && expect.name !== '', 'Say which account the Recovery Kit is for.');
  const mismatch = recoveryKitMismatch(header, expect); assert(!mismatch, mismatch);
  const canonical = parsePassphrase(words);
  const key = await kitKey(canonical, salt, argon2id, cryptoImpl);
  let plain = null;
  try {
    try { plain = new Uint8Array(await cryptoImpl.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: additionalData(header), tagLength: TAG_BYTES * 8 }, key, ciphertext)); }
    catch { fail(WRONG_RECOVERY_WORDS); }
    let sheet = null;
    try {
      const plainText = decoder.decode(plain), parsed = JSON.parse(plainText);
      sheet = sameFields(parsed, ['sheet']) && JSON.stringify({ sheet: parsed.sheet }) === plainText ? parsed.sheet : null;
      if (sheet !== null) await checkSheet(sheet, cryptoImpl);
    } catch { sheet = null; }
    assert(sheet !== null, WRONG_RECOVERY_WORDS);
    return { sheetText: sheet };
  } finally { plain?.fill(0); }
}
