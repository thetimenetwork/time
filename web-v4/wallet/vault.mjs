/* Local software vault. No network or storage access is permitted in this module. */
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
export const KDF = Object.freeze({ algorithm: 'argon2id', version: 19, memoryKiB: 65536, iterations: 3, parallelism: 1, hashLength: 32 });
const COMMON = new Set(['passwordpassword', 'password123456789', '123456789012345', '1234567890123456', 'qwertyuiopasdfgh', 'letmeinletmein123', 'correct horse battery staple', 'this is my password', 'iloveyouiloveyou', 'abcdefghijklmnop', '000000000000000', '111111111111111', 'password1234567890']);
export const hex = bytes => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
export function unhex(value, length) {
  if (typeof value !== 'string' || !/^[0-9a-f]+$/.test(value) || value.length !== length * 2) throw new Error('Invalid hexadecimal field');
  return Uint8Array.from(value.match(/../g), pair => parseInt(pair, 16));
}
export function b64(bytes) {
  let s = ''; for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s);
}
export function fromB64(s, maximum = 4096) {
  if (typeof s !== 'string' || s.length > maximum * 2 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error('Invalid encoded vault');
  const raw = atob(s); if (raw.length > maximum) throw new Error('Vault is too large');
  const result = Uint8Array.from(raw, c => c.charCodeAt(0));
  if (b64(result) !== s) throw new Error('Non-canonical encoded vault');
  return result;
}
export function validateName(value) {
  const name = String(value).replace(/^@/, '');
  if (!/^[a-z0-9_]{2,15}$/.test(name)) throw new Error('Use 2–15 lowercase letters, numbers or underscores.');
  return name;
}
// What makes a chosen password easy for a guessing program (web audit of November 2026, K-6). A vault is locked with
// Argon2id of 64 MiB and three passes: a graphics card tries about 1,650 passwords a second, and such a program tries
// repeats, keyboard runs, letters or digits in order and common words with digits first. These rules apply when a
// password is chosen (checkPassword, below); a vault that exists opens as before, whatever its password.
/// The commonest words, which a password must be more than (with digits and signs after them, or with each other).
const EASY_WORDS = ['password', 'passw0rd', 'qwerty', 'letmein', 'welcome', 'iloveyou', 'admin', 'monkey', 'dragon', 'football', 'baseball', 'sunshine', 'princess', 'master', 'shadow',
  'superman', 'trustno1', 'abc', 'summer', 'winter', 'spring', 'autumn', 'hello', 'freedom', 'whatever', 'starwars', 'mynameis', 'secret', 'login', 'wallet', 'bitcoin', 'money', 'love'];
/// The keyboard runs: the rows (English, German, French) read on, and the columns walked two ways.
const KEY_RUNS = ['qwertyuiopasdfghjklzxcvbnm', 'qwertzuiopasdfghjklyxcvbnm', 'azertyuiopqsdfghjklmwxcvbn', '1q2w3e4r5t6y7u8i9o0p', 'q1w2e3r4t5y6u7i8o9p0', 'qazwsxedcrfvtgbyhnujmikolp', '1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p']
  .flatMap(run => [run, [...run].reverse().join('')]);
const EASY = 'This password is too easy to guess: ', UNRELATED = ' Choose four or five unrelated words.';
/// A unit of 1 to 8 characters repeated two or more times, with at most three other characters around it.
function repeatedUnit(low) {
  for (let size = 1; size <= 8; size++) for (let at = 0; at + size <= low.length; at++) {
    const count = low.split(low.slice(at, at + size)).length - 1;
    if (count >= 2 && low.length - count * size <= 3) return true;
  }
  return false;
}
/// The same word of four or more letters twice, apart or one after the other.
function sameWordTwice(low) {
  const words = low.match(/\p{L}+/gu) || [];
  return words.some((word, at) => word.length >= 4 && words.indexOf(word) !== at) || words.some(word => /^(\p{L}{4,})\1+$/u.test(word));
}
/// A keyboard run of eight or more characters, with at most three other characters around it.
function keyboardRun(low) {
  for (const run of KEY_RUNS) for (let size = Math.min(run.length, low.length); size >= 8; size--) {
    for (let at = 0; at + size <= run.length; at++) if (low.includes(run.slice(at, at + size)) && low.length - size <= 3) return true;
  }
  return false;
}
/// Letters or digits in order, up or down (and their repeats), with at most three other characters: a character
/// written several times in a row counts once.
function inOrder(low) {
  const text = low.replace(/(.)\1+/gu, '$1'), letter = c => /[a-z]/.test(c) ? 1 : /[0-9]/.test(c) ? 2 : 0;
  let covered = 0, at = 0;
  while (at < text.length) {
    let end = at + 1, step = 0;
    while (end < text.length && letter(text[end]) && letter(text[end]) === letter(text[at])) {
      const delta = text.charCodeAt(end) - text.charCodeAt(end - 1);
      if (Math.abs(delta) !== 1 || (step && delta !== step)) break;
      step = delta; end++;
    }
    if (end - at >= 3 && letter(text[at])) covered += end - at;
    at = end > at + 1 ? end : at + 1;
  }
  return text.length - covered <= 3;
}
/// One or more of the commonest words (or the account's own name), with only digits and signs around them.
function commonWord(low, name) {
  const words = [...EASY_WORDS, ...(name && name.length >= 2 ? [name.toLowerCase()] : [])].map(word => word.replace(/[^a-z0-9]/g, ''));
  return new RegExp(`^[\\W\\d_]*(?:(?:${words.join('|')})[\\W\\d_]*)+$`, 'u').test(low);
}
export function checkPassword(password, name = '') {
  if (typeof password !== 'string' || [...password].length < 15) throw new Error('Choose a password with at least 15 characters. A unique passphrase works well.');
  if ([...password].length > 1024) throw new Error('Use a password of at most 1,024 characters.');
  if (password.includes('\0') || /[\ud800-\udfff]/u.test(password.replace(/[\u{10000}-\u{10ffff}]/gu, ''))) throw new Error('Use valid Unicode text without NUL characters.');
  const low = password.toLowerCase();
  if (COMMON.has(low) || new Set([...low]).size < 5 || /^(.)\1+$/u.test(password) || /^(?:password|qwerty|123456|letmein|welcome)[\W\d]*$/i.test(password) || (name && low.replace(/[\W\d_]/g, '') === name.toLowerCase())) throw new Error('This password is too easy to guess. Choose a unique passphrase.');
  if (repeatedUnit(low)) throw new Error(EASY + 'it repeats the same part.' + UNRELATED);
  if (sameWordTwice(low)) throw new Error(EASY + 'it has the same word twice.' + UNRELATED);
  if (keyboardRun(low)) throw new Error(EASY + 'it follows the keys of a keyboard.' + UNRELATED);
  if (inOrder(low)) throw new Error(EASY + 'it is letters or digits in order.' + UNRELATED);
  if (commonWord(low, name)) throw new Error(EASY + 'it is a common word with digits or signs.' + UNRELATED);
  return true;
}
// ---- the rule ------------------------------------------------------------------------------------------------------
// Since 24 November 2026 (README.md, "Passwords the wallet makes"), whatever this wallet seals is sealed one of three
// ways, and sealVault refuses any other: (i) with the device's secret and the password together (version 3); (ii) under
// a password the wallet made, of 72 random bits (a MadePassword from makePassword, below; the header says `password:
// "made"`); (iii) under a key derived from another key of the account that is itself sealed one of those ways (version
// 4, sealUnder). A password a person chose never seals a key alone: someone with a copy of this browser's data or of a
// backup file could guess it on their own computer (web audit, O-3). Records sealed before keep opening, whatever their
// password. sealing-rule.test.mjs holds the modules that may seal, and fails any other.
export const RULE = 'The wallet never seals a key under a password a person chose, alone: only with the device\'s secret and the password together (vault version 3), under a password the wallet made of at least 72 random bits, or under a key derived from a key that is itself sealed one of those ways (vault version 4).';
// A password the wallet makes: four words of three syllables, each syllable one of 16 consonants and one of 4 vowels,
// the syllables of the recovery words (security-flows.mjs, generatePassphrase): 6 bits a syllable, 18 bits a word, 72
// bits. They are 9 random bytes of the browser's own crypto.getRandomValues (globalThis.crypto: nothing else can be
// handed in), cut into twelve values of 6 bits: every value is reachable, and none is likelier than another. It is
// written with a dash between the words (`kerine-netoji-nesimo-vebine`), so that it is not mixed up with the five
// recovery words, written with spaces. It is read forgivingly: case, spaces and dashes are ignored, and Argon2id is
// given its one canonical form, the four words in lower case joined by one dash.
export const SYLLABLES = Object.freeze({ consonants: 'bdfghjklmnprstvz', vowels: 'aeio' });
export const MADE_PASSWORD = Object.freeze({ words: 4, syllablesPerWord: 3, bits: 72, bytes: 9 });
const MADE_TOKEN = Symbol('made by the wallet');
// The made passwords that may still seal a key alone. makePassword puts each one in, and sealVault takes it out as it
// seals: one password the wallet made seals one record, once, and is then only a text that opens it (the review of 24
// November 2026, finding 5). Nothing outside this module can put one in.
const FRESH = new WeakSet();
/// A password the wallet made. Only this module makes one: from makePassword (`fresh` until it sealed one record), or
/// read back from what a person typed (readMadePassword: it opens a record, or seals one with the device).
export class MadePassword {
  #text;
  constructor(token, text) {
    if (token !== MADE_TOKEN) throw new TypeError('A made password comes from makePassword or readMadePassword.');
    this.#text = text; Object.freeze(this);
  }
  get text() { return this.#text; }
  /// Whether it may still seal a key alone: made by makePassword, and no record sealed under it yet.
  get fresh() { return FRESH.has(this); }
  static is(value) { return typeof value === 'object' && value !== null && #text in value; }
}
/// The text that 9 bytes give, cut into twelve values of 6 bits in order. A plain text, which seals nothing alone: the
/// tests read every value through it, and makePassword gives it the browser's random bytes.
export function madeText(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== MADE_PASSWORD.bytes) throw new TypeError('A made password comes from 9 bytes.');
  const syllables = [];
  let buffer = 0, bits = 0;
  try {
    for (const byte of bytes) {
      buffer = (buffer << 8) | byte; bits += 8;
      while (bits >= 6) { bits -= 6; const v = (buffer >> bits) & 63; syllables.push(SYLLABLES.consonants[v >> 2] + SYLLABLES.vowels[v & 3]); }
      buffer &= (1 << bits) - 1;
    }
  } finally { buffer = 0; }
  const words = [];
  for (let i = 0; i < syllables.length; i += MADE_PASSWORD.syllablesPerWord) words.push(syllables.slice(i, i + MADE_PASSWORD.syllablesPerWord).join(''));
  return words.join('-');
}
/// A new password of 72 random bits, which may seal one record alone (sealVault). It takes no argument: its bytes come
/// from globalThis.crypto.getRandomValues into an array of its own, whatever that function returns, and are wiped after.
export function makePassword() {
  const bytes = new Uint8Array(MADE_PASSWORD.bytes);
  try {
    globalThis.crypto.getRandomValues(bytes);
    const text = madeText(bytes);
    if (madeForm(text) !== text) throw new Error('The wallet could not make a password. Nothing was kept.');
    const made = new MadePassword(MADE_TOKEN, text);
    FRESH.add(made);
    return made;
  } finally { bytes.fill(0); }
}
const MADE_LETTERS = new RegExp(`^(?:[${SYLLABLES.consonants}][${SYLLABLES.vowels}]){${MADE_PASSWORD.words * MADE_PASSWORD.syllablesPerWord}}$`);
/// The canonical form of a typed made password, or null when the text is not one the wallet could have made.
export function madeForm(text) {
  if (typeof text !== 'string' || text.length > 256) return null;
  const letters = text.normalize('NFKC').toLowerCase().replace(/[\s\p{Pd}−]+/gu, '');
  if (!MADE_LETTERS.test(letters)) return null;
  return letters.match(new RegExp(`.{${2 * MADE_PASSWORD.syllablesPerWord}}`, 'g')).join('-');
}
/// What a person is told when a record's password was made by the wallet and the text typed cannot be one.
export const madeWords = intent => (intent === 'spend'
  ? 'Your payment password is one the wallet made: four words of six letters, joined by dashes. Check it against what you wrote down.'
  : 'Your login password is one the wallet made: four words of six letters, joined by dashes. Check it against what your browser saved, or what you wrote down.');
/// A made password as a person typed it, in its canonical form; an error with `madeForm` when it cannot be one.
export function readMadePassword(text, intent = 'signin') {
  const form = madeForm(text);
  if (form === null) throw Object.assign(new Error(madeWords(intent)), { madeForm: true });
  return new MadePassword(MADE_TOKEN, form);
}
function validateBinding(binding) {
  if (!binding || Object.keys(binding).sort().join(',') !== 'name,networkId,publicKey') throw new Error('Invalid vault binding');
  if (validateName(binding.name) !== binding.name) throw new Error('Invalid canonical vault name'); unhex(binding.networkId, 32); unhex(binding.publicKey, 32);
  return { networkId: binding.networkId, name: binding.name, publicKey: binding.publicKey };
}
// Record intents. A version-1 record holds a protocol-4 device key (both powers) and has the
// implicit intent 'device'. A version-2 record names what its key is for, and that name is part
// of the authenticated data, so it cannot be relabelled without failing decryption:
//  - 'signin': the sign-in key of a secured account, under the login password;
//  - 'spend':  the spend key of a secured account, under the separate payment password.
// Callers say which intents they accept. The default accepts only login keys ('device' and
// 'signin'), so no existing path (unlock, backup export or import) can open a spend key.
export const INTENTS = Object.freeze(['signin', 'spend']);
export const LOGIN_INTENTS = Object.freeze(['device', 'signin']);
const ALL_INTENTS = new Set(['device', ...INTENTS]);
// Version 3: a version-2 key (signin or spend) locked to this device as well (device-lock.mjs, "Lock my keys to this
// device"). Its header names the device's key, `device: { credential }` (the WebAuthn credential id, base64url), and the
// whole header is the authenticated data, as for every version. The vault key is HKDF-SHA-256 of the Argon2id output of
// the password and the device's 32-byte secret (WebAuthn PRF) together, with the record's random salt and, as info,
// DEVICE_LOCK_DOMAIN and the header: without the device's secret the record opens for nobody, whatever the password.
// A version-3 record is refused before any derivation when no device secret comes with it (it never falls back to the
// password alone), and a client from before version 3 refuses it as an unknown version. Nothing here asks the device:
// its secret comes in as an argument.
export const DEVICE_LOCK_DOMAIN = 'TCDEVNET-VAULT-DEVICE-LOCK-V1';
export const DEVICE_NEEDED = 'This key is locked to a device. The device must give its secret before the password can open it.';
const CREDENTIAL = /^[A-Za-z0-9_-]{22,1364}$/;
function validateDevice(device) {
  if (!device || typeof device !== 'object' || Object.keys(device).join(',') !== 'credential' || typeof device.credential !== 'string' || !CREDENTIAL.test(device.credential)) throw new Error('Invalid vault device');
  return { credential: device.credential };
}
// A record whose password the wallet made says so in its header, `password: "made"`, after `version` and `intent` and
// before `binding` (versions 1, 2 and 3): the header is the authenticated data, so the mark cannot be added or taken
// away without failing decryption. The wallet then reads what is typed as a made password (readMadePassword) and says
// so when it cannot be one; a record without the mark is read as before, byte for byte.
const MADE_MARK = 'made';
function header(binding, intent = 'device', device = null, made = false) {
  const mark = made ? { password: MADE_MARK } : {};
  if (device !== null) {
    if (!INTENTS.includes(intent)) throw new Error('Only a login key or a payment key can be locked to a device.');
    return { version: 3, intent, ...mark, binding: validateBinding(binding), kdf: { ...KDF }, device: validateDevice(device) };
  }
  if (intent === 'device') return { version: 1, ...mark, binding: validateBinding(binding), kdf: { ...KDF } };
  if (!INTENTS.includes(intent)) throw new Error('Invalid vault intent');
  return { version: 2, intent, ...mark, binding: validateBinding(binding), kdf: { ...KDF } };
}
export const vaultIntent = record => (record.version === 2 || record.version === 3 ? record.intent : 'device');
/// The device key a vault is locked to (its credential id), or null for a vault the password alone opens.
export const vaultDevice = record => (record?.version === 3 && typeof record.device?.credential === 'string' ? record.device.credential : null);
/// Whether a record's password was made by the wallet (its header says so).
export const vaultMade = record => record?.password === MADE_MARK && [1, 2, 3].includes(record?.version);
/// The key a version-4 record is sealed under ({ intent, publicKey }), or null.
export const vaultUnder = record => (record?.version === 4 && record.under && typeof record.under.publicKey === 'string' ? { intent: record.under.intent, publicKey: record.under.publicKey } : null);
/// How a record is sealed, by the rule: 'device' (version 3), 'made' (a password the wallet made), 'under' (version 4),
/// or 'chosen' (a password a person chose, alone: a record from before the rule; it opens, and nothing makes one now).
export const sealOf = record => (vaultDevice(record) ? 'device' : vaultUnder(record) ? 'under' : vaultMade(record) ? 'made' : 'chosen');
function accepted(expected) {
  const list = expected === undefined ? LOGIN_INTENTS : Array.isArray(expected) ? expected : [expected];
  if (!list.length || list.some(intent => !ALL_INTENTS.has(intent))) throw new Error('Invalid vault intent');
  return list;
}
export function validateVaultRecord(record, expectedIntent) {
  if (record?.version === 4) return validateUnderRecord(record, expectedIntent);
  const base = record?.version === 3 ? 'binding,ciphertext,device,intent,iv,kdf,salt,version' : record?.version === 2 ? 'binding,ciphertext,intent,iv,kdf,salt,version' : 'binding,ciphertext,iv,kdf,salt,version';
  const fields = record && Object.hasOwn(record, 'password') ? base.split(',').concat('password').sort().join(',') : base;
  if (!record || ![1, 2, 3].includes(record.version) || Object.keys(record).sort().join(',') !== fields
    || (Object.hasOwn(record, 'password') && record.password !== MADE_MARK)
    || ((record.version === 2 || record.version === 3) && !INTENTS.includes(record.intent))
    || !record.kdf || Object.keys(record.kdf).sort().join(',') !== Object.keys(KDF).sort().join(',')
    || Object.entries(KDF).some(([key,value]) => record.kdf[key] !== value)) throw new Error('Unsupported vault version, intent or KDF. No weaker fallback is permitted.');
  if (expectedIntent !== undefined && !accepted(expectedIntent).includes(vaultIntent(record))) throw new Error('This vault holds another kind of key.');
  const h=header(record.binding, vaultIntent(record), record.version === 3 ? record.device : null, vaultMade(record)),salt=fromB64(record.salt,16),iv=fromB64(record.iv,12),ciphertext=fromB64(record.ciphertext);
  if(salt.length!==16||iv.length!==12||ciphertext.length<17)throw new Error('Invalid vault encoding');
  return {...h,salt:b64(salt),iv:b64(iv),ciphertext:b64(ciphertext)};
}
// Version 4: a key sealed under another key of the same account that this browser keeps, not under a password (rule
// iii): the registration key of a sign-up, kept until the chain holds the account, under the account's new login key.
// Its header names that key, `under: { intent: "signin", publicKey }`, and is the authenticated data. The vault key is
// HKDF-SHA-256 of the 32-byte seed of that login key, with the record's random 16-byte salt, and as info the UTF-8 bytes
// of UNDER_KEY_DOMAIN, a zero byte and the header; no Argon2id, as a seed has 256 bits. It opens only with that login
// key once that key was opened itself (openUnder), never with anything typed; its plaintext is that of version 1. A
// client from before version 4 refuses it as an unknown version, and so does openVault.
export const UNDER_KEY_DOMAIN = 'TCDEVNET-VAULT-UNDER-KEY-V1';
export const UNDER_NEEDED = 'This key opens with another key of this browser, not with a password.';
const HEX32 = /^[0-9a-f]{64}$/;
function underHeader(binding, under) {
  if (!under || Object.keys(under).sort().join(',') !== 'intent,publicKey' || under.intent !== 'signin' || typeof under.publicKey !== 'string' || !HEX32.test(under.publicKey)) throw new Error('Invalid vault under');
  return { version: 4, binding: validateBinding(binding), under: { intent: 'signin', publicKey: under.publicKey } };
}
function validateUnderRecord(record, expectedIntent) {
  if (Object.keys(record).sort().join(',') !== 'binding,ciphertext,iv,salt,under,version') throw new Error('Unsupported vault version, intent or KDF. No weaker fallback is permitted.');
  if (expectedIntent !== undefined && !accepted(expectedIntent).includes('device')) throw new Error('This vault holds another kind of key.');
  const h = underHeader(record.binding, record.under), salt = fromB64(record.salt, 16), iv = fromB64(record.iv, 12), ciphertext = fromB64(record.ciphertext);
  if (h.under.publicKey === h.binding.publicKey || salt.length !== 16 || iv.length !== 12 || ciphertext.length < 17) throw new Error('Invalid vault encoding');
  return { ...h, salt: b64(salt), iv: b64(iv), ciphertext: b64(ciphertext) };
}
/// The 32 bytes a device gave, as a copy that the caller of derive wipes; anything else is refused.
function deviceBytes(secret) {
  const bytes = secret instanceof Uint8Array ? secret : secret instanceof ArrayBuffer ? new Uint8Array(secret) : null;
  if (!bytes || bytes.length !== 32) throw new Error('A device secret is 32 bytes.');
  return new Uint8Array(bytes);
}
/// The vault key: Argon2id of the password alone (versions 1 and 2), or with `lock` ({ secret, header }, version 3)
/// HKDF-SHA-256 of the Argon2id output and the device's secret together.
async function derive(password, salt, argon2id, cryptoImpl, lock = null) {
  if (typeof argon2id !== 'function') throw new Error('Local Argon2id is unavailable. Unlock is disabled.');
  const passwordBytes = encoder.encode(password);
  let derived, both;
  try {
    derived = await argon2id({ password: passwordBytes, salt, parallelism: KDF.parallelism, iterations: KDF.iterations, memorySize: KDF.memoryKiB, hashLength: KDF.hashLength, outputType: 'binary' });
    if (!lock) return await cryptoImpl.subtle.importKey('raw', derived, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    const device = deviceBytes(lock.secret);
    both = new Uint8Array(derived.length + 32); both.set(derived, 0); both.set(device, derived.length); device.fill(0);
    const base = await cryptoImpl.subtle.importKey('raw', both, 'HKDF', false, ['deriveKey']);
    const info = encoder.encode(`${DEVICE_LOCK_DOMAIN}\0${JSON.stringify(lock.header)}`);
    return await cryptoImpl.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally { passwordBytes.fill(0); if (derived?.fill) derived.fill(0); both?.fill(0); }
}
/// Seals `secret` by the rule (RULE, above). `password`: a MadePassword, or, only with `lock`, the text a person chose
/// (held to checkPassword). With `lock` ({ credential, secret }: the device's key and the 32 bytes it gave for this
/// vault), a version-3 record that needs the device too (login and payment keys only). Without `lock`, only a password
/// the wallet has just made (makePassword) and that has sealed nothing yet is taken: a text, a made password read back
/// from what a person typed, or one that sealed a record already, is refused with RULE before anything is derived. A
/// fresh made password is used up here, with the device or without.
export async function sealVault(secret, password, binding, argon2id, cryptoImpl = globalThis.crypto, intent = 'device', lock = null) {
  const made = MadePassword.is(password), fresh = made && FRESH.delete(password);
  if (!lock && !fresh) throw new Error(RULE);
  if (!made) checkPassword(password, binding.name);
  // A version-2 key carries nothing but the key: no registration salt, no protocol-4 intent.
  if (intent !== 'device' && (!secret || Object.keys(secret).join(',') !== 'pkcs8')) throw new Error('Invalid vault contents');
  const h = header(binding, intent, lock ? { credential: lock.credential } : null, made), salt = cryptoImpl.getRandomValues(new Uint8Array(16)), iv = cryptoImpl.getRandomValues(new Uint8Array(12));
  const key = await derive(made ? password.text : password, salt, argon2id, cryptoImpl, lock ? { secret: lock.secret, header: h } : null);
  const plaintext = encoder.encode(JSON.stringify(secret));
  try {
    const ciphertext = await cryptoImpl.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(JSON.stringify(h)), tagLength: 128 }, key, plaintext);
    return { ...h, salt: b64(salt), iv: b64(iv), ciphertext: b64(ciphertext) };
  } finally { plaintext.fill(0); }
}
/// What a record decrypts to, checked: the key, imported so that it cannot be exported, must be the record's.
async function opened(plain, intent, binding, cryptoImpl) {
  const secret = JSON.parse(decoder.decode(plain));
  if (!secret || typeof secret.pkcs8 !== 'string' || Object.keys(secret).some(key=>!(intent === 'device' ? ['pkcs8','nameSalt','intent'] : ['pkcs8']).includes(key))) throw new Error('Invalid vault contents');
  if(secret.nameSalt!==undefined)unhex(secret.nameSalt,32);
  if(secret.intent!==undefined&&!['device','recovery'].includes(secret.intent))throw new Error('Invalid vault intent');
  const bytes = fromB64(secret.pkcs8, 256);
  let privateKey, storageKey = null;
  try {
    privateKey = await cryptoImpl.subtle.importKey('pkcs8', bytes, { name: 'Ed25519' }, false, ['sign']);
    // A login key also gives the key of what the browser keeps private for the account (storageKeyFrom, below). A key
    // it cannot be derived from opens the vault all the same: the page then keeps its history for itself only.
    if (LOGIN_INTENTS.includes(intent)) storageKey = await storageKeyFrom(bytes, binding, cryptoImpl).catch(() => null);
  } finally { bytes.fill(0); }
  const pub = await cryptoImpl.subtle.importKey('raw', unhex(binding.publicKey, 32), { name: 'Ed25519' }, false, ['verify']);
  const challenge = encoder.encode('TCDEVNET-VAULT-CHECK-V1');
  const sig = await cryptoImpl.subtle.sign('Ed25519', privateKey, challenge);
  if (!await cryptoImpl.subtle.verify('Ed25519', pub, sig, challenge)) throw new Error('Vault key does not match account');
  return { secret, privateKey, binding: { ...binding }, intent, storageKey };
}
/// Opens a vault. `deviceSecret`: the 32 bytes the device gave for a version-3 record (vaultDevice names its key);
/// without them such a record is refused at once (an error with `deviceNeeded`), and for any other record they are not
/// used. A record whose password the wallet made reads `password` as a made password: a text that cannot be one is
/// refused before any derivation (an error with `madeForm`, in words that say so). A version-4 record is refused (an
/// error with `underNeeded`): it opens with openUnder.
export async function openVault(record, password, argon2id, cryptoImpl = globalThis.crypto, expectedIntent, deviceSecret = null) {
  // The intent is checked before any derivation: a payment password is never tried on a login vault.
  record=validateVaultRecord(record, accepted(expectedIntent));
  if(typeof password!=='string'||[...password].length>1024)throw new Error('Invalid password input');
  if (record.version === 4) throw Object.assign(new Error(UNDER_NEEDED), { underNeeded: true });
  if (record.version === 3 && deviceSecret === null) throw Object.assign(new Error(DEVICE_NEEDED), { deviceNeeded: true });
  const intent = vaultIntent(record), made = vaultMade(record), h = header(record.binding, intent, record.version === 3 ? record.device : null, made), salt = fromB64(record.salt, 16), iv = fromB64(record.iv, 12), ciphertext = fromB64(record.ciphertext);
  if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 17) throw new Error('Invalid vault encoding');
  const text = made ? readMadePassword(password, intent).text : password;
  const key = await derive(text, salt, argon2id, cryptoImpl, record.version === 3 ? { secret: deviceSecret, header: h } : null);
  let plain;
  try {
    plain = new Uint8Array(await cryptoImpl.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(JSON.stringify(h)), tagLength: 128 }, key, ciphertext));
    return await opened(plain, intent, h.binding, cryptoImpl);
  } catch { throw new Error('Could not unlock this vault. Check your password and local vault integrity.'); }
  finally { plain?.fill(0); }
}
/// The key of a version-4 record, from the seed of the login key it is sealed under (`parent`: { publicKey, pkcs8 }, the
/// pkcs8 in base64, as openVault and newDevice give it).
async function underKey(parent, salt, h, cryptoImpl) {
  if (!parent || parent.publicKey !== h.under.publicKey || typeof parent.pkcs8 !== 'string') throw new Error('This key is sealed under another login key.');
  const bytes = fromB64(parent.pkcs8, 256), seed = seedOf(bytes);
  try {
    const base = await cryptoImpl.subtle.importKey('raw', seed, 'HKDF', false, ['deriveKey']);
    return await cryptoImpl.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode(`${UNDER_KEY_DOMAIN}\0${JSON.stringify(h)}`) }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally { bytes.fill(0); seed.fill(0); }
}
/// Seals `secret` (a key with the plaintext of version 1: pkcs8, nameSalt, intent) under the login key `parent` ({
/// publicKey, pkcs8 }) of the same account: a version-4 record (rule iii). Nothing typed goes into it.
export async function sealUnder(secret, binding, parent, cryptoImpl = globalThis.crypto) {
  if (!secret || typeof secret.pkcs8 !== 'string' || Object.keys(secret).some(key => !['pkcs8', 'nameSalt', 'intent'].includes(key))) throw new Error('Invalid vault contents');
  const h = underHeader(binding, { intent: 'signin', publicKey: parent?.publicKey });
  if (h.under.publicKey === h.binding.publicKey) throw new Error('A key is not sealed under itself.');
  const salt = cryptoImpl.getRandomValues(new Uint8Array(16)), iv = cryptoImpl.getRandomValues(new Uint8Array(12));
  const key = await underKey(parent, salt, h, cryptoImpl), plaintext = encoder.encode(JSON.stringify(secret));
  try {
    const ciphertext = await cryptoImpl.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(JSON.stringify(h)), tagLength: 128 }, key, plaintext);
    return { ...h, salt: b64(salt), iv: b64(iv), ciphertext: b64(ciphertext) };
  } finally { plaintext.fill(0); }
}
/// Opens a version-4 record with the login key it is sealed under (`parent`: { publicKey, pkcs8 }, of a vault that
/// openVault opened). Returns what openVault returns.
export async function openUnder(record, parent, cryptoImpl = globalThis.crypto) {
  const r = validateVaultRecord(record), h = underHeader(r.binding, r.under), salt = fromB64(r.salt, 16), iv = fromB64(r.iv, 12), ciphertext = fromB64(r.ciphertext);
  const key = await underKey(parent, salt, h, cryptoImpl);
  let plain;
  try {
    plain = new Uint8Array(await cryptoImpl.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(JSON.stringify(h)), tagLength: 128 }, key, ciphertext));
    return await opened(plain, 'device', h.binding, cryptoImpl);
  } catch { throw new Error('Could not open this key with the login key it is kept under. This browser\'s data may have been changed.'); }
  finally { plain?.fill(0); }
}
/// A new key. With `place` ({ networkId, name }: the account a login key is made for), also the key of what the browser
/// keeps private for that account (storageKeyFrom), while the key's secret is still in memory.
export async function newDevice(cryptoImpl = globalThis.crypto, place = null) {
  const pair = await cryptoImpl.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await cryptoImpl.subtle.exportKey('pkcs8', pair.privateKey));
  try {
    const privateKey = await cryptoImpl.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
    const publicKey = hex(await cryptoImpl.subtle.exportKey('raw', pair.publicKey));
    const made = { privateKey, publicKey, secret: { pkcs8: b64(pkcs8) } };
    if (place) made.storageKey = await storageKeyFrom(pkcs8, { networkId: place.networkId, name: place.name, publicKey }, cryptoImpl).catch(() => null);
    return made;
  } finally { pkcs8.fill(0); }
}
// The key of what this browser keeps private for an account while the wallet is unlocked (locked-store.mjs): the
// activity, the names paid, the marks of the orders paid. It is derived from the 32-byte seed of the login key with
// HKDF-SHA-256, in a domain of its own and for one account of one network, as an AES-256-GCM key that cannot be
// exported. It exists only where the login key's secret was in memory (openVault, newDevice above), and nothing
// about it is stored: a vault keeps its format.
export const STORE_KEY_DOMAIN = 'TCDEVNET-WALLET-PRIVATE-STORE-V1';
const ED25519_OID = [0x06, 0x03, 0x2b, 0x65, 0x70], SEED_OCTETS = [0x04, 0x22, 0x04, 0x20];
const at = (bytes, pattern, from = 0) => { for (let i = from; i + pattern.length <= bytes.length; i++) if (pattern.every((b, k) => bytes[i + k] === b)) return i; return -1; };
/// The seed of an Ed25519 key in PKCS #8 (RFC 8410: the private key is an octet string of 32 bytes in an octet string),
/// as a copy the caller wipes.
function seedOf(pkcs8) {
  const bytes = new Uint8Array(pkcs8), oid = at(bytes, ED25519_OID), start = oid < 0 ? -1 : at(bytes, SEED_OCTETS, oid + ED25519_OID.length);
  if (bytes[0] !== 0x30 || start < 0 || start + SEED_OCTETS.length + 32 > bytes.length) throw new Error('Invalid key encoding');
  return bytes.slice(start + SEED_OCTETS.length, start + SEED_OCTETS.length + 32);
}
export async function storageKeyFrom(pkcs8, binding, cryptoImpl = globalThis.crypto) {
  const { networkId, name, publicKey } = validateBinding(binding), seed = seedOf(pkcs8);
  try {
    const base = await cryptoImpl.subtle.importKey('raw', seed, 'HKDF', false, ['deriveKey']);
    return await cryptoImpl.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: encoder.encode(STORE_KEY_DOMAIN), info: encoder.encode(`private-store\0${networkId}\0${name}\0${publicKey}`) },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally { seed.fill(0); }
}
export function forgetSecret(secret) { if (secret) for (const key of Object.keys(secret)) secret[key] = null; }
