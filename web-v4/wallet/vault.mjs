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
export function checkPassword(password, name = '') {
  if (typeof password !== 'string' || [...password].length < 15) throw new Error('Choose a password with at least 15 characters. A unique passphrase works well.');
  if ([...password].length > 1024) throw new Error('Use a password of at most 1,024 characters.');
  if (password.includes('\0') || /[\ud800-\udfff]/u.test(password.replace(/[\u{10000}-\u{10ffff}]/gu, ''))) throw new Error('Use valid Unicode text without NUL characters.');
  const low = password.toLowerCase();
  if (COMMON.has(low) || new Set([...low]).size < 5 || /^(.)\1+$/u.test(password) || /^(?:password|qwerty|123456|letmein|welcome)[\W\d]*$/i.test(password) || (name && low.replace(/[\W\d_]/g, '') === name.toLowerCase())) throw new Error('This password is too easy to guess. Choose a unique passphrase.');
  return true;
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
function header(binding, intent = 'device') {
  if (intent === 'device') return { version: 1, binding: validateBinding(binding), kdf: { ...KDF } };
  if (!INTENTS.includes(intent)) throw new Error('Invalid vault intent');
  return { version: 2, intent, binding: validateBinding(binding), kdf: { ...KDF } };
}
export const vaultIntent = record => record.version === 2 ? record.intent : 'device';
function accepted(expected) {
  const list = expected === undefined ? LOGIN_INTENTS : Array.isArray(expected) ? expected : [expected];
  if (!list.length || list.some(intent => !ALL_INTENTS.has(intent))) throw new Error('Invalid vault intent');
  return list;
}
export function validateVaultRecord(record, expectedIntent) {
  const fields = record?.version === 2 ? 'binding,ciphertext,intent,iv,kdf,salt,version' : 'binding,ciphertext,iv,kdf,salt,version';
  if (!record || ![1, 2].includes(record.version) || Object.keys(record).sort().join(',') !== fields
    || (record.version === 2 && !INTENTS.includes(record.intent))
    || !record.kdf || Object.keys(record.kdf).sort().join(',') !== Object.keys(KDF).sort().join(',')
    || Object.entries(KDF).some(([key,value]) => record.kdf[key] !== value)) throw new Error('Unsupported vault version, intent or KDF. No weaker fallback is permitted.');
  if (expectedIntent !== undefined && !accepted(expectedIntent).includes(vaultIntent(record))) throw new Error('This vault holds another kind of key.');
  const h=header(record.binding, vaultIntent(record)),salt=fromB64(record.salt,16),iv=fromB64(record.iv,12),ciphertext=fromB64(record.ciphertext);
  if(salt.length!==16||iv.length!==12||ciphertext.length<17)throw new Error('Invalid vault encoding');
  return {...h,salt:b64(salt),iv:b64(iv),ciphertext:b64(ciphertext)};
}
async function derive(password, salt, argon2id, cryptoImpl) {
  if (typeof argon2id !== 'function') throw new Error('Local Argon2id is unavailable. Unlock is disabled.');
  const passwordBytes = encoder.encode(password);
  let derived;
  try {
    derived = await argon2id({ password: passwordBytes, salt, parallelism: KDF.parallelism, iterations: KDF.iterations, memorySize: KDF.memoryKiB, hashLength: KDF.hashLength, outputType: 'binary' });
    return await cryptoImpl.subtle.importKey('raw', derived, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  } finally { passwordBytes.fill(0); if (derived?.fill) derived.fill(0); }
}
export async function sealVault(secret, password, binding, argon2id, cryptoImpl = globalThis.crypto, intent = 'device') {
  checkPassword(password, binding.name);
  // A version-2 key carries nothing but the key: no registration salt, no protocol-4 intent.
  if (intent !== 'device' && (!secret || Object.keys(secret).join(',') !== 'pkcs8')) throw new Error('Invalid vault contents');
  const h = header(binding, intent), salt = cryptoImpl.getRandomValues(new Uint8Array(16)), iv = cryptoImpl.getRandomValues(new Uint8Array(12));
  const key = await derive(password, salt, argon2id, cryptoImpl);
  const plaintext = encoder.encode(JSON.stringify(secret));
  try {
    const ciphertext = await cryptoImpl.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(JSON.stringify(h)), tagLength: 128 }, key, plaintext);
    return { ...h, salt: b64(salt), iv: b64(iv), ciphertext: b64(ciphertext) };
  } finally { plaintext.fill(0); }
}
export async function openVault(record, password, argon2id, cryptoImpl = globalThis.crypto, expectedIntent) {
  // The intent is checked before any derivation: a payment password is never tried on a login vault.
  record=validateVaultRecord(record, accepted(expectedIntent));
  if(typeof password!=='string'||[...password].length>1024)throw new Error('Invalid password input');
  const intent = vaultIntent(record), h = header(record.binding, intent), salt = fromB64(record.salt, 16), iv = fromB64(record.iv, 12), ciphertext = fromB64(record.ciphertext);
  if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 17) throw new Error('Invalid vault encoding');
  const key = await derive(password, salt, argon2id, cryptoImpl);
  let plain;
  try {
    plain = new Uint8Array(await cryptoImpl.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(JSON.stringify(h)), tagLength: 128 }, key, ciphertext));
    const secret = JSON.parse(decoder.decode(plain));
    if (!secret || typeof secret.pkcs8 !== 'string' || Object.keys(secret).some(key=>!(intent === 'device' ? ['pkcs8','nameSalt','intent'] : ['pkcs8']).includes(key))) throw new Error('Invalid vault contents');
    if(secret.nameSalt!==undefined)unhex(secret.nameSalt,32);
    if(secret.intent!==undefined&&!['device','recovery'].includes(secret.intent))throw new Error('Invalid vault intent');
    const bytes = fromB64(secret.pkcs8, 256);
    let privateKey;
    try { privateKey = await cryptoImpl.subtle.importKey('pkcs8', bytes, { name: 'Ed25519' }, false, ['sign']); } finally { bytes.fill(0); }
    const pub = await cryptoImpl.subtle.importKey('raw', unhex(record.binding.publicKey, 32), { name: 'Ed25519' }, false, ['verify']);
    const challenge = encoder.encode('TCDEVNET-VAULT-CHECK-V1');
    const sig = await cryptoImpl.subtle.sign('Ed25519', privateKey, challenge);
    if (!await cryptoImpl.subtle.verify('Ed25519', pub, sig, challenge)) throw new Error('Vault key does not match account');
    return { secret, privateKey, binding: h.binding, intent };
  } catch { throw new Error('Could not unlock this vault. Check your password and local vault integrity.'); }
  finally { plain?.fill(0); }
}
export async function newDevice(cryptoImpl = globalThis.crypto) {
  const pair = await cryptoImpl.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await cryptoImpl.subtle.exportKey('pkcs8', pair.privateKey));
  try {
    const privateKey = await cryptoImpl.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
    return { privateKey, publicKey: hex(await cryptoImpl.subtle.exportKey('raw', pair.publicKey)), secret: { pkcs8: b64(pkcs8) } };
  } finally { pkcs8.fill(0); }
}
export function forgetSecret(secret) { if (secret) for (const key of Object.keys(secret)) secret[key] = null; }
