// Account security for the browser wallet: everything that is not the page.
//
// The wallet library `client-v4/account-security.mjs` builds the payloads and the bytes keys sign.
// This module decides what to build for a person who knows nothing about roles: the recovery
// sheet, the recovery passphrase, the default policy, which way a payment goes, what the security
// inbox shows, how a lost device is recovered, and where the encrypted keys live. It touches no
// page and no network. The wallet library is passed in (`createSecurityFlows`), because the page
// loads it from `/sdk/` and the tests from `client-v4/`.
import { KDF, hex, unhex, checkPassword, validateVaultRecord, vaultIntent, newDevice, sealVault, forgetSecret } from './vault.mjs';
import { effectiveLimit, pauseLimit } from './protection.mjs';

const encoder = new TextEncoder();
const fail = message => { throw new Error(message); };
const assert = (value, message) => { if (!value) fail(message); };
const MICROS = 1000000n;
const concat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0; for (const p of parts) { out.set(p, at); at += p.length; } return out; };
const u64 = value => { const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, BigInt(value)); return out; };
const decimal = value => { assert(typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value) && BigInt(value) < 1n << 64n, 'Expected a whole number'); return value; };

// ------------------------------------------------------------------ time
export const elapsedOf = state => BigInt(state.time_micros) - BigInt(state.genesis.genesis_time_micros);
/// The wall-clock time of an elapsed-time value of the chain.
export const dateOf = (state, elapsedMicros) => new Date(Number((BigInt(state.genesis.genesis_time_micros) + BigInt(elapsedMicros)) / 1000n));
/// The clock of the waits at a verified state (TimeSDK.securityNow): what every moment a security row stores is compared
/// with (`ready_elapsed_micros`, `expires_elapsed_micros` of a waiting replacement, `frozen_until_elapsed_micros`,
/// `allowance_elapsed_micros`). On a network whose genesis has `waits_survive_stops` it is the chain's time since genesis
/// less the total of the chain's stops; on any other it is the chain's time, elapsedOf. What a key signs (the expiry of a
/// freeze, of approvals, of a login request) is dated on the chain's time, elapsedOf, on every network.
export const waitsOf = (sdk, state) => BigInt(sdk.securityNow(state));
/// A moment on the clock of the waits as a person reads it (TimeSDK.securityDeadline): its date, and `later`, true while
/// that date is only the earliest it can come because a stop of the chain moves it. Then the page says "not before". On a
/// network without the rule `later` is false and the date is the one dateOf gives.
export function momentOf(sdk, state, moment) {
  try { const due = sdk.securityDeadline(state, String(moment)); return { date: new Date(Number(BigInt(due.timeMicros) / 1000n)), later: due.earliest === true }; }
  catch { let rule = false; try { rule = sdk.waitsSurviveStops(state) === true; } catch { rule = true; } return { date: dateOf(state, moment), later: rule }; }
}
/// A freeze not included within five minutes is void (the engine admits it while it has 30 s left).
export const FREEZE_LIFETIME_MICROS = 5n * 60n * MICROS;
/// Approvals of a root operation are dated ten minutes ahead: as short as a submission allows.
/// A payment's must be at most an hour ahead.
export const APPROVAL_LIFETIME_MICROS = 10n * 60n * MICROS;

// ------------------------------------------------------------------ recovery sheet
// 32 random bytes and a 3-byte checksum, 35 bytes = 280 bits = 56 characters of Crockford base32
// (no I, L, O or U), printed as 14 groups of 4. Reading ignores case, spaces and dashes and
// takes O for 0 and I or L for 1. The checksum is the first 3 bytes of
// SHA-256("TCDEVNET-RECOVERY-SHEET-V1\0" || seed): a typo passes with odds of 1 in 16.7 million,
// and a sheet that passes still has to give a recovery key of the account.
// The 32 bytes are the recovery key's Ed25519 seed.
export const SHEET_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export const SHEET = Object.freeze({ groups: 14, groupLength: 4, seedBytes: 32, checkBytes: 3 });
const SHEET_DOMAIN = encoder.encode('TCDEVNET-RECOVERY-SHEET-V1\0');
async function sheetCheck(seed, cryptoImpl) {
  const digest = new Uint8Array(await cryptoImpl.subtle.digest('SHA-256', concat(SHEET_DOMAIN, seed)));
  return digest.slice(0, SHEET.checkBytes);
}
export async function encodeSheet(seed, cryptoImpl = globalThis.crypto) {
  assert(seed instanceof Uint8Array && seed.length === SHEET.seedBytes, 'A recovery sheet holds 32 bytes');
  const bytes = concat(seed, await sheetCheck(seed, cryptoImpl));
  let text = '', buffer = 0, bits = 0;
  try {
    for (const byte of bytes) {
      buffer = (buffer << 8) | byte; bits += 8;
      while (bits >= 5) { bits -= 5; text += SHEET_ALPHABET[(buffer >> bits) & 31]; }
      buffer &= (1 << bits) - 1;
    }
  } finally { bytes.fill(0); buffer = 0; }
  return text.match(/.{4}/g).join(' ');
}
/// The characters of a typed sheet, cleaned up; no checksum test.
export function sheetCharacters(text) {
  assert(typeof text === 'string' && text.length <= 512, 'Enter the recovery sheet');
  return text.toUpperCase().replace(/[\s-]+/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
}
export async function decodeSheet(text, cryptoImpl = globalThis.crypto) {
  const chars = sheetCharacters(text);
  assert(/^[0-9A-HJKMNP-TV-Z]*$/.test(chars), 'The recovery sheet uses only digits and the letters printed on it. Check for a wrong character.');
  assert(chars.length === SHEET.groups * SHEET.groupLength, `The recovery sheet has ${SHEET.groups} groups of ${SHEET.groupLength} characters. One is missing or extra.`);
  const bytes = new Uint8Array(SHEET.seedBytes + SHEET.checkBytes);
  let buffer = 0, bits = 0, at = 0;
  for (const char of chars) {
    buffer = (buffer << 5) | SHEET_ALPHABET.indexOf(char); bits += 5;
    if (bits >= 8) { bits -= 8; bytes[at++] = (buffer >> bits) & 255; buffer &= (1 << bits) - 1; }
  }
  const seed = bytes.slice(0, SHEET.seedBytes), check = await sheetCheck(seed, cryptoImpl);
  const ok = check.every((byte, i) => byte === bytes[SHEET.seedBytes + i]);
  bytes.fill(0);
  if (!ok) { seed.fill(0); fail('This recovery sheet has a typo. Compare each group with the paper.'); }
  return seed;
}
export const sheetGroups = text => sheetCharacters(text).match(/.{1,4}/g) || [];
/// Two different groups (0-based) the person types back to show the sheet was written down.
export function pickConfirmGroups(cryptoImpl = globalThis.crypto) {
  const draw = () => { const r = new Uint32Array(1); for (;;) { cryptoImpl.getRandomValues(r); if (r[0] < 4294967296 - (4294967296 % SHEET.groups)) return r[0] % SHEET.groups; } };
  const first = draw(); let second = draw(); while (second === first) second = draw();
  return [first, second].sort((a, b) => a - b);
}
export function confirmGroups(sheetText, picks, answers) {
  const groups = sheetGroups(sheetText);
  assert(Array.isArray(picks) && picks.length === answers.length, 'Enter each requested group');
  picks.forEach((index, i) => assert(sheetCharacters(String(answers[i] ?? '')) === groups[index], `Group ${index + 1} does not match the sheet. Check what you wrote down.`));
  return true;
}

// ------------------------------------------------------------------ keys from seeds
const PKCS8_ED25519 = unhex('302e020100300506032b657004220420', 16);
const fromB64url = text => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - text.length % 4) % 4)), c => c.charCodeAt(0));
/// An Ed25519 key from its 32-byte seed: the public key as hex and a signing key that cannot be exported.
export async function keyFromSeed(seed, cryptoImpl = globalThis.crypto) {
  assert(seed instanceof Uint8Array && seed.length === 32, 'A key seed has 32 bytes');
  const der = concat(PKCS8_ED25519, seed);
  try {
    const open = await cryptoImpl.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, true, ['sign']);
    const jwk = await cryptoImpl.subtle.exportKey('jwk', open);
    const publicKey = hex(fromB64url(jwk.x)); jwk.d = null;
    const privateKey = await cryptoImpl.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign']);
    return { publicKey, privateKey };
  } finally { der.fill(0); }
}
export async function sheetKey(sheetText, cryptoImpl = globalThis.crypto) {
  const seed = await decodeSheet(sheetText, cryptoImpl);
  try { return await keyFromSeed(seed, cryptoImpl); } finally { seed.fill(0); }
}
export function newSheetSeed(cryptoImpl = globalThis.crypto) { return cryptoImpl.getRandomValues(new Uint8Array(SHEET.seedBytes)); }

// ------------------------------------------------------------------ recovery passphrase
// The wallet makes the passphrase; the person does not choose it. Its key's public half is on the
// chain, where anyone can test guesses offline, so it must not be guessable: 72 random bits,
// written as four pronounceable words of three syllables. A syllable is one of 16 consonants
// (b d f g h j k l m n p r s t v z) and one of 4 vowels (a e i o): 6 bits, 12 syllables, 72 bits.
// No word list is used: none with a known licence was on this machine, and nothing was downloaded.
// The key is Argon2id(passphrase, salt) used as an Ed25519 seed, with
// salt = "TCDEVNET-RECOVERY-PASSPHRASE-V1\0" || network id (32 bytes) || account id (8 bytes, big-endian),
// and the passphrase read in its one canonical form: lower case, words separated by one space.
export const PASSPHRASE_KDF = Object.freeze({ algorithm: 'argon2id', version: 19, memoryKiB: 262144, iterations: 4, parallelism: 1, hashLength: 32 });
if (PASSPHRASE_KDF.memoryKiB < KDF.memoryKiB || PASSPHRASE_KDF.iterations < KDF.iterations || PASSPHRASE_KDF.hashLength !== 32) throw new Error('The passphrase KDF must be at least as strong as the vault KDF');
const PASSPHRASE_DOMAIN = encoder.encode('TCDEVNET-RECOVERY-PASSPHRASE-V1\0');
export const PASSPHRASE_TOO_HEAVY = 'This device could not compute your recovery passphrase key: it needs 256 MiB of memory. Do this on a computer instead. There is no lighter version, because it would give a different key.';
const CONSONANTS = 'bdfghjklmnprstvz', VOWELS = 'aeio';
export const PASSPHRASE = Object.freeze({ words: 4, syllablesPerWord: 3, bits: 72 });
const SYLLABLE = `[${CONSONANTS}][${VOWELS}]`;
const WORD = new RegExp(`^(?:${SYLLABLE}){${PASSPHRASE.syllablesPerWord}}$`);
export function normalizePassphrase(text) {
  assert(typeof text === 'string', 'Enter the recovery passphrase');
  return text.normalize('NFKC').toLowerCase().replace(/[\s-]+/gu, ' ').trim();
}
/// A new passphrase: 9 random bytes, 12 syllables of 6 bits each.
export function generatePassphrase(cryptoImpl = globalThis.crypto) {
  const bytes = cryptoImpl.getRandomValues(new Uint8Array(PASSPHRASE.bits / 8));
  let buffer = 0, bits = 0, syllables = [];
  try {
    for (const byte of bytes) {
      buffer = (buffer << 8) | byte; bits += 8;
      while (bits >= 6) { bits -= 6; const v = (buffer >> bits) & 63; syllables.push(CONSONANTS[v >> 2] + VOWELS[v & 3]); }
      buffer &= (1 << bits) - 1;
    }
  } finally { bytes.fill(0); buffer = 0; }
  const words = [];
  for (let i = 0; i < syllables.length; i += PASSPHRASE.syllablesPerWord) words.push(syllables.slice(i, i + PASSPHRASE.syllablesPerWord).join(''));
  return words.join(' ');
}
/// A typed passphrase in its canonical form, or a plain error naming what is wrong.
export function parsePassphrase(text) {
  const words = normalizePassphrase(text).split(' ').filter(Boolean);
  assert(words.length === PASSPHRASE.words, `Your recovery passphrase is ${PASSPHRASE.words} words of six letters. Check it against what you wrote down.`);
  words.forEach((word, i) => assert(WORD.test(word), `Word ${i + 1} of your recovery passphrase is not one the wallet makes. Check it against what you wrote down.`));
  return words.join(' ');
}
export const passphraseSalt = (networkId, accountId) => concat(PASSPHRASE_DOMAIN, unhex(networkId, 32), u64(decimal(String(accountId))));
// An account signed up protected (kind 45, signup-ui.mjs) has its recovery keys from its first block, and gets its
// number only in that block: its first passphrase cannot name it. Its salt names the account's identity key instead, the
// registration key, which the account keeps for ever and the chain shows as `public_key`:
// salt = "TCDEVNET-RECOVERY-PASSPHRASE-REGISTRATION-V1\0" || network id (32 bytes) || registration key (32 bytes).
// Like the account number, it is one account's own: no guess is tested against two accounts at once. New papers made
// later (replaceRecovery) name the account number as always.
const REGISTRATION_PASSPHRASE_DOMAIN = encoder.encode('TCDEVNET-RECOVERY-PASSPHRASE-REGISTRATION-V1\0');
export const registrationPassphraseSalt = (networkId, registrationKey) => concat(REGISTRATION_PASSPHRASE_DOMAIN, unhex(networkId, 32), unhex(registrationKey, 32));
/// A recovery passphrase is one the wallet made: chosen ones are refused, however long.
export function checkPassphrase(passphrase, { passwords = [] } = {}) {
  const text = parsePassphrase(passphrase);
  assert(!passwords.some(p => typeof p === 'string' && normalizePassphrase(p) === text), 'Your recovery passphrase must differ from your passwords.');
  return true;
}
/// `accountId`, or `registrationKey` for the first papers of an account signed up protected: one of the two.
export async function passphraseSeed({ passphrase, networkId, accountId, registrationKey, argon2id }) {
  assert(typeof argon2id === 'function', 'Local Argon2id is unavailable.');
  assert((accountId === undefined) !== (registrationKey === undefined), 'A passphrase key names the account by its number or by its registration key, not both.');
  const text = parsePassphrase(passphrase);
  const password = encoder.encode(text), salt = registrationKey === undefined ? passphraseSalt(networkId, accountId) : registrationPassphraseSalt(networkId, registrationKey);
  let seed;
  try {
    seed = await argon2id({ password, salt, parallelism: PASSPHRASE_KDF.parallelism, iterations: PASSPHRASE_KDF.iterations, memorySize: PASSPHRASE_KDF.memoryKiB, hashLength: PASSPHRASE_KDF.hashLength, outputType: 'binary' });
  } catch {
    // Usually memory: the derivation needs 256 MiB. A lighter one would give another key, so there is none.
    fail(PASSPHRASE_TOO_HEAVY);
  } finally { password.fill(0); }
  assert(seed instanceof Uint8Array && seed.length === 32, 'Argon2id returned an unexpected result');
  return seed;
}
export async function passphraseKey({ passphrase, networkId, accountId, registrationKey, argon2id, cryptoImpl = globalThis.crypto }) {
  const seed = await passphraseSeed({ passphrase, networkId, accountId, registrationKey, argon2id });
  try { return await keyFromSeed(seed, cryptoImpl); } finally { seed.fill(0); }
}
/// The key a typed passphrase gives for `account`: by its number, as for every account; and, on a network that takes
/// protected registrations (`registered`), when that is not one of the account's recovery keys, by its identity key, as
/// for the first papers of an account signed up protected. `isRecovery(key)` says whether a key is one of the account's.
/// The second try is a second calculation of 256 MiB, made only when the first key is not the account's. Returns the key
/// that is a recovery key of the account, or else the first one (the caller says that it is not one).
export async function accountPassphraseKey({ passphrase, networkId, account, registered = false, isRecovery, argon2id, cryptoImpl = globalThis.crypto }) {
  const byNumber = await passphraseKey({ passphrase, networkId, accountId: account.id, argon2id, cryptoImpl });
  if (!registered || isRecovery(byNumber) || !/^[0-9a-f]{64}$/.test(String(account.public_key ?? ''))) return byNumber;
  const byIdentity = await passphraseKey({ passphrase, networkId, registrationKey: account.public_key, argon2id, cryptoImpl });
  if (isRecovery(byIdentity)) { byNumber.privateKey = null; return byIdentity; }
  byIdentity.privateKey = null; return byNumber;
}

// ------------------------------------------------------------------ passwords and policy
/// The login and payment passwords: each passes the vault rules, and they differ.
/// Two passwords count as the same if they differ only in case, spacing or Unicode form.
export const samePassword = (a, b) => typeof a === 'string' && typeof b === 'string' && a.normalize('NFKC').toLowerCase().replace(/\s+/gu, '') === b.normalize('NFKC').toLowerCase().replace(/\s+/gu, '');
export function checkPasswords({ login, payment, name = '' }) {
  if (login !== undefined) checkPassword(login, name);
  if (payment !== undefined) checkPassword(payment, name);
  assert(login === undefined || payment === undefined || !samePassword(login, payment), 'Your payment password must differ from your login password.');
  return true;
}
/// How much a spend key alone can move: the allowance refills evenly over 24 hours, so the full
/// limit can go at once and, as it refills, almost as much again within the same 24 hours.
export const limitExposure = limitMicros => ({ atOnce: BigInt(limitMicros), within24h: 2n * BigInt(limitMicros) });
export const DEFAULTS = Object.freeze({ delayHours: '48', freezeHours: '48', threshold: '2' });
/// The daily limit that "Protect my account" suggests, in seconds. The one place it is written: the form is
/// prefilled from it and its words are made from it (security-ui.mjs).
export const DEFAULT_DAILY_LIMIT_SECONDS = '600';
/// A daily limit in whole seconds as a person reads it: "10 minutes of seconds a day (600)".
export function dailyLimitWords(secondsText = DEFAULT_DAILY_LIMIT_SECONDS) {
  const s = BigInt(decimal(String(secondsText)));
  const unit = (n, word) => `${n} ${word}${n === 1n ? '' : 's'} of seconds a day (${s})`;
  if (s > 0n && s % 3600n === 0n) return unit(s / 3600n, 'hour');
  if (s > 0n && s % 60n === 0n) return unit(s / 60n, 'minute');
  return `${s} second${s === 1n ? '' : 's'} a day`;
}
const MAX_PERIOD_SECONDS = 30n * 86400n;
/// The shortest waiting period the network accepts, in whole hours (the engine's own unit is seconds).
export const minimumHours = state => { const micros = BigInt(state.config?.recovery_min_delay_micros ?? '0'); return (micros + 3600n * MICROS - 1n) / (3600n * MICROS); };
/// The default waiting period: 48 hours, or the network minimum if that is longer.
export const defaultHours = state => { const min = minimumHours(state); return (min > 48n ? min : 48n).toString(); };
/// The policy of a newly secured account. `dailyLimitMicros` comes from `parseSeconds`.
export function choosePolicy({ dailyLimitMicros, delayHours = DEFAULTS.delayHours, freezeHours = DEFAULTS.freezeHours, threshold = DEFAULTS.threshold, recoveryKeys = 2, feeMicros, minDelayMicros }) {
  const limit = BigInt(decimal(String(dailyLimitMicros))), fee = BigInt(decimal(String(feeMicros)));
  assert(limit > fee, 'Choose a daily limit above the network fee.');
  const minimum = BigInt(decimal(String(minDelayMicros ?? '0')));
  const seconds = (hours, what) => {
    assert(typeof hours === 'string' && /^[1-9][0-9]{0,3}$/.test(hours), `Enter the ${what} in whole hours.`);
    const value = BigInt(hours) * 3600n;
    assert(value * MICROS >= minimum, `This network needs a ${what} of at least ${(minimum + 3600n * MICROS - 1n) / (3600n * MICROS)} hours.`);
    assert(value <= MAX_PERIOD_SECONDS, `The ${what} can be at most 30 days.`);
    return value.toString();
  };
  assert(typeof threshold === 'string' && /^[2-8]$/.test(threshold) && Number(threshold) <= recoveryKeys, `Proofs needed: at least 2 and at most ${recoveryKeys}, the number of recovery keys.`);
  return { threshold, daily_limit_micros: limit.toString(), delay_seconds: seconds(delayHours, 'waiting period'), freeze_seconds: seconds(freezeHours, 'freeze length') };
}

/// A new key for one role of a protected account, and its vault under `password` (vault.mjs, version 2: `intent` is
/// 'signin' or 'spend'). The key can sign at once; its secret leaves memory once it is sealed. "Protect my account",
/// the replacements of keys (security-ui.mjs) and signing up protected (signup-ui.mjs) make their keys here.
export async function sealedKey({ password, networkId, name, intent, argon2id, cryptoImpl = globalThis.crypto }) {
  const key = await newDevice(cryptoImpl); let record;
  try { record = await sealVault({ pkcs8: key.secret.pkcs8 }, password, { networkId, name, publicKey: key.publicKey }, argon2id, cryptoImpl, intent); } finally { forgetSecret(key.secret); }
  return { key: { publicKey: key.publicKey, privateKey: key.privateKey }, record };
}

// ------------------------------------------------------------------ where encrypted keys live
// Login slot: the vault the wallet has always used (protocol-4 key, or the sign-in key).
// Spend slot: the spend key, under the payment password.
// Next slots: keys made for an action that has not been seen on the chain yet. They replace the
// live ones only once the chain shows their public key in the expected role.
export function vaultSlots(networkId, name) {
  return {
    login: `timecurrency.vault.v1:${networkId}:${name}`,
    spend: `timecurrency.spend-vault.v1:${networkId}:${name}`,
    nextLogin: `timecurrency.vault-next.v1:${networkId}:${name}:signin`,
    nextSpend: `timecurrency.vault-next.v1:${networkId}:${name}:spend`,
    nextNote: `timecurrency.vault-next.v1:${networkId}:${name}:action`,
    request: `${REQUEST_PREFIX}${networkId}:${name}`,
  };
}
/// A login asked of another device (M3) lives in its own slot: it is not a change this browser
/// made, so it never blocks one, and it never replaces a key this browser still holds.
export const REQUEST_PREFIX = 'timecurrency.login-request.v1:';
export const STAGED_PREFIX = 'timecurrency.vault-next.v1:';
const ROLE_OF_INTENT = { signin: 'signin', spend: 'spend' };
function readRecord(storage, key, intent) {
  const raw = storage.getItem(key); if (raw === null) return null;
  let record; try { record = JSON.parse(raw); } catch { fail('A stored vault is damaged.'); }
  validateVaultRecord(record, intent);
  return record;
}
/// Keeps new encrypted keys aside until the chain has them. Never overwrites keys kept aside.
/// `action` says what would put them on the chain, so that they are dropped only on proof that it
/// cannot any more: {kind, nonce, authEpoch} for kinds with a nonce, {kind: 73, version, expires}
/// for a root operation, or {kind: 'remote'} for a key another device is asked to add.
export function stageVaults(storage, slots, { signin, spend }, action = null) {
  for (const [key, record, intent] of [[slots.nextLogin, signin, 'signin'], [slots.nextSpend, spend, 'spend']]) {
    if (!record) continue;
    assert(storage.getItem(key) === null, 'Keys from an earlier attempt are still waiting. Check that attempt first.');
    validateVaultRecord(record, intent);
  }
  if (action) storage.setItem(slots.nextNote, JSON.stringify(action));
  if (signin) storage.setItem(slots.nextLogin, JSON.stringify(signin));
  if (spend) storage.setItem(slots.nextSpend, JSON.stringify(spend));
}
/// The height at which the action was seen in a block: no state below it may drop the keys.
export function stagedSeenAt(storage, slots, height) {
  const note = stagedNote(storage, slots); if (!note) return;
  storage.setItem(slots.nextNote, JSON.stringify({ ...note, seenHeight: String(height) }));
}
export function stagedNote(storage, slots) {
  const raw = storage.getItem(slots.nextNote); if (raw === null) return null;
  try { const note = JSON.parse(raw); return note && typeof note === 'object' ? note : null; } catch { return null; }
}
/// Whether a state proves that the action behind staged keys can no longer put them on the chain.
/// A state read before the block that included it shows the nonce or version not yet used, so it
/// proves nothing, and neither does any state below the height where the action was seen.
export function stagedVoid(note, { account, security, state }) {
  if (!note || !account || !state) return false;
  if (note.seenHeight !== undefined && BigInt(state.height) < BigInt(note.seenHeight)) return false;
  const now = BigInt(state.time_micros) - BigInt(state.genesis.genesis_time_micros);
  if (note.kind === 70 || note.kind === 71) return BigInt(account.nonce) >= BigInt(note.nonce) || BigInt(account.auth_epoch) > BigInt(note.authEpoch);
  if (note.kind === 73) {
    if (BigInt(note.expires) <= now) return true;
    if (security) return BigInt(security.version) > BigInt(note.version);
    // No row: proof only if this state was read with the security rows and so proves the absence.
    return Array.isArray(state.security);
  }
  return false;
}
const roleOfDevice = device => device.can_manage ? (device.can_spend ? null : 'recover') : device.can_spend ? 'spend' : 'signin';
const holds = (account, publicKey, role) => Boolean(account?.devices?.some(d => d.public_key === publicKey && roleOfDevice(d) === role));
/// Moves staged keys that the chain now holds into the live slots. The record they replace (the
/// protocol-4 key after securing, an old sign-in or spend key) is overwritten and so forgotten.
export function settleStaged(storage, slots, account) {
  const promoted = [];
  for (const [next, live, intent] of [[slots.nextLogin, slots.login, 'signin'], [slots.nextSpend, slots.spend, 'spend']]) {
    const record = readRecord(storage, next, intent); if (!record) continue;
    if (holds(account, record.binding.publicKey, ROLE_OF_INTENT[intent])) { storage.setItem(live, JSON.stringify(record)); storage.removeItem(next); promoted.push(intent); }
  }
  if (!hasStaged(storage, slots)) storage.removeItem(slots.nextNote);
  return promoted;
}
/// Drops staged keys the chain does not hold, and only on proof that the action behind them is
/// void (`stagedVoid`). Without that proof, for example from a state read before its block, or for
/// keys staged without a note, nothing is dropped. Returns what was dropped.
export function discardStaged(storage, slots, account, proof = {}) {
  if (!stagedVoid(stagedNote(storage, slots), { account, ...proof })) return [];
  const dropped = [];
  for (const [next, intent] of [[slots.nextLogin, 'signin'], [slots.nextSpend, 'spend']]) {
    const record = readRecord(storage, next, intent);
    if (record && !holds(account, record.binding.publicKey, ROLE_OF_INTENT[intent])) { storage.removeItem(next); dropped.push(intent); }
  }
  if (!hasStaged(storage, slots)) storage.removeItem(slots.nextNote);
  return dropped;
}
/// Names of this network's accounts with keys kept aside or a login asked of another device, so
/// that a reload settles them before any unlock.
export const stagedNames = (storage, keys, networkId) => [...new Set(keys.filter(k => k.startsWith(`${STAGED_PREFIX}${networkId}:`) || k.startsWith(`${REQUEST_PREFIX}${networkId}:`)).map(k => k.slice(k.indexOf(networkId) + networkId.length + 1).split(':')[0]))];

// ------------------------------------------------------------------ a login asked of another device
export function storeLoginRequest(storage, slots, record, request) {
  assert(storage.getItem(slots.request) === null, 'This browser already asked for a login. Withdraw that request first.');
  validateVaultRecord(record, 'signin');
  storage.setItem(slots.request, JSON.stringify({ record, request }));
}
export function loginRequestOf(storage, slots) {
  const raw = storage.getItem(slots.request); if (raw === null) return null;
  try { const value = JSON.parse(raw); validateVaultRecord(value.record, 'signin'); return value.request ? value : null; } catch { return null; }
}
export const withdrawLoginRequest = (storage, slots) => storage.removeItem(slots.request);
/// Whether this browser holds a key the account has now: then a login request is void.
export function holdsLiveKey(storage, slots, account) {
  for (const key of [slots.login, slots.spend]) {
    const raw = storage.getItem(key); if (raw === null) continue;
    try { const pub = JSON.parse(raw).binding.publicKey; if (account.devices.some(d => d.public_key === pub)) return true; } catch {}
  }
  return false;
}
/// 'promoted' once the account holds the requested key and this browser holds no live key;
/// 'dropped' (and the request deleted) once this browser holds a live key; otherwise null.
export function settleLoginRequest(storage, slots, account) {
  const pending = loginRequestOf(storage, slots);
  if (!pending) { if (storage.getItem(slots.request) !== null) storage.removeItem(slots.request); return null; }
  if (holdsLiveKey(storage, slots, account)) { storage.removeItem(slots.request); return 'dropped'; }
  if (!holds(account, pending.record.binding.publicKey, 'signin')) return null;
  storage.setItem(slots.login, JSON.stringify(pending.record)); storage.removeItem(slots.request);
  return 'promoted';
}
export const hasStaged = (storage, slots) => storage.getItem(slots.nextLogin) !== null || storage.getItem(slots.nextSpend) !== null;
export function spendRecord(storage, slots) { return readRecord(storage, slots.spend, 'spend'); }

// ------------------------------------------------------------------ recovery on a new device
// What survives a reload while a replacement asked for by the recovery keys waits. Public keys
// and counters only: the recovery sheet and passphrase are never stored.
/// Before a recovery on this browser. Records whose key the account no longer has (a removed login
/// key, a replaced payment key) are worthless and may be replaced. A record whose key the account
/// still has is never overwritten: it blocks, with the reason.
export function lostDeviceSlots(storage, slots, account) {
  const stale = [];
  for (const [key, what] of [[slots.login, 'login'], [slots.spend, 'payment']]) {
    const raw = storage.getItem(key); if (raw === null) continue;
    let record; try { record = JSON.parse(raw); validateVaultRecord(record); } catch { return { stale: [], blocked: `This browser's ${what} key record is damaged. Recover from a fresh browser profile.` }; }
    if (account.devices.some(d => d.public_key === record.binding.publicKey)) return { stale: [], blocked: what === 'payment' ? 'This browser still holds a payment key of this account. Use your payment password to make a new login key instead. If you forgot it, recover from a fresh browser profile.' : `This browser can still unlock @${account.name}. Unlock it instead.` };
    stale.push(key);
  }
  return { stale, blocked: null };
}

/// Protocol-4 actions this wallet may offer with this browser's key. A secured account refuses
/// device management and guardian recovery (kinds 8, 9, 11 to 16), and its login key signs
/// nothing on the chain, so none of them is offered for it.
export function protocol4Actions(account, publicKey, secured) {
  const device = account?.devices?.find(d => d.public_key === publicKey);
  const manage = Boolean(device?.can_manage) && !secured, spend = Boolean(device?.can_spend) && !secured;
  return { addDevice: manage, revokeDevice: manage, guardianPolicy: manage, guardianApprove: manage, guardianConsent: manage, cancelRecovery: manage, cancelPending: manage, stakeAndEarn: spend };
}
/// The keys of a secured account as the Devices tab shows them: by what each one does.
export function deviceRows(account, ownKeys = []) {
  const words = {
    signin: ['Login key', 'Signs in to websites. It cannot pay, freeze or change keys.'],
    spend: ['Payment key', 'Pays within the daily limit, starts larger payments that wait, freezes, and replaces login keys.'],
    recover: ['Recovery key', 'Your recovery sheet or passphrase, kept off this device. Two of them, or one with the payment key, make big changes.'],
  };
  return account.devices.map(d => { const role = roleOfDevice(d), [title, detail] = words[role] || ['Key with both powers', 'Not allowed on a secured account.'];
    return { publicKey: d.public_key, role, title: ownKeys.includes(d.public_key) ? `${title} of this browser` : title, detail }; });
}

/// A request from another browser to become a login of the account. It carries the new sign-in
/// key's acceptance of the role (the bytes the engine verifies for kind 71) and, signed by the same
/// key over a wallet message, the account's authority epoch and an expiry: once the account's keys
/// change, or after a few hours, the request is refused, so a request saved in a chat cannot bring
/// back a key the owner removed. Public: no secret.
export const LOGIN_REQUEST_LIFETIME_MICROS = 6n * 3600n * MICROS;
const REQUEST_DOMAIN = encoder.encode('TCDEVNET-WALLET-LOGIN-REQUEST-V1\0');
export const loginRequestMessage = ({ networkId, accountId, authEpoch, expires, publicKey }) => concat(REQUEST_DOMAIN, unhex(networkId, 32), u64(decimal(String(accountId))), u64(decimal(String(authEpoch))), u64(decimal(String(expires))), unhex(publicKey, 32));
const REQUEST_FIELDS = 'accountId,authEpoch,expires,name,networkId,proof,publicKey,requestProof,type,version';
export function parseSigninRequest(text, { networkId, account, now }) {
  assert(typeof text === 'string' && text.length < 4096, 'Paste the request from the other browser.');
  let r; try { r = JSON.parse(text); } catch { fail('Paste the request from the other browser.'); }
  assert(r && Object.keys(r).sort().join(',') === REQUEST_FIELDS && r.version === 2 && r.type === 'signin-key', 'This is not a login request from this wallet, or it is from an older version. Ask the other browser for a new one.');
  assert(r.networkId === networkId && r.accountId === String(account.id) && r.name === account.name, 'This request is for another account or network.');
  unhex(r.publicKey, 32); unhex(r.proof, 64); unhex(r.requestProof, 64); decimal(r.authEpoch); decimal(r.expires);
  assert(r.authEpoch === String(account.auth_epoch), 'This request was made before the account\'s keys last changed. Ask the other browser for a new one.');
  assert(BigInt(r.expires) > BigInt(now) && BigInt(r.expires) <= BigInt(now) + LOGIN_REQUEST_LIFETIME_MICROS + 5n * 60n * MICROS, 'This request has expired. Ask the other browser for a new one.');
  assert(!account.devices.some(d => d.public_key === r.publicKey), 'This key is already on the account.');
  return { public_key: r.publicKey, proof: r.proof, requestProof: r.requestProof, authEpoch: r.authEpoch, expires: r.expires };
}
/// A short fingerprint of a public key, the same on both browsers: 64 bits of SHA-256, in 4 groups.
export async function fingerprint(publicKey, cryptoImpl = globalThis.crypto) {
  const digest = new Uint8Array(await cryptoImpl.subtle.digest('SHA-256', unhex(publicKey, 32)));
  return hex(digest.slice(0, 8)).match(/.{4}/g).join(' ');
}

export const progressKey = (networkId, name) => `timecurrency.security-recovery.v1:${networkId}:${name}`;
const PROGRESS_FIELDS = 'accountId,name,networkId,signin,spend,version';
export function parseProgress(raw) {
  if (raw === null || raw === undefined) return null;
  let value; try { value = JSON.parse(raw); } catch { fail('The stored recovery progress is damaged.'); }
  assert(value && Object.keys(value).sort().join(',') === PROGRESS_FIELDS && value.version === 1, 'The stored recovery progress is damaged.');
  decimal(value.accountId); unhex(value.networkId, 32); unhex(value.signin, 32); unhex(value.spend, 32);
  assert(/^[a-z0-9_]{2,15}$/.test(value.name), 'The stored recovery progress is damaged.');
  return value;
}
export const progressRecord = ({ networkId, account, signin, spend }) => ({ version: 1, networkId, name: account.name, accountId: String(account.id), signin, spend });
/// Where a recovery started on this device stands: 'done' (the new keys are the account's),
/// 'waiting', 'ready' (finish it now), or 'none' (nothing is waiting for these keys: the request
/// never landed, was cancelled by someone holding two proofs, or its claim window passed).
export function recoveryStatus({ progress, account, security, now }) {
  if (!account || String(account.id) !== progress.accountId) return { stage: 'none' };
  if (holds(account, progress.spend, 'spend')) return { stage: 'done' };
  const root = security?.pending_root;
  if (root && root.devices.some(d => d.public_key === progress.spend && roleOfDevice(d) === 'spend')) {
    const ready = BigInt(root.ready_elapsed_micros), expires = BigInt(root.expires_elapsed_micros), at = BigInt(now);
    if (at > expires) return { stage: 'none' };
    return { stage: at >= ready ? 'ready' : 'waiting', ready, expires, remainingMicros: at >= ready ? 0n : ready - at };
  }
  return { stage: 'none' };
}

// ------------------------------------------------------------------ protective actions in flight
// Freeze, root operations, finishing and cancelling carry no nonce, so the nonce-based rules of
// the pending reservations cannot retire them. Each has its own slot, and is retired once the
// counter it names has moved on or its date has passed.
export const protectiveSlot = (kind, accountId) => `security-${kind}-${accountId}`;
export function protectiveObsolete({ kind, payload, version }, security, now) {
  if (!security) return true;
  const at = BigInt(now);
  switch (kind) {
    case 72: return payload.freezes !== security.freezes || payload.version !== security.version || BigInt(payload.expires_elapsed_micros) <= at;
    case 73: return version !== security.version || BigInt(payload.expires_elapsed_micros) <= at;
    case 74: return payload.version !== security.version || !security.pending_root;
    case 76: return payload.type === 'payment' ? !security.pending_payments.some(p => p.id === payload.id) : security.pending_limit?.id !== payload.id;
    default: return true;
  }
}

/// The only actions this wallet signs with a secured account's spend key, besides kinds 70 to 77:
/// payments, the staking kinds of Staking, and the operation of a validator (More, Validator
/// operator: kinds 17, 18, 19 and 24, and its withdrawal, kind 21). The engine takes every staking
/// kind (5 to 7, 17 to 21, 23, 24) from a key with `can_spend` (v5/src/engine.rs, `apply`: "spending
/// device required"), so from the payment key and from no other key of a secured account. It counts
/// what the action takes out of the balance, fee included, against the daily limit, and refuses it
/// while the account is frozen when that is more than nothing (engine.rs, `apply`:
/// `security.spend(before.saturating_sub(balance), now)`; security.rs, `Security::spend`). None of it
/// waits, and no recovery paper pays it: what waits is a payment (kind 75), and a root operation
/// pays transfers only (security.rs, `Operation::Pay`). Double-sign evidence (20), auction bids and
/// claims are not on this list, and the login key signs none of them.
export const SPEND_KEY_KINDS = Object.freeze(['transfer', 'merchant_payment', 'delegate', 'undelegate', 'withdraw_stake', 'register_validator', 'self_bond', 'self_unbond', 'retire_validator']);
/// The operation of the account's own validator (pos-ui.mjs, Validator operator), of the list above.
export const VALIDATOR_KINDS = Object.freeze(['register_validator', 'self_bond', 'self_unbond', 'retire_validator']);
/// The least bond of a validator, which its registration takes from the balance, by the staking profile a verified state
/// names (`state.pos.profile`): pos/src/lib.rs, `Profile::min_self_bond`, a day of seconds on a production network and
/// one second on a laboratory one such as the test network.
export const MIN_SELF_BOND_MICROS = Object.freeze({ production: 86400000000n, laboratory: 1000000n });
export function minSelfBond(state) {
  const profile = state?.pos?.profile;
  assert(typeof profile === 'string' && Object.hasOwn(MIN_SELF_BOND_MICROS, profile), 'This wallet does not know the least bond of a validator on this network. Nothing was signed.');
  return MIN_SELF_BOND_MICROS[profile];
}
export function assertSpendKeyKind(kind) {
  assert(typeof kind === 'string' && SPEND_KEY_KINDS.includes(kind), 'The payment key signs payments and staking only. This action cannot be signed with it.');
  return true;
}
/// A validator's upgrade signal (kind 80) is the one other action this wallet signs with a secured
/// account's spend key, from the Validator signal tab only. The engine takes it, like staking, from
/// a key with `can_spend` (docs/design/upgrade-mechanism.md, section 5.1: "a spend key of a secured
/// account. A sign-in key or a recovery key cannot signal"). It moves nothing; its fee counts
/// against the daily limit, and a frozen account cannot send it.
export const SIGNAL_KIND = 'upgrade_signal';
/// What app.js asks before it signs anything with a payment key: a kind of the list above, or a signal.
export function assertSpendKeySigns(kind) {
  if (kind === SIGNAL_KIND) return true;
  return assertSpendKeyKind(kind);
}
/// Whether the account is secured, by a verified state that carries the security rows: it has a row there. The
/// one definition, asked by the Security tab and by signing.mjs before a login key signs anything.
export function accountSecured(state, account) {
  return Boolean(account) && Array.isArray(state?.security) && state.security.some(row => row.account === String(account.id));
}
/// What a staking action takes out of the balance at most: what it bonds, and the fee. A stake and an addition to a
/// validator's bond bond their amount; a validator's registration bonds `bondMicros`, the network's least bond
/// (minSelfBond), or the bond its payload names (v5/src/pos_adapter.rs, kind 17). Unbonding, taking a validator's bond
/// out and retiring take the fee only. A withdrawal usually adds to the balance; counting its fee keeps the check on the
/// safe side.
export function stakeOutflow(kind, payload, feeMicros, { bondMicros } = {}) {
  assertSpendKeyKind(kind);
  const fee = BigInt(decimal(String(feeMicros)));
  if (kind === 'delegate' || kind === 'self_bond') return BigInt(decimal(payload.amount)) + fee;
  if (kind === 'register_validator') return BigInt(decimal(payload.self_bond === undefined ? String(bondMicros) : payload.self_bond)) + fee;
  assert(['undelegate', 'withdraw_stake', 'self_unbond', 'retire_validator'].includes(kind), 'Not a staking action.');
  return fee;
}

/// True when an account may have a security row: no key holds both powers. Its state must then be
/// read with `include_security`, so that the row or its absence is proven.
export const needsSecurityRow = account => Boolean(account?.devices?.length) && !account.devices.some(d => d.can_manage && d.can_spend);

// ------------------------------------------------------------------ with the wallet library
// Time. A function below that only compares with moments of a security row (choosePayment, checkStake, checkSignal,
// inboxEvents, removedLogin, and recoveryStatus above) takes as `now` the clock of the waits (waitsOf). One that also
// dates what is signed takes `now`, the chain's time, for that date, and `waitsNow`, the clock of the waits, for the
// comparisons. On a network without `waits_survive_stops` the two are the same.
export function createSecurityFlows({ security: sec }) {
  assert(sec?.payloads && sec.operations && sec.signSecurityAction, 'The account security library is required');
  const { KIND } = sec;
  /// The security row of an account in a verified state: the row, null if proven absent, or an
  /// error if the state was read without `include_security`.
  function rowOf(state, account) {
    assert(Array.isArray(state?.security), 'The security state of this account was not proven. Refresh and try again.');
    return sec.securityOf(state, account.id);
  }
  const roleOf = (account, publicKey) => { const d = account.devices.find(row => row.public_key === publicKey); return d ? sec.roleOf(d) : undefined; };
  const SIGNERS = { [KIND.signin]: ['spend'], [KIND.payment]: ['spend'], [KIND.limit]: ['spend'], [KIND.freeze]: ['spend', 'recover'], [KIND.cancel]: ['spend', 'recover'], [KIND.root]: ['spend', 'recover'], 3: ['spend'], 10: ['spend'], 5: ['spend'], 6: ['spend'], 17: ['spend'], 18: ['spend'], 19: ['spend'], 21: ['spend'], 24: ['spend'], 80: ['spend'] };
  /// Refuses a key that the chain would refuse for this action. On a secured account no key holds
  /// both powers, so the protocol-4 key that secured it can sign nothing any more.
  function assertSigner(account, publicKey, kind) {
    const role = roleOf(account, publicKey);
    if (kind === KIND.secure) { assert(role === null, 'Only a key that can both pay and manage the account can secure it.'); return; }
    assert(role !== undefined, 'This key is no longer a key of the account.');
    assert(SIGNERS[kind]?.includes(role), role === null ? 'This account is not secured yet.' : role === 'signin' ? 'The login key cannot do this. Enter your payment password.' : 'This key cannot do this.');
  }
  async function sign({ networkId, kind, account, signer, payload, check = true }) {
    if (check) assertSigner(account, signer.publicKey, kind);
    const sequenced = sec.SEQUENCED.has(kind);
    const tx = await sec.signSecurityAction({ networkId, kind, account, publicKey: signer.publicKey, privateKey: signer.privateKey, payload });
    return { kind, payload, tx, sequenced, nonce: sequenced ? (BigInt(account.nonce) + 1n).toString() : '0', authEpoch: sequenced ? String(account.auth_epoch) : '0' };
  }

  /// Kind 70, signed by the protocol-4 key. After it lands that key is on no account and is forgotten.
  async function buildSecure({ networkId, account, fullKey, signin, spend, recovery, policy, feeMicros }) {
    assertSigner(account, fullKey.publicKey, KIND.secure);
    assert(!account.recovery_policy, 'Turn guardian recovery off before securing this account.');
    assert(BigInt(account.balance) >= BigInt(feeMicros), 'Securing the account costs the network fee, and the account holds less.');
    assert(Array.isArray(recovery) && recovery.length >= 2 && BigInt(policy.threshold) <= BigInt(recovery.length), 'Two recovery keys are needed.');
    const all = [signin.publicKey, spend.publicKey, fullKey.publicKey, ...recovery.map(k => k.publicKey)];
    assert(new Set(all).size === all.length, 'Every key must be new and different.');
    const join = (key, role) => sec.acceptRole({ networkId, accountId: String(account.id), role, ...key });
    const keys = [await join(signin, 'signin'), await join(spend, 'spend')];
    for (const key of recovery) keys.push(await join(key, 'recover'));
    return sign({ networkId, kind: KIND.secure, account, signer: fullKey, payload: sec.payloads.secure(keys, sec.policy({ threshold: policy.threshold, dailyLimitMicros: policy.daily_limit_micros, delaySeconds: policy.delay_seconds, freezeSeconds: policy.freeze_seconds })), check: false });
  }

  /// A root operation: every approver signs the same bytes, naming all approvers; one of them submits.
  async function buildRoot({ networkId, account, security, operation, approvers, submitter = approvers[0], expiresElapsedMicros }) {
    const keys = approvers.map(k => k.publicKey);
    const proofs = sec.proofs(account, keys);
    assert(BigInt(proofs.count) >= BigInt(security.policy.threshold), `This needs ${security.policy.threshold} proofs: your payment password and a recovery key, or two recovery keys.`);
    assert(keys.includes(submitter.publicKey), 'The key that submits must be one of the approvers.');
    const common = { networkId, accountId: String(account.id), version: security.version, expiresElapsedMicros: String(expiresElapsedMicros), operation, approvers: keys };
    const approvals = [];
    for (const key of approvers) approvals.push(await sec.approve({ ...common, publicKey: key.publicKey, privateKey: key.privateKey }));
    const built = await sign({ networkId, kind: KIND.root, account, signer: submitter, payload: sec.payloads.root(operation, String(expiresElapsedMicros), approvals) });
    return { ...built, version: security.version, spend: proofs.spend };
  }
  const requireRecoveryKey = (account, key, what) => assert(roleOf(account, key.publicKey) === 'recover', `This ${what} does not belong to @${account.name}. Check it and try again.`);

  /// How a payment of `amount` goes: a normal transfer within the remaining allowance, or a choice
  /// between waiting and paying now with a recovery proof.
  function choosePayment({ security, now, amount, feeMicros, balance }) {
    const fee = BigInt(feeMicros), value = BigInt(amount), total = value + fee, left = sec.allowance(security, now);
    const replacing = Boolean(security.pending_root && BigInt(security.pending_root.expires_elapsed_micros) >= BigInt(now));
    const frozen = sec.frozen(security, now);
    const result = { allowance: left, total, frozen, replacing };
    assert(value > 0n, 'Enter an amount above zero.');
    if (replacing) return { ...result, mode: 'blocked', reason: 'A replacement of your keys is waiting. No payment can be made until it is finished or cancelled.' };
    if (BigInt(balance) < total) return { ...result, mode: 'blocked', reason: 'The account does not hold the amount and the network fee.' };
    // A freeze stops payments within the limit and waiting ones. Your payment key with a recovery key can still pay.
    if (frozen) return { ...result, mode: 'frozen', reason: 'Your account is frozen, so payments with your payment password alone are refused until the freeze ends. See Home.', waitPossible: false, waitReason: 'The account is frozen.', delaySeconds: BigInt(security.policy.delay_seconds) };
    if (total <= left) return { ...result, mode: 'transfer' };
    const wait = left < fee ? 'Today\'s limit cannot even cover the fee of a waiting payment. Try again later.' : security.pending_payments.length >= 4 ? 'Four payments are already waiting.' : null;
    return { ...result, mode: 'over', waitPossible: wait === null, waitReason: wait, delaySeconds: BigInt(security.policy.delay_seconds) };
  }

  /// Whether a staking action can be signed now: refused while frozen (a freeze, or a waiting change
  /// of keys), and what it takes out of the balance must fit what is left of today's limit. There
  /// is no way around the limit for staking: the person raises it (it waits) or stakes in parts.
  function checkStake({ security, now, outflowMicros, feeMicros, balance }) {
    const total = BigInt(outflowMicros), fee = BigInt(feeMicros), left = sec.allowance(security, now);
    const result = { allowance: left, total };
    if (sec.frozen(security, now)) return { ...result, mode: 'frozen', reason: 'Your account is frozen, so staking, unbonding and withdrawing are refused until the freeze ends. See Home.' };
    if (BigInt(balance) < total) return { ...result, mode: 'blocked', reason: 'The account does not hold the amount and the network fee.' };
    if (total > left) return { ...result, mode: 'over', fitsToday: left > fee ? left - fee : 0n, delaySeconds: BigInt(security.policy.delay_seconds), dailyLimit: BigInt(security.policy.daily_limit_micros) };
    return { ...result, mode: 'ok' };
  }
  /// Whether a secured account can send an upgrade signal now. The signal moves nothing, but its
  /// fee lowers the balance: the engine refuses it while the account is frozen, and the fee must
  /// fit what is left of today's limit (`Security::spend`).
  function checkSignal({ security, now, feeMicros, balance }) {
    const fee = BigInt(feeMicros), left = sec.allowance(security, now);
    if (sec.frozen(security, now)) return { mode: 'frozen', allowance: left, reason: 'Your account is frozen. A frozen account can neither signal nor withdraw, and its signal does not count until the freeze ends. See Home.' };
    if (BigInt(balance) < fee) return { mode: 'blocked', allowance: left, reason: 'A signal costs the network fee, and the account holds less.' };
    if (fee > left) return { mode: 'over', allowance: left, reason: 'A signal costs the network fee, and less than that is left of your daily limit today. Try again later, or raise your daily limit on Home.' };
    return { mode: 'ok', allowance: left };
  }
  /// Everything the security inbox shows, from the verified row.
  function inboxEvents({ account, security, now, ownKeys = [] }) {
    const at = BigInt(now), events = [];
    for (const p of security.pending_payments) events.push({ type: 'payment', id: p.id, to: p.to, amount: p.amount, ready: BigInt(p.ready_elapsed_micros), readyNow: at >= BigInt(p.ready_elapsed_micros), cancel: { kind: KIND.cancel, payload: sec.payloads.cancelPayment(p.id) }, execute: { kind: KIND.payment, payload: sec.payloads.paymentExecute(p.id) } });
    const raise = security.pending_limit;
    if (raise && at < BigInt(raise.ready_elapsed_micros)) events.push({ type: 'limit', id: raise.id, dailyLimit: raise.daily_limit_micros, ready: BigInt(raise.ready_elapsed_micros), readyNow: false, cancel: { kind: KIND.cancel, payload: sec.payloads.cancelRaise(raise.id) } });
    const root = security.pending_root;
    if (root && at <= BigInt(root.expires_elapsed_micros)) {
      const keys = root.devices.map(d => ({ publicKey: d.public_key, role: sec.roleOf(d), known: account.devices.some(o => o.public_key === d.public_key) }));
      events.push({ type: 'replacement', ready: BigInt(root.ready_elapsed_micros), expires: BigInt(root.expires_elapsed_micros), readyNow: at >= BigInt(root.ready_elapsed_micros), keys, cancel: { kind: KIND.root, operation: sec.operations.cancel() } });
    }
    const until = BigInt(security.frozen_until_elapsed_micros);
    events.push({ type: 'frozen', frozen: sec.frozen(security, now), until: until > at ? until : null, byReplacement: Boolean(root && at <= BigInt(root.expires_elapsed_micros)), canFreeze: until - at <= BigInt(security.policy.freeze_seconds) * MICROS / 2n });
    for (const d of account.devices) if (sec.roleOf(d) === 'signin') events.push({ type: 'signin', publicKey: d.public_key, mine: ownKeys.includes(d.public_key) });
    return events;
  }

  /// Kind 72. A freeze names the freeze count and the version, and is void after five minutes.
  /// Two clocks (see waitsOf): `now` is the chain's time, on which the freeze's own expiry is dated; `waitsNow` is the
  /// clock of the waits, which the stored end of a freeze is compared with. It is `now` unless given.
  function freezePayload({ security, now, waitsNow = now }) {
    const at = BigInt(now), until = BigInt(security.frozen_until_elapsed_micros);
    assert(until - BigInt(waitsNow) <= BigInt(security.policy.freeze_seconds) * MICROS / 2n, 'The account is already frozen.');
    return sec.payloads.freeze(security, (at + FREEZE_LIFETIME_MICROS).toString());
  }
  const buildFreeze = async ({ networkId, account, security, signer, now, waitsNow = now }) => sign({ networkId, kind: KIND.freeze, account, signer, payload: freezePayload({ security, now, waitsNow }) });
  async function buildUnfreeze({ networkId, account, security, spend, recovery, now, waitsNow = now }) {
    assert(BigInt(security.frozen_until_elapsed_micros) > BigInt(waitsNow), 'The account is not frozen.');
    return buildRoot({ networkId, account, security, operation: sec.operations.unfreeze(security.freezes), approvers: [spend, recovery], submitter: spend, expiresElapsedMicros: BigInt(now) + APPROVAL_LIFETIME_MICROS });
  }
  async function buildPayNow({ networkId, account, security, spend, recovery, to, amount, now }) {
    requireRecoveryKey(account, recovery, 'recovery key');
    return buildRoot({ networkId, account, security, operation: sec.operations.pay(String(to), String(amount)), approvers: [spend, recovery], submitter: spend, expiresElapsedMicros: BigInt(now) + APPROVAL_LIFETIME_MICROS });
  }
  const buildWaitingPayment = ({ networkId, account, spend, to, amount }) => sign({ networkId, kind: KIND.payment, account, signer: spend, payload: sec.payloads.paymentRequest(String(to), String(amount)) });
  const buildExecute = ({ networkId, account, spend, id }) => sign({ networkId, kind: KIND.payment, account, signer: spend, payload: sec.payloads.paymentExecute(id) });
  const buildCancel = ({ networkId, account, signer, event }) => sign({ networkId, kind: KIND.cancel, account, signer, payload: event.cancel.payload });
  async function buildCancelReplacement({ networkId, account, security, approvers, now }) {
    assert(security.pending_root, 'No replacement of the keys is waiting.');
    return buildRoot({ networkId, account, security, operation: sec.operations.cancel(), approvers, submitter: approvers[0], expiresElapsedMicros: BigInt(now) + APPROVAL_LIFETIME_MICROS });
  }
  /// Kind 77: a raise waits, a lowering is immediate. With `now`, the limit it is compared with is the one in force
  /// then (a raise whose wait is over applies before the stored row shows it).
  async function buildLimit({ networkId, account, security, spend, dailyLimitMicros, feeMicros, now, waitsNow = now }) {
    const next = BigInt(decimal(String(dailyLimitMicros))), current = waitsNow === undefined ? BigInt(security.policy.daily_limit_micros) : effectiveLimit(security, waitsNow);
    assert(next !== current, 'The daily limit already has this value.');
    assert(next > BigInt(feeMicros), 'Choose a daily limit above the network fee, or your payment key cannot pay at all.');
    return { ...await sign({ networkId, kind: KIND.limit, account, signer: spend, payload: sec.payloads.limit(next.toString()) }), raise: next > current };
  }
  /// "Pause payments": kind 77 lowering the limit to exactly the fee of one action, at once (protection.mjs says why
  /// it is not zero). The engine charges this action's own fee to the allowance first, and refuses it while frozen.
  async function buildPause({ networkId, account, security, spend, feeMicros, now, waitsNow = now }) {
    const fee = BigInt(decimal(String(feeMicros)));
    assert(!sec.frozen(security, waitsNow), 'The account is frozen: nothing can be paid at once, paused or not.');
    assert(effectiveLimit(security, waitsNow) > fee, 'Payments are paused already.');
    assert(sec.allowance(security, waitsNow) >= fee,'Pausing costs the network fee, and less than that is left of your daily limit right now. Freeze the account instead, or try again later.');
    assert(BigInt(account.balance) >= fee, 'Pausing costs the network fee, and the account holds less. Freeze the account instead: a freeze costs what the account has.');
    return sign({ networkId, kind: KIND.limit, account, signer: spend, payload: sec.payloads.limit(pauseLimit(fee)) });
  }
  /// A daily limit set at once by the payment key and one recovery key: a root replacement that keeps every key in
  /// its role and changes the limit only (the engine has no other operation for it). Being a replacement, it drops
  /// what is waiting and moves the authority epoch on, so websites end their sessions (`install` in the engine), and
  /// it would end a freeze: it is not offered for a frozen account. The allowance keeps what was left under the old
  /// limit and refills from there.
  async function buildLimitNow({ networkId, account, security, spend, recovery, dailyLimitMicros, feeMicros, now, waitsNow = now }) {
    requireRecoveryKey(account, recovery, 'recovery key');
    const next = BigInt(decimal(String(dailyLimitMicros)));
    assert(!sec.frozen(security, waitsNow), 'The account is frozen. End the freeze first.');
    assert(next > BigInt(feeMicros), 'Choose a daily limit above the network fee, or your payment key cannot pay at all.');
    assert(next !== effectiveLimit(security, waitsNow), 'The daily limit already has this value.');
    assert(BigInt(account.balance) >= BigInt(feeMicros), 'This costs the network fee, and the account holds less.');
    const keys = account.devices.map(d => sec.keepKey(d.public_key, sec.roleOf(d)));
    return buildRoot({ networkId, account, security, operation: sec.operations.replace(keys, { ...security.policy, daily_limit_micros: next.toString() }), approvers: [spend, recovery], submitter: spend, expiresElapsedMicros: BigInt(now) + APPROVAL_LIFETIME_MICROS });
  }
  /// Kind 71: a new sign-in key for this device; every other sign-in key goes.
  async function buildReplaceSignin({ networkId, account, spend, signin }) {
    assert(roleOf(account, signin.publicKey) === undefined, 'The new login key must be new.');
    const add = [await sec.acceptRole({ networkId, accountId: String(account.id), role: 'signin', ...signin })];
    const remove = account.devices.filter(d => sec.roleOf(d) === 'signin').map(d => d.public_key);
    return sign({ networkId, kind: KIND.signin, account, signer: spend, payload: sec.payloads.signin({ add, remove }) });
  }
  /// Root replace approved by the spend key and one recovery key, at once: a new spend key and a new
  /// sign-in key for this browser. Every other spend and sign-in key goes, including one a thief
  /// added with the stolen spend key; the recovery keys stay.
  async function buildReplaceSpend({ networkId, account, security, spend, recovery, newSpend, newSignin, now, submitter = spend, expiresElapsedMicros }) {
    requireRecoveryKey(account, recovery, 'recovery key');
    assert(newSignin, 'A new login key for this browser is part of replacing the payment key.');
    for (const key of [newSpend, newSignin]) assert(roleOf(account, key.publicKey) === undefined, 'The new keys must be new.');
    const accept = (key, role) => sec.acceptRole({ networkId, accountId: String(account.id), role, ...key });
    const keys = [await accept(newSpend, 'spend'), await accept(newSignin, 'signin')];
    for (const d of account.devices) if (sec.roleOf(d) === 'recover') keys.push(sec.keepKey(d.public_key, 'recover'));
    return buildRoot({ networkId, account, security, operation: sec.operations.replace(keys, security.policy), approvers: [spend, recovery], submitter, expiresElapsedMicros: expiresElapsedMicros ?? BigInt(now) + APPROVAL_LIFETIME_MICROS });
  }
  /// Root replace approved by the spend key and one current recovery key, at once: a new recovery
  /// sheet and passphrase replace every recovery key. Sign-in and spend keys stay. Being immediate,
  /// it also ends a waiting change of keys and a freeze (`install` in the engine).
  async function buildReplaceRecovery({ networkId, account, security, spend, recovery, newSheet, newPhrase, now }) {
    requireRecoveryKey(account, recovery, 'recovery key');
    for (const key of [newSheet, newPhrase]) assert(roleOf(account, key.publicKey) === undefined, 'The new recovery keys must be new.');
    assert(newSheet.publicKey !== newPhrase.publicKey, 'The new recovery keys must differ.');
    const accept = key => sec.acceptRole({ networkId, accountId: String(account.id), role: 'recover', ...key });
    const keys = [await accept(newSheet), await accept(newPhrase)];
    for (const d of account.devices) { const role = sec.roleOf(d); if (role === 'signin' || role === 'spend') keys.push(sec.keepKey(d.public_key, role)); }
    const threshold = BigInt(security.policy.threshold) > 2n ? '2' : security.policy.threshold;
    return buildRoot({ networkId, account, security, operation: sec.operations.replace(keys, { ...security.policy, threshold }), approvers: [spend, recovery], submitter: spend, expiresElapsedMicros: BigInt(now) + APPROVAL_LIFETIME_MICROS });
  }
  /// Kind 71 adding the sign-in key of another browser (from `parseSigninRequest`), removing nothing.
  /// Both signatures of the request must check, and its epoch must still be the account's.
  async function buildAddSignin({ networkId, account, spend, request }) {
    assert(request.authEpoch === String(account.auth_epoch), 'This request was made before the account\'s keys last changed. Ask the other browser for a new one.');
    assert(await verifyProof(networkId, account, request), 'The request\'s proof does not check. Ask the other browser for a new one.');
    return sign({ networkId, kind: KIND.signin, account, signer: spend, payload: sec.payloads.signin({ add: [{ public_key: request.public_key, proof: request.proof }] }) });
  }
  async function verifyProof(networkId, account, request) {
    const key = await globalThis.crypto.subtle.importKey('raw', unhex(request.public_key, 32), 'Ed25519', false, ['verify']);
    const accepted = await globalThis.crypto.subtle.verify('Ed25519', key, unhex(request.proof, 64), sec.keyMessage({ networkId, accountId: String(account.id), role: 'signin', publicKey: request.public_key }));
    const dated = await globalThis.crypto.subtle.verify('Ed25519', key, unhex(request.requestProof, 64), loginRequestMessage({ networkId, accountId: String(account.id), authEpoch: request.authEpoch, expires: request.expires, publicKey: request.public_key }));
    return accepted && dated;
  }
  /// The login request this browser shows to a device that holds the payment key.
  async function signinRequest({ networkId, account, key, now }) {
    const accountId = String(account.id), authEpoch = String(account.auth_epoch), expires = (BigInt(now) + LOGIN_REQUEST_LIFETIME_MICROS).toString();
    const accepted = await sec.acceptRole({ networkId, accountId, role: 'signin', ...key });
    const requestProof = hex(new Uint8Array(await globalThis.crypto.subtle.sign('Ed25519', key.privateKey, loginRequestMessage({ networkId, accountId, authEpoch, expires, publicKey: key.publicKey }))));
    return { version: 2, type: 'signin-key', networkId, accountId, name: account.name, authEpoch, expires, publicKey: key.publicKey, proof: accepted.proof, requestProof };
  }
  /// Lost device: the two recovery keys ask for a new sign-in and spend key. Recovery keys stay,
  /// every other key goes. It waits `delay_seconds` with the account frozen.
  async function buildLostDeviceRequest({ networkId, account, security, sheet, phrase, signin, spend, now }) {
    assert(security, `@${account.name} has not secured its account. Use guardian recovery instead.`);
    assert(!security.pending_root, 'A replacement of the keys is already waiting for this account.');
    requireRecoveryKey(account, sheet, 'recovery sheet');
    requireRecoveryKey(account, phrase, 'recovery passphrase');
    assert(sheet.publicKey !== phrase.publicKey, 'The recovery sheet and the passphrase must be different keys.');
    const accept = (key, role) => sec.acceptRole({ networkId, accountId: String(account.id), role, ...key });
    const keys = [await accept(signin, 'signin'), await accept(spend, 'spend')];
    for (const d of account.devices) if (sec.roleOf(d) === 'recover') keys.push(sec.keepKey(d.public_key, 'recover'));
    return buildRoot({ networkId, account, security, operation: sec.operations.replace(keys, security.policy), approvers: [sheet, phrase], submitter: sheet, expiresElapsedMicros: BigInt(now) + APPROVAL_LIFETIME_MICROS });
  }
  /// Kind 74, signed by the new spend key once the wait is over.
  async function buildFinalize({ networkId, account, security, spend, now, waitsNow = now }) {
    const root = security?.pending_root;
    assert(root, 'No replacement of the keys is waiting for this account.');
    assert(root.devices.some(d => d.public_key === spend.publicKey && sec.roleOf(d) === 'spend'), 'The waiting replacement does not name this device\'s payment key.');
    assert(BigInt(waitsNow) >= BigInt(root.ready_elapsed_micros), 'The waiting period is not over yet.');
    return sign({ networkId, kind: KIND.finalize, account, signer: spend, payload: sec.payloads.finalize(security), check: false });
  }
  /// A secured account whose login key on this browser is gone: what the person can still do here.
  function removedLogin({ account, security, spendKey, now }) {
    const spendUsable = Boolean(spendKey) && roleOf(account, spendKey) === 'spend';
    const frozen = sec.frozen(security, now), replacing = Boolean(security.pending_root && BigInt(security.pending_root.expires_elapsed_micros) >= BigInt(now));
    return { spendUsable, frozen, replacing, canReplaceLogin: spendUsable && !frozen };
  }
  /// How many things wait for the person: waiting items, a freeze they may not have placed, and guardian recoveries of the account.
  function inboxCount({ events = [], recoveryCases = [], accountId }) {
    let count = events.filter(e => e.type === 'payment' || e.type === 'limit' || e.type === 'replacement').length;
    if (events.some(e => e.type === 'frozen' && e.frozen && !e.byReplacement)) count++;
    return count + recoveryCases.filter(r => r.target === String(accountId)).length;
  }
  return { buildReplaceRecovery, buildAddSignin, signinRequest, checkStake, checkSignal, removedLogin, inboxCount, rowOf, roleOf, assertSigner, buildSecure, buildRoot, choosePayment, inboxEvents, freezePayload, buildFreeze, buildUnfreeze, buildPayNow, buildWaitingPayment, buildExecute, buildCancel, buildCancelReplacement, buildLimit, buildPause, buildLimitNow, buildReplaceSignin, buildReplaceSpend, buildLostDeviceRequest, buildFinalize, KIND };
}
export { vaultIntent };
