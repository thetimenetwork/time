// "Move my account to another device": the authority of a protected account moves to a new device. Keys never travel.
//
// Why: whoever locked their keys to a device ("Lock my keys to this device", device-lock.mjs) has no backup file of them,
// and without this the only way to a new phone is the recovery words and the account's waiting period.
//
// How. Each step is a function below; the pages call them.
// 1. The NEW device makes a login key and a payment key and has the page seal them (`seal`, which returns the records:
//    locked to the device from birth with the person's new passwords, or under passwords the wallet makes). The page's
//    `open` then gives each record's private key, and this module checks that it signs for that record's public key.
//    Keys under passwords the wallet made are opened again with those passwords. Keys locked from birth were opened
//    already, inside the sealing, with a second answer of the device (device-lock.mjs, sealAtBirth): the page gives
//    those keys and does not ask the device a third time. Then both records are kept aside, and only then is the move
//    request given, with its code (prepareMove).
// 2. The request is public data only, carried to the OLD device as text by any means. The old device checks all of it
//    (reviewMove; the order is in MOVE_CHECKS) and asks the person to type the code they read on the new device's screen
//    (checkCode). It never shows the code it expects, nor anything the code can be read from.
// 3. With its payment key (the payment password, and the device if its keys are locked) and one recovery key (the words
//    or the sheet), the old device signs one root replacement that takes effect at once (buildMove, and the replacement it
//    alone reaches): the two new keys with the other device's acceptances, every recovery key kept, the policy kept. By the
//    engine's rule every other payment and login key of the account goes, the old device's included.
// 4. The old device forgets its keys of the account only once a verified state shows the account holding exactly the new
//    payment key and login key, or holding a key of the move and none of the keys this browser keeps (the new device may
//    have changed its keys before the old one looked again) (oldDeviceStatus, forgetOldDevice, mayForget). The new device
//    puts its keys in place once a verified state shows them on the account (resumeMove).
// No private key, password or device secret leaves either device; nothing but the chain is involved; nothing waits.
//
// The request is one line of JSON (moveRequestText), its fields in this order:
//   {"type":"time-move-request","version":1,"networkId":<64 hex>,"accountId":<decimal>,"name":<account name>,
//    "authEpoch":<decimal>,"expires":<decimal>,"signin":{"publicKey":<64 hex>,"proof":<128 hex>,"requestProof":<128 hex>},
//    "spend":{"publicKey":<64 hex>,"proof":<128 hex>,"requestProof":<128 hex>}}
// `proof` is the key's acceptance of its role on the account (account-security.mjs, acceptRole: what the engine checks).
// `requestProof` is the key's signature, made by EACH of the two keys, over
//   "TCDEVNET-WALLET-MOVE-REQUEST-V1\0" || network id (32 bytes) || account number (8 bytes, big-endian) ||
//   authority epoch (8) || expiry (8; the chain's time, elapsed microseconds) || login public key (32) || payment key (32).
// The expiry is one hour after the chain's time the new device read. The code is the first 80 bits of
//   SHA-256("TCDEVNET-WALLET-MOVE-CODE-V1\0" || the same fields in the same order),
// written as 16 characters of SHEET_ALPHABET (security-flows.mjs) in four groups of four. Anyone who holds the request
// can work the code out: it proves that the request the old device holds is the one the new device's screen belongs to,
// and nothing about who made that request (MOVE_WORDS.onlyYours is what the page says about that).
//
// What each device keeps (public data and sealed records; the storage is the caller's), under the prefix of keys kept
// aside (STAGED_PREFIX), so that device-lock.mjs (credentialInUse) counts a device key these records are locked to as in
// use, and so that the page's start (stagedNames) reads the account's state:
// - the new device (moveSlots): the records of one move that may be shown ("active"), and of one that was withdrawn while
//   it could still land ("held": withdrawMove says why), and a note with their requests;
// - the old device: from just before it sends the move until the chain decides, a note with the request and the version
//   and expiry it signed (rememberMove), so that a page closed meanwhile still forgets its keys once the move landed.
//
// No page and no network here: the storage, the account security library (`security`), the clock (`now`, the chain's
// time of a verified state; `waitsNow`, its clock of the waits: security-flows.mjs, waitsOf) and the sealing come in as
// arguments. Web Locks (`locks`, navigator.locks) are required: every write is made under the account's vault lock, never
// while the person types or the device asks.
import { hex, unhex, validateVaultRecord, forgetSecret } from './vault.mjs';
import { createSecurityFlows, vaultSlots, elapsedOf, dateOf, hasStaged, loginRequestOf, SHEET_ALPHABET, STAGED_PREFIX, APPROVAL_LIFETIME_MICROS } from './security-flows.mjs';
import { lockPlaces } from './device-lock.mjs';

const encoder = new TextEncoder();
const fail = message => { throw new Error(message); };
const assert = (value, message) => { if (!value) fail(message); };
const MICROS = 1000000n;
const concat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0; for (const p of parts) { out.set(p, at); at += p.length; } return out; };
const u64 = value => { const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, BigInt(value)); return out; };
const isDecimal = value => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) < 1n << 64n;
const HEX32 = /^[0-9a-f]{64}$/, HEX64 = /^[0-9a-f]{128}$/, NAME = /^[a-z0-9_]{2,15}$/;
const ROLES = Object.freeze(['signin', 'spend']);

/// How long a request may be used: an hour of the chain's time after the new device read it.
export const MOVE_REQUEST_LIFETIME_MICROS = 3600n * MICROS;
/// How far the old device's view of the chain's time may lag behind the new device's.
const SKEW_MICROS = 5n * 60n * MICROS;
export const MOVE_TYPE = 'time-move-request';
export const MOVE_CODE = Object.freeze({ bits: 80, groups: 4, groupLength: 4 });
const REQUEST_DOMAIN = encoder.encode('TCDEVNET-WALLET-MOVE-REQUEST-V1\0');
const CODE_DOMAIN = encoder.encode('TCDEVNET-WALLET-MOVE-CODE-V1\0');
const OPEN_DOMAIN = encoder.encode('TCDEVNET-WALLET-MOVE-OPEN-CHECK-V1\0');
const MAX_TEXT = 4096;

/// What the person reads.
export const MOVE_WORDS = Object.freeze({
  // Said on the old device above the field of the code, and nowhere else is the code asked for.
  onlyYours: 'Type only the code your own new device shows you right now: if anyone sent you this code or this request, stop, because whoever made the request would get your account.',
  paste: 'Paste the move request from your new device.',
  notRequest: 'This is not a move request from this wallet. Make a new one on your new device.',
  damaged: 'This move request is damaged. Make a new one on your new device, and carry it again.',
  otherNetwork: 'This move request is for another network.',
  otherAccount: 'This move request is for another account.',
  epoch: "This move request was made before your account's keys last changed. Make a new one on your new device.",
  expired: 'This move request has expired. Make a new one on your new device.',
  ahead: 'This move request is dated further ahead than this wallet dates them. Make a new one on your new device.',
  sameKey: 'This move request names one key for both roles. Make a new one on your new device.',
  onAccount: 'A key of this move request is a key of your account already. Make a new one on your new device.',
  signatures: 'The signatures of this move request do not check: it was changed on its way. Make a new one on your new device, and carry it another way.',
  notProtected: 'This account is not protected. Only a protected account moves this way.',
  threshold: 'Your account needs more than two proofs for a change of its keys, and a move gives two: your payment password and one recovery key. Replace your keys under Keys instead.',
  waits: 'The clock of the waits of the state read is required (security-flows.mjs, waitsOf). Nothing was checked or signed.',
  replacing: 'A replacement of your keys is waiting on your account. Look at it on Home first: a move would end it unseen.',
  frozen: 'Your account is frozen. End the freeze first: a move would end it unseen.',
  fee: 'Moving your account costs the network fee, and the account holds less.',
  codeForm: 'The code is 16 characters, in four groups of four, as your new device shows it.',
  codeWrong: 'This is not the code of this request, so nothing was signed. Read the code on your new device again. If it is what you typed, the request was changed on its way: make a new one, and carry it another way.',
  // The new device.
  notFound: 'This account was not found on the network.',
  hasPayment: 'This browser holds the payment key of this account already: there is nothing to move to it.',
  otherChange: 'A change of keys or a login request of this browser is still waiting for the network. Finish or withdraw it first.',
  alreadyWaiting: 'A move request of this browser is still waiting. Show it again, or withdraw it first.',
  notSealed: 'The new keys could not be kept on this browser. No request was made.',
  notOpened: 'The new keys did not open again on this browser, so no request was made. Nothing was kept.',
  notKept: 'This browser did not keep the new keys as they were written, so no request was made. Nothing was kept.',
  fleeting: 'This browser may delete what this page keeps here (a private window, or storage it clears when it needs room). If it did before your move lands, nobody would hold your new keys, and your account would need your recovery words and its waiting period. Allow this site to keep its data, or use a normal window of a browser that keeps it.',
  unread: 'The network could not be read, so nothing was deleted: the new keys stay on this browser.',
  locks: 'This browser needs Web Locks to keep your keys safe across tabs. Use a current Chrome, Edge or Firefox.',
  heldBusy: until => `A request withdrawn earlier on this browser could still be used until ${until}. Wait until then, or finish the move with this one.`,
  // The old device.
  sentWaiting: 'A move sent from this browser is still waiting for the network. Wait for it first.',
  notMovedYet: 'The network does not show your account on your new device yet, so this browser keeps its keys.',
  mixedKeep: 'Your account still has a key of this browser besides the keys of your new device, so this browser keeps its keys. Look at your keys under Keys.',
});

/// What the old device checks, in this order (reviewMove; buildMove checks all of it again on the state it signs on).
export const MOVE_CHECKS = Object.freeze([
  'the text: at most 4096 characters, JSON, exactly the fields of a move request, type and version',
  'every field well formed: hexadecimal keys and signatures of their lengths, whole numbers, an account name',
  'the network', 'the account: its number and its name', "the account's authority epoch",
  'the expiry: not passed, and at most an hour and five minutes ahead', 'two different keys', 'neither key a key of the account',
  'the account protected', 'at most two proofs needed (a move gives the payment key and one recovery key)', 'no replacement of its keys waiting',
  'not frozen (on the clock of the waits)', 'the network fee in the account',
  'each key\'s acceptance of its role, and each key\'s signature over the request',
  'the code the person typed (checkCode), before any password or recovery key is asked for',
]);

// ------------------------------------------------------------------ the request
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const FIELDS = 'accountId,authEpoch,expires,name,networkId,signin,spend,type,version';
const KEY_FIELDS = 'proof,publicKey,requestProof';
const canonical = (r = {}) => Object.freeze({ type: MOVE_TYPE, version: 1, networkId: r?.networkId, accountId: r?.accountId, name: r?.name, authEpoch: r?.authEpoch, expires: r?.expires,
  signin: Object.freeze({ publicKey: r.signin?.publicKey, proof: r.signin?.proof, requestProof: r.signin?.requestProof }),
  spend: Object.freeze({ publicKey: r.spend?.publicKey, proof: r.spend?.proof, requestProof: r.spend?.requestProof }) });
/// The text form of a request: one line of JSON, its fields in their order.
export const moveRequestText = request => JSON.stringify(canonical(request));
/// A request from its text, checked for its form only (MOVE_CHECKS, the first two).
export function readMoveRequest(text) {
  assert(typeof text === 'string' && text.trim() !== '', MOVE_WORDS.paste);
  assert(text.length <= MAX_TEXT, MOVE_WORDS.notRequest);
  let r; try { r = JSON.parse(text); } catch { fail(MOVE_WORDS.notRequest); }
  assert(plain(r) && Object.keys(r).sort().join(',') === FIELDS && r.type === MOVE_TYPE && r.version === 1 && ROLES.every(role => plain(r[role]) && Object.keys(r[role]).sort().join(',') === KEY_FIELDS), MOVE_WORDS.notRequest);
  assert(typeof r.networkId === 'string' && HEX32.test(r.networkId) && isDecimal(r.accountId) && typeof r.name === 'string' && NAME.test(r.name) && isDecimal(r.authEpoch) && isDecimal(r.expires)
    && ROLES.every(role => typeof r[role].publicKey === 'string' && HEX32.test(r[role].publicKey) && typeof r[role].proof === 'string' && HEX64.test(r[role].proof) && typeof r[role].requestProof === 'string' && HEX64.test(r[role].requestProof)), MOVE_WORDS.damaged);
  return canonical(r);
}
/// A request against the account the old device has open, at `now` (the chain's time of its verified state): MOVE_CHECKS,
/// the third to the eighth. No signature is checked here.
export function checkMoveRequest(request, { networkId, account, now }) {
  assert(request.networkId === networkId, MOVE_WORDS.otherNetwork);
  assert(request.accountId === String(account.id) && request.name === account.name, MOVE_WORDS.otherAccount);
  assert(request.authEpoch === String(account.auth_epoch), MOVE_WORDS.epoch);
  const at = BigInt(now), expires = BigInt(request.expires);
  assert(expires > at, MOVE_WORDS.expired);
  assert(expires <= at + MOVE_REQUEST_LIFETIME_MICROS + SKEW_MICROS, MOVE_WORDS.ahead);
  assert(request.signin.publicKey !== request.spend.publicKey, MOVE_WORDS.sameKey);
  assert(!account.devices.some(d => d.public_key === request.signin.publicKey || d.public_key === request.spend.publicKey), MOVE_WORDS.onAccount);
  return request;
}
export const parseMoveRequest = (text, context) => checkMoveRequest(readMoveRequest(text), context);
const fieldBytes = r => concat(unhex(r.networkId, 32), u64(r.accountId), u64(r.authEpoch), u64(r.expires), unhex(r.signin.publicKey, 32), unhex(r.spend.publicKey, 32));
/// What each of the two keys signs (`requestProof`).
export const moveRequestMessage = r => concat(REQUEST_DOMAIN, fieldBytes(r));
/// The last moment of the chain's time at which a move built on this request can still land: the old device signs only
/// before the request expires, and dates its approvals APPROVAL_LIFETIME_MICROS ahead (security-flows.mjs, buildRoot).
export const moveWindowEnd = request => BigInt(request.expires) + APPROVAL_LIFETIME_MICROS;

// ------------------------------------------------------------------ the code
function base32(bytes) {
  let text = '', buffer = 0, bits = 0;
  for (const byte of bytes) { buffer = (buffer << 8) | byte; bits += 8; while (bits >= 5) { bits -= 5; text += SHEET_ALPHABET[(buffer >> bits) & 31]; } buffer &= (1 << bits) - 1; }
  return text;
}
/// The code of a request: 16 characters in four groups of four. Only the new device shows it.
export async function moveCode(request, cryptoImpl = globalThis.crypto) {
  const digest = new Uint8Array(await cryptoImpl.subtle.digest('SHA-256', concat(CODE_DOMAIN, fieldBytes(request))));
  return base32(digest.slice(0, MOVE_CODE.bits / 8)).match(/.{4}/g).join(' ');
}
/// The characters of a typed code: case, spaces and dashes ignored, O read as 0 and I or L as 1, as on a recovery sheet.
export function codeCharacters(text) {
  assert(typeof text === 'string' && text.length <= 64, MOVE_WORDS.codeForm);
  const chars = text.toUpperCase().replace(/[\s-]+/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
  assert(/^[0-9A-HJKMNP-TV-Z]{16}$/.test(chars), MOVE_WORDS.codeForm);
  return chars;
}
/// Whether `typed` is the code of `request`; a plain error in the person's words when it is not. The expected code is
/// compared here and never returned.
export async function checkCode(request, typed, cryptoImpl = globalThis.crypto) {
  const chars = codeCharacters(typed), expected = (await moveCode(request, cryptoImpl)).replace(/ /g, '');
  let differ = 0; for (let i = 0; i < expected.length; i++) differ |= chars.charCodeAt(i) ^ expected.charCodeAt(i);
  assert(differ === 0, MOVE_WORDS.codeWrong);
  return true;
}

// ------------------------------------------------------------------ signatures
async function verifies(cryptoImpl, publicKey, signature, message) {
  try {
    const key = await cryptoImpl.subtle.importKey('raw', unhex(publicKey, 32), { name: 'Ed25519' }, false, ['verify']);
    return await cryptoImpl.subtle.verify({ name: 'Ed25519' }, key, unhex(signature, 64), message);
  } catch { return false; }
}
/// Both acceptances (the bytes the engine verifies) and both signatures over the request; a plain error otherwise.
export async function verifyMoveRequest(request, { security: sec, cryptoImpl = globalThis.crypto }) {
  const message = moveRequestMessage(request);
  for (const role of ROLES) {
    const key = request[role];
    const accepted = await verifies(cryptoImpl, key.publicKey, key.proof, sec.keyMessage({ networkId: request.networkId, accountId: request.accountId, role, publicKey: key.publicKey }));
    const dated = await verifies(cryptoImpl, key.publicKey, key.requestProof, message);
    assert(accepted && dated, MOVE_WORDS.signatures);
  }
  return true;
}

// ------------------------------------------------------------------ storage that lasts
/// Whether what this browser keeps for the wallet's site lasts: the browser's own answer, through its StorageManager
/// (`storageManager`: navigator.storage). `persisted()` true: the browser does not clear it to make room. False: it may
/// ("best effort"), and then, with `ask`, the browser is asked once (`persist()`, which a browser grants or refuses by its
/// own rules, sometimes by asking the person). Returns { lasting: true | false | null, asked }: null when the browser gives
/// no answer (no StorageManager, or it refused to say).
/// What this can NOT tell: whether the window is private (a private window keeps until it closes; browsers answer there
/// as for any storage that may be cleared, or grant it for the session), whether the person will clear the site's data,
/// whether the device is lost, or (in Safari) whether storage of a site not opened for some days will be cleared. So a
/// new device should be opened again soon after the move, to settle its keys.
export async function lastingStorage(storageManager, { ask = true } = {}) {
  if (!storageManager || typeof storageManager.persisted !== 'function') return { lasting: null, asked: false };
  let lasting;
  try { lasting = (await storageManager.persisted()) === true; } catch { return { lasting: null, asked: false }; }
  if (lasting || !ask || typeof storageManager.persist !== 'function') return { lasting, asked: false };
  try { lasting = (await storageManager.persist()) === true; } catch { lasting = false; }
  return { lasting, asked: true };
}

// ------------------------------------------------------------------ where things are kept
export function moveSlots(networkId, name) {
  assert(HEX32.test(networkId) && NAME.test(name), 'Invalid account');
  const base = `${STAGED_PREFIX}${networkId}:${name}:`;
  return { note: base + 'move', active: { signin: base + 'movesignin', spend: base + 'movespend' }, held: { signin: base + 'moveheldsignin', spend: base + 'moveheldspend' }, bound: base + 'movebound', sent: base + 'moved' };
}
const POSITIONS = Object.freeze(['active', 'held']);
const NOTE_FIELDS = 'active,held,version';
function readNote(storage, slots) {
  const raw = storage.getItem(slots.note); if (raw === null) return null;
  let note; try { note = JSON.parse(raw); } catch { fail('damaged'); }
  assert(plain(note) && Object.keys(note).sort().join(',') === NOTE_FIELDS && note.version === 1, 'damaged');
  const out = { version: 1, active: null, held: null };
  for (const which of POSITIONS) if (note[which] !== null) out[which] = readMoveRequest(JSON.stringify(note[which]));
  return out;
}
const writeNote = (storage, slots, note) => { if (!note.active && !note.held) storage.removeItem(slots.note); else storage.setItem(slots.note, JSON.stringify({ version: 1, active: note.active, held: note.held })); };
/// The record at `key` when it is there, sound for `role`, of this account, and of `publicKey` (any key when null); else null.
function soundRecord(storage, key, role, publicKey, networkId, name) {
  const raw = storage.getItem(key); if (raw === null) return null;
  let record; try { record = JSON.parse(raw); validateVaultRecord(record, role); } catch { return null; }
  const b = record.binding;
  return b.networkId === networkId && b.name === name && (publicKey === null || b.publicKey === publicKey) ? record : null;
}
/// The records of a position, when both are there, sound, and the keys of `request` for this account; else null.
function recordsAt(storage, slots, which, request, networkId, name) {
  const out = {};
  for (const role of ROLES) { out[role] = soundRecord(storage, slots[which][role], role, request[role].publicKey, networkId, name); if (!out[role]) return null; }
  return out;
}
const livePlace = (live, role) => (role === 'signin' ? live.login : live.spend);
const dropPosition = (storage, slots, which) => { for (const key of Object.values(slots[which])) storage.removeItem(key); };
/// Records of a position the note does not name were never shown, or are copies of records the note names elsewhere.
function tidy(storage, slots, note) { for (const which of POSITIONS) if (!note?.[which]) dropPosition(storage, slots, which); }
// The bound: the last moment of the chain's time at which a move on any request of this browser can still land
// (moveWindowEnd of the latest). It is written, in a key of its own, before the records of a request, so that a note this
// wallet cannot read (damaged, or of a later wallet) still says until when its records must be kept.
function readBound(storage, slots) {
  try { const value = JSON.parse(storage.getItem(slots.bound)); return plain(value) && value.version === 1 && isDecimal(value.until) ? BigInt(value.until) : null; } catch { return null; }
}
function writeBound(storage, slots, until) {
  const kept = readBound(storage, slots);
  storage.setItem(slots.bound, JSON.stringify({ version: 1, until: String(kept !== null && kept > until ? kept : until) }));
}
/// The bound kept beside the records, or else read leniently from the note's text (every expiry it names, plus the life of
/// the approvals); null when neither gives one.
function boundOf(storage, slots) {
  let found = readBound(storage, slots);
  const raw = storage.getItem(slots.note);
  if (typeof raw === 'string') for (const m of raw.matchAll(/"expires"\s*:\s*"(0|[1-9][0-9]{0,19})"/g)) { const until = BigInt(m[1]) + APPROVAL_LIFETIME_MICROS; if (found === null || until > found) found = until; }
  return found;
}
/// Once nothing of a move is left, its bound goes too.
function finishIfEmpty(storage, slots) {
  if (storage.getItem(slots.note) === null && POSITIONS.every(which => Object.values(slots[which]).every(key => storage.getItem(key) === null))) storage.removeItem(slots.bound);
}
const dropAll = (storage, slots) => { for (const which of POSITIONS) dropPosition(storage, slots, which); storage.removeItem(slots.note); storage.removeItem(slots.bound); };
/// Every write of what a browser keeps for a move is made under the account's vault lock (the lock every other writer of
/// its vaults takes), so that two tabs never overwrite each other's keys. Without Web Locks nothing is written.
const needLocks = locks => assert(typeof locks?.request === 'function', MOVE_WORDS.locks);
const underLock = (locks, networkId, name, work) => { needLocks(locks); return locks.request(`timecurrency:vault:${networkId}:${name}`, { mode: 'exclusive' }, work); };
function accountIn(state, name, required = true) {
  const account = Array.isArray(state?.accounts) ? state.accounts.find(a => a.name === name) ?? null : null;
  if (required) assert(account, MOVE_WORDS.notFound);
  return account;
}

// ------------------------------------------------------------------ with the account security library
/// `locks`: navigator.locks; every function that writes what a browser keeps for a move refuses to run without it (it can
/// also be given to each call).
export function createDeviceMove({ security: sec, cryptoImpl = globalThis.crypto, locks: defaultLocks = null }) {
  assert(sec?.acceptRole && sec.keyMessage && sec.operations && sec.roleOf, 'The account security library is required');
  const flows = createSecurityFlows({ security: sec });
  const holds = (account, publicKey, role) => account.devices.some(d => d.public_key === publicKey && sec.roleOf(d) === role);
  const workingKeys = account => account.devices.filter(d => { const role = sec.roleOf(d); return role === 'signin' || role === 'spend'; });
  /// How the account stands against a request: 'exact' (its payment and login keys are the request's two, and no others),
  /// 'mixed' (one of them is on the account, or both with others), or 'absent'.
  function shapeOf(account, request) {
    const signin = holds(account, request.signin.publicKey, 'signin'), spend = holds(account, request.spend.publicKey, 'spend');
    if (signin && spend && workingKeys(account).length === 2) return 'exact';
    return signin || spend ? 'mixed' : 'absent';
  }
  function rowIn(state, account) {
    assert(Array.isArray(state?.security), 'The security state of this account was not proven. Refresh and try again.');
    return sec.securityOf(state, account.id);
  }
  /// MOVE_CHECKS, from "the account protected" to "the network fee". `waitsNow`, the clock of the waits (security-flows.mjs,
  /// waitsOf), is required: on a network whose waits survive stops it is not the chain's time, and a freeze or a waiting
  /// replacement read on the chain's time could look over when it is not (the engine would take the move over it).
  function accountReady({ account, security, waitsNow, feeMicros }) {
    assert(waitsNow !== undefined && waitsNow !== null && /^(0|[1-9][0-9]*)$/.test(String(waitsNow)), MOVE_WORDS.waits);
    assert(security, MOVE_WORDS.notProtected);
    assert(isDecimal(String(security.policy?.threshold)) && BigInt(security.policy.threshold) <= 2n, MOVE_WORDS.threshold);
    const root = security.pending_root;
    assert(!(root && BigInt(root.expires_elapsed_micros) >= BigInt(waitsNow)), MOVE_WORDS.replacing);
    assert(!sec.frozen(security, waitsNow), MOVE_WORDS.frozen);
    if (feeMicros !== undefined) assert(BigInt(account.balance) >= BigInt(feeMicros), MOVE_WORDS.fee);
  }

  // ---------------------------------------------------------------- the new device
  /// The request for two keys ({ publicKey, privateKey }) of this account, dated `now` (the chain's time) plus an hour.
  async function moveRequest({ networkId, account, signin, spend, now }) {
    assert(signin.publicKey !== spend.publicKey, MOVE_WORDS.sameKey);
    const accountId = String(account.id);
    const fields = { networkId, accountId, name: account.name, authEpoch: String(account.auth_epoch), expires: (BigInt(now) + MOVE_REQUEST_LIFETIME_MICROS).toString(), signin: { publicKey: signin.publicKey }, spend: { publicKey: spend.publicKey } };
    const message = moveRequestMessage(fields);
    const part = async (key, role) => ({ publicKey: key.publicKey, proof: (await sec.acceptRole({ networkId, accountId, role, publicKey: key.publicKey, privateKey: key.privateKey })).proof,
      requestProof: hex(new Uint8Array(await cryptoImpl.subtle.sign({ name: 'Ed25519' }, key.privateKey, message))) });
    return canonical({ ...fields, signin: await part(signin, 'signin'), spend: await part(spend, 'spend') });
  }
  /// Whether an opened key signs for `publicKey`: a fresh challenge in a domain of its own, signed and verified.
  async function signsFor(opened, publicKey) {
    let ok = false;
    try {
      const challenge = concat(OPEN_DOMAIN, cryptoImpl.getRandomValues(new Uint8Array(32)));
      ok = await verifies(cryptoImpl, publicKey, hex(new Uint8Array(await cryptoImpl.subtle.sign({ name: 'Ed25519' }, opened.privateKey, challenge))), challenge);
    } catch { ok = false; }
    assert(ok, MOVE_WORDS.notOpened);
  }
  const shown = async request => ({ request, text: moveRequestText(request), code: await moveCode(request, cryptoImpl), expires: BigInt(request.expires) });

  /// Step 1, on the new device. `state`: a verified state with the account (by `name`) and its security row. `seal(wanted)`
  /// gets [{ intent: 'signin' }, { intent: 'spend' }] and returns, in that order, [{ key: { publicKey, privateKey }, record }]
  /// (security-flows.mjs, sealedKeys, through device-lock.mjs, newKeysByRule). `open(record)` returns the record's private
  /// key ({ privateKey }): opened again by vault.mjs openVault where the wallet made its password; for a key locked from
  /// birth, the key that sealAtBirth's second answer of the device already opened (the device is not asked again). Each
  /// must sign for its record's public key, else everything stops and nothing is kept. The records are kept before the
  /// request exists. Returns { request, text, code, expires }.
  /// The account's vault lock is held only to read and check, and again to check and write: not while the person types
  /// passwords or answers the device (`seal`, `open`), so that another tab can still open the wallet meanwhile. What is
  /// checked first is checked again under the lock before anything is written: another tab may have made a request since.
  /// `lasting`: what lastingStorage answered for this browser. A move on storage the browser may clear (or says nothing
  /// about) could leave the account with keys nobody holds, if the browser clears it before the move lands: no request is
  /// made there unless the page told the person so (MOVE_WORDS.fleeting) and they chose to go on (`accepted: true`).
  async function prepareMove({ storage, networkId, state, name, now = state ? elapsedOf(state) : undefined, waitsNow, lasting, seal, open, locks = defaultLocks }) {
    needLocks(locks);
    assert(plain(lasting) && [true, false, null].includes(lasting.lasting), 'The answer of lastingStorage is required.');
    assert(lasting.lasting === true || lasting.accepted === true, MOVE_WORDS.fleeting);
    assert(typeof seal === 'function' && typeof open === 'function', 'Sealing and opening functions are required.');
    const account = accountIn(state, name), security = rowIn(state, account);
    accountReady({ account, security, waitsNow });
    const live = vaultSlots(networkId, name), slots = moveSlots(networkId, name);
    const ready = () => {
      let note; try { note = readNote(storage, slots); } catch { fail(MOVE_WORDS.alreadyWaiting); }
      tidy(storage, slots, note); finishIfEmpty(storage, slots);
      assert(!note?.active, MOVE_WORDS.alreadyWaiting);
      let spendHere = null; try { spendHere = JSON.parse(storage.getItem(live.spend))?.binding?.publicKey ?? null; } catch { spendHere = null; }
      assert(!(spendHere && holds(account, spendHere, 'spend')), MOVE_WORDS.hasPayment);
      assert(!hasStaged(storage, live) && storage.getItem(live.request) === null && !loginRequestOf(storage, live), MOVE_WORDS.otherChange);
      return note;
    };
    await underLock(locks, networkId, name, async () => { ready(); });
    const made = await seal(ROLES.map(intent => ({ intent })));
    const opened = [];
    try {
      assert(Array.isArray(made) && made.length === 2, MOVE_WORDS.notSealed);
      const records = {};
      ROLES.forEach((role, i) => {
        const record = made[i]?.record, publicKey = made[i]?.key?.publicKey;
        try { validateVaultRecord(record, role); } catch { fail(MOVE_WORDS.notSealed); }
        assert(record.binding.networkId === networkId && record.binding.name === name && record.binding.publicKey === publicKey, MOVE_WORDS.notSealed);
        records[role] = record;
      });
      assert(records.signin.binding.publicKey !== records.spend.binding.publicKey, MOVE_WORDS.notSealed);
      assert(!account.devices.some(d => d.public_key === records.signin.binding.publicKey || d.public_key === records.spend.binding.publicKey), MOVE_WORDS.notSealed);
      // Each record's private key from the page (opened again, or opened already by the device's second answer at sealing),
      // and what it gives signs for the record's public key. The request is signed with those keys, so that it exists only
      // if they do.
      for (const role of ROLES) { const one = await open(records[role]); opened.push(one); await signsFor(one, records[role].binding.publicKey); }
      const request = await moveRequest({ networkId, account, signin: { publicKey: records.signin.binding.publicKey, privateKey: opened[0].privateKey }, spend: { publicKey: records.spend.binding.publicKey, privateKey: opened[1].privateKey }, now });
      return await underLock(locks, networkId, name, async () => {
        const note = ready();
        // Kept aside before anything is shown: the bound, the records, the note last. A page closed between them keeps
        // records the note does not name, which nothing showed and the next call drops.
        let written = false;
        try {
          written = true;
          const texts = { signin: JSON.stringify(records.signin), spend: JSON.stringify(records.spend) };
          writeBound(storage, slots, moveWindowEnd(request));
          storage.setItem(slots.active.signin, texts.signin); storage.setItem(slots.active.spend, texts.spend);
          writeNote(storage, slots, { active: request, held: note?.held ?? null });
          // Read back before anything is shown: a storage that takes a write and does not keep it makes no request.
          let back = null; try { back = readNote(storage, slots)?.active ?? null; } catch { back = null; }
          const bound = readBound(storage, slots);
          assert(ROLES.every(role => storage.getItem(slots.active[role]) === texts[role]) && back && moveRequestText(back) === moveRequestText(request) && bound !== null && bound >= moveWindowEnd(request), MOVE_WORDS.notKept);
          written = false;
          return shown(request);
        } finally {
          if (written) { try { dropPosition(storage, slots, 'active'); writeNote(storage, slots, { active: null, held: note?.held ?? null }); finishIfEmpty(storage, slots); } catch { /* the next call drops them */ } }
        }
      });
    } finally {
      for (const one of [...(Array.isArray(made) ? made : []).map(m => m?.key), ...opened]) if (one) { forgetSecret(one.secret); one.privateKey = null; }
    }
  }

  /// Puts in place, role by role, each key of a position that the account holds: from its sound record, or found in place
  /// already (a page closed half way through settling). Only when every key the account holds from it is in place does
  /// everything of the move go (another request of this browser can no longer land: the replacement moved the version on).
  /// A key the account holds whose record is missing or cannot be read here keeps everything as it is, and is said
  /// ('damaged', `landed`, `unplaced`): a later wallet may read the record, and nothing is deleted. Null when the account
  /// holds neither key.
  function settleIfLanded(storage, networkId, name, slots, note, which, account) {
    const request = note[which], live = vaultSlots(networkId, name), settled = [], unplaced = [];
    for (const role of ROLES) {
      if (!holds(account, request[role].publicKey, role)) continue;
      const record = soundRecord(storage, slots[which][role], role, request[role].publicKey, networkId, name);
      if (record) { storage.setItem(livePlace(live, role), JSON.stringify(record)); settled.push(role); }
      else if (soundRecord(storage, livePlace(live, role), role, request[role].publicKey, networkId, name)) settled.push(role);
      else unplaced.push(role);
    }
    if (!settled.length && !unplaced.length) return null;
    const others = workingKeys(account).filter(d => d.public_key !== request.signin.publicKey && d.public_key !== request.spend.publicKey).length, withdrawn = which === 'held';
    if (unplaced.length) return { stage: 'damaged', landed: true, settled, unplaced, others, withdrawn };
    dropAll(storage, slots);
    return { stage: settled.length === 2 && others === 0 ? 'settled' : 'mixed', settled, others, withdrawn };
  }
  /// A note this wallet cannot read: which request is whose is not known. Every sound record whose key the account holds in
  /// its role is put in place; nothing else is deleted unless the verified chain's time `now` is past the bound (boundOf), and
  /// with no bound at all nothing ever is.
  function damagedNote(storage, networkId, name, slots, account, now) {
    const live = vaultSlots(networkId, name), settled = [];
    for (const which of POSITIONS) for (const role of ROLES) {
      const record = soundRecord(storage, slots[which][role], role, null, networkId, name);
      if (record && holds(account, record.binding.publicKey, role)) { storage.setItem(livePlace(live, role), JSON.stringify(record)); if (!settled.includes(role)) settled.push(role); }
    }
    settled.sort();
    const until = boundOf(storage, slots);
    if (until !== null && BigInt(now) >= until) { dropAll(storage, slots); return { stage: 'forgotten', damaged: true, settled }; }
    return { stage: 'damaged', settled, until };
  }
  /// Steps 1 and 4 after the page was closed, or on any later look, on the new device. With a verified `state`: keys the
  /// account holds are put in place ('settled', or 'mixed' when the account holds other payment or login keys too, or only
  /// one of the two); keys of a request that can no longer land are forgotten ('expired'); a request that can still be
  /// used is given again ('waiting', with its text and code); one that expired but could still land is kept and not shown
  /// ('closing'), as is one made before the account's keys changed ('stale'). Without a state nothing is changed ('unread').
  async function resumeMove({ storage, networkId, name, state = null, now = state ? elapsedOf(state) : undefined, locks = defaultLocks }) {
    needLocks(locks);
    const slots = moveSlots(networkId, name);
    return underLock(locks, networkId, name, async () => {
      const account = state ? accountIn(state, name, false) : null, readable = Boolean(account) && now !== undefined;
      let note; try { note = readNote(storage, slots); } catch { return readable ? damagedNote(storage, networkId, name, slots, account, now) : { stage: 'damaged' }; }
      tidy(storage, slots, note); finishIfEmpty(storage, slots);
      if (!note) return { stage: 'none' };
      if (!readable) {
        // Shown again only while both of its records are there and sound: without them, a move on it would land on keys
        // nobody holds.
        const sound = note.active && recordsAt(storage, slots, 'active', note.active, networkId, name);
        return { stage: 'unread', withdrawn: Boolean(note.held), ...(sound ? await shown(note.active) : note.active ? { damaged: true } : {}) };
      }
      for (const which of POSITIONS) if (note[which]) { const done = settleIfLanded(storage, networkId, name, slots, note, which, account); if (done) return done; }
      const at = BigInt(now);
      if (note.held && at >= moveWindowEnd(note.held)) { dropPosition(storage, slots, 'held'); note.held = null; writeNote(storage, slots, note); finishIfEmpty(storage, slots); }
      if (!note.active) return note.held ? { stage: 'withdrawn', until: moveWindowEnd(note.held) } : { stage: 'none' };
      const request = note.active, until = moveWindowEnd(request);
      const forget = stage => { dropPosition(storage, slots, 'active'); note.active = null; writeNote(storage, slots, note); finishIfEmpty(storage, slots); return { stage }; };
      if (!recordsAt(storage, slots, 'active', request, networkId, name)) return at >= until ? forget('expired') : { stage: 'damaged', until };
      if (at >= until) return forget('expired');
      if (at >= BigInt(request.expires)) return { stage: 'closing', until };
      if (String(account.auth_epoch) !== request.authEpoch) return { stage: 'stale', until };
      return { stage: 'waiting', ...await shown(request) };
    });
  }
  /// "Withdraw" on the new device. It never forgets keys a verified state shows on the account (those are put in place
  /// instead), and without a verified state it changes nothing. A request that can still land (the old device may have
  /// signed it already: its approvals last ten minutes past the request) is not shown again, but its keys are kept
  /// ("held") until a verified state shows that time passed with the keys still off the account; a new request can be
  /// made meanwhile. Returns { stage: 'withdrawn', until } | { stage: 'forgotten' } | what settling gave | { stage: 'none' }.
  async function withdrawMove({ storage, networkId, name, state = null, now = state ? elapsedOf(state) : undefined, locks = defaultLocks }) {
    needLocks(locks);
    const slots = moveSlots(networkId, name);
    return underLock(locks, networkId, name, async () => {
      let note; try { note = readNote(storage, slots); } catch { note = undefined; }
      if (note !== undefined) { tidy(storage, slots, note); finishIfEmpty(storage, slots); }
      if (note === null) return { stage: 'none' };
      if (note && !note.active) return note.held ? { stage: 'withdrawn', until: moveWindowEnd(note.held) } : { stage: 'none' };
      const account = state ? accountIn(state, name, false) : null;
      assert(account && now !== undefined, MOVE_WORDS.unread);
      // A note that cannot be read: what the account holds is put in place, the rest kept until the bound.
      if (note === undefined) return damagedNote(storage, networkId, name, slots, account, now);
      for (const which of POSITIONS) if (note[which]) { const done = settleIfLanded(storage, networkId, name, slots, note, which, account); if (done) return { ...done, refused: true }; }
      const at = BigInt(now), request = note.active, records = recordsAt(storage, slots, 'active', request, networkId, name);
      if (at >= moveWindowEnd(request)) { dropPosition(storage, slots, 'active'); note.active = null; writeNote(storage, slots, note); finishIfEmpty(storage, slots); return { stage: 'forgotten' }; }
      // A record missing or unreadable while the request could still land: kept as it is, as resumeMove keeps it.
      if (!records) return { stage: 'damaged', until: moveWindowEnd(request) };
      if (note.held) {
        const until = moveWindowEnd(note.held);
        if (at < until) throw Object.assign(new Error(MOVE_WORDS.heldBusy(dateOf(state, until).toLocaleString())), { until });
        dropPosition(storage, slots, 'held'); note.held = null; writeNote(storage, slots, note);
      }
      // Copied to the held place, then the note, then the active place emptied: a page closed between any two keeps one
      // copy the note names, and the other is dropped as a copy (tidy).
      storage.setItem(slots.held.signin, JSON.stringify(records.signin)); storage.setItem(slots.held.spend, JSON.stringify(records.spend));
      writeNote(storage, slots, { active: null, held: request });
      dropPosition(storage, slots, 'active');
      return { stage: 'withdrawn', until: moveWindowEnd(request) };
    });
  }

  // ---------------------------------------------------------------- the old device
  /// Step 2: the request pasted on the old device, checked (MOVE_CHECKS, all but the code) against the account it has open,
  /// read just now. `now`: the chain's time of that state; `waitsNow`: its clock of the waits. Returns { request, shown }:
  /// `shown` is what the page may show, and holds neither the code nor anything it can be read from.
  async function reviewMove({ text, networkId, account, security, now, waitsNow, feeMicros }) {
    assert(isDecimal(String(feeMicros)), 'The network fee is required.');
    const request = checkMoveRequest(readMoveRequest(text), { networkId, account, now });
    accountReady({ account, security, waitsNow, feeMicros });
    await verifyMoveRequest(request, { security: sec, cryptoImpl });
    return { request, shown: Object.freeze({ account: account.name, removes: workingKeys(account).length, keeps: account.devices.filter(d => sec.roleOf(d) === 'recover').length,
      cancelsPayments: security.pending_payments.length, cancelsLimit: Boolean(security.pending_limit), expires: request.expires, feeMicros: String(feeMicros) }) };
  }
  /// The replacement of a move: the root replacement that replaces a stolen payment key (security-flows.mjs,
  /// buildReplaceSpend), approved by this browser's payment key and one recovery key and in force at once, except that the
  /// new payment key and login key come with the other device's acceptances instead of being made here. Every other payment
  /// and login key goes, this browser's included; every recovery key and the policy stay. The bytes are those the engine
  /// took (client-v4/device-move.fixture.json). It is closed in here, and reached only through buildMove below, after the
  /// request and the code were checked: no page can build a move without the code.
  async function replacement({ networkId, account, security, spend, recovery, request, now }) {
    assert(spend && flows.roleOf(account, spend.publicKey) === 'spend', 'Moving your account needs the payment key of this browser.');
    assert(recovery, 'Moving your account needs one of your recovery keys as well: your recovery words or the sheet of your Recovery Kit.');
    assert(flows.roleOf(account, recovery.publicKey) === 'recover', `This recovery key does not belong to @${account.name}. Check it and try again.`);
    const keys = ROLES.map(role => ({ public_key: request[role].publicKey, role, proof: request[role].proof }));
    for (const d of account.devices) if (sec.roleOf(d) === 'recover') keys.push(sec.keepKey(d.public_key, 'recover'));
    return flows.buildRoot({ networkId, account, security, operation: sec.operations.replace(keys, security.policy), approvers: [spend, recovery], submitter: spend, expiresElapsedMicros: BigInt(now) + APPROVAL_LIFETIME_MICROS });
  }
  /// Step 3: everything of reviewMove again, on the state read just before signing, and the code; then the replacement,
  /// approved by `spend` (this browser's payment key, opened) and `recovery` (a recovery key of the account). A wrong code,
  /// or one proof only, and nothing is signed.
  async function buildMove({ networkId, request, typedCode, account, security, spend, recovery, now, waitsNow, feeMicros }) {
    assert(isDecimal(String(feeMicros)), 'The network fee is required.');
    const checked = checkMoveRequest(readMoveRequest(moveRequestText(request)), { networkId, account, now });
    accountReady({ account, security, waitsNow, feeMicros });
    await verifyMoveRequest(checked, { security: sec, cryptoImpl });
    await checkCode(checked, typedCode, cryptoImpl);
    return { ...await replacement({ networkId, account, security, spend, recovery, request: checked, now }), request: checked };
  }
  const readSent = (storage, slots) => {
    const raw = storage.getItem(slots.sent); if (raw === null) return null;
    let sent; try { sent = JSON.parse(raw); } catch { return false; }
    if (!plain(sent) || Object.keys(sent).sort().join(',') !== 'approvalsExpire,request,signedVersion,version' || sent.version !== 1 || !isDecimal(sent.signedVersion) || !isDecimal(sent.approvalsExpire)) return false;
    try { return { ...sent, request: readMoveRequest(JSON.stringify(sent.request)) }; } catch { return false; }
  };
  /// Just before the old device sends the move (the page's beforeSubmit): a note of what it signed, so that a page closed
  /// meanwhile forgets its keys once the move landed. Refused while an earlier move from this browser is undecided.
  async function rememberMove({ storage, networkId, name, request, built, locks = defaultLocks }) {
    needLocks(locks);
    const slots = moveSlots(networkId, name);
    return underLock(locks, networkId, name, async () => {
      assert(storage.getItem(slots.sent) === null, MOVE_WORDS.sentWaiting);
      storage.setItem(slots.sent, JSON.stringify({ version: 1, request: canonical(request), signedVersion: String(built.version), approvalsExpire: String(built.payload.expires_elapsed_micros) }));
    });
  }
  /// What this browser keeps of the account's keys, and forgets after a move: its login and payment records, keys kept
  /// aside, a login it asked of another device, a swap of the device lock left half way, and the notes of a move.
  function forgetKeys(storage, networkId, name) {
    const live = vaultSlots(networkId, name), places = lockPlaces(networkId, name), slots = moveSlots(networkId, name);
    const keys = [live.login, live.spend, live.nextLogin, live.nextSpend, live.nextNote, live.request, places.login, places.spend, slots.sent, slots.note, ...Object.values(slots.active), ...Object.values(slots.held)];
    const removed = keys.filter(key => storage.getItem(key) !== null);
    for (const key of removed) storage.removeItem(key);
    return removed;
  }
  /// The public keys of every key record this browser keeps for the account (what forgetKeys removes of keys); null when one
  /// of them cannot be read, so that nothing is decided on a key that is not known.
  function keptKeys(storage, networkId, name) {
    const live = vaultSlots(networkId, name), places = lockPlaces(networkId, name), keys = [];
    for (const place of [live.login, live.spend, live.nextLogin, live.nextSpend, places.login, places.spend, live.request]) {
      const raw = storage.getItem(place); if (raw === null) continue;
      let value; try { value = JSON.parse(raw); } catch { return null; }
      const key = (place === live.request ? value?.record : value)?.binding?.publicKey;
      if (typeof key !== 'string' || !HEX32.test(key)) return null;
      keys.push(key);
    }
    return keys;
  }
  /// Whether this browser may forget its keys after a move: the account holds exactly the request's payment and login keys;
  /// or it holds one of them, or both and others (the new device changed its keys since), and none of this browser's keys.
  function mayForget(storage, networkId, name, account, request) {
    const shape = shapeOf(account, request);
    if (shape === 'exact') return true;
    if (shape !== 'mixed') return false;
    const own = keptKeys(storage, networkId, name);
    return own !== null && !own.some(key => account.devices.some(d => d.public_key === key));
  }
  /// Step 4 on the old device, and after its page was closed. With a verified `state`: 'forgotten' once the account holds
  /// exactly the request's payment and login keys, or holds one of them and none of this browser's keys; 'mixed' (nothing
  /// forgotten) when it holds one of them and a key of this browser too; 'void' (the note goes, the keys stay) once the move
  /// can no longer land (its approvals expired, or the security version moved past the one it signed); else 'waiting'.
  /// Without a state: 'unread', nothing changed.
  async function oldDeviceStatus({ storage, networkId, name, state = null, now = state ? elapsedOf(state) : undefined, locks = defaultLocks }) {
    needLocks(locks);
    const slots = moveSlots(networkId, name);
    return underLock(locks, networkId, name, async () => {
      const sent = readSent(storage, slots);
      if (sent === null) return { stage: 'none' };
      if (sent === false) return { stage: 'damaged' };
      const account = state ? accountIn(state, name, false) : null;
      if (!account || now === undefined || String(account.id) !== sent.request.accountId) return { stage: 'unread' };
      if (shapeOf(account, sent.request) !== 'absent') return mayForget(storage, networkId, name, account, sent.request) ? { stage: 'forgotten', removed: forgetKeys(storage, networkId, name) } : { stage: 'mixed' };
      const row = Array.isArray(state.security) ? sec.securityOf(state, account.id) : null;
      if (BigInt(now) >= BigInt(sent.approvalsExpire) || (row && BigInt(row.version) > BigInt(sent.signedVersion))) { storage.removeItem(slots.sent); return { stage: 'void' }; }
      return { stage: 'waiting' };
    });
  }
  /// Forgets this browser's keys of the account after a move, and only once the verified `state` shows what
  /// oldDeviceStatus forgets on (mayForget). Before that it refuses, and keeps everything.
  async function forgetOldDevice({ storage, networkId, name, state, request, locks = defaultLocks }) {
    needLocks(locks);
    const account = accountIn(state, name), checked = readMoveRequest(moveRequestText(request));
    return underLock(locks, networkId, name, async () => {
      const shape = shapeOf(account, checked);
      assert(String(account.id) === checked.accountId && mayForget(storage, networkId, name, account, checked), shape === 'mixed' ? MOVE_WORDS.mixedKeep : MOVE_WORDS.notMovedYet);
      return forgetKeys(storage, networkId, name);
    });
  }

  return { moveRequest, prepareMove, resumeMove, withdrawMove, reviewMove, checkCode: (request, typed) => checkCode(request, typed, cryptoImpl), buildMove, rememberMove, oldDeviceStatus, forgetOldDevice, shapeOf };
}
