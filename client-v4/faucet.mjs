// The faucet of a Time TEST network: gives a fixed amount of test time to developers who ask,
// and sponsors the registration of a new account for a developer who has none.
//
// Nobody holds any time when a network starts, so on a test network somebody has to send a
// developer the first seconds. This service is that somebody. It must never run on a network
// whose time has value: it refuses to start unless its config says `test_network: true`, names
// the network id, that id is the one of the trust manifest and of the state it reads with a
// proof, and the chain id is one of the test chains this file knows (`TEST_CHAINS`).
//
// What it holds: one spend key of the faucet's own account. The account has adopted the security
// rules (v5/README.md, "Account security"), so that key pays at once only within the daily limit
// set on the chain. The service reads the account's proven state before it starts and before
// every grant, and gives nothing when the key is not a spend key of the account, when it holds
// more power than that, when the limit on the chain is above what the config allows, or when a
// payment or a raise of the limit is waiting on the account. The faucet makes neither, so one
// that waits means the key is in someone else's hands: the faucet stops, says so, freezes its
// own account and cancels what waits (see `guard`).
//
// How a grant is made, and what each step survives:
//
// 1. The request is checked against the limits and recorded (`reserved`), in one transaction.
// 2. The action is signed with the account's next free nonce, and its bytes, hash and nonce are
//    written to the store (`signed`) before anything is sent. From here on these are the only
//    bytes this request will ever have: a grant is never signed a second time.
// 3. The bytes are sent to the node. From this moment the grant counts against the limits,
//    WHATEVER THE NODE ANSWERS: "refused" is the node's word, and a node that says it and keeps
//    the bytes can still get them into a block. If the node takes them, the grant is `submitted`.
//    If it refuses them, or does not answer, or the process stops, the grant stays `signed`.
// 4. A timer (and every start) settles what is open. Bytes whose nonce the chain has not used
//    and that the node did not answer for are sent again, the same bytes. Bytes the node refused
//    are sent one more time, and only when they stand at the head of the line and three blocks
//    have passed since the refusal; refused there again, they are `withdrawn` with everything
//    queued behind them. (If that one sending gets no answer, or the process stops before its
//    answer is recorded, the same bytes go out again: harmless, the chain takes them once.)
//    Bytes whose nonce the proven state shows as used are
//    looked up on the node by hash: found, the grant is `included`; not found for a while,
//    another action used the nonce and the grant is `superseded`; if the node cannot tell for
//    hours, it is `unconfirmed`. Withdrawn and superseded grants are still looked up for some
//    hours, in case a block took them after all.
//
// Only a request that was never sent (`cancelled`) does not count. Everything else counts for
// 24 hours, paid or not: when in doubt the faucet gives less, never more. The 24 hours are
// counted in the block time of proven states, not on this machine's clock. Requests are handled
// one at a time from the proof to the node's answer, so two requests never get the same nonce.
import http from 'node:http';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { readFileSync, constants as fsConstants } from 'node:fs';
import { open as openFile, unlink } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import './time-sdk.js';
import { roleOf, securityOf, allowance, frozen, KIND, payloads, signSecurityAction } from './account-security.mjs';
import { ApiError, createRateLimiter, createStateReader, normalIp, carriesBody } from './api.mjs';
import { IndexerError, plainText } from './indexer.mjs';
import { withTimeout } from './security-watch-service.mjs';

const SDK = globalThis.TimeSDK;
const MAX_U64 = 18446744073709551615n;
export const MAX_BODY_BYTES = 1024;
export const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;
const MAX_URL_LENGTH = 512;
/// The chains a faucet may serve: the prefixes of test chain ids. Today that is the one family
/// the installed verifier accepts at all. A network whose time has value gets another chain id,
/// and nothing in a config file can add it here.
export const TEST_CHAINS = Object.freeze(['time-devnet-v4-']);
export const isTestChain = (chainId) => typeof chainId === 'string' && TEST_CHAINS.some((prefix) => chainId.startsWith(prefix) && chainId.length > prefix.length);
/// A registration consent must still be valid this long after the state it is checked against:
/// nodes admit what carries an expiry only if it is valid 30 seconds after the last block.
const EXPIRY_MARGIN_MICROS = 45_000_000n;
/// Records of grants are kept this long, then removed. Who asked for one (a keyed hash of the caller's address
/// group, under a key that is not in the store) is kept only as long as a limit counts it: 24 hours of block time,
/// and then emptied.
const KEEP_MS = 30 * DAY_MS;
/// How long what was removed from the store may stay in its log of writes (the -wal file) before that log is copied
/// into the store and emptied (see `prune`).
const SCRUB_MS = 10 * 60_000;
/// How many times the limits of one address (an IPv4 address or an IPv6 /56) the IPv6 /48 around it has, unless the
/// config says otherwise; and how many times the registrations of one address all callers together get in 24 hours.
export const NETWORK_FACTOR = 3, REGISTRATIONS_FACTOR = 10;
/// The refusals of the node for a sponsored registration that no sending will ever change: an account holds the key,
/// or a commitment of the key that has not expired waits (registration/src/lib.rs, `commit`; the node's log is the
/// error's own text, v5/src/app.rs `check_batch`). Such bytes are withdrawn at once (see signAndSend).
const SETTLED_REFUSALS = Object.freeze({ 'registration key already belongs to an account': 'already_registered', 'unexpired registration commitment already exists': 'already_committed' });
/// How long the body of a request may take to arrive (it is at most MAX_BODY_BYTES).
const BODY_MS = 5000;
/// The page's address with an account for its field, as the page itself accepts one (web-v4/faucet/app.js): a number
/// or a name, with or without "@" (written "%40" too), in either case, and nothing else.
const PREFILL = /^\/\?account=(?:@|%40)?[A-Za-z0-9_]{1,20}$/;
const PAGE_FILES = { '/': ['index.html', 'text/html; charset=utf-8'], '/app.js': ['app.js', 'text/javascript; charset=utf-8'], '/styles.css': ['styles.css', 'text/css; charset=utf-8'],
  // The menu of the public networks that every page of the project carries (web-v4/shared/network-menu.js).
  '/web-v4/shared/network-menu.js': ['../shared/network-menu.js', 'text/javascript; charset=utf-8'], '/web-v4/shared/network-menu.css': ['../shared/network-menu.css', 'text/css; charset=utf-8'] };
const bad = (code, message) => { throw new ApiError(400, code, message); };
const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex').toUpperCase();

/// The key a caller is limited under: its IPv4 address, or its IPv6 /56 (what one subscriber is
/// commonly given; per address, one subscriber would be a great many callers).
export function callerKey(address) {
  const ip = normalIp(address);
  if (ip === null) return 'unknown';
  if (!ip.includes(':')) return ip;
  const groups = ip.split(':');
  return `${groups[0]}:${groups[1]}:${groups[2]}:${(parseInt(groups[3], 16) & 0xff00).toString(16)}::/56`;
}
/// The network a caller is also counted under: the IPv6 /48 around its /56 (what one site is commonly given), so
/// that one network does not count as 256 callers. Null for IPv4, whose address is the caller. Takes an address, or
/// a caller key as `callerKey` gives it.
export function networkOf(address) {
  const key = /::\/56$/.test(String(address)) ? String(address) : callerKey(address);
  const match = /^([0-9a-f]+):([0-9a-f]+):([0-9a-f]+):[0-9a-f]+::\/56$/.exec(key);
  return match ? `${match[1]}:${match[2]}:${match[3]}::/48` : null;
}

/// Reads the spend key from its file: 64 hexadecimal characters, the 32-byte Ed25519 seed, and
/// nothing else but a final line break. Returns the public key (hex) and a private key that
/// cannot be exported. No error names what the file holds.
export async function readSpendKey(file) {
  let text;
  try { text = readFileSync(file, 'utf8'); } catch { throw new Error('The key file could not be read'); }
  const match = /^([0-9a-f]{64})\r?\n?$/.exec(text);
  if (!match) throw new Error('The key file holds one line: the 32-byte Ed25519 seed of the spend key as 64 lower-case hexadecimal characters');
  const der = SDK.hexToBytes(`302e020100300506032b657004220420${match[1]}`);
  try {
    const exportable = await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, true, ['sign']);
    const publicKey = SDK.bytesToHex(new Uint8Array(Buffer.from((await crypto.subtle.exportKey('jwk', exportable)).x, 'base64url')));
    const privateKey = await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign']);
    return { publicKey, privateKey };
  } catch { throw new Error('The key file does not hold a usable Ed25519 key'); } finally { der.fill(0); }
}

/// Looks an action up on the node by its hash (`/tx` of the CometBFT RPC, which needs the node's
/// transaction index). Returns `{ height, tx }` (the bytes in base64), or null when the node says
/// it has no such transaction. Throws when the node cannot tell.
/// The address is the operator's; nothing a caller sends chooses it.
export function createTxLookup(origin, { fetcher = globalThis.fetch, timeoutMs = 10000 } = {}) {
  const base = new URL(origin);
  return async (hash) => {
    if (!/^[0-9A-F]{64}$/.test(hash)) throw new Error('A hash is 64 hexadecimal characters');
    const url = new URL('/tx', base);
    url.searchParams.set('hash', `0x${hash}`);
    let answer;
    try {
      const response = await fetcher(url, { redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
      const text = await response.text();
      if (text.length > 4 * 1024 * 1024) throw new Error('too large');
      answer = JSON.parse(text);
    } catch { throw new IndexerError('RPC_UNAVAILABLE', 'The RPC could not be asked for the action'); }
    if (answer?.result && typeof answer.result.tx === 'string' && /^[1-9][0-9]*$/.test(String(answer.result.height))) {
      if (Number(answer.result.tx_result?.code ?? 0) !== 0) throw new IndexerError('RPC_INVALID', 'The node lists the action with a failed result');
      return { height: String(answer.result.height), tx: answer.result.tx };
    }
    if (/not found/i.test(String(answer?.error?.data ?? '') + String(answer?.error?.message ?? ''))) return null;
    throw new IndexerError('RPC_REFUSED', 'The RPC cannot look actions up by hash (is its transaction index on?)');
  };
}

// ------------------------------------------------------------------ the store
/// Statuses of bytes that may still be sent: they wait for a signature, the node, or a block.
const SENDABLE = ['signed', 'submitted'];
/// Version 5 (2026-11-24) keeps who asked as a keyed hash of the caller's address group, with the hash of its IPv6
/// /48 beside it, empties both after 24 hours, and holds NOT the key of those hashes (`loadCallerKey`). Version 4 kept
/// the key in the store, so that the file alone gave back who asked (every IPv4 address can be tried in seconds);
/// version 3 kept the address groups themselves for 30 days. A store of either is moved to version 5 in place when it
/// is opened (see openStore).
const SCHEMA = '5', MOVABLE_SCHEMAS = Object.freeze(['3', '4']);
/// What an existing file must hold to be this faucet's store, or why it is not. Nothing is written
/// to find out: a file of another version, network or account is refused as it is.
function storeMismatch(db, networkId, account) {
  let held;
  try {
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((row) => row.name);
    if (tables.length === 0) return null; // a new file
    held = tables.includes('meta') ? Object.fromEntries(db.prepare('SELECT key, value FROM meta').all().map((row) => [row.key, row.value])) : {};
  } catch { return 'This data directory holds a file that is not a store of the faucet; use a new one'; }
  if (held.schema !== SCHEMA && !MOVABLE_SCHEMAS.includes(held.schema)) return 'This data directory holds the store of another version of the faucet; use a new one (see the README before you do)';
  if (held.network_id !== networkId) return 'This data directory belongs to another network; use a new one';
  if (held.account !== account) return 'This data directory belongs to another faucet account; use a new one';
  return null;
}
/// Opens (or creates) the faucet's store. The file belongs to one network and one faucet account
/// for good. Every write reaches the disk before the call returns (`synchronous=FULL`): a grant
/// that was recorded is still recorded after a power cut. (`synchronous` is for tests, which make
/// hundreds of grants and would otherwise keep the disk busy under every other test.)
///
/// `created_at` of a grant is block time (of the proven state the grant was made on), in
/// milliseconds: the 24 hours of the limits are counted in it. The other times are this
/// machine's clock and only pace the work.
///
/// Who asked is never kept as an address. `caller` holds a keyed hash (HMAC-SHA-256) of the caller's address group
/// (`callerKey`), `network` one of its IPv6 /48 (`networkOf`; null for IPv4). Both fields are emptied once the
/// request is 24 hours old: no limit looks further back.
///
/// The key of the hashes (`callerKey`, 32 bytes) is given by the service and is never written to the store
/// (`loadCallerKey` says where it is kept). The store keeps only a check of it (`caller_key_check`, a keyed hash of a
/// fixed text, which tells nothing about the key): hashes made under another key match nobody, so when the key is not
/// the one of the check (it was lost with the memory that held it, or there is none) they are removed at once, and
/// the counts per caller start afresh (`opened.forgotten`). The counts that know no caller (per account, per key and
/// the totals of the day) are unchanged by any of this.
///
/// What is removed does not stay in the file: `secure_delete` overwrites deleted records and emptied fields with
/// zeros, and the log of writes (-wal) is copied into the store and emptied within SCRUB_MS of a removal (`prune`).
///
/// `opened` says what the opening did: `moved` (the version a store was moved from, or null), `forgotten`, and
/// `rewritten` (true when the store was written anew after a move, false when that failed and waits for the next
/// start, null when there was nothing to do).
export function openFaucetStore({ filename, networkId, account, synchronous = 'FULL', callerKey = randomBytes(32) }) {
  if (!['FULL', 'NORMAL', 'OFF'].includes(synchronous)) throw new Error('synchronous is FULL, NORMAL or OFF');
  if (!Buffer.isBuffer(callerKey) || callerKey.length !== 32) throw new Error('callerKey is 32 bytes');
  const db = new DatabaseSync(filename);
  const mismatch = storeMismatch(db, networkId, account);
  if (mismatch) { db.close(); throw new Error(mismatch); }
  try { return openStore(db, { networkId, account, synchronous, callerKey }); } catch (error) { try { db.close(); } catch { /* closed already */ } throw error; }
}

/// The key of the hashes of who asked (openFaucetStore). It is never in the store. Without `file` it is made at
/// every start and held in memory only. With `file` it is also kept in that file, so that a restart of the service
/// counts the same callers as before: the file belongs on a file system in memory (tmpfs: /dev/shm, or a directory
/// of the faucet's user under /run), on no disk and in no backup, and it is emptied by a reboot, after which the
/// faucet makes a new key and the counts per caller start afresh.
/// - The file is read without following a link, and used only if it is a plain file of this process's user (any
///   user's, for root) that no other user may read, holding 64 lower-case hexadecimal characters and nothing else
///   but a final line break.
/// - A file that is not so is removed and made anew, when it can be; one that is missing is made (mode 600, never
///   over an existing file).
/// - When nothing of that works, the key is held in memory only and `problem` says why. No message says what the
///   file holds.
/// Returns { key, source: 'kept' (read from the file) | 'new' (made and written to it) | 'memory', problem }, and for
/// 'new' `replaced`: what was wrong with the file it replaced, or null.
export async function loadCallerKey(file) {
  if (file === undefined || file === null) return { key: randomBytes(32), source: 'memory', problem: null };
  const NOFOLLOW = fsConstants.O_NOFOLLOW ?? 0;
  const ours = (info) => typeof process.getuid !== 'function' || ((process.getuid() === 0 || info.uid === process.getuid()) && (info.mode & 0o077) === 0);
  let found = null;
  try {
    const handle = await openFile(file, fsConstants.O_RDONLY | NOFOLLOW);
    try {
      const info = await handle.stat();
      if (!info.isFile()) found = { bad: 'is not a plain file' };
      else if (!ours(info)) found = { bad: 'belongs to another user, or other users may read it' };
      else {
        const match = info.size <= 128 ? /^([0-9a-f]{64})\n?$/.exec((await handle.readFile()).toString('latin1')) : null;
        found = match ? { key: Buffer.from(match[1], 'hex') } : { bad: 'does not hold a key' };
      }
    } finally { await handle.close(); }
  } catch (error) {
    if (error.code === 'ELOOP') found = { bad: 'is a link' };
    else if (error.code !== 'ENOENT') return { key: randomBytes(32), source: 'memory', problem: `its file could not be read (${error.code ?? 'error'})` };
  }
  if (found?.key) return { key: found.key, source: 'kept', problem: null };
  if (found?.bad) {
    try { await unlink(file); } catch { return { key: randomBytes(32), source: 'memory', problem: `its file ${found.bad}, and could not be replaced` }; }
  }
  const key = randomBytes(32);
  let handle;
  try { handle = await openFile(file, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | NOFOLLOW, 0o600); } catch (error) {
    return { key, source: 'memory', problem: `its file could not be made (${error.code ?? 'error'})` };
  }
  try { await handle.writeFile(`${key.toString('hex')}\n`); } catch (error) {
    await handle.close().catch(() => {}); await unlink(file).catch(() => {});
    return { key, source: 'memory', problem: `its file could not be written (${error.code ?? 'error'})` };
  }
  await handle.close();
  return { key, source: 'new', problem: null, replaced: found?.bad ?? null };
}
function openStore(db, { networkId, account, synchronous, callerKey }) {
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=${synchronous}; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON;`);
  db.exec(`
    CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS grants (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kind TEXT NOT NULL CHECK(kind IN ('grant', 'registration')),
      recipient TEXT NOT NULL, caller TEXT NOT NULL, network TEXT, amount INTEGER NOT NULL, cost INTEGER NOT NULL, created_at INTEGER NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('reserved', 'signed', 'submitted', 'included', 'withdrawn', 'superseded', 'unconfirmed', 'cancelled')),
      reason TEXT, payload TEXT NOT NULL, nonce TEXT, hash TEXT, raw BLOB, signed_height TEXT,
      attempts INTEGER NOT NULL DEFAULT 0, sent_at INTEGER, accepted INTEGER NOT NULL DEFAULT 0,
      refusal_height TEXT, consumed_at INTEGER, ended_at INTEGER, checked_at INTEGER, settled INTEGER NOT NULL DEFAULT 0, height TEXT);
    CREATE INDEX IF NOT EXISTS grants_recipient ON grants (kind, recipient, created_at);
    CREATE INDEX IF NOT EXISTS grants_caller ON grants (kind, caller, created_at);
    CREATE INDEX IF NOT EXISTS grants_created ON grants (created_at);
    CREATE INDEX IF NOT EXISTS grants_hash ON grants (hash);
    CREATE INDEX IF NOT EXISTS grants_unsettled ON grants (settled) WHERE settled = 0;
    CREATE TABLE IF NOT EXISTS refusals (caller TEXT NOT NULL, at INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS refusals_caller ON refusals (caller, at);
    CREATE TABLE IF NOT EXISTS cancels (
      item TEXT PRIMARY KEY, hash TEXT NOT NULL, raw BLOB NOT NULL, created_at INTEGER NOT NULL, expires TEXT, sent_at INTEGER, attempts INTEGER NOT NULL DEFAULT 0, refusals INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL CHECK(status IN ('signed', 'sent', 'done', 'void'))) WITHOUT ROWID;
  `);
  const metaGet = db.prepare('SELECT value FROM meta WHERE key = ?'), metaPut = db.prepare('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
  for (const [key, value] of [['schema', SCHEMA], ['network_id', networkId], ['account', account]]) if (metaGet.get(key) === undefined) metaPut.run(key, value);
  const hmac = (key, text) => createHmac('sha256', key).update(text).digest('hex').slice(0, 32);
  /// The keyed hash a caller's address group is kept under (null for none).
  const group = (text) => (text === null || text === undefined ? null : hmac(callerKey, String(text)));
  const check = hmac(callerKey, 'time faucet: the check of the key of who asked');
  /// A store of version 4 is moved with the key it held (`previous`, see below): its hashes are kept as the hash under
  /// the new key of the old hash (`carried`), and this run, which holds the old key in memory, counts them for the
  /// caller they are of. The next start no longer can (the old key is gone), and those requests then count for nobody.
  let previous = null;
  const carried = (old) => hmac(callerKey, `version 4:${old}`);
  /// The hashes a caller's address group may be stored under: its own, and, in the run that moved a store of
  /// version 4, its carried one (null otherwise, which matches no row).
  const candidates = (text) => (text === null || text === undefined ? [null, null] : [group(text), previous ? carried(hmac(previous, String(text))) : null]);
  const opened = { moved: null, forgotten: false, rewritten: null };
  const from = metaGet.get('schema').value;
  if (MOVABLE_SCHEMAS.includes(from)) {
    // In one transaction, before anything else is read or written. Version 3 kept the address groups themselves:
    // they are replaced by their hashes, and the /48 of each IPv6 one is added beside it. Version 4 kept its key in
    // the store: its hashes are carried (above), and the key is removed from the store.
    db.exec('BEGIN IMMEDIATE');
    try {
      if (!db.prepare('PRAGMA table_info(grants)').all().some((column) => column.name === 'network')) db.exec('ALTER TABLE grants ADD COLUMN network TEXT');
      const old = from === '4' ? metaGet.get('caller_key')?.value ?? null : null;
      if (from === '4' && old !== null && /^[0-9a-f]{64}$/.test(old)) previous = Buffer.from(old, 'hex');
      // What a stored value becomes: an address group of version 3 its hash, a hash of version 4 its carried hash (or
      // nothing, if the old key cannot be read), an emptied field stays empty.
      const move = (value) => (!value ? null : from === '3' ? group(value) : previous ? carried(value) : null);
      const rewrite = db.prepare('UPDATE grants SET caller = ?, network = ? WHERE id = ?');
      for (const row of db.prepare('SELECT id, caller, network FROM grants').all()) rewrite.run(move(row.caller) ?? '', from === '3' ? group(networkOf(row.caller)) : move(row.network), row.id);
      const refusals = db.prepare('UPDATE refusals SET caller = ? WHERE rowid = ?');
      for (const row of db.prepare('SELECT rowid, caller FROM refusals').all()) refusals.run(move(row.caller) ?? '', row.rowid);
      db.prepare('DELETE FROM meta WHERE key = ?').run('caller_key');
      metaPut.run('caller_key_check', check);
      metaPut.run('rewrite_pending', from);
      metaPut.run('schema', SCHEMA);
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); throw error; }
    opened.moved = from;
  } else if (metaGet.get('caller_key_check')?.value !== check) {
    // The hashes in the store were made under another key, or the store is new: whatever they are, they match nobody.
    db.exec('BEGIN IMMEDIATE');
    try {
      const emptied = db.prepare("UPDATE grants SET caller = '', network = NULL WHERE caller <> '' OR network IS NOT NULL").run().changes + db.prepare('DELETE FROM refusals').run().changes;
      metaPut.run('caller_key_check', check);
      db.exec('COMMIT');
      opened.forgotten = emptied > 0;
    } catch (error) { db.exec('ROLLBACK'); throw error; }
    if (opened.forgotten) db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  }
  // After a move nothing of the version before stays in the file: the old key and the old values were overwritten
  // with zeros when they were replaced (secure_delete); the store is written anew from what it holds now (VACUUM,
  // which also drops what the version before had freed without overwriting it); and its log of writes is copied into
  // it and emptied. Until that has worked (a full disk), every start tries it again (`opened.rewritten`).
  if (metaGet.get('rewrite_pending')) {
    try {
      db.exec('PRAGMA temp_store=MEMORY; VACUUM;');
      db.prepare('DELETE FROM meta WHERE key = ?').run('rewrite_pending');
      db.exec('PRAGMA wal_checkpoint(TRUNCATE);');
      opened.rewritten = true;
    } catch { opened.rewritten = false; }
  }
  db.exec('CREATE INDEX IF NOT EXISTS grants_network ON grants (kind, network, created_at) WHERE network IS NOT NULL');
  const s = {
    insert: db.prepare("INSERT INTO grants (kind, recipient, caller, network, amount, cost, created_at, status, payload) VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved', ?)"),
    byRecipient: db.prepare("SELECT COUNT(*) AS n, MIN(created_at) AS oldest FROM grants WHERE kind = ? AND recipient = ? AND created_at > ? AND status <> 'cancelled'"),
    byCaller: db.prepare("SELECT COUNT(*) AS n, MIN(created_at) AS oldest FROM grants WHERE kind = ? AND caller IN (?, ?) AND created_at > ? AND status <> 'cancelled'"),
    byNetwork: db.prepare("SELECT COUNT(*) AS n, MIN(created_at) AS oldest FROM grants WHERE kind = ? AND network IN (?, ?) AND created_at > ? AND status <> 'cancelled'"),
    ofKind: db.prepare("SELECT COUNT(*) AS n, MIN(created_at) AS oldest FROM grants WHERE kind = ? AND created_at > ? AND status <> 'cancelled'"),
    total: db.prepare("SELECT COALESCE(SUM(cost), 0) AS used, MIN(created_at) AS oldest FROM grants WHERE created_at > ? AND status <> 'cancelled'"),
    recent: db.prepare("SELECT * FROM grants WHERE kind = ? AND recipient = ? AND created_at > ? AND status <> 'cancelled' ORDER BY id DESC LIMIT 5"),
    newest: db.prepare('SELECT MAX(created_at) AS at FROM grants'),
    open: db.prepare('SELECT * FROM grants WHERE settled = 0 ORDER BY id'),
    highestNonce: db.prepare('SELECT MAX(CAST(nonce AS INTEGER)) AS n FROM grants WHERE nonce IS NOT NULL'),
    byHash: db.prepare('SELECT * FROM grants WHERE hash = ? ORDER BY id DESC LIMIT 1'),
    byId: db.prepare('SELECT * FROM grants WHERE id = ?'),
    signed: db.prepare("UPDATE grants SET status = 'signed', nonce = ?, hash = ?, raw = ?, signed_height = ? WHERE id = ? AND status = 'reserved'"),
    attempt: db.prepare('UPDATE grants SET attempts = attempts + 1, sent_at = ? WHERE id = ?'),
    accepted: db.prepare("UPDATE grants SET status = 'submitted', accepted = 1, refusal_height = NULL, reason = NULL WHERE id = ? AND status IN ('signed', 'submitted')"),
    refused: db.prepare('UPDATE grants SET refusal_height = COALESCE(refusal_height, ?), reason = ? WHERE id = ?'),
    finish: db.prepare('UPDATE grants SET status = ?, reason = ?, settled = ?, ended_at = COALESCE(ended_at, ?) WHERE id = ?'),
    included: db.prepare("UPDATE grants SET status = 'included', reason = NULL, height = ?, settled = 1 WHERE id = ?"),
    consumed: db.prepare('UPDATE grants SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL'),
    checked: db.prepare('UPDATE grants SET checked_at = ? WHERE id = ?'),
    settle: db.prepare('UPDATE grants SET settled = 1 WHERE id = ?'),
    pruneGrants: db.prepare('DELETE FROM grants WHERE settled = 1 AND created_at < ?'),
    forgetCallers: db.prepare("UPDATE grants SET caller = '', network = NULL WHERE created_at <= ? AND (caller <> '' OR network IS NOT NULL)"),
    sponsored: db.prepare("SELECT COUNT(*) AS n FROM grants WHERE kind = 'registration' AND recipient = ? AND created_at > ? AND status <> 'cancelled'"),
    refusalAdd: db.prepare('INSERT INTO refusals (caller, at) VALUES (?, ?)'),
    refusalCount: db.prepare('SELECT COUNT(*) AS n, MIN(at) AS oldest FROM refusals WHERE caller IN (?, ?) AND at > ?'),
    pruneRefusals: db.prepare('DELETE FROM refusals WHERE at < ?'),
    cancelGet: db.prepare('SELECT * FROM cancels WHERE item = ?'),
    cancelAdd: db.prepare("INSERT INTO cancels (item, hash, raw, created_at, expires, status) VALUES (?, ?, ?, ?, ?, 'signed')"),
    cancelSent: db.prepare("UPDATE cancels SET status = 'sent', attempts = attempts + 1, sent_at = ? WHERE item = ?"),
    cancelStatus: db.prepare('UPDATE cancels SET status = ? WHERE item = ?'),
    cancelRemove: db.prepare("DELETE FROM cancels WHERE item = ? AND status = 'void'"),
    cancelRefused: db.prepare('UPDATE cancels SET refusals = refusals + 1 WHERE item = ?'),
    cancelOpen: db.prepare("SELECT * FROM cancels WHERE status IN ('signed', 'sent') ORDER BY COALESCE(sent_at, 0), created_at"),
    cancelCount: db.prepare("SELECT COUNT(*) AS n FROM cancels WHERE created_at > ? AND item NOT LIKE 'freeze:%'"),
    pruneCancels: db.prepare("DELETE FROM cancels WHERE status NOT IN ('signed', 'sent') AND created_at < ?"),
    kvGet: db.prepare('SELECT value FROM kv WHERE key = ?'),
    kvPut: db.prepare('INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'),
  };
  const transaction = (work) => {
    db.exec('BEGIN IMMEDIATE');
    try { const result = work(); db.exec('COMMIT'); return result; } catch (error) { db.exec('ROLLBACK'); throw error; }
  };
  let closed = false;
  const usageOf = (kind, recipient, given, since) => {
    const who = typeof given === 'string' ? { caller: given, network: networkOf(given) } : given, network = candidates(who.network);
    return { recipient: s.byRecipient.get(kind, recipient, since), caller: s.byCaller.get(kind, ...candidates(who.caller), since), network: network[0] === null ? null : s.byNetwork.get(kind, ...network, since), kind: s.ofKind.get(kind, since), total: s.total.get(since) };
  };
  // When something was last removed, and when the log of writes was last copied into the store and emptied.
  let removedSince = false, scrubbedAt = -Infinity;
  return {
    networkId, account, opened,
    /// The time a new record gets: the block time given, but never before the newest record.
    stamp: (blockMs) => Math.max(blockMs, s.newest.get().at ?? 0),
    /// What counts against the limits of a request of `kind` for `recipient` by `who` ({ caller, network }: the address
    /// group and the /48 as callerKey and networkOf give them, never kept as such) since `since`: the recipient's,
    /// the caller's, its network's (null for IPv4), all requests of the kind, and what was paid in all.
    usage: (kind, recipient, who, since) => usageOf(kind, recipient, who, since),
    recent: (kind, recipient, since) => s.recent.all(kind, recipient, since),
    /// Whether the faucet sponsored the registration of one of `keys` since `since` (block time).
    sponsoredSince: (keys, since) => keys.some((key) => typeof key === 'string' && s.sponsored.get(key, since).n > 0),
    /// Checks the limits and records the request, or neither. `check(usage)` throws to refuse. Who asked is `who`, or
    /// `caller` alone (an address or a caller key: its network is then the one networkOf gives).
    reserve({ kind, recipient, who: given, caller, amount, cost, at, payload, check }) {
      const who = given ?? { caller, network: networkOf(caller) };
      return transaction(() => {
        check(usageOf(kind, recipient, who, at - DAY_MS));
        return Number(s.insert.run(kind, recipient, group(who.caller), group(who.network), amount, cost, at, JSON.stringify(payload)).lastInsertRowid);
      });
    },
    /// Every grant something may still be done for: sent, sent again, or given its last label.
    open: () => s.open.all(),
    /// The highest nonce a grant in the store was signed with (0 with none). Old grants are pruned, so the
    /// service keeps the highest it has seen in `meta` as well.
    highestNonce: () => BigInt(s.highestNonce.get().n ?? 0),
    byHash: (hash) => s.byHash.get(hash) ?? null,
    byId: (id) => s.byId.get(id) ?? null,
    signed(id, { nonce, hash, raw, height }) { if (s.signed.run(nonce, hash, raw, height, id).changes !== 1) throw new Error('The grant is not waiting for a signature'); },
    attempt: (id, at) => { s.attempt.run(at, id); },
    accepted: (id) => { s.accepted.run(id); },
    /// The node refused the bytes at the proven height given. They stay what they are.
    refused: (id, height, reason) => { s.refused.run(height, reason, id); },
    finish: (id, status, reason, settled, at) => { s.finish.run(status, reason, settled, at, id); },
    included: (id, height) => { s.included.run(height, id); },
    consumed: (id, at) => { s.consumed.run(at, id); },
    checked: (id, at) => { s.checked.run(at, id); },
    settle: (id) => { s.settle.run(id); },
    /// Requests an address made that cost a proof and were refused for what they asked.
    refusals: { add: (caller, at) => { s.refusalAdd.run(group(caller), at); }, count: (caller, since) => s.refusalCount.get(...candidates(caller), since) },
    /// The protective actions the faucet signed for its own account: the cancellation of an item that
    /// waits (`payment:<id>`, `limit:<id>`) and the freeze of an incident (`freeze:<count>:<version>`).
    /// One row, and so one signature, per item or incident, for good.
    cancels: {
      get: (item) => s.cancelGet.get(item) ?? null,
      add: (item, hash, raw, at, expires = null) => { s.cancelAdd.run(item, hash, raw, at, expires); },
      sent: (item, at) => { s.cancelSent.run(at, item); },
      refused: (item) => { s.cancelRefused.run(item); },
      status: (item, status) => { s.cancelStatus.run(status, item); },
      /// Only what has become void is ever removed, to make room for its one successor.
      remove: (item) => { s.cancelRemove.run(item); },
      /// Those still being sent, the one sent longest ago first.
      open: () => s.cancelOpen.all(),
      /// Cancellations signed since (a freeze is not counted: the chain itself spaces freezes).
      count: (since) => s.cancelCount.get(since).n,
    },
    /// Removes what no limit and no lookup needs any more: who asked, once the request is 24 hours old (no limit
    /// looks further back: the per-address and per-network counts take 24 hours, the refusals an hour); the rest of
    /// a settled record after 30 days, for its lookup. What is removed is overwritten with zeros (secure_delete) in
    /// the log of writes, and the log is copied into the store and emptied (a TRUNCATE checkpoint) at most every
    /// SCRUB_MS of this machine's clock while something was removed: the old values then stay in neither file.
    prune(blockMs, clockMs) {
      const changes = s.forgetCallers.run(blockMs - DAY_MS).changes + s.pruneGrants.run(blockMs - KEEP_MS).changes + s.pruneRefusals.run(blockMs - HOUR_MS).changes + s.pruneCancels.run(clockMs - KEEP_MS).changes;
      if (changes > 0) removedSince = true;
      if (removedSince && clockMs - scrubbedAt >= SCRUB_MS) {
        try { db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); removedSince = false; scrubbedAt = clockMs; } catch { /* busy: the next pass tries again */ }
      }
    },
    meta: { get: (key) => metaGet.get(key)?.value ?? null, put: (key, value) => { metaPut.run(key, String(value)); } },
    /// Where the light client of the state reader keeps the newest checkpoint it verified.
    checkpointStorage: () => ({ getItem: async (key) => s.kvGet.get(key)?.value ?? null, setItem: async (key, value) => { s.kvPut.run(key, value); } }),
    /// Closing the last connection copies the log of writes into the store and removes it.
    close() { if (!closed) { closed = true; db.close(); } },
  };
}

// ------------------------------------------------------------------ the service
const iso = (ms) => new Date(ms).toISOString();
const NOTICE = 'This is a test network. Test time has no value and cannot be exchanged for anything.';
const NOTES = {
  reserved: 'Recorded; it is being signed.',
  signed: 'Signed, and the node has not confirmed that it took the action. The faucet sends the same action again until the chain has it or keeps refusing it. It never signs a second one for this request.',
  submitted: 'The node took the action. It is not in a block yet as far as the faucet has seen.',
  included: 'The action is in a block.',
  withdrawn: 'The chain kept refusing the action, so the faucet stopped sending it. It counts against the limits all the same. Ask again later.',
  superseded: 'The chain used the nonce of this action and the node does not find the action in a block: another action used the nonce. It counts against the limits all the same.',
  unconfirmed: 'The chain used the nonce of this action, and the node could not say whether this action is the one in the block. It counts against the limits.',
  cancelled: 'The request was recorded and never sent. Nothing was paid.',
};
/// What a refusal of the node is answered with. The node's own words go to the log, never to a caller.
const REFUSALS = {
  chain_daily_limit: [503, 'The node refused the payment: the daily limit of the faucet account on the chain is used up.'],
  faucet_frozen: [503, 'The node refused the payment: the faucet account is frozen on the chain.'],
  faucet_empty: [503, 'The node refused the payment: the faucet account cannot pay it.'],
  node_refused: [502, 'The node refused the action.'],
};
const REFUSAL_TAIL = ' The faucet signs no other action for this request, and the request counts against the limits. The same action is sent one more time, when it is first in line and a few blocks have passed; "lookup" says what became of it.';
/// What a sponsorship the node refused for good is answered with (see SETTLED_REFUSALS).
const WITHDRAWN_REFUSALS = Object.freeze({
  already_committed: 'The node refused the sponsorship: a registration of this key is waiting on the chain already, sent by someone else first. The faucet withdrew its action, will not send it again, and counts it against the limits. Make the registration the waiting commitment names, or sign up with a new key.',
  already_registered: 'The node refused the sponsorship: this key already belongs to an account. The faucet withdrew its action, will not send it again, and counts it against the limits.',
});

/// Starts the faucet. Options (see deploy/faucet/README.md for the config file):
/// - `trust`, `networkId`, `testNetwork` (must be true), `rpc`, `lookup` (an action by hash), `verifier`, `dataFile`,
///   `callerKeyFile` (where the key of the hashes of who asked is kept between starts, on a file system in memory:
///   see loadCallerKey; without it a restart forgets the counts per caller and per network);
/// - `account` (the faucet's own), `key` { publicKey, privateKey } (its spend key);
/// - `grantMicros`, `limits` { perAccountPerDay, perAddressPerDay, totalPerDayMicros, registrationsPerAddressPerDay, and if wanted
///   perNetworkPerDay and registrationsPerNetworkPerDay (an IPv6 /48: NETWORK_FACTOR times those of an address unless set),
///   registrationsPerDay (all callers: REGISTRATIONS_FACTOR times registrationsPerAddressPerDay unless set) },
///   `minBalanceMicros` (the floor), `maxRecipientBalanceMicros`, `maxChainDailyLimitMicros`, `sponsorRegistrations`,
///   `cancelWaiting` (cancel what waits on the account: default true), `freezeOnMisuse` (freeze the account when
///   something waits on it that the faucet did not make: default true);
/// - `host`, `port`, `hosts`, `corsOrigins`, `rateLimit` { perSecond, burst }, `trustedProxies`, `servePage`;
/// - `stateTimeoutMs`, `reconcileMs`, `resubmitMs`, `supersededAfterMs`, `labelMs` (how long a grant is looked up
///   for its last label), `idleReadMs` (how often the account is read when nothing is open: see `tick`),
///   `maxStallMs` (how long the proven state may stand still), `maxClockSkewMs`, `maxWaiting`,
///   `maxLive` (grants that may wait for a block at once), `refusedPerAddressPerHour`, `maxCancelsPerDay`;
/// - for tests: `readState`, `now`, `log`, `autoStart`, `storeSynchronous`.
export async function createFaucetService({
  trust, networkId, testNetwork, rpc, lookup, verifier, dataFile, callerKeyFile, account, key, grantMicros, limits, minBalanceMicros, maxRecipientBalanceMicros, maxChainDailyLimitMicros,
  sponsorRegistrations = false, cancelWaiting = true, freezeOnMisuse = true, host = '127.0.0.1', port = 8940, hosts = [], corsOrigins = [], rateLimit = {}, trustedProxies = [], servePage = true,
  stateTimeoutMs = 15000, reconcileMs = 5000, idleReadMs = 10000, resubmitMs = 30000, supersededAfterMs = 60000, labelMs = 6 * 3600000, maxStallMs = 300000, maxClockSkewMs = 300000, maxWaiting = 16, maxLive = 64,
  refusedPerAddressPerHour = 50, maxCancelsPerDay = 24, readState, now = Date.now, log = () => {}, autoStart = true, storeSynchronous = 'FULL',
}) {
  // ---- a test network, and only that
  if (testNetwork !== true) throw new Error('The faucet runs on test networks only: its config must state "test_network": true');
  if (String(trust?.app_version) !== '4' || !/^[0-9a-f]{64}$/.test(trust?.network_id ?? '') || typeof trust?.chain_id !== 'string') throw new Error('trust is the application-4 trust manifest the SDK takes');
  if (!/^[0-9a-f]{64}$/.test(networkId ?? '') || networkId !== trust.network_id) throw new Error('network_id is not the network of the trust manifest: the faucet serves exactly the test network its config names');
  if (!isTestChain(trust.chain_id)) throw new Error(`The chain id of the trust manifest is not one of a test network (${TEST_CHAINS.map((prefix) => `${prefix}…`).join(', ')}): the faucet does not start`);
  if (!/^(0|[1-9][0-9]{0,19})$/.test(account ?? '') || BigInt(account) >= MAX_U64) throw new Error('account is the number of the faucet account');
  if (!/^[0-9a-f]{64}$/.test(key?.publicKey ?? '') || !key.privateKey) throw new Error('The faucet needs the spend key of its account');
  const whole = (value, name, min = 1n) => { if (typeof value !== 'bigint' || value < min || value > 1_000_000_000_000_000n) throw new Error(`${name} is out of range`); return value; };
  const grant = whole(grantMicros, 'grantMicros'), floor = whole(minBalanceMicros, 'minBalanceMicros', 0n), richAbove = whole(maxRecipientBalanceMicros, 'maxRecipientBalanceMicros', 0n);
  const chainLimitMax = whole(maxChainDailyLimitMicros, 'maxChainDailyLimitMicros'), totalPerDay = whole(limits?.totalPerDayMicros, 'limits.totalPerDayMicros');
  const count = (value, name, min = 1) => { if (!Number.isInteger(value) || value < min || value > 1_000_000) throw new Error(`${name} is out of range`); return value; };
  const perAccount = count(limits.perAccountPerDay, 'limits.perAccountPerDay'), perAddress = count(limits.perAddressPerDay, 'limits.perAddressPerDay');
  const registrationsPerAddress = count(limits.registrationsPerAddressPerDay ?? 1, 'limits.registrationsPerAddressPerDay');
  // The IPv6 /48 of a caller is counted too, at NETWORK_FACTOR times the limits of one address; and the registrations
  // of all callers together have a total of their own, apart from the total of the grants (see checkLimits).
  const perNetwork = count(limits.perNetworkPerDay ?? NETWORK_FACTOR * perAddress, 'limits.perNetworkPerDay');
  const registrationsPerNetwork = count(limits.registrationsPerNetworkPerDay ?? NETWORK_FACTOR * registrationsPerAddress, 'limits.registrationsPerNetworkPerDay');
  const registrationsPerDay = count(limits.registrationsPerDay ?? REGISTRATIONS_FACTOR * registrationsPerAddress, 'limits.registrationsPerDay');
  if (perNetwork < perAddress || registrationsPerNetwork < registrationsPerAddress) throw new Error('limits.perNetworkPerDay and limits.registrationsPerNetworkPerDay are at least the limits of one address');
  if (typeof rpc !== 'function' || typeof lookup !== 'function') throw new Error('The faucet needs the RPC of a node and a way to look an action up by hash');

  const page = {};
  if (servePage) for (const [route, [file, type]] of Object.entries(PAGE_FILES)) page[route] = { type, body: readFileSync(new URL(`../web-v4/faucet/${file}`, import.meta.url)) };
  // The key of the hashes of who asked, which the store does not hold. Said in the log: where it came from, and
  // what the opening of the store did with what it held (see openFaucetStore). Never the key or its file's content.
  const callers = await loadCallerKey(callerKeyFile);
  if (callers.source === 'memory' && callerKeyFile !== undefined && callerKeyFile !== null) log('error', `the key of the hashes of who asked is held in memory only: ${callers.problem}. A restart of the faucet will forget how many requests each caller and each IPv6 /48 made in the last 24 hours; the limits per account and the totals of the day still hold`);
  if (callers.replaced) log('warn', `the file of the key of the hashes of who asked ${callers.replaced}: it was replaced by a new key`);
  const store = openFaucetStore({ filename: dataFile, networkId, account, synchronous: storeSynchronous, callerKey: callers.key });
  if (store.opened.moved) log('info', `the store was moved from version ${store.opened.moved} to ${SCHEMA}: who asked is kept as a hash under a key that is not in the store, and the store holds no key of the version before`, { from: store.opened.moved });
  if (store.opened.rewritten === false) log('error', 'the store could not be written anew after its move (is the disk full?): what the version before freed without overwriting may still be in its free space. The next start tries again');
  if (store.opened.forgotten) log(callerKeyFile === undefined || callerKeyFile === null ? 'info' : 'warn', 'who asked in the last 24 hours was hashed under another key (it was held in memory only, or its file was emptied by a reboot): those hashes were removed, and the counts per caller and per IPv6 /48 start afresh; the limits per account and the totals of the day still hold');
  const limiter = createRateLimiter({ perSecond: 5, burst: 20, ...rateLimit, now });
  const proxies = new Set(trustedProxies.map(normalIp).filter(Boolean));
  const origins = new Set(corsOrigins);
  const hostName = (value) => String(value || '').toLowerCase().replace(/:(?:80|443)$/, '');
  const ownHosts = new Set(hosts.map(hostName));
  let server, timer = null, closing = null, queue = Promise.resolve(), waiting = 0;
  /// What the proven reads showed last. `blockMs` and `height` only grow.
  const seen = {
    at: 0, asked: 0, ok: false, problem: null, height: 0n, advancedAt: now(), blockMs: 0, balance: null, fee: null, limit: null, allowance: null, nonce: null, frozen: false, raise: false, waitingPayments: 0,
    unsentSince: null, lookupFailingSince: null, busyAt: null, busyCount: 0,
  };
  const alarmed = new Set();
  try { readState ??= createStateReader({ rpc, trust, verifier, storage: store.checkpointStorage() }); } catch (error) { store.close(); throw error; }

  // ---- proven state
  async function provenState(selection) {
    let result;
    try { result = await withTimeout(readState(selection), stateTimeoutMs, undefined, 'node'); } catch (error) {
      seen.ok = false;
      log('warn', 'a verified state read failed', { error: plainText(error?.message, 160) });
      throw new ApiError(503, 'state_unavailable', 'The state of the network could not be read with a valid proof; the faucet gives nothing without it', { retryAfter: 5 });
    }
    // The proof is checked against the trust manifest by the verifier; the network it proves must be the configured one.
    if (result?.verified !== true || result.state?.network_id !== networkId) { seen.ok = false; throw new ApiError(503, 'wrong_network', 'The proven state belongs to another network than the one this faucet is configured for'); }
    const state = result.state, height = BigInt(state.height), blockMs = Number(BigInt(state.time_micros) / 1000n);
    // Whether the chain moves is judged by what is proven, not by what the node says of itself.
    if (height > seen.height) { seen.height = height; seen.advancedAt = now(); }
    if (blockMs > seen.blockMs) seen.blockMs = blockMs;
    return state;
  }
  const elapsedOf = (state) => BigInt(state.time_micros) - BigInt(state.genesis?.genesis_time_micros ?? trust.genesis_time_micros);
  /// The total of the chain's stops at a state (`TimeSDK.stoppedMicros`): on a network whose waits survive a stop
  /// (`waits_survive_stops`), what the metadata row of every proven state carries; 0 on any other. The moments of a
  /// security row (when a freeze ends, when a payment or a raise of the limit is ready, when the allowance was
  /// counted) are on the clock of the waits, the chain's time less this total. Read on the chain's time they come too
  /// early by the total: a freeze looks over, a raise in force and the allowance refilled while the chain holds the
  /// opposite. What a key signs stays on the chain's time: the expiry of the faucet's own freeze, and of a
  /// registration consent. (A state without its configuration, which only tests give, is read as before.)
  const stoppedOf = (state) => (state.config === undefined && state.stopped_micros === undefined ? 0n : BigInt(SDK.stoppedMicros(state)));
  /// The faucet account as this state proves it, with why the key may not be used on it (`problem`,
  /// which never names the key). Remembers what it saw for /v1/faucet and the health check.
  /// `elapsed` is the chain's time since genesis, `clock` the clock of the waits, `stopped` the difference.
  function faucetView(state) {
    const row = state.accounts.find((item) => String(item.id) === account);
    const device = (row?.devices || []).find((item) => item.public_key === key.publicKey), role = device ? roleOf(device) : undefined;
    const security = row ? securityOf(state, account) : null, elapsed = elapsedOf(state), stopped = stoppedOf(state), clock = elapsed - stopped;
    // A raise of the limit that has finished waiting is in force. The engine applies it before it
    // judges the next action of the account, and until an action succeeds the row still lists it
    // as waiting; it can no longer be cancelled. One that still waits was started with a spend key.
    const dueRaise = security?.pending_limit && BigInt(security.pending_limit.ready_elapsed_micros) <= clock ? security.pending_limit : null;
    const waitingRaise = security?.pending_limit && !dueRaise ? security.pending_limit : null;
    const limitNow = security ? BigInt((dueRaise ?? security.policy).daily_limit_micros) : null;
    const problem = !row ? 'The faucet account does not exist on this network'
      : !device ? 'The key in key_file is not a key of the faucet account'
        : role === null ? 'The key in key_file holds every power of the faucet account: the account must adopt the security rules, and the faucet must hold a spend key only'
          : role !== 'spend' ? 'The key in key_file is not a spend key of the faucet account'
            : !security ? 'The proven state shows no security rules for the faucet account: without them no daily limit bounds its key'
              : limitNow > chainLimitMax ? 'The daily limit of the faucet account on the chain is above max_chain_daily_limit_micros'
                : waitingRaise && BigInt(waitingRaise.daily_limit_micros) > chainLimitMax ? 'A raise of the daily limit above max_chain_daily_limit_micros is waiting on the faucet account: cancel it with a spend or recovery key'
                  : null;
    Object.assign(seen, { at: now(), ok: true, problem });
    if (problem && !alarmed.has(problem)) { alarmed.add(problem); log('error', 'the faucet stops giving', { reason: problem }); }
    if (!row || !security) return { problem, usable: false };
    const view = {
      problem, usable: role === 'spend', row, security, elapsed, clock, stopped, height: BigInt(state.height), blockMs: Number(BigInt(state.time_micros) / 1000n),
      fee: BigInt(SDK.networkFee(state)), balance: BigInt(row.balance), nonce: BigInt(row.nonce), allowance: allowance(security, clock), frozen: frozen(security, clock),
      waitingPayments: (security.pending_payments || []).length, raise: Boolean(waitingRaise), waitingRaise, limit: limitNow,
    };
    Object.assign(seen, { balance: view.balance, fee: view.fee, nonce: view.nonce, limit: limitNow, allowance: view.allowance, frozen: view.frozen, raise: view.raise, waitingPayments: view.waitingPayments });
    return view;
  }
  /// Grants that can still take money out of the account: not sent yet, or sent with a nonce the chain has not used.
  const liveOf = (open, nonce) => open.filter((g) => g.status === 'reserved' || (SENDABLE.includes(g.status) && BigInt(g.nonce) > nonce));
  const outstanding = (open, nonce) => liveOf(open, nonce).reduce((sum, g) => sum + BigInt(g.cost), 0n);
  /// The lowest nonce above the chain's that no grant on its way holds.
  function nextNonce(open, chainNonce) {
    const floorNonce = BigInt(store.meta.get('nonce_floor') ?? '0');
    const held = new Set(open.filter((g) => SENDABLE.includes(g.status)).map((g) => g.nonce));
    let nonce = (chainNonce > floorNonce ? chainNonce : floorNonce) + 1n;
    while (held.has(nonce.toString())) nonce += 1n;
    return nonce;
  }
  const raiseFloor = (nonce) => { if (BigInt(nonce) > BigInt(store.meta.get('nonce_floor') ?? '0')) store.meta.put('nonce_floor', nonce); };

  // ---- what stops the faucet
  /// Why nothing is given on what `v` shows of the account (a view, or `seen`), each as its code.
  /// The grant path and /v1/faucet both ask here, so what the page says is what a request gets.
  function stops(v, at) {
    const reasons = [];
    if (v.problem) reasons.push('key_or_account_check_failed');
    if (v.waitingPayments) reasons.push('payment_above_limit_waiting');
    if (v.raise) reasons.push('limit_raise_waiting');
    if (v.frozen) reasons.push('frozen');
    if (at - seen.advancedAt > maxStallMs) reasons.push('chain_not_advancing');
    return reasons;
  }
  const STOP_ERRORS = {
    key_or_account_check_failed: () => new ApiError(503, 'faucet_unavailable', 'The faucet is not giving: its account or key failed a safety check. Its operator has been told in the log'),
    payment_above_limit_waiting: () => new ApiError(503, 'faucet_unavailable', 'The faucet is not giving: a payment that it did not make is waiting on its account. Its operator has been told in the log'),
    limit_raise_waiting: () => new ApiError(503, 'faucet_unavailable', 'The faucet is not giving: a change of its daily limit that it did not make is waiting on its account. Its operator has been told in the log'),
    frozen: () => new ApiError(503, 'faucet_frozen', 'The faucet account is frozen on the chain; nothing is given until that ends', { retryAfter: 600 }),
    chain_not_advancing: () => new ApiError(503, 'state_unavailable', 'The proven state of the network has not moved for some minutes; the faucet gives nothing on old news', { retryAfter: 30 }),
  };
  function stopCheck(view, at) { const reasons = stops(view, at); if (reasons.length) throw STOP_ERRORS[reasons[0]](); }
  /// The checks on the faucet's own account for a payment of `cost`, with what is already on its way taken off.
  function affordable(view, open, cost) {
    const pending = outstanding(open, view.nonce);
    if (view.balance - pending - cost < floor) throw new ApiError(503, 'faucet_empty', 'The faucet is at its floor and gives nothing until it is refilled', { retryAfter: 3600 });
    if (view.allowance - pending < cost) throw new ApiError(503, 'chain_daily_limit', 'The daily limit of the faucet account on the chain is used up. It refills over 24 hours; ask again later', { retryAfter: 600 });
  }
  const busy = (error) => { seen.busyAt = now(); seen.busyCount += 1; return error; };
  /// No new grant is signed while an earlier one has not reached the node, and only so many wait for a block.
  function lineClear(open, nonce) {
    const live = liveOf(open, nonce);
    if (live.some((g) => g.status !== 'submitted')) throw busy(new ApiError(503, 'node_unavailable', 'An earlier grant has not reached the node yet; the faucet sends it first. Try again shortly', { retryAfter: 10 }));
    if (live.length >= maxLive) throw busy(new ApiError(503, 'busy', 'Too many grants wait for a block; try again shortly', { retryAfter: 10 }));
  }
  /// Everything that stops the giving (`reasons`), what of it is a fault (`faults`), and what is for the
  /// operator without stopping anything (`warnings`).
  /// One reason is not a fault: `daily_total_given`, the faucet has given what its config allows in 24 hours and
  /// gives again when the oldest grant leaves that window. That is a faucet doing its work, and any caller can
  /// bring it about, so it must not turn the health check red. While it holds, the daily limit on the chain is
  /// expected to be nearly used as well (the operator sets it to about the same number), so that is no fault then
  /// either. A chain limit that is used up while the config's total is not is one: something else spent it.
  /// And so is one that is used up while the total is given, when the account's nonce has moved without the
  /// faucet in the last 24 hours (`nonceWatch`): the allowance on the chain refills over the day while the
  /// config's total frees nothing until its oldest grant is 24 hours old, so whoever else holds the key can pay
  /// the refilled allowance out, and "the faucet gave its total" would explain that away for the whole day.
  function conditions() {
    const at = now(), reasons = [], warnings = [];
    const elsewhere = Number(store.meta.get('key_used_elsewhere_at') ?? 0), elsewhereToday = elsewhere > 0 && at - elsewhere < DAY_MS;
    if (!seen.ok || at - seen.at > Math.max(60000, reconcileMs * 6)) reasons.push('state_unavailable');
    reasons.push(...stops(seen, at));
    if (seen.ok && seen.balance !== null && !seen.problem) {
      const pending = outstanding(store.open(), seen.nonce), cost = grant + seen.fee;
      if (seen.balance - pending - cost < floor) reasons.push('below_floor');
      if (seen.allowance - pending < cost) reasons.push('chain_daily_limit_used_up');
    }
    if (seen.unsentSince !== null && at - seen.unsentSince > 60000) reasons.push('node_not_taking_actions');
    const given = leftToday(store.stamp(seen.blockMs)) < grant + (seen.fee ?? 0n);
    if (given) reasons.push('daily_total_given');
    const faults = reasons.filter((reason) => reason !== 'daily_total_given' && !(given && !elsewhereToday && reason === 'chain_daily_limit_used_up'));
    if (seen.lookupFailingSince !== null && at - seen.lookupFailingSince > 60000) warnings.push('lookups_failing');
    if (seen.busyAt !== null && at - seen.busyAt < 300000) warnings.push('requests_refused_busy');
    if (seen.ok && Math.abs(at - seen.blockMs) > maxClockSkewMs) warnings.push('clock_differs_from_block_time');
    if (elsewhereToday) warnings.push('key_used_elsewhere');
    return { reasons, faults, warnings };
  }
  /// What is left of the total of 24 hours at block time `at`.
  const leftToday = (at) => { const left = totalPerDay - BigInt(store.usage('grant', '', { caller: '', network: null }, at - DAY_MS).total.used); return left > 0n ? left : 0n; };
  /// How many registrations are left in the current 24 hours at block time `at`.
  const registrationsLeft = (at) => Math.max(0, registrationsPerDay - store.usage('registration', '', { caller: '', network: null }, at - DAY_MS).kind.n);

  // ---- one at a time
  /// Runs `work` after everything queued before it. Requests wait in a bounded line.
  function serial(work, bounded = true) {
    if (bounded && waiting >= maxWaiting) throw busy(new ApiError(503, 'busy', 'The faucet is busy; try again shortly', { retryAfter: 2 }));
    waiting += 1;
    const run = queue.then(work).finally(() => { waiting -= 1; });
    queue = run.catch(() => {});
    return run;
  }
  const submit = (raw) => rpc('/broadcast_tx_sync', { tx: `0x${Buffer.from(raw).toString('hex')}` });
  const inCache = (error) => error instanceof IndexerError && /already exists in cache/i.test(error.rpcMessage || '');

  // ---- sending
  const classify = (text) => (/over the daily limit/i.test(text) ? 'chain_daily_limit' : /frozen/i.test(text) ? 'faucet_frozen' : /insufficient/i.test(text) ? 'faucet_empty' : 'node_refused');
  /// Sends the stored bytes of a grant. Returns 'accepted', 'unknown' (no usable answer: the node
  /// may or may not have them), or `{ refused: <the node's reason> }`. Whatever it returns, the
  /// bytes have left this machine: only the chain decides from here whether they are paid.
  async function send(row) {
    store.attempt(row.id, now());
    let result;
    try { result = await submit(row.raw); } catch (error) {
      if (inCache(error)) { store.accepted(row.id); return 'accepted'; }
      log('warn', 'the node did not answer a submission; the same bytes are sent again later', { grant: row.id, code: error instanceof IndexerError ? error.code : 'INTERNAL' });
      return 'unknown';
    }
    const code = Object.hasOwn(result ?? {}, 'code') ? result.code : null;
    if (code === 0 && typeof result.hash === 'string' && result.hash.toUpperCase() === row.hash) { store.accepted(row.id); return 'accepted'; }
    if (code === 0 || code === null) { log('error', 'the node answered a submission for another transaction', { grant: row.id }); return 'unknown'; }
    return { refused: plainText(result.log, 160) || 'no reason given' };
  }
  /// Signs a reserved grant with the next free nonce, records the bytes, and sends them.
  async function signAndSend(id, view, state, open) {
    const reserved = store.byId(id);
    const nonce = nextNonce(open, view.nonce).toString();
    const kind = reserved.kind === 'grant' ? 'transfer' : 'sponsor_registration';
    const tx = await SDK.signAction({ networkId, kind, from: account, nonce, authEpoch: String(view.row.auth_epoch), publicKey: key.publicKey, payload: JSON.parse(reserved.payload) }, key.privateKey);
    const hash = sha256Hex(tx);
    store.signed(id, { nonce, hash, raw: tx, height: String(state.height) });
    const outcome = await send(store.byId(id));
    if (outcome === 'accepted' || outcome === 'unknown') return outcome;
    // A sponsored registration that the node refuses because its key is taken (an account holds it, or a commitment
    // of it waits: someone's sponsorship of the same key, sent first) is refused for good: no sending changes that.
    // Before 2026-11-24 such bytes stayed open, counted and unsent for three blocks and a settling pass, and since
    // nothing new is signed while earlier bytes have not reached the node, every grant and sign-up of everybody waited
    // with them: anyone could bring that about at will, with a sponsorship of his own for a key and at once a request
    // to the faucet for the same key. They are now withdrawn at once, when no other bytes on their way hold a later
    // nonce (none can: they were signed last). They stay in the store and count against the limits, they are never
    // sent again, and they are looked up by their hash when their nonce is used (the next action of the faucet uses
    // it), as every withdrawn action is: a node that said "refused" and kept them cannot make the faucet forget an
    // action that was paid.
    const settled = reserved.kind === 'registration' && Object.hasOwn(SETTLED_REFUSALS, outcome.refused) ? SETTLED_REFUSALS[outcome.refused] : null;
    if (settled && !store.open().some((g) => g.id !== id && SENDABLE.includes(g.status) && BigInt(g.nonce) > BigInt(nonce))) {
      store.finish(id, 'withdrawn', settled, 0, now());
      log('warn', 'the node refused a sponsored registration for good at its first sending: it is withdrawn at once, never sent again, and counts', { grant: id, reason: settled, node: outcome.refused });
      return { refused: settled };
    }
    // "Refused" is the node's word. The bytes stay open and counted; the settling pass tries them
    // once more three blocks on, and withdraws them if the chain still refuses.
    const reason = classify(outcome.refused);
    store.refused(id, String(state.height), reason);
    log('warn', 'the node refused a grant at its first sending; it stays counted', { grant: id, reason, node: outcome.refused });
    return { refused: reason };
  }

  // ---- limits
  const retryIn = (oldest, at) => Math.max(1, Math.ceil(((oldest ?? at) + DAY_MS - at) / 1000));
  const publicGrant = (row) => ({
    kind: row.kind, status: row.status, hash: row.hash, ...(row.kind === 'grant' ? { account: row.recipient } : { public_key: row.recipient }), amount_micros: String(row.amount),
    nonce: row.nonce, created_at: iso(row.created_at), height: row.height, reason: row.reason, note: NOTES[row.status],
  });
  /// Throws the refusal of a limit that `usage` shows as reached. `cost` is what the request would add to the total.
  /// - Per caller: an IPv4 address or an IPv6 /56. Per network: the IPv6 /48 around it, at NETWORK_FACTOR times the
  ///   limits of one address unless set (before 2026-11-24 a /48 counted as 256 callers, and took every grant of the
  ///   day and 5,120 names).
  /// - Per recipient: `perRecipient` grants an account (one in the first 24 hours of an account whose registration
  ///   this faucet sponsored: see giveGrant), one sponsorship a key.
  /// - The two totals are apart: a grant is refused when the money given in 24 hours would pass `totalPerDayMicros`,
  ///   which counts the sponsored registrations too; a registration is refused only by the number of registrations in
  ///   24 hours (`registrationsPerDay`), never by the money. So grants that use up the day do not close sign-up, and
  ///   sign-ups that use up theirs take from the grants at most their cost.
  function checkLimits(kind, usage, cost, at, recipient, perRecipient = kind === 'grant' ? perAccount : 1) {
    const perCaller = kind === 'grant' ? perAddress : registrationsPerAddress, perNet = kind === 'grant' ? perNetwork : registrationsPerNetwork;
    if (usage.caller.n >= perCaller) throw new ApiError(429, 'address_limit', `This address has had its ${perCaller} per 24 hours`, { retryAfter: retryIn(usage.caller.oldest, at) });
    if (usage.network && usage.network.n >= perNet) throw new ApiError(429, 'address_limit', `The network of this address (its IPv6 /48) has had its ${perNet} per 24 hours`, { retryAfter: retryIn(usage.network.oldest, at) });
    if (recipient !== null && usage.recipient.n >= perRecipient) {
      const words = kind !== 'grant' ? 'This key has been sponsored in the last 24 hours; "previous" lists it'
        : perRecipient < perAccount ? `This account was registered with this faucet's sponsorship in the last 24 hours, and a new account gets ${perRecipient} in its first 24 hours; "previous" lists what it was given`
          : `This account has had its ${perRecipient} per 24 hours; "previous" lists what it was given`;
      throw new ApiError(429, 'account_limit', words, { retryAfter: retryIn(usage.recipient.oldest, at), body: { previous: store.recent(kind, recipient, at - DAY_MS).map(publicGrant) } });
    }
    if (kind === 'registration') {
      if (usage.kind.n >= registrationsPerDay) throw new ApiError(429, 'daily_total', `The faucet has sponsored its ${registrationsPerDay} registrations for 24 hours`, { retryAfter: retryIn(usage.kind.oldest, at) });
    } else if (BigInt(usage.total.used) + cost > totalPerDay) throw new ApiError(429, 'daily_total', 'The faucet has given its total for 24 hours', { retryAfter: retryIn(usage.total.oldest, at) });
  }
  /// What a request costs the faucet before any limit counts it is bounded too. A request for
  /// which a proof was read and which was then refused for what it asks (an account that does
  /// not exist, one that holds enough) is noted; an address with `refusedPerAddressPerHour` of
  /// them in an hour of block time waits until the oldest is an hour old. People behind one
  /// address share the count, which is why it is high and the wait short.
  function checkRefusals(caller, at) {
    const made = store.refusals.count(caller, at - HOUR_MS);
    if (made.n >= refusedPerAddressPerHour) throw new ApiError(429, 'address_limit', 'Too many requests from this address in the last hour were for what the faucet cannot give; try again later', { retryAfter: Math.max(1, Math.ceil(((made.oldest ?? at) + HOUR_MS - at) / 1000)) });
  }
  async function counted(caller, work) {
    try { return await work(); } catch (error) {
      if (error instanceof ApiError && [400, 404, 409].includes(error.status)) store.refusals.add(caller, store.stamp(seen.blockMs));
      throw error;
    }
  }

  // ---- the two requests
  function answer(id, outcome, extra) {
    const row = store.byId(id), lookupPath = `/v1/faucet/grants/${row.hash}`;
    if (outcome !== 'accepted' && outcome !== 'unknown') {
      // A registration withdrawn at once (see signAndSend) is answered for what it is, and without "sent once more".
      if (Object.hasOwn(WITHDRAWN_REFUSALS, outcome.refused)) throw new ApiError(409, outcome.refused, WITHDRAWN_REFUSALS[outcome.refused], { body: { hash: row.hash, lookup: lookupPath } });
      const [status, sentence] = REFUSALS[outcome.refused];
      throw new ApiError(status, outcome.refused, sentence + REFUSAL_TAIL, { retryAfter: 30, body: { hash: row.hash, lookup: lookupPath } });
    }
    return { status: 202, body: { ...publicGrant(row), status: outcome === 'accepted' ? 'submitted' : 'pending', ...extra, note: outcome === 'accepted' ? 'Submitted is not included. Look the hash up until it is in a block.' : NOTES.signed, lookup: lookupPath, notice: NOTICE } };
  }
  /// The grants an account whose registration this faucet sponsored gets in its first 24 hours (block time, from the
  /// sponsorship). Before 2026-11-24 the faucet's own free registrations made the limit per account worth nothing:
  /// "register ten accounts, then ask two grants for each". Now each free registration brings one grant on its
  /// first day: a newcomer who signs up and asks a minute later gets it, and a second the next day.
  const NEW_ACCOUNT_GRANTS = 1;
  async function giveGrant(wanted, caller) {
    const who = { caller, network: networkOf(caller) };
    // Before any proof is read: the limits that need none, at the newest block time seen.
    const early = store.stamp(seen.blockMs);
    checkRefusals(caller, early);
    checkLimits('grant', store.usage('grant', wanted.id ?? '', who, early - DAY_MS), grant, early, wanted.id ?? null);
    return serial(() => counted(caller, async () => {
      const state = await provenState({ ids: wanted.id && wanted.id !== account ? [account, wanted.id] : [account], ...(wanted.name ? { names: [wanted.name] } : {}), include_security: true });
      const view = faucetView(state);
      stopCheck(view, now());
      const recipient = state.accounts.find((item) => (wanted.id ? String(item.id) === wanted.id : item.name === wanted.name));
      if (!recipient) throw new ApiError(404, 'account_not_found', `No such account on this network.${sponsorRegistrations ? ' A developer without an account can have its registration sponsored: POST /v1/faucet/registrations' : ''}`);
      const to = String(recipient.id);
      if (to === account) bad('invalid_account', 'The faucet does not pay itself');
      if (BigInt(recipient.balance) > richAbove) throw new ApiError(409, 'already_funded', `This account already holds more than ${richAbove} microseconds; the faucet gives to accounts that need it`);
      const open = store.open(), cost = grant + view.fee, stamp = store.stamp(view.blockMs);
      // Any key of the account counts: the one whose registration was sponsored is among them.
      const keys = [recipient.public_key, ...(Array.isArray(recipient.devices) ? recipient.devices.map((device) => device?.public_key) : [])];
      const perRecipient = store.sponsoredSince(keys, stamp - DAY_MS) ? Math.min(perAccount, NEW_ACCOUNT_GRANTS) : perAccount;
      checkLimits('grant', store.usage('grant', to, who, stamp - DAY_MS), cost, stamp, to, perRecipient);
      lineClear(open, view.nonce);
      affordable(view, open, cost);
      const id = store.reserve({ kind: 'grant', recipient: to, who, amount: Number(grant), cost: Number(cost), at: stamp, payload: { to, amount: grant.toString() }, check: (usage) => checkLimits('grant', usage, cost, stamp, to, perRecipient) });
      log('info', 'grant recorded', { grant: id, account: to });
      return answer(id, await signAndSend(id, view, state, open), { fee_micros: view.fee.toString() });
    }));
  }
  async function sponsor(input, caller) {
    const consent = SDK.sponsorConsentBytes({ networkId, sponsorAccount: account, publicKey: input.public_key, commitment: input.commitment, expiresElapsedMicros: input.expires_elapsed_micros });
    let consented = false;
    try { consented = await crypto.subtle.verify('Ed25519', await crypto.subtle.importKey('raw', SDK.hexToBytes(input.public_key, 32), 'Ed25519', false, ['verify']), SDK.hexToBytes(input.proof, 64), consent); } catch { consented = false; }
    if (!consented) bad('invalid_consent', 'proof is not the signature of public_key over the sponsorship consent that names this faucet\'s account and network (GET /v1/faucet gives both)');
    const who = { caller, network: networkOf(caller) };
    const early = store.stamp(seen.blockMs);
    checkRefusals(caller, early);
    checkLimits('registration', store.usage('registration', input.public_key, who, early - DAY_MS), 1n, early, input.public_key);
    return serial(() => counted(caller, async () => {
      const state = await provenState({ ids: [account], public_keys: [input.public_key], include_security: true });
      const view = faucetView(state);
      stopCheck(view, now());
      if (state.accounts.some((item) => item.public_key === input.public_key || (item.devices || []).some((device) => device.public_key === input.public_key))) throw new ApiError(409, 'already_registered', 'This key already belongs to an account');
      const elapsed = view.elapsed, expiry = BigInt(input.expires_elapsed_micros), rules = state.config?.registration;
      if (!rules || !/^[1-9][0-9]*$/.test(String(rules.max_lifetime_micros)) || !/^(0|[1-9][0-9]*)$/.test(String(rules.fee_micros))) throw new ApiError(503, 'state_unavailable', 'The proven state does not show the registration rules of this network');
      const waitingCommit = (state.name_commits || []).find((item) => item.public_key === input.public_key && BigInt(item.expires_elapsed_micros) >= elapsed);
      if (waitingCommit) throw new ApiError(409, 'already_committed', 'A registration of this key is waiting on the chain already; reveal the name, or wait for it to expire', { body: { same_commitment: waitingCommit.commitment === input.commitment } });
      if (expiry < elapsed + EXPIRY_MARGIN_MICROS || expiry > elapsed + BigInt(rules.max_lifetime_micros)) bad('invalid_expiry', 'expires_elapsed_micros must be at least 45 seconds and at most the registration lifetime of the network after the newest proven state (state_time_micros of an account answer, less the genesis time)');
      const open = store.open(), cost = BigInt(rules.fee_micros) + view.fee, stamp = store.stamp(view.blockMs);
      lineClear(open, view.nonce);
      affordable(view, open, cost);
      const id = store.reserve({ kind: 'registration', recipient: input.public_key, who, amount: Number(rules.fee_micros), cost: Number(cost), at: stamp, payload: input, check: (usage) => checkLimits('registration', usage, cost, stamp, input.public_key) });
      log('info', 'registration sponsorship recorded', { grant: id });
      // The commitment is a hash: the faucet cannot tell, and need not, whether it is that of a reveal (kind 2) or of a
      // registration that carries the account's keys (kind 45, on a network with `protected_registration`). It pays for
      // it either way, and the new key's consent, which names the commitment, keeps it from paying for any other.
      return answer(id, await signAndSend(id, view, state, open), { fee_micros: view.fee.toString(), next: 'When the hash is in a block, sign and submit, with the new key and in a later block, the registration the commitment names: the reveal (kind 2), or the registration that carries the account\'s keys (kind 45). Then ask for a grant with the new account.' });
    }));
  }

  // ---- what waits on the account without the faucet having made it
  /// A payment above the limit, or a raise of the limit, that waits on the faucet account was
  /// started with a spend key, and not by this service: the key is in someone else's hands. The
  /// faucet stops giving while it waits (`stops`), says so at error level, and acts with the two
  /// protective actions a spend key may sign. Neither takes a nonce, each costs one fee, and the
  /// fee is charged only when a block takes the action.
  ///
  /// The freeze (kind 72, unless `freezeOnMisuse` is off). It drops everything that waits at once
  /// and stops the key from paying out the daily limit. Its payload names the count of freezes
  /// and the version of the security row, so the chain takes one such freeze and never a second.
  /// - One signature per incident (that count and version), recorded before it is sent. It is
  ///   dated an hour past the moment the last waiting item is due, so that it stays valid for as
  ///   long as it is needed, and at most 30 days less an hour.
  /// - The same bytes are sent again every minute while an item waits and the proven state does
  ///   not show the account frozen. A refusal of the node is not an end: whoever holds the key
  ///   can hold the one place a key has in the node's waiting list, but only with a freeze of
  ///   his own, which freezes the account just the same.
  /// - A new freeze is signed for the same incident only when the earlier one has expired
  ///   unused: at most one an hour, never two that are valid together.
  ///
  /// The cancellation (kind 76, unless `cancelWaiting` is off), for each waiting item.
  /// - One signature per item, for good, recorded before it is sent; at most `maxCancelsPerDay`
  ///   items a day.
  /// - The same bytes again, at most once a minute per item and one cancellation a pass, for as
  ///   long as the proven state shows the item. A refusal means "not this time": the holder of
  ///   the key can keep a cancellation out with one of his own that waits, and only for as long
  ///   as that one waits.
  ///
  /// It buys time. The answer to a stolen key is the owner's: replace the keys.
  const RESEND_MS = 60000, HOUR_MICROS = 3600000000n, MAX_FREEZE_MICROS = 30n * 86400000000n - HOUR_MICROS;
  /// Sends a protective action of the faucet's own. Returns 'accepted', 'unknown' or 'refused'.
  async function dispatch(row, at, what) {
    store.cancels.sent(row.item, at);
    let result;
    try { result = await submit(row.raw); } catch (error) {
      if (inCache(error)) return 'accepted';
      log('warn', `the node did not answer ${what}; the same bytes are sent again in a minute`, { item: row.item });
      return 'unknown';
    }
    if (Object.hasOwn(result ?? {}, 'code') && result.code !== 0) {
      store.cancels.refused(row.item);
      if (row.refusals === 0) log('error', `the node refused ${what}; the same bytes are sent again every minute while they are needed`, { item: row.item, node: plainText(result.log, 160) });
      return 'refused';
    }
    if (row.attempts === 0) log('warn', `${what} was sent`, { item: row.item, hash: row.hash });
    return 'accepted';
  }
  async function guard(view, at) {
    // `ready` is when an item can happen at the earliest, as a time of the chain: its moment on the clock of the waits
    // plus the stops so far (a later stop only moves it later).
    const security = view.security, waitingItems = [
      ...(security.pending_payments || []).map((item) => ({ item: `payment:${item.id}`, ready: BigInt(item.ready_elapsed_micros) + view.stopped, payload: () => payloads.cancelPayment(item.id) })),
      ...(view.waitingRaise ? [{ item: `limit:${view.waitingRaise.id}`, ready: BigInt(view.waitingRaise.ready_elapsed_micros) + view.stopped, payload: () => payloads.cancelRaise(view.waitingRaise.id) }] : []),
    ];
    const frozenNow = BigInt(security.frozen_until_elapsed_micros) > view.clock;
    // What was being sent and is not needed, or not valid, any more is closed.
    for (const row of store.cancels.open()) {
      if (!row.item.startsWith('freeze:')) { if (!waitingItems.some((entry) => entry.item === row.item)) store.cancels.status(row.item, 'done'); continue; }
      if (frozenNow) store.cancels.status(row.item, 'done');
      else if (view.elapsed + EXPIRY_MARGIN_MICROS >= BigInt(row.expires)) {
        store.cancels.status(row.item, 'void');
        if (waitingItems.length) log('error', 'the freeze of the faucet account did not get into a block before it expired. Freeze the account with a recovery key', { item: row.item });
      }
    }
    if (!waitingItems.length) return;
    store.meta.put('key_used_elsewhere_at', at);
    for (const { item } of waitingItems) {
      if (alarmed.has(item)) continue;
      alarmed.add(item);
      log('error', 'a payment or a raise of the limit that the faucet did not make is waiting on its account: its key is used elsewhere. The faucet gives nothing while it waits. Replace the keys of the account', { item });
    }
    if (freezeOnMisuse && !frozenNow) {
      const incident = `freeze:${security.freezes}:${security.version}`;
      let row = store.cancels.get(incident);
      if (row?.status === 'void') { store.cancels.remove(incident); row = null; } // expired unused: the one case in which the incident gets another
      if (!row) {
        const due = waitingItems.reduce((latest, entry) => (entry.ready > latest ? entry.ready : latest), view.elapsed) + HOUR_MICROS;
        const expires = (due > view.elapsed + MAX_FREEZE_MICROS ? view.elapsed + MAX_FREEZE_MICROS : due).toString();
        const tx = await signSecurityAction({ networkId, kind: KIND.freeze, account: view.row, publicKey: key.publicKey, privateKey: key.privateKey, payload: payloads.freeze(security, expires) });
        store.cancels.add(incident, sha256Hex(tx), tx, at, expires);
        row = store.cancels.get(incident);
        log('error', 'the faucet freezes its own account, because its key is used elsewhere. The account pays nothing for the freeze period; replace its keys with the recovery keys', { item: incident, hash: row.hash });
      }
      if (row.status !== 'done' && (row.sent_at === null || at - row.sent_at >= RESEND_MS)) await dispatch(row, at, 'the freeze of the faucet account');
    }
    if (!cancelWaiting) return;
    // One cancellation at a time (a key has one place for them in the node's waiting list): while
    // one was sent within the minute and its item still waits, no other is sent. Then the one that
    // was sent longest ago, those never sent first.
    if (store.cancels.open().some((row) => !row.item.startsWith('freeze:') && row.sent_at !== null && at - row.sent_at < RESEND_MS)) return;
    const capped = store.cancels.count(at - DAY_MS) >= maxCancelsPerDay;
    const candidates = waitingItems.map((entry) => ({ entry, row: store.cancels.get(entry.item) }))
      .filter(({ row }) => (row ? row.sent_at === null || at - row.sent_at >= RESEND_MS : !capped))
      .sort((a, b) => (a.row?.sent_at ?? 0) - (b.row?.sent_at ?? 0));
    if (capped && waitingItems.some((entry) => !store.cancels.get(entry.item)) && !alarmed.has('cancels')) { alarmed.add('cancels'); log('error', 'too many cancellations in 24 hours: no more are signed. Replace the keys of the account'); }
    const next = candidates[0];
    if (!next) return;
    let row = next.row;
    if (!row) {
      const tx = await signSecurityAction({ networkId, kind: KIND.cancel, account: view.row, publicKey: key.publicKey, privateKey: key.privateKey, payload: next.entry.payload() });
      store.cancels.add(next.entry.item, sha256Hex(tx), tx, at);
      row = store.cancels.get(next.entry.item);
    }
    await dispatch(row, at, 'the cancellation of what waits on the faucet account');
  }

  // ---- a nonce the faucet did not sign
  /// A payment within the daily limit by another holder of the spend key leaves nothing waiting on the account,
  /// so `guard` never sees it. It leaves one trace: the account's nonce. Every charge to the daily limit comes
  /// with a nonce (v5/src/security.rs: the limit is charged by what a spend key sends with the account's next
  /// nonce, a transfer, a payment to a shop, a sponsored registration, kinds 71, 75 and 77; the kinds without
  /// a nonce, 72, 73, 74 and 76, do not charge it), and a replacement of the keys uses one as well. So a proven
  /// nonce above every nonce this faucet has signed means that someone else signed for the account, or that
  /// its keys were replaced. That is said at error level and kept as `key_used_elsewhere_at`.
  /// - What counts as signed: the highest nonce of a grant in the store, and the highest ever accounted for
  ///   (`nonce_accounted`, since old grants are pruned).
  /// - The first proven read of a store starts the count at what the chain shows: what happened on the account
  ///   before the faucet was installed (its funding, the adoption of the rules) is not the faucet's business.
  /// - A nonce that was said once is accounted for: the same use is not said again at every pass.
  /// - A foreign action that takes a nonce the faucet did sign is not seen here; the grant that held it ends
  ///   as `superseded`, with its own line in the log.
  function nonceWatch(view, at) {
    const recorded = store.meta.get('nonce_accounted') ?? null, signed = store.highestNonce();
    let known = recorded === null ? view.nonce : BigInt(recorded);
    if (signed > known) known = signed;
    if (view.nonce > known) {
      store.meta.put('key_used_elsewhere_at', at);
      log('error', 'the chain shows a nonce of the faucet account used that the faucet did not sign: its key is used elsewhere, or its keys were replaced. Replace the keys of the account', { proven_nonce: view.nonce.toString(), signed_up_to: known.toString() });
      known = view.nonce;
    }
    if (recorded === null || BigInt(recorded) !== known) store.meta.put('nonce_accounted', known.toString());
  }

  // ---- settling what is open
  /// One pass over the open grants. Runs in the same line as requests, so no nonce is given out
  /// while it works. `force` reads the state even when nothing is open (the periodic check).
  async function settle(force = false) {
    let open = store.open();
    if (!open.length && !force) return;
    let state;
    // When this read began: the pace of the faucet's own reads is counted from here. Not from the answer (a read
    // that takes any time at all would then put the next one a whole pass later), and not from the reads that
    // requests cause: those do not guard the account or watch its nonce, and whoever sends requests could put
    // the faucet's own look at its account off for as long as he likes.
    seen.asked = now();
    try { state = await provenState({ ids: [account], include_security: true }); } catch { return; }
    const view = faucetView(state), at = now();
    if (!view.row) return;
    if (view.usable) await guard(view, at).catch((error) => log('error', 'guarding the account failed', { error: plainText(error?.message, 160) }));
    nonceWatch(view, at);

    // 1. Nonces the chain has used: which action used them? At most 20 lookups a pass, those not asked for longest first.
    const used = open.filter((g) => g.nonce !== null && BigInt(g.nonce) <= view.nonce).sort((a, b) => (a.checked_at ?? 0) - (b.checked_at ?? 0));
    let lookups = 0, failures = 0;
    for (const row of used) {
      store.consumed(row.id, at);
      raiseFloor(row.nonce);
      // How long a label is waited for: from the moment the nonce was seen used, or, for bytes that were
      // ended before (withdrawn, superseded), from that moment.
      const sendable = SENDABLE.includes(row.status), since = sendable ? row.consumed_at ?? at : row.ended_at ?? at, late = at - since >= labelMs;
      // Withdrawn bytes that a later grant made again (same account, nonce and key give the same bytes): the later record tells.
      if (row.status === 'withdrawn' && store.byHash(row.hash).id !== row.id) { store.settle(row.id); continue; }
      let found = null, told = false;
      if (lookups < 20) {
        lookups += 1; store.checked(row.id, at);
        try { found = await lookup(row.hash); told = true; } catch { failures += 1; }
      }
      if (found && found.tx === Buffer.from(row.raw).toString('base64')) { store.included(row.id, found.height); log('info', 'grant included', { grant: row.id, height: found.height }); continue; }
      if (told && sendable && at - since >= supersededAfterMs) {
        // Still looked up for a while: the node's index can be late, and then the record is put right.
        store.finish(row.id, 'superseded', 'nonce_used_by_another_action', late ? 1 : 0, at);
        log('error', 'the chain used the nonce of a grant and the node does not find the grant: is the faucet key used elsewhere?', { grant: row.id });
        continue;
      }
      // After `labelMs` nothing more is asked: what the node could not tell stays untold.
      if (late) { if (sendable) store.finish(row.id, 'unconfirmed', 'the_node_could_not_tell', 1, at); else store.settle(row.id); }
    }
    if (failures) log('warn', 'actions could not be looked up on the node (is its transaction index on?)', { failed: failures });
    seen.lookupFailingSince = failures ? seen.lookupFailingSince ?? at : lookups ? null : seen.lookupFailingSince;
    // Withdrawn bytes whose nonce nobody used: after the same time they are left alone.
    for (const row of open) if (row.status === 'withdrawn' && BigInt(row.nonce) > view.nonce && at - (row.ended_at ?? at) >= labelMs) store.settle(row.id);

    // 2. Bytes that are still valid: the same bytes again, in nonce order. Nothing is sent with a key that failed its check.
    const live = view.problem ? [] : store.open().filter((g) => SENDABLE.includes(g.status) && BigInt(g.nonce) > view.nonce).sort((a, b) => (BigInt(a.nonce) < BigInt(b.nonce) ? -1 : 1));
    for (const [index, row] of live.entries()) {
      const head = BigInt(row.nonce) === view.nonce + 1n;
      if (row.refusal_height !== null) {
        // Refused before. It is sent one more time, and only when two things hold. It stands at the
        // head of the line: until then what is ahead of it explains the refusal or decides it.
        // And three blocks have passed: the proof is a block or two behind the node, so the bytes
        // may just have entered a block when they were refused.
        if (!head) continue;
        if (view.height < BigInt(row.refusal_height) + 3n) break;
      } else if (row.status === 'submitted' && at - (row.sent_at ?? 0) < resubmitMs) continue;
      const outcome = await send(row);
      if (outcome === 'unknown') break; // the node does not answer: everything waits for the next pass
      if (outcome === 'accepted') continue;
      const reason = classify(outcome.refused);
      if (row.refusal_height === null) { store.refused(row.id, String(state.height), reason); if (head) break; continue; }
      // The head of the line, refused again three blocks on: the chain does not take it.
      for (const later of live.slice(index)) store.finish(later.id, 'withdrawn', later.id === row.id ? reason : 'queued_behind_a_refused_grant', 0, at);
      log('error', 'the chain keeps refusing a grant: it and those queued behind it are withdrawn', { grant: row.id, reason, node: outcome.refused, withdrawn: live.length - index });
      break;
    }

    // 3. Requests recorded but never signed (the process stopped in between): they are made now, or cancelled.
    for (const row of store.open().filter((g) => g.status === 'reserved')) {
      try {
        stopCheck(view, at);
        const rest = store.open().filter((g) => g.id !== row.id);
        affordable(view, rest, BigInt(row.cost));
        await signAndSend(row.id, view, state, rest);
      } catch (error) { if (store.byId(row.id).status === 'reserved') store.finish(row.id, 'cancelled', error instanceof ApiError ? error.code : 'internal', 1, at); }
    }
    const unsent = liveOf(store.open(), view.nonce).some((g) => g.status !== 'submitted');
    seen.unsentSince = unsent ? seen.unsentSince ?? at : null;
    store.prune(store.stamp(seen.blockMs), at);
  }
  /// The timer: one pass at a time, every `reconcileMs`.
  /// - With nothing open the account is still read every `idleReadMs` (10 seconds): that is how the faucet
  ///   notices a payment or a raise that it did not make, so it bounds how long a misuse of its key goes unseen.
  ///   It also keeps the health check current and the light client's checkpoint fresh. The 10 seconds are
  ///   counted from the moment the last of these reads was asked for (`settle`), with half a pass of slack.
  ///   Counted from its answer, a read that took any time at all put the next one a whole pass later: every 15
  ///   seconds, not 10. The reads that requests cause do not count.
  /// - After a read that failed the account is read at every pass.
  /// - While something waits on the account, or a freeze or cancellation of the faucet's own is on its way, the
  ///   account is read at every pass: the freeze is then seen in its block, and said, one pass later.
  const incident = () => seen.waitingPayments > 0 || seen.raise || store.cancels.open().length > 0;
  let ticking = false;
  const tick = () => {
    if (ticking) return;
    ticking = true;
    serial(() => settle(incident() || !seen.ok || now() - seen.asked >= idleReadMs - reconcileMs / 2), false).catch((error) => log('error', 'settling failed', { error: plainText(error?.message, 160) })).finally(() => { ticking = false; });
  };

  // ---- routes
  const HANDLERS = {
    'GET /v1/faucet': () => {
      const left = leftToday(store.stamp(seen.blockMs)), { reasons } = conditions(), usable = seen.ok && !seen.problem && seen.balance !== null;
      return { status: 200, body: {
        notice: NOTICE, test_network: true, network_id: networkId, chain_id: trust.chain_id, account,
        gives: { grant_micros: grant.toString(), fee_paid_by: 'the faucet', window_hours: 24, per_account: perAccount, per_new_account: Math.min(perAccount, NEW_ACCOUNT_GRANTS), per_address: perAddress, per_network: perNetwork, total_micros: totalPerDay.toString(),
          not_to_accounts_holding_more_than_micros: richAbove.toString(), floor_micros: floor.toString(), address_means: 'an IPv4 address, or an IPv6 /56; the IPv6 /48 around it is counted too (per_network)',
          new_account_means: 'an account whose registration this faucet sponsored in the last 24 hours' },
        left: { total_micros: left.toString(), grants: (left / (grant + (seen.fee ?? 0n))).toString() },
        registrations: { sponsored: sponsorRegistrations, per_address: sponsorRegistrations ? registrationsPerAddress : 0, per_network: sponsorRegistrations ? registrationsPerNetwork : 0, per_day: sponsorRegistrations ? registrationsPerDay : 0, left: sponsorRegistrations ? registrationsLeft(store.stamp(seen.blockMs)) : 0 },
        giving: reasons.length === 0, reasons,
        chain: usable ? { state_height: seen.height.toString(), block_time: iso(seen.blockMs), balance_micros: seen.balance.toString(), fee_micros: seen.fee.toString(), daily_limit_micros: seen.limit.toString(), daily_limit_left_micros: seen.allowance.toString(), read_at: iso(seen.at) } : null,
      } };
    },
    'GET /v1/faucet/health': () => {
      const { reasons, faults, warnings } = conditions(), open = store.open(), elsewhere = Number(store.meta.get('key_used_elsewhere_at') ?? 0);
      // 503 says one thing: something is wrong and the faucet is not giving. A faucet that has given its
      // total for 24 hours is not giving either (`giving` is false, the reason is listed), but nothing is
      // wrong: that answer is 200. Warnings are in the body, with 200: some of them a caller can cause, and
      // none of them stops a grant.
      return { status: faults.length ? 503 : 200, body: {
        ok: faults.length === 0, giving: reasons.length === 0, reasons, faults, warnings,
        open_grants: open.length, waiting_for_a_block: seen.nonce === null ? 0 : liveOf(open, seen.nonce).length, state_height: seen.height.toString(),
        refused_busy: seen.busyCount, key_used_elsewhere_at: elsewhere ? iso(elsewhere) : null,
      } };
    },
    'GET /v1/faucet/grants/{hash}': ({ hash }) => {
      const row = store.byHash(hash);
      if (!row) throw new ApiError(404, 'not_found', 'This faucet has no record of an action with this hash (records are kept for 30 days)');
      return { status: 200, body: { ...publicGrant(row), notice: NOTICE } };
    },
    'POST /v1/faucet/grants': ({ body, caller }) => {
      if (Object.keys(body).join(',') !== 'account' || typeof body.account !== 'string') bad('invalid_body', 'The body is {"account": "<account number or name>"} and nothing else');
      const text = body.account;
      if (/^(0|[1-9][0-9]{0,19})$/.test(text) && BigInt(text) < MAX_U64) return giveGrant({ id: text }, caller);
      const name = text.startsWith('@') ? text.slice(1) : text;
      if (!/^[a-z0-9_]{2,15}$/.test(name) || /^[0-9]+$/.test(name)) bad('invalid_account', 'An account is its number, or its name of 2 to 15 lower-case letters, digits and underscores');
      return giveGrant({ name }, caller);
    },
    'POST /v1/faucet/registrations': ({ body, caller }) => {
      if (!sponsorRegistrations) throw new ApiError(404, 'not_offered', 'This faucet does not sponsor registrations');
      if (Object.keys(body).sort().join(',') !== 'commitment,expires_elapsed_micros,proof,public_key' || !/^[0-9a-f]{64}$/.test(body.public_key) || !/^[0-9a-f]{64}$/.test(body.commitment) || !/^[0-9a-f]{128}$/.test(body.proof)
        || typeof body.expires_elapsed_micros !== 'string' || !/^[1-9][0-9]{0,19}$/.test(body.expires_elapsed_micros) || BigInt(body.expires_elapsed_micros) > MAX_U64) {
        bad('invalid_body', 'The body is {"public_key", "commitment", "expires_elapsed_micros", "proof"}: lower-case hexadecimal, the expiry a decimal string, nothing else');
      }
      return sponsor({ public_key: body.public_key, commitment: body.commitment, expires_elapsed_micros: body.expires_elapsed_micros, proof: body.proof }, caller);
    },
  };

  // ---- HTTP
  const BASE_HEADERS = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY', 'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'" };
  const PAGE_POLICY = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
  function reply(response, status, body, headers = {}) {
    const text = JSON.stringify(body);
    response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(text), ...headers });
    response.end(text);
  }
  function failure(response, error) {
    if (error.extra.close) response.once('finish', () => { const request = response.req; request?.resume(); setTimeout(() => request?.destroy(), 1000).unref?.(); });
    reply(response, error.status, { error: { code: error.code, message: error.message }, ...(error.extra.body || {}) }, {
      ...(error.extra.retryAfter ? { 'Retry-After': String(error.extra.retryAfter) } : {}), ...(error.extra.allow ? { Allow: error.extra.allow } : {}), ...(error.extra.close ? { Connection: 'close' } : {}) });
  }
  /// Who is asking: the peer, or what trusted proxies say about it. X-Forwarded-For is read from
  /// the right, past the entries that are trusted proxies themselves; what stands left of the
  /// first other entry is the caller's own claim and is not read.
  function callerOf(request) {
    const peer = normalIp(request.socket.remoteAddress);
    if (peer === null || !proxies.has(peer)) return callerKey(peer);
    const entries = String(request.headers['x-forwarded-for'] || '').split(',');
    for (let i = entries.length - 1; i >= 0; i--) {
      const ip = normalIp(entries[i]);
      if (ip === null) break;
      if (!proxies.has(ip)) return callerKey(ip);
    }
    return callerKey(peer);
  }
  /// The JSON object of a request body: at most MAX_BODY_BYTES, UTF-8, in its one plain spelling
  /// (no key twice, no escapes, no numbers where strings belong).
  async function readBody(request) {
    if (!/^application\/json(?:\s*;|$)/i.test(request.headers['content-type'] || '')) throw new ApiError(415, 'unsupported_media_type', 'Send JSON with Content-Type: application/json');
    const tooLarge = () => new ApiError(413, 'body_too_large', `The body is at most ${MAX_BODY_BYTES} bytes`, { close: true });
    if (Number(request.headers['content-length']) > MAX_BODY_BYTES) throw tooLarge();
    // A body of at most a kilobyte that takes longer than BODY_MS to arrive is not waited for.
    const bytes = await new Promise((resolve, reject) => {
      const chunks = []; let size = 0, over = false;
      const timer = setTimeout(() => { over = true; chunks.length = 0; reject(new ApiError(408, 'body_too_slow', `The body did not arrive within ${BODY_MS / 1000} seconds`, { close: true })); }, BODY_MS);
      timer.unref?.();
      request.on('data', (chunk) => { if (over) return; size += chunk.length; if (size > MAX_BODY_BYTES) { over = true; clearTimeout(timer); chunks.length = 0; reject(tooLarge()); } else chunks.push(chunk); });
      request.on('end', () => { clearTimeout(timer); if (!over) resolve(Buffer.concat(chunks)); });
      request.on('error', () => { clearTimeout(timer); reject(new ApiError(400, 'invalid_body', 'The body could not be read')); });
    });
    let text, body;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); body = JSON.parse(text); } catch { throw new ApiError(400, 'invalid_json', 'The body is not valid JSON'); }
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.values(body).some((value) => typeof value !== 'string')) bad('invalid_body', 'The body is a JSON object of strings');
    if (JSON.stringify(body) !== text.replace(/\s+/g, '')) bad('invalid_body', 'Write each field once, as a plain string without escapes');
    return body;
  }
  async function handle(request, response) {
    for (const [name, value] of Object.entries(BASE_HEADERS)) response.setHeader(name, value);
    // A request that carries a body ends its connection with its answer. Answered before its body was read (refused
    // for its route, method, rate, size or kind of body), a connection used to stay open for as long as the body kept
    // coming, a byte at a time, whatever the answer was: before 2026-11-24 a caller over its rate limit, whose requests
    // cost it nothing, could hold every connection of the faucet that way. What is still coming is read and dropped
    // for a moment after the answer, so that the answer is not lost to a reset, and then the connection is closed.
    if (carriesBody(request.headers)) {
      response.setHeader('Connection', 'close');
      response.once('finish', () => { if (!request.complete) { request.resume(); setTimeout(() => request.destroy(), 1000).unref?.(); } });
    }
    try {
      if (request.rawHeaders.filter((name, i) => i % 2 === 0 && name.toLowerCase() === 'host').length > 1) throw new ApiError(400, 'invalid_request', 'A request names its host once');
      const bound = server.address()?.port, asked = hostName(request.headers.host);
      const local = [`127.0.0.1:${bound}`, `localhost:${bound}`, `[::1]:${bound}`];
      if (!ownHosts.has(asked) && !local.map(hostName).includes(asked)) throw new ApiError(421, 'unknown_host', 'This server does not answer under that host name');
      // A browser names the page a request comes from, scheme included. Two kinds of page may
      // ask: the faucet's own page opened on this machine (http, the very address asked), and
      // the origins the operator listed. Behind a TLS proxy the page's own origin is one of
      // those to list: this process cannot know under which scheme it is reached.
      const origin = request.headers.origin;
      if (origin !== undefined) {
        const own = local.some((name) => origin === `http://${name}` && hostName(name) === asked);
        if (!own && !origins.has(origin)) throw new ApiError(403, 'origin_not_allowed', 'This origin may not call the faucet from a browser');
        // A page of another origin may read how long to wait: a browser hides Retry-After from it unless it is named here.
        if (!own) { response.setHeader('Access-Control-Allow-Origin', origin); response.setHeader('Access-Control-Expose-Headers', 'Retry-After'); response.setHeader('Vary', 'Origin'); }
      }
      if (request.method === 'OPTIONS' && origin !== undefined) { response.writeHead(204, { 'Access-Control-Allow-Methods': 'GET, POST', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '600' }); response.end(); return; }
      const raw = request.url || '';
      if (raw.length > MAX_URL_LENGTH) throw new ApiError(414, 'url_too_long', 'The address is too long');
      // The page, with an account named for its field (`/?account=alice`: a link may carry it, and the page shows it
      // in the field, where the person can change it, and asks for nothing by itself). The one query any address
      // here takes: `account`, once, in the form the page accepts (web-v4/faucet/app.js, accountFromAddress).
      // Before 2026-11-24 it was refused like any query, and the page's prefill never worked.
      const target = servePage && PREFILL.test(raw) ? '/' : raw;
      // A plain path and nothing else: no route here takes a query.
      if (!/^\/[A-Za-z0-9/._-]*$/.test(target) || target.includes('//') || target.includes('..')) throw new ApiError(400, 'invalid_url', 'The address is a plain path such as /v1/faucet, without a query');
      const lookupMatch = /^\/v1\/faucet\/grants\/([0-9A-Fa-f]{64})$/.exec(target);
      const path = lookupMatch ? '/v1/faucet/grants/{hash}' : target;
      const methods = ['GET', 'POST'].filter((method) => HANDLERS[`${method} ${path}`]);
      const static_ = Object.hasOwn(page, target) ? page[target] : null;
      // Every request counts against its sender before anything is done for it.
      const caller = callerOf(request);
      const wait = limiter.take(caller, request.method === 'POST' ? 10 : 1);
      if (wait) throw new ApiError(429, 'rate_limited', 'Too many requests from this address', { retryAfter: wait });
      if (static_) {
        if (request.method !== 'GET' && request.method !== 'HEAD') throw new ApiError(405, 'method_not_allowed', 'This route does not take that method', { allow: 'GET' });
        response.writeHead(200, { 'Content-Type': static_.type, 'Content-Length': static_.body.length, 'Content-Security-Policy': PAGE_POLICY });
        response.end(request.method === 'HEAD' ? undefined : static_.body); return;
      }
      if (methods.length === 0) throw new ApiError(404, 'unknown_route', 'No such route; GET /v1/faucet says what this faucet gives');
      if (!methods.includes(request.method)) throw new ApiError(405, 'method_not_allowed', 'This route does not take that method', { allow: methods.join(', ') });
      const body = request.method === 'POST' ? await readBody(request) : undefined;
      const result = await HANDLERS[`${request.method} ${path}`]({ body, caller, hash: lookupMatch?.[1].toUpperCase() });
      reply(response, result.status, result.body);
    } catch (error) {
      if (response.headersSent) { response.destroy(); return; }
      if (error instanceof ApiError) { failure(response, error); return; }
      log('error', 'request failed', { error: plainText(error?.message, 160) });
      failure(response, new ApiError(500, 'internal', 'The request could not be answered'));
    }
  }
  const close = () => closing ??= (async () => {
    clearInterval(timer);
    await queue;
    if (server?.listening) await new Promise((resolve) => { server.close(() => resolve()); server.closeAllConnections?.(); });
    store.close();
  })();

  // ---- start: the network and the key are checked against a proof before anything is served
  try {
    let state;
    try { state = await provenState({ ids: [account], include_security: true }); } catch (error) {
      throw new Error(error.code === 'wrong_network' ? 'The node proves the state of another network than network_id: the faucet does not start' : 'The state of the network could not be read with a valid proof: the faucet does not start without checking its network and its key');
    }
    const problem = faucetView(state).problem;
    if (problem) throw new Error(`${problem}: the faucet does not start`);
    // What an earlier run left open is settled before the first request is taken.
    await serial(() => settle(true), false);
    // Node holds a request to `requestTimeout` only when it checks, every 30 seconds unless set: every second here.
    server = http.createServer({ connectionsCheckingInterval: 1000 }, (request, response) => { handle(request, response); });
    server.on('clientError', (error, socket) => {
      if (!socket.writable || socket.bytesWritten > 0) { socket.destroy(); return; }
      const status = error?.code === 'HPE_HEADER_OVERFLOW' ? '431 Request Header Fields Too Large' : error?.code === 'ERR_HTTP_REQUEST_TIMEOUT' ? '408 Request Timeout' : '400 Bad Request';
      socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
      setTimeout(() => socket.destroy(), 1000).unref?.();
    });
    server.requestTimeout = 15000; server.headersTimeout = 5000; server.keepAliveTimeout = 5000; server.maxRequestsPerSocket = 100; server.maxConnections = 512; server.maxHeadersCount = 64;
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, () => { server.removeListener('error', reject); resolve(); }); });
  } catch (error) { await close(); throw error; }
  if (autoStart) { timer = setInterval(tick, reconcileMs); timer.unref?.(); }
  const address = server.address();
  return {
    url: `http://${address.family === 'IPv6' ? `[${address.address}]` : address.address}:${address.port}`,
    store, close,
    /// Where the key of the hashes of who asked came from at this start: 'kept', 'new' or 'memory' (loadCallerKey).
    callerKey: callers.source,
    /// One pass of settling, as the timer runs it (for tests and for the start script).
    settle: () => serial(() => settle(true), false),
  };
}

/// Every route of the faucet, for the README and the tests.
export const ROUTES = Object.freeze(['GET /v1/faucet', 'GET /v1/faucet/health', 'GET /v1/faucet/grants/{hash}', 'POST /v1/faucet/grants', 'POST /v1/faucet/registrations', 'GET /', 'GET /app.js', 'GET /styles.css']);
