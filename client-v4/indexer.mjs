// Indexer: follows the blocks of a Time network from a CometBFT RPC and keeps, in SQLite, what
// validators do not keep: every block, every action with its hash, and the activity of each
// account. The HTTP API (api.mjs) answers from it.
//
// The index is a convenience, not a proof. But it is never filled on the RPC's word:
//
// - A header is accepted only when its hash is one the light client vouches for. The existing
//   light client (light-client.mjs, with the installed WASM verifier) verifies the newest block
//   against the configured trust anchor: validator signatures, validator-set changes, trusting
//   period. Every older header down to the next block to index is then tied to that verified
//   block by the chain of block hashes (each header names the hash of the one before it), and
//   `headerHash` below recomputes each hash from the header's fields. A header the RPC made up
//   has another hash and is refused.
// - As a cross-check, the hash this file computes for the light client's own checkpoint header
//   must equal the hash the verifier computed for it, or nothing is indexed.
// - The transactions of a block must hash to the `data_hash` of its verified header.
// - This application's validators reject a proposal in which any transaction fails, so a
//   transaction in a final block has executed. The next header commits to the results of the
//   block before it; when it arrives the indexer checks that they are all the plain successful
//   result (`results_checked`), and stops for good if they are not.
//
// Blocks are final on this network, so the index only ever grows, in height order, from the
// configured start height: an answer never changes once given, and a cursor never misses a row.
//
// What an RPC that lies or lags can still do: withhold. It can serve nothing, or old blocks. The
// index then stops growing, and `status()` says by how much it is behind.
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import './time-sdk.js';
import { createLightClient } from './light-client.mjs';
import { fetchLightBlock } from './certified-view.mjs';

const SDK = globalThis.TimeSDK;
const MAX_U64 = 18446744073709551615n;
const ANONYMOUS = MAX_U64.toString();
export const SCHEMA_VERSION = 3;
/// An hour in micros: the unit of the counts per hour (`hours()`).
export const HOUR_MICROS = 3600000000;
/// More transactions than 4 MiB of the smallest action can hold; a block answer above this is refused.
export const MAX_BLOCK_TXS = 32768;
/// The largest signed action the engine accepts (`wire::HEADER + MAX_PAYLOAD + 64`, rounded up as the gateway does).
export const MAX_ACTION_BYTES = 512 * 1024 + 512;
const HEADERS_PER_REQUEST = 20; // what CometBFT's /blockchain returns at most

/// Thrown for everything the indexer refuses. `code` is safe to show to API callers; the message
/// goes to the operator's log and never holds a URL or a secret.
export class IndexerError extends Error {
  constructor(code, message) { super(message); this.name = 'IndexerError'; this.code = code; }
}
const refuse = (code, message) => { throw new IndexerError(code, message); };
/// Faults that stop indexing until an operator has looked: the verified chain contradicts what is
/// already indexed. Neither can happen while fewer than a third of the validators are faulty.
const FATAL = new Set(['CHAIN_CONFLICT', 'RESULTS_MISMATCH']);

// ------------------------------------------------------------------ hashes
const sha256 = (...parts) => { const hash = createHash('sha256'); for (const part of parts) hash.update(part); return hash.digest(); };
const LEAF = Buffer.from([0]), NODE = Buffer.from([1]);
const EMPTY_HASH = sha256(Buffer.alloc(0));

/// The levels of the Merkle tree CometBFT builds (RFC 6962): leaves first, the root last. Pairs
/// are hashed level by level and an odd last node moves up unchanged, which gives the same tree
/// as the recursive definition.
export function merkleLevels(items) {
  const levels = [items.map((item) => sha256(LEAF, item))];
  while (levels.at(-1).length > 1) {
    const below = levels.at(-1), above = [];
    for (let i = 0; i + 1 < below.length; i += 2) above.push(sha256(NODE, below[i], below[i + 1]));
    if (below.length % 2) above.push(below.at(-1));
    levels.push(above);
  }
  return levels;
}
export function merkleRoot(items) {
  return items.length === 0 ? EMPTY_HASH : merkleLevels(items).at(-1)[0];
}
/// The proof CometBFT's /tx?prove=true gives for leaf `index`: the sibling hashes from the leaf up.
export function merkleProof(items, index) {
  const levels = merkleLevels(items), aunts = [];
  for (let depth = 0, i = index; depth < levels.length - 1; depth++, i >>= 1) {
    const level = levels[depth];
    if (i === level.length - 1 && level.length % 2) continue; // an odd last node has no sibling here
    aunts.push(level[i ^ 1]);
  }
  return { root: levels.at(-1)[0], leaf: levels[0][index], aunts };
}
/// The root of a block's transactions (`data_hash`): each leaf is the SHA-256 of a transaction.
export const transactionsRoot = (txHashes) => merkleRoot(txHashes);
/// `last_results_hash` of the block after one with `count` transactions that all executed: this
/// application answers the default result for each, whose deterministic encoding is empty.
export function successfulResultsRoot(count) {
  return merkleRoot(Array.from({ length: count }, () => Buffer.alloc(0)));
}

// Protobuf, as far as a header needs it.
function varint(value) {
  let rest = BigInt.asUintN(64, BigInt(value));
  const bytes = [];
  do { const low = Number(rest & 0x7fn); rest >>= 7n; bytes.push(rest ? low | 0x80 : low); } while (rest);
  return Buffer.from(bytes);
}
/// A varint field; proto3 leaves a zero out.
const numberField = (field, value) => (BigInt(value) === 0n ? Buffer.alloc(0) : Buffer.concat([Buffer.from([field << 3]), varint(value)]));
/// A bytes or string field; proto3 leaves an empty one out.
const bytesField = (field, bytes) => (bytes.length === 0 ? Buffer.alloc(0) : Buffer.concat([Buffer.from([(field << 3) | 2]), varint(bytes.length), bytes]));
/// An embedded message that is always written, even when empty (gogoproto "nullable = false").
const messageField = (field, bytes) => Buffer.concat([Buffer.from([(field << 3) | 2]), varint(bytes.length), bytes]);

const badHeader = (what) => refuse('RPC_INVALID', `The RPC answered a header with an invalid ${what}`);
function decimalOf(value, what, max = MAX_U64) {
  const text = typeof value === 'number' && Number.isSafeInteger(value) ? String(value) : value;
  if (typeof text !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(text) || BigInt(text) > max) badHeader(what);
  return BigInt(text);
}
/// Hex of exactly one of `sizes` bytes; a missing or empty value is the empty hash field.
function hexOf(value, what, sizes) {
  if (value === undefined || value === null || value === '') { if (!sizes.includes(0)) badHeader(what); return Buffer.alloc(0); }
  if (typeof value !== 'string' || !/^(?:[0-9A-Fa-f]{2})+$/.test(value) || !sizes.includes(value.length / 2)) badHeader(what);
  return Buffer.from(value, 'hex');
}
/// A block time as CometBFT writes it (RFC 3339, UTC, up to nine decimals): whole seconds and nanoseconds.
export function parseBlockTime(text) {
  const match = typeof text === 'string' && /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/.exec(text);
  if (!match || Number(match[1]) < 1970) badHeader('time');
  const ms = Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6]));
  // A date that does not exist (month 13, 30 February) does not survive the round trip.
  if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 19) !== text.slice(0, 19)) badHeader('time');
  return { seconds: BigInt(ms / 1000), nanos: Number((match[7] || '').padEnd(9, '0')) };
}
function blockIdBytes(id) {
  if (id === undefined || id === null) return messageField(2, Buffer.alloc(0));
  if (typeof id !== 'object') badHeader('last block id');
  const parts = id.parts ?? id.part_set_header ?? {};
  if (typeof parts !== 'object') badHeader('last block id');
  const partSet = Buffer.concat([numberField(1, decimalOf(parts.total ?? 0, 'part count', 0xffffffffn)), bytesField(2, hexOf(parts.hash, 'part set hash', [0, 32]))]);
  return Buffer.concat([bytesField(1, hexOf(id.hash, 'last block hash', [0, 32])), messageField(2, partSet)]);
}
/// The hash of a block header as CometBFT computes it (`types.Header.Hash`): the Merkle root of
/// its fourteen fields, each in its protobuf encoding. Every field this file reads from a header
/// is one of them, so a header with a verified hash cannot have been altered in any of them.
export function headerHash(header) {
  if (!header || typeof header !== 'object' || Array.isArray(header)) badHeader('form');
  const version = header.version && typeof header.version === 'object' ? header.version : badHeader('version');
  if (typeof header.chain_id !== 'string' || header.chain_id.length === 0 || header.chain_id.length > 50) badHeader('chain id');
  const height = decimalOf(header.height, 'height', (1n << 63n) - 1n);
  if (height === 0n) badHeader('height');
  const time = parseBlockTime(header.time);
  const hash32 = (name) => bytesField(1, hexOf(header[name], name, [0, 32]));
  return merkleRoot([
    Buffer.concat([numberField(1, decimalOf(version.block ?? '0', 'block version')), numberField(2, decimalOf(version.app ?? '0', 'app version'))]),
    bytesField(1, Buffer.from(header.chain_id, 'utf8')),
    numberField(1, height),
    Buffer.concat([numberField(1, time.seconds), numberField(2, time.nanos)]),
    blockIdBytes(header.last_block_id),
    hash32('last_commit_hash'),
    hash32('data_hash'),
    bytesField(1, hexOf(header.validators_hash, 'validators hash', [32])),
    hash32('next_validators_hash'),
    hash32('consensus_hash'),
    bytesField(1, hexOf(header.app_hash, 'app hash', [0, 32])),
    hash32('last_results_hash'),
    hash32('evidence_hash'),
    bytesField(1, hexOf(header.proposer_address, 'proposer address', [0, 20])),
  ]);
}

// ------------------------------------------------------------------ actions
/// Kind numbers and their names, from the SDK. The engine also reserves 23 (always refused), 63
/// (treasury) and 81 (the rule switch of an emergency release, which no release of version 4
/// executes), which the SDK does not decode: those, and any kind added later, are stored opaque.
/// A validator's upgrade signal (80) is decoded: its payload is the plan it supports, or `{}` for
/// a withdrawal. It moves nothing and pays the network fee.
export const KIND_NAMES = Object.freeze(Object.fromEntries(Object.entries(SDK.KINDS).map(([name, kind]) => [kind, name])));
const isAmount = (value) => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= MAX_U64;
const isAccount = (value) => isAmount(value) && value !== ANONYMOUS;
const ENVELOPE_DOMAIN = Buffer.from('TCDEVNET-ACTION-V1\0');

/// What an action costs, as far as its bytes tell (README of the version-5 engine, "The amount
/// of the fee"): the network's fee, nothing, or the fee but no more than the account has left.
function feeRule(kind, payload) {
  // 45 is a registration that carries a set of keys (`register_protected`): like a reveal it pays nothing, the
  // sponsor paid for its commitment.
  if ([40, 41, 42, 14, 15, 45].includes(kind) || (kind === 12 && payload?.accept === false)) return 'none';
  if ([72, 74, 76].includes(kind) || (kind === 73 && payload?.op?.type === 'replace')) return 'at_most_network_fee';
  return 'network_fee';
}
/// The indexed facts of one action. `transfers` is true when including the action moved `amount`
/// from `sender` to `recipient`: a transfer (3), a payment to a shop (10) or a payment approved
/// by several keys (73 with a `pay` operation). A payment above the daily limit (75) only asks:
/// its `request` names recipient and amount without moving anything, and its `execute` moves a
/// payment the action does not describe. `waiting` says what an action does to the payments that
/// wait: 'request', 'execute', 'cancel' (a 76 that cancels a waiting payment) or 'replace' (a 73
/// that replaces the keys, which drops them all); the store ties an execute to its request where
/// that is certain (see `followWaiting`).
export function describeAction(bytes, networkId) {
  const raw = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  let action;
  try { action = SDK.decodeAction(new Uint8Array(raw)); } catch { action = null; }
  if (!action || action.networkId !== networkId) {
    // Not decodable by the SDK. If the envelope has the usual frame, keep its kind and sender.
    const framed = raw.length >= ENVELOPE_DOMAIN.length + 93 + 64 && raw.subarray(0, ENVELOPE_DOMAIN.length).equals(ENVELOPE_DOMAIN)
      && raw.subarray(ENVELOPE_DOMAIN.length, ENVELOPE_DOMAIN.length + 32).toString('hex') === networkId
      && raw.readUInt32BE(ENVELOPE_DOMAIN.length + 89) === raw.length - ENVELOPE_DOMAIN.length - 93 - 64;
    const sender = framed ? raw.readBigUInt64BE(ENVELOPE_DOMAIN.length + 33).toString() : null;
    return { opaque: true, kind: framed ? raw[ENVELOPE_DOMAIN.length + 32] : null, sender: sender === ANONYMOUS ? null : sender,
      nonce: framed ? raw.readBigUInt64BE(ENVELOPE_DOMAIN.length + 41).toString() : null, recipient: null, amount: null, reference: null, transfers: false, feeRule: 'unknown', waiting: null };
  }
  const { kind, payload } = action;
  const waiting = kind === 75 && (payload.type === 'request' || payload.type === 'execute') ? payload.type : kind === 76 && payload.type === 'payment' ? 'cancel' : kind === 73 && payload.op?.type === 'replace' ? 'replace' : null;
  const facts = { opaque: false, kind, sender: action.from === ANONYMOUS ? null : action.from, nonce: action.nonce, recipient: null, amount: null, reference: null, transfers: false, feeRule: feeRule(kind, payload), waiting };
  const pay = kind === 3 || kind === 10 ? payload : kind === 73 && payload.op?.type === 'pay' ? payload.op : kind === 75 && payload.type === 'request' ? payload : null;
  if (pay && isAccount(pay.to) && isAmount(pay.amount)) {
    facts.recipient = pay.to; facts.amount = pay.amount; facts.transfers = kind !== 75;
    if (kind === 10 && typeof payload.reference === 'string' && /^[0-9a-f]{64}$/.test(payload.reference)) facts.reference = payload.reference;
  }
  return facts;
}

// ------------------------------------------------------------------ the RPC
const RPC_METHODS = new Set(['/status', '/commit', '/validators', '/block', '/blockchain', '/abci_query', '/broadcast_tx_sync']);
/// Text from outside (an RPC's error, a node's log line), cut down to something safe to pass on.
export const plainText = (value, max = 200) => String(value ?? '').replace(/[^\x20-\x7e]/g, ' ').slice(0, max);
/// A function `(method, parameters) => result` over a CometBFT RPC address, like the gateway's.
/// Every call has a time limit that covers the body, and an answer larger than `maxBytes` is
/// dropped unread. The address is fixed by the operator; nothing a caller sends chooses it.
export function createRpc(origin, { fetcher = globalThis.fetch, timeoutMs = 10000, maxBytes = 16 * 1024 * 1024 } = {}) {
  const base = new URL(origin);
  return async (method, parameters = {}) => {
    if (!RPC_METHODS.has(method)) throw new IndexerError('RPC_INVALID', 'RPC method not used by this service');
    const url = new URL(method, base);
    for (const [key, value] of Object.entries(parameters)) {
      if (typeof value !== 'string') throw new IndexerError('RPC_INVALID', 'RPC parameters are strings');
      url.searchParams.set(key, value);
    }
    // A submitted action can be half a megabyte: too long for an address. It goes in the body of
    // a JSON-RPC POST, where CometBFT takes the bytes as base64.
    let request = { redirect: 'error' };
    if (method === '/broadcast_tx_sync') {
      const hex = /^0x((?:[0-9a-f]{2})+)$/.exec(parameters.tx ?? '');
      if (!hex) throw new IndexerError('RPC_INVALID', 'A submitted action is 0x-prefixed hexadecimal');
      url.search = '';
      url.pathname = '/';
      request = { ...request, method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'broadcast_tx_sync', params: { tx: Buffer.from(hex[1], 'hex').toString('base64') } }) };
    }
    let text, ok;
    try {
      const response = await fetcher(url, { ...request, signal: AbortSignal.timeout(timeoutMs) });
      ok = response.ok;
      const chunks = []; let size = 0;
      for await (const chunk of response.body) {
        size += chunk.length;
        if (size > maxBytes) throw new IndexerError('RPC_INVALID', 'RPC answer exceeds the size limit');
        chunks.push(chunk);
      }
      text = Buffer.concat(chunks).toString('utf8');
    } catch (error) {
      if (error instanceof IndexerError) throw error;
      throw new IndexerError('RPC_UNAVAILABLE', error?.name === 'TimeoutError' ? 'The RPC did not answer in time' : 'The RPC could not be reached');
    }
    let answer;
    try { answer = JSON.parse(text); } catch { throw new IndexerError('RPC_INVALID', 'The RPC answer is not JSON'); }
    if (!ok || answer?.error || answer?.result === undefined || answer.result === null) {
      const failure = new IndexerError('RPC_REFUSED', 'The RPC refused the request');
      failure.rpcMessage = plainText(answer?.error?.data || answer?.error?.message || '');
      throw failure;
    }
    return answer.result;
  };
}

// ------------------------------------------------------------------ the store
const hexUpper = (bytes) => Buffer.from(bytes).toString('hex').toUpperCase();
/// A cursor names a position in chain order: "<height>.<index in block>".
export function encodeCursor(height, index) { return `${height}.${index}`; }
/// `text` is the cursor as it was given, which is what an empty page hands back. A height above
/// what a number holds exactly is beyond every block and is read as the largest one.
export function decodeCursor(text) {
  const match = typeof text === 'string' && /^([1-9][0-9]{0,15})\.(0|[1-9][0-9]{0,5})$/.exec(text);
  return match ? { height: Math.min(Number(match[1]), Number.MAX_SAFE_INTEGER), index: Number(match[2]), text } : null;
}

/// Opens (or creates) the index of one network. The file belongs to that network and start
/// height for good; another network or start height is refused, never mixed in.
export function openIndex({ filename, networkId, chainId, startHeight = 1 }) {
  if (typeof filename !== 'string' || !filename) throw new Error('The index needs a file name');
  if (!/^[0-9a-f]{64}$/.test(networkId ?? '') || typeof chainId !== 'string' || !chainId) throw new Error('The index needs the network id and chain id of the trust manifest');
  if (!Number.isSafeInteger(startHeight) || startHeight < 1) throw new Error('start_height is a whole number from 1');
  const db = new DatabaseSync(filename);
  // The index can be rebuilt from the chain, so a commit need not reach the disk before the next
  // block: after a power cut SQLite is consistent and the indexer continues where the file ends.
  db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS verified (height INTEGER PRIMARY KEY, hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS blocks (
      height INTEGER PRIMARY KEY, hash TEXT NOT NULL, previous_hash TEXT NOT NULL, time_micros INTEGER NOT NULL, time TEXT NOT NULL,
      proposer TEXT NOT NULL, app_hash TEXT NOT NULL, data_hash TEXT NOT NULL, tx_count INTEGER NOT NULL, payment_count INTEGER NOT NULL,
      results_checked INTEGER NOT NULL DEFAULT 0 CHECK(results_checked IN (0, 1)));
    CREATE TABLE IF NOT EXISTS actions (
      height INTEGER NOT NULL, idx INTEGER NOT NULL, hash TEXT NOT NULL, kind INTEGER, opaque INTEGER NOT NULL CHECK(opaque IN (0, 1)),
      sender TEXT, nonce TEXT, recipient TEXT, amount TEXT, reference TEXT, transfers INTEGER NOT NULL CHECK(transfers IN (0, 1)),
      fee_rule TEXT NOT NULL, request_hash TEXT, request_status TEXT, raw BLOB NOT NULL, PRIMARY KEY (height, idx)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS actions_sender_nonce ON actions (sender, nonce) WHERE nonce <> '0';
    CREATE INDEX IF NOT EXISTS actions_hash ON actions (hash);
    CREATE INDEX IF NOT EXISTS actions_incoming ON actions (recipient, height, idx) WHERE transfers = 1;
    CREATE INDEX IF NOT EXISTS actions_outgoing ON actions (sender, height, idx) WHERE transfers = 1;
    CREATE INDEX IF NOT EXISTS actions_transfers ON actions (height, idx) WHERE transfers = 1;
    CREATE TABLE IF NOT EXISTS block_trees (height INTEGER PRIMARY KEY, tree BLOB NOT NULL);
    CREATE TABLE IF NOT EXISTS waiting_senders (sender TEXT PRIMARY KEY, executed INTEGER NOT NULL DEFAULT 0, cancelled INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS webhook_targets (target TEXT PRIMARY KEY, from_height INTEGER, skipped INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS waiting (sender TEXT NOT NULL, height INTEGER NOT NULL, idx INTEGER NOT NULL, hash TEXT NOT NULL, recipient TEXT, amount TEXT, PRIMARY KEY (sender, height, idx)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS actions_pair ON actions (recipient, sender, height, idx) WHERE transfers = 1;
    CREATE INDEX IF NOT EXISTS actions_reference ON actions (recipient, reference, height, idx) WHERE transfers = 1 AND reference IS NOT NULL;
    CREATE TABLE IF NOT EXISTS activity (account TEXT NOT NULL, height INTEGER NOT NULL, idx INTEGER NOT NULL, role TEXT NOT NULL, PRIMARY KEY (account, height, idx)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS accounts (
      account TEXT PRIMARY KEY, actions_sent INTEGER NOT NULL, payments_sent INTEGER NOT NULL, sent_micros TEXT NOT NULL,
      payments_received INTEGER NOT NULL, received_micros TEXT NOT NULL, first_height INTEGER NOT NULL, last_height INTEGER NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS outbox (
      seq INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, event_id TEXT NOT NULL, body TEXT NOT NULL,
      dead INTEGER NOT NULL DEFAULT 0 CHECK(dead IN (0, 1)), attempts INTEGER NOT NULL DEFAULT 0, UNIQUE (target, event_id));
    CREATE INDEX IF NOT EXISTS outbox_queue ON outbox (target, dead, seq);
    CREATE TABLE IF NOT EXISTS hourly (
      hour INTEGER PRIMARY KEY, blocks INTEGER NOT NULL, actions INTEGER NOT NULL, payments INTEGER NOT NULL, moved_micros TEXT NOT NULL);
  `);
  const getMeta = db.prepare('SELECT value FROM meta WHERE key = ?'), putMeta = db.prepare('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value');
  const scope = { schema: String(SCHEMA_VERSION), network_id: networkId, chain_id: chainId, start_height: String(startHeight) };
  for (const [key, value] of Object.entries(scope)) {
    const stored = getMeta.get(key)?.value;
    if (stored === undefined) putMeta.run(key, value);
    else if (stored !== value) {
      db.close();
      throw new Error(key === 'start_height'
        ? `This index starts at height ${stored}; an index is filled in height order from its start, so another start height needs a new data directory`
        : `This index belongs to another ${key.replace('_', ' ')}; use a new data directory`);
    }
  }

  const statements = {
    high: db.prepare('SELECT MAX(height) AS height FROM blocks'),
    block: db.prepare('SELECT * FROM blocks WHERE height = ?'),
    blocksBefore: db.prepare('SELECT * FROM blocks WHERE height < ? ORDER BY height DESC LIMIT ?'),
    blocksAfter: db.prepare('SELECT * FROM blocks WHERE height > ? ORDER BY height ASC LIMIT ?'),
    insertBlock: db.prepare('INSERT INTO blocks (height, hash, previous_hash, time_micros, time, proposer, app_hash, data_hash, tx_count, payment_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
    checkResults: db.prepare('UPDATE blocks SET results_checked = 1 WHERE height = ?'),
    insertAction: db.prepare('INSERT INTO actions (height, idx, hash, kind, opaque, sender, nonce, recipient, amount, reference, transfers, fee_rule, request_hash, request_status, raw) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
    setPaymentCount: db.prepare('UPDATE blocks SET payment_count = ? WHERE height = ?'),
    setRequestStatus: db.prepare('UPDATE actions SET request_status = ? WHERE height = ? AND idx = ?'),
    actionBySenderNonce: db.prepare("SELECT a.*, b.time, b.time_micros, b.results_checked FROM actions a INDEXED BY actions_sender_nonce JOIN blocks b ON b.height = a.height WHERE a.sender = ? AND a.nonce = ? AND a.nonce <> '0' AND a.hash <> ? ORDER BY a.height ASC, a.idx ASC LIMIT 1"),
    webhookTarget: db.prepare('SELECT from_height FROM webhook_targets WHERE target = ?'),
    webhookRegister: db.prepare('INSERT OR IGNORE INTO webhook_targets (target, from_height) VALUES (?, NULL)'),
    webhookForget: db.prepare('DELETE FROM webhook_targets WHERE target = ?'),
    webhookList: db.prepare('SELECT target FROM webhook_targets'),
    webhookStart: db.prepare('UPDATE webhook_targets SET from_height = ? WHERE from_height IS NULL'),
    webhookSkip: db.prepare('UPDATE webhook_targets SET skipped = skipped + 1 WHERE target = ?'),
    webhookSkipped: db.prepare('SELECT COALESCE(SUM(skipped), 0) AS skipped, COUNT(*) AS targets, SUM(from_height IS NULL) AS waiting FROM webhook_targets'),
    insertTree: db.prepare('INSERT INTO block_trees (height, tree) VALUES (?, ?)'),
    tree: db.prepare('SELECT tree FROM block_trees WHERE height = ?'),
    actionHashAt: db.prepare('SELECT hash FROM actions WHERE height = ? AND idx = ?'),
    waitingFollowed: db.prepare('SELECT executed, cancelled FROM waiting_senders WHERE sender = ?'),
    waitingFollow: db.prepare('INSERT INTO waiting_senders (sender) VALUES (?) ON CONFLICT (sender) DO UPDATE SET executed = 0, cancelled = 0'),
    waitingSettled: db.prepare('UPDATE waiting_senders SET executed = ?, cancelled = ? WHERE sender = ?'),
    waitingUnfollow: db.prepare('DELETE FROM waiting_senders WHERE sender = ?'),
    waitingAdd: db.prepare('INSERT INTO waiting (sender, height, idx, hash, recipient, amount) VALUES (?, ?, ?, ?, ?, ?)'),
    waitingOf: db.prepare('SELECT height, idx, hash, recipient, amount FROM waiting WHERE sender = ? ORDER BY height ASC, idx ASC'),
    waitingClear: db.prepare('DELETE FROM waiting WHERE sender = ?'),
    insertActivity: db.prepare('INSERT OR IGNORE INTO activity (account, height, idx, role) VALUES (?, ?, ?, ?)'),
    account: db.prepare('SELECT * FROM accounts WHERE account = ?'),
    putAccount: db.prepare(`INSERT INTO accounts (account, actions_sent, payments_sent, sent_micros, payments_received, received_micros, first_height, last_height) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (account) DO UPDATE SET actions_sent = excluded.actions_sent, payments_sent = excluded.payments_sent, sent_micros = excluded.sent_micros,
      payments_received = excluded.payments_received, received_micros = excluded.received_micros, last_height = excluded.last_height`),
    actionByHash: db.prepare('SELECT a.*, b.time, b.time_micros, b.hash AS block_hash, b.results_checked, b.tx_count FROM actions a JOIN blocks b ON b.height = a.height WHERE a.hash = ? ORDER BY a.height ASC, a.idx ASC LIMIT 2'),
    blockTxHashes: db.prepare('SELECT hash FROM actions WHERE height = ? ORDER BY idx ASC'),
    blockActions: db.prepare('SELECT a.height, a.idx, a.hash, a.kind, a.opaque, a.sender, a.nonce, a.recipient, a.amount, a.reference, a.transfers, a.fee_rule, a.request_hash, a.request_status, b.time, b.time_micros, b.results_checked FROM actions a JOIN blocks b ON b.height = a.height WHERE a.height = ? AND a.idx > ? ORDER BY a.idx ASC LIMIT ?'),
    verifiedAt: db.prepare('SELECT hash FROM verified WHERE height = ?'),
    verifiedLowest: db.prepare('SELECT height, hash FROM verified ORDER BY height ASC LIMIT 1'),
    verifiedCount: db.prepare('SELECT COUNT(*) AS count FROM verified'),
    putVerified: db.prepare('INSERT INTO verified (height, hash) VALUES (?, ?) ON CONFLICT (height) DO UPDATE SET hash = excluded.hash'),
    dropVerified: db.prepare('DELETE FROM verified WHERE height <= ?'),
    clearVerified: db.prepare('DELETE FROM verified'),
    kvGet: db.prepare('SELECT value FROM kv WHERE key = ?'),
    kvPut: db.prepare('INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value'),
    enqueue: db.prepare('INSERT OR IGNORE INTO outbox (target, event_id, body) VALUES (?, ?, ?)'),
    outboxNext: db.prepare('SELECT seq, event_id, body, attempts FROM outbox WHERE target = ? AND dead = 0 ORDER BY seq ASC LIMIT 1'),
    outboxDone: db.prepare('DELETE FROM outbox WHERE seq = ?'),
    outboxTried: db.prepare('UPDATE outbox SET attempts = attempts + 1 WHERE seq = ?'),
    outboxDead: db.prepare('UPDATE outbox SET dead = 1, attempts = attempts + 1 WHERE seq = ?'),
    outboxCounts: db.prepare('SELECT target, dead, COUNT(*) AS count FROM outbox GROUP BY target, dead'),
    outboxTargets: db.prepare('SELECT DISTINCT target FROM outbox'),
    outboxDropTarget: db.prepare('DELETE FROM outbox WHERE target = ?'),
    outboxOverflow: db.prepare('DELETE FROM outbox WHERE target = ? AND dead = 0 AND seq <= (SELECT seq FROM outbox WHERE target = ? AND dead = 0 ORDER BY seq DESC LIMIT 1 OFFSET ?)'),
    outboxDeadOverflow: db.prepare('DELETE FROM outbox WHERE target = ? AND dead = 1 AND seq <= (SELECT seq FROM outbox WHERE target = ? AND dead = 1 ORDER BY seq DESC LIMIT 1 OFFSET ?)'),
    hour: db.prepare('SELECT blocks, actions, payments, moved_micros FROM hourly WHERE hour = ?'),
    putHour: db.prepare('INSERT INTO hourly (hour, blocks, actions, payments, moved_micros) VALUES (?, ?, ?, ?, ?) ON CONFLICT (hour) DO UPDATE SET blocks = excluded.blocks, actions = excluded.actions, payments = excluded.payments, moved_micros = excluded.moved_micros'),
    hours: db.prepare('SELECT hour, blocks, actions, payments, moved_micros FROM hourly ORDER BY hour ASC'),
  };
  // Lists in chain order, either way, from a cursor. One prepared statement per shape; every
  // value a caller chose is a bound parameter.
  const listing = (select, where, order) => db.prepare(`${select} WHERE ${where} AND (a.height, a.idx) ${order === 'asc' ? '>' : '<'} (?, ?) ORDER BY a.height ${order}, a.idx ${order} LIMIT ?`);
  const ACTION_COLUMNS = 'a.height, a.idx, a.hash, a.kind, a.opaque, a.sender, a.nonce, a.recipient, a.amount, a.reference, a.transfers, a.fee_rule, a.request_hash, a.request_status, b.time, b.time_micros, b.results_checked';
  const activitySelect = `SELECT ${ACTION_COLUMNS}, v.role FROM activity v JOIN actions a ON a.height = v.height AND a.idx = v.idx JOIN blocks b ON b.height = a.height`;
  const paymentSelect = `SELECT ${ACTION_COLUMNS} FROM actions a JOIN blocks b ON b.height = a.height`;
  // Payments in chain order between a position and a height, for a reconnecting stream: all of
  // them, those to an account, or those from one. Each is served by its own index of payments, so
  // what is read is what is sent. The index is named, so that the plan cannot fall back to
  // reading every action of the blocks in between.
  const span = (index, where) => db.prepare(`SELECT ${ACTION_COLUMNS} FROM actions a INDEXED BY ${index} JOIN blocks b ON b.height = a.height WHERE ${where}a.transfers = 1 AND (a.height, a.idx) > (?, ?) AND a.height <= ? ORDER BY a.height ASC, a.idx ASC LIMIT ?`);
  statements.span_all = span('actions_transfers', '');
  statements.span_in = span('actions_incoming', 'a.recipient = ? AND ');
  statements.span_out = span('actions_outgoing', 'a.sender = ? AND ');
  for (const order of ['asc', 'desc']) {
    // The actions an account sent in blocks above a height, read through the account's own activity: what is
    // read is what the account has in those blocks, never the blocks themselves.
    statements[`sent_above_${order}`] = db.prepare(`${activitySelect} WHERE v.account = ? AND v.role = 'sender' AND v.height > ? ORDER BY v.height ${order}, v.idx ${order} LIMIT ?`);
    statements[`activity_${order}`] = db.prepare(`${activitySelect} WHERE v.account = ? AND (v.height, v.idx) ${order === 'asc' ? '>' : '<'} (?, ?) ORDER BY v.height ${order}, v.idx ${order} LIMIT ?`);
    statements[`payments_${order}`] = listing(paymentSelect, 'a.recipient = ? AND a.transfers = 1', order);
    statements[`payments_reference_${order}`] = listing(paymentSelect, 'a.recipient = ? AND a.transfers = 1 AND a.reference = ?', order);
    statements[`payments_sender_${order}`] = listing(paymentSelect, 'a.recipient = ? AND a.transfers = 1 AND a.sender = ?', order);
    statements[`payments_reference_sender_${order}`] = listing(paymentSelect, 'a.recipient = ? AND a.transfers = 1 AND a.reference = ? AND a.sender = ?', order);
  }

  /// Ties the completion of a payment above the daily limit (kind 75 `execute`) to its request,
  /// where the bytes of the chain make that certain, and records how each request ended. The
  /// engine keeps the waiting payments of a secured account in its security row under numbers the
  /// actions do not carry, so the index cannot look one up. What it can know, from the actions alone:
  /// - after the account adopts the rules (70), is frozen (72), finishes a replacement of its keys
  ///   (74) or asks for one (73 `replace`, with or without a spend key), nothing is waiting
  ///   (`security.rs`: a new row, `drop_waiting`);
  /// - nothing is waiting before a request with nonce 1. Every request takes the account's next
  ///   nonce, so that is the account's first action with a nonce: an account that adopted the rules
  ///   (70) or had its keys replaced used one before. Such an account had its rules from its first
  ///   block: a registration that carries its keys (45) or a protected account of the genesis. The
  ///   bytes of a registration name no account number, so the account is followed from that request;
  /// - only a `request` adds a waiting payment, and each adds exactly one;
  /// - an `execute` or a cancellation in a block removed exactly one that was waiting.
  /// So from such a point on, the requests seen since (the set) hold everything that waits, and at
  /// most as many wait as the set holds requests less the completions and cancellations seen.
  /// - One request in the set and nothing settled yet: an `execute` completes that one. The action
  ///   then moves the request's amount to the request's recipient and is stored as a payment.
  /// - More than one: which request a completion or cancellation ends is not known, and nothing is
  ///   attributed: a wrong recipient would be worse than none. They are counted. When as many
  ///   have been seen as the set holds requests, none is waiting any more and the set is empty
  ///   again, so the next lone request is followed like the first.
  /// - An action of the account that could not be decoded may have added or removed one: the
  ///   account is not followed again until the next point where nothing is waiting.
  /// How a request ended is written to its row (`request_status`), the one field of a stored
  /// action that changes later: waiting, completed, cancelled, dropped (a freeze or a replacement
  /// of keys took it), ended (settled together with others, so that it is not known whether it was
  /// completed or cancelled), unknown (the account is not followed).
  /// Called in block order, inside the transaction that stores the block, before the action is stored.
  function followWaiting(action, height, idx) {
    const { kind, sender } = action;
    if (sender === null || kind === null) return;
    const finish = (status) => { for (const request of statements.waitingOf.all(sender)) statements.setRequestStatus.run(status, request.height, request.idx); statements.waitingClear.run(sender); };
    let followed = statements.waitingFollowed.get(sender);
    // A first request (nonce 1) of an account that is not followed: nothing waits before it (see above).
    if (!followed && kind === 75 && action.waiting === 'request' && !action.opaque && action.nonce === '1') { statements.waitingFollow.run(sender); followed = statements.waitingFollowed.get(sender); }
    if (kind === 70 || kind === 72 || kind === 74 || (kind === 73 && action.waiting === 'replace')) {
      // Whatever still waited is gone. If some of the set were settled before, it is not known which.
      if (followed) finish(followed.executed + followed.cancelled === 0 ? 'dropped' : 'ended');
      statements.waitingFollow.run(sender);
      return;
    }
    if (kind !== 75 && kind !== 76) return;
    if (action.waiting === 'request') action.requestStatus = followed ? 'waiting' : 'unknown';
    if (!followed) return;
    if (action.opaque || (kind === 75 && action.waiting === null)) {
      if (kind === 75) { finish('unknown'); statements.waitingUnfollow.run(sender); }
      return;
    }
    if (action.waiting === 'request') { statements.waitingAdd.run(sender, height, idx, action.hash, action.recipient, action.amount); return; }
    if (action.waiting !== 'execute' && action.waiting !== 'cancel') return; // a cancellation of something else
    const requests = statements.waitingOf.all(sender);
    if (requests.length === 0) return; // nothing known to wait: not expected of a block; nothing to conclude
    let { executed, cancelled } = followed;
    if (requests.length === 1 && executed + cancelled === 0) {
      const [request] = requests;
      if (action.waiting === 'execute' && request.recipient !== null) {
        action.recipient = request.recipient; action.amount = request.amount; action.transfers = true; action.requestHash = request.hash;
      }
      finish(action.waiting === 'execute' ? 'completed' : 'cancelled');
      return;
    }
    if (action.waiting === 'execute') executed += 1; else cancelled += 1;
    if (executed + cancelled < requests.length) { statements.waitingSettled.run(executed, cancelled, sender); return; }
    // Every request of the set is settled: all completed, all cancelled, or some of each.
    finish(cancelled === 0 ? 'completed' : executed === 0 ? 'cancelled' : 'ended');
    statements.waitingSettled.run(0, 0, sender);
  }
  let closed = false;
  function transaction(work) {
    db.exec('BEGIN IMMEDIATE');
    try { const result = work(); db.exec('COMMIT'); return result; } catch (error) { db.exec('ROLLBACK'); throw error; }
  }
  /// Adds a block's counts to the hour of its time (UTC hours since 1970). Inside the transaction that writes it.
  function countHour(timeMicros, actions, payments, moved) {
    const hour = Math.floor(timeMicros / HOUR_MICROS), row = statements.hour.get(hour);
    statements.putHour.run(hour, (row?.blocks ?? 0) + 1, (row?.actions ?? 0) + actions, (row?.payments ?? 0) + payments, (BigInt(row?.moved_micros ?? '0') + moved).toString());
  }
  // The counts per hour (`hours()`, for the API's figures) came after the index. `hourly_through` is the height they
  // count up to, written with each block. An index written before them, or blocks written by a program that does not
  // keep them (an older release run on the same data), are counted when the index opens, in one transaction: an index
  // with no mark from scratch, one whose mark is below its highest block from the block after the mark.
  {
    const mark = getMeta.get('hourly_through')?.value, high = statements.high.get().height ?? 0;
    if (mark === undefined || Number(mark) < high) {
      transaction(() => {
        const from = mark === undefined ? 0 : Number(mark), hours = new Map();
        if (mark === undefined) db.exec('DELETE FROM hourly');
        for (const row of db.prepare(`SELECT time_micros / ${HOUR_MICROS} AS hour, COUNT(*) AS blocks, SUM(tx_count) AS actions, SUM(payment_count) AS payments FROM blocks WHERE height > ? GROUP BY hour`).all(from))
          hours.set(row.hour, { blocks: row.blocks, actions: row.actions, payments: row.payments, moved: 0n });
        for (const row of db.prepare(`SELECT b.time_micros / ${HOUR_MICROS} AS hour, a.amount FROM actions a INDEXED BY actions_transfers JOIN blocks b ON b.height = a.height WHERE a.transfers = 1 AND a.height > ?`).all(from))
          hours.get(row.hour).moved += BigInt(row.amount);
        for (const [hour, h] of hours) {
          const row = statements.hour.get(hour);
          statements.putHour.run(hour, (row?.blocks ?? 0) + h.blocks, (row?.actions ?? 0) + h.actions, (row?.payments ?? 0) + h.payments, (BigInt(row?.moved_micros ?? '0') + h.moved).toString());
        }
        putMeta.run('hourly_through', String(high));
      });
    }
  }
  const store = {
    networkId, chainId, startHeight,
    /// The highest indexed height, or null while the index is empty.
    high: () => statements.high.get().height ?? null,
    block: (height) => statements.block.get(height) ?? null,
    blocksBefore: (height, limit) => statements.blocksBefore.all(height, limit),
    blocksAfter: (height, limit) => statements.blocksAfter.all(height, limit),
    blockActions: (height, afterIndex, limit) => statements.blockActions.all(height, afterIndex, limit),
    blockTxHashes: (height) => statements.blockTxHashes.all(height).map((row) => row.hash),
    /// The action with this hash (upper-case hex): the first inclusion, and whether there are more.
    actionByHash(hash) {
      const rows = statements.actionByHash.all(hash);
      return rows.length ? { ...rows[0], repeated: rows.length > 1 } : null;
    },
    account: (account) => statements.account.get(account) ?? null,
    /// What the index holds, hour by hour of block time (UTC hours since 1970), oldest first: blocks, actions,
    /// payments and the micros they moved (a decimal string). Hours without a block have no row.
    hours: () => statements.hours.all().map((row) => ({ ...row })),
    /// The action of `sender` that carries `nonce`, other than the one with `hash`. A nonce is
    /// used once, so there is at most one. (Actions without a nonce carry 0 and are not looked up.)
    actionBySenderNonce: (sender, nonce, hash) => (nonce === '0' ? null : statements.actionBySenderNonce.get(sender, nonce, hash) ?? null),
    /// Webhook targets and where each starts: the height of the chain when the target was first
    /// configured. `start(height)` gives every target that has none yet this start.
    webhooks: {
      register: (target) => statements.webhookRegister.run(target),
      forget: (target) => statements.webhookForget.run(target),
      list: () => statements.webhookList.all().map((row) => row.target),
      start: (height) => Number(statements.webhookStart.run(height).changes),
      totals: () => { const row = statements.webhookSkipped.get(); return { skipped: Number(row.skipped), targets: Number(row.targets), waiting: Number(row.waiting ?? 0) }; },
    },
    /// Payments after `cursor` up to `maxHeight`, in chain order: `direction` 'all', or 'in' / 'out' of `account`.
    paymentsSpan: (direction, account, cursor, maxHeight, limit) => statements[`span_${direction}`].all(...(direction === 'all' ? [] : [account]), cursor.height, cursor.index, maxHeight, limit),
    /// The Merkle proof that action `idx` is in block `height` of `total` actions, from the tree
    /// stored with the block: the sibling hashes from the leaf up, as CometBFT gives them.
    inclusionProof(height, idx, total) {
      const leafOf = (i) => sha256(LEAF, Buffer.from(statements.actionHashAt.get(height, i).hash, 'hex'));
      const stored = total > 1 ? statements.tree.get(height)?.tree : null;
      let expected = 0;
      for (let size = total; size > 1;) { size = Math.ceil(size / 2); expected += 32 * size; }
      if (total > 1 && stored?.length !== expected) {
        // No stored tree (it should not happen): build it from the hashes of the block.
        const proof = merkleProof(statements.blockTxHashes.all(height).map((row) => Buffer.from(row.hash, 'hex')), idx);
        return { root: proof.root, leaf: proof.leaf, aunts: proof.aunts };
      }
      const tree = stored && Buffer.from(stored.buffer, stored.byteOffset, stored.length), aunts = [];
      // `start` is where the current level begins in the stored tree, which holds the levels above the leaves.
      for (let depth = 0, size = total, i = idx, start = 0; size > 1; depth++) {
        const alone = size % 2 === 1 && i === size - 1; // an odd last node has no sibling on its level
        if (!alone) aunts.push(depth === 0 ? leafOf(i ^ 1) : Buffer.from(tree.subarray(start + 32 * (i ^ 1), start + 32 * (i ^ 1) + 32)));
        if (depth > 0) start += 32 * size;
        size = Math.ceil(size / 2); i >>= 1;
      }
      const leaf = leafOf(idx);
      return { root: total > 1 ? Buffer.from(tree.subarray(tree.length - 32)) : leaf, leaf, aunts };
    },
    activity: (account, order, cursor, limit) => statements[`activity_${order}`].all(account, cursor.height, cursor.index, limit),
    /// The actions `account` sent in blocks above `height`, oldest first ('asc') or newest first ('desc').
    sentAbove: (account, height, order, limit) => statements[`sent_above_${order}`].all(account, height, limit),
    payments(account, { reference = null, sender = null }, order, cursor, limit) {
      const name = `payments${reference ? '_reference' : ''}${sender ? '_sender' : ''}_${order}`;
      const filters = [account, ...(reference ? [reference] : []), ...(sender ? [sender] : [])];
      return statements[name].all(...filters, cursor.height, cursor.index, limit);
    },
    // ---- verified header hashes waiting for their block
    verifiedHash: (height) => statements.verifiedAt.get(height)?.hash ?? null,
    verifiedLowest: () => statements.verifiedLowest.get() ?? null,
    verifiedCount: () => statements.verifiedCount.get().count,
    putVerified: (rows) => transaction(() => { for (const [height, hash] of rows) statements.putVerified.run(height, hash); }),
    clearVerified: () => statements.clearVerified.run(),
    /// A checkpoint store for a light client, kept with the index. `scope` keeps the indexer's
    /// client and the API's state client apart: each moves forward on its own.
    checkpointStorage: (scope) => ({
      getItem: async (key) => statements.kvGet.get(`${scope}:${key}`)?.value ?? null,
      setItem: async (key, value) => { statements.kvPut.run(`${scope}:${key}`, value); },
    }),
    /// Writes one verified block with its actions, the activity and totals of the accounts in it
    /// and the webhook events it causes, or nothing at all. Returns the payments of the block, and
    /// how many webhook events were left out because the block is older than their target.
    /// `webhookTargets(account)` names the targets that are told of a payment to that account;
    /// `tree` is the Merkle levels of the transaction hashes if the caller has them already.
    writeBlock({ block, actions, events = [], previousChecked, webhookTargets = () => [], tree = null }) {
      return transaction(() => {
        statements.insertBlock.run(block.height, block.hash, block.previous_hash, block.time_micros, block.time, block.proposer, block.app_hash, block.data_hash, actions.length, 0);
        if (previousChecked) statements.checkResults.run(block.height - 1);
        if (actions.length > 1) {
          const levels = tree ?? merkleLevels(actions.map((action) => Buffer.from(action.hash, 'hex')));
          statements.insertTree.run(block.height, Buffer.concat(levels.slice(1).flat()));
        }
        const totals = new Map(), payments = [];
        let skipped = 0;
        const of = (account) => {
          if (!totals.has(account)) {
            const row = statements.account.get(account);
            totals.set(account, row
              ? { ...row, sent: BigInt(row.sent_micros), received: BigInt(row.received_micros) }
              : { actions_sent: 0, payments_sent: 0, sent: 0n, payments_received: 0, received: 0n, first_height: block.height });
          }
          return totals.get(account);
        };
        actions.forEach((action, idx) => {
          // Payments above the limit first: completing one makes this action a payment, and may
          // end a request stored earlier, in this block or before.
          followWaiting(action, block.height, idx);
          statements.insertAction.run(block.height, idx, action.hash, action.kind, action.opaque ? 1 : 0, action.sender, action.nonce, action.recipient, action.amount, action.reference, action.transfers ? 1 : 0, action.feeRule, action.requestHash ?? null, action.requestStatus ?? null, action.raw);
          if (action.sender !== null) {
            statements.insertActivity.run(action.sender, block.height, idx, 'sender');
            const sender = of(action.sender); sender.actions_sent += 1;
            if (action.transfers) { sender.payments_sent += 1; sender.sent += BigInt(action.amount); }
          }
          if (action.transfers) {
            statements.insertActivity.run(action.recipient, block.height, idx, 'recipient');
            const recipient = of(action.recipient); recipient.payments_received += 1; recipient.received += BigInt(action.amount);
            const payment = paymentEvent({ ...action, height: block.height, idx, time: block.time, request_hash: action.requestHash ?? null, results_checked: 0 });
            payments.push(payment);
            for (const target of webhookTargets(action.recipient)) {
              // A target is told of payments from the height the chain had when the target was
              // first configured: never of the history before it, always of everything after,
              // however late the block is indexed. (A target the store does not know has no such start.)
              const known = statements.webhookTarget.get(target);
              if (known && (known.from_height === null || block.height < known.from_height)) { statements.webhookSkip.run(target); skipped += 1; }
              else statements.enqueue.run(target, payment.id, JSON.stringify(payment));
            }
          } else if (action.waiting === 'request' && action.recipient !== null) {
            // Nothing has moved yet, but the recipient can see that a payment to it was asked for.
            statements.insertActivity.run(action.recipient, block.height, idx, 'pending');
            of(action.recipient);
          }
        });
        statements.setPaymentCount.run(payments.length, block.height);
        countHour(block.time_micros, actions.length, payments.length, payments.reduce((sum, payment) => sum + BigInt(payment.amount), 0n));
        putMeta.run('hourly_through', String(block.height));
        for (const [account, t] of totals) statements.putAccount.run(account, t.actions_sent, t.payments_sent, t.sent.toString(), t.payments_received, t.received.toString(), t.first_height, block.height);
        for (const event of events) statements.enqueue.run(event.target, event.id, event.body);
        statements.dropVerified.run(block.height);
        return { payments, skipped };
      });
    },
    // ---- webhook queues (api.mjs delivers them)
    outbox: {
      next: (target) => statements.outboxNext.get(target) ?? null,
      done: (seq) => statements.outboxDone.run(seq),
      tried: (seq) => statements.outboxTried.run(seq),
      dead: (seq) => statements.outboxDead.run(seq),
      counts: () => statements.outboxCounts.all(),
      targets: () => statements.outboxTargets.all().map((row) => row.target),
      dropTarget: (target) => statements.outboxDropTarget.run(target).changes,
      /// Keeps the newest `keep` waiting events and the newest `keepDead` dead letters of a target.
      trim: (target, keep, keepDead) => Number(statements.outboxOverflow.run(target, target, keep).changes) + Number(statements.outboxDeadOverflow.run(target, target, keepDead).changes),
    },
    close() { if (!closed) { closed = true; db.close(); } },
  };
  return store;
}

// ------------------------------------------------------------------ the indexer
const base64Bytes = (value) => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length > 0 && bytes.length <= MAX_ACTION_BYTES && bytes.toString('base64') === value ? bytes : null;
};
const sameHash = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === 64 && a.toLowerCase() === b.toLowerCase();

/// Options:
/// - `rpc(method, parameters)`: a CometBFT RPC (createRpc). Untrusted.
/// - `trust`: the application-4 trust manifest, installed independently of the RPC.
/// - `store`: openIndex(...) for the same network.
/// - `verifier`: the installed proof verifier (proof-verifier.mjs).
/// - `webhookTargets(account)`: ids of the webhook targets that want payments to this account.
///   A target registered with the store (`store.webhooks.register`) is told of payments from the
///   height the chain had when it was registered: the first tip the light client verifies after
///   that. Building an index does not send the history before; a block made while this process
///   was down is never left out, however late it is indexed.
/// - `onBlock({ block, payments, actions })`: called after a block is stored (the API's event streams).
/// - `pollMs` (500): how long to wait when there is nothing new; `now()`; `log(level, message, fields)`.
export function createIndexer({ rpc, trust, store, verifier, webhookTargets = () => [], onBlock = () => {}, pollMs = 500, now = Date.now, log = () => {}, blocksPerStep = 64, headersPerStep = 2000 }) {
  if (typeof rpc !== 'function') throw new Error('rpc is a function (method, parameters) => result');
  if (trust?.network_id !== store.networkId || trust?.chain_id !== store.chainId) throw new Error('The index and the trust manifest are for different networks');
  const light = createLightClient({ trust, verifier, storage: store.checkpointStorage('indexer'), now, fetchBlock: (height) => fetchLightBlock({ rpc, height }) });
  const status = {
    started_at: null, tip_height_reported: null, tip_reported_at: null, last_block_at: null, last_step_at: null,
    consecutive_failures: 0, last_error: null, fault: null, headers_to_verify: 0,
  };
  let stopped = true, halting = false, running = null, timer = null, wake = null, skippedLogged = false;

  /// Makes sure a verified hash is known for height `next`: asks the light client for a verified
  /// block at or above it, then follows the chain of block hashes down, a bounded number of
  /// headers per call. Returns true once `next` is covered.
  async function anchor(next, tip) {
    let frontier = store.verifiedLowest();
    // Hashes are dropped as their blocks are stored, so none can be below the next block.
    if (frontier && frontier.height < next) { store.clearVerified(); frontier = null; }
    if (!frontier) {
      let checkpoint;
      try {
        await light.ready();
        checkpoint = light.getCheckpoint();
        if (!checkpoint || BigInt(checkpoint.height) < BigInt(next)) {
          if (tip < next) return false; // nothing new on the chain
          try { checkpoint = await light.updateTo(String(tip)); } catch (first) {
            // The newest block may not be served in full yet (its next validator set): take the one before.
            if (tip - 1 < next || /CHECKPOINT_REFRESH_REQUIRED/.test(String(first?.message))) throw first;
            checkpoint = await light.updateTo(String(tip - 1));
          }
          // The verified height of the chain right now: where webhook targets that are new start.
          const started = store.webhooks.start(Number(checkpoint.height));
          if (started) log('info', 'webhooks start at this height; payments in earlier blocks are indexed without one', { targets: started, from_height: Number(checkpoint.height) });
        }
      } catch (error) {
        if (error instanceof IndexerError) throw error;
        const text = String(error?.message ?? error);
        if (/CHECKPOINT_REFRESH_REQUIRED/.test(text)) refuse('TRUST_EXPIRED', 'The trust anchor has expired: install a freshly authenticated trust manifest');
        refuse('LIGHT_CLIENT', `The light client did not verify the newest block (${plainText(text, 120)})`);
      }
      // The light client vouches for this hash. Before following it down, check that this file
      // computes the same hash for the same header as the verifier did.
      const header = checkpoint.block?.signed_header?.header;
      if (!/^[0-9a-f]{64}$/.test(checkpoint.block_hash ?? '') || headerHash(header).toString('hex') !== checkpoint.block_hash) refuse('LIGHT_CLIENT', 'The header hash computed here differs from the light client\'s: refusing to index');
      const height = Number(checkpoint.height);
      if (!Number.isSafeInteger(height) || height < next) refuse('LIGHT_CLIENT', 'The light client returned an unusable checkpoint');
      store.putVerified([[height, checkpoint.block_hash]]);
      frontier = { height, hash: checkpoint.block_hash };
    }
    for (let budget = headersPerStep; frontier.height > next && budget > 0;) {
      // Header h gives the hash of h - 1, so the headers from the frontier down to next + 1 are needed.
      const top = frontier.height, bottom = Math.max(next + 1, top - HEADERS_PER_REQUEST + 1);
      const answer = await rpc('/blockchain', { minHeight: String(bottom), maxHeight: String(top) });
      const metas = Array.isArray(answer?.block_metas) ? answer.block_metas : refuse('RPC_INVALID', 'The RPC answered no block headers');
      if (metas.length > HEADERS_PER_REQUEST) refuse('RPC_INVALID', 'The RPC answered more headers than asked');
      const byHeight = new Map(metas.map((meta) => [String(meta?.header?.height), meta.header]));
      const rows = []; let expected = frontier.hash, height = top;
      // CometBFT may answer fewer headers than asked (never none): continue below what it gave.
      for (; height >= bottom && byHeight.has(String(height)); height--, budget--) {
        const header = byHeight.get(String(height));
        if (headerHash(header).toString('hex') !== expected) refuse('HEADER_MISMATCH', `The RPC's header ${height} is not the one the verified chain names`);
        expected = hexOf(header.last_block_id?.hash, 'last block hash', [32]).toString('hex');
        rows.push([height - 1, expected]);
      }
      if (height === top) refuse('RPC_INVALID', 'The RPC did not answer the header that was asked for');
      if (rows.length) store.putVerified(rows);
      frontier = store.verifiedLowest();
    }
    status.headers_to_verify = frontier.height - next;
    return frontier.height === next;
  }

  /// Fetches block `height`, checks it against its verified hash and stores it.
  async function indexBlock(height) {
    const expected = store.verifiedHash(height);
    const answer = await rpc('/block', { height: String(height) });
    const header = answer?.block?.header, txs = answer?.block?.data?.txs ?? [];
    if (!header || !Array.isArray(txs) || txs.length > MAX_BLOCK_TXS) refuse('RPC_INVALID', 'The RPC answered an unusable block');
    const hash = headerHash(header).toString('hex');
    if (hash !== expected) refuse('HEADER_MISMATCH', `The RPC's block ${height} is not the one the verified chain names`);
    // From here on the header is authentic: every field read below is covered by its hash.
    if (header.chain_id !== store.chainId || String(header.height) !== String(height)) refuse('HEADER_MISMATCH', 'A verified header belongs to another chain or height');

    const raws = txs.map((encoded) => base64Bytes(encoded) ?? refuse('RPC_INVALID', 'The RPC answered a transaction that is not canonical base64'));
    const digests = raws.map((raw) => sha256(raw));
    const dataHash = hexOf(header.data_hash, 'data hash', [0, 32]);
    // A block without transactions has the hash of nothing, or no data hash at all.
    const tree = raws.length === 0 ? null : merkleLevels(digests);
    const dataMatches = raws.length === 0 ? dataHash.length === 0 || dataHash.equals(EMPTY_HASH) : dataHash.equals(tree.at(-1)[0]);
    if (!dataMatches) refuse('DATA_MISMATCH', `The RPC's transactions of block ${height} are not the ones its verified header commits to`);

    // This header continues what is indexed, and commits to the results of the block before it.
    const previous = store.block(height - 1);
    const previousHash = hexOf(header.last_block_id?.hash, 'last block hash', [0, 32]).toString('hex');
    let previousChecked = false;
    if (previous) {
      if (previous.hash !== previousHash) refuse('CHAIN_CONFLICT', `The verified block ${height} does not continue the indexed block ${height - 1}`);
      const results = hexOf(header.last_results_hash, 'last results hash', [0, 32]);
      const allSucceeded = previous.tx_count === 0 ? results.length === 0 || results.equals(EMPTY_HASH) : results.equals(successfulResultsRoot(previous.tx_count));
      if (!allSucceeded) refuse('RESULTS_MISMATCH', `Block ${height} does not commit to successful results for every transaction of block ${height - 1}`);
      previousChecked = true;
    } else if (height !== store.startHeight) refuse('CHAIN_CONFLICT', 'The index has a gap below the next block');

    const time = parseBlockTime(header.time);
    const timeMicros = Number(time.seconds) * 1e6 + Math.floor(time.nanos / 1000);
    const block = {
      height, hash, previous_hash: previousHash, time_micros: timeMicros, time: new Date(Number(time.seconds) * 1000).toISOString().slice(0, 19) + '.' + String(Math.floor(time.nanos / 1000)).padStart(6, '0') + 'Z',
      proposer: String(header.proposer_address ?? '').toUpperCase(), app_hash: String(header.app_hash ?? '').toUpperCase(), data_hash: dataHash.toString('hex').toUpperCase(),
    };
    const actions = raws.map((raw, idx) => ({ ...describeAction(raw, store.networkId), hash: hexUpper(digests[idx]), raw, idx }));
    const { payments, skipped } = store.writeBlock({ block, actions, previousChecked, tree, webhookTargets });
    // Said once per run; /v1/health counts every one.
    if (skipped && !skippedLogged) { skippedLogged = true; log('warn', 'payments in blocks from before their webhook was configured are indexed without a webhook; /v1/health counts them', { height, events: skipped }); }
    status.last_block_at = now();
    // `actions`: the block's actions as stored, with their bytes (`raw`); the recipient of a completed waiting payment is
    // filled in where the store tied it to its request. The API's hints for wallets read them (api.mjs, touch).
    try { onBlock({ block: { ...block, tx_count: actions.length, payment_count: payments.length }, payments, actions }); } catch (error) { log('error', 'a block listener failed', { error: plainText(error?.message) }); }
  }

  /// One round: learn the tip, verify headers down to the next block, index what is verified.
  /// Returns true when there is more to do right away.
  async function step() {
    if (status.fault) return false;
    const node = await rpc('/status');
    const network = node?.node_info?.network;
    if (network !== undefined && network !== store.chainId) refuse('RPC_INVALID', 'The RPC is a node of another chain');
    const tipText = node?.sync_info?.latest_block_height;
    if (typeof tipText !== 'string' || !/^(0|[1-9][0-9]{0,15})$/.test(tipText)) refuse('RPC_INVALID', 'The RPC reported no usable height');
    const tip = Number(tipText);
    status.tip_height_reported = tip; status.tip_reported_at = now();
    let next = (store.high() ?? store.startHeight - 1) + 1;
    if (!(await anchor(next, tip))) return store.verifiedLowest() !== null; // still walking down, or nothing new
    let done = 0;
    for (; done < blocksPerStep && !halting && store.verifiedHash(next); done++, next++) await indexBlock(next);
    return done === blocksPerStep || tip >= next;
  }

  async function round() {
    try {
      const more = await step();
      status.last_step_at = now(); status.consecutive_failures = 0; status.last_error = null;
      return more ? 0 : pollMs;
    } catch (error) {
      const code = error instanceof IndexerError ? error.code : 'INTERNAL';
      status.consecutive_failures += 1; status.last_error = { code, at: now() };
      if (FATAL.has(code)) { status.fault = { code, at: now() }; log('error', 'indexing stopped: the verified chain contradicts the index; an operator must look', { code, detail: plainText(error.message) }); return pollMs; }
      // The first failure and every twentieth are logged; the count is in the status meanwhile.
      if (status.consecutive_failures % 20 === 1) log('warn', 'indexing step failed; trying again', { code, detail: plainText(error?.message), failures: status.consecutive_failures });
      return Math.min(30000, pollMs * 2 ** Math.min(status.consecutive_failures, 8));
    }
  }

  return {
    /// One round, for tests and tools. Throws what the round refused.
    step,
    /// Follows the chain until `stop()`. A failed round is retried with a growing pause, at most 30 s.
    start() {
      if (!stopped) return; stopped = false; halting = false; status.started_at = now();
      const loop = async () => {
        while (!stopped) {
          const pause = await round();
          if (stopped) break;
          if (pause > 0) await new Promise((resolve) => { wake = resolve; timer = setTimeout(resolve, pause); timer.unref?.(); });
        }
      };
      running = loop();
    },
    async stop() { stopped = true; halting = true; clearTimeout(timer); wake?.(); await running; running = null; halting = false; },
    /// How far the index is, and how far behind. Heights the RPC reported are marked as such: only
    /// the indexed height and its block time are verified.
    status() {
      const high = store.high(), last = high === null ? null : store.block(high);
      const reported = status.tip_height_reported;
      return {
        start_height: store.startHeight, indexed_height: high, indexed_block_time: last?.time ?? null,
        // The age of the newest indexed block by this machine's clock: the lag that needs no word of the RPC.
        seconds_behind: last ? Math.max(0, Math.round((now() - last.time_micros / 1000) / 1000)) : null,
        tip_height_reported: reported, blocks_behind_reported: reported === null ? null : Math.max(0, reported - (high ?? store.startHeight - 1)),
        headers_to_verify: status.headers_to_verify, consecutive_failures: status.consecutive_failures,
        last_error: status.last_error && { code: status.last_error.code, at: new Date(status.last_error.at).toISOString() },
        fault: status.fault && { code: status.fault.code, at: new Date(status.fault.at).toISOString() },
        running: !stopped,
      };
    },
  };
}

/// The event of one payment, as webhooks and the event stream carry it: the fields of a list item
/// under the same names, with an id that is the same wherever and however often it is delivered.
/// Takes an action as stored (`idx`, `request_hash`, `results_checked`) with its block's height and time.
export function paymentEvent(row) {
  return {
    id: `payment:${row.hash}`, type: 'payment', source: 'index', proven: false,
    hash: row.hash, height: String(row.height), index: row.idx, time: row.time,
    kind: row.kind, kind_name: row.kind === null ? null : KIND_NAMES[row.kind] ?? null, sender: row.sender, nonce: row.nonce,
    recipient: row.recipient, amount: row.amount, reference: row.reference, transfers: true,
    request_hash: row.request_hash ?? null, results_checked: row.results_checked === 1,
  };
}
