// Bitcoin Core's JSON-RPC, for the two services of the market (spec/market.md): the relay of block headers
// (market-relay.mjs) and the prover of payments (market-prover.mjs). Read calls only, to nodes the operator runs.
//
// WHAT A NODE IS TRUSTED FOR: nothing that decides anything. The chain checks the proof of work, the difficulty and
// the links of every header it is handed (kind 40), and every part of a proof of payment (kind 54). So a node that
// lies or lags can do three things, and no more:
// - withhold: answer nothing, or answer "no such block". The services then use another configured node, and say
//   in their health answer which node is silent;
// - lag: show an old tip. The relay reports the age of the newest header it can find, and a second node covers it;
// - show a losing branch, or blocks it invented. The chain refuses headers without the work, and keeps a valid
//   branch with less work as a branch. A proof built from an invented block is refused: its header is not on the
//   chain the Time chain follows.
// What it cannot do is make a service send something the chain then accepts wrongly: the chain verifies by itself.
// One case needs the operator: a valid branch with more work that leaves the chain far below its tip halts the
// chain's header chain for good (spec/market.md, 10.5). The relay does not hand such a branch in by itself
// (market-relay.mjs, `deep_reorg`).
//
// What this file checks of every answer, so that an answer for something else is never used:
// - a block hash, a header and a block are held to each other: the double SHA-256 of the 80 header bytes is the
//   hash that was asked for, and the transactions of a block give the Merkle root its header names;
// - a transaction is the one whose id was asked for (the id is computed here, from the bytes);
// - every answer is bounded in size and in time, and no redirect is followed.
// AMOUNTS ARE NEVER READ FROM JSON. Bitcoin Core prints an amount as a decimal number of bitcoin, which a JSON
// parser turns into a binary fraction. An output's value is read from the bytes of its transaction
// (`transactionOutputs` of bitcoin-address.mjs), in satoshis, as a whole number.
//
// The password of a node (its cookie, or a user name and a password) is read from a file or from the config when a
// call is made, sent to that node only, and appears in no error, no log line and no health answer.
import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { stripWitness, transactionOutputs } from './bitcoin-address.mjs';

/// The calls this client makes. No other method is ever sent.
export const METHODS = Object.freeze(['getblockchaininfo', 'getbestblockhash', 'getblockhash', 'getblockheader', 'getblock', 'getrawtransaction', 'gettxoutproof']);
/// The names Bitcoin Core gives its networks (`chain` of getblockchaininfo), by the names the chain's genesis uses.
export const CORE_CHAINS = Object.freeze({ mainnet: 'main', testnet3: 'test', regtest: 'regtest' });
/// The largest block is four million bytes; in hexadecimal, inside a JSON answer, that is a little over eight.
const MAX_BLOCK_ANSWER = 9 * 1024 * 1024, MAX_SMALL_ANSWER = 256 * 1024;
const ANSWER_LIMIT = Object.freeze({ getblock: MAX_BLOCK_ANSWER, getrawtransaction: MAX_BLOCK_ANSWER });
const HASH = /^[0-9a-f]{64}$/;

/// Why a call failed. `code` is one of:
/// - UNAVAILABLE: no usable answer (not reachable, too slow, too large, a server error);
/// - UNAUTHORIZED: the node refused the name and password;
/// - REFUSED: the node answered with an error of its own (`rpcCode` is Bitcoin Core's number: -5 "not found",
///   -8 "out of range");
/// - INVALID: the answer is not what was asked for, or not in the form Bitcoin Core gives.
/// The message never holds an address, a password or anything the node sent beyond a short plain text.
export class BitcoinRpcError extends Error {
  constructor(code, message, rpcCode = null) { super(message); this.name = 'BitcoinRpcError'; this.code = code; this.rpcCode = rpcCode; }
}
const plain = (value, max = 120) => String(value ?? '').replace(/[^\x20-\x7e]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
const invalid = (what) => new BitcoinRpcError('INVALID', `The Bitcoin node's answer is not ${what}`);
const sha256d = (bytes) => createHash('sha256').update(createHash('sha256').update(bytes).digest()).digest();
/// A hash as Bitcoin software prints it: the bytes reversed, in lowercase hexadecimal.
const printed = (bytes) => Buffer.from(bytes).reverse().toString('hex');
/// The hash of a block from its 80 header bytes (lowercase hexadecimal), as Bitcoin software prints it.
export function headerHash(headerHex) {
  if (typeof headerHex !== 'string' || !/^[0-9a-f]{160}$/.test(headerHex)) throw new Error('A block header is 80 bytes in lowercase hexadecimal');
  return printed(sha256d(Buffer.from(headerHex, 'hex')));
}
/// What a header says of itself: the hash of the block before it, and its time in seconds.
export function headerFields(headerHex) {
  const hash = headerHash(headerHex), bytes = Buffer.from(headerHex, 'hex');
  return { hash, previous: printed(bytes.subarray(4, 36)), merkleRoot: bytes.subarray(36, 68).toString('hex'), time: bytes.readUInt32LE(68) };
}

// ---------------------------------------------------------------- a block, from its bytes
function sizeAt(bytes, at) {
  if (at >= bytes.length) throw invalid('a whole block');
  const first = bytes[at];
  if (first < 0xfd) return [first, at + 1];
  const width = first === 0xfd ? 2 : first === 0xfe ? 4 : 8;
  if (width === 8 || at + 1 + width > bytes.length) throw invalid('a whole block');
  return [width === 2 ? bytes.readUInt16LE(at + 1) : bytes.readUInt32LE(at + 1), at + 1 + width];
}
/// Where the transaction that starts at `at` ends. Only the lengths are followed here; each transaction is then read
/// strictly, to its last byte, by bitcoin-address.mjs.
function transactionEnd(bytes, at) {
  const need = (to) => { if (to > bytes.length) throw invalid('a whole block'); return to; };
  let p = need(at + 4), count;
  const witness = bytes[p] === 0x00;
  if (witness) p = need(p + 2);
  [count, p] = sizeAt(bytes, p);
  const inputs = count;
  for (let i = 0; i < inputs; i++) { p = need(p + 36); [count, p] = sizeAt(bytes, p); p = need(p + count + 4); }
  [count, p] = sizeAt(bytes, p);
  for (let i = count; i > 0; i--) { p = need(p + 8); let length; [length, p] = sizeAt(bytes, p); p = need(p + length); }
  if (witness) for (let i = 0; i < inputs; i++) { let items; [items, p] = sizeAt(bytes, p); for (let j = 0; j < items; j++) { let length; [length, p] = sizeAt(bytes, p); p = need(p + length); } }
  return need(p + 4);
}
/// The Merkle root of a block's transaction ids (each 32 bytes, as they stand), as Bitcoin computes it.
function merkleRoot(ids) {
  let level = ids;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(sha256d(Buffer.concat([level[i], level[i + 1] ?? level[i]])));
    level = next;
  }
  return level[0];
}
/// Reads a serialized block (lowercase hexadecimal, as `getblock <hash> 0` gives it) and holds it to itself: its
/// transactions give the Merkle root of its header. Returns `{ hash, header, previous, time, transactions }`, each
/// transaction `{ txid, hex, bareBytes }`: its id as Bitcoin software prints it, its bytes as the node gave them
/// (with witness data), and its size without witness data. The first transaction is the coinbase.
export function readBlock(blockHex) {
  if (typeof blockHex !== 'string' || blockHex.length < 162 || blockHex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(blockHex)) throw invalid('a block in lowercase hexadecimal');
  const bytes = Buffer.from(blockHex, 'hex'), header = blockHex.slice(0, 160), fields = headerFields(header);
  let [count, at] = sizeAt(bytes, 80);
  // A transaction takes at least 60 bytes: a count that cannot fit is refused before anything is allocated.
  if (count < 1 || count > (bytes.length - at) / 60) throw invalid('a whole block');
  const transactions = [], ids = [];
  for (let i = 0; i < count; i++) {
    const end = transactionEnd(bytes, at), hex = blockHex.slice(2 * at, 2 * end);
    let bare;
    try { bare = Buffer.from(stripWitness(hex), 'hex'); } catch { throw invalid('a block of whole transactions'); }
    const id = sha256d(bare);
    ids.push(id); transactions.push({ txid: printed(id), hex, bareBytes: bare.length });
    at = end;
  }
  if (at !== bytes.length) throw invalid('one whole block');
  if (merkleRoot(ids).toString('hex') !== fields.merkleRoot) throw new BitcoinRpcError('INVALID', 'The transactions the Bitcoin node gave are not those of the block header');
  return { hash: fields.hash, header, previous: fields.previous, time: fields.time, transactions };
}
/// The outputs of a block that pay one of `scripts` (a Set of receiving scripts in lowercase hexadecimal):
/// `[{ txid, vout, sats, script, index, bareBytes }]`, `sats` a decimal string read from the transaction's bytes,
/// `index` the transaction's place in the block. A coinbase output is listed too (`index` 0): the chain refuses it,
/// and the caller says so.
export function paymentsIn(block, scripts) {
  const found = [], wanted = [...scripts];
  if (wanted.length === 0) return found;
  block.transactions.forEach((transaction, index) => {
    // A script is part of the bytes of a transaction that pays it: one that holds none of them is not read further.
    if (!wanted.some((script) => transaction.hex.includes(script))) return;
    transactionOutputs(transaction.hex).forEach((output, vout) => {
      if (scripts.has(output.script)) found.push({ txid: transaction.txid, vout, sats: output.sats, script: output.script, index, bareBytes: transaction.bareBytes });
    });
  });
  return found;
}

// ---------------------------------------------------------------- one node
/// How a node is signed in to: a cookie file (Bitcoin Core writes one at every start), or a user name with a
/// password given in the config or in a file. Returns a function that reads it when a call is made, so that a new
/// cookie after a restart of the node is found.
/// - A password file must be readable by its owner only; a cookie file may also be readable by its group (the
///   node's own setting `rpccookieperms=group`), never by everyone. Windows keeps no such modes, and the check is
///   the operator's there.
export function nodeLogin({ cookieFile, user, password, passwordFile }) {
  const fromFile = async (file, most, what) => {
    let info, text;
    try { info = await stat(file); text = await readFile(file, 'utf8'); } catch { throw new BitcoinRpcError('UNAUTHORIZED', `The ${what} of a Bitcoin node could not be read`); }
    if (process.platform !== 'win32' && (info.mode & most) !== 0) throw new BitcoinRpcError('UNAUTHORIZED', `The ${what} of a Bitcoin node can be read by other users of this machine`);
    return text.replace(/\r?\n$/, '');
  };
  if (cookieFile !== undefined) return () => fromFile(cookieFile, 0o007, 'cookie file');
  if (passwordFile !== undefined) return async () => `${user}:${await fromFile(passwordFile, 0o077, 'password file')}`;
  return async () => `${user}:${password}`;
}

/// A client of one Bitcoin Core node. `url` is the node's RPC address (an origin, no user name or password in it);
/// `login` gives "name:password" (see `nodeLogin`). Every call gives up after `timeoutMs`, body included.
export function createBitcoinRpc({ url, login, fetcher = globalThis.fetch, timeoutMs = 15000 }) {
  const base = new URL(url);
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || `${base.origin}/` !== base.href) throw new Error('The address of a Bitcoin node is an http(s) origin, without user name, password, path or query');
  let id = 0;
  async function call(method, params) {
    if (!METHODS.includes(method)) throw new Error('RPC method not used by this client');
    let response, text;
    const secret = Buffer.from(await login(), 'utf8').toString('base64');
    try {
      response = await fetcher(base, { method: 'POST', redirect: 'error', cache: 'no-store', headers: { 'content-type': 'application/json', authorization: `Basic ${secret}` }, body: JSON.stringify({ jsonrpc: '1.0', id: ++id, method, params }), signal: AbortSignal.timeout(timeoutMs) });
      const limit = ANSWER_LIMIT[method] ?? MAX_SMALL_ANSWER, chunks = []; let size = 0;
      for await (const chunk of response.body ?? []) {
        size += chunk.length;
        if (size > limit) throw new BitcoinRpcError('UNAVAILABLE', 'The Bitcoin node\'s answer exceeds the size limit');
        chunks.push(chunk);
      }
      text = Buffer.concat(chunks).toString('utf8');
    } catch (error) {
      if (error instanceof BitcoinRpcError) throw error;
      // Only the system's own code of a failed connection is kept: its words can hold an address.
      const cause = String(error?.cause?.code ?? '');
      throw new BitcoinRpcError('UNAVAILABLE', error?.name === 'TimeoutError' ? 'The Bitcoin node did not answer in time' : `The Bitcoin node could not be reached${/^[A-Z][A-Z0-9_]{1,40}$/.test(cause) ? ` (${cause})` : ''}`);
    }
    if (response.status === 401 || response.status === 403) throw new BitcoinRpcError('UNAUTHORIZED', 'The Bitcoin node refused the name and password, or this machine\'s address');
    let answer = null;
    try { answer = JSON.parse(text); } catch { /* judged below */ }
    if (answer && typeof answer === 'object' && answer.error) throw new BitcoinRpcError('REFUSED', `The Bitcoin node refused ${method}: ${plain(answer.error.message) || 'no reason given'}`, Number.isInteger(answer.error.code) ? answer.error.code : null);
    if (!response.ok || !answer || typeof answer !== 'object' || !Object.hasOwn(answer, 'result')) throw new BitcoinRpcError('UNAVAILABLE', `The Bitcoin node answered HTTP ${response.status} without a result`);
    return answer.result;
  }
  const hashOf = (value, what) => { if (typeof value !== 'string' || !HASH.test(value)) throw invalid(what); return value; };
  const asked = (hash) => { if (typeof hash !== 'string' || !HASH.test(hash)) throw new Error('A block hash or a transaction id is 64 lowercase hexadecimal characters'); return hash; };
  const height = (value, what) => { if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw invalid(what); return value; };

  /// The node's view of its chain: `{ chain, blocks, bestHash, work, initialDownload }`. `chain` is Bitcoin Core's
  /// name of the network (CORE_CHAINS), `work` the total work of its best chain as a number.
  async function chainInfo() {
    const info = await call('getblockchaininfo', []);
    if (!info || typeof info !== 'object' || typeof info.chain !== 'string' || !/^[a-z0-9]{1,16}$/.test(info.chain) || typeof info.chainwork !== 'string' || !HASH.test(info.chainwork)) throw invalid('a description of its chain');
    return { chain: info.chain, blocks: height(info.blocks, 'a description of its chain'), bestHash: hashOf(info.bestblockhash, 'a description of its chain'), work: BigInt(`0x${info.chainwork}`), initialDownload: info.initialblockdownload === true };
  }
  const bestHash = async () => hashOf(await call('getbestblockhash', []), 'a block hash');
  /// The hash of the block at `at` on the node's best chain, or null when its chain is not that high.
  async function hashAt(at) {
    height(at, 'used');
    try { return hashOf(await call('getblockhash', [at]), 'a block hash'); } catch (error) { if (error instanceof BitcoinRpcError && error.rpcCode === -8) return null; throw error; }
  }
  /// The 80 bytes of a block's header, in lowercase hexadecimal. They are the header of the block asked for.
  async function header(hash) {
    const hex = await call('getblockheader', [asked(hash), false]);
    if (typeof hex !== 'string' || !/^[0-9a-f]{160}$/.test(hex) || headerHash(hex) !== hash) throw invalid('the header of the block asked for');
    return hex;
  }
  /// Where the node has a block: `{ hash, height, onBestChain, previous, time }`, or null when it does not know it.
  /// `onBestChain` is false for a block of a branch the node has left.
  async function headerInfo(hash) {
    let info;
    try { info = await call('getblockheader', [asked(hash), true]); } catch (error) { if (error instanceof BitcoinRpcError && error.rpcCode === -5) return null; throw error; }
    if (!info || typeof info !== 'object' || info.hash !== hash || !Number.isInteger(info.confirmations) || !Number.isInteger(info.time) || info.time < 0) throw invalid('the place of the block asked for');
    const at = height(info.height, 'the place of the block asked for');
    if (at > 0) hashOf(info.previousblockhash, 'the place of the block asked for');
    return { hash, height: at, onBestChain: info.confirmations >= 1, previous: at > 0 ? info.previousblockhash : null, time: info.time };
  }
  /// A block, read from its bytes and held to its header and to the hash asked for (`readBlock`).
  async function block(hash) {
    const read = readBlock(await call('getblock', [asked(hash), 0]));
    if (read.hash !== hash) throw invalid('the block asked for');
    return read;
  }
  /// A transaction of a block, as the node gives it (with witness data). Its id is the one asked for.
  async function rawTransaction(txid, blockHash) {
    const hex = await call('getrawtransaction', [asked(txid), false, asked(blockHash)]);
    let id;
    try { id = printed(sha256d(Buffer.from(stripWitness(hex), 'hex'))); } catch { throw invalid('a transaction'); }
    if (id !== txid) throw invalid('the transaction asked for');
    return hex;
  }
  /// The Merkle proof of transactions of one block (`gettxoutproof`), in lowercase hexadecimal. It is not judged
  /// here: `proofPayload` of bitcoin-address.mjs holds it to the block and to the two transactions.
  async function txOutProof(txids, blockHash) {
    const hex = await call('gettxoutproof', [txids.map(asked), asked(blockHash)]);
    if (typeof hex !== 'string' || hex.length < 172 || hex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(hex)) throw invalid('a Merkle proof');
    return hex;
  }
  return Object.freeze({ origin: base.origin, chainInfo, bestHash, hashAt, header, headerInfo, block, rawTransaction, txOutProof });
}

// ---------------------------------------------------------------- several nodes
/// The configured nodes as one source. `nodes` is `[{ name, rpc }]`, `rpc` a client of `createBitcoinRpc`.
/// - `look(network)` asks every node where it stands, at the same time, and returns one entry for each:
///   `{ name, rpc, ok, height, bestHash, work, time, downloading, problem }`. A node that does not answer, answers
///   garbage or is on another Bitcoin network than `network` has `ok: false` and a `problem` in a few plain words;
///   it is not used in that round. `time` is the time of the node's newest header. A node that says it is still
///   downloading its chain is used (what it has is checked like anything else) and marked `downloading`.
/// - `first(usable, ask)` asks the nodes of `usable` in turn and returns the first answer; a node that fails is
///   passed over. Throws the last failure when none answers.
export function createBitcoinNodes(nodes) {
  const names = nodes.map((node) => node.name);
  if (new Set(names).size !== names.length) throw new Error('Two Bitcoin nodes have the same name');
  async function look(network) {
    const wanted = CORE_CHAINS[network];
    return Promise.all(nodes.map(async ({ name, rpc }) => {
      try {
        const info = await rpc.chainInfo();
        if (info.chain !== wanted) return { name, rpc, ok: false, problem: `on another Bitcoin network (${plain(info.chain, 16)})` };
        const tip = await rpc.headerInfo(info.bestHash);
        if (!tip) return { name, rpc, ok: false, problem: 'its best block changed while it was asked' };
        return { name, rpc, ok: true, height: tip.height, bestHash: tip.hash, work: info.work, time: tip.time, downloading: info.initialDownload, problem: null };
      } catch (error) {
        return { name, rpc, ok: false, problem: error instanceof BitcoinRpcError ? `${error.code}: ${error.message}` : 'unexpected failure' };
      }
    }));
  }
  async function first(usable, ask) {
    let last = new BitcoinRpcError('UNAVAILABLE', 'No Bitcoin node is usable');
    for (const node of usable) {
      try { return await ask(node.rpc, node); } catch (error) { if (!(error instanceof BitcoinRpcError)) throw error; last = error; }
    }
    throw last;
  }
  return Object.freeze({ names, look, first });
}
