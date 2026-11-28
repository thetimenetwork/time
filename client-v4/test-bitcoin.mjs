// Test bitcoin for a Time TEST network: the service behind deploy/test-bitcoin/start.mjs.
//
// A test network's market of seconds against bitcoin (spec/market.md) follows a private Bitcoin chain in regtest,
// which runs on the network's own machine and which nobody outside can reach. This service is the way in for
// testers: it runs that Bitcoin node, mines its blocks on a fixed pace, makes receiving addresses and pays any
// regtest address on request. The coins are play money: a regtest chain is worth nothing, by construction.
//
// What it does, and what each part holds to:
//
// - THE NODE. It starts Bitcoin Core as its child, in regtest, with no peer-to-peer side at all and its RPC on the
//   loopback address, restarts it when it ends, and stops it when the service stops. Or it uses a node that
//   already runs. Either way it sends nothing but `getblockchaininfo` to a node until that node has said its chain
//   is `regtest`, and asks again after every failed call (`createWalletRpc`).
// - ONE WALLET of that node: it mines to it, pays from it and makes the testers' addresses in it.
// - A BLOCK EVERY `blockSeconds`, never on demand, so that a page can say when the next one comes.
// - THE ARCHIVE. Every block of the best chain is written to local files, and the wallet's keys once more. A node
//   that has lost blocks (a new machine, or a node that was killed before it wrote its newest blocks to its own
//   disk) is handed them again, in order, before anything is mined: the same blocks, so the same hashes, so no
//   reorganisation for whoever follows this chain. See `createChain`.
// - THE HTTP API AND THE PAGE, under one path. Every request is limited per caller, the amounts per caller and in
//   all. From a browser, only the pages of the origins the operator listed may ask.
//
// Amounts are whole numbers of satoshis everywhere, as BigInt inside and as decimal strings in JSON. Bitcoin
// Core's RPC writes an amount as a decimal number of bitcoin; this file never lets a JSON parser turn one into a
// binary fraction (`createWalletRpc` keeps the digits as they were written), and what a payment paid is read from
// the bytes of its transaction.
//
// Nothing a caller sends reaches the node except: an address that this file's own codec accepted as a regtest
// address (to `send` and `getaddressinfo`), and an amount this file wrote. The methods sent are those of
// METHODS and no other, and no words of the node are passed on to a caller.
import http from 'node:http';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { chmod, mkdir, open, readFile, readdir, rename, unlink } from 'node:fs/promises';
import path from 'node:path';
import { addressToScript, scriptForm, scriptToAddress, transactionOutputs } from './bitcoin-address.mjs';
import { BitcoinRpcError, readBlock } from './bitcoin-rpc.mjs';
import { callerKey, normalIp } from './callers.mjs';

/// The hash of the first block of every regtest chain. The archive holds the blocks above it.
export const REGTEST_GENESIS = '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206';
/// How many blocks one file of the archive holds.
export const CHUNK_BLOCKS = 500;
/// The calls this service makes. No other method is ever sent.
export const METHODS = Object.freeze(['getblockchaininfo', 'getblockhash', 'getblock', 'generatetoaddress', 'submitblock', 'listwallets', 'loadwallet', 'createwallet', 'stop',
  'getnewaddress', 'getaddressinfo', 'getbalances', 'send', 'gettransaction', 'listdescriptors', 'importdescriptors']);
const WALLET_METHODS = new Set(['getnewaddress', 'getaddressinfo', 'getbalances', 'send', 'gettransaction', 'listdescriptors', 'importdescriptors']);
/// The forms of address the service makes for a tester, with Bitcoin Core's name for each.
export const ADDRESS_FORMS = Object.freeze({ p2wpkh: 'bech32', p2tr: 'bech32m' });
/// The smallest amount Bitcoin Core sends to each form of address (its "dust" rule at the usual 3 satoshis a byte).
export const DUST_SATS = Object.freeze({ p2pkh: 546n, p2sh: 540n, p2wpkh: 294n, p2wsh: 330n, p2tr: 330n });
/// What the service pays a block's miner for each payment, in satoshis per virtual byte, and the most a payment's
/// transaction may weigh (4,000 weight units are at most 1,000 bytes without witness data). The miner is the
/// service, so the fee comes back; the two numbers are about the SIZE of a payment. A proof of payment (kind 54)
/// carries the whole transaction and costs its sender a fee for every 256 bytes. Bitcoin Core's wallet gathers its
/// small coins into a payment whenever the fee rate is at or below the rate it thinks cheap (10): on a chain of
/// 3,400 blocks, Bitcoin Core 32.1 paid 0.05 bitcoin with 62 coins in 5,668 virtual bytes at a rate of 10, and
/// with one coin in 164 at a rate of 31 (tried on 2026-11-27). Above three times its cheap rate it looks for the
/// lightest set of coins, and the weight is a ceiling it holds to whatever the rate.
const FEE_RATE = 31, MAX_TX_WEIGHT = 4000;
/// A payment is not tried when the wallet holds less than the amount and this much for the fee.
const FEE_RESERVE_SATS = 40_000n;
/// A descriptor of the archived wallet is imported this many addresses past the last one the file knows of, so
/// that an address made after the file was last copied away is still the wallet's.
const RESTORE_AHEAD = 1000;
export const MAX_BODY_BYTES = 1024;
const BODY_MS = 5000, MAX_URL_LENGTH = 512, DAY_MS = 86_400_000, HOUR_MS = 3_600_000;
const MAX_SATS = 2_100_000_000_000_000n;
const HASH = /^[0-9a-f]{64}$/;
const NOTICE = 'Play money. This is bitcoin of a private test chain: it is worth nothing and cannot be exchanged for anything.';

const plain = (value, max = 160) => String(value ?? '').replace(/[^\x20-\x7e]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
const pause = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

// ---------------------------------------------------------------- amounts
/// Satoshis as the decimal text Bitcoin Core's RPC takes for an amount in bitcoin. Whole-number arithmetic only.
/// (The same lines as `btcText` of the market trial, campaign/lib/market-bitcoin.mjs.)
export function btcText(sats) {
  const n = BigInt(sats);
  if (n <= 0n || n > MAX_SATS) throw new Error('an amount in satoshis is from 1 to 2.1 x 10^15');
  return `${n / 100_000_000n}.${String(n % 100_000_000n).padStart(8, '0')}`;
}
/// The satoshis of an amount as Bitcoin Core writes one: digits, a point and exactly eight digits ("0.00012345").
/// Takes the text, never a number.
export function satsOfBtc(text) {
  const match = typeof text === 'string' ? /^(-?)([0-9]{1,8})\.([0-9]{8})$/.exec(text) : null;
  if (!match) throw new Error('not an amount as Bitcoin Core writes one');
  const sats = BigInt(match[2]) * 100_000_000n + BigInt(match[3]);
  return match[1] ? -sats : sats;
}
/// A whole number of satoshis from its one spelling as a decimal string, or null.
export function parseSats(text) {
  return typeof text === 'string' && /^(0|[1-9][0-9]{0,15})$/.test(text) ? BigInt(text) : null;
}

// ---------------------------------------------------------------- answers that are errors
/// An answer that is an error: `code` is stable and for programs, `message` is for people.
export class ServiceError extends Error {
  constructor(status, code, message, extra = {}) { super(message); this.name = 'ServiceError'; this.status = status; this.code = code; this.extra = extra; }
}
const bad = (code, message) => { throw new ServiceError(400, code, message); };

// ---------------------------------------------------------------- the node's RPC
/// The largest block is four million bytes; in hexadecimal, inside a JSON answer, that is a little over eight.
const ANSWER_LIMIT = Object.freeze({ getblock: 9 * 1024 * 1024 });
/// A client of one Bitcoin Core node, for a regtest chain only. `url` is the node's RPC address (an origin), `login`
/// gives "name:password" when a call is made (`nodeLogin` of bitcoin-rpc.mjs), `wallet` is the name of the wallet
/// the wallet calls go to.
/// - `chainInfo()` asks `getblockchaininfo` and throws WRONG_CHAIN unless the chain is `regtest`.
/// - `call(method, params, { timeoutMs })` sends one of METHODS. Before the first call, and again after any call
///   that got no usable answer (the node may have been replaced), it asks `chainInfo()` first: a node that is not
///   on regtest is sent nothing else.
/// - Numbers of an answer that are not whole (Bitcoin Core's amounts) come back as the text the node wrote, never
///   as a binary fraction.
/// Errors are `BitcoinRpcError` (bitcoin-rpc.mjs): UNAVAILABLE, UNAUTHORIZED, REFUSED (with `rpcCode`), INVALID,
/// and WRONG_CHAIN.
export function createWalletRpc({ url, login, wallet, fetcher = globalThis.fetch, timeoutMs = 15000 }) {
  const base = new URL(url);
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || `${base.origin}/` !== base.href) throw new Error('The address of a Bitcoin node is an http(s) origin, without user name, password, path or query');
  if (typeof wallet !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,31}$/.test(wallet)) throw new Error('The name of the wallet is 1 to 32 lower-case letters, digits, - and _');
  let id = 0, regtest = false;
  async function send(method, params, timeout) {
    let response, text;
    const secret = Buffer.from(await login(), 'utf8').toString('base64');
    try {
      response = await fetcher(new URL(WALLET_METHODS.has(method) ? `/wallet/${wallet}` : '/', base), { method: 'POST', redirect: 'error', cache: 'no-store', headers: { 'content-type': 'application/json', authorization: `Basic ${secret}` }, body: JSON.stringify({ jsonrpc: '1.0', id: ++id, method, params }), signal: AbortSignal.timeout(timeout) });
      const limit = ANSWER_LIMIT[method] ?? 1024 * 1024, chunks = []; let size = 0;
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
    // A number with a point or an exponent is kept as the node wrote it (JSON.parse gives the source text of each value).
    try { answer = JSON.parse(text, (key, value, context) => (typeof value === 'number' && !/^-?[0-9]+$/.test(context?.source ?? '') ? String(context?.source ?? value) : value)); } catch { /* judged below */ }
    if (answer && typeof answer === 'object' && answer.error) throw new BitcoinRpcError('REFUSED', `The Bitcoin node refused ${method}: ${plain(answer.error.message, 120) || 'no reason given'}`, Number.isInteger(answer.error.code) ? answer.error.code : null);
    if (!response.ok || !answer || typeof answer !== 'object' || !Object.hasOwn(answer, 'result')) throw new BitcoinRpcError('UNAVAILABLE', `The Bitcoin node answered HTTP ${response.status} without a result`);
    return answer.result;
  }
  const lost = (error) => { if (error instanceof BitcoinRpcError && error.code !== 'REFUSED') regtest = false; return error; };
  async function chainInfo({ timeoutMs: timeout = timeoutMs } = {}) {
    let info;
    try { info = await send('getblockchaininfo', [], timeout); } catch (error) { throw lost(error); }
    if (!info || typeof info !== 'object' || typeof info.chain !== 'string' || !Number.isInteger(info.blocks) || info.blocks < 0 || typeof info.bestblockhash !== 'string' || !HASH.test(info.bestblockhash)) { regtest = false; throw new BitcoinRpcError('INVALID', 'The Bitcoin node\'s answer is not a description of its chain'); }
    regtest = info.chain === 'regtest';
    if (!regtest) throw new BitcoinRpcError('WRONG_CHAIN', 'The Bitcoin node is not on regtest: this service sends it nothing else');
    return { blocks: info.blocks, bestHash: info.bestblockhash };
  }
  async function call(method, params = [], { timeoutMs: timeout = timeoutMs } = {}) {
    if (!METHODS.includes(method) || method === 'getblockchaininfo') throw new Error('RPC method not used by this service');
    if (!regtest) await chainInfo();
    try { return await send(method, params, timeout); } catch (error) { throw lost(error); }
  }
  return Object.freeze({ origin: base.origin, wallet, chainInfo, call });
}

// ---------------------------------------------------------------- the node as a child process
/// The arguments of the node: regtest, no P2P listener, no outgoing connection, no DNS seed, the network switched
/// off, and RPC on the loopback address only. (The list of the market trial, campaign/lib/market-bitcoin.mjs
/// `nodeArguments`, as it ran on AWS on 2026-11-26.)
export function nodeArguments({ datadir, rpcPort }) {
  return ['-regtest', '-server=1', `-datadir=${datadir}`, '-listen=0', '-listenonion=0', '-discover=0', '-dnsseed=0', '-fixedseeds=0', '-connect=0', '-networkactive=0',
    '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1', `-rpcport=${rpcPort}`, '-fallbackfee=0.0002', '-keypool=16', '-printtoconsole=0'];
}
/// Runs Bitcoin Core as a child of this process.
/// - `start()` uses a node that already answers on the port (one an earlier run of the service left behind), or
///   starts the program and waits until `answers()` is true. A program that ends while it starts is an error.
/// - A child that ends later is started again, after 2 seconds, then 4, up to 30.
/// - `ensure()` is for a node that was found running and has no child to watch: when it no longer answers, it is
///   started.
/// - `stop(ask)` calls `ask()` (the RPC `stop`), waits `stopMs` for the child to end, and kills it after that.
export function createNodeRunner({ program, datadir, rpcPort, answers, log = () => {}, spawner = spawn, sleep = pause, startMs = 120_000, stopMs = 45_000 }) {
  let child = null, ended = null, started = false, stopping = false, reviving = null, restarts = 0;
  const said = async () => plain((await readFile(path.join(datadir, 'regtest', 'debug.log'), 'utf8').catch(() => '')).trim().split('\n').slice(-6).join(' | ').slice(-600), 600) || 'its log is empty';
  function launch() {
    ended = null;
    const made = spawner(program, nodeArguments({ datadir, rpcPort }), { stdio: 'ignore', windowsHide: true });
    child = made;
    const over = (how) => { if (child !== made) return; child = null; ended = how; if (started && !stopping) revive(); };
    made.once('error', (error) => over({ error: plain(error?.code ?? error?.message, 60) }));
    made.once('exit', (code, signal) => over({ code, signal }));
  }
  async function untilAnswers() {
    for (const end = Date.now() + startMs; ; await sleep(250)) {
      if (await answers()) return;
      if (!child) throw new Error(`Bitcoin Core ended while starting (${JSON.stringify(ended)}): ${await said()}`);
      if (Date.now() > end) throw new Error(`Bitcoin Core did not answer on its RPC port within ${startMs / 1000} s: ${await said()}`);
    }
  }
  function revive() {
    reviving ??= (async () => {
      for (let wait = 2000; !stopping; wait = Math.min(wait * 2, 30_000)) {
        restarts += 1;
        log('error', 'the Bitcoin node ended and is started again', { ended, restarts, wait_seconds: wait / 1000 });
        await sleep(wait);
        if (stopping) break;
        try { if (await answers()) break; if (!child) launch(); await untilAnswers(); log('info', 'the Bitcoin node answers again', { restarts }); break; } catch (error) { log('error', 'the Bitcoin node did not come back', { error: plain(error.message, 300) }); }
      }
      reviving = null;
    })();
    return reviving;
  }
  return {
    async start() {
      if (await answers()) { started = true; log('warn', 'a Bitcoin node already answers on the RPC port: it is used, and stopped with the service'); return; }
      launch();
      try { await untilAnswers(); } catch (error) { stopping = true; child?.kill(); throw error; }
      started = true;
    },
    ensure() { if (started && !child && !reviving && !stopping) { ended = { found: 'no longer answering' }; revive(); } },
    async stop(ask = async () => {}) {
      // A node this runner neither started nor took over is someone else's: it is not told to stop.
      if (!started && !child) { stopping = true; return; }
      stopping = true;
      const made = child;
      try { await ask(); } catch { /* it may be gone already */ }
      if (made) {
        const gone = new Promise((resolve) => { if (child !== made) resolve(true); else made.once('exit', () => resolve(true)); });
        let timer; const late = new Promise((resolve) => { timer = setTimeout(() => resolve(false), stopMs); });
        const ended_ = await Promise.race([gone, late]); clearTimeout(timer);
        if (!ended_) { log('error', 'the Bitcoin node did not end when told to and was killed'); made.kill('SIGKILL'); await gone; }
      } else {
        for (const end = Date.now() + stopMs; Date.now() < end && await answers(); ) await sleep(250);
      }
      await reviving;
    },
    running: () => child !== null,
    restarts: () => restarts,
  };
}

// ---------------------------------------------------------------- the archive
/// The archive of a regtest chain in one local directory:
///
///   blocks-00000001.txt   the blocks at heights 1 to 500, one on each line, in lowercase hexadecimal
///   blocks-00000501.txt   heights 501 to 1,000; and so on. Only the last file holds fewer than 500 lines.
///   wallet.json           the wallet's descriptors WITH THEIR PRIVATE KEYS (file mode 600)
///
/// A file is written whole under a temporary name, synced, and renamed into place: a reader sees the old file or
/// the new one, never a part. The block at height 0 is not kept: every regtest chain begins with the same one.
/// Copying the directory elsewhere, and back, is someone else's work: this reads and writes local files only.
export function createArchive(directory, { chunk = CHUNK_BLOCKS } = {}) {
  const nameOf = (first) => `blocks-${String(first).padStart(8, '0')}.txt`, walletFile = path.join(directory, 'wallet.json');
  const firstOf = (height) => Math.floor((height - 1) / chunk) * chunk + 1;
  async function writeWhole(file, text) {
    const temporary = `${file}.${process.pid}.tmp`, handle = await open(temporary, 'w', 0o600);
    try { await handle.writeFile(text); await handle.sync(); } finally { await handle.close(); }
    await rename(temporary, file);
  }
  /// The first heights of the files, ascending. Throws when a file is missing in between.
  async function firsts() {
    const found = [];
    for (const name of await readdir(directory)) { const match = /^blocks-([0-9]{8})\.txt$/.exec(name); if (match) found.push(Number(match[1])); }
    found.sort((a, b) => a - b);
    found.forEach((first, index) => { if (first !== index * chunk + 1) throw new Error(`The archive has no file ${nameOf(index * chunk + 1)} before ${nameOf(first)}: it is not used as it is`); });
    return found;
  }
  async function linesOf(first) {
    const text = await readFile(path.join(directory, nameOf(first)), 'utf8');
    if (text !== '' && !text.endsWith('\n')) throw new Error(`The archive file ${nameOf(first)} does not end with a line break`);
    const lines = text === '' ? [] : text.slice(0, -1).split('\n');
    if (lines.length > chunk || lines.some((line) => !/^[0-9a-f]{162,}$/.test(line))) throw new Error(`The archive file ${nameOf(first)} is not a list of at most ${chunk} blocks in lowercase hexadecimal`);
    return lines;
  }
  let held = null;
  return {
    directory, chunk, firstOf,
    async prepare() {
      await mkdir(directory, { recursive: true, mode: 0o700 });
      // What a run that was cut short left under a temporary name is of no use.
      for (const name of await readdir(directory)) if (/^(?:blocks-[0-9]{8}\.txt|wallet\.json)\.[0-9]+\.tmp$/.test(name)) await unlink(path.join(directory, name)).catch(() => {});
    },
    /// Every block of the archive, in order: `{ height, hex }`.
    async* blocks() {
      const all = await firsts();
      for (const [index, first] of all.entries()) {
        const lines = await linesOf(first);
        if (index < all.length - 1 && lines.length !== chunk) throw new Error(`The archive file ${nameOf(first)} holds ${lines.length} blocks and is not the last: it is not used as it is`);
        for (const [offset, hex] of lines.entries()) yield { height: first + offset, hex };
      }
    },
    /// The block at `height`, from its file (one file's lines are kept in memory between calls).
    async block(height) {
      const first = firstOf(height);
      if (held?.first !== first) held = { first, lines: await linesOf(first) };
      const hex = held.lines[height - first];
      if (hex === undefined) throw new Error(`The archive does not hold the block at height ${height}`);
      return hex;
    },
    /// The first `count` lines of the file that begins at `first` (none when there is no such file).
    async head(first, count) { return count <= 0 ? [] : (await linesOf(first).catch((error) => { if (error.code === 'ENOENT') return []; throw error; })).slice(0, count); },
    /// Writes the file that begins at `first`; an empty list removes it.
    async write(first, lines) {
      held = null;
      if (lines.length === 0) { await unlink(path.join(directory, nameOf(first))).catch((error) => { if (error.code !== 'ENOENT') throw error; }); return; }
      await writeWhole(path.join(directory, nameOf(first)), `${lines.join('\n')}\n`);
    },
    /// Removes every file that begins above `first`.
    async dropAbove(first) { held = null; for (const other of await firsts()) if (other > first) await unlink(path.join(directory, nameOf(other))); },
    async readWallet() {
      let text;
      try { text = await readFile(walletFile, 'utf8'); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
      let value = null;
      try { value = JSON.parse(text); } catch { /* judged below */ }
      if (!value || typeof value !== 'object' || !Array.isArray(value.descriptors) || value.descriptors.length === 0 || value.descriptors.some((entry) => !entry || typeof entry.desc !== 'string')) throw new Error('wallet.json of the archive is not a list of descriptors: it is not used as it is');
      return value;
    },
    async writeWallet(value) {
      await writeWhole(walletFile, `${JSON.stringify(value, null, 1)}\n`);
      // The file was made with mode 600; a file that was there before keeps the mode it is given here.
      if (process.platform !== 'win32') await chmod(walletFile, 0o600);
    },
    /// Moves a wallet.json of another wallet out of the way, under a name that says when.
    async setWalletAside(at) { const aside = `${walletFile}.replaced-${at}`; await rename(walletFile, aside); return path.basename(aside); },
  };
}

// ---------------------------------------------------------------- the chain, as this service knows it
/// The best chain of the node, block by block, and what the service keeps of it:
/// - the hash and the time of every block, by height;
/// - which heights the transactions are in (the newest `maxTransactions` of them; every transaction of this chain
///   that is not a coinbase is a payment the wallet made);
/// - every output that pays a script of the two forms the service makes addresses of, by script: what an address
///   of the wallet has received, with the amounts read from the transactions' bytes;
/// - with an `archive`, every block as bytes, in the archive's files.
///
/// `load()` reads the archive into memory, once, before anything else.
/// `follow()` brings memory and the archive up to the node's best chain, and returns
/// `{ height, fork, restored, archiveFault }`:
/// - A NODE THAT IS BEHIND on the same chain (it holds fewer blocks than the archive, and its best block is one
///   of them) is handed the blocks it lacks, in order (`submitblock`), before anything is read from it. That is
///   how a new node on a new machine gets the old chain, and how a node that was killed before it wrote its
///   newest blocks to disk gets them back. `restored` counts them.
/// - A NODE THAT HAS ANOTHER BLOCK at a height (a reorganisation, which this service never makes itself) is
///   believed: what was kept above the last common block is dropped, the archive's files are rewritten from
///   there, and `fork` is that height. With `refuseForeign` (the first `follow` of a start), a node that shares no
///   block with a non-empty archive is refused instead: the directory belongs to another chain, and nothing in it
///   is overwritten.
/// - New blocks are read as bytes, held to the hash asked for and to their parent, and added. The last file of
///   the archive is written once per call that added blocks.
/// - A file of the archive that cannot be written does not stop the chain: the blocks stay in memory, the next
///   call writes them, and `archiveFault` says what went wrong meanwhile.
export function createChain({ rpc, archive = null, log = () => {}, maxTransactions = 100_000 }) {
  const hashes = [REGTEST_GENESIS], times = [0], outputs = new Map(), heights = new Map();
  // The blocks that are not in a finished file of the archive yet, and the height the first of them is at.
  let open_ = [], openFirst = 1, dirty = false, loaded = false;
  const wanted = (script) => (script.length === 44 && script.startsWith('0014')) || (script.length === 68 && script.startsWith('5120'));
  function add(height, hex, { keep = true, block = readBlock(hex) } = {}) {
    if (block.previous !== hashes[height - 1]) throw new BitcoinRpcError('INVALID', `The block at height ${height} does not stand on the block below it`);
    hashes.push(block.hash); times.push(block.time);
    block.transactions.forEach((transaction, index) => {
      if (index === 0) return; // the coinbase pays the miner, which is the service
      heights.delete(transaction.txid); heights.set(transaction.txid, height);
      if (heights.size > maxTransactions) heights.delete(heights.keys().next().value);
      let outs;
      try { outs = transactionOutputs(transaction.hex); } catch { return; }
      for (const out of outs) {
        if (!wanted(out.script)) continue;
        const list = outputs.get(out.script);
        if (list) list.push({ txid: transaction.txid, sats: out.sats, height }); else outputs.set(out.script, [{ txid: transaction.txid, sats: out.sats, height }]);
      }
    });
    if (archive && keep) { open_.push(hex); dirty = true; }
    return block;
  }
  /// The bytes of a block that is kept: from memory when no finished file holds it yet, from its file otherwise.
  const kept = (height) => (height >= openFirst ? open_[height - openFirst] : archive.block(height));
  /// Forgets everything above `height`.
  async function cut(height) {
    hashes.length = height + 1; times.length = height + 1;
    for (const [script, list] of outputs) { const left = list.filter((entry) => entry.height <= height); if (left.length) outputs.set(script, left); else outputs.delete(script); }
    for (const [txid, at] of heights) if (at > height) heights.delete(txid);
    if (archive) {
      // The file that holds the first block dropped is written anew with the blocks below it, and those above it go.
      const first = Math.min(openFirst, archive.firstOf(height + 1));
      open_ = first === openFirst ? open_.slice(0, height + 1 - first) : await archive.head(first, height + 1 - first);
      if (open_.length !== height + 1 - first) throw new Error(`The archive does not hold the blocks from height ${first} to ${height} that it is to keep`);
      openFirst = first; dirty = true;
      await archive.dropAbove(first);
    }
  }
  /// Writes what is not in the files yet: every full file, then the last one as far as it goes (at most once per
  /// call of `follow`, so once per new block when the service runs).
  async function settle() {
    if (!archive || !dirty) return;
    while (open_.length >= archive.chunk) { await archive.write(openFirst, open_.slice(0, archive.chunk)); open_ = open_.slice(archive.chunk); openFirst += archive.chunk; }
    await archive.write(openFirst, open_);
    dirty = false;
  }
  return {
    height: () => hashes.length - 1,
    hashAt: (height) => hashes[height] ?? null,
    bestHash: () => hashes[hashes.length - 1],
    bestTime: () => times[times.length - 1],
    /// Where a transaction is: its height, or null when no block of the best chain is known to hold it.
    heightOf: (txid) => heights.get(txid) ?? null,
    /// What a script has received in blocks: `[{ txid, sats, height }]`, oldest first.
    received: (script) => outputs.get(script) ?? [],
    async load() {
      if (loaded || !archive) { loaded = true; return 0; }
      // The lines are in the files already: nothing is written while they are read.
      for await (const { height, hex } of archive.blocks()) {
        if (height !== hashes.length) throw new Error(`The archive's blocks are not in order at height ${height}`);
        try { add(height, hex, { keep: false }); } catch (error) { throw new Error(`The archive's block at height ${height} is not a block of its chain (${plain(error?.message, 120)}): the archive is not used as it is`); }
      }
      const top = hashes.length - 1;
      openFirst = archive.firstOf(top + 1); open_ = await archive.head(openFirst, top + 1 - openFirst); dirty = false; loaded = true;
      if (open_.length !== top + 1 - openFirst) throw new Error('The archive changed while it was read');
      return top;
    },
    async follow({ refuseForeign = false } = {}) {
      let info = await rpc.chainInfo(), restored = 0, fork = null;
      const known = hashes.length - 1;
      let common = Math.min(info.blocks, known);
      while (common > 0 && await rpc.call('getblockhash', [common]) !== hashes[common]) common -= 1;
      if (common < known && common === info.blocks && archive) {
        // The node holds fewer blocks than the archive, and all it holds are the archive's: it gets the rest.
        for (let height = common + 1; height <= known; height++) {
          const said = await rpc.call('submitblock', [await kept(height)], { timeoutMs: 60_000 });
          if (said !== null && said !== 'duplicate') throw new BitcoinRpcError('INVALID', `The Bitcoin node did not take the archived block at height ${height} (${plain(said, 40)})`);
          restored += 1;
        }
        info = await rpc.chainInfo();
        common = Math.min(info.blocks, known);
        while (common > 0 && await rpc.call('getblockhash', [common]) !== hashes[common]) common -= 1;
        if (common < known && common === info.blocks) throw new BitcoinRpcError('INVALID', `The Bitcoin node took the archived blocks and stands at height ${info.blocks}, not ${known}`);
      }
      if (common < known) {
        if (refuseForeign && common === 0 && info.blocks > 0 && archive) throw new Error('The archive directory holds the blocks of another chain than the Bitcoin node\'s: nothing was overwritten. Give the service the archive of this node\'s chain, or an empty directory');
        fork = common;
        log('error', 'A REORGANISATION OF THE REGTEST CHAIN: the node holds other blocks than this service knew', { last_common_height: common, blocks_dropped: known - common, node_height: info.blocks, ...(archive ? { archive: 'rewritten from the first block that differs' } : {}) });
        await cut(common);
      }
      let archiveFault = null;
      const write = async () => { try { await settle(); archiveFault = null; } catch (error) { archiveFault = plain(error?.message, 200) || 'the archive could not be written'; } };
      try {
        for (let height = hashes.length; height <= info.blocks; height++) {
          const hash = await rpc.call('getblockhash', [height]);
          if (typeof hash !== 'string' || !HASH.test(hash)) throw new BitcoinRpcError('INVALID', 'The Bitcoin node\'s answer is not a block hash');
          const hex = await rpc.call('getblock', [hash, 0], { timeoutMs: 60_000 });
          let block;
          try { block = readBlock(hex); } catch (error) { throw error instanceof BitcoinRpcError ? error : new BitcoinRpcError('INVALID', 'The Bitcoin node\'s answer is not a block'); }
          if (block.hash !== hash) throw new BitcoinRpcError('INVALID', 'The Bitcoin node gave another block than the one asked for');
          add(height, hex, { block });
          // A long chain read for the first time is written as it comes, not held whole in memory.
          if (archive && open_.length >= 2 * archive.chunk) await write();
        }
      } catch (error) { await write(); throw error; }
      await write();
      return { height: hashes.length - 1, fork, restored, archiveFault };
    },
  };
}

// ---------------------------------------------------------------- limits
/// What callers may have in a day, counted on this machine's clock, in memory: a restart of the service forgets
/// the counts. "A day" is the 24 hours before the request, "an hour" the 60 minutes before it.
/// `payment(caller, sats)` and `address(caller)` count a request and return a function that takes the count back
/// (for a request that the node then certainly did not carry out), or throw the refusal.
export function createLimits({ perCallerPerDaySats, paymentsPerCallerPerHour, totalPerDaySats, totalPaymentsPerDay, addressesPerCallerPerDay, totalAddressesPerDay, now = Date.now }) {
  let payments = [], addresses = [];
  const trim = () => { const from = now() - DAY_MS; if (payments.length && payments[0].at <= from) payments = payments.filter((entry) => entry.at > from); if (addresses.length && addresses[0].at <= from) addresses = addresses.filter((entry) => entry.at > from); };
  const until = (entry, span) => Math.max(1, Math.ceil((entry.at + span - now()) / 1000));
  const limit = (code, message, retryAfter) => new ServiceError(429, code, message, { retryAfter });
  const sum = (list) => list.reduce((total, entry) => total + entry.sats, 0n);
  const taken = (list, entry) => () => { const at = list.indexOf(entry); if (at >= 0) list.splice(at, 1); };
  return {
    /// What `caller` may still be paid in the current day, in satoshis: its own rest, or the rest of all if smaller.
    left(caller) {
      trim();
      const own = perCallerPerDaySats - sum(payments.filter((entry) => entry.caller === caller)), all = totalPerDaySats - sum(payments);
      const least = own < all ? own : all;
      return least > 0n ? least : 0n;
    },
    payment(caller, sats) {
      trim();
      const mine = payments.filter((entry) => entry.caller === caller), hour = mine.filter((entry) => entry.at > now() - HOUR_MS);
      if (hour.length >= paymentsPerCallerPerHour) throw limit('caller_limit', `One caller gets ${paymentsPerCallerPerHour} payments in an hour`, until(hour[0], HOUR_MS));
      if (sum(mine) + sats > perCallerPerDaySats) throw limit('caller_limit', `One caller gets ${perCallerPerDaySats} satoshis in 24 hours, and this payment would pass that`, mine.length ? until(mine[0], DAY_MS) : 1);
      if (payments.length >= totalPaymentsPerDay) throw limit('daily_total', 'The service has made all the payments it makes in 24 hours', until(payments[0], DAY_MS));
      if (sum(payments) + sats > totalPerDaySats) throw limit('daily_total', 'The service has paid what it pays in 24 hours, or this payment would pass that', until(payments[0], DAY_MS));
      const entry = { at: now(), caller, sats };
      payments.push(entry);
      return taken(payments, entry);
    },
    address(caller) {
      trim();
      const mine = addresses.filter((entry) => entry.caller === caller);
      if (mine.length >= addressesPerCallerPerDay) throw limit('caller_limit', `One caller gets ${addressesPerCallerPerDay} new addresses in 24 hours`, until(mine[0], DAY_MS));
      if (addresses.length >= totalAddressesPerDay) throw limit('daily_total', 'The service has made all the addresses it makes in 24 hours', until(addresses[0], DAY_MS));
      const entry = { at: now(), caller };
      addresses.push(entry);
      return taken(addresses, entry);
    },
  };
}
/// A token bucket per caller: `burst` requests at once, refilled at `perSecond`. The table is bounded: callers whose
/// bucket is full again are forgotten, then the oldest. (The lines of `createRateLimiter` of api.mjs, so that this
/// service loads nothing of the Time SDK.)
function createRateLimiter({ perSecond = 5, burst = 20, maxClients = 10000, now = Date.now } = {}) {
  const buckets = new Map();
  return {
    /// Takes `cost` tokens. Returns 0 if allowed, or the seconds to wait.
    take(client, cost = 1) {
      const at = now();
      let bucket = buckets.get(client);
      if (!bucket) {
        if (buckets.size >= maxClients) {
          for (const [key, b] of buckets) if (b.tokens + (Math.max(0, at - b.at) / 1000) * perSecond >= burst) buckets.delete(key);
          for (const key of buckets.keys()) { if (buckets.size < maxClients) break; buckets.delete(key); }
        }
        bucket = { tokens: burst, at };
      } else buckets.delete(client);
      bucket.tokens = Math.min(burst, bucket.tokens + (Math.max(0, at - bucket.at) / 1000) * perSecond); bucket.at = at;
      buckets.set(client, bucket);
      if (bucket.tokens >= cost) { bucket.tokens -= cost; return 0; }
      return Math.max(1, Math.ceil((cost - bucket.tokens) / perSecond));
    },
  };
}
/// Whether a request announces a body: a length other than 0, or a transfer coding.
const carriesBody = (headers) => headers['transfer-encoding'] !== undefined || (headers['content-length'] !== undefined && headers['content-length'] !== '0');
/// Whether a browser loads this address for a page of another site in a way the page needs no permission for (an
/// image, a script, a frame): such a request carries no Origin, so the origin rule never sees it. The fetch
/// metadata says what kind a request is. From another site two kinds pass: a CORS request, which the origin rule
/// then decides, and a person's own navigation to the address (a link followed). A request without the headers
/// comes from a program, or from a browser that does not send them. (The rule of api.mjs, `embeddedElsewhere`.)
function embeddedElsewhere(headers) {
  const site = headers['sec-fetch-site'], mode = headers['sec-fetch-mode'], dest = headers['sec-fetch-dest'];
  if (site !== 'cross-site' && site !== 'same-site') return false;
  if (mode === 'cors') return false;
  if (mode === 'navigate') return dest !== undefined && dest !== 'document';
  return true;
}

// ---------------------------------------------------------------- the service
/// The files of the page, by the path under the service's base path. app.mjs loads the address codec as
/// ../shared/bitcoin-address.mjs, which is the same path in the repository and under the base path.
const PAGE_FILES = Object.freeze({
  '/': ['test-bitcoin/index.html', 'text/html; charset=utf-8'],
  '/test-bitcoin/app.mjs': ['test-bitcoin/app.mjs', 'text/javascript; charset=utf-8'],
  '/test-bitcoin/styles.css': ['test-bitcoin/styles.css', 'text/css; charset=utf-8'],
  '/shared/bitcoin-address.mjs': ['shared/bitcoin-address.mjs', 'text/javascript; charset=utf-8'],
  // The menu of the public networks that every page of the project carries.
  '/shared/network-menu.js': ['shared/network-menu.js', 'text/javascript; charset=utf-8'],
  '/shared/network-menu.css': ['shared/network-menu.css', 'text/css; charset=utf-8'],
});
/// The page's address with what fills its pay form: `?address=` and `?sats=`, each at most once, in either order.
const PREFILL = /^\/\?(?:address=[A-Za-z0-9]{14,90}(?:&sats=[0-9]{1,16})?|sats=[0-9]{1,16}(?:&address=[A-Za-z0-9]{14,90})?)$/;

/// Starts the service and returns `{ url, close, tick, health, chain }` once it is ready.
/// - `rpc`: a client of the node (`createWalletRpc`).
/// - `runner`: the node as a child process (`createNodeRunner`), or null for a node that someone else runs.
/// - `archive`: `createArchive(directory)`, or null.
/// - `blockSeconds`, and the limits: `maxPaymentSats`, `perCallerPerDaySats`, `totalPerDaySats` (BigInt),
///   `paymentsPerCallerPerHour`, `totalPaymentsPerDay`, `addressesPerCallerPerDay`, `totalAddressesPerDay`.
/// - `host`, `port`, `hosts`, `origins`, `basePath`, `rateLimit`, `trustedProxies`, `servePage`: the listening side.
///   `origins` lists the origins whose pages may ask from a browser, each whole (scheme, name, port); the service's
///   own page opened on this machine (http://127.0.0.1:<port>) may ask without being listed. A request without an
///   Origin header (a program) is not judged by it.
/// - `log(level, message, fields)`, and for tests `now`, `sleep`, and `autoMine: false` (no timer: the test calls
///   `tick()`).
export async function createTestBitcoinService({
  rpc, runner = null, archive = null, blockSeconds = 20,
  maxPaymentSats = 5_000_000n, perCallerPerDaySats = 100_000_000n, paymentsPerCallerPerHour = 30, totalPerDaySats = 20_000_000_000n, totalPaymentsPerDay = 10_000,
  addressesPerCallerPerDay = 20, totalAddressesPerDay = 5000,
  host = '127.0.0.1', port = 8960, hosts = [], origins = [], basePath = '/bitcoin', rateLimit = {}, trustedProxies = [], servePage = true,
  log = () => {}, now = Date.now, sleep = pause, autoMine = true,
}) {
  if (typeof basePath !== 'string' || !/^(?:\/[a-z0-9][a-z0-9-]{0,31}){0,4}$/.test(basePath)) throw new Error('basePath is "" or a path such as /bitcoin');
  const blockMs = blockSeconds * 1000;
  const limits = createLimits({ perCallerPerDaySats, paymentsPerCallerPerHour, totalPerDaySats, totalPaymentsPerDay, addressesPerCallerPerDay, totalAddressesPerDay, now });
  const limiter = createRateLimiter({ perSecond: 5, burst: 20, ...rateLimit, now });
  const proxies = new Set(trustedProxies.map(normalIp).filter(Boolean));
  const hostName = (value) => String(value || '').toLowerCase().replace(/:(?:80|443)$/, '');
  const ownHosts = new Set(hosts.map(hostName)), allowedOrigins = new Set(origins);
  const page = {};
  if (servePage) for (const [route, [file, type]] of Object.entries(PAGE_FILES)) page[route] = { type, body: readFileSync(new URL(`../web-v4/${file}`, import.meta.url)) };
  const chain = createChain({ rpc, archive, log });

  // What the service knows of itself between two looks at the node.
  let ready = false, closing = null, server = null, timer = null, nextAt = 0, working = Promise.resolve();
  let nodeState = 'starting', archiveFault = null, balance = 0n, miningAddress = null, testerDescriptors = new Set(), walletWritten = null, saidAt = new Map();
  // Payments that are in no block yet, by transaction id: `{ script, sats, at }`. Those of this run only.
  const waiting = new Map();
  // The scripts of addresses that are known to be the wallet's.
  const made = new Set();
  let queued = 0, line = Promise.resolve();

  const once = (key, level, message, fields) => { const at = now(); if (at - (saidAt.get(key) ?? -Infinity) < 60_000) return; saidAt.set(key, at); log(level, message, fields); };
  const secondsToNext = () => Math.max(0, Math.ceil((nextAt - now()) / 1000));

  // ---- the wallet
  /// A wallet call. A node that was started again may not have the wallet loaded: it is loaded, and the call made once more.
  async function wallet(method, params = [], options = {}) {
    try { return await rpc.call(method, params, options); } catch (error) {
      if (!(error instanceof BitcoinRpcError) || error.code !== 'REFUSED' || error.rpcCode !== -18) throw error;
      await openWallet();
      return rpc.call(method, params, options);
    }
  }
  const descriptorsOf = async (withKeys) => {
    const listed = await wallet('listdescriptors', [withKeys]);
    if (!listed || !Array.isArray(listed.descriptors) || listed.descriptors.some((entry) => !entry || typeof entry.desc !== 'string')) throw new BitcoinRpcError('INVALID', 'The Bitcoin node\'s answer is not a list of descriptors');
    return listed.descriptors.map((entry) => ({ desc: entry.desc, active: entry.active === true, internal: entry.internal === true, ...(Array.isArray(entry.range) ? { range: entry.range, next_index: Number.isInteger(entry.next_index) ? entry.next_index : entry.next } : {}) }));
  };
  /// The wallet, loaded: the node's own, or made anew. A node that has no such wallet gets the archive's, when the
  /// archive holds one: a blank wallet with the archived descriptors, which then finds its coins in the blocks.
  async function openWallet() {
    const loaded = await rpc.call('listwallets');
    if (Array.isArray(loaded) && loaded.includes(rpc.wallet)) return 'loaded';
    try { await rpc.call('loadwallet', [rpc.wallet], { timeoutMs: 120_000 }); return 'loaded'; } catch (error) {
      // -18: no such wallet. -35: loaded already. -4: Bitcoin Core's word for several troubles of a wallet file.
      if (error instanceof BitcoinRpcError && error.rpcCode === -35) return 'loaded';
      if (!(error instanceof BitcoinRpcError) || error.code !== 'REFUSED' || (error.rpcCode !== -18 && error.rpcCode !== -4)) throw error;
    }
    const kept = archive ? await archive.readWallet() : null;
    // Blocks without the keys of the coins in them: a new wallet could never pay. Said before a wallet is made.
    if (!kept && archive && chain.height() > 0) throw new Error('The archive holds blocks and no wallet.json, and the node has no wallet: the keys of the coins in those blocks are not here. The service does not start; put wallet.json back, or use an empty archive directory');
    if (!kept) { await rpc.call('createwallet', { wallet_name: rpc.wallet, load_on_startup: true }, { timeoutMs: 120_000 }); return 'made'; }
    await rpc.call('createwallet', { wallet_name: rpc.wallet, blank: true, load_on_startup: true }, { timeoutMs: 120_000 });
    const requests = kept.descriptors.map((entry) => {
      const next = Number.isInteger(entry.next_index) && entry.next_index >= 0 ? entry.next_index : 0;
      const ranged = Array.isArray(entry.range) && entry.range.length === 2 && entry.range.every((value) => Number.isInteger(value) && value >= 0);
      // From the first block on: the wallet reads every block it is then handed, and a rescan of a chain it already holds.
      return { desc: entry.desc, active: entry.active === true, internal: entry.internal === true, timestamp: 0, ...(ranged ? { range: [0, Math.max(entry.range[1], next + RESTORE_AHEAD)], next_index: next } : {}) };
    });
    const results = await rpc.call('importdescriptors', [requests], { timeoutMs: 600_000 });
    if (!Array.isArray(results) || results.length !== requests.length || results.some((result) => result?.success !== true)) throw new Error('The Bitcoin node did not take every descriptor of the archived wallet: the service does not start on a wallet that lacks keys. Empty the node\'s data directory before the next start');
    return 'restored';
  }
  /// Keeps the archive's copy of the wallet's keys as the wallet is now (a descriptor's next index moves with every
  /// address made), and learns which descriptors the testers' addresses come from.
  async function noteWallet() {
    const open = await descriptorsOf(false);
    testerDescriptors = new Set(open.filter((entry) => entry.active && !entry.internal && /^(?:wpkh|tr)\(/.test(entry.desc)).map((entry) => entry.desc));
    if (!archive) return;
    const descriptors = await descriptorsOf(true), text = JSON.stringify(descriptors);
    if (text === walletWritten) return;
    if (walletWritten === null) {
      const kept = await archive.readWallet().catch(() => ({ descriptors: [] }));
      if (kept && JSON.stringify(kept.descriptors.map((entry) => entry.desc).sort()) !== JSON.stringify(descriptors.map((entry) => entry.desc).sort())) {
        log('error', 'wallet.json of the archive held the keys of another wallet than the node\'s: it was moved aside and the node\'s wallet written', { moved_to: await archive.setWalletAside(new Date(now()).toISOString().replace(/[^0-9]/g, '').slice(0, 14)) });
      }
    }
    await archive.writeWallet({ format: 'time-test-bitcoin-wallet-1', note: 'The descriptors of the test network\'s regtest wallet, WITH PRIVATE KEYS. Play money: a regtest chain is worth nothing.', wallet: rpc.wallet, descriptors });
    walletWritten = text;
  }
  async function readBalance() {
    const balances = await wallet('getbalances');
    balance = satsOfBtc(balances?.mine?.trusted);
    return balances;
  }
  /// Waits until the wallet has read the node's newest block (it reads them a moment after the node takes them).
  async function walletCaughtUp(height) {
    for (const end = Date.now() + 120_000; Date.now() < end; await sleep(200)) {
      const seen = (await readBalance())?.lastprocessedblock?.height;
      if (!Number.isInteger(seen) || seen >= height) return;
    }
    throw new Error('The wallet of the Bitcoin node did not read the chain within two minutes');
  }

  // ---- one look at the node, and one block
  async function look(options) {
    const result = await chain.follow(options);
    archiveFault = result.archiveFault;
    if (archiveFault) once('archive', 'error', 'THE ARCHIVE COULD NOT BE WRITTEN: the chain goes on, and a lost machine would lose the blocks that are not in it', { error: archiveFault });
    for (const [txid, payment] of waiting) if (chain.heightOf(txid) !== null || now() - payment.at > DAY_MS) waiting.delete(txid);
    if (result.restored) log('warn', 'the Bitcoin node held fewer blocks than the archive: the blocks it lacked were handed to it, in order', { blocks: result.restored, height: result.height });
    return result;
  }
  /// The archive's copy of the wallet, kept up; a file that cannot be written is the archive's fault, not the node's.
  async function keepWallet() {
    try { await noteWallet(); } catch (error) {
      if (error instanceof BitcoinRpcError) throw error;
      archiveFault = plain(error?.message, 200) || 'wallet.json could not be written';
      once('archive', 'error', 'THE ARCHIVE COULD NOT BE WRITTEN: the chain goes on, and a lost machine would lose the blocks that are not in it', { error: archiveFault });
    }
  }
  /// One round: bring the node and the archive together, mine one block, read it. Never throws.
  async function tick() {
    const run = working.then(async () => {
      try {
        // First what the node may have lost, so that the new block stands on the chain's true best block.
        await look();
        await rpc.call('generatetoaddress', [1, miningAddress], { timeoutMs: 60_000 });
        await look();
        await keepWallet();
        await readBalance();
        nodeState = 'ok';
      } catch (error) {
        const ofNode = error instanceof BitcoinRpcError;
        if (ofNode) nodeState = error.code === 'WRONG_CHAIN' ? 'not_regtest' : error.code === 'REFUSED' || error.code === 'INVALID' ? 'node_failing' : 'node_unreachable';
        else archiveFault = plain(error?.message, 200) || 'a round failed';
        once(`tick:${ofNode ? error.code : 'local'}`, 'error', ofNode ? 'no block was made in this round: the Bitcoin node failed' : 'no block was made in this round: the service failed on its own side', { error: plain(error?.message, 300), status: ofNode ? nodeState : 'archive_failing' });
        if (ofNode && nodeState === 'node_unreachable') runner?.ensure();
      }
    });
    working = run;
    return run;
  }
  /// A round at its time, and when the next one is due. The pace is fixed: a round that came late is not made up
  /// for by a block at once.
  async function round() {
    await tick();
    nextAt += blockMs;
    if (nextAt <= now()) nextAt = now() + blockMs;
  }
  function schedule() {
    if (closing || !autoMine) return;
    timer = setTimeout(async () => { await round(); schedule(); }, Math.max(0, nextAt - now()));
  }

  // ---- what the routes answer
  function health() {
    const age = Math.max(0, Math.floor(now() / 1000) - chain.bestTime());
    const status = !ready ? 'starting' : nodeState !== 'ok' ? nodeState : age > 3 * blockSeconds ? 'no_new_block' : archiveFault ? 'archive_failing' : balance < maxPaymentSats + FEE_RESERVE_SATS ? 'wallet_cannot_pay' : 'ok';
    return { ok: status === 'ok', body: { status, network: 'regtest', height: chain.height(), seconds_since_block: ready ? age : null, block_seconds: blockSeconds, balance_sats: balance.toString(), archive: archive ? (archiveFault ? 'failing' : 'written') : 'none', node_restarts: runner?.restarts() ?? 0 } };
  }
  const mustBeReady = () => { if (!ready) throw new ServiceError(503, 'starting', 'The service is starting. Try again in a moment', { retryAfter: 5 }); };
  const confirmations = (height) => (height === null ? 0 : chain.height() - height + 1);
  /// A text a caller gave as an address: its script and form, or the refusal. The codec's own words say what is wrong.
  async function readAddress(text) {
    if (typeof text !== 'string' || !/^[A-Za-z0-9]{14,90}$/.test(text)) bad('invalid_address', 'An address is 14 to 90 letters and digits. An address of this test chain begins with bcrt1 (or with m, n or 2)');
    let script;
    try { script = await addressToScript(text, 'regtest'); } catch (error) { bad('invalid_address', plain(error?.message, 240) || 'This is not an address of this test chain'); }
    return { script, form: scriptForm(script), address: await scriptToAddress(script, 'regtest') };
  }
  /// One piece of work on the wallet at a time, with at most 32 waiting.
  function inLine(work) {
    if (queued >= 32) throw new ServiceError(503, 'busy', 'Too many requests wait for the wallet. Try again in a moment', { retryAfter: 2 });
    queued += 1;
    const run = line.then(work).finally(() => { queued -= 1; });
    line = run.catch(() => {});
    return run;
  }
  const nodeTrouble = (error, what) => {
    log('error', `the Bitcoin node failed ${what}`, { error: plain(error?.message, 300), ...(error instanceof BitcoinRpcError ? { kind: error.code, rpc_code: error.rpcCode } : {}) });
    return new ServiceError(503, 'node_unavailable', 'The Bitcoin node of the test network did not answer. Try again in a moment', { retryAfter: 5 });
  };

  const HANDLERS = {
    'GET /v1/health': () => { const answer = health(); return { status: answer.ok ? 200 : 503, body: answer.body }; },
    'GET /v1/status': ({ caller }) => {
      mustBeReady();
      return { status: 200, body: {
        network: 'regtest', height: chain.height(), best_hash: chain.bestHash(), block_seconds: blockSeconds, seconds_to_next_block: secondsToNext(),
        max_payment_sats: maxPaymentSats.toString(), per_caller_per_day_sats: perCallerPerDaySats.toString(), left_today_for_caller_sats: limits.left(caller).toString(), balance_sats: balance.toString(),
        paying: health().ok, addresses_per_caller_per_day: addressesPerCallerPerDay, notice: NOTICE,
      } };
    },
    'POST /v1/addresses': async ({ body, caller }) => {
      mustBeReady();
      const keys = Object.keys(body);
      if (keys.some((key) => key !== 'form') || (body.form !== undefined && !Object.hasOwn(ADDRESS_FORMS, body.form))) bad('invalid_body', 'The body is {"form": "p2wpkh"} or {"form": "p2tr"}, or {} for p2wpkh');
      const form = body.form ?? 'p2wpkh';
      return inLine(async () => {
        const giveBack = limits.address(caller);
        let address;
        try { address = await wallet('getnewaddress', ['tester', ADDRESS_FORMS[form]]); } catch (error) { giveBack(); throw nodeTrouble(error, 'to make an address'); }
        // What the node gave is held to the codec the page and the market use: an address of the form asked for.
        let read;
        try { read = await readAddress(address); } catch { read = null; }
        if (!read || read.form !== form || read.address !== address) { giveBack(); throw nodeTrouble(new Error('the node gave something that is not an address of the form asked for'), 'to make an address'); }
        if (made.size > 100_000) made.clear();
        made.add(read.script);
        return { status: 200, body: { address, form, note: 'The address is held by the test network\'s Bitcoin node: what arrives at it is shown by this service and cannot be spent by you.', notice: NOTICE } };
      });
    },
    'GET /v1/addresses/{address}': async ({ name }) => {
      mustBeReady();
      const { script, form, address } = await readAddress(name);
      const unknown = () => new ServiceError(404, 'unknown_address', 'This is not an address this service made');
      if (!Object.hasOwn(ADDRESS_FORMS, form)) throw unknown();
      if (!made.has(script)) {
        let info;
        try { info = await wallet('getaddressinfo', [address]); } catch (error) { throw nodeTrouble(error, 'to say whose an address is'); }
        // An address of the wallet's own, from one of the two lines of addresses testers are given (not its change, not its mining address).
        if (info?.ismine !== true || !testerDescriptors.has(info.parent_desc)) throw unknown();
        if (made.size > 100_000) made.clear();
        made.add(script);
      }
      const inBlocks = chain.received(script), notYet = [...waiting].filter(([, payment]) => payment.script === script);
      const payments = [...notYet.map(([txid, payment]) => ({ txid, sats: payment.sats.toString(), height: null, confirmations: 0 })).reverse(),
        ...inBlocks.slice(-50).reverse().map((entry) => ({ txid: entry.txid, sats: entry.sats, height: entry.height, confirmations: confirmations(entry.height) }))].slice(0, 50);
      return { status: 200, body: {
        address, form, received_sats: inBlocks.reduce((total, entry) => total + BigInt(entry.sats), 0n).toString(), unconfirmed_sats: notYet.reduce((total, [, payment]) => total + payment.sats, 0n).toString(),
        payments, height: chain.height(), notice: NOTICE,
      } };
    },
    'POST /v1/payments': async ({ body, caller }) => {
      mustBeReady();
      if (Object.keys(body).sort().join(',') !== 'address,sats') bad('invalid_body', 'The body is {"address": "<a regtest address>", "sats": "<satoshis, as a decimal string>"} and nothing else');
      const { script, form, address } = await readAddress(body.address);
      const sats = parseSats(body.sats);
      if (sats === null || sats < 1n) bad('invalid_amount', 'sats is a whole number of satoshis from 1, as a decimal string without leading zeros');
      if (sats > maxPaymentSats) bad('amount_too_large', `One payment is at most ${maxPaymentSats} satoshis`);
      if (sats < DUST_SATS[form]) bad('amount_too_small', `Bitcoin nodes do not pass on a payment of less than ${DUST_SATS[form]} satoshis to this kind of address`);
      return inLine(async () => {
        const giveBack = limits.payment(caller, sats);
        if (nodeState !== 'ok') { giveBack(); throw new ServiceError(503, 'node_unavailable', 'The Bitcoin node of the test network is not answering. Try again in a moment', { retryAfter: 5 }); }
        if (balance < sats + FEE_RESERVE_SATS) { giveBack(); throw new ServiceError(503, 'wallet_empty', 'The wallet of this service does not hold enough to pay that now'); }
        let txid;
        try {
          // The amount arrives whole: `send` pays the fee on top of it unless told otherwise, and it is not told.
          const sent = await wallet('send', { outputs: [{ [address]: btcText(sats) }], fee_rate: FEE_RATE, options: { max_tx_weight: MAX_TX_WEIGHT } });
          // Without `complete` the wallet made a transaction it could not sign, and sent nothing.
          if (sent?.complete !== true) throw new BitcoinRpcError('REFUSED', 'The Bitcoin node made a payment it did not send', null);
          txid = sent.txid;
        } catch (error) {
          if (error instanceof BitcoinRpcError && (error.code === 'WRONG_CHAIN' || error.code === 'UNAUTHORIZED')) { giveBack(); throw nodeTrouble(error, 'to pay: nothing was sent'); }
          if (!(error instanceof BitcoinRpcError) || error.code !== 'REFUSED') {
            // No answer: the payment may have been made. It stays counted.
            log('error', 'the Bitcoin node gave no answer to a payment: it is not known whether it was sent', { sats: sats.toString(), error: plain(error?.message, 200) });
            throw new ServiceError(503, 'node_unavailable', 'The Bitcoin node of the test network did not answer. It is not known whether the payment was sent: it counts against the limits. Look at the address before you ask again', { retryAfter: 5 });
          }
          giveBack();
          log('warn', 'the Bitcoin node refused a payment', { sats: sats.toString(), rpc_code: error.rpcCode, error: plain(error.message, 200) });
          // Bitcoin Core gives one number (-4) for all of these, and tells them apart in words.
          if (/too small/i.test(error.message)) throw new ServiceError(400, 'amount_too_small', 'The Bitcoin node does not send an amount this small to this kind of address');
          if (/insufficient funds/i.test(error.message)) { await readBalance().catch(() => {}); throw new ServiceError(503, 'wallet_empty', 'The wallet of this service does not hold enough to pay that now'); }
          // The wallet's coins are tied up in payments that wait for the next block.
          if (/mempool|maximum weight/i.test(error.message)) throw new ServiceError(503, 'wallet_busy', 'The wallet has made as many payments as fit before the next block. Try again after it', { retryAfter: secondsToNext() + 1 });
          throw new ServiceError(502, 'node_refused', 'The Bitcoin node of the test network refused the payment');
        }
        if (typeof txid !== 'string' || !HASH.test(txid)) throw nodeTrouble(new Error('the node\'s answer to a payment is not a transaction id'), 'to pay');
        waiting.set(txid, { script, sats, at: now() });
        // What was sent is read from the transaction's bytes: an output to this script with exactly this amount.
        try {
          const sent = await wallet('gettransaction', [txid]);
          if (!transactionOutputs(sent.hex).some((out) => out.script === script && out.sats === sats.toString())) log('error', 'A PAYMENT DOES NOT PAY WHAT WAS ASKED: its transaction has no output with the script and the amount', { txid, sats: sats.toString() });
          await readBalance();
        } catch (error) { once('pay-check', 'warn', 'a payment was sent and could not be read back from the node', { error: plain(error?.message, 200) }); }
        log('info', 'paid', { txid, sats: sats.toString(), form });
        return { status: 200, body: { txid, address, sats: sats.toString(), seconds_to_next_block: secondsToNext(), notice: NOTICE } };
      });
    },
    'GET /v1/payments/{txid}': ({ name }) => {
      mustBeReady();
      const height = chain.heightOf(name);
      if (height === null && !waiting.has(name)) throw new ServiceError(404, 'not_found', 'This service has no record of a payment with this transaction id (it keeps the newest 100,000, and payments that are in no block only until it is started again)');
      return { status: 200, body: { txid: name, confirmations: confirmations(height), height, seconds_to_next_block: secondsToNext() } };
    },
  };

  // ---- HTTP
  const BASE_HEADERS = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY', 'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'" };
  const PAGE_POLICY = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
  function reply(response, status, body, headers = {}) {
    const text = JSON.stringify(body);
    response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(text), ...headers });
    response.end(response.req?.method === 'HEAD' ? undefined : text);
  }
  function failure(response, error) {
    if (error.extra.close) response.once('finish', () => { const request = response.req; request?.resume(); setTimeout(() => request?.destroy(), 1000).unref?.(); });
    reply(response, error.status, { error: { code: error.code, message: error.message } }, {
      ...(error.extra.retryAfter ? { 'Retry-After': String(error.extra.retryAfter) } : {}), ...(error.extra.allow ? { Allow: error.extra.allow } : {}), ...(error.extra.close ? { Connection: 'close' } : {}) });
  }
  /// Who is asking: the peer, or what trusted proxies say about it. X-Forwarded-For is read from the right, past
  /// the entries that are trusted proxies themselves; what stands left of the first other entry is the caller's
  /// own claim and is not read. A caller is an IPv4 address or an IPv6 /64 (callers.mjs).
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
  /// The JSON object of a request body: at most MAX_BODY_BYTES, UTF-8, in its one plain spelling (no key twice, no
  /// escapes, no numbers where strings belong).
  async function readBody(request) {
    if (!/^application\/json(?:\s*;|$)/i.test(request.headers['content-type'] || '')) throw new ServiceError(415, 'unsupported_media_type', 'Send JSON with Content-Type: application/json');
    const tooLarge = () => new ServiceError(413, 'body_too_large', `The body is at most ${MAX_BODY_BYTES} bytes`, { close: true });
    if (Number(request.headers['content-length']) > MAX_BODY_BYTES) throw tooLarge();
    const bytes = await new Promise((resolve, reject) => {
      const chunks = []; let size = 0, over = false;
      const late = setTimeout(() => { over = true; chunks.length = 0; reject(new ServiceError(408, 'body_too_slow', `The body did not arrive within ${BODY_MS / 1000} seconds`, { close: true })); }, BODY_MS);
      late.unref?.();
      request.on('data', (chunk) => { if (over) return; size += chunk.length; if (size > MAX_BODY_BYTES) { over = true; clearTimeout(late); chunks.length = 0; reject(tooLarge()); } else chunks.push(chunk); });
      request.on('end', () => { clearTimeout(late); if (!over) resolve(Buffer.concat(chunks)); });
      request.on('error', () => { clearTimeout(late); reject(new ServiceError(400, 'invalid_body', 'The body could not be read')); });
    });
    let text, body;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); body = JSON.parse(text); } catch { throw new ServiceError(400, 'invalid_json', 'The body is not valid JSON'); }
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.values(body).some((value) => typeof value !== 'string')) bad('invalid_body', 'The body is a JSON object of strings');
    if (JSON.stringify(body) !== text.replace(/\s+/g, '')) bad('invalid_body', 'Write each field once, as a plain string without escapes');
    return body;
  }
  async function handle(request, response) {
    for (const [name, value] of Object.entries(BASE_HEADERS)) response.setHeader(name, value);
    // A request that carries a body ends its connection with its answer, so that a refused request cannot hold a
    // connection for as long as its body keeps coming (the faucet's rule, client-v4/faucet.mjs).
    if (carriesBody(request.headers)) {
      response.setHeader('Connection', 'close');
      response.once('finish', () => { if (!request.complete) { request.resume(); setTimeout(() => request.destroy(), 1000).unref?.(); } });
    }
    try {
      if (request.rawHeaders.filter((name, i) => i % 2 === 0 && name.toLowerCase() === 'host').length > 1) throw new ServiceError(400, 'invalid_request', 'A request names its host once');
      const bound = server.address()?.port, asked = hostName(request.headers.host);
      const local = [`127.0.0.1:${bound}`, `localhost:${bound}`, `[::1]:${bound}`];
      if (!ownHosts.has(asked) && !local.map(hostName).includes(asked)) throw new ServiceError(421, 'unknown_host', 'This server does not answer under that host name');
      // A browser names the page a request comes from, scheme included. Two kinds of page may ask: the service's
      // own page opened on this machine (http, the very address asked), and the origins the operator listed.
      // Behind a TLS proxy the page's own public origin is one of those to list: this process cannot know under
      // which scheme it is reached. (The faucet's rule, client-v4/faucet.mjs.)
      const origin = request.headers.origin;
      if (origin !== undefined) {
        const own = local.some((name) => origin === `http://${name}` && hostName(name) === asked);
        if (!own && !allowedOrigins.has(origin)) throw new ServiceError(403, 'origin_not_allowed', 'This origin may not call the service from a browser');
        // A page of another origin may read how long to wait: a browser hides Retry-After from it unless it is named here.
        if (!own) { response.setHeader('Access-Control-Allow-Origin', origin); response.setHeader('Access-Control-Expose-Headers', 'Retry-After'); response.setHeader('Vary', 'Origin'); }
      }
      if (embeddedElsewhere(request.headers)) throw new ServiceError(403, 'origin_not_allowed', 'A page of another site may not load this address');
      if (request.method === 'OPTIONS' && origin !== undefined) { response.writeHead(204, { 'Access-Control-Allow-Methods': 'GET, POST', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '600' }); response.end(); return; }
      const raw = request.url || '';
      if (raw.length > MAX_URL_LENGTH) throw new ServiceError(414, 'url_too_long', 'The address is too long');
      // Every request counts against its sender before anything is done for it.
      const caller = callerOf(request);
      const wait = limiter.take(caller, request.method === 'POST' ? 10 : 1);
      if (wait) throw new ServiceError(429, 'rate_limited', 'Too many requests from this address', { retryAfter: wait });
      if (raw !== basePath && !raw.startsWith(`${basePath}/`)) throw new ServiceError(404, 'unknown_route', `No such route; this service answers under ${basePath}/`);
      if (raw === basePath && servePage) { response.writeHead(308, { Location: `${basePath}/`, 'Content-Length': 0 }); response.end(); return; }
      const rest = raw.slice(basePath.length);
      // The page, with an address and an amount for its pay form: the one query any address here takes.
      const target = servePage && PREFILL.test(rest) ? '/' : rest;
      if (!/^\/[A-Za-z0-9/._-]*$/.test(target) || target.includes('//') || target.includes('..')) throw new ServiceError(400, 'invalid_url', `The address is a plain path such as ${basePath}/v1/status, without a query`);
      const static_ = Object.hasOwn(page, target) ? page[target] : null;
      if (static_) {
        if (request.method !== 'GET' && request.method !== 'HEAD') throw new ServiceError(405, 'method_not_allowed', 'This route does not take that method', { allow: 'GET' });
        response.writeHead(200, { 'Content-Type': static_.type, 'Content-Length': static_.body.length, 'Content-Security-Policy': PAGE_POLICY });
        response.end(request.method === 'HEAD' ? undefined : static_.body); return;
      }
      const named = /^\/v1\/(addresses|payments)\/([A-Za-z0-9]{1,90})$/.exec(target);
      const route = named ? `/v1/${named[1]}/{${named[1] === 'addresses' ? 'address' : 'txid'}}` : target;
      const methods = ['GET', 'POST'].filter((method) => HANDLERS[`${method} ${route}`]);
      if (methods.length === 0) throw new ServiceError(404, 'unknown_route', `No such route; GET ${basePath}/v1/status says what this service gives`);
      if (!methods.includes(request.method)) throw new ServiceError(405, 'method_not_allowed', 'This route does not take that method', { allow: methods.join(', ') });
      let name = named?.[2];
      if (named?.[1] === 'payments') { name = name.toLowerCase(); if (!HASH.test(name)) bad('invalid_txid', 'A transaction id is 64 hexadecimal characters'); }
      const body = request.method !== 'POST' ? undefined : carriesBody(request.headers) ? await readBody(request) : {};
      const result = await HANDLERS[`${request.method} ${route}`]({ body, caller, name });
      reply(response, result.status, result.body);
    } catch (error) {
      if (response.headersSent) { response.destroy(); return; }
      if (error instanceof ServiceError) { failure(response, error); return; }
      log('error', 'request failed', { error: plain(error?.message, 160) });
      failure(response, new ServiceError(500, 'internal', 'The request could not be answered'));
    }
  }
  const close = () => closing ??= (async () => {
    clearTimeout(timer);
    await working.catch(() => {});
    if (server?.listening) await new Promise((resolve) => { server.close(() => resolve()); server.closeAllConnections?.(); });
    await line.catch(() => {});
    // The node is told to stop by this service only when this service runs it.
    if (runner) await runner.stop(() => rpc.call('stop', [], { timeoutMs: 10_000 }));
  })();

  // ---- start: the port first (a second service on the same port stops here, before it touches the node), then the
  // node, its chain and its wallet; the routes answer "starting" until all of it is in place.
  try {
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
    // Said before the node is ready: a supervisor that must not wait for a long restore of the archive starts the next
    // services on this line; until "test bitcoin started" the health answer says `starting`.
    log('info', 'test bitcoin listening', { port });

    if (runner) await runner.start();
    await rpc.chainInfo();
    if (await rpc.call('getblockhash', [0]) !== REGTEST_GENESIS) throw new Error('The Bitcoin node says regtest and its first block is not regtest\'s: the service does not start');
    if (archive) await archive.prepare();
    const archived = await chain.load();
    const opened = await openWallet();
    if (opened !== 'loaded') log(opened === 'restored' ? 'warn' : 'info', opened === 'restored' ? 'the node had no wallet: the wallet of the archive was put into it' : 'the node had no wallet: a new one was made', { wallet: rpc.wallet });
    const begun = await look({ refuseForeign: true });
    // While it runs, the service goes on without its archive and says so. It does not start without it.
    if (begun.archiveFault) throw new Error(`The archive directory cannot be written (${begun.archiveFault}): the service does not start`);
    await noteWallet();
    // An address of a form no tester is given, whose coins are spent with few bytes outside the witness data.
    miningAddress = await wallet('getnewaddress', ['mining', 'p2sh-segwit']);
    if ((await readAddress(miningAddress).catch(() => null))?.form !== 'p2sh') throw new Error('The Bitcoin node did not give a mining address of the form asked for');
    // A new chain: the first coins can be spent 100 blocks after they were mined.
    if (chain.height() < 101) { await rpc.call('generatetoaddress', [101 - chain.height(), miningAddress], { timeoutMs: 300_000 }); await look(); }
    await walletCaughtUp(chain.height());
    await noteWallet();
    const found = { height: chain.height(), balance_sats: balance.toString() };
    nodeState = 'ok';
    // A chain whose newest block is older than a pace (the service was down, or the chain came from the archive) is
    // due its next block now: it is mined before the service says it is ready, so that its health answer is true
    // from its first moment.
    if (Math.floor(now() / 1000) - chain.bestTime() >= blockSeconds) await tick();
    ready = true; nextAt = now() + blockMs;
    schedule();
    const address = server.address();
    return {
      url: `http://${address.family === 'IPv6' ? `[${address.address}]` : address.address}:${address.port}`,
      close, tick: round, health, chain,
      /// What the start found, before it mined anything on top: how many blocks came from the archive, how many of
      /// them the node lacked, how the wallet was opened, the height and what the wallet could spend.
      started: { archived, restored: begun.restored, wallet: opened, ...found },
    };
  } catch (error) { await close(); throw error; }
}

/// Every route of the service, relative to its base path, for the README and the tests.
export const ROUTES = Object.freeze(['GET /v1/health', 'GET /v1/status', 'POST /v1/addresses', 'GET /v1/addresses/{address}', 'POST /v1/payments', 'GET /v1/payments/{txid}',
  'GET /', 'GET /test-bitcoin/app.mjs', 'GET /test-bitcoin/styles.css', 'GET /shared/bitcoin-address.mjs', 'GET /shared/network-menu.js', 'GET /shared/network-menu.css']);
