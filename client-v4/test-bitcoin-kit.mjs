// A Bitcoin Core node in regtest, with one wallet, that exists in a test only: for the tests of the test-bitcoin
// service (test-bitcoin.test.mjs).
//
// It answers Bitcoin Core's JSON-RPC over a `fetch` of its own, in the forms Bitcoin Core 32.1 gave when it was
// asked on 2026-11-27 (amounts written as decimal numbers of bitcoin, the error codes -4, -5 and -18 with their
// words, the answers of submitblock; -8 and -35 are the numbers the other tests of this folder use and were not
// asked again), so that the service's real client is in every test. Its blocks are real in what a
// reader of bytes can check: transactions serialized as Bitcoin serializes them, ids, Merkle roots, header
// hashes, each header naming its parent. They have no proof of work, and its transactions spend nothing that
// exists: nothing on this side checks either.
//
// Its wallet is a stand-in with the wallet's outline, not its rules: addresses come from "descriptors" that are
// a seed and a line (pkh, wpkh, tr; received or change), what it holds is worked out from the blocks alone (so a
// second node that is given the descriptors and the blocks holds the same), every payment costs the same fee and
// carries one change output, and `send` refuses with Bitcoin Core's number for it (-4) and its words. It is not
// Bitcoin Core: the test against the real program is
// test-bitcoin-regtest.test.mjs.
import { createHash } from 'node:crypto';
import { addressToScript, scriptToAddress, stripWitness } from './bitcoin-address.mjs';
import { headerFields, readBlock } from './bitcoin-rpc.mjs';
import { REGTEST_GENESIS } from './test-bitcoin.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
const sha256d = (bytes) => sha256(sha256(bytes));
const reversed = (hex) => Buffer.from(hex, 'hex').reverse().toString('hex');
const u32 = (value) => { const bytes = Buffer.alloc(4); bytes.writeUInt32LE(value >>> 0); return bytes; };
const u64 = (value) => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64LE(BigInt(value)); return bytes; };
function size(value) {
  if (value < 0xfd) return Buffer.from([value]);
  const bytes = Buffer.alloc(3); bytes[0] = 0xfd; bytes.writeUInt16LE(value, 1); return bytes;
}
const txidOf = (hex) => Buffer.from(sha256d(Buffer.from(stripWitness(hex), 'hex'))).reverse().toString('hex');
function merkleRootOf(ids) {
  let level = ids.map((id) => Buffer.from(id, 'hex').reverse());
  while (level.length > 1) { const next = []; for (let i = 0; i < level.length; i += 2) next.push(sha256d(Buffer.concat([level[i], level[i + 1] ?? level[i]]))); level = next; }
  return level[0];
}
/// An amount as Bitcoin Core writes it inside JSON: a bare decimal number with eight places. `amount()` marks it,
/// and `written` turns the marks into bare numbers once the answer is JSON text.
const amount = (sats) => { const n = BigInt(sats), minus = n < 0n, a = minus ? -n : n; return { __amount: `${minus ? '-' : ''}${a / 100_000_000n}.${String(a % 100_000_000n).padStart(8, '0')}` }; };
const written = (value) => JSON.stringify(value).replace(/\{"__amount":"(-?[0-9]+\.[0-9]{8})"\}/g, '$1');
const FEE = 1410n, MATURITY = 100, KEYPOOL = 16;
const DUST = { '76a9': 546n, a914: 540n, '0014': 294n, '0020': 330n, 5120: 330n };

/// The lines of addresses of a wallet with the seed `seed`: four for receiving, four for change.
const LINES = Object.freeze([['pkh', 44, false], ['pkh', 44, true], ['sh', 49, false], ['sh', 49, true], ['tr', 86, false], ['tr', 86, true], ['wpkh', 84, false], ['wpkh', 84, true]]);
function scriptOf(seed, kind, internal, index) {
  const hash = sha256(`${seed}/${kind}/${internal ? 1 : 0}/${index}`).toString('hex');
  return kind === 'pkh' ? `76a914${hash.slice(0, 40)}88ac` : kind === 'sh' ? `a914${hash.slice(0, 40)}87` : kind === 'wpkh' ? `0014${hash.slice(0, 40)}` : `5120${hash}`;
}
/// A descriptor as Bitcoin Core writes one: `sh(wpkh(…))` for the line of addresses that begin with 2.
const wrapped = (kind, inner) => (kind === 'sh' ? `sh(wpkh(${inner}))` : `${kind}(${inner})`);
const privateText = (seed, kind, purpose, internal) => `${wrapped(kind, `tprv${seed}/${purpose}h/1h/0h/${internal ? 1 : 0}/*`)}#fake0000`;
const publicText = (seed, kind, purpose, internal) => `${wrapped(kind, `[${sha256(seed).toString('hex').slice(0, 8)}/${purpose}h/1h/0h]tpub${sha256(`pub${seed}`).toString('hex').slice(0, 24)}/${internal ? 1 : 0}/*`)}#fake0000`;

/// One node. `name` makes its blocks its own: two nodes never mine the same block.
/// - `fault`: null, 'silent' (the connection fails), or 'slow' (no answer before the caller gives up).
/// - `chain`: what it says its chain is ('regtest'; set to 'main' to play a node of another network).
/// - `calls`: every call it was sent, `[method, params, wallet]`, in order.
/// - `refuseWith`: words with which `send` refuses every payment (Bitcoin Core's number for it is -4); `unsigned`:
///   `send` answers with a transaction it did not sign or send; `shortPay`: it pays a satoshi less than asked.
/// - `forget(count)`: drops its newest blocks, as a node that was killed before it wrote them to disk.
/// - `reorganise(depth, count)`: replaces its newest `depth` blocks by `count` others.
/// - `unload()`: forgets which wallets are loaded, as a node that was started again.
export function createFakeRegtest({ name = 'a', time = 1_800_000_000, password = '__cookie__:fake', unconfirmedLimit = 25 } = {}) {
  const node = { fault: null, chain: 'regtest', calls: [], password, stopped: false };
  let blocks = [], mempool = [], counter = 0, clock = time;
  const wallets = new Map(), loaded = new Set();
  const unique = (label) => sha256(`${name}:${label}:${counter += 1}`);
  const tip = () => (blocks.length ? blocks[blocks.length - 1].hash : REGTEST_GENESIS);
  const refuse = (code, message) => { const error = new Error(message); error.rpc = code; throw error; };

  function makeTransaction(outputs) {
    const body = Buffer.concat([size(1), unique('input'), u32(0), size(0), u32(0xfffffffd), size(outputs.length), ...outputs.flatMap(({ sats, script }) => [u64(sats), size(script.length / 2), Buffer.from(script, 'hex')])]);
    const stack = Buffer.concat([size(2), size(71), Buffer.alloc(71, 0x30), size(33), Buffer.alloc(33, 0x02)]);
    return Buffer.concat([u32(2), Buffer.from([0, 1]), body, stack, u32(0)]).toString('hex');
  }
  function makeCoinbase(height, sats, script) {
    const input = Buffer.concat([Buffer.from([3]), u32(height).subarray(0, 3), unique('coinbase').subarray(0, 8)]);
    const outputs = [{ sats, script }, { sats: 0n, script: `6a24aa21a9ed${'00'.repeat(32)}` }];
    return Buffer.concat([u32(2), Buffer.from([0, 1]), size(1), Buffer.alloc(32), u32(0xffffffff), size(input.length), input, u32(0xffffffff),
      size(outputs.length), ...outputs.flatMap(({ sats: value, script: out }) => [u64(value), size(out.length / 2), Buffer.from(out, 'hex')]), size(1), size(32), Buffer.alloc(32), u32(0)]).toString('hex');
  }
  const subsidy = (height) => { const halvings = Math.floor(height / 150); return halvings >= 64 ? 0n : 5_000_000_000n >> BigInt(halvings); };
  function mine(script) {
    const height = blocks.length + 1, taken = mempool; mempool = [];
    const transactions = [makeCoinbase(height, subsidy(height) + FEE * BigInt(taken.length), script), ...taken.map((entry) => entry.hex)];
    // A block's time is the node's clock (`now`, when a test sets one); without a clock, a second after the last.
    clock = node.now ? Math.max(clock, Math.floor(node.now() / 1000)) : clock + 1;
    const header = Buffer.concat([u32(0x20000000), Buffer.from(reversed(tip()), 'hex'), merkleRootOf(transactions.map(txidOf)), u32(clock), Buffer.from('ffff7f20', 'hex'), unique('nonce').subarray(0, 4)]).toString('hex');
    const hex = header + size(transactions.length).toString('hex') + transactions.join('');
    blocks.push({ hash: headerFields(header).hash, hex, transactions });
    return blocks[blocks.length - 1].hash;
  }

  // ---- the wallet
  const outputsOf = readOutputs;
  function newWallet(seed) { return { seed, lines: seed === null ? [] : LINES.map(([kind, purpose, internal]) => ({ kind, purpose, internal, next: 0, end: KEYPOOL })) }; }
  /// Every script of the wallet, by script: `{ line, index }`. Worked out once for each state of its lines.
  function owned(wallet) {
    const state = `${wallet.seed}|${wallet.lines.map((line) => line.end).join(',')}`;
    if (wallet.ownedFor === state) return wallet.owned;
    const scripts = new Map();
    for (const line of wallet.lines) for (let index = 0; index < line.end; index++) scripts.set(scriptOf(wallet.seed, line.kind, line.internal, index), { line, index });
    wallet.ownedFor = state; wallet.owned = scripts;
    return scripts;
  }
  /// What the wallet holds, from the blocks and the waiting payments alone.
  function holdings(wallet) {
    const mine_ = owned(wallet);
    let trusted = 0n, immature = 0n;
    const count = (hex, coinbaseAt) => {
      const outs = outputsOf(hex);
      if (coinbaseAt !== null) { for (const out of outs) if (mine_.has(out.script)) { if (blocks.length - coinbaseAt + 1 > MATURITY) trusted += BigInt(out.sats); else immature += BigInt(out.sats); } return; }
      // A payment of this wallet carries a change output of its own: it cost what went to others, and the fee.
      if (!outs.some((out) => mine_.get(out.script)?.line.internal)) { for (const out of outs) if (mine_.has(out.script)) trusted += BigInt(out.sats); return; }
      for (const out of outs) if (!mine_.has(out.script)) trusted -= BigInt(out.sats);
      trusted -= FEE;
    };
    blocks.forEach((block, at) => block.transactions.forEach((hex, index) => count(hex, index === 0 ? at + 1 : null)));
    for (const entry of mempool) count(entry.hex, null);
    return { trusted, immature };
  }
  /// A line moves on when one of its addresses is used: what a wallet does when it reads a block.
  function markUsed(wallet, from = 0) {
    for (const block of blocks.slice(from)) for (const hex of block.transactions) for (const out of outputsOf(hex)) {
      const found = owned(wallet).get(out.script);
      if (found && found.index >= found.line.next) { found.line.next = found.index + 1; found.line.end = Math.max(found.line.end, found.line.next + KEYPOOL); }
    }
  }
  const lineOf = (wallet, kind, internal) => wallet.lines.find((line) => line.kind === kind && line.internal === internal) ?? refuse(-4, 'Error: This wallet has no available keys');
  function nextScript(wallet, kind, internal) {
    const line = lineOf(wallet, kind, internal), script = scriptOf(wallet.seed, kind, internal, line.next);
    line.next += 1; line.end = Math.max(line.end, line.next + KEYPOOL);
    return script;
  }

  const methods = {
    getblockchaininfo: () => ({ chain: node.chain, blocks: blocks.length, headers: blocks.length, bestblockhash: tip(), difficulty: 4.656542373906925e-10, verificationprogress: 1, initialblockdownload: false, chainwork: (2n * BigInt(blocks.length + 1)).toString(16).padStart(64, '0') }),
    getblockhash: ([height]) => (height === 0 ? REGTEST_GENESIS : blocks[height - 1]?.hash ?? refuse(-8, 'Block height out of range')),
    getblock: ([hash, verbosity]) => { if (verbosity !== 0) refuse(-8, 'this node gives blocks as bytes only'); return blocks.find((block) => block.hash === hash)?.hex ?? refuse(-5, 'Block not found'); },
    generatetoaddress: async ([count, address]) => { const script = await addressToScript(address, 'regtest').catch(() => refuse(-5, 'Error: Invalid address')); const before = blocks.length, hashes = []; for (let i = 0; i < count; i++) hashes.push(mine(script)); for (const wallet of wallets.values()) markUsed(wallet, before); return hashes; },
    submitblock: ([hex]) => {
      let block;
      try { block = readBlock(hex); } catch { refuse(-22, 'Block decode failed'); }
      if (blocks.some((known) => known.hash === block.hash)) return 'duplicate';
      if (block.previous !== tip()) return 'inconclusive';
      blocks.push({ hash: block.hash, hex, transactions: block.transactions.map((transaction) => transaction.hex) });
      clock = Math.max(clock, block.time);
      for (const wallet of wallets.values()) markUsed(wallet, blocks.length - 1);
      return null;
    },
    listwallets: () => [...loaded],
    loadwallet: ([name_]) => { if (!wallets.has(name_)) refuse(-18, `Wallet file verification failed. Failed to load database path '/var/lib/fake/regtest/wallets/${name_}'. Path does not exist.`); if (loaded.has(name_)) refuse(-35, 'Wallet is already loaded.'); loaded.add(name_); return { name: name_ }; },
    createwallet: (params) => {
      const given = Array.isArray(params) ? { wallet_name: params[0] } : params;
      if (wallets.has(given.wallet_name)) refuse(-4, 'Wallet file verification failed. Failed to create database path. Database already exists.');
      wallets.set(given.wallet_name, newWallet(given.blank ? null : sha256(`${name}:seed:${given.wallet_name}`).toString('hex').slice(0, 32))); loaded.add(given.wallet_name);
      return { name: given.wallet_name };
    },
    stop: () => { node.stopped = true; node.fault = 'silent'; return 'Bitcoin Core stopping'; },
  };
  const walletMethods = {
    getnewaddress: async (wallet, [, type]) => scriptToAddress(nextScript(wallet, { legacy: 'pkh', 'p2sh-segwit': 'sh', bech32: 'wpkh', bech32m: 'tr' }[type] ?? refuse(-5, 'Unknown address type'), false), 'regtest'),
    getaddressinfo: async (wallet, [address]) => {
      const script = await addressToScript(address, 'regtest').catch(() => refuse(-5, 'Invalid or unsupported Base58-encoded address.'));
      const found = owned(wallet).get(script);
      if (!found) return { address, scriptPubKey: script, ismine: false, solvable: false, iswatchonly: false, ischange: false, labels: [] };
      return { address, scriptPubKey: script, ismine: true, solvable: true, parent_desc: publicText(wallet.seed, found.line.kind, found.line.purpose, found.line.internal), iswatchonly: false, ischange: found.line.internal, labels: found.line.internal ? [] : [''] };
    },
    getbalances: (wallet) => { const held = holdings(wallet); return { mine: { trusted: amount(held.trusted), untrusted_pending: amount(0n), immature: amount(held.immature) }, lastprocessedblock: { hash: tip(), height: blocks.length } }; },
    send: async (wallet, params) => {
      const outputs = Array.isArray(params) ? null : params.outputs;
      if (!Array.isArray(outputs) || outputs.length !== 1 || Object.keys(outputs[0]).length !== 1 || typeof params.fee_rate !== 'number' || !Number.isInteger(params.options?.max_tx_weight) || params.options.subtract_fee_from_outputs !== undefined) refuse(-8, 'this node takes send with named arguments: outputs (one address and its amount), fee_rate, options.max_tx_weight');
      const [to, written_] = Object.entries(outputs[0])[0];
      const script = await addressToScript(to, 'regtest').catch(() => refuse(-5, `Invalid Bitcoin address: ${to}`));
      const match = /^([0-9]{1,8})\.([0-9]{8})$/.exec(String(written_)) ?? refuse(-3, 'Invalid amount');
      const sats = BigInt(match[1]) * 100_000_000n + BigInt(match[2]);
      if (node.refuseWith) refuse(-4, node.refuseWith);
      if (sats < (DUST[script.slice(0, 4)] ?? 546n)) refuse(-4, 'Transaction amount too small');
      if (holdings(wallet).trusted < sats + FEE) refuse(-4, 'Insufficient funds');
      if (mempool.length >= unconfirmedLimit) refuse(-4, 'Unconfirmed UTXOs are available, but spending them creates a chain of transactions that will be rejected by the mempool');
      const hex = makeTransaction([{ sats: node.shortPay ? sats - 1n : sats, script }, { sats: 1000n, script: nextScript(wallet, script.startsWith('5120') ? 'tr' : 'wpkh', true) }]);
      if (node.unsigned) return { complete: false, psbt: 'cHNidP8BAA==' };
      mempool.push({ hex, txid: txidOf(hex) });
      return { txid: txidOf(hex), complete: true };
    },
    gettransaction: (wallet, [txid]) => {
      const waiting = mempool.find((entry) => entry.txid === txid);
      if (waiting) return { amount: amount(0n), fee: amount(-FEE), confirmations: 0, txid, hex: waiting.hex };
      for (const [at, block] of blocks.entries()) for (const hex of block.transactions) if (txidOf(hex) === txid) return { amount: amount(0n), confirmations: blocks.length - at, blockheight: at + 1, blockhash: block.hash, txid, hex };
      return refuse(-5, 'Invalid or non-wallet transaction id');
    },
    listdescriptors: (wallet, [withKeys]) => ({ wallet_name: 'fake', descriptors: wallet.lines.map((line) => ({ desc: (withKeys ? privateText : publicText)(wallet.seed, line.kind, line.purpose, line.internal), timestamp: 1_795_806_226, active: true, internal: line.internal, range: [0, line.end - 1], next: line.next, next_index: line.next })) }),
    importdescriptors: (wallet, [requests]) => requests.map((request) => {
      const match = /^(pkh|wpkh|tr|sh\(wpkh)\(tprv([0-9a-f]+)\/([0-9]+)h\/1h\/0h\/([01])\/\*\)\)?#fake0000$/.exec(request.desc);
      if (!match || (wallet.seed !== null && wallet.seed !== match[2])) return { success: false, error: { code: -5, message: 'Invalid descriptor' } };
      wallet.seed = match[2];
      wallet.lines.push({ kind: match[1] === 'sh(wpkh' ? 'sh' : match[1], purpose: Number(match[3]), internal: match[4] === '1', next: request.next_index ?? 0, end: Math.max((request.range?.[1] ?? KEYPOOL - 1) + 1, (request.next_index ?? 0) + KEYPOOL) });
      node.imported = (node.imported ?? []).concat([{ desc: request.desc.replace(/tprv[0-9a-f]+/, 'tprv…'), timestamp: request.timestamp, range: request.range, next_index: request.next_index, internal: request.internal, active: request.active }]);
      markUsed(wallet);
      return { success: true };
    }),
  };

  node.fetcher = async (url, init) => {
    if (node.fault === 'silent') { const error = new TypeError('fetch failed'); error.cause = { code: 'ECONNREFUSED' }; throw error; }
    if (node.fault === 'slow') await new Promise((resolve, reject) => { init.signal.addEventListener('abort', () => reject(init.signal.reason)); });
    const answer = (status, body) => new Response(written(body), { status, headers: { 'content-type': 'application/json' } });
    if (init.headers.authorization !== `Basic ${Buffer.from(node.password).toString('base64')}`) return new Response('', { status: 401 });
    const request = JSON.parse(init.body), walletName = /^\/wallet\/([^/]+)$/.exec(new URL(url).pathname)?.[1] ?? null;
    node.calls.push([request.method, request.params, walletName]);
    try {
      if (methods[request.method]) return answer(200, { result: await methods[request.method](request.params), error: null, id: request.id });
      if (!walletMethods[request.method]) refuse(-32601, 'Method not found');
      if (walletName === null || !loaded.has(walletName)) refuse(-18, 'Requested wallet does not exist or is not loaded');
      return answer(200, { result: await walletMethods[request.method](wallets.get(walletName), request.params), error: null, id: request.id });
    } catch (error) {
      if (error.rpc === undefined) throw error;
      return answer(error.rpc === -32601 ? 404 : 500, { result: null, error: { code: error.rpc, message: error.message }, id: request.id });
    }
  };
  node.height = () => blocks.length;
  node.tip = tip;
  node.blockAt = (height) => blocks[height - 1];
  node.waiting = () => mempool.map((entry) => entry.txid);
  node.forget = (count) => { blocks = blocks.slice(0, Math.max(0, blocks.length - count)); };
  node.reorganise = (depth, count) => { blocks = blocks.slice(0, blocks.length - depth); const script = `76a914${'ee'.repeat(20)}88ac`; for (let i = 0; i < count; i++) mine(script); };
  node.unload = () => { loaded.clear(); };
  node.wallets = () => [...wallets.keys()];
  node.methodsCalled = () => [...new Set(node.calls.map(([method]) => method))].sort();
  return node;
}

/// The outputs of a transaction serialized as this file serializes one (version, marker and flag, one input, the
/// outputs): `[{ sats, script }]`. Small enough to be read here, without the codec under test.
function readOutputs(hex) {
  const bytes = Buffer.from(hex, 'hex');
  let at = 4 + 2 + 1 + 36;
  const scriptLength = bytes[at]; at += 1 + scriptLength + 4;
  const count = bytes[at]; at += 1;
  const outputs = [];
  for (let i = 0; i < count; i++) {
    const sats = bytes.readBigUInt64LE(at).toString(); at += 8;
    const length = bytes[at]; at += 1;
    outputs.push({ sats, script: bytes.subarray(at, at + length).toString('hex') }); at += length;
  }
  return outputs;
}

/// A log that keeps its lines: `log(level, message, fields)`, and `said(pattern)` gives the lines whose message matches.
export function createLog() {
  const lines = [];
  const log = (level, message, fields = {}) => { lines.push({ level, message, ...fields }); };
  log.lines = lines;
  log.said = (pattern) => lines.filter((entry) => pattern.test(entry.message));
  return log;
}
