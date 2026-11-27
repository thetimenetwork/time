// A Bitcoin node and a Time chain that exist in a test only, for the tests of the market's services
// (bitcoin-rpc.test.mjs, market-relay.test.mjs, market-prover.test.mjs).
//
// THE BITCOIN NODE answers Bitcoin Core's JSON-RPC over a `fetch` of its own, in the forms Bitcoin Core 32 gives, so
// that the real client (bitcoin-rpc.mjs) is in every test. Its blocks are real in everything a client can check:
// transactions serialized as Bitcoin serializes them (with witness data), ids, Merkle roots, header hashes, and
// Merkle proofs as `gettxoutproof` writes them. They have no proof of work: nothing on this side of the chain
// checks one. A block made elsewhere (the engine's own, from spec/market-vectors.json) can be put on its chain.
//
// THE TIME CHAIN keeps the rows of the market in the engine's forms and judges the three actions the services send
// as the engine does (v5/src/market.rs, bitcoin-bridge/src/payment.rs and chain.rs), with the engine's words for
// each refusal: kind 40 (headers), kind 54 (a proof of payment) and kind 55 (an expiry). It is not the engine: it
// checks no proof of work and keeps every branch. What it gives a reader has the form of a verified state.
import { createHash } from 'node:crypto';
import './time-sdk.js';
import { proofPayload, stripWitness, transactionOutputs } from './bitcoin-address.mjs';
import { headerFields, readBlock } from './bitcoin-rpc.mjs';

const SDK = globalThis.TimeSDK;
const sha256d = (bytes) => createHash('sha256').update(createHash('sha256').update(bytes).digest()).digest();
const reversed = (hex) => Buffer.from(hex, 'hex').reverse().toString('hex');
const u32 = (value) => { const bytes = Buffer.alloc(4); bytes.writeUInt32LE(value >>> 0); return bytes; };
const u64 = (value) => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64LE(BigInt(value)); return bytes; };
function size(value) {
  if (value < 0xfd) return Buffer.from([value]);
  if (value <= 0xffff) { const bytes = Buffer.alloc(3); bytes[0] = 0xfd; bytes.writeUInt16LE(value, 1); return bytes; }
  const bytes = Buffer.alloc(5); bytes[0] = 0xfe; bytes.writeUInt32LE(value, 1); return bytes;
}
let counter = 0;
/// 32 bytes no other call gives, the same in every run.
const unique = (label) => createHash('sha256').update(`${label}:${counter += 1}`).digest();

/// A payment as a wallet makes one: a transaction with one input and the outputs given (`[{ sats, script }]`), with
/// witness data unless `witness` is false. `padding` adds that many bytes of an output that carries data, to make a
/// transaction of a size. Returns its bytes in lowercase hexadecimal, as a node gives them.
export function makePayment(outputs, { witness = true, padding = 0 } = {}) {
  const all = [...outputs];
  for (let left = padding; left > 0; left -= 9000) all.push({ sats: 0, script: Buffer.concat([Buffer.from([0x6a, 0x4d]), Buffer.from([Math.min(left, 9000) & 0xff, Math.min(left, 9000) >> 8]), Buffer.alloc(Math.min(left, 9000), 7)]).toString('hex') });
  const body = Buffer.concat([
    size(1), unique('input'), u32(0), size(0), u32(0xfffffffd),
    size(all.length), ...all.flatMap(({ sats, script }) => [u64(sats), size(script.length / 2), Buffer.from(script, 'hex')]),
  ]);
  const stack = Buffer.concat([size(2), size(71), Buffer.alloc(71, 0x30), size(33), Buffer.alloc(33, 0x02)]);
  return Buffer.concat([u32(2), ...(witness ? [Buffer.from([0, 1])] : []), body, ...(witness ? [stack] : []), u32(0)]).toString('hex');
}
/// The coinbase transaction of a block at `height`, `extra` bytes longer than a miner needs.
function makeCoinbase(height, extra = 0) {
  const script = Buffer.concat([Buffer.from([3]), u32(height).subarray(0, 3), unique('coinbase').subarray(0, 8)]);
  const outputs = [{ sats: 5000000000n, script: `0014${'c0'.repeat(20)}` }];
  for (let left = extra; left > 0; left -= 9000) outputs.push({ sats: 0, script: Buffer.concat([Buffer.from([0x6a, 0x4d]), Buffer.from([Math.min(left, 9000) & 0xff, Math.min(left, 9000) >> 8]), Buffer.alloc(Math.min(left, 9000), 9)]).toString('hex') });
  return Buffer.concat([
    u32(2), Buffer.from([0, 1]), size(1), Buffer.alloc(32), u32(0xffffffff), size(script.length), script, u32(0xffffffff),
    size(outputs.length), ...outputs.flatMap(({ sats, script: out }) => [u64(sats), size(out.length / 2), Buffer.from(out, 'hex')]),
    size(1), size(32), Buffer.alloc(32), u32(0),
  ]).toString('hex');
}
const txidBytes = (hex) => sha256d(Buffer.from(stripWitness(hex), 'hex'));
function merkleRootOf(ids) {
  let level = ids;
  while (level.length > 1) { const next = []; for (let i = 0; i < level.length; i += 2) next.push(sha256d(Buffer.concat([level[i], level[i + 1] ?? level[i]]))); level = next; }
  return level[0];
}
/// What `gettxoutproof` writes: the header, the number of transactions, and BIP37's partial Merkle tree.
function merkleBlock(header, ids, wanted) {
  const width = (height) => (ids.length + (1 << height) - 1) >> height;
  const hashAt = (height, place) => {
    if (height === 0) return ids[place];
    const left = hashAt(height - 1, place * 2), right = place * 2 + 1 < width(height - 1) ? hashAt(height - 1, place * 2 + 1) : left;
    return sha256d(Buffer.concat([left, right]));
  };
  let top = 0;
  while (width(top) > 1) top += 1;
  const bits = [], hashes = [];
  const walk = (height, place) => {
    let above = false;
    for (let i = place << height; i < (place + 1) << height && i < ids.length; i++) above ||= wanted.has(i);
    bits.push(above);
    if (height === 0 || !above) { hashes.push(hashAt(height, place)); return; }
    walk(height - 1, place * 2);
    if (place * 2 + 1 < width(height - 1)) walk(height - 1, place * 2 + 1);
  };
  walk(top, 0);
  const flags = Buffer.alloc(Math.ceil(bits.length / 8));
  bits.forEach((bit, index) => { if (bit) flags[index >> 3] |= 1 << (index & 7); });
  return Buffer.concat([Buffer.from(header, 'hex'), u32(ids.length), size(hashes.length), ...hashes, size(flags.length), flags]).toString('hex');
}

/// A Bitcoin network of the test. `mine` adds a block; `node()` is one node's view of it.
export function createFakeBitcoin({ network = 'regtest', time = 1_800_000_000 } = {}) {
  const blocks = new Map(), chainName = { mainnet: 'main', testnet3: 'test', regtest: 'regtest' }[network];
  let best = null, clock = time;
  function put(block) {
    blocks.set(block.hash, block);
    // The branch with the most work is the best one; of two equal ones, the one seen first.
    if (best === null || block.work > best.work) best = block;
    return block;
  }
  function build(parent, transactions, { coinbaseExtra = 0, at } = {}) {
    const height = parent ? parent.height + 1 : 0, all = [makeCoinbase(height, coinbaseExtra), ...transactions], ids = all.map(txidBytes);
    clock = at ?? clock + 600;
    const header = Buffer.concat([u32(0x20000000), Buffer.from(parent ? reversed(parent.hash) : '00'.repeat(32), 'hex'), merkleRootOf(ids), u32(clock), Buffer.from('ffff7f20', 'hex'), unique('nonce').subarray(0, 4)]).toString('hex');
    return { hash: headerFields(header).hash, header, height, previous: parent?.hash ?? null, time: clock, transactions: all, ids, work: (parent?.work ?? 0n) + 2n };
  }
  put(build(null, []));
  /// The block at `height` on the branch that ends in `tip`.
  const ancestor = (tip, height) => { let block = tip; while (block && block.height > height) block = blocks.get(block.previous); return block?.height === height ? block : null; };
  const onBest = (block, tip = best) => ancestor(tip, block.height)?.hash === block.hash;
  return {
    network,
    get best() { return best; },
    block: (hash) => blocks.get(hash),
    at: (height, tip = best) => ancestor(tip, height),
    /// Adds a block on `parent` (a hash; the best block unless given) with `transactions` (bytes in hexadecimal).
    mine(transactions = [], { parent, coinbaseExtra, at } = {}) { return put(build(parent ? blocks.get(parent) : best, transactions, { coinbaseExtra, at })); },
    /// `count` empty blocks, one on the other.
    mineMany(count, options = {}) { let last; for (let i = 0; i < count; i++) last = this.mine([], { ...options, parent: last?.hash ?? options.parent }); return last; },
    /// Puts a block made elsewhere on the best chain: its header and transactions as they are. Its header names a
    /// parent this network does not have, so nothing may walk back through it.
    adopt(header, transactions) {
      const ids = transactions.map(txidBytes), fields = headerFields(header);
      if (merkleRootOf(ids).toString('hex') !== fields.merkleRoot) throw new Error('these are not the transactions of that header');
      return put({ hash: fields.hash, header, height: best.height + 1, previous: best.hash, saidPrevious: fields.previous, time: fields.time, transactions, ids, work: best.work + 2n });
    },
    /// One node. It stands at the network's best block and knows every block that was made, unless `lag` (how many
    /// blocks behind it stands) or `tip` (the hash its best chain ends in, set at any time) says otherwise: such a
    /// node knows its own best chain, and the branches it was shown (`show(hash)`). `fault` can be set at any time:
    /// 'silent' (the connection fails), 'slow' (no answer before the client gives up), 'garbage' (an answer that
    /// is not JSON), 'wrong' (answers of the right form for something else), or `{ withhold: hash }` (it does not
    /// give that block). `calls` counts every method asked. `password` is what it accepts.
    node({ lag = 0, password = '__cookie__:feed' } = {}) {
      const self = { lag, fault: null, calls: {}, password, tip: null };
      const tip = () => (self.tip ? blocks.get(self.tip) : ancestor(best, Math.max(0, best.height - self.lag)));
      const shown = new Set();
      const known = (hash) => { const block = blocks.get(hash); return block && ((self.lag === 0 && !self.tip) || onBest(block, tip()) || shown.has(hash)) ? block : null; };
      self.show = (hash) => { for (let block = blocks.get(hash); block; block = blocks.get(block.previous)) shown.add(block.hash); };
      const refuse = (code, message) => { const error = new Error(message); error.rpc = code; throw error; };
      const answer = (method, params) => {
        const at = tip();
        if (method === 'getblockchaininfo') return { chain: chainName, blocks: at.height, headers: at.height, bestblockhash: at.hash, difficulty: 4.656542373906925e-10, time: at.time, chainwork: at.work.toString(16).padStart(64, '0'), initialblockdownload: false };
        if (method === 'getbestblockhash') return at.hash;
        if (method === 'getblockhash') return ancestor(at, params[0])?.hash ?? refuse(-8, 'Block height out of range');
        const block = known(params[method === 'getrawtransaction' ? 2 : method === 'gettxoutproof' ? 1 : 0]) ?? refuse(-5, 'Block not found');
        if (self.fault?.withhold === block.hash && method !== 'getblockheader') refuse(-1, 'Block not available (pruned data)');
        if (method === 'getblockheader') {
          if (params[1] === false) return block.header;
          return { hash: block.hash, confirmations: onBest(block, at) ? at.height - block.height + 1 : -1, height: block.height, version: 536870912, merkleroot: reversed(headerFields(block.header).merkleRoot), time: block.time, mediantime: block.time, nonce: 0, bits: '207fffff', difficulty: 4.656542373906925e-10, chainwork: block.work.toString(16).padStart(64, '0'), nTx: block.transactions.length, ...(block.height > 0 ? { previousblockhash: block.saidPrevious ?? block.previous } : {}) };
        }
        if (method === 'getblock') return Buffer.concat([Buffer.from(block.header, 'hex'), size(block.transactions.length), ...block.transactions.map((hex) => Buffer.from(hex, 'hex'))]).toString('hex');
        const place = (txid) => { const index = block.ids.findIndex((id) => Buffer.from(id).reverse().toString('hex') === txid); return index < 0 ? refuse(-5, 'No such transaction found in the provided block') : index; };
        if (method === 'getrawtransaction') return block.transactions[place(params[0])];
        if (method === 'gettxoutproof') return merkleBlock(block.header, block.ids, new Set(params[0].map(place)));
        return refuse(-32601, 'Method not found');
      };
      self.fetcher = async (url, options) => {
        const request = JSON.parse(options.body);
        self.calls[request.method] = (self.calls[request.method] ?? 0) + 1;
        self.lastRequest = { url: String(url), authorization: options.headers.authorization, redirect: options.redirect };
        if (self.fault === 'silent') throw Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:18443'), { code: 'ECONNREFUSED' }) });
        if (self.fault === 'slow') return new Promise((_, reject) => { options.signal.addEventListener('abort', () => reject(options.signal.reason)); });
        if (options.headers.authorization !== `Basic ${Buffer.from(self.password).toString('base64')}`) return new Response('', { status: 401 });
        if (self.fault === 'garbage') return new Response('<html>502 Bad Gateway</html>', { status: 200 });
        let result;
        try { result = answer(request.method, request.params); } catch (error) {
          if (error.rpc === undefined) throw error;
          return new Response(JSON.stringify({ result: null, error: { code: error.rpc, message: error.message }, id: request.id }), { status: error.rpc === -32601 ? 404 : 500 });
        }
        if (self.fault === 'wrong') result = typeof result === 'string' ? result.replace(/[0-9a-f]{8}$/, (end) => (end === '00000000' ? '11111111' : '00000000')) : { ...result, hash: '00'.repeat(32), bestblockhash: 'ff'.repeat(32) };
        return new Response(JSON.stringify({ result, error: null, id: request.id }), { status: 200 });
      };
      return self;
    },
  };
}

// ---------------------------------------------------------------- the Time chain
const ROW_DEFAULTS = Object.freeze({ market: true, profile: 'laboratory', feeMicros: '1000', maxBatch: 256, maxReorg: 144 });
/// A Time chain with the market. `bitcoin` is the fake network whose genesis its header chain starts from.
/// - `learn(headers)` and `follow(bitcoin)` hand it headers as a kind 40 action would (the latter all of the best
///   chain it lacks); `addAccount`, `addOrder`, `addFill` write rows; `commit()` ends a block.
/// - `endpoint` is `{ readState, submit }` as `createTimeEndpoint` gives them. An action is judged when it is
///   submitted, as a node judges one at admission, on top of those it took before; what it changed shows in
///   `readState` after the next `commit()`. With `autoCommit` (the default) every action taken ends a block.
/// - `fault` can be 'silent' (reads and submissions fail), 'deaf' (it takes actions and never puts one in a block),
///   or `{ refuse: words }` (it refuses every action with those words).
export function createFakeChain({ bitcoin, networkId = 'ab'.repeat(32), autoCommit = true, ...options }) {
  const settings = { ...ROW_DEFAULTS, ...options }, rules = SDK.MARKET_RULES[settings.profile];
  const genesis = bitcoin.at(0);
  const live = {
    height: 10n, timeMicros: 1_800_000_000_000_000n, headers: new Map([[genesis.hash, { hash: genesis.hash, height: 0, previous: null, work: 2n }]]), tips: [genesis.hash], best: genesis.hash, halted: null,
    accounts: new Map(), security: new Map(), orders: new Map(), fills: new Map(), paid: new Map(), nextFill: 1n, nextOrder: 1n, trades: 0n, sats: 0n, seconds: 0n, lastPrice: null, entries: [{ at: '0', height: '0' }],
  };
  const GENESIS_MICROS = 1_799_999_000_000_000n;
  let shown = structuredClone(live);
  const self = { fault: null, reads: [], submitted: [], refusals: [], autoCommit };
  const refuse = (words) => { throw Object.assign(new Error(words), { refusal: true }); };
  const clock = (state) => state.timeMicros - GENESIS_MICROS;
  const bestOf = (state) => state.headers.get(state.best);
  const ancestor = (state, hash, height) => { let block = state.headers.get(hash); while (block && block.height > height) block = state.headers.get(block.previous); return block?.height === height ? block : null; };

  /// Takes blocks as `{ hash, previous }`, each on a parent the chain holds: the engine's `prepare_headers`.
  function applyBlocks(state, list) {
    if (state.halted) refuse('Bitcoin bridge is paused after a reorganization');
    if (list.length === 0 || list.length > settings.maxBatch) refuse('Bitcoin header batch bound');
    let fresh = 0;
    for (const fields of list) {
      if (state.headers.has(fields.hash)) continue;
      const parent = state.headers.get(fields.previous) ?? refuse('unknown or pruned Bitcoin parent');
      const record = { hash: fields.hash, height: parent.height + 1, previous: parent.hash, work: parent.work + 2n };
      state.headers.set(record.hash, record); fresh += 1;
      state.tips = [...state.tips.filter((tip) => tip !== parent.hash), record.hash].sort();
      const best = bestOf(state);
      if (!state.halted && record.work > best.work) {
        let a = best, b = record;
        while (a.hash !== b.hash) { if (a.height >= b.height) a = state.headers.get(a.previous); else b = state.headers.get(b.previous); }
        if (best.height - a.height > settings.maxReorg) state.halted = { reason: 'deep_reorg', old_tip: best.hash, candidate: record.hash, common_height: a.height };
        else state.best = record.hash;
      }
    }
    if (fresh === 0) refuse('Bitcoin relay contains no new headers');
    // The clock of heights (spec/market.md, 5.4).
    const height = bestOf(state).height;
    state.entries = state.entries.filter((entry) => Number(entry.height) <= height);
    if (state.entries.length === 0 || Number(state.entries.at(-1).height) < height) state.entries.push({ at: clock(state).toString(), height: String(height) });
    while (state.entries.length > 256) state.entries.shift();
  }
  const applyHeaders = (state, headers) => applyBlocks(state, headers.map((header) => headerFields(header)));
  function endFill(state, fill) {
    state.fills.delete(fill.id);
    const order = state.orders.get(fill.order);
    if (order?.scripts) for (const entry of order.scripts) if (entry.fill === fill.id) { delete entry.fill; entry.used = true; }
  }
  async function applyProof(state, action, raw) {
    const p = action.payload, fill = state.fills.get(p.fill) ?? refuse('no such fill');
    if (stripWitness(p.transaction) !== p.transaction || stripWitness(p.coinbase) !== p.coinbase) refuse('the Bitcoin payment transaction is carried without its witness data');
    try { await proofPayload({ fill: p.fill, script: fill.script, blockHash: p.block_hash, transaction: p.transaction, coinbase: p.coinbase, merkleProof: p.merkle_proof, vout: p.vout }); } catch (error) { refuse(`Bitcoin merkle proof does not match exactly the coinbase and the payment (${error.message})`); }
    const txid = Buffer.from(sha256d(Buffer.from(p.transaction, 'hex'))).reverse().toString('hex'), outpoint = `${txid}:${p.vout}`;
    if (state.paid.has(outpoint)) refuse('this Bitcoin output has paid for a fill already');
    const paidSats = BigInt(transactionOutputs(p.transaction)[Number(p.vout)].sats), still = BigInt(fill.sats), order = state.orders.get(fill.order);
    if (!(paidSats >= still || paidSats >= BigInt(order.min_sats) || paidSats * 2n >= still)) refuse('a payment of a part is at least the order\'s smallest trade, or half of what the fill still needs');
    const full = paidSats >= still, seconds = full ? BigInt(fill.amount_micros) : BigInt(fill.amount_micros) * paidSats / still;
    if (seconds < 1n) refuse('the payment buys less than a microsecond');
    const deposit = full ? BigInt(fill.deposit_micros) : BigInt(fill.deposit_micros) * seconds / BigInt(fill.amount_micros);
    const cost = BigInt(SDK.marketActionFee(54, p, settings.feeMicros)), sender = state.accounts.get(action.from);
    const brings = (action.from === fill.to ? seconds : 0n) + (action.from === fill.payer ? deposit : 0n);
    if (BigInt(sender.balance) + brings < cost) refuse('the sender cannot pay the fee of this proof');
    if (state.halted) refuse('Bitcoin bridge paused after reorganization');
    const block = state.headers.get(p.block_hash) ?? refuse('payment Bitcoin block unknown or pruned'), best = bestOf(state);
    const confirmed = best.height - block.height + 1;
    if (confirmed < 1) refuse('payment block is above the best height');
    if (confirmed < Number(fill.confirmations)) refuse('Bitcoin payment lacks confirmations');
    const start = Number(fill.start_height), alone = [...state.headers.values()].filter((other) => other.height === block.height).length === 1;
    if (block.height <= start) {
      if (alone || start - block.height >= 6) refuse('Bitcoin payment is not after the starting block');
      if (best.height < start + Number(fill.confirmations)) refuse('after a reorganisation a payment counts when the chain has its confirmations past the starting height');
      if (!state.headers.has(fill.start_hash)) refuse('Bitcoin payment is not after the starting block, which is no longer held');
      if (ancestor(state, fill.start_hash, block.height)?.hash === block.hash) refuse('Bitcoin payment is not after the starting block');
    }
    if (ancestor(state, best.hash, block.height)?.hash !== block.hash) refuse('payment is not on greatest-work Bitcoin chain');
    state.paid.set(outpoint, { fill: fill.id, height: String(block.height), sats: paidSats.toString() });
    const credit = (id, amount) => { const account = state.accounts.get(id); if (account) account.balance = (BigInt(account.balance) + amount).toString(); };
    credit(fill.to, seconds); credit(fill.payer, deposit);
    if (full) endFill(state, fill); else Object.assign(fill, { amount_micros: (BigInt(fill.amount_micros) - seconds).toString(), deposit_micros: (BigInt(fill.deposit_micros) - deposit).toString(), sats: (still - paidSats).toString() });
    state.trades += 1n; state.sats += paidSats < still ? paidSats : still; state.seconds += seconds; state.lastPrice = fill.price;
    sender.balance = (BigInt(sender.balance) - cost).toString();
    self.proofs.push({ fill: p.fill, outpoint, sats: paidSats.toString(), full, fee: cost.toString(), bytes: raw });
  }
  function applyExpire(state, action) {
    const fill = state.fills.get(action.payload.fill) ?? refuse('no such fill');
    const verdict = SDK.marketExpiry(view(state, { include_market: true, include_bitcoin: true }), fill);
    if (!verdict.possible) refuse({ halted: 'the Bitcoin header chain is halted: a fill ends by a release or by its owner\'s settle', height: 'the chain has not learnt the last height of this fill', grace: 'a fill ends after the time in which a proof of a payment made in time is accepted', time: 'a fill ends after its time to pay and to confirm, counted from when it was made' }[verdict.reason]);
    const sender = state.accounts.get(action.from);
    if (BigInt(sender.balance) < BigInt(settings.feeMicros)) refuse('insufficient balance');
    endFill(state, fill); sender.balance = (BigInt(sender.balance) - BigInt(settings.feeMicros)).toString();
    self.expired.push(fill.id);
  }
  /// A state in the form the verifier gives one, with the rows a selection names.
  function view(state, selection = {}) {
    const best = bestOf(state), market = { orders: {}, fills: {}, accounts: {}, scripts: {}, candles: {} };
    for (const [field, most] of Object.entries(SDK.MARKET_SELECTION)) if ((selection[field] ?? []).length > most) throw new Error('selection budget exceeded');
    if (selection.include_market) {
      market.summary = { fills: String(state.fills.size), ...(state.lastPrice ? { last_price: state.lastPrice } : {}), next_fill: state.nextFill.toString(), next_order: state.nextOrder.toString(), orders: String(state.orders.size), sats: state.sats.toString(), seconds_micros: state.seconds.toString(), trades: state.trades.toString() };
      market.heights = { entries: structuredClone(state.entries) };
    }
    for (const id of selection.market_fills ?? []) market.fills[id] = structuredClone(state.fills.get(id) ?? null);
    for (const id of selection.market_orders ?? []) market.orders[id] = structuredClone(state.orders.get(id) ?? null);
    const asked = Boolean(selection.include_market) || Object.keys(SDK.MARKET_SELECTION).some((field) => selection[field]?.length);
    return {
      height: state.height.toString(), time_micros: state.timeMicros.toString(), network_id: networkId, protocol_version: '4', stopped_micros: '0',
      genesis: { chain_id: 'time-devnet-v4-test-kit', genesis_time_micros: GENESIS_MICROS.toString() },
      config: { profile: settings.profile, waits_survive_stops: true, ...(settings.market ? { market: true } : {}), ...(settings.feeMicros === '1000' ? {} : { fee_micros: settings.feeMicros }), bitcoin: { network: bitcoin.network } },
      accounts: (selection.ids ?? []).flatMap((id) => (state.accounts.has(id) ? [structuredClone(state.accounts.get(id))] : [])),
      ...(selection.include_security ? { security: (selection.ids ?? []).flatMap((id) => (state.security.has(id) ? [structuredClone(state.security.get(id))] : [])) } : {}),
      ...(selection.include_bitcoin ? { bitcoin: { meta: {
        config: { network: bitcoin.network, confirmations: 12, max_batch: settings.maxBatch, max_fork_tips: 32, retention: 8192, max_reorg: settings.maxReorg, max_tip_age_secs: 7200, max_future_secs: 7200, mainnet_receipts_enabled: false },
        best_tip: best.hash, best_height: best.height, best_work: best.work.toString(16).padStart(64, '0'), pruned_below: 0, record_count: state.headers.size, tips: [...state.tips], credited_height: 0, credited_hash: genesis.hash, halted: structuredClone(state.halted),
      } } } : {}),
      ...(asked && settings.market ? { market } : asked ? { market: { ...market, ...(selection.include_market ? { summary: null, heights: null } : {}) } } : {}),
    };
  }
  function commit(seconds = 1) { live.height += 1n; live.timeMicros += BigInt(Math.round(seconds * 1_000_000)); shown = structuredClone(live); }
  Object.assign(self, {
    networkId, proofs: [], expired: [], commit,
    /// Lets `seconds` pass without a block's worth of actions.
    pass(seconds) { commit(seconds); },
    learn(headers) { applyHeaders(live, headers); commit(); },
    /// Takes every block of the network's best chain it lacks, by the network's own word for each block's parent
    /// (a block that was put there with `adopt` names another in its header).
    follow(source = bitcoin) { const missing = []; for (let block = source.best; block && !live.headers.has(block.hash); block = source.block(block.previous)) missing.unshift({ hash: block.hash, previous: block.previous }); for (let i = 0; i < missing.length; i += settings.maxBatch) applyBlocks(live, missing.slice(i, i + settings.maxBatch)); commit(); },
    live,
    addAccount({ id, balance = '0', nonce = '0', publicKey, canManage = false, canSpend = true, security = null }) {
      live.accounts.set(id, { id, name: `account_${id}`, public_key: publicKey, balance, nonce, auth_epoch: '0', devices: [{ public_key: publicKey, can_manage: canManage, can_spend: canSpend }] });
      if (security) live.security.set(id, { account: id, ...security });
      commit();
    },
    addOrder(row) { live.orders.set(row.id, structuredClone(row)); if (BigInt(row.id) >= live.nextOrder) live.nextOrder = BigInt(row.id) + 1n; commit(); },
    /// A fill as the engine writes one. `start_height` and `start_hash` are the chain's best block now unless given.
    addFill(row) {
      const best = bestOf(live), fill = { opened_micros: clock(live).toString(), created: { height: live.height.toString(), time_micros: live.timeMicros.toString() }, start_height: String(best.height), start_hash: best.hash, ...structuredClone(row) };
      live.fills.set(fill.id, fill); if (BigInt(fill.id) >= live.nextFill) live.nextFill = BigInt(fill.id) + 1n;
      commit(); return fill;
    },
    fill: (id) => structuredClone(live.fills.get(id) ?? null),
    account: (id) => structuredClone(live.accounts.get(id) ?? null),
    endpoint: {
      async readState(selection = {}) {
        if (self.fault === 'silent') throw new Error('no proof could be had');
        self.reads.push(structuredClone(selection));
        return { state: view(shown, selection) };
      },
      async submit(bytes) {
        if (self.fault === 'silent') throw Object.assign(new Error('The Time node did not take the action'), { code: 'UNAVAILABLE' });
        const raw = Buffer.from(bytes).toString('hex');
        self.submitted.push(raw);
        if (self.fault === 'deaf') return { accepted: true };
        if (self.fault?.refuse) { self.refusals.push(self.fault.refuse); return { accepted: false, reason: self.fault.refuse }; }
        try {
          const action = SDK.decodeAction(new Uint8Array(bytes));
          if (action.networkId !== networkId) refuse('wrong network');
          if (action.kind === 40) applyHeaders(live, action.payload.headers);
          else {
            const sender = live.accounts.get(action.from) ?? refuse('unknown account'), device = sender.devices.find((item) => item.public_key === action.publicKey);
            if (!device?.can_spend) refuse('device permission is insufficient');
            const key = await crypto.subtle.importKey('raw', SDK.hexToBytes(action.publicKey, 32), 'Ed25519', false, ['verify']), body = new Uint8Array(bytes);
            if (!(await crypto.subtle.verify('Ed25519', key, body.slice(-64), body.slice(0, -64)))) refuse('invalid signature');
            if (BigInt(action.nonce) !== BigInt(sender.nonce) + 1n) refuse('invalid nonce');
            if (action.authEpoch !== sender.auth_epoch) refuse('stale authority epoch');
            if (action.kind === 54) await applyProof(live, action, raw); else if (action.kind === 55) applyExpire(live, action); else refuse('unsupported action');
            sender.nonce = action.nonce;
          }
        } catch (error) {
          if (!error.refusal) throw error;
          self.refusals.push(error.message);
          return { accepted: false, reason: error.message };
        }
        if (self.autoCommit) commit();
        return { accepted: true };
      },
    },
  });
  // What the chain holds now, whether or not a block has shown it yet.
  Object.defineProperties(self, {
    bestHeight: { get: () => bestOf(live).height }, bestTip: { get: () => live.best }, halted: { get: () => live.halted }, clockEntries: { get: () => live.entries },
  });
  return self;
}

/// A clock a test moves by hand.
export function createClock(start = 1_800_000_000_000) {
  let at = start;
  const now = () => at;
  now.advance = (ms) => { at += ms; };
  return now;
}
/// A log that keeps its lines: `lines` holds `{ level, message, ...fields }`, `text()` everything as one string.
export function createLog() {
  const lines = [];
  const log = (level, message, fields = {}) => { lines.push({ level, message, ...fields }); };
  log.lines = lines;
  log.text = () => JSON.stringify(lines);
  log.said = (pattern) => lines.filter((line) => pattern.test(line.message));
  return log;
}
/// A block made elsewhere, from a proof of the vectors (spec/market-vectors.json): the header its Merkle proof
/// begins with, and the two transactions as a node gives them.
export function vectorBlock(action) {
  return { header: action.payload.merkle_proof.slice(0, 160), transactions: [action.bitcoin_node.coinbase, action.bitcoin_node.transaction] };
}
export { readBlock };
