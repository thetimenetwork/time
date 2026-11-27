// The prover of Bitcoin payments, for a Time chain with the market (spec/market.md).
//
// A buyer takes a sell order, pays bitcoin to the address of the fill, and the chain hands the seconds over when
// someone shows it a proof of that payment (kind 54). A wallet in a browser cannot ask a Bitcoin node for one. This
// service does: it finds the payments to the addresses of open fills and sends the proofs, with a key and an
// account of its own. Anyone may prove any payment, and nobody is paid for it: a proof costs its sender a fee.
//
// WHICH FILLS ARE OPEN is read from the chain's PROVEN state and from nothing else. The ids of fills are dense,
// from 1 to `next_fill` - 1 of the market's summary; a fill that has ended has no row and never has one again. So
// the prover reads the rows sixteen at a time (what one proof may carry), keeps the ones that exist, reads those
// again every round, and reads the new ids as `next_fill` grows. At its first start it reads downwards from the
// newest and stops when it has found as many open fills as the summary counts. No index and no API is asked: an
// index could leave a fill out, or invent one.
//
// WHICH PAYMENTS. The prover looks at Bitcoin through the chain's eyes. It starts from the chain's best Bitcoin
// block, whose hash is proven, and walks down from it on a node: each header names its parent's hash, and each
// header is held to the hash it was asked by. So every block the prover reads is an ancestor of the block the
// chain itself holds as its best, whatever the node says its own best chain is. A node cannot show the prover a
// block that is not on the chain's best chain; it can only fail to give one. Every such block from the lowest
// height at which an open fill can still be paid is read once for each fill, by its hash, held to its header, and
// searched for outputs that pay a fill's script. A block is known by its hash, never by its height: after a
// reorganisation the walk finds other blocks at the same heights, and those are read.
// - A payment counts above the fill's starting height. At or below it, it counts only after a reorganisation, in a
//   block that was not on the chain the fill started on, fewer than six blocks below (5.2, point 7). So the search
//   starts five blocks below the lowest starting height, and what it finds there is tried only when the fill's
//   starting block is no longer on the chain's best chain.
// - The confirmations are counted on the chain's view: its proven best height less the block's height, plus one.
//   A node that is ahead of the chain does not make a payment ready, and one that is behind does not hold it back
//   once another node has the block.
//
// WHEN IT SENDS. A payment that has its confirmations and counts (it pays what is still to pay, or at least the
// order's smallest trade, or at least half of what is still to pay) is proven: the payment's transaction and the
// block's coinbase from a node, both without witness data, the Merkle proof of the two (`gettxoutproof`), put
// together and checked by `proofPayload`. The proof is signed with the prover's key and handed in. Then the
// account and the fill are read again, with a proof, until the account's nonce shows the action in a block, and
// the log says what the fill held before and holds after.
//
// IT DOES NOT SEND TWICE, AND DOES NOT HAMMER. One action is on its way at a time. What was sent is remembered by
// the output it proves. A proof the chain refuses is in no block and costs no fee; it is tried again later, each
// time after a longer wait, and "this output has paid already" ends it. The rows that record counted outputs
// (`market/paid/`) cannot be read with a proof, so that refusal is the endpoint's word; what the prover trusts is
// the fill's own row, whose `sats` fall when a payment is counted.
//
// WHAT CANNOT BE PROVEN is said once, in plain words: a payment in a transaction above 100,000 bytes without its
// witness data, a block whose coinbase is above 150,000 bytes, an output of a coinbase, a payment too small to
// count. Only the seller's settle (kind 57) delivers the seconds for the first three.
//
// FEES. A proof pays the network's fee once more for every 256 bytes of its payload (`marketActionFee`). The
// operator sets the most one proof may cost and the most a day may cost; a proof above the first is not sent, and
// when the second is used up nothing is sent until the next day (UTC), and the health answer says so.
//
// THE KEY signs actions of the prover's own account and nothing else. The prover checks, with a proof, at its start
// and in every round: that the key is a key of the account that may spend; that the account has adopted the
// security rules, with this key a spend key only (unless the operator said otherwise); and that the account holds
// no more than the ceiling the operator set. It sends nothing while one of these fails. The key is never logged,
// never part of an error, and never leaves the process.
import './time-sdk.js';
import { proofPayload } from './bitcoin-address.mjs';
import { BitcoinRpcError, headerFields, paymentsIn } from './bitcoin-rpc.mjs';
import { allowance, frozen, roleOf, securityOf } from './account-security.mjs';
import { createOnce, headerChainOf, OPEN_NETWORKS } from './market-service.mjs';

const SDK = globalThis.TimeSDK;
/// The sizes a proof may carry (spec/market.md, 2.1), and how far at or below its starting height a payment may lie.
export const MAX_PAYMENT_BYTES = 100_000, MAX_COINBASE_BYTES = 150_000, START_SLACK = 6;
const ROWS = SDK.MARKET_SELECTION.market_fills;
/// What the engine says when it refuses a proof or an expiry (v5/src/market.rs, bitcoin-bridge/src/payment.rs).
/// These are an endpoint's words. They decide how long the prover waits before it tries again; `counted` and
/// `ended` end the tries for one output, which costs a buyer nothing a lying endpoint could not cost them anyway
/// by dropping the action.
const SAID = Object.freeze({
  counted: /this Bitcoin output has paid for a fill already/i,
  ended: /no such fill/i,
  before: /not after the starting block/i,
  later: /lacks confirmations|above the best height|unknown or pruned|not on greatest-work|past the starting height|not learnt the last height|a fill ends after/i,
  funds: /cannot pay the fee|insufficient|daily limit|frozen/i,
  halted: /paused after|is halted/i,
  small: /a payment of a part is at least|less than a microsecond/i,
});
/// What a refusal means to the prover: 'counted', 'ended', 'before', 'later', 'funds', 'halted', 'small' or 'other'.
export const refusalKind = (reason) => Object.keys(SAID).find((name) => SAID[name].test(reason)) ?? 'other';
const said = refusalKind;

async function mapLimit(items, limit, work) {
  const results = new Array(items.length); let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => { while (next < items.length) { const index = next++; results[index] = await work(items[index]); } }));
  return results;
}
const chunks = (list, size) => Array.from({ length: Math.ceil(list.length / size) }, (_, index) => list.slice(index * size, (index + 1) * size));
const day = (ms) => new Date(ms).toISOString().slice(0, 10);

/// What the prover remembers between starts: which ids of fills it has looked at, which fills were open, and what
/// it spent today. `load()` gives the stored object or null; `save(value)` replaces it. In memory unless given.
export function memoryStore(initial = null) {
  let held = initial === null ? null : structuredClone(initial);
  return { load: async () => (held === null ? null : structuredClone(held)), save: async (value) => { held = structuredClone(value); }, get value() { return held; } };
}

/// The prover. `nodes` is what `createBitcoinNodes` gives; `readState` and `submit` are those of a Time endpoint;
/// `account` is the prover's own account (a decimal id) and `key` its `{ publicKey, privateKey }`.
/// Settings (amounts in microseconds, as BigInt or decimal strings):
/// - `maxBalanceMicros`: the ceiling; nothing is sent while the account holds more. `minBalanceMicros`: a warning.
/// - `maxFeePerProofMicros`, `maxFeesPerDayMicros`: the budgets.
/// - `expire` (false): also end fills whose time has passed and for which no payment is known (kind 55).
/// - `allowUnsecured` (false): use an account that has not adopted the security rules.
/// - `only`: the id of one fill; nothing else is looked at (the one-shot tool).
/// - `maxProofsPerRound` (8), `maxBlocksPerRound` (64), `maxReadsPerRound` (32 proofs of 16 fills), `pollMs`
///   (10000), `settleMs` (20000: how long a round waits for its action to show in a block), `settleStepMs` (1000),
///   `abandonMs` (300000: after this long an action that is in no block is given up).
/// Returns `{ round(), health(), report(), start(), stop() }`. `round()` resolves to `{ more }`.
export function createProver({ nodes, readState, submit, networkId, account, key, store = memoryStore(), log = () => {}, now = Date.now, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)), settings = {} }) {
  const {
    expire = false, allowUnsecured = false, only = null, maxProofsPerRound = 8, maxBlocksPerRound = 64, maxReadsPerRound = 32, pollMs = 10000, catchUpMs = 1000, settleMs = 20000, settleStepMs = 1000, abandonMs = 300000,
  } = settings;
  const amount = (name) => { const value = settings[name]; if (value === undefined || value === null || !/^(0|[1-9][0-9]{0,18})$/.test(String(value))) throw new Error(`${name} is a whole number of microseconds`); return BigInt(value); };
  const ceiling = amount('maxBalanceMicros'), feeLimit = amount('maxFeePerProofMicros'), dayLimit = amount('maxFeesPerDayMicros'), lowBalance = settings.minBalanceMicros === undefined ? 0n : amount('minBalanceMicros');
  if (typeof account !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(account)) throw new Error('account is the number of the prover\'s account, in decimal');
  if (only !== null && (typeof only !== 'string' || !/^[1-9][0-9]{0,19}$/.test(only))) throw new Error('only is the id of a fill');
  const once = createOnce({ now });

  // ---- what is known
  const fills = new Map(), minSats = new Map();
  // Every id from `low` to `high` has been looked at; an ended fill never comes back.
  let low = null, high = null, loaded = false;
  // The chain's best chain, as heights -> hashes, for the heights the open fills need.
  const heights = new Map();
  // Block hash -> the ids of the fills it was searched for.
  const scanned = new Map();
  // `${txid}:${vout}` -> a payment to the script of an open fill.
  const payments = new Map();
  // The action on its way: { kind, fill, outpoint, nonce, fee, at, bytes, before }.
  let inFlight = null;
  // Fill id -> when an expiry the chain refused may be tried again.
  const expireNotBefore = new Map();
  let spent = { day: day(now()), micros: 0n, proofs: 0, expiries: 0 };
  const seen = {
    startedAt: now(), lastRoundAt: null, lastGoodRoundAt: null, status: 'starting', problems: [], warnings: new Set(), stateHeight: null, chain: null, views: [], nextFill: null, balance: null, leftToScan: 0,
    proven: 0, expired: 0, lastProofAt: null, withheld: 0,
  };
  const events = [];
  const tell = (level, message, fields = {}) => { log(level, message, fields); events.push({ level, message, ...fields }); if (events.length > 500) events.shift(); };

  // What a service remembered of the fills, kept as it was by the one-shot tool, which looks at one fill only.
  let book = { low: null, high: null, open: [] };
  async function remember() {
    if (only === null) book = { low: low?.toString() ?? null, high: high?.toString() ?? null, open: [...fills.keys()] };
    await store.save({ network_id: networkId, account, ...book, day: spent.day, spent_micros: spent.micros.toString(), proofs: spent.proofs, expiries: spent.expiries });
  }
  async function recall() {
    loaded = true;
    let held = null;
    try { held = await store.load(); } catch { tell('warn', 'what the prover remembered could not be read; it starts afresh'); }
    if (!held || held.network_id !== networkId || held.account !== account) return;
    book = { low: held.low ?? null, high: held.high ?? null, open: Array.isArray(held.open) ? held.open : [] };
    if (only === null && /^[0-9]+$/.test(held.low ?? '') && /^[0-9]+$/.test(held.high ?? '')) { low = BigInt(held.low); high = BigInt(held.high); for (const id of held.open ?? []) if (/^[1-9][0-9]*$/.test(id)) fills.set(id, null); }
    if (held.day === spent.day && /^[0-9]+$/.test(held.spent_micros ?? '')) spent = { day: held.day, micros: BigInt(held.spent_micros), proofs: Number(held.proofs) || 0, expiries: Number(held.expiries) || 0 };
  }
  const today = () => { const date = day(now()); if (date !== spent.day) spent = { day: date, micros: 0n, proofs: 0, expiries: 0 }; return spent; };

  // ---- the prover's own account, as a state proves it
  function accountOf(state) {
    const row = (state.accounts ?? []).find((item) => String(item.id) === account), device = (row?.devices ?? []).find((item) => item.public_key === key.publicKey);
    const role = device ? roleOf(device) : undefined, security = row ? securityOf(state, account) : null, clock = BigInt(SDK.securityNow(state));
    const problem = !row ? 'the prover\'s account does not exist on this network'
      : !device ? 'the key is not a key of the prover\'s account'
        : !device.can_spend ? 'the key may not spend for the prover\'s account'
          : !allowUnsecured && role === null ? 'the key holds every power of the prover\'s account: the account must adopt the security rules, and the prover hold a spend key only'
            : !allowUnsecured && !security ? 'the prover\'s account has not adopted the security rules: no daily limit bounds its key'
              : BigInt(row.balance) > ceiling ? 'the prover\'s account holds more than max_balance_micros: move the surplus away'
                : security && frozen(security, clock) ? 'the prover\'s account is frozen'
                  : null;
    if (!row) return { problem };
    return { problem, balance: BigInt(row.balance), nonce: BigInt(row.nonce), authEpoch: String(row.auth_epoch), fee: BigInt(SDK.networkFee(state)), allowance: security ? allowance(security, clock) : null };
  }

  // ---- the open fills
  async function readFills(ids, budget) {
    for (const group of chunks(ids, ROWS)) {
      if (budget.reads <= 0) return false;
      budget.reads -= 1;
      const { state } = await readState({ market_fills: group });
      for (const id of group) { const row = SDK.marketFill(state, id); if (row === null) fills.delete(id); else fills.set(id, row); }
    }
    return true;
  }
  /// Brings the set of open fills up to date. Returns whether every id has been looked at.
  async function lookAtFills(summary, budget) {
    const next = BigInt(summary.next_fill);
    seen.nextFill = next.toString();
    if (low === null) { low = next; high = next - 1n; }
    // The one-shot tool looks at one fill and at nothing else.
    if (only !== null) { low = 1n; high = next - 1n; fills.set(only, fills.get(only) ?? null); }
    let whole = await readFills([...fills.keys()].sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1)), budget);
    // New ids, upwards.
    while (whole && high < next - 1n) {
      const group = []; for (let id = high + 1n; id < next && group.length < ROWS; id++) group.push(id.toString());
      whole = await readFills(group, budget);
      if (whole) high += BigInt(group.length);
    }
    // At a first start: downwards from the newest, until as many open fills are found as the summary counts.
    while (whole && low > 1n && fills.size < Number(summary.fills)) {
      const group = []; for (let id = low - 1n; id >= 1n && group.length < ROWS; id--) group.push(id.toString());
      whole = await readFills(group, budget);
      if (whole) low -= BigInt(group.length);
    }
    // The smallest trade of each order a fill came from: part of a row that never changes.
    const unknown = [...new Set([...fills.values()].filter(Boolean).map((fill) => fill.order).filter((id) => !minSats.has(id)))];
    for (const group of chunks(unknown, SDK.MARKET_SELECTION.market_orders)) {
      if (budget.reads <= 0) return false;
      budget.reads -= 1;
      const { state } = await readState({ market_orders: group });
      for (const id of group) { const row = SDK.marketOrder(state, id); if (row !== null) minSats.set(id, BigInt(row.min_sats)); }
    }
    return whole && low <= 1n ? true : whole && fills.size >= Number(summary.fills);
  }

  // ---- the chain's best chain on a node
  /// Brings `heights` up to date between `from` and the chain's best height: the blocks under the chain's proven
  /// best block, found by walking down from it on a node. `rpc.header` holds each header to the hash it was asked
  /// by, so what a node gives is that block's header or a failure. After a reorganisation the walk goes down to the
  /// fork, and the heights above it get their new hashes.
  async function mapHeights(rpc, chain, from) {
    for (const height of [...heights.keys()]) if (height < from || height > chain.bestHeight) heights.delete(height);
    // Nothing is written until the whole walk is done: a walk that a node breaks off leaves what was known.
    const fresh = [];
    const before = async (hash) => headerFields(await rpc.header(hash)).previous;
    let height = chain.bestHeight, hash = chain.bestTip;
    // From the proven best block down, header by header, until a block that is the one known at its height:
    // below it nothing has changed, for a block has one parent.
    for (; height >= from && heights.get(height) !== hash; height--) {
      fresh.push([height, hash]);
      if (height > from) hash = await before(hash);
    }
    // A fill that started lower than every fill before it: the map goes on downwards from its lowest block.
    if (height >= from) {
      let lowest = height;
      while (lowest > from && heights.has(lowest - 1)) lowest -= 1;
      hash = heights.get(lowest);
      for (height = lowest - 1; height >= from; height--) { hash = await before(hash); fresh.push([height, hash]); }
    }
    for (const [at, block] of fresh) heights.set(at, block);
  }
  const lowestHeight = (fill) => Math.max(0, Number(fill.start_height) - (START_SLACK - 1));

  /// Searches the blocks the open fills need and that were not searched for them yet. Returns the number left.
  async function scan(sources, chain, budget) {
    const open = [...fills.values()].filter(Boolean);
    if (open.length === 0) { scanned.clear(); return 0; }
    const from = Math.min(...open.map(lowestHeight));
    let left = 0;
    for (let height = from; height <= chain.bestHeight; height++) {
      const hash = heights.get(height), done = scanned.get(hash) ?? new Set();
      const wanted = open.filter((fill) => height >= lowestHeight(fill) && !done.has(fill.id));
      if (wanted.length === 0) continue;
      if (budget.blocks <= 0) { left += 1; continue; }
      budget.blocks -= 1;
      let block;
      try { block = await nodes.first(sources, (rpc) => rpc.block(hash)); } catch (error) {
        if (!(error instanceof BitcoinRpcError)) throw error;
        left += 1; seen.withheld += 1;
        if (once(`block|${hash}`)) tell('warn', 'a Bitcoin block could not be had from any node; it is asked for again next round', { height, block: hash, code: error.code });
        continue;
      }
      const byScript = new Map(wanted.map((fill) => [fill.script, fill]));
      for (const found of paymentsIn(block, new Set(byScript.keys()))) {
        const fill = byScript.get(found.script), outpoint = `${found.txid}:${found.vout}`, before = payments.get(outpoint);
        const cannot = found.index === 0 ? 'it is an output of a coinbase transaction, which pays for no fill'
          : found.bareBytes > MAX_PAYMENT_BYTES ? `its transaction is ${found.bareBytes.toLocaleString('en-US')} bytes without witness data, and a proof carries at most ${MAX_PAYMENT_BYTES.toLocaleString('en-US')}`
            : block.transactions[0].bareBytes > MAX_COINBASE_BYTES ? `the coinbase transaction of its block is ${block.transactions[0].bareBytes.toLocaleString('en-US')} bytes, and a proof carries at most ${MAX_COINBASE_BYTES.toLocaleString('en-US')}`
              : null;
        if (before && before.blockHash !== hash) tell('warn', 'a payment is in another block after a reorganisation', { fill: fill.id, txid: found.txid, vout: found.vout, was: before.blockHash, now: hash, height });
        payments.set(outpoint, { ...(before && before.blockHash === hash ? before : {}), outpoint, fill: fill.id, script: found.script, sats: BigInt(found.sats), txid: found.txid, vout: found.vout, blockHash: hash, height, coinbaseTxid: block.transactions[0].txid, cannot, done: before?.done ?? false });
        if (!before) tell('info', 'found a payment to the address of a fill', { fill: fill.id, txid: found.txid, vout: found.vout, sats: found.sats, height, block: hash });
        if (cannot && once(`cannot|${outpoint}|${hash}`)) tell('error', `A PAYMENT CANNOT BE PROVEN: ${cannot}. Only the seller's settle (kind 57) delivers the seconds for it.`, { fill: fill.id, txid: found.txid, vout: found.vout, sats: found.sats, height, block: hash });
      }
      for (const fill of wanted) done.add(fill.id);
      scanned.set(hash, done);
    }
    // Blocks that left the chain's best chain, and those no open fill needs any more, are forgotten.
    const live = new Set(heights.values());
    for (const hash of scanned.keys()) if (!live.has(hash)) scanned.delete(hash);
    return left;
  }

  // ---- sending
  /// Reads the prover's account and one fill again, with a proof.
  async function look(fillId, extra = {}) {
    const { state } = await readState({ ids: [account], include_security: true, market_fills: [fillId], ...extra });
    return { state, me: accountOf(state), fill: SDK.marketFill(state, fillId) };
  }
  /// Why nothing can be paid for now, or null: a budget, the balance, the daily limit of the account.
  function cannotPay(me, fee, brings = 0n) {
    const used = today();
    if (fee > feeLimit) return 'above_fee_limit';
    if (used.micros + fee > dayLimit) return 'daily_fee_budget_used_up';
    if (me.balance + brings < fee) return 'balance_too_low';
    if (me.allowance !== null && me.allowance + brings < fee) return 'daily_limit_of_the_account_used_up';
    return null;
  }
  /// Signs and hands in one action of the prover's account, then waits for the account's nonce to show it in a
  /// block. Returns `{ sent: false, reason }` (refused, in the endpoint's words), or `{ sent: true, included, after }`:
  /// `after` is the look that showed it, or null when no block held it within `settleMs`.
  async function send(kind, payload, fee, me, fillId, note) {
    const nonce = me.nonce + 1n, bytes = await SDK.signAction({ networkId, kind, from: account, nonce: nonce.toString(), authEpoch: me.authEpoch, publicKey: key.publicKey, payload }, key.privateKey);
    // Remembered before it leaves: if nobody answers, the bytes may still have arrived, and the next round sends
    // the same bytes again and signs nothing new.
    inFlight = { kind, fill: fillId, nonce, fee, at: now(), bytes, ...note };
    const answer = await submit(bytes);
    if (!answer.accepted) { inFlight = null; return { sent: false, reason: answer.reason }; }
    return { sent: true, ...(await settle()) };
  }
  /// Waits until a proof shows the nonce of the action on its way, or `settleMs` have passed.
  async function settle() {
    for (const until = now() + settleMs; ;) {
      const after = await look(inFlight.fill);
      if (after.me.nonce !== undefined && after.me.nonce >= inFlight.nonce) return { included: true, after };
      if (now() >= until) return { included: false, after: null };
      await sleep(settleStepMs);
    }
  }
  /// What a block did with the action that was on its way, said and counted.
  async function conclude(after) {
    const flown = inFlight, used = today();
    inFlight = null;
    seen.balance = after.me.balance ?? seen.balance;
    const paid = flown.before.balance - after.me.balance + (flown.brings ?? 0n);
    if (flown.kind === 54) {
      const payment = payments.get(flown.outpoint), before = flown.before.fill, counted = after.fill === null || BigInt(after.fill.sats) < BigInt(before.sats);
      if (!counted) {
        // The nonce moved and the fill did not: another action took the nonce. Nothing was paid for this proof.
        seen.warnings.add('nonce_used_elsewhere');
        tell('error', 'the account\'s nonce moved without this proof: the key is used by something else. The proof is tried again', { fill: flown.fill });
        if (payment) payment.nextAt = now() + 5000;
        return;
      }
      used.micros += paid > 0n ? paid : flown.fee; used.proofs += 1; seen.proven += 1; seen.lastProofAt = now();
      if (payment) payment.done = true;
      tell('info', after.fill === null ? 'proof counted: the fill is paid in full and has ended' : 'proof counted: a part of the fill is paid', {
        fill: flown.fill, txid: payment?.txid, vout: payment?.vout, paid_sats: payment?.sats.toString(), fee_micros: (paid > 0n ? paid : flown.fee).toString(),
        before: { sats: before.sats, amount_micros: before.amount_micros, deposit_micros: before.deposit_micros },
        after: after.fill === null ? null : { sats: after.fill.sats, amount_micros: after.fill.amount_micros, deposit_micros: after.fill.deposit_micros },
      });
      if (after.fill === null) fills.delete(flown.fill); else fills.set(flown.fill, after.fill);
    } else {
      if (after.fill !== null) { tell('error', 'the account\'s nonce moved without this expiry: the key is used by something else', { fill: flown.fill }); seen.warnings.add('nonce_used_elsewhere'); return; }
      used.micros += paid > 0n ? paid : flown.fee; used.expiries += 1; seen.expired += 1;
      fills.delete(flown.fill);
      tell('info', 'a fill whose time had passed has ended: its seconds are back with the seller', { fill: flown.fill, fee_micros: (paid > 0n ? paid : flown.fee).toString() });
    }
    await remember();
  }
  /// Whether a payment at or below its fill's starting height can count (5.2, point 7): 'yes', 'never', 'wait' (the
  /// new branch is not yet the confirmations past the start), or 'unknown' (no node has the chain the fill started
  /// on: the chain is asked).
  async function afterStart(rpc, payment, fill, chain) {
    const start = Number(fill.start_height);
    if (payment.height > start) return 'yes';
    if (start - payment.height >= START_SLACK) return 'never';
    // The fill's starting block is still on the chain's best chain: nothing below it was reorganised, the
    // payment's block was there when the fill was made, and the payment is older than the fill.
    if (heights.get(start) === fill.start_hash) return 'never';
    // Otherwise: the block at the payment's height on the chain the fill started on, by walking that chain down.
    let hash = fill.start_hash;
    for (let height = start; height > payment.height; height--) {
      try { hash = headerFields(await rpc.header(hash)).previous; } catch (error) { if (error instanceof BitcoinRpcError && error.code === 'REFUSED') return 'unknown'; throw error; }
    }
    if (hash === payment.blockHash) return 'never';
    return chain.bestHeight >= start + Number(fill.confirmations) ? 'yes' : 'wait';
  }
  /// The payload of the proof of a payment, from the first node that gives what `proofPayload` accepts.
  async function build(sources, payment, fill) {
    let last = new BitcoinRpcError('UNAVAILABLE', 'No Bitcoin node is usable');
    for (const node of sources) {
      try {
        const [transaction, coinbase, merkleProof] = [await node.rpc.rawTransaction(payment.txid, payment.blockHash), await node.rpc.rawTransaction(payment.coinbaseTxid, payment.blockHash), await node.rpc.txOutProof([payment.coinbaseTxid, payment.txid], payment.blockHash)];
        return SDK.marketActionPayload(54, await proofPayload({ fill: fill.id, script: fill.script, blockHash: payment.blockHash, transaction, coinbase, merkleProof, vout: payment.vout }));
      } catch (error) { last = error; }
    }
    throw last;
  }

  /// Proves what is ready, one payment after the other. Returns `{ stop, more, counted }`: why nothing more is sent
  /// this round (or null), whether proofs are left for the next one, and how many were counted.
  async function prove(primary, sources, chain, budget) {
    const ready = [...payments.values()].filter((payment) => !payment.done && !payment.cannot && !payment.never && heights.get(payment.height) === payment.blockHash && fills.get(payment.fill))
      .sort((a, b) => (a.height - b.height) || (a.sats === b.sats ? 0 : a.sats > b.sats ? -1 : 1));
    let counted = 0;
    for (const payment of ready) {
      if (budget.proofs <= 0) return { stop: null, more: true, counted };
      if (payment.nextAt !== undefined && payment.nextAt > now()) continue;
      const { me, fill } = await look(payment.fill);
      if (fill === null) { fills.delete(payment.fill); continue; }
      fills.set(fill.id, fill);
      if (me.problem) return { stop: 'key', counted };
      if (chain.bestHeight - payment.height + 1 < Number(fill.confirmations)) continue;
      const placed = await afterStart(primary.rpc, payment, fill, chain);
      if (placed === 'never') {
        payment.never = true;
        if (once(`never|${payment.outpoint}`)) tell('info', 'a payment to the address of a fill was made in a block at or below the block the fill started on: it does not count for this fill', { fill: fill.id, txid: payment.txid, vout: payment.vout, height: payment.height, start_height: fill.start_height });
        continue;
      }
      if (placed === 'wait') continue;
      const least = minSats.get(fill.order), still = BigInt(fill.sats);
      const counts = payment.sats >= still || (least !== undefined && payment.sats >= least) || payment.sats * 2n >= still;
      if (!counts || SDK.marketFillBuys(fill, payment.sats.toString()) === '0') {
        payment.small = true;
        if (once(`small|${payment.outpoint}|${fill.sats}`)) tell('warn', 'a payment is too small to count now: it is less than the order\'s smallest trade and less than half of what the fill still needs. It is tried again when the fill needs less', { fill: fill.id, txid: payment.txid, vout: payment.vout, paid_sats: payment.sats.toString(), still_to_pay_sats: fill.sats, smallest_trade_sats: least?.toString() ?? null });
        continue;
      }
      payment.small = false;
      let payload;
      try { payload = await build(sources, payment, fill); } catch (error) {
        payment.tries = (payment.tries ?? 0) + 1; payment.nextAt = now() + Math.min(600_000, 5000 * 2 ** payment.tries);
        if (once(`build|${payment.outpoint}`)) tell('warn', 'the proof of a payment could not be put together from any node; it is tried again later', { fill: fill.id, txid: payment.txid, reason: error instanceof BitcoinRpcError ? `${error.code}: ${error.message}` : String(error.message).slice(0, 160) });
        continue;
      }
      const fee = BigInt(SDK.marketActionFee(54, payload, me.fee.toString())), seconds = BigInt(SDK.marketFillBuys(fill, payment.sats.toString()));
      // What the proof brings its sender, when the prover is itself a side of the fill.
      const brings = (account === fill.to ? seconds : 0n) + (account === fill.payer ? (payment.sats >= still ? BigInt(fill.deposit_micros) : BigInt(fill.deposit_micros) * seconds / BigInt(fill.amount_micros)) : 0n);
      const unpaid = cannotPay(me, fee, brings);
      if (unpaid === 'above_fee_limit') {
        // Looked at again in an hour: the proof is put together anew each time, and its size does not change.
        payment.costly = true; payment.nextAt = now() + 3_600_000;
        if (once(`fee|${payment.outpoint}`)) tell('warn', 'a proof would cost more than max_fee_per_proof_micros and is not sent', { fill: fill.id, txid: payment.txid, fee_micros: fee.toString() });
        continue;
      }
      payment.costly = false;
      if (unpaid) return { stop: unpaid, counted };
      budget.proofs -= 1;
      const result = await send(54, payload, fee, me, fill.id, { outpoint: payment.outpoint, brings, before: { fill, balance: me.balance } });
      if (!result.sent) {
        const why = said(result.reason);
        if (why === 'counted') { payment.done = true; tell('info', 'the chain says this output has paid for its fill already: someone else proved it', { fill: fill.id, txid: payment.txid, vout: payment.vout }); continue; }
        if (why === 'ended') { fills.delete(fill.id); continue; }
        if (why === 'before') {
          payment.never = true;
          tell('info', 'the chain says this payment is not after the block its fill started on: it does not count for this fill', { fill: fill.id, txid: payment.txid, vout: payment.vout, height: payment.height, start_height: fill.start_height });
          continue;
        }
        payment.tries = (payment.tries ?? 0) + 1; payment.nextAt = now() + Math.min(600_000, 5000 * 2 ** payment.tries);
        if (why === 'halted') return { stop: 'halted', counted };
        if (why === 'funds') return { stop: 'refused_for_funds', counted };
        if (once(`refused|${payment.outpoint}|${why}`)) tell(why === 'later' ? 'info' : 'warn', 'the chain refused a proof; it cost nothing and is tried again later', { fill: fill.id, txid: payment.txid, vout: payment.vout, reason: result.reason, next_try_in_seconds: Math.round((payment.nextAt - now()) / 1000) });
        continue;
      }
      if (!result.included) return { stop: 'in_flight', counted };
      await conclude(result.after);
      counted += 1;
    }
    return { stop: null, more: false, counted };
  }

  /// Ends fills whose time has passed and for which no payment is known. Returns `{ stop }` as `prove`.
  async function expireDue(chain, scannedAll) {
    // A fill is not ended while a block it could be paid in has not been searched: a payment may be in it.
    if (!scannedAll) return { stop: null };
    let sent = 0;
    for (const id of [...fills.keys()]) {
      if (sent >= 4) break;
      if ([...payments.values()].some((payment) => payment.fill === id && !payment.never)) continue;
      if (!fills.get(id) || (expireNotBefore.get(id) ?? 0) > now()) continue;
      const { state, me, fill } = await look(id, { include_market: true, include_bitcoin: true });
      if (fill === null) { fills.delete(id); continue; }
      if (me.problem) return { stop: 'key' };
      const verdict = SDK.marketExpiry(state, fill);
      if (!verdict.possible) continue;
      const payload = SDK.marketExpire({ fill: id }), fee = BigInt(SDK.marketActionFee(55, payload, me.fee.toString())), unpaid = cannotPay(me, fee);
      if (unpaid) return { stop: unpaid };
      sent += 1;
      const result = await send(55, payload, fee, me, id, { before: { fill, balance: me.balance } });
      if (!result.sent) {
        const why = said(result.reason);
        if (why === 'ended') { fills.delete(id); continue; }
        if (why === 'halted') return { stop: 'halted' };
        if (why === 'funds') return { stop: 'refused_for_funds' };
        expireNotBefore.set(id, now() + 60_000);
        if (once(`expire|${id}|${why}`)) tell('info', 'the chain refused an expiry; it cost nothing and is tried again later', { fill: id, reason: result.reason });
        continue;
      }
      if (!result.included) return { stop: 'in_flight' };
      await conclude(result.after);
    }
    return { stop: null };
  }

  let running = null;
  /// One round. Never throws: what went wrong is in the log and in the health answer.
  function round() { return running ??= turn().catch((error) => { seen.status = 'failing'; seen.problems = ['a round failed']; if (once(`round|${error?.code ?? error?.message}`)) tell('warn', 'a round could not be finished', { code: error instanceof BitcoinRpcError ? error.code : error?.code === 'UNAVAILABLE' ? 'TIME_ENDPOINT_UNAVAILABLE' : 'INTERNAL', ...(error instanceof BitcoinRpcError || error?.code === 'UNAVAILABLE' ? {} : { what: String(error?.message).slice(0, 160) }) }); return { more: false }; }).finally(() => { running = null; }); }
  async function turn() {
    const at = now();
    seen.lastRoundAt = at;
    if (!loaded) await recall();
    const fail = (status, problem, level = 'warn') => { seen.status = status; seen.problems = [problem]; if (once(`${status}|${problem}`)) tell(level, problem); return { more: false }; };
    let state, chain;
    try { state = (await readState({ ids: [account], include_security: true, include_bitcoin: true, include_market: true })).state; chain = headerChainOf(state); } catch (error) {
      return fail('time_unreachable', SDK.isUpgradeRequired(error) ? 'the Time chain runs a protocol version this prover does not implement: install the release that does' : 'no proven state of the Time chain could be read');
    }
    seen.stateHeight = String(state.height); seen.chain = chain; seen.warnings = new Set();
    if (!SDK.marketSetting(state)) return fail('no_market', 'this Time network has no market: there is nothing to prove', 'error');
    if (!OPEN_NETWORKS.includes(chain.network)) return fail('refused_network', 'this Time network follows Bitcoin mainnet, which is closed in this version of the market: the prover sends nothing', 'error');
    const me = accountOf(state);
    seen.balance = me.balance ?? null;
    if (me.problem) return fail('key_or_account', `${me.problem}. Nothing is sent.`, 'error');
    if (me.balance < lowBalance) seen.warnings.add('balance_low');
    // An action that was on its way when the last round ended.
    if (inFlight) {
      if (me.nonce >= inFlight.nonce) await conclude(await look(inFlight.fill));
      else if (at - inFlight.at > abandonMs) { tell('warn', 'an action the endpoint took is in no block after a long while; it is given up. If a block takes it later, its fee is not counted in the day\'s budget', { fill: inFlight.fill, kind: inFlight.kind }); inFlight = null; } else {
        // The same bytes again: a node that has them says so, and one that lost them has them back. A node that
        // refuses them now does not hold them: unless a block took them meanwhile, they are in no block and will
        // be in none, and the prover is free to sign again.
        const again = await submit(inFlight.bytes).catch(() => null);
        if (again && !again.accepted) {
          const after = await look(inFlight.fill);
          if (after.me.nonce >= inFlight.nonce) await conclude(after); else inFlight = null;
        } else {
          seen.warnings.add('an_action_is_in_no_block_yet');
          seen.status = 'waiting_for_a_block'; seen.problems = []; seen.lastGoodRoundAt = at;
          return { more: false };
        }
      }
    }
    const budget = { reads: maxReadsPerRound, blocks: maxBlocksPerRound };
    const summary = SDK.marketSummary(state), wholeBook = await lookAtFills(summary, budget);
    if (chain.halted) {
      seen.status = 'halted'; seen.problems = ['the header chain of the Time chain is halted'];
      if (once('halted')) tell('error', 'THE BITCOIN HEADER CHAIN OF THE TIME CHAIN IS HALTED. No proof and no expiry is accepted: a fill ends by its buyer\'s release or its seller\'s settle only (spec/market.md, 10.5). The prover sends nothing.', { reason: chain.halted.reason, best_height: chain.bestHeight });
      await remember();
      return { more: false };
    }
    const views = await nodes.look(chain.network), usable = views.filter((view) => view.ok);
    for (const view of views) if (!view.ok && once(`node|${view.name}|${view.problem}`)) tell('warn', 'a Bitcoin node is not usable', { node: view.name, problem: view.problem });
    // A node can show Bitcoin as the chain sees it when it has the chain's best block: every block below is then
    // reached from that block, by the hash each header names as its parent.
    await Promise.all(usable.map(async (view) => { try { await view.rpc.header(chain.bestTip); view.agrees = true; } catch { view.agrees = false; } }));
    seen.views = views;
    const agreeing = usable.filter((view) => view.agrees), sources = [...agreeing, ...usable.filter((view) => !view.agrees)];
    if (usable.length === 0) return fail('no_bitcoin_node', 'no configured Bitcoin node gave a usable answer');
    if (agreeing.length === 0) return fail('no_node_sees_the_chains_best_block', 'no Bitcoin node has the chain\'s best Bitcoin block: the nodes are behind the chain, or have never seen its branch. Nothing is searched or sent until one has it');
    const open = [...fills.values()].filter(Boolean);
    let left = 0;
    if (open.length) {
      await mapHeights(agreeing[0].rpc, chain, Math.min(...open.map(lowestHeight)));
      left = await scan(sources, chain, budget);
    } else { heights.clear(); scanned.clear(); }
    seen.leftToScan = left;
    // Payments of fills that have ended are forgotten: a payment to such an address is for nothing, and nobody
    // can claim it (5.1).
    for (const [outpoint, payment] of payments) if (!fills.has(payment.fill)) { payments.delete(outpoint); if (!payment.done && !payment.never && once(`late|${outpoint}`)) tell('warn', 'a payment was found to the address of a fill that has ended: it was counted by a proof of someone else, or it came too late and bought nothing', { fill: payment.fill, txid: payment.txid, vout: payment.vout, sats: payment.sats.toString() }); }
    // A payment that was too small becomes one that counts when another has lowered what the fill needs: the
    // payments are gone through again while a pass counted one.
    let outcome;
    budget.proofs = maxProofsPerRound;
    do { outcome = await prove(agreeing[0], sources, chain, budget); } while (!outcome.stop && !outcome.more && outcome.counted > 0);
    if (!outcome.stop && expire && only === null) outcome = { ...(await expireDue(chain, left === 0)), more: outcome.more };
    await remember();
    const stops = { key: ['key_or_account', 'the key or the account of the prover is not as it must be'], halted: ['halted', 'the header chain of the Time chain is halted'], refused_for_funds: ['cannot_pay', 'the chain refused an action for the sender\'s balance or daily limit'] };
    if (outcome.stop && outcome.stop !== 'in_flight') {
      const [status, problem] = stops[outcome.stop] ?? [outcome.stop, { daily_fee_budget_used_up: 'the fees of today have reached max_fees_per_day_micros: nothing more is sent until tomorrow (UTC)', balance_too_low: 'the prover\'s account holds less than the next action costs: send it seconds', daily_limit_of_the_account_used_up: 'the daily limit of the prover\'s account is used up: nothing more is sent until it refills' }[outcome.stop] ?? outcome.stop];
      seen.status = status; seen.problems = [problem]; seen.lastGoodRoundAt = at;
      if (once(`stop|${status}`)) tell('error', `THE PROVER HAS STOPPED SENDING: ${problem}`);
      return { more: false };
    }
    const more = left > 0 || !wholeBook || outcome.more === true;
    seen.status = outcome.stop === 'in_flight' ? 'waiting_for_a_block' : more ? 'catching_up' : 'ok'; seen.problems = [];
    seen.lastGoodRoundAt = at;
    return { more };
  }

  /// The health answer: `{ ok, body }` (createHealthServer). Not ok when the prover cannot do its work: the header
  /// chain is halted, the key or the account is not as it must be, a budget or the balance is used up, no node
  /// sees the chain's best block, or no round has gone well for three poll intervals (at least a minute).
  function health() {
    const at = now(), quiet = at - (seen.lastGoodRoundAt ?? seen.startedAt), stalled = quiet > Math.max(3 * pollMs, 60_000), used = today();
    // What stops the prover's work until a person acts fails the answer at once; what a later round can mend
    // (an endpoint or a node that does not answer) fails it when it has lasted.
    const hard = ['halted', 'refused_network', 'no_market', 'key_or_account', 'cannot_pay', 'daily_fee_budget_used_up', 'balance_too_low', 'daily_limit_of_the_account_used_up'].includes(seen.status), all = [...payments.values()];
    const working = ['ok', 'catching_up', 'waiting_for_a_block', 'starting'].includes(seen.status);
    const status = working && stalled ? 'stalled' : seen.status, ok = !hard && !stalled && seen.lastGoodRoundAt !== null;
    const warnings = [...seen.warnings];
    if (seen.views.some((view) => !view.ok)) warnings.push('a_bitcoin_node_is_not_usable');
    if (seen.views.some((view) => view.ok && !view.agrees)) warnings.push('a_bitcoin_node_does_not_see_the_chains_best_block');
    if (all.some((payment) => payment.cannot && !payment.done)) warnings.push('a_payment_cannot_be_proven');
    if (all.some((payment) => payment.costly && !payment.done)) warnings.push('a_proof_costs_more_than_allowed');
    if (seen.leftToScan > 0) warnings.push('blocks_left_to_search');
    return { ok, body: {
      ok, status, problems: seen.problems, warnings,
      started_at: new Date(seen.startedAt).toISOString(), last_round_at: seen.lastRoundAt && new Date(seen.lastRoundAt).toISOString(), last_good_round_at: seen.lastGoodRoundAt && new Date(seen.lastGoodRoundAt).toISOString(), seconds_since_good_round: seen.lastGoodRoundAt === null ? null : Math.round((at - seen.lastGoodRoundAt) / 1000),
      time_chain: { proven_height: seen.stateHeight },
      header_chain: seen.chain && { bitcoin_network: seen.chain.network, best_height: seen.chain.bestHeight, best_block: seen.chain.bestTip, halted: seen.chain.halted !== null },
      bitcoin_nodes: seen.views.map((view) => ({ name: view.name, usable: view.ok, sees_the_chains_best_block: view.agrees === true, height: view.height ?? null, problem: view.problem ?? null })),
      fills: { open: [...fills.values()].filter(Boolean).length, next_fill: seen.nextFill, looked_at_from: low?.toString() ?? null, looked_at_to: high?.toString() ?? null },
      payments: {
        waiting: all.filter((payment) => !payment.done && !payment.cannot && !payment.never).length, cannot_be_proven: all.filter((payment) => payment.cannot && !payment.done).length, too_small_now: all.filter((payment) => payment.small && !payment.done).length,
        proven_since_start: seen.proven, last_proof_at: seen.lastProofAt && new Date(seen.lastProofAt).toISOString(),
      },
      blocks_left_to_search: seen.leftToScan, action_in_no_block_yet: inFlight !== null, expire, fills_ended_since_start: seen.expired,
      fees: { day: used.day, spent_micros: used.micros.toString(), most_per_day_micros: dayLimit.toString(), most_per_proof_micros: feeLimit.toString(), proofs: used.proofs, expiries: used.expiries },
      balance_micros: seen.balance?.toString() ?? null, balance_low: seen.balance !== null && seen.balance < lowBalance, max_balance_micros: ceiling.toString(),
    } };
  }
  /// What the prover knows and did, for the one-shot tool: the open fills, the payments found, and the log lines.
  const report = () => ({
    fills: [...fills.values()].filter(Boolean).sort((a, b) => (BigInt(a.id) < BigInt(b.id) ? -1 : 1)).map((fill) => structuredClone(fill)),
    payments: [...payments.values()].map((payment) => ({ fill: payment.fill, txid: payment.txid, vout: payment.vout, sats: payment.sats.toString(), height: payment.height, block: payment.blockHash, proven: payment.done === true, cannot: payment.cannot ?? null, never: payment.never === true, too_small_now: payment.small === true })),
    events: [...events],
  });

  let timer = null, stopped = true;
  function start() {
    if (!stopped) return;
    stopped = false;
    const loop = async () => { const { more } = await round(); if (!stopped) timer = setTimeout(loop, more ? catchUpMs : pollMs); };
    timer = setTimeout(loop, 0);
  }
  async function stop() { stopped = true; clearTimeout(timer); await running?.catch(() => {}); }
  /// Reads the account once, with a proof, and throws when the key or the account is not as it must be: a service
  /// calls this before it starts, so that a wrong key or an account above its ceiling stops the start.
  async function check() {
    const { state } = await readState({ ids: [account], include_security: true, include_bitcoin: true, include_market: true });
    if (!SDK.marketSetting(state)) throw new Error('This Time network has no market: there is nothing to prove');
    if (!OPEN_NETWORKS.includes(headerChainOf(state).network)) throw new Error('This Time network follows Bitcoin mainnet, which is closed in this version of the market');
    const me = accountOf(state);
    if (me.problem) throw new Error(`The prover does not start: ${me.problem}`);
    return { balance: me.balance, fee: me.fee };
  }
  return Object.freeze({ round, health, report, start, stop, check });
}
