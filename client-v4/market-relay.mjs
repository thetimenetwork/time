// The relay of Bitcoin block headers, for a Time chain with the market (spec/market.md).
//
// The chain follows Bitcoin's header chain by itself, and learns of it only from kind 40 actions: unsigned, free,
// sent by anyone (spec/market.md, 10.4). Nobody is paid to send them. Without a relay no fill is made, proven or
// expired. This is that relay. It holds no key and signs nothing.
//
// Each round it:
// 1. reads, with a proof, which Bitcoin block the chain has as its best, the ends of every branch it holds, and
//    whether its header chain is halted (`headerChainOf`);
// 2. asks every configured Bitcoin node where it stands;
// 3. for each node whose best block the chain does not hold, finds where the node's best chain leaves what the
//    chain holds, and hands in the headers from there, in batches the engine accepts (`max_batch` of the chain's
//    own configuration, read with the proof).
// EVERY VALID BRANCH A NODE SHOWS IS HANDED IN. The relay does not choose between branches: the chain checks the
// work of each header and keeps the branch with the most. Two nodes on two branches give the chain both.
//
// WHERE A BRANCH LEAVES THE CHAIN. Only the row `bitcoin/meta` is proven: the best block and the ends of the
// branches, not every header. So the relay asks the node about the chain's best block:
// - the node has it on its best chain: the headers above it are new;
// - the node has it on a branch it has left (a reorganisation): the node is walked back, block by block, to the
//   last block the two share;
// - the node does not know it (the chain was told of that block by someone else): the relay offers the node's
//   last header, then its last two, four, eight ... The chain takes a batch whose first header has a parent it
//   holds, refuses the others, and a refused action costs nothing.
//
// A REORGANISATION DEEPER THAN THE CHAIN FOLLOWS. A branch with more work that leaves the chain's best chain more
// than `max_reorg` blocks below its tip (144) halts the chain's header chain, and this version has no action that
// starts it again (spec/market.md, 10.5). The chain's rule stands whoever sends the headers. But the relay does not
// pull that lever on the word of one node: with `deepReorg: 'stop'` (the default) it does not hand such a branch
// in, says so in the log and in the health answer, and goes on serving the other nodes. A person then looks: a node
// pointed at the wrong chain looks the same as a real deep reorganisation. `deepReorg: 'relay'` hands it in.
// Once the header chain is halted the relay sends nothing more and says so: there is nothing a relay can do.
//
// THE PACE (spec/market.md, 5.4). After every kind 40 action that raises the best height, the chain's clock of
// heights gains one entry, and it keeps 256. A fill can end without payment only GRACE after the chain learnt its
// last height, and "when the chain learnt it" is read from that clock. So what matters is the number of ACTIONS,
// not of headers:
// - many headers in one action cost one entry and tell the clock the truth: the chain learnt those heights then.
//   A fill that started behind Bitcoin loses its time in heights at that moment, and the rules give it a floor in
//   time for exactly that case (5.5, point 4). A relay that held headers back would help nobody: a proof needs the
//   chain to hold the payment's block and its confirmations.
// - many small actions push the old entries out. More than 256 within GRACE and the clock has forgotten when it
//   learnt the last height of every open fill; it then reads the oldest entry left, which is younger than GRACE,
//   and no fill can end until the stream stops and GRACE has passed again. Sellers' seconds stay locked meanwhile.
// So the relay fills every action to the batch size, and while a fill is open it sends at most
// CLOCK_ACTIONS_PER_GRACE (64, a quarter of the clock) actions in any window of GRACE: no entry younger than three
// times GRACE is ever pushed out by this relay. At 256 headers an action that is 16,384 headers per GRACE. While no
// fill is open nothing reads the clock, and only `maxActionsPerRound` bounds a round. A long gap is caught up at
// that pace, round after round, without waiting for each batch to be in a block: the node that took a batch judges
// the next one on top of it.
import './time-sdk.js';
import { BitcoinRpcError, headerFields } from './bitcoin-rpc.mjs';
import { headerChainOf, OPEN_NETWORKS, createOnce } from './market-service.mjs';

const SDK = globalThis.TimeSDK;
/// The most actions the relay sends in any window of GRACE while a fill is open: a quarter of the clock of heights.
export const CLOCK_ACTIONS_PER_GRACE = 64;
/// What the engine says when it refuses a batch of headers (bitcoin-bridge/src/chain.rs, `prepare_headers`). These
/// are an endpoint's words: they decide where the relay looks next, and nothing else.
const SAID = Object.freeze({
  nothingNew: /contains no new headers|no retained state effect/i,
  unknownParent: /unknown or pruned Bitcoin parent/i,
  halted: /paused after a reorganization/i,
});

/// What a refusal of a batch of headers means to the relay: 'nothing_new', 'unknown_parent', 'halted' or 'refused'.
export function headersRefusal(reason) {
  for (const [name, pattern] of Object.entries(SAID)) if (pattern.test(reason)) return { nothingNew: 'nothing_new', unknownParent: 'unknown_parent', halted: 'halted' }[name];
  return 'refused';
}

/// `items` mapped by `work`, at most `limit` at a time, in order.
async function mapLimit(items, limit, work) {
  const results = new Array(items.length); let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => { while (next < items.length) { const index = next++; results[index] = await work(items[index]); } }));
  return results;
}
class NodeChanged extends Error {}

/// The relay. `nodes` is what `createBitcoinNodes` gives; `readState` and `submit` are those of a Time endpoint
/// (`createTimeEndpoint`); `networkId` is the Time network's, from the trust manifest.
/// Settings: `maxActionsPerRound` (4), `deepReorg` ('stop' or 'relay'), `maxHeaderAgeSeconds` (3600),
/// `maxBehindSeconds` (300), `maxDisagreeSeconds` (1800), `pollMs` (10000), `catchUpMs` (1000: the pause before the
/// next round while headers are left to send), `pendingMs` (60000: how long headers a node took are taken as held
/// before a proof shows them).
/// Returns `{ round(), health(), start(), stop() }`. `round()` resolves to `{ more }`: whether headers are left.
export function createRelay({ nodes, readState, submit, networkId, log = () => {}, now = Date.now, settings = {} }) {
  const { maxActionsPerRound = 4, deepReorg = 'stop', maxHeaderAgeSeconds = 3600, maxBehindSeconds = 300, maxDisagreeSeconds = 1800, pollMs = 10000, catchUpMs = 1000, pendingMs = 60000 } = settings;
  if (!['stop', 'relay'].includes(deepReorg)) throw new Error('deepReorg is "stop" or "relay"');
  const once = createOnce({ now });
  // Ends of branches a node took a moment ago, which no proof shows yet: hash -> { height, at }.
  const pending = new Map();
  // Pairs (the chain's best block, a node's best block) for which nothing is left to do, or a try was refused:
  // key -> { until }. A pair is looked at again when either block changes, or when `until` has passed.
  const settled = new Map();
  // When the chain took an action of this relay: for the pace.
  const taken = [];
  // Nodes that show a branch the relay does not hand in: name -> { key, forkHeight, chainHeight, nodeHeight }.
  const deep = new Map();
  const seen = {
    startedAt: now(), lastRoundAt: null, lastGoodRoundAt: null, status: 'starting', problems: [], stateHeight: null, chain: null, views: [], behindSince: null, disagreeSince: null,
    blocksBehind: null, nodesBehind: false, newestHeaderTime: null, handedIn: 0, lastHandedInAt: null, lastRefusal: null, unpassedSince: null,
  };
  const settle = (key, ms) => { settled.delete(key); settled.set(key, { until: now() + ms }); if (settled.size > 256) settled.delete(settled.keys().next().value); };
  const isSettled = (key) => { const entry = settled.get(key); return entry !== undefined && entry.until > now(); };

  /// The headers of the node's best chain from `from` to `to`, each held to the one before it. `parent` is the hash
  /// the first must build on, or null when that is what the chain is being asked.
  async function headersOf(rpc, from, to, parent) {
    const heights = Array.from({ length: to - from + 1 }, (_, index) => from + index);
    const hashes = await mapLimit(heights, 8, (height) => rpc.hashAt(height));
    if (hashes.some((hash) => hash === null)) throw new NodeChanged();
    const headers = await mapLimit(hashes, 8, (hash) => rpc.header(hash));
    let previous = parent;
    for (const header of headers) {
      const fields = headerFields(header);
      if (previous !== null && fields.previous !== previous) throw new NodeChanged();
      previous = fields.hash;
    }
    return { headers, last: previous };
  }

  /// Hands one batch in. Returns 'taken', 'nothing_new', 'unknown_parent', 'halted' or 'refused'.
  async function handIn(headers, lastHash, lastHeight, budget) {
    const answer = await submit(SDK.publicHeadersAction(networkId, headers));
    if (answer.accepted) {
      // Bytes the node already holds were counted when it first took them.
      if (!answer.known) { budget.left -= 1; taken.push(now()); seen.handedIn += headers.length; seen.lastHandedInAt = now(); }
      pending.delete(lastHash); pending.set(lastHash, { height: lastHeight, at: now() });
      if (pending.size > 16) pending.delete(pending.keys().next().value);
      return 'taken';
    }
    const outcome = headersRefusal(answer.reason);
    if (outcome === 'refused') seen.lastRefusal = { at: now(), reason: answer.reason };
    return outcome;
  }

  /// Hands in the node's best chain from `from` on, a batch at a time, while the round's budget lasts. Returns
  /// `{ more }`, or `{ outcome }` when the chain refused a batch.
  async function stream(node, chain, from, parent, budget) {
    let next = from, previous = parent;
    while (next <= node.height) {
      if (budget.left <= 0) return { more: true };
      const to = Math.min(node.height, next + chain.maxBatch - 1), { headers, last } = await headersOf(node.rpc, next, to, previous);
      const outcome = await handIn(headers, last, to, budget);
      if (outcome !== 'taken') return { outcome };
      next = to + 1; previous = last;
    }
    return { more: false };
  }

  /// What one node has that the chain does not, handed in. Returns `{ more }`.
  async function serve(node, chain, budget) {
    const key = `${chain.bestTip}|${node.bestHash}`;
    if (deep.get(node.name)?.key !== key) deep.delete(node.name);
    if (chain.tips.includes(node.bestHash) || pending.has(node.bestHash) || isSettled(key)) return { more: false };
    if (budget.left <= 0) return { more: true };
    const refusedFor = (ms, outcome) => {
      settle(key, ms);
      // What the relay took as held was not: the next round starts from what a proof shows.
      if (outcome === 'unknown_parent') pending.clear();
      if (outcome === 'refused' && once(`refused|${seen.lastRefusal?.reason}`)) log('warn', 'the chain refused headers of a Bitcoin node', { node: node.name, reason: seen.lastRefusal?.reason });
      return { more: false, outcome };
    };
    // The chain's best height as far as this relay knows: what a proof shows, or what a node took a moment ago.
    const best = Math.max(chain.bestHeight, ...[...pending.values()].map((entry) => entry.height));
    // The newest end the node still has on its best chain: one this relay handed in a moment ago, or the proven one.
    let basis = null;
    for (const [hash, entry] of [...pending].reverse()) {
      const held = await node.rpc.headerInfo(hash);
      if (held?.onBestChain) { basis = { hash, height: entry.height }; break; }
    }
    let held = basis ? { onBestChain: true, height: basis.height, hash: basis.hash } : await node.rpc.headerInfo(chain.bestTip);
    if (held?.onBestChain) {
      // The node's chain goes on from a block the chain holds.
      const result = await stream(node, chain, held.height + 1, held.hash, budget);
      if (result.outcome === 'nothing_new') { settle(key, 60_000); return { more: false }; }
      if (result.outcome) return refusedFor(result.outcome === 'refused' ? 60_000 : 5_000, result.outcome);
      return result;
    }
    if (held) {
      // A reorganisation: the node has left the chain's best block. Walk back to the last block the two share.
      // A branch with no more work than the chain's that left it too far below its tip is not kept by the chain
      // as a branch: there is nothing to hand in, and nothing to raise an alarm for.
      const weak = (forkHeight) => {
        if (once(`weak|${key}`)) log('info', 'a Bitcoin node is on a branch with no more work than the chain\'s that left the chain\'s best chain far below its tip; nothing is handed in', { node: node.name, fork_height: forkHeight });
        settle(key, 600_000); return { more: false };
      };
      let cursor = held;
      for (let steps = 0; !cursor.onBestChain; steps++) {
        const before = cursor.previous === null || steps >= chain.maxBatch ? null : await node.rpc.headerInfo(cursor.previous);
        if (!before) return node.work <= chain.bestWork ? weak(null) : tooDeep(node, chain, key, null);
        cursor = before;
      }
      const depth = best - cursor.height, halting = depth > chain.maxReorg || cursor.height < chain.creditedHeight;
      if (halting && node.work <= chain.bestWork) return weak(cursor.height);
      if (halting && deepReorg !== 'relay') return tooDeep(node, chain, key, cursor.height);
      if (halting && node.height - cursor.height > chain.maxBatch) return tooDeep(node, chain, key, cursor.height, 'it cannot be handed in: the engine takes such a branch in one batch only, and this one is longer');
      if (once(`reorg|${key}`)) log('warn', 'Bitcoin reorganisation: handing in the new branch', { node: node.name, fork_height: cursor.height, depth, new_height: node.height });
      const result = await stream(node, chain, cursor.height + 1, cursor.hash, budget);
      if (result.outcome === 'nothing_new') { settle(key, 60_000); return { more: false }; }
      if (result.outcome) return refusedFor(result.outcome === 'refused' ? 60_000 : 5_000, result.outcome);
      return result;
    }
    // The node does not know the chain's best block. Offer its last header, then its last two, four, eight ...
    // The lowest block a batch may build on: in 'stop' mode never so low that taking the branch could halt.
    const top = Math.min(chain.bestHeight, node.height);
    const lowest = Math.max(1, chain.prunedBelow + 1, deepReorg === 'relay' ? 0 : Math.max(best - chain.maxReorg, chain.creditedHeight) + 1);
    for (let reach = 1; ; reach = Math.min(reach * 2, chain.maxBatch)) {
      const from = Math.max(lowest, top - reach + 1);
      if (from > node.height) break;
      const to = Math.min(node.height, from + chain.maxBatch - 1), { headers, last } = await headersOf(node.rpc, from, to, null);
      const outcome = await handIn(headers, last, to, budget);
      if (outcome === 'taken') return to < node.height ? stream(node, chain, to + 1, last, budget).then((result) => (result.outcome ? refusedFor(5_000, result.outcome) : result)) : { more: false };
      if (outcome === 'nothing_new' && to >= node.height) { settle(key, 600_000); return { more: false }; } // the chain holds the node's branch: the node is behind
      if (outcome === 'nothing_new') return stream(node, chain, to + 1, last, budget).then((result) => (result.outcome ? refusedFor(result.outcome === 'nothing_new' ? 600_000 : 5_000, result.outcome) : result));
      if (outcome !== 'unknown_parent') return refusedFor(outcome === 'refused' ? 60_000 : 5_000, outcome);
      if (from === lowest || reach === chain.maxBatch) break;
    }
    if (node.work <= chain.bestWork) {
      if (once(`apart|${key}`)) log('info', 'a Bitcoin node is on a chain with no more work than the chain\'s, and they share no recent block; nothing is handed in', { node: node.name, node_height: node.height });
      settle(key, 600_000); return { more: false };
    }
    return tooDeep(node, chain, key, null);
  }
  function tooDeep(node, chain, key, forkHeight, why = null) {
    deep.set(node.name, { key, forkHeight, chainHeight: chain.bestHeight, nodeHeight: node.height });
    if (once(`deep|${key}`)) log('error', `A BITCOIN NODE SHOWS A BRANCH THAT LEAVES THE CHAIN'S BEST CHAIN DEEPER THAN THE CHAIN FOLLOWS. ${why ?? 'It is not handed in: taken with more work, it would halt the chain\'s header chain for good.'} Check that the node is on the right chain; see "A deep reorganisation" in deploy/market-relay/README.md`, { node: node.name, fork_height: forkHeight, chain_height: chain.bestHeight, node_height: node.height, max_reorg: chain.maxReorg });
    settle(key, 600_000);
    return { more: false };
  }

  let running = null;
  /// One round. Never throws: what went wrong is in the log and in the health answer.
  function round() { return running ??= turn().finally(() => { running = null; }); }
  async function turn() {
    const at = now();
    seen.lastRoundAt = at;
    const fail = (status, problem, level = 'warn') => { seen.status = status; seen.problems = [problem]; if (once(`${status}|${problem}`)) log(level, problem); return { more: false }; };
    let state, chain;
    try { state = (await readState({ include_bitcoin: true, include_market: true })).state; chain = headerChainOf(state); } catch (error) {
      return fail('time_unreachable', SDK.isUpgradeRequired(error) ? 'the Time chain runs a protocol version this relay does not implement: install the release that does' : 'no proven state of the Time chain could be read');
    }
    seen.stateHeight = String(state.height); seen.chain = chain;
    if (!OPEN_NETWORKS.includes(chain.network)) return fail('refused_network', 'this Time network follows Bitcoin mainnet, which is closed in this version of the market: the relay sends nothing', 'error');
    if (chain.halted) {
      seen.status = 'halted'; seen.problems = ['the header chain of the Time chain is halted'];
      if (once('halted')) log('error', 'THE BITCOIN HEADER CHAIN OF THE TIME CHAIN IS HALTED. No header is accepted any more, and nothing this relay sends can change that: it needs a software release (spec/market.md, 10.5). Fills end by a release or a settle only.', { reason: chain.halted.reason, common_height: chain.halted.commonHeight, best_height: chain.bestHeight });
      return { more: false };
    }
    let fills = 0, graceMs = 0;
    if (SDK.marketSetting(state)) { fills = Number(SDK.marketSummary(state).fills); graceMs = Number(BigInt(SDK.marketRules(state).graceMicros) / 1000n); }
    // What a proof now shows is no longer pending; what no proof shows after a while was not passed on.
    for (const [hash, entry] of pending) {
      if (chain.tips.includes(hash) || chain.bestHeight > entry.height) { pending.delete(hash); seen.unpassedSince = null; } else if (at - entry.at > pendingMs) {
        pending.delete(hash); seen.unpassedSince ??= entry.at;
        if (once('unpassed')) log('warn', 'headers the endpoint took are in no block after a while: it may not pass actions on', { seconds: Math.round((at - entry.at) / 1000) });
      }
    }
    const views = await nodes.look(chain.network), usable = views.filter((view) => view.ok).sort((a, b) => (a.work === b.work ? 0 : a.work > b.work ? -1 : 1));
    seen.views = views;
    for (const view of views) if (!view.ok && once(`node|${view.name}|${view.problem}`)) log('warn', 'a Bitcoin node is not usable', { node: view.name, problem: view.problem });
    if (usable.length === 0) return fail('no_bitcoin_node', 'no configured Bitcoin node gave a usable answer');
    seen.newestHeaderTime = Math.max(...usable.map((view) => view.time));
    seen.disagreeSince = new Set(usable.map((view) => view.bestHash)).size > 1 ? seen.disagreeSince ?? at : null;
    // The chain is behind when a node has a chain with more work that the chain does not hold. A node with less
    // work is itself behind, or on a losing branch: that is the node's trouble, and a warning.
    const strongest = usable[0], behind = strongest.work > chain.bestWork && !chain.tips.includes(strongest.bestHash);
    seen.nodesBehind = strongest.work < chain.bestWork;
    seen.blocksBehind = behind ? strongest.height - chain.bestHeight : 0;
    seen.behindSince = behind ? seen.behindSince ?? at : null;
    // The pace: what a round may send, and what the clock of heights bears while a fill is open.
    while (taken.length && at - taken[0] > Math.max(graceMs, 1)) taken.shift();
    const budget = { left: fills > 0 ? Math.min(maxActionsPerRound, Math.max(0, CLOCK_ACTIONS_PER_GRACE - taken.length)) : maxActionsPerRound };
    let more = false, halted = false, failed = 0;
    for (const name of deep.keys()) if (!usable.some((view) => view.name === name)) deep.delete(name);
    for (const node of usable) {
      try {
        const result = await serve(node, chain, budget);
        more ||= result.more === true;
        if (result.outcome === 'halted') halted = true;
      } catch (error) {
        failed += 1;
        if (!(error instanceof NodeChanged) && once(`serve|${node.name}|${error?.code ?? 'failure'}`)) log('warn', 'a round could not be finished with a Bitcoin node', { node: node.name, code: error instanceof BitcoinRpcError ? error.code : error?.code === 'UNAVAILABLE' ? 'TIME_ENDPOINT_UNAVAILABLE' : 'INTERNAL' });
      }
      if (halted) break;
    }
    seen.status = deep.size ? 'deep_reorganisation' : more ? 'catching_up' : failed === usable.length ? 'no_bitcoin_node' : 'ok';
    seen.problems = deep.size ? ['a Bitcoin node shows a branch that leaves the chain deeper than the chain follows; it is not handed in'] : [];
    if (failed < usable.length) seen.lastGoodRoundAt = at;
    return { more };
  }

  /// The health answer: `{ ok, body }` (createHealthServer). Not ok when the header chain is halted, when a deep
  /// reorganisation waits for a person, on Bitcoin mainnet, when no round has gone well for three poll intervals
  /// (at least a minute), or when the chain has been behind the nodes for longer than `maxBehindSeconds`.
  function health() {
    const at = now(), seconds = (since) => (since === null ? null : Math.round((at - since) / 1000));
    const quiet = at - (seen.lastGoodRoundAt ?? seen.startedAt), stalled = quiet > Math.max(3 * pollMs, 60_000);
    const headerAge = seen.newestHeaderTime === null ? null : Math.round(at / 1000) - seen.newestHeaderTime;
    const warnings = [];
    if (headerAge !== null && headerAge > maxHeaderAgeSeconds) warnings.push('newest_bitcoin_header_is_old');
    if (seen.disagreeSince !== null && at - seen.disagreeSince > maxDisagreeSeconds * 1000) warnings.push('bitcoin_nodes_disagree');
    if (seen.views.some((view) => !view.ok)) warnings.push('a_bitcoin_node_is_not_usable');
    if (seen.views.some((view) => view.downloading)) warnings.push('a_bitcoin_node_is_still_downloading');
    if (seen.nodesBehind) warnings.push('every_bitcoin_node_is_behind_the_chain');
    if (seen.unpassedSince !== null) warnings.push('headers_taken_but_in_no_block');
    if (seen.lastRefusal && at - seen.lastRefusal.at < 600_000) warnings.push('headers_refused');
    const behindLong = seen.behindSince !== null && at - seen.behindSince > maxBehindSeconds * 1000;
    const hard = ['halted', 'deep_reorganisation', 'refused_network'].includes(seen.status);
    const status = hard ? seen.status : stalled ? (seen.status === 'ok' || seen.status === 'catching_up' || seen.status === 'starting' ? 'stalled' : seen.status) : behindLong ? 'chain_behind' : seen.status;
    const ok = !hard && !stalled && !behindLong && seen.lastGoodRoundAt !== null;
    return { ok, body: {
      ok, status, problems: seen.problems, warnings, deep_reorg: deepReorg,
      started_at: new Date(seen.startedAt).toISOString(), last_round_at: seen.lastRoundAt && new Date(seen.lastRoundAt).toISOString(), last_good_round_at: seen.lastGoodRoundAt && new Date(seen.lastGoodRoundAt).toISOString(), seconds_since_good_round: seen.lastGoodRoundAt === null ? null : seconds(seen.lastGoodRoundAt),
      time_chain: { proven_height: seen.stateHeight },
      header_chain: seen.chain && { bitcoin_network: seen.chain.network, best_height: seen.chain.bestHeight, best_block: seen.chain.bestTip, branches: seen.chain.tips.length, halted: seen.chain.halted !== null, halt_reason: seen.chain.halted?.reason ?? null },
      bitcoin_nodes: seen.views.map((view) => ({ name: view.name, usable: view.ok, height: view.height ?? null, best_block: view.bestHash ?? null, downloading: view.downloading === true, problem: view.problem ?? null })),
      newest_bitcoin_header_age_seconds: headerAge, blocks_behind: seen.blocksBehind, behind_seconds: seconds(seen.behindSince), nodes_disagree_seconds: seconds(seen.disagreeSince),
      deep_reorganisations: [...deep].map(([node, entry]) => ({ node, fork_height: entry.forkHeight, chain_height: entry.chainHeight, node_height: entry.nodeHeight })),
      headers_handed_in: seen.handedIn, last_handed_in_at: seen.lastHandedInAt && new Date(seen.lastHandedInAt).toISOString(), actions_in_grace_window: taken.length,
    } };
  }

  let timer = null, stopped = true;
  function start() {
    if (!stopped) return;
    stopped = false;
    const loop = async () => {
      const { more } = await round().catch(() => ({ more: false }));
      if (!stopped) { timer = setTimeout(loop, more ? catchUpMs : pollMs); }
    };
    timer = setTimeout(loop, 0);
  }
  async function stop() { stopped = true; clearTimeout(timer); await running?.catch(() => {}); }
  return Object.freeze({ round, health, start, stop });
}
