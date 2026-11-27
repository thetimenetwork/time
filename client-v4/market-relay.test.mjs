// The relay of Bitcoin headers (market-relay.mjs), with a Bitcoin node and a Time chain that exist in the test
// only (market-test-kit.mjs). The node is asked through the real client of Bitcoin Core's RPC.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import './time-sdk.js';
import { createBitcoinNodes, createBitcoinRpc } from './bitcoin-rpc.mjs';
import { CLOCK_ACTIONS_PER_GRACE, createRelay } from './market-relay.mjs';
import { headerChainOf } from './market-service.mjs';
import { createClock, createFakeBitcoin, createFakeChain, createLog } from './market-test-kit.mjs';

const SDK = globalThis.TimeSDK;
const fixture = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/market-engine.json', import.meta.url), 'utf8'));
const rpcOf = (node, password = node.password) => createBitcoinRpc({ url: 'http://127.0.0.1:18443/', login: async () => password, fetcher: node.fetcher, timeoutMs: 200 });
/// A relay over `named` nodes ({ name: node }) and a chain, with a clock and a log of the test.
function relayOf(chain, named, settings = {}) {
  const now = createClock(), log = createLog();
  const relay = createRelay({ nodes: createBitcoinNodes(Object.entries(named).map(([name, node]) => ({ name, rpc: rpcOf(node) }))), ...chain.endpoint, networkId: chain.networkId, log, now, settings });
  return { relay, now, log, rounds: async (count) => { const results = []; for (let i = 0; i < count; i++) results.push(await relay.round()); return results; } };
}
/// The batches of headers the chain was sent, as numbers of headers.
const batches = (chain) => chain.submitted.map((raw) => SDK.decodeAction(Uint8Array.from(Buffer.from(raw, 'hex'))).payload.headers.length);
const openFill = (chain) => chain.addFill({ id: '1', order: '1', owner: '5', payer: '6', to: '6', side: 'sell', price: '250000000', amount_micros: '40000000', deposit_micros: '2000000', sats: '10000', confirmations: '2', pay_blocks: '6', script: `0014${'02'.repeat(20)}` });

test('the header chain is read from the row the engine proves', () => {
  for (const name of ['trading', 'learnt', 'due']) {
    const entry = fixture.cases[name].proof.entries.find((item) => Buffer.from(item.key_hex, 'hex').toString() === 'bitcoin/meta');
    const row = JSON.parse(Buffer.from(entry.value_b64, 'base64').toString('utf8')), chain = headerChainOf({ bitcoin: row });
    assert.equal(chain.network, 'regtest');
    assert.equal(chain.bestHeight, fixture.cases[name].bitcoin_best_height ?? row.meta.best_height);
    assert.equal(chain.bestTip, row.meta.best_tip);
    assert.equal(chain.bestWork, BigInt(`0x${row.meta.best_work}`));
    assert.deepEqual([chain.maxBatch, chain.maxReorg, chain.maxTipAgeSecs, chain.halted, chain.creditedHeight], [256, 144, 7200, null, 0]);
    assert.equal(chain.tips.includes(chain.bestTip), true);
    // A halted header chain, in the engine's form.
    assert.deepEqual(headerChainOf({ bitcoin: { meta: { ...row.meta, halted: { reason: 'deep_reorg', old_tip: row.meta.best_tip, candidate: 'ab'.repeat(32), common_height: 3 } } } }).halted, { reason: 'deep_reorg', commonHeight: 3 });
  }
  // A state that was read without the row says nothing, and that is an error, never "not halted".
  assert.throws(() => headerChainOf({}), /include_bitcoin/);
  assert.throws(() => headerChainOf({ bitcoin: { meta: { best_height: 3 } } }), /include_bitcoin/);
});

test('new blocks are handed in as one action, and a relay with nothing to do sends nothing', async () => {
  const bitcoin = createFakeBitcoin(), chain = createFakeChain({ bitcoin }), node = bitcoin.node(), { relay, rounds, log } = relayOf(chain, { own: node });
  bitcoin.mineMany(3);
  assert.deepEqual(await rounds(1), [{ more: false }]);
  assert.deepEqual(batches(chain), [3]);
  assert.equal(chain.bestTip, bitcoin.best.hash);
  await rounds(3);
  assert.deepEqual(batches(chain), [3], 'the chain holds the node\'s best block: nothing more is sent');
  bitcoin.mine();
  await rounds(1);
  assert.deepEqual(batches(chain), [3, 1]);
  // The action is the unsigned one of kind 40: no account, no key, an empty signature.
  const action = SDK.decodeAction(Uint8Array.from(Buffer.from(chain.submitted[0], 'hex')));
  assert.deepEqual([action.kind, action.from, action.nonce, action.publicKey], [40, SDK.MAX_U64, '0', '00'.repeat(32)]);
  assert.match(chain.submitted[0], /(?:00){64}$/);
  // The health answer says what the last round read with a proof: one round later, the block that was handed in.
  await rounds(1);
  const { ok, body } = relay.health();
  assert.equal(ok, true);
  assert.deepEqual([body.status, body.header_chain.best_height, body.header_chain.best_block, body.blocks_behind, body.headers_handed_in, body.warnings], ['ok', 4, bitcoin.best.hash, 0, 4, []]);
  assert.deepEqual(body.bitcoin_nodes, [{ name: 'own', usable: true, height: 4, best_block: bitcoin.best.hash, downloading: false, problem: null }]);
  assert.equal(log.lines.filter((line) => line.level !== 'info').length, 0);
});

test('a long gap is caught up batch after batch, without waiting for a block, and costs the clock one entry an action', async () => {
  const bitcoin = createFakeBitcoin(), chain = createFakeChain({ bitcoin, autoCommit: false }), { relay, rounds } = relayOf(chain, { own: bitcoin.node() }, { maxActionsPerRound: 4 });
  bitcoin.mineMany(1500);
  // No block of the Time chain ends between these rounds: the relay builds on what the node took.
  assert.deepEqual(await rounds(2), [{ more: true }, { more: false }]);
  assert.deepEqual(batches(chain), [256, 256, 256, 256, 256, 220]);
  assert.equal(relay.health().body.status, 'ok');
  chain.commit();
  await rounds(2);
  assert.deepEqual(batches(chain).length, 6, 'once a proof shows the headers, nothing is sent again');
  assert.equal(chain.bestHeight, 1500);
  assert.equal(chain.bestTip, bitcoin.best.hash);
  assert.equal(chain.clockEntries.length, 1 + 6, 'six actions for 1,500 headers: six entries of the clock, beside the one of the start');
});

test('while a fill is open, no more actions are sent in a window of GRACE than the clock of heights bears', async () => {
  // Batches of two headers, so that catching up takes many actions; a laboratory network, whose GRACE is 20 s.
  const bitcoin = createFakeBitcoin(), chain = createFakeChain({ bitcoin, maxBatch: 2 }), { relay, rounds, now } = relayOf(chain, { own: bitcoin.node() }, { maxActionsPerRound: 50 });
  bitcoin.mineMany(4);
  await rounds(1);
  openFill(chain);
  const learnt = chain.clockEntries.at(-1);
  bitcoin.mineMany(400);
  assert.deepEqual(await rounds(3), [{ more: true }, { more: true }, { more: true }]);
  // 50, then the 12 that were left of 64 (two were sent before the fill), then none until the window has moved.
  assert.equal(batches(chain).length, 2 + CLOCK_ACTIONS_PER_GRACE - 2);
  assert.equal(relay.health().body.actions_in_grace_window, CLOCK_ACTIONS_PER_GRACE);
  assert.equal(relay.health().body.status, 'catching_up');
  assert.deepEqual(chain.clockEntries.find((entry) => entry.height === learnt.height), learnt, 'the clock still says when the chain learnt the heights of the open fill');
  now.advance(21_000);
  assert.deepEqual(await rounds(1), [{ more: true }]);
  assert.equal(batches(chain).length, 64 + 50);
  // Without an open fill nothing reads the clock, and only the round's own bound holds.
  const free = createFakeChain({ bitcoin, maxBatch: 2 }), other = relayOf(free, { own: bitcoin.node() }, { maxActionsPerRound: 50 });
  await other.rounds(3);
  assert.equal(batches(free).length, 150);
});

test('a reorganisation: the node is walked back to the last block it shares with the chain, and the new branch handed in', async () => {
  const bitcoin = createFakeBitcoin(), chain = createFakeChain({ bitcoin }), { relay, rounds, log } = relayOf(chain, { own: bitcoin.node() });
  const fork = bitcoin.mineMany(7), old = bitcoin.mineMany(3);
  await rounds(1);
  assert.equal(chain.bestTip, old.hash);
  // Bitcoin leaves the last three blocks for a branch of five.
  const fresh = bitcoin.mineMany(5, { parent: fork.hash });
  assert.equal(bitcoin.best.hash, fresh.hash);
  await rounds(1);
  assert.deepEqual(batches(chain), [10, 5]);
  assert.equal(chain.bestTip, fresh.hash);
  assert.equal(chain.bestHeight, 12);
  assert.deepEqual(log.said(/reorganisation/).map((line) => [line.level, line.fork_height, line.depth, line.new_height]), [['warn', 7, 3, 12]]);
  assert.equal(relay.health().ok, true);
});

test('a node that never saw the chain\'s best block: its last headers are offered, further back each time, until the chain takes them', async () => {
  const bitcoin = createFakeBitcoin(), chain = createFakeChain({ bitcoin });
  const fork = bitcoin.mineMany(20), mine = bitcoin.mineMany(6, { parent: fork.hash });
  // Someone else told the chain of a branch this node has never seen; it has more work than the node's.
  const theirs = bitcoin.mineMany(7, { parent: fork.hash });
  chain.follow();
  assert.equal(chain.bestTip, theirs.hash);
  const node = bitcoin.node();
  node.tip = mine.hash;
  const { relay, rounds, log } = relayOf(chain, { own: node });
  await rounds(1);
  // Offered: the last header, the last two, four, eight. The chain refused the first three for their unknown parent.
  assert.deepEqual(batches(chain), [1, 2, 4, 8]);
  assert.deepEqual(chain.refusals, ['unknown or pruned Bitcoin parent', 'unknown or pruned Bitcoin parent', 'unknown or pruned Bitcoin parent']);
  // The chain now holds the node's branch beside its own, and still follows the one with more work.
  assert.equal(chain.live.tips.includes(mine.hash), true);
  assert.equal(chain.bestTip, theirs.hash);
  await rounds(3);
  assert.equal(batches(chain).length, 4, 'the chain holds the node\'s best block as the end of a branch: nothing more is sent');
  assert.equal(relay.health().ok, true);
  assert.equal(log.lines.filter((line) => line.level === 'error').length, 0);
  // A node that is only behind: the chain holds its last header, says so once, and is not asked again.
  const behind = createFakeChain({ bitcoin }), late = bitcoin.node({ lag: 3 });
  behind.follow();
  const second = relayOf(behind, { late });
  await second.rounds(4);
  assert.deepEqual(batches(behind), [1]);
  assert.deepEqual(behind.refusals, ['Bitcoin relay contains no new headers']);
  // That is the node's trouble, not the chain's: a warning, and the health answer stays good however long it lasts.
  second.now.advance(3_600_000);
  await second.rounds(1);
  assert.deepEqual([second.relay.health().ok, second.relay.health().body.status, second.relay.health().body.blocks_behind, second.relay.health().body.warnings.includes('every_bitcoin_node_is_behind_the_chain')], [true, 'ok', 0, true]);
});

test('two nodes on two branches: the chain is given both, and decides by work', async () => {
  const bitcoin = createFakeBitcoin(), chain = createFakeChain({ bitcoin });
  const fork = bitcoin.mineMany(5), left = bitcoin.mineMany(2, { parent: fork.hash }), right = bitcoin.mineMany(3, { parent: fork.hash });
  const a = bitcoin.node(), b = bitcoin.node();
  a.tip = left.hash; b.tip = right.hash;
  const { relay, rounds, now } = relayOf(chain, { a, b }, { maxDisagreeSeconds: 60 });
  await rounds(2);
  assert.deepEqual(chain.live.tips.slice().sort(), [left.hash, right.hash].sort());
  assert.equal(chain.bestTip, right.hash);
  assert.equal(relay.health().ok, true);
  assert.deepEqual(relay.health().body.warnings, []);
  // The nodes still disagree a while later: the health answer says so.
  now.advance(61_000);
  await rounds(1);
  assert.deepEqual(relay.health().body.warnings, ['bitcoin_nodes_disagree']);
  assert.equal(relay.health().body.nodes_disagree_seconds, 61);
});

test('a branch that would halt the header chain is not handed in: said once, loudly, and shown in the health answer', async () => {
  const bitcoin = createFakeBitcoin(), chain = createFakeChain({ bitcoin });
  const fork = bitcoin.mineMany(40);
  bitcoin.mineMany(160);
  chain.follow();
  // A branch with more work that leaves the chain's best chain 160 blocks below its tip: the chain follows 144.
  const deep = bitcoin.mineMany(170, { parent: fork.hash });
  assert.equal(bitcoin.best.hash, deep.hash);
  const honest = bitcoin.node(), stopped = relayOf(chain, { own: honest });
  await stopped.rounds(4);
  assert.deepEqual(batches(chain), [], 'nothing is sent');
  assert.equal(chain.halted, null);
  const health = stopped.relay.health();
  assert.equal(health.ok, false);
  assert.equal(health.body.status, 'deep_reorganisation');
  assert.deepEqual(health.body.deep_reorganisations, [{ node: 'own', fork_height: 40, chain_height: 200, node_height: 210 }]);
  assert.deepEqual(stopped.log.lines.filter((line) => line.level === 'error').map((line) => [/DEEPER THAN THE CHAIN FOLLOWS/.test(line.message), line.fork_height, line.max_reorg]), [[true, 40, 144]], 'one line for four rounds');
  // The same branch from a node that never saw the chain's own: the relay offers headers no further back than the
  // chain follows, finds no block they share, and stops the same way.
  const blind = bitcoin.node();
  blind.tip = deep.hash;
  const second = relayOf(chain, { blind });
  await second.rounds(3);
  assert.equal(chain.halted, null);
  assert.equal(second.relay.health().body.status, 'deep_reorganisation');
  assert.equal(second.log.lines.filter((line) => line.level === 'error').length, 1);
  assert.equal(chain.refusals.every((reason) => reason === 'unknown or pruned Bitcoin parent'), true);
  // A second node on the chain's own branch is still served while the first waits for a person.
  const third = bitcoin.node(), next = bitcoin.mine([], { parent: chain.bestTip });
  third.tip = next.hash;
  assert.equal(bitcoin.best.hash, deep.hash);
  const mixed = relayOf(chain, { own: honest, third });
  await mixed.rounds(2);
  assert.equal(chain.bestTip, next.hash);
  assert.equal(chain.bestHeight, 201);
  assert.equal(mixed.relay.health().body.status, 'deep_reorganisation');
  // A node on an old branch with less work, far below the chain's tip: the chain would not keep it, nothing is
  // sent, and it is no alarm. The node is said to be behind.
  const short = bitcoin.mineMany(30, { parent: fork.hash }), weak = bitcoin.node();
  weak.tip = short.hash; weak.show(chain.bestTip);
  const quiet = relayOf(chain, { weak });
  const sent = chain.submitted.length;
  await quiet.rounds(3);
  assert.equal(chain.submitted.length, sent);
  assert.deepEqual([quiet.relay.health().ok, quiet.relay.health().body.status, quiet.relay.health().body.warnings], [true, 'ok', ['every_bitcoin_node_is_behind_the_chain']]);
  assert.deepEqual(quiet.log.lines.map((line) => [line.level, /no more work than the chain's/.test(line.message), line.fork_height]), [['info', true, 40]]);
});

test('with deepReorg "relay" the branch is handed in, the chain halts, and the relay then sends nothing and says why', async () => {
  const bitcoin = createFakeBitcoin(), chain = createFakeChain({ bitcoin });
  const fork = bitcoin.mineMany(40);
  bitcoin.mineMany(160);
  chain.follow();
  bitcoin.mineMany(170, { parent: fork.hash });
  const { relay, rounds, log } = relayOf(chain, { own: bitcoin.node() }, { deepReorg: 'relay' });
  await rounds(1);
  assert.deepEqual(batches(chain), [170]);
  assert.equal(chain.halted.reason, 'deep_reorg');
  bitcoin.mineMany(2);
  await rounds(5);
  assert.deepEqual(batches(chain), [170], 'a halted header chain takes nothing: the relay does not try');
  const health = relay.health();
  assert.deepEqual([health.ok, health.body.status, health.body.header_chain.halted, health.body.header_chain.halt_reason], [false, 'halted', true, 'deep_reorg']);
  assert.equal(log.said(/HEADER CHAIN OF THE TIME CHAIN IS HALTED/).length, 1, 'said once, not every round');
  assert.throws(() => createRelay({ nodes: createBitcoinNodes([]), ...chain.endpoint, networkId: chain.networkId, settings: { deepReorg: 'yes' } }), /"stop" or "relay"/);
});

test('one node silent, one lying, one behind: the relay goes on with the one that answers, and sends nothing wrong', async () => {
  const bitcoin = createFakeBitcoin(), chain = createFakeChain({ bitcoin });
  bitcoin.mineMany(6);
  const good = bitcoin.node(), silent = bitcoin.node(), garbage = bitcoin.node(), wrong = bitcoin.node(), late = bitcoin.node({ lag: 4 });
  silent.fault = 'silent'; garbage.fault = 'garbage'; wrong.fault = 'wrong';
  const { relay, rounds, log } = relayOf(chain, { silent, garbage, wrong, late, good });
  await rounds(2);
  assert.equal(chain.bestTip, bitcoin.best.hash);
  // Every header the chain was sent is one of the real chain's, whoever answered.
  const real = new Set(Array.from({ length: 7 }, (_, height) => bitcoin.at(height).header));
  for (const raw of chain.submitted) for (const header of SDK.decodeAction(Uint8Array.from(Buffer.from(raw, 'hex'))).payload.headers) assert.equal(real.has(header), true);
  const health = relay.health();
  assert.equal(health.ok, true);
  assert.deepEqual(health.body.bitcoin_nodes.map((node) => [node.name, node.usable]), [['silent', false], ['garbage', false], ['wrong', false], ['late', true], ['good', true]]);
  assert.deepEqual(health.body.warnings, ['a_bitcoin_node_is_not_usable']);
  assert.match(health.body.bitcoin_nodes[0].problem, /could not be reached/);
  assert.equal(log.said(/a Bitcoin node is not usable/).length, 3, 'each unusable node is said once');
  // No node at all: nothing is sent, and after a while the health answer fails.
  good.fault = 'silent'; late.fault = 'silent';
  bitcoin.mine();
  const sent = chain.submitted.length;
  await rounds(2);
  assert.equal(chain.submitted.length, sent);
  assert.equal(relay.health().body.status, 'no_bitcoin_node');
});

test('the health answer shows within minutes a relay that stalls, a chain that stays behind, and a Bitcoin tip that is old', async () => {
  // The first block that is mined is dated at the moment the test's clock starts.
  const bitcoin = createFakeBitcoin({ time: 1_800_000_000 - 1200 }), chain = createFakeChain({ bitcoin }), node = bitcoin.node();
  const { relay, rounds, now } = relayOf(chain, { own: node }, { pollMs: 10_000, maxBehindSeconds: 120, maxHeaderAgeSeconds: 1800, pendingMs: 30_000 });
  assert.deepEqual([relay.health().ok, relay.health().body.status], [false, 'starting']);
  bitcoin.mine();
  await rounds(1);
  assert.equal(relay.health().ok, true);
  assert.equal(relay.health().body.newest_bitcoin_header_age_seconds, 0);
  // No round for three poll intervals (at least a minute): the relay is stalled, whatever it last said.
  now.advance(61_000);
  assert.deepEqual([relay.health().ok, relay.health().body.status, relay.health().body.seconds_since_good_round], [false, 'stalled', 61]);
  await rounds(1);
  assert.equal(relay.health().ok, true);
  // The endpoint takes the headers and puts them in no block: the chain stays behind.
  chain.fault = 'deaf';
  bitcoin.mine();
  await rounds(1);
  assert.equal(relay.health().ok, true);
  now.advance(40_000);
  await rounds(1);
  assert.deepEqual(relay.health().body.warnings, ['headers_taken_but_in_no_block']);
  now.advance(90_000);
  await rounds(1);
  assert.deepEqual([relay.health().ok, relay.health().body.status, relay.health().body.blocks_behind, relay.health().body.behind_seconds], [false, 'chain_behind', 1, 130]);
  // The endpoint passes actions on again. The relay sends the headers once more when it no longer takes the last
  // sending as held, and the next proof shows them.
  chain.fault = null;
  now.advance(31_000);
  await rounds(2);
  assert.equal(relay.health().ok, true);
  assert.deepEqual(relay.health().body.warnings, []);
  // No new Bitcoin block for longer than the operator allows: a warning, since the nodes may all be cut off.
  now.advance(2_500_000);
  await rounds(1);
  assert.deepEqual([relay.health().ok, relay.health().body.warnings], [true, ['newest_bitcoin_header_is_old']]);
  // The Time endpoint does not answer: the relay says so, and fails once that has lasted.
  chain.fault = 'silent';
  await rounds(1);
  assert.equal(relay.health().body.status, 'time_unreachable');
  now.advance(61_000);
  await rounds(1);
  assert.deepEqual([relay.health().ok, relay.health().body.status], [false, 'time_unreachable']);
});

test('Bitcoin mainnet is refused, and a relay holds nothing secret in its log or its health answer', async () => {
  const bitcoin = createFakeBitcoin({ network: 'mainnet' }), chain = createFakeChain({ bitcoin }), node = bitcoin.node({ password: 'relay:a-password-nobody-may-see' });
  bitcoin.mineMany(2);
  const { relay, rounds, log } = relayOf(chain, { own: node });
  await rounds(3);
  assert.deepEqual(chain.submitted, []);
  assert.deepEqual([relay.health().ok, relay.health().body.status], [false, 'refused_network']);
  assert.equal(log.said(/mainnet, which is closed/).length, 1);
  // A regtest relay through every kind of trouble: the password and the node's address appear nowhere.
  const regtest = createFakeBitcoin(), second = createFakeChain({ bitcoin: regtest }), own = regtest.node({ password: 'relay:a-password-nobody-may-see' });
  const other = relayOf(second, { own });
  regtest.mineMany(3);
  await other.rounds(1);
  own.fault = 'silent'; await other.rounds(1);
  own.fault = 'garbage'; await other.rounds(1);
  own.password = 'changed'; own.fault = null; await other.rounds(1);
  const everything = other.log.text() + JSON.stringify(other.relay.health());
  assert.doesNotMatch(everything, /a-password-nobody-may-see|18443|127\.0\.0\.1/);
  assert.match(everything, /refused the name and password/);
});
