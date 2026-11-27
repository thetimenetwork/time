// The prover of Bitcoin payments (market-prover.mjs), with a Bitcoin node and a Time chain that exist in the test
// only (market-test-kit.mjs), on the engine's own material: the proofs the engine accepted
// (spec/market-vectors.json) and the rows it proves (verifier-v4/fixtures/market-engine.json).
import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import './time-sdk.js';
import * as installed from './proof-verifier.mjs';
import { transactionOutputs } from './bitcoin-address.mjs';
import { createBitcoinNodes, createBitcoinRpc } from './bitcoin-rpc.mjs';
import { createProver, memoryStore } from './market-prover.mjs';
import { loadSigningKey } from './market-service.mjs';
import { createClock, createFakeBitcoin, createFakeChain, createLog, makePayment, vectorBlock } from './market-test-kit.mjs';

const SDK = globalThis.TimeSDK;
const vectors = JSON.parse(await readFile(new URL('../spec/market-vectors.json', import.meta.url), 'utf8'));
const fixture = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/market-engine.json', import.meta.url), 'utf8'));
const [partProof, fullProof] = vectors.actions.filter((action) => action.kind === 54);
// The key of the vectors' prover (account 7): a test key, one byte repeated.
const SEED = partProof.seed_hex, PROVER = '7';
// Rows of the engine: the sell order and the fill in progress of the fixture's state `trading`.
const ORDER = fixture.cases.trading.market.orders['1'];
const { start_height: _h, start_hash: _s, opened_micros: _o, created: _c, ...ENGINE_FILL } = fixture.cases.trading.market.fills['2'];
const SECURITY = { allowance_elapsed_micros: '0', allowance_micros: '600000000', freezes: '0', frozen_until_elapsed_micros: '0', next_id: '1', pending_limit: null, pending_payments: [], pending_root: null, policy: { daily_limit_micros: '600000000', delay_seconds: '86400', freeze_seconds: '86400', threshold: '2' }, version: '1' };
const SCRIPT = `0014${'7c'.repeat(20)}`, ELSEWHERE = `0014${'e1'.repeat(20)}`;
/// A fill of 40 seconds for 10,000 satoshis at the order's price, paid to `script`.
const fillOf = (id, script = SCRIPT, more = {}) => ({ id, order: '1', owner: '5', payer: '6', to: '6', side: 'sell', price: '250000000', amount_micros: '40000000', deposit_micros: '2000000', sats: '10000', confirmations: '2', pay_blocks: '6', script, ...more });

/// A Bitcoin network of ten blocks (or `blocks`), and a Time chain that follows it, with a seller (5), a buyer (6), the prover's
/// account (7, with the security rules and a spend key) and the engine's sell order.
async function world({ blocks = 10, ...options } = {}) {
  const bitcoin = createFakeBitcoin(), chain = createFakeChain({ bitcoin, networkId: vectors.network_id, ...options });
  const key = await loadSigningKey({ env: 'PROVER_KEY' }, { PROVER_KEY: SEED });
  if (blocks) { bitcoin.mineMany(blocks); chain.follow(); }
  chain.addAccount({ id: '5', publicKey: 'a5'.repeat(32) }); chain.addAccount({ id: '6', publicKey: 'a6'.repeat(32) });
  chain.addAccount({ id: PROVER, balance: '1000000', publicKey: key.publicKey, security: SECURITY });
  chain.addOrder(ORDER);
  return { bitcoin, chain, key };
}
function proverOf({ chain, key }, named, settings = {}, more = {}) {
  const now = more.now ?? createClock(), log = createLog(), store = more.store ?? memoryStore();
  const rpcOf = (node) => createBitcoinRpc({ url: 'http://127.0.0.1:18443/', login: async () => node.password, fetcher: node.fetcher, timeoutMs: 200 });
  const prover = createProver({
    nodes: createBitcoinNodes(Object.entries(named).map(([name, node]) => ({ name, rpc: rpcOf(node) }))), ...chain.endpoint, networkId: chain.networkId, account: PROVER, key: more.key ?? key, store, log, now, sleep: async (ms) => { now.advance(ms); },
    settings: { maxBalanceMicros: '5000000', maxFeePerProofMicros: '100000', maxFeesPerDayMicros: '1000000', ...settings },
  });
  return { prover, now, log, store, rounds: async (count = 1) => { const results = []; for (let i = 0; i < count; i++) results.push(await prover.round()); return results; } };
}
const sentKinds = (chain) => chain.submitted.map((raw) => SDK.decodeAction(Uint8Array.from(Buffer.from(raw, 'hex'))).kind);
const sentProofs = (chain) => chain.submitted.map((raw) => SDK.decodeAction(Uint8Array.from(Buffer.from(raw, 'hex')))).filter((action) => action.kind === 54);

test('a payment of a part and then the rest: the prover sends, byte for byte, the two proofs the engine accepted', async () => {
  // The engine's two blocks are put right on the test network's first block. Their headers name the engine's own
  // chain as their parents, which this network does not have: the prover, which walks down from the chain's best
  // block by the parents the headers name, finds below them a block no node can give, says so, and goes on.
  const w = await world({ blocks: 0 }), { bitcoin, chain } = w;
  const script = transactionOutputs(partProof.payload.transaction)[Number(partProof.payload.vout)].script;
  chain.addFill(fillOf(partProof.payload.fill, script, { confirmations: '1' }));
  assert.deepEqual([chain.fill('1').amount_micros, chain.fill('1').deposit_micros, chain.fill('1').sats], Object.values(partProof.fill.before));
  const { prover, rounds, log } = proverOf(w, { own: bitcoin.node() });
  await rounds(2);
  assert.deepEqual(chain.submitted, [], 'nothing is paid, nothing is sent');
  // The buyer pays 4,000 of the 10,000 satoshis: the engine's own block, as a node gives it.
  const first = vectorBlock(partProof);
  bitcoin.adopt(first.header, first.transactions); chain.follow();
  await rounds(1);
  assert.equal(chain.submitted.length, 1);
  assert.equal(chain.submitted[0], partProof.signed_hex, 'the same bytes as the proof the engine accepted: payload, nonce, signature');
  const after = chain.fill('1');
  assert.deepEqual({ amount_micros: after.amount_micros, deposit_micros: after.deposit_micros, sats: after.sats }, partProof.fill.after);
  assert.equal(chain.account(PROVER).balance, (1000000n - BigInt(partProof.fee_micros)).toString(), 'the fee the engine took for it');
  await rounds(2);
  assert.equal(chain.submitted.length, 1, 'a counted payment is not proven again');
  // The rest, in the next block, in a transaction with many outputs.
  const second = vectorBlock(fullProof);
  bitcoin.adopt(second.header, second.transactions); chain.follow();
  await rounds(1);
  assert.deepEqual(chain.submitted, [partProof.signed_hex, fullProof.signed_hex]);
  assert.equal(chain.fill('1'), null, 'paid in full: the fill has ended');
  assert.equal(chain.account(PROVER).balance, (1000000n - BigInt(partProof.fee_micros) - BigInt(fullProof.fee_micros)).toString());
  assert.equal(chain.account('6').balance, '42000000', 'the buyer has the 40 seconds and the deposit back');
  // The log says what changed, and the health answer what it cost.
  const counted = log.said(/^proof counted/);
  assert.deepEqual(counted.map((line) => [line.message, line.fill, line.paid_sats, line.fee_micros, line.before.sats, line.after?.sats ?? null]), [
    ['proof counted: a part of the fill is paid', '1', '4000', partProof.fee_micros, '10000', '6000'],
    ['proof counted: the fill is paid in full and has ended', '1', transactionOutputs(fullProof.payload.transaction)[Number(fullProof.payload.vout)].sats, fullProof.fee_micros, '6000', null],
  ]);
  // The block below the engine's two, which no node has, was asked for and said to be missing, once.
  assert.deepEqual(log.said(/could not be had from any node/).map((line) => line.height), [0]);
  await rounds(1);
  const { ok, body } = prover.health();
  assert.equal(ok, true);
  assert.deepEqual([body.status, body.fills.open, body.payments.proven_since_start, body.fees.spent_micros, body.fees.proofs, body.balance_micros], ['ok', 0, 2, String(Number(partProof.fee_micros) + Number(fullProof.fee_micros)), 2, chain.account(PROVER).balance]);
});

test('the confirmations are counted on the chain\'s view of Bitcoin, not on the node\'s', async () => {
  const w = await world(), { bitcoin, chain } = w;
  // The engine's own fill row, started at the chain's best block now: 3,000 satoshis, two confirmations.
  const fill = chain.addFill(ENGINE_FILL);
  const { prover, rounds } = proverOf(w, { own: bitcoin.node() });
  const paid = bitcoin.mine([makePayment([{ sats: 3000, script: fill.script }, { sats: 77, script: ELSEWHERE }])]);
  await rounds(1);
  assert.equal(prover.health().body.payments.waiting, 0, 'the chain does not know the block yet: the prover does not look above the chain\'s best block');
  chain.follow();
  await rounds(1);
  assert.deepEqual([prover.health().body.payments.waiting, chain.submitted.length], [1, 0], 'one confirmation of two');
  // The node sees two more blocks; the chain has not been told. The node's count is not the chain's.
  bitcoin.mineMany(2);
  await rounds(2);
  assert.equal(chain.submitted.length, 0);
  chain.follow();
  await rounds(1);
  assert.equal(sentProofs(chain).length, 1);
  assert.equal(sentProofs(chain)[0].payload.block_hash, paid.hash);
  assert.equal(chain.fill(fill.id), null);
  assert.equal(chain.account('6').balance, String(BigInt(ENGINE_FILL.amount_micros) + BigInt(ENGINE_FILL.deposit_micros)));
});

test('the blocks that are searched are those under the chain\'s best block, whatever the node\'s own best chain is', async () => {
  const w = await world(), { bitcoin, chain } = w;
  const fill = chain.addFill(fillOf('1')), start = bitcoin.best;
  // Two branches from the fill's starting block. The chain follows the first, which holds no payment.
  const followed = bitcoin.mineMany(3, { parent: start.hash });
  chain.follow();
  // The node's own best chain is another branch, which the chain was never told of. A payment to the fill's
  // address is in it.
  const paying = bitcoin.mine([makePayment([{ sats: 10000, script: SCRIPT }])], { parent: start.hash }), other = bitcoin.mineMany(2, { parent: paying.hash });
  assert.equal(other.height, followed.height);
  const node = bitcoin.node();
  node.tip = other.hash; node.show(followed.hash);
  const { prover, rounds } = proverOf(w, { own: node });
  await rounds(3);
  // The node would give that block to anyone who asked by height. The prover asked by the hashes under the
  // chain's best block, and never saw it.
  assert.deepEqual([chain.submitted.length, chain.refusals.length, prover.report().payments.length], [0, 0, 0]);
  assert.equal(prover.health().ok, true);
  assert.equal(node.calls.getblockhash, undefined, 'no block is asked for by its height');
  // A node that never saw the chain's branch cannot serve at all, and the prover says so.
  const blind = bitcoin.node();
  blind.tip = other.hash;
  const second = proverOf(w, { own: blind });
  await second.rounds(2);
  assert.deepEqual([chain.submitted.length, second.prover.health().body.status], [0, 'no_node_sees_the_chains_best_block']);
  // The node's branch grows, the chain is told and follows it: now the payment is under the chain's best block.
  node.tip = bitcoin.mineMany(2, { parent: other.hash }).hash; chain.follow();
  await rounds(1);
  assert.deepEqual(sentProofs(chain).map((action) => action.payload.block_hash), [paying.hash]);
  assert.equal(chain.fill(fill.id), null);
  assert.equal(chain.refusals.length, 0);
});

test('several payments to one fill in one block, two of them outputs of one transaction: one proof each, the largest first', async () => {
  const w = await world(), { bitcoin, chain } = w;
  chain.addFill(fillOf('1'));
  const { prover, rounds, log } = proverOf(w, { own: bitcoin.node() });
  const double = makePayment([{ sats: 4000, script: SCRIPT }, { sats: 123456, script: ELSEWHERE }, { sats: 2500, script: SCRIPT }]), single = makePayment([{ sats: 3500, script: SCRIPT }], { witness: false });
  const block = bitcoin.mine([makePayment([{ sats: 1, script: ELSEWHERE }]), double, single]);
  bitcoin.mine(); chain.follow();
  await rounds(1);
  const proofs = sentProofs(chain);
  assert.deepEqual(proofs.map((action) => [action.payload.block_hash === block.hash, action.payload.vout, action.nonce]), [[true, '0', '1'], [true, '0', '2'], [true, '2', '3']]);
  assert.deepEqual(chain.proofs.map((proof) => [proof.sats, proof.full]), [['4000', false], ['3500', false], ['2500', true]]);
  assert.equal(chain.fill('1'), null);
  assert.deepEqual(log.said(/^proof counted/).map((line) => [line.before.sats, line.after?.sats ?? null]), [['10000', '6000'], ['6000', '2500'], ['2500', null]]);
  assert.equal(chain.refusals.length, 0, 'nothing the chain had to refuse');
  await rounds(2);
  assert.equal(chain.submitted.length, 3);
});

test('a payment too small to count is said once and not sent; it is sent when the fill needs no more than it pays', async () => {
  const w = await world(), { bitcoin, chain } = w;
  chain.addFill(fillOf('1'));
  const { prover, rounds, log } = proverOf(w, { own: bitcoin.node() });
  // 300 satoshis: below the order's smallest trade (1,000) and below half of the 10,000 still to pay.
  bitcoin.mine([makePayment([{ sats: 300, script: SCRIPT }])]); bitcoin.mine(); chain.follow();
  await rounds(3);
  assert.equal(chain.submitted.length, 0);
  assert.deepEqual(log.said(/too small to count/).map((line) => [line.level, line.paid_sats, line.still_to_pay_sats, line.smallest_trade_sats]), [['warn', '300', '10000', '1000']], 'once for three rounds');
  assert.equal(prover.health().body.payments.too_small_now, 1);
  // The buyer pays the other 9,700. Then 300 are still to pay, and the small payment pays them in full.
  bitcoin.mine([makePayment([{ sats: 9700, script: SCRIPT }])]); bitcoin.mine(); chain.follow();
  await rounds(1);
  assert.deepEqual(chain.proofs.map((proof) => [proof.sats, proof.full]), [['9700', false], ['300', true]]);
  assert.equal(chain.fill('1'), null);
  assert.equal(chain.refusals.length, 0);
});

test('a reorganisation moves the payment to another block: it is found again by the block\'s hash and proven there', async () => {
  const w = await world(), { bitcoin, chain } = w;
  const fill = chain.addFill(fillOf('1')), start = bitcoin.best, payment = makePayment([{ sats: 10000, script: SCRIPT }]);
  const { prover, rounds, log } = proverOf(w, { own: bitcoin.node() });
  const first = bitcoin.mine([payment]); chain.follow();
  await rounds(1);
  assert.deepEqual([prover.report().payments.map((found) => found.block), chain.submitted.length], [[first.hash], 0], 'found, with one confirmation of two');
  // Bitcoin leaves that block: an empty one takes its place, and the payment is in the block after it.
  const empty = bitcoin.mine([], { parent: start.hash }), second = bitcoin.mine([payment], { parent: empty.hash });
  bitcoin.mine([], { parent: second.hash }); chain.follow();
  assert.equal(bitcoin.at(11).hash, empty.hash);
  await rounds(1);
  assert.deepEqual(log.said(/another block after a reorganisation/).map((line) => [line.was, line.now, line.height]), [[first.hash, second.hash, 12]]);
  assert.deepEqual(sentProofs(chain).map((action) => action.payload.block_hash), [second.hash], 'one proof, for the block the payment is in now');
  assert.equal(chain.fill(fill.id), null);
  assert.equal(chain.refusals.length, 0);
});

test('a payment at or below the starting height counts only after a reorganisation, in a block that was not on the fill\'s chain', async () => {
  const w = await world(), { bitcoin, chain } = w;
  // The address received money before the fill was made: that payment is not for this fill, and is never sent.
  const early = makePayment([{ sats: 10000, script: SCRIPT }]);
  bitcoin.mine([early]); bitcoin.mine(); chain.follow();
  const fill = chain.addFill(fillOf('1'));
  assert.equal(fill.start_height, '12');
  const { rounds, log } = proverOf(w, { own: bitcoin.node() });
  bitcoin.mineMany(3); chain.follow();
  await rounds(3);
  assert.equal(chain.submitted.length, 0);
  assert.equal(log.said(/at or below the block the fill started on/).length, 1);
  // A reorganisation from two blocks below the start: the buyer's payment lands in the new block at the starting
  // height itself. The engine counts it once the new branch has the confirmations past the start (5.2, point 7).
  const paying = makePayment([{ sats: 10000, script: SCRIPT }]), fork = bitcoin.at(10);
  const a = bitcoin.mine([], { parent: fork.hash }), b = bitcoin.mine([paying], { parent: a.hash });
  assert.equal(b.height, 12);
  const tip = bitcoin.mineMany(4, { parent: b.hash });
  assert.equal(bitcoin.best.hash, tip.hash);
  chain.follow();
  await rounds(1);
  assert.deepEqual(sentProofs(chain).map((action) => action.payload.block_hash), [b.hash]);
  assert.equal(chain.fill('1'), null);
  assert.equal(chain.refusals.length, 0);
});

test('a node that withholds a block, lags, or answers garbage does not stop the prover while another node answers', async () => {
  const w = await world(), { bitcoin, chain } = w;
  chain.addFill(fillOf('1'));
  const good = bitcoin.node(), keeps = bitcoin.node(), late = bitcoin.node({ lag: 3 }), garbage = bitcoin.node();
  garbage.fault = 'garbage';
  const paid = bitcoin.mine([makePayment([{ sats: 10000, script: SCRIPT }])]);
  bitcoin.mine(); chain.follow();
  keeps.fault = { withhold: paid.hash };
  // Alone, the node that does not give the block finds nothing; the prover says which block it lacks and waits.
  const alone = proverOf(w, { keeps });
  await alone.rounds(2);
  assert.equal(chain.submitted.length, 0);
  assert.deepEqual(alone.log.said(/could not be had from any node/).map((line) => [line.block, line.height]), [[paid.hash, 11]]);
  assert.deepEqual([alone.prover.health().ok, alone.prover.health().body.blocks_left_to_search, alone.prover.health().body.warnings], [true, 1, ['blocks_left_to_search']]);
  // A node that is behind the chain alone: it does not see the chain's best block, and nothing is searched.
  const behind = proverOf(w, { late, garbage });
  await behind.rounds(2);
  assert.equal(chain.submitted.length, 0);
  assert.equal(behind.prover.health().body.status, 'no_node_sees_the_chains_best_block');
  assert.deepEqual(behind.prover.health().body.bitcoin_nodes.map((node) => [node.name, node.usable, node.sees_the_chains_best_block]), [['late', true, false], ['garbage', false, false]]);
  // With one good node among them the proof goes out, and it is the real one.
  const { prover, rounds } = proverOf(w, { garbage, keeps, late, good });
  await rounds(1);
  assert.deepEqual(chain.proofs.map((proof) => [proof.sats, proof.full]), [['10000', true]]);
  assert.equal(chain.refusals.length, 0);
  assert.deepEqual(prover.health().body.warnings.sort(), ['a_bitcoin_node_does_not_see_the_chains_best_block', 'a_bitcoin_node_is_not_usable']);
  // The block comes back: the prover that waited finds the payment, and its fill has ended meanwhile.
  keeps.fault = null;
  await alone.rounds(2);
  assert.equal(chain.submitted.length, 1, 'nothing is sent for a fill that has ended');
});

test('what cannot be proven is said once, plainly: a payment too large, a coinbase too large', async () => {
  const w = await world(), { bitcoin, chain } = w;
  chain.addFill(fillOf('1')); chain.addFill(fillOf('2', ELSEWHERE));
  const { prover, rounds, log } = proverOf(w, { own: bitcoin.node() });
  // 100,001 bytes and more without witness data: only a miner puts such a transaction in a block.
  bitcoin.mine([makePayment([{ sats: 10000, script: SCRIPT }], { padding: 100_100 })]);
  bitcoin.mine([makePayment([{ sats: 10000, script: ELSEWHERE }])], { coinbaseExtra: 150_100 });
  bitcoin.mineMany(2); chain.follow();
  await rounds(3);
  assert.equal(chain.submitted.length, 0);
  const lines = log.said(/A PAYMENT CANNOT BE PROVEN/);
  assert.deepEqual(lines.map((line) => [line.level, line.fill]), [['error', '1'], ['error', '2']]);
  assert.match(lines[0].message, /its transaction is 100,\d{3} bytes without witness data, and a proof carries at most 100,000\. Only the seller's settle/);
  assert.match(lines[1].message, /the coinbase transaction of its block is 150,\d{3} bytes, and a proof carries at most 150,000/);
  assert.deepEqual([prover.health().body.payments.cannot_be_proven, prover.health().body.warnings], [2, ['a_payment_cannot_be_proven']]);
});

test('the budgets: a proof above the most per proof is not sent, and when the day\'s fees are used up the prover stops and says so', async () => {
  const w = await world(), { bitcoin, chain } = w;
  chain.addFill(fillOf('1')); chain.addFill(fillOf('2', ELSEWHERE));
  bitcoin.mine([makePayment([{ sats: 10000, script: SCRIPT }]), makePayment([{ sats: 10000, script: ELSEWHERE }])]);
  bitcoin.mine(); chain.follow();
  // A proof of such a payment costs 4,000 microseconds on this network.
  const stingy = proverOf(w, { own: bitcoin.node() }, { maxFeePerProofMicros: '3999' });
  await stingy.rounds(3);
  assert.equal(chain.submitted.length, 0);
  assert.deepEqual(stingy.log.said(/more than max_fee_per_proof_micros/).map((line) => line.fee_micros), ['4000', '4000']);
  assert.deepEqual(stingy.prover.health().body.warnings, ['a_proof_costs_more_than_allowed']);
  // Room for one proof a day.
  const { prover, rounds, now, log, store } = proverOf(w, { own: bitcoin.node() }, { maxFeesPerDayMicros: '7000' });
  await rounds(3);
  assert.equal(chain.submitted.length, 1);
  assert.deepEqual([prover.health().ok, prover.health().body.status, prover.health().body.fees.spent_micros], [false, 'daily_fee_budget_used_up', '4000']);
  assert.equal(log.said(/THE PROVER HAS STOPPED SENDING: the fees of today have reached max_fees_per_day_micros/).length, 1);
  // A restart does not forget what was spent today.
  const again = proverOf(w, { own: bitcoin.node() }, { maxFeesPerDayMicros: '7000' }, { store, now });
  await again.rounds(2);
  assert.equal(chain.submitted.length, 1);
  assert.equal(again.prover.health().body.status, 'daily_fee_budget_used_up');
  // The next day (UTC) it sends again.
  now.advance(24 * 3600 * 1000);
  await again.rounds(1);
  assert.equal(chain.submitted.length, 2);
  assert.deepEqual([again.prover.health().ok, again.prover.health().body.fees.spent_micros], [true, '4000']);
});

test('the balance: too little stops the prover, a little is a warning, and more than the ceiling stops the start', async () => {
  const w = await world(), { bitcoin, chain, key } = w;
  chain.addFill(fillOf('1'));
  bitcoin.mine([makePayment([{ sats: 10000, script: SCRIPT }])]); bitcoin.mine(); chain.follow();
  chain.live.accounts.get(PROVER).balance = '3999'; chain.commit();
  const poor = proverOf(w, { own: bitcoin.node() }, { minBalanceMicros: '50000' });
  await poor.rounds(2);
  assert.equal(chain.submitted.length, 0);
  assert.deepEqual([poor.prover.health().ok, poor.prover.health().body.status, poor.prover.health().body.balance_low], [false, 'balance_too_low', true]);
  chain.live.accounts.get(PROVER).balance = '40000'; chain.commit();
  await poor.rounds(1);
  assert.equal(chain.submitted.length, 1);
  assert.deepEqual([poor.prover.health().ok, poor.prover.health().body.warnings], [true, ['balance_low']]);
  // The account holds more than the operator's ceiling: the service does not start, and a running one sends nothing.
  chain.addFill(fillOf('2', ELSEWHERE));
  bitcoin.mine([makePayment([{ sats: 10000, script: ELSEWHERE }])]); bitcoin.mine(); chain.follow();
  chain.live.accounts.get(PROVER).balance = '5000001'; chain.commit();
  const rich = proverOf(w, { own: bitcoin.node() });
  await assert.rejects(rich.prover.check(), /does not start: the prover's account holds more than max_balance_micros/);
  await rich.rounds(2);
  assert.equal(chain.submitted.length, 1);
  assert.deepEqual([rich.prover.health().ok, rich.prover.health().body.status], [false, 'key_or_account']);
  chain.live.accounts.get(PROVER).balance = '5000000'; chain.commit();
  assert.deepEqual(await rich.prover.check(), { balance: 5000000n, fee: 1000n });
  // An amount that is not written out is refused: nothing about money has a default.
  for (const name of ['maxBalanceMicros', 'maxFeePerProofMicros', 'maxFeesPerDayMicros']) assert.throws(() => proverOf(w, { own: bitcoin.node() }, { [name]: undefined }), new RegExp(`${name} is a whole number of microseconds`));
  assert.throws(() => createProver({ nodes: createBitcoinNodes([]), ...chain.endpoint, networkId: chain.networkId, account: '@prover', key, settings: { maxBalanceMicros: '1', maxFeePerProofMicros: '1', maxFeesPerDayMicros: '1' } }), /account is the number/);
});

test('the key: only a spend key of a secured account of its own is used, and it appears in no log, error, health answer or store', async () => {
  const w = await world(), { bitcoin, chain, key } = w;
  chain.addFill(fillOf('1'));
  bitcoin.mine([makePayment([{ sats: 10000, script: SCRIPT }])]); bitcoin.mine(); chain.follow();
  // A key the account does not have.
  const other = await loadSigningKey({ env: 'K' }, { K: '09'.repeat(32) }), stranger = proverOf(w, { own: bitcoin.node() }, {}, { key: other });
  await assert.rejects(stranger.prover.check(), /the key is not a key of the prover's account/);
  await stranger.rounds(1);
  assert.equal(stranger.prover.health().body.status, 'key_or_account');
  // The account's one key with every power, and an account without the security rules.
  chain.addAccount({ id: PROVER, balance: '1000000', publicKey: key.publicKey, canManage: true, security: SECURITY });
  await assert.rejects(proverOf(w, { own: bitcoin.node() }).prover.check(), /holds every power of the prover's account/);
  chain.addAccount({ id: PROVER, balance: '1000000', publicKey: key.publicKey });
  chain.live.security.delete(PROVER); chain.commit();
  const plain = proverOf(w, { own: bitcoin.node() });
  await assert.rejects(plain.prover.check(), /has not adopted the security rules/);
  await plain.rounds(1);
  assert.equal(chain.submitted.length, 0);
  // The operator may say otherwise, for a laboratory network.
  const allowed = proverOf(w, { own: bitcoin.node() }, { allowUnsecured: true });
  await allowed.prover.check();
  // A frozen account sends nothing.
  chain.live.security.set(PROVER, { account: PROVER, ...SECURITY, frozen_until_elapsed_micros: '99999999999999' }); chain.commit();
  await assert.rejects(proverOf(w, { own: bitcoin.node() }).prover.check(), /is frozen/);
  chain.live.security.set(PROVER, { account: PROVER, ...SECURITY }); chain.commit();
  // Through all of it, and a proof: the seed is nowhere.
  await allowed.rounds(1);
  assert.equal(chain.proofs.length, 1);
  const everything = [stranger, plain, allowed].map((one) => one.log.text() + JSON.stringify(one.prover.health()) + JSON.stringify(one.prover.report()) + JSON.stringify(one.store.value)).join('\n');
  assert.doesNotMatch(everything, new RegExp(`${SEED}|${'09'.repeat(32)}`));
  assert.doesNotMatch(everything, /privateKey|CryptoKey/);
  assert.match(everything, /proof counted/);

  // Where the key comes from: a variable of the environment, removed once read, or a file only its owner reads.
  const environment = { PROVER_KEY: SEED, OTHER: 'kept' };
  const loaded = await loadSigningKey({ env: 'PROVER_KEY' }, environment);
  assert.equal(loaded.publicKey, partProof.public_key);
  assert.deepEqual(environment, { OTHER: 'kept' });
  assert.equal(loaded.privateKey.extractable, false);
  await assert.rejects(loadSigningKey({ env: 'PROVER_KEY' }, environment), /the environment variable that key_env names is not set/i);
  await assert.rejects(loadSigningKey({ env: 'OTHER' }, environment), (error) => /one line: the 32-byte Ed25519 seed/.test(error.message) && !error.message.includes('kept'));
  await assert.rejects(loadSigningKey({}), /exactly one of key_env and key_file/);
  await assert.rejects(loadSigningKey({ env: 'A', file: '/b' }), /exactly one of key_env and key_file/);
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-prover-key-'));
  try {
    const file = path.join(directory, 'spend');
    await writeFile(file, `${SEED}\n`, { mode: 0o600 });
    assert.equal((await loadSigningKey({ file })).publicKey, partProof.public_key);
    await writeFile(path.join(directory, 'bad'), `${'AB'.repeat(32)}\n`, { mode: 0o600 });
    await assert.rejects(loadSigningKey({ file: path.join(directory, 'bad') }), (error) => /one line/.test(error.message) && !/ABAB/i.test(error.message) && !error.message.includes(directory));
    await assert.rejects(loadSigningKey({ file: path.join(directory, 'absent') }), (error) => error.message === 'The key file could not be read');
    if (process.platform !== 'win32') { await chmod(file, 0o640); await assert.rejects(loadSigningKey({ file }), /read by other users of this machine: chmod 600/); }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('nothing is sent twice: an action that is in no block is the same bytes again, and a refused proof waits longer each time', async () => {
  const w = await world(), { bitcoin, chain } = w;
  chain.addFill(fillOf('1'));
  bitcoin.mine([makePayment([{ sats: 10000, script: SCRIPT }])]); bitcoin.mine(); chain.follow();
  // The endpoint takes the proof and puts it in no block.
  chain.fault = 'deaf';
  const { prover, rounds, now, log } = proverOf(w, { own: bitcoin.node() }, { settleMs: 5000, abandonMs: 60_000 });
  await rounds(4);
  assert.equal(chain.submitted.length, 4, 'the first sending and one more each round');
  assert.equal(new Set(chain.submitted).size, 1, 'the same bytes: nothing new was signed');
  assert.deepEqual([prover.health().ok, prover.health().body.status, prover.health().body.action_in_no_block_yet, prover.health().body.warnings], [true, 'waiting_for_a_block', true, ['an_action_is_in_no_block_yet']]);
  // The endpoint works again and takes the same bytes: the proof is counted, once.
  chain.fault = null;
  await rounds(2);
  assert.deepEqual(chain.proofs.map((proof) => proof.sats), ['10000']);
  assert.equal(new Set(chain.submitted).size, 1);
  assert.equal(log.said(/^proof counted/).length, 1);

  // A chain that refuses: the proof costs nothing and is tried again after 10 s, 20 s, 40 s ..., not every round.
  chain.addFill(fillOf('2', ELSEWHERE));
  bitcoin.mine([makePayment([{ sats: 10000, script: ELSEWHERE }])]); bitcoin.mine(); chain.follow();
  chain.fault = { refuse: 'Bitcoin payment lacks confirmations' };
  const before = chain.submitted.length, balance = chain.account(PROVER).balance;
  await rounds(5);
  assert.equal(chain.submitted.length, before + 1);
  now.advance(10_000); await rounds(3);
  assert.equal(chain.submitted.length, before + 2);
  now.advance(10_000); await rounds(1);
  assert.equal(chain.submitted.length, before + 2);
  now.advance(10_000); await rounds(1);
  assert.equal(chain.submitted.length, before + 3);
  assert.equal(chain.account(PROVER).balance, balance, 'a refused proof costs no fee');
  assert.equal(log.said(/the chain refused a proof/).length, 1, 'said once');
  // "This output has paid already" ends it: someone else proved the payment.
  chain.fault = { refuse: 'this Bitcoin output has paid for a fill already' };
  now.advance(600_000); await rounds(1);
  now.advance(600_000); await rounds(3);
  assert.equal(chain.submitted.length, before + 4);
  assert.equal(log.said(/someone else proved it/).length, 1);
});

test('which fills are open is read from proven rows, sixteen at a time: newest first at a first start, and only what is new after a restart', async () => {
  const w = await world(), { bitcoin, chain } = w;
  // Forty fills were made; three are still open.
  for (let id = 1; id <= 40; id++) chain.addFill(fillOf(String(id), `0014${id.toString(16).padStart(2, '0').repeat(20)}`));
  for (let id = 1; id <= 40; id++) if (![22, 37, 40].includes(id)) chain.live.fills.delete(String(id));
  chain.commit(); chain.reads.length = 0;
  const { prover, rounds, store } = proverOf(w, { own: bitcoin.node() });
  await rounds(1);
  assert.deepEqual(prover.report().fills.map((fill) => fill.id).sort(), ['22', '37', '40']);
  const asked = chain.reads.filter((selection) => selection.market_fills).map((selection) => selection.market_fills);
  assert.equal(asked.every((ids) => ids.length <= 16), true);
  // Ids 40 down to 9 in two reads: the three open fills are found, and the older ids are not read at all.
  assert.deepEqual(asked.slice(0, 2).map((ids) => [ids[0], ids.at(-1)]), [['40', '25'], ['24', '9']]);
  assert.deepEqual([prover.health().body.fills.looked_at_from, prover.health().body.fills.looked_at_to, prover.health().body.fills.next_fill], ['9', '40', '41']);
  // Every round reads the open ones again, and nothing else.
  chain.reads.length = 0;
  await rounds(1);
  assert.deepEqual(chain.reads.filter((selection) => selection.market_fills && !selection.ids).map((selection) => selection.market_fills), [['22', '37', '40']]);
  // A new fill, and one that ended: the next round sees both.
  chain.addFill(fillOf('41', ELSEWHERE)); chain.live.fills.delete('22'); chain.commit();
  await rounds(1);
  assert.deepEqual(prover.report().fills.map((fill) => fill.id).sort(), ['37', '40', '41']);
  // A restart goes on from what was remembered.
  chain.reads.length = 0;
  const again = proverOf(w, { own: bitcoin.node() }, {}, { store });
  await again.rounds(1);
  assert.deepEqual(again.prover.report().fills.map((fill) => fill.id).sort(), ['37', '40', '41']);
  assert.deepEqual(chain.reads.filter((selection) => selection.market_fills && !selection.ids).map((selection) => selection.market_fills), [['37', '40', '41']]);
  // A store of another account or network is not used.
  const fresh = proverOf(w, { own: bitcoin.node() }, {}, { store: memoryStore({ ...store.value, account: '8' }) });
  await fresh.rounds(1);
  assert.deepEqual([fresh.prover.health().body.fills.open, fresh.prover.health().body.fills.looked_at_from], [3, '26'], 'a first start again: the newest sixteen ids held all three');
});

test('the engine\'s proven rows, through the installed verifier: the open fills of the fixture are found, and no API is asked', async (t) => {
  const item = fixture.cases.trading;
  const marketOnly = (selection) => Object.fromEntries(Object.entries(selection).filter(([name]) => name === 'include_bitcoin' || name === 'include_market' || name.startsWith('market_')));
  const knowsTheMarket = await installed.verifyViewProof(item.proof, item.trust, { include_market: true }, item.now_ms).then((probe) => Object.hasOwn(probe.state, 'market'), () => false);
  if (!knowsTheMarket) return t.skip('the compiled verifier in web-v4/shared/verifier predates the rows of the market; build it with node tools/build-verifier.mjs --local to run this test');
  const key = await loadSigningKey({ env: 'K' }, { K: SEED }), asked = [];
  // Every row of the market and of the header chain comes out of the verifier; the fixture proves no account, so
  // the prover's own account row is added to what was verified.
  const readState = async (selection) => {
    asked.push(selection);
    const { state } = await installed.verifyViewProof(item.proof, item.trust, marketOnly(selection), item.now_ms);
    return { state: { ...state, accounts: [{ id: PROVER, name: 'prover', public_key: key.publicKey, balance: '1000000', nonce: '0', auth_epoch: '0', devices: [{ public_key: key.publicKey, can_manage: false, can_spend: true }] }], security: [{ account: PROVER, ...SECURITY }] } };
  };
  const bitcoin = createFakeBitcoin(), node = bitcoin.node(), log = createLog();
  const prover = createProver({
    nodes: createBitcoinNodes([{ name: 'own', rpc: createBitcoinRpc({ url: 'http://127.0.0.1:18443/', login: async () => node.password, fetcher: node.fetcher }) }]), readState, submit: async () => assert.fail('nothing is sent'),
    networkId: item.trust.network_id, account: PROVER, key, log, now: createClock(item.now_ms), settings: { maxBalanceMicros: '5000000', maxFeePerProofMicros: '100000', maxFeesPerDayMicros: '1000000' },
  });
  await prover.round();
  // Fill 1 has ended (a proven absence), fills 2 and 3 are open.
  assert.deepEqual(prover.report().fills.map((fill) => fill.id), ['2', '3']);
  assert.deepEqual(prover.report().fills[0], item.market.fills['2']);
  assert.deepEqual([prover.health().body.fills.looked_at_from, prover.health().body.fills.looked_at_to], ['1', '3']);
  assert.equal(prover.health().body.header_chain.best_block, item.market && JSON.parse(Buffer.from(item.proof.entries.find((entry) => Buffer.from(entry.key_hex, 'hex').toString() === 'bitcoin/meta').value_b64, 'base64').toString()).meta.best_tip);
  // The test's Bitcoin node has never seen the engine's regtest chain: the prover searches nothing and says so.
  assert.equal(prover.health().body.status, 'no_node_sees_the_chains_best_block');
  assert.equal(asked.every((selection) => (selection.market_fills ?? []).length <= 16), true);
});

test('expiring is off unless asked for; when on, a fill whose time has passed and that has no payment is ended, and a paid one never', async () => {
  const w = await world(), { bitcoin, chain } = w;
  chain.addFill(fillOf('1')); chain.addFill(fillOf('2', ELSEWHERE));
  // A payment to fill 2 that is too small to count: the fill is someone's purchase in progress all the same.
  bitcoin.mine([makePayment([{ sats: 200, script: ELSEWHERE }])]);
  // The chain learns the last height of both fills (start + 6 + 2 - 1), and the time to pay and the grace pass.
  bitcoin.mineMany(8); chain.follow();
  chain.pass(120);
  const off = proverOf(w, { own: bitcoin.node() });
  await off.rounds(2);
  assert.deepEqual(chain.submitted, []);
  const on = proverOf(w, { own: bitcoin.node() }, { expire: true });
  await on.rounds(2);
  assert.deepEqual(sentKinds(chain), [55]);
  assert.deepEqual(chain.expired, ['1']);
  assert.notEqual(chain.fill('2'), null, 'a fill a payment was found for is never ended by the prover');
  assert.deepEqual(on.log.said(/whose time had passed has ended/).map((line) => [line.fill, line.fee_micros]), [['1', '1000']]);
  assert.deepEqual([on.prover.health().body.fills_ended_since_start, on.prover.health().body.fees.expiries, on.prover.health().body.fees.spent_micros], [1, 1, '1000']);
  // A fill whose time has not passed is left alone, and the chain is not asked.
  chain.addFill(fillOf('3', SCRIPT));
  await on.rounds(2);
  assert.deepEqual(sentKinds(chain), [55]);
});

test('a halted header chain and Bitcoin mainnet: the prover sends nothing and says why', async () => {
  const w = await world(), { bitcoin, chain } = w;
  chain.addFill(fillOf('1'));
  bitcoin.mine([makePayment([{ sats: 10000, script: SCRIPT }])]); bitcoin.mine(); chain.follow();
  chain.live.halted = { reason: 'deep_reorg', old_tip: chain.bestTip, candidate: 'ab'.repeat(32), common_height: 3 }; chain.commit();
  const { prover, rounds, log } = proverOf(w, { own: bitcoin.node() }, { expire: true });
  await rounds(3);
  assert.deepEqual(chain.submitted, []);
  assert.deepEqual([prover.health().ok, prover.health().body.status], [false, 'halted']);
  assert.equal(log.said(/HEADER CHAIN OF THE TIME CHAIN IS HALTED/).length, 1);
  const mainnet = createFakeBitcoin({ network: 'mainnet' }), other = createFakeChain({ bitcoin: mainnet, networkId: vectors.network_id });
  other.addAccount({ id: PROVER, balance: '1000000', publicKey: w.key.publicKey, security: SECURITY });
  const closed = proverOf({ chain: other, key: w.key }, { own: mainnet.node() });
  await assert.rejects(closed.prover.check(), /mainnet, which is closed/);
  await closed.rounds(1);
  assert.deepEqual([closed.prover.health().ok, closed.prover.health().body.status], [false, 'refused_network']);
  // A network without the market.
  const none = createFakeChain({ bitcoin, networkId: vectors.network_id, market: false });
  none.addAccount({ id: PROVER, balance: '1000000', publicKey: w.key.publicKey, security: SECURITY });
  const without = proverOf({ chain: none, key: w.key }, { own: bitcoin.node() });
  await assert.rejects(without.prover.check(), /has no market/);
  await without.rounds(1);
  assert.equal(without.prover.health().body.status, 'no_market');
});

test('the one-shot tool\'s mode: one fill is looked at, proven, and reported; the others are left alone', async () => {
  const w = await world(), { bitcoin, chain } = w;
  chain.addFill(fillOf('1')); chain.addFill(fillOf('2', ELSEWHERE));
  bitcoin.mine([makePayment([{ sats: 10000, script: SCRIPT }]), makePayment([{ sats: 4000, script: ELSEWHERE }])]);
  bitcoin.mine(); chain.follow();
  const store = memoryStore({ network_id: chain.networkId, account: PROVER, low: '1', high: '2', open: ['1', '2'], day: '2000-01-01', spent_micros: '0', proofs: 0, expiries: 0 });
  const { prover, rounds } = proverOf(w, { own: bitcoin.node() }, { only: '2' }, { store });
  await rounds(2);
  assert.deepEqual(chain.proofs.map((proof) => [proof.fill, proof.sats, proof.full]), [['2', '4000', false]]);
  const report = prover.report();
  assert.deepEqual(report.fills.map((fill) => [fill.id, fill.sats]), [['2', '6000']]);
  assert.deepEqual(report.payments.map((payment) => [payment.fill, payment.sats, payment.proven, payment.height]), [['2', '4000', true, 11]]);
  assert.equal(report.events.some((event) => /^proof counted: a part/.test(event.message)), true);
  // What a service on the same data directory remembered of the fills is as it was.
  assert.deepEqual([store.value.low, store.value.high, store.value.open], ['1', '2', ['1', '2']]);
  assert.equal(store.value.spent_micros, '4000');
  assert.throws(() => proverOf(w, { own: bitcoin.node() }, { only: 'two' }), /only is the id of a fill/);
});
