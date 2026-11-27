// The services of the market against a real Bitcoin Core, in regtest with its networking off
// (tools/bitcoin-regtest.mjs). What the client of the RPC reads, and what the prover makes of it, is held to what
// Bitcoin Core itself gives: the forms, the byte order of hashes, the removal of witness data, and a Merkle proof
// with exactly two matches, the coinbase first.
//
// It needs Bitcoin Core 32.1 in .tools/bitcoin-core-32.1 of this repository, of the repository folder beside it
// (../production), or in the folder TIME_BITCOIN_CORE_DIR names (the folder that holds bitcoind). Without it the
// test is skipped. The Time chain is the test's own (market-test-kit.mjs): the engine is not part of this test.
//
// With TIME_MARKET_REGTEST_EXPORT set to a file name, the headers and the proofs of this run are written there, for
// the engine's own verifier: bitcoin-bridge/tests/prover.rs reads them (TIME_MARKET_REGTEST_SCENARIO).
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { access, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import './time-sdk.js';
import { merkleProofMatches, stripWitness, transactionOutputs } from './bitcoin-address.mjs';
import { createBitcoinNodes, createBitcoinRpc, headerFields, nodeLogin, paymentsIn } from './bitcoin-rpc.mjs';
import { createProver } from './market-prover.mjs';
import { createRelay } from './market-relay.mjs';
import { loadSigningKey } from './market-service.mjs';
import { createFakeChain, createLog } from './market-test-kit.mjs';
import { createRegtest } from '../tools/bitcoin-regtest.mjs';

const SDK = globalThis.TimeSDK;
const root = fileURLToPath(new URL('../', import.meta.url)), exe = process.platform === 'win32' ? '.exe' : '';
const REGTEST_GENESIS = '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206';
async function coreDirectory() {
  const places = [process.env.TIME_BITCOIN_CORE_DIR, path.join(root, '.tools/bitcoin-core-32.1/bitcoin-32.1/bin'), path.join(root, '../production/.tools/bitcoin-core-32.1/bitcoin-32.1/bin')].filter(Boolean);
  for (const place of places) if (await access(path.join(place, `bitcoind${exe}`)).then(() => true, () => false)) return place;
  return null;
}
const coreDir = await coreDirectory();
const SECURITY = { allowance_elapsed_micros: '0', allowance_micros: '600000000', freezes: '0', frozen_until_elapsed_micros: '0', next_id: '1', pending_limit: null, pending_payments: [], pending_root: null, policy: { daily_limit_micros: '600000000', delay_seconds: '86400', freeze_seconds: '86400', threshold: '2' }, version: '1' };

test('against Bitcoin Core in regtest: the client reads what the node gives, the relay follows a reorganisation, and the prover\'s proofs are the node\'s own bytes', { skip: coreDir ? false : 'Bitcoin Core 32.1 is not in .tools/bitcoin-core-32.1 here or in ../production, and TIME_BITCOIN_CORE_DIR is not set', timeout: 180_000 }, async () => {
  const core = await createRegtest({ coreDir });
  try {
    const wallet = { wallet: 'time-regtest-fixture' };
    const rpc = createBitcoinRpc({ url: `http://127.0.0.1:${core.rpcPort}/`, login: nodeLogin({ cookieFile: path.join(core.datadir, 'regtest', '.cookie') }) });
    const nodes = createBitcoinNodes([{ name: 'core', rpc }]);
    assert.equal((await core.rpc('getnetworkinfo')).networkactive, false, 'this node talks to no network');
    await core.mine(101);

    // ---- the chain's view, the header relay
    const chain = createFakeChain({ bitcoin: { network: 'regtest', at: () => ({ hash: REGTEST_GENESIS }) }, networkId: 'ce'.repeat(32) }), relayLog = createLog();
    const relay = createRelay({ nodes, ...chain.endpoint, networkId: chain.networkId, log: relayLog });
    await relay.round();
    const info = await core.rpc('getblockchaininfo');
    assert.deepEqual(await rpc.chainInfo(), { chain: 'regtest', blocks: 101, bestHash: info.bestblockhash, work: BigInt(`0x${info.chainwork}`), initialDownload: info.initialblockdownload });
    assert.equal(chain.bestTip, info.bestblockhash, 'the relay handed in every header from the genesis block');
    assert.equal(chain.bestHeight, 101);
    assert.equal(await rpc.hashAt(0), REGTEST_GENESIS);
    assert.equal(await rpc.hashAt(102), null);

    // ---- two fills, paid by one transaction; a third payment in a transaction of its own
    const key = await loadSigningKey({ env: 'K' }, { K: '0c'.repeat(32) });
    chain.addAccount({ id: '7', balance: '1000000', publicKey: key.publicKey, security: SECURITY }); chain.addAccount({ id: '6', publicKey: 'a6'.repeat(32) });
    const addresses = [await core.rpc('getnewaddress', ['', 'bech32'], wallet), await core.rpc('getnewaddress', ['', 'bech32m'], wallet), await core.rpc('getnewaddress', ['', 'legacy'], wallet)];
    const scripts = [];
    for (const address of addresses) scripts.push((await core.rpc('getaddressinfo', [address], wallet)).scriptPubKey);
    assert.deepEqual(scripts.map((script) => SDK.marketScriptForm(script)), ['p2wpkh', 'p2tr', 'p2pkh']);
    chain.addOrder({ amount_micros: '0', bond_micros: '0', confirmations: '2', created: { height: '3', time_micros: '1800000000000000' }, deposit_ppm: '0', id: '1', key: 'aa'.repeat(32), min_deposit_micros: '0', min_sats: '1000', open: true, owner: '5', pay_blocks: '6', price: '250000000', scripts: scripts.map((script, index) => ({ fill: String(index + 1), script })), side: 'sell' });
    // 10,000 satoshis each; the third is paid 12,345, more than it needs.
    const fills = scripts.map((script, index) => chain.addFill({ id: String(index + 1), order: '1', owner: '5', payer: '6', to: '6', side: 'sell', price: '250000000', amount_micros: '40000000', deposit_micros: '0', sats: '10000', confirmations: '2', pay_blocks: '6', script }));
    assert.deepEqual([fills[0].start_height, fills[0].start_hash], ['101', info.bestblockhash]);
    const both = await core.rpc('sendmany', ['', { [addresses[0]]: '0.00010000', [addresses[1]]: '0.00010000' }], wallet);
    const single = await core.rpc('sendtoaddress', [addresses[2], '0.00012345'], wallet);
    const [paidIn] = await core.mine(1);
    await core.mine(1);

    // ---- a block, as the client reads it and as Bitcoin Core lists it
    const listed = await core.rpc('getblock', [paidIn, 1]), block = await rpc.block(paidIn);
    assert.equal(listed.tx.length, 3);
    assert.deepEqual(block.transactions.map((transaction) => transaction.txid), listed.tx, 'the ids, in the block\'s order, as Bitcoin Core prints them');
    assert.equal(block.header, await core.rpc('getblockheader', [paidIn, false]));
    assert.equal(await rpc.header(paidIn), block.header);
    assert.equal(headerFields(block.header).previous, listed.previousblockhash);
    assert.equal(headerFields(block.header).time, listed.time);
    assert.deepEqual(await rpc.headerInfo(paidIn), { hash: paidIn, height: 102, onBestChain: true, previous: listed.previousblockhash, time: listed.time });
    for (const transaction of block.transactions) {
      const raw = await core.rpc('getrawtransaction', [transaction.txid, false, paidIn]), decoded = await core.rpc('decoderawtransaction', [raw]);
      assert.equal(transaction.hex, raw);
      assert.equal(await rpc.rawTransaction(transaction.txid, paidIn), raw);
      // Without its witness data a transaction keeps its id, and its hash becomes its id.
      const bare = await core.rpc('decoderawtransaction', [stripWitness(raw)]);
      assert.deepEqual([bare.txid, bare.hash, bare.size], [decoded.txid, decoded.txid, transaction.bareBytes]);
      assert.equal(decoded.txid, transaction.txid);
    }
    assert.notEqual(stripWitness(block.transactions[0].hex), block.transactions[0].hex, 'the coinbase of a block with a witness commitment has witness data');
    // The outputs that pay the three scripts, with their values read from the bytes.
    const found = paymentsIn(block, new Set(scripts));
    assert.deepEqual(found.map((payment) => [payment.txid, payment.sats]).sort(), [[both, '10000'], [both, '10000'], [single, '12345']].sort());
    for (const payment of found) {
      const out = (await core.rpc('getrawtransaction', [payment.txid, true, paidIn])).vout[payment.vout];
      assert.deepEqual([out.scriptPubKey.hex, Math.round(out.value * 1e8)], [payment.script, Number(payment.sats)]);
    }

    // ---- the prover: not before the chain knows the blocks, then one proof for each payment
    const log = createLog();
    const prover = createProver({ nodes, ...chain.endpoint, networkId: chain.networkId, account: '7', key, log, sleep: async () => {}, settings: { maxBalanceMicros: '5000000', maxFeePerProofMicros: '100000', maxFeesPerDayMicros: '1000000' } });
    await prover.round();
    assert.deepEqual(chain.submitted.filter((raw) => SDK.decodeAction(Uint8Array.from(Buffer.from(raw, 'hex'))).kind === 54), [], 'the node has the payments; the chain has not been told of their block');
    await relay.round();
    assert.equal(chain.bestHeight, 103);
    await prover.round();
    assert.deepEqual(chain.proofs.map((proof) => [proof.fill, proof.sats, proof.full]).sort(), [['1', '10000', true], ['2', '10000', true], ['3', '12345', true]]);
    assert.equal(chain.refusals.filter((reason) => !/no new headers/.test(reason)).length, 0);
    const coinbaseId = listed.tx[0], scenario = [];
    for (const raw of chain.proofs.map((proof) => proof.bytes)) {
      const { payload } = SDK.decodeAction(Uint8Array.from(Buffer.from(raw, 'hex'))), fill = fills[Number(payload.fill) - 1];
      const txid = payload.fill === '3' ? single : both, fromCore = await core.rpc('gettxoutproof', [[coinbaseId, txid], paidIn]);
      assert.equal(payload.block_hash, paidIn);
      assert.equal(payload.merkle_proof, fromCore, 'the Merkle proof is what gettxoutproof gives for the two ids');
      assert.deepEqual((await core.rpc('verifytxoutproof', [payload.merkle_proof])).sort(), [coinbaseId, txid].sort(), 'Bitcoin Core finds exactly the two transactions in it');
      const matched = await merkleProofMatches(payload.merkle_proof, paidIn);
      assert.deepEqual([matched.length, matched[0].place, matched[0].hash], [2, 0, Buffer.from(coinbaseId, 'hex').reverse().toString('hex')], 'two matches, the coinbase at the first place');
      assert.equal(payload.transaction, stripWitness(await core.rpc('getrawtransaction', [txid, false, paidIn])));
      assert.equal(payload.coinbase, stripWitness(await core.rpc('getrawtransaction', [coinbaseId, false, paidIn])));
      const decoded = await core.rpc('decoderawtransaction', [payload.transaction]);
      assert.equal(decoded.vout[Number(payload.vout)].scriptPubKey.hex, fill.script, 'the output named pays the fill\'s script');
      scenario.push({ fill: payload.fill, script: fill.script, start_height: Number(fill.start_height), start_hash: fill.start_hash, confirmations: Number(fill.confirmations), sats: transactionOutputs(payload.transaction)[Number(payload.vout)].sats, proof: { block_hash: payload.block_hash, transaction: payload.transaction, vout: Number(payload.vout), coinbase: payload.coinbase, merkle_proof: payload.merkle_proof } });
    }
    if (process.env.TIME_MARKET_REGTEST_EXPORT) {
      const headers = []; for (let height = 1; height <= 103; height++) headers.push(await rpc.header(await rpc.hashAt(height)));
      await writeFile(process.env.TIME_MARKET_REGTEST_EXPORT, JSON.stringify({ note: 'Written by client-v4/market-services-regtest.test.mjs from a Bitcoin Core regtest of one run: the headers above the genesis block, and the proofs the prover made.', now_secs: (await core.rpc('getblockheader', [info.bestblockhash, true])).time + 7200, headers, payments: scenario }, null, 1));
    }

    // ---- a reorganisation on the real node: the block of the payments is left, and the relay follows
    await core.rpc('invalidateblock', [paidIn]);
    // Mined to another address: a block with the same coinbase and the same second would be the block just left.
    const fresh = await core.mine(3, { address: await core.rpc('getnewaddress', ['', 'bech32'], wallet) }), stale = await rpc.headerInfo(paidIn);
    assert.deepEqual([stale.onBestChain, stale.height], [false, 102], 'Bitcoin Core keeps the block it left, and says it is on no chain');
    await relay.round();
    assert.equal(chain.bestTip, fresh[2]);
    assert.equal(chain.bestHeight, 104);
    assert.deepEqual(relayLog.said(/reorganisation/).map((line) => [line.fork_height, line.depth, line.new_height]), [[101, 2, 104]]);
    assert.equal(relay.health().ok, true);
  } finally {
    await core.stop();
    await rm(core.datadir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
});
