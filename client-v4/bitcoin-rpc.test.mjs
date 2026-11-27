// The client of Bitcoin Core's RPC (bitcoin-rpc.mjs), against a node that exists in the test only
// (market-test-kit.mjs) and against the engine's own blocks (spec/market-vectors.json).
import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { BitcoinRpcError, CORE_CHAINS, METHODS, createBitcoinNodes, createBitcoinRpc, headerFields, headerHash, nodeLogin, paymentsIn, readBlock } from './bitcoin-rpc.mjs';
import { merkleProofMatches, proofPayload, stripWitness, transactionId, transactionOutputs } from './bitcoin-address.mjs';
import { createFakeBitcoin, makePayment, vectorBlock } from './market-test-kit.mjs';

const vectors = JSON.parse(await readFile(new URL('../spec/market-vectors.json', import.meta.url), 'utf8'));
const proofs = vectors.actions.filter((action) => action.kind === 54);
const SCRIPT = `0014${'5a'.repeat(20)}`, OTHER = `5120${'6b'.repeat(32)}`, PASSWORD = '__cookie__:c0ffee-not-a-real-one';
const client = (node, options = {}) => createBitcoinRpc({ url: 'http://127.0.0.1:18443/', login: async () => node.password, fetcher: node.fetcher, timeoutMs: 200, ...options });
const refused = (code, pattern) => (error) => error instanceof BitcoinRpcError && error.code === code && (!pattern || pattern.test(error.message));
const blockHex = (header, transactions) => header + (transactions.length < 0xfd ? transactions.length.toString(16).padStart(2, '0') : '') + transactions.join('');

test('a block of the engine\'s own is read as the engine proved it: ids, the coinbase first, witness data removed', async () => {
  for (const action of proofs) {
    const made = vectorBlock(action), block = readBlock(blockHex(made.header, made.transactions));
    assert.equal(block.hash, action.payload.block_hash);
    assert.equal(block.transactions.length, 2);
    // What the engine's Merkle proof holds for this block, in the block's order, as the bytes stand.
    const matched = await merkleProofMatches(action.payload.merkle_proof, block.hash);
    assert.deepEqual(block.transactions.map((transaction) => Buffer.from(transaction.txid, 'hex').reverse().toString('hex')), matched.map((match) => match.hash));
    assert.deepEqual(matched.map((match) => match.place), [0, 1]);
    // The proof carries each transaction without its witness data; the node gave them with it.
    assert.equal(stripWitness(block.transactions[0].hex), action.payload.coinbase);
    assert.equal(stripWitness(block.transactions[1].hex), action.payload.transaction);
    assert.notEqual(block.transactions[1].hex, action.payload.transaction);
    assert.equal(block.transactions[1].bareBytes, action.payload.transaction.length / 2);
    assert.equal(block.transactions[1].txid, await transactionId(action.payload.transaction));
    // The output the proof names is found by its script, with its value read from the bytes.
    const script = transactionOutputs(action.payload.transaction)[Number(action.payload.vout)].script;
    const found = paymentsIn(block, new Set([script]));
    assert.deepEqual(found.map((payment) => [payment.txid, payment.vout, payment.index]), [[block.transactions[1].txid, Number(action.payload.vout), 1]]);
    assert.equal(found[0].sats, transactionOutputs(action.payload.transaction)[Number(action.payload.vout)].sats);
  }
  // The first of the two is the payment of a part: the engine counted the 4,000 satoshis this reads.
  const part = vectorBlock(proofs[0]);
  assert.equal(paymentsIn(readBlock(blockHex(part.header, part.transactions)), new Set([transactionOutputs(proofs[0].payload.transaction)[0].script]))[0].sats, proofs[0].fill.paid_sats);
});

test('every call gives what Bitcoin Core gives, held to what was asked: hashes as printed, headers, blocks, transactions, proofs', async () => {
  const bitcoin = createFakeBitcoin(), node = bitcoin.node();
  bitcoin.mineMany(3);
  const payment = makePayment([{ sats: 1, script: OTHER }, { sats: 2099999999999999n, script: SCRIPT }]), other = makePayment([{ sats: 700, script: OTHER }], { witness: false });
  const block = bitcoin.mine([other, payment]);
  bitcoin.mineMany(2);
  const rpc = client(node), info = await rpc.chainInfo();
  assert.deepEqual(info, { chain: 'regtest', blocks: 6, bestHash: bitcoin.best.hash, work: 14n, initialDownload: false });
  assert.equal(await rpc.bestHash(), bitcoin.best.hash);
  assert.equal(await rpc.hashAt(4), block.hash);
  assert.equal(await rpc.hashAt(7), null, 'a height above the node\'s chain is "not that high", not a failure');
  const header = await rpc.header(block.hash);
  assert.equal(header.length, 160);
  assert.equal(headerHash(header), block.hash);
  assert.equal(headerFields(header).previous, bitcoin.at(3).hash, 'the parent\'s hash is read from the header in the order Bitcoin software prints it');
  assert.deepEqual(await rpc.headerInfo(block.hash), { hash: block.hash, height: 4, onBestChain: true, previous: bitcoin.at(3).hash, time: block.time });
  assert.equal(await rpc.headerInfo('ab'.repeat(32)), null);
  assert.equal((await rpc.headerInfo(bitcoin.at(0).hash)).previous, null);
  const read = await rpc.block(block.hash);
  assert.equal(read.hash, block.hash);
  assert.deepEqual(read.transactions.map((transaction) => transaction.hex), block.transactions);
  assert.equal(read.transactions[2].txid, await transactionId(payment));
  // An amount that a decimal number of bitcoin cannot carry is read to the satoshi, as a string.
  assert.deepEqual(paymentsIn(read, new Set([SCRIPT])), [{ txid: read.transactions[2].txid, vout: 1, sats: '2099999999999999', script: SCRIPT, index: 2, bareBytes: stripWitness(payment).length / 2 }]);
  assert.deepEqual(paymentsIn(read, new Set([OTHER])).map((found) => [found.index, found.vout, found.sats]), [[1, 0, '700'], [2, 0, '1']]);
  assert.deepEqual(paymentsIn(read, new Set()), []);
  assert.equal(await rpc.rawTransaction(read.transactions[2].txid, block.hash), payment);
  const merkle = await rpc.txOutProof([read.transactions[0].txid, read.transactions[2].txid], block.hash);
  // Exactly two matches, the coinbase at the first place: what a proof of payment is made of.
  assert.deepEqual((await merkleProofMatches(merkle, block.hash)).map((match) => match.place), [0, 2]);
  const payload = await proofPayload({ fill: '7', script: SCRIPT, blockHash: block.hash, transaction: payment, coinbase: read.transactions[0].hex, merkleProof: merkle });
  assert.deepEqual(payload, { block_hash: block.hash, coinbase: stripWitness(read.transactions[0].hex), fill: '7', merkle_proof: merkle, transaction: stripWitness(payment), vout: '1' });
  assert.notEqual(payload.coinbase, read.transactions[0].hex, 'the node gave the coinbase with its witness data');
  // Nothing but the read calls is ever sent, with no redirect followed.
  assert.deepEqual(Object.keys(node.calls).sort(), [...METHODS].sort());
  assert.equal(node.lastRequest.redirect, 'error');
  assert.deepEqual(CORE_CHAINS, { mainnet: 'main', testnet3: 'test', regtest: 'regtest' });
});

test('a node that is silent, slow, or answers something else is a failure with a reason, never an answer', async () => {
  const bitcoin = createFakeBitcoin(), node = bitcoin.node({ password: PASSWORD });
  const block = bitcoin.mine([makePayment([{ sats: 5000, script: SCRIPT }])]);
  const rpc = client(node), txid = (await rpc.block(block.hash)).transactions[1].txid;
  const seen = [];
  const failing = async (code, pattern, work) => { await assert.rejects(work, (error) => { seen.push(error.message, String(error.stack)); return refused(code, pattern)(error); }); };
  node.fault = 'silent';
  await failing('UNAVAILABLE', /could not be reached \(ECONNREFUSED\)$/, rpc.chainInfo());
  node.fault = 'slow';
  await failing('UNAVAILABLE', /did not answer in time/, rpc.block(block.hash));
  node.fault = 'garbage';
  await failing('UNAVAILABLE', /HTTP 200 without a result/, rpc.bestHash());
  // Answers of the right form for something else: another header, another block, another transaction.
  node.fault = 'wrong';
  await failing('INVALID', /header of the block asked for/, rpc.header(block.hash));
  await failing('INVALID', /place of the block asked for/, rpc.headerInfo(block.hash));
  await failing('INVALID', null, rpc.block(block.hash));
  await failing('INVALID', null, rpc.rawTransaction(txid, block.hash));
  node.fault = { withhold: block.hash };
  await failing('REFUSED', /Block not available/, rpc.block(block.hash));
  node.fault = null;
  await failing('REFUSED', /No such transaction/, rpc.rawTransaction('cd'.repeat(32), block.hash));
  // A wrong password is said as such, and no error of any kind holds the password or the address.
  await failing('UNAUTHORIZED', /refused the name and password/, client(node, { login: async () => 'someone:wrong-guess' }).chainInfo());
  for (const text of seen) { assert.doesNotMatch(text, /c0ffee|wrong-guess|__cookie__/); assert.doesNotMatch(text, /127\.0\.0\.1|18443/); }
  assert.equal(node.lastRequest.authorization, `Basic ${Buffer.from('someone:wrong-guess').toString('base64')}`, 'the password goes to the node, in the header, and nowhere else');
  // A method that is not one of the read calls is never sent.
  assert.equal(Object.keys(node.calls).every((method) => METHODS.includes(method)), true);
  // The address is an origin: no user name or password in it, no path.
  for (const url of ['http://user:secret@127.0.0.1:18443/', 'http://127.0.0.1:18443/wallet/x', 'ftp://127.0.0.1/', 'http://127.0.0.1:18443/?a=1']) assert.throws(() => createBitcoinRpc({ url, login: async () => '' }), /origin/);
});

test('a block whose transactions are not those of its header, or that is cut or padded, is refused', async () => {
  const bitcoin = createFakeBitcoin(), block = bitcoin.mine([makePayment([{ sats: 5000, script: SCRIPT }]), makePayment([{ sats: 6000, script: SCRIPT }])]);
  const whole = blockHex(block.header, block.transactions);
  assert.equal(readBlock(whole).transactions.length, 3);
  // A node that swaps a payment for one it invented: the Merkle root of the header says so.
  const invented = blockHex(block.header, [block.transactions[0], makePayment([{ sats: 9000000, script: SCRIPT }]), block.transactions[2]]);
  assert.throws(() => readBlock(invented), refused('INVALID', /not those of the block header/));
  assert.throws(() => readBlock(blockHex(block.header, block.transactions.slice(0, 2))), refused('INVALID'));
  assert.throws(() => readBlock(whole.slice(0, -2)), refused('INVALID'));
  assert.throws(() => readBlock(`${whole}00`), refused('INVALID'));
  assert.throws(() => readBlock(whole.toUpperCase()), refused('INVALID'));
  assert.throws(() => readBlock(`${block.header}fdffff`), refused('INVALID'), 'a count of transactions that cannot fit is refused before anything is read');
  // An answer larger than a block can be is dropped unread.
  const node = bitcoin.node(), huge = { ...node, fetcher: async () => new Response(JSON.stringify({ result: 'ab'.repeat(5 * 1024 * 1024), error: null })) };
  await assert.rejects(client(huge).block(block.hash), refused('UNAVAILABLE', /size limit/));
  await assert.rejects(client({ ...node, fetcher: async () => new Response(JSON.stringify({ result: 'ab'.repeat(200 * 1024), error: null })) }).header(block.hash), refused('UNAVAILABLE', /size limit/));
});

test('the password of a node is read when a call is made: a cookie file, or a name with a password or its file', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-bitcoin-rpc-'));
  try {
    const cookie = path.join(directory, 'cookie'), secret = path.join(directory, 'rpc-password');
    await writeFile(cookie, '__cookie__:first\n', { mode: 0o640 });
    const login = nodeLogin({ cookieFile: cookie });
    assert.equal(await login(), '__cookie__:first');
    // The node was restarted and wrote a new cookie: the next call finds it.
    await writeFile(cookie, '__cookie__:second');
    assert.equal(await login(), '__cookie__:second');
    await writeFile(secret, 'correct horse\n', { mode: 0o600 });
    assert.equal(await nodeLogin({ user: 'relay', passwordFile: secret })(), 'relay:correct horse');
    assert.equal(await nodeLogin({ user: 'relay', password: 'in the config' })(), 'relay:in the config');
    await assert.rejects(nodeLogin({ cookieFile: path.join(directory, 'absent') })(), (error) => refused('UNAUTHORIZED', /could not be read/)(error) && !error.message.includes(directory));
    if (process.platform !== 'win32') {
      await chmod(secret, 0o640);
      await assert.rejects(nodeLogin({ user: 'relay', passwordFile: secret })(), refused('UNAUTHORIZED', /read by other users/));
      await chmod(cookie, 0o644);
      await assert.rejects(login(), refused('UNAUTHORIZED', /read by other users/));
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('several nodes are one source: each says where it stands, and one that fails is passed over', async () => {
  const bitcoin = createFakeBitcoin(), mainnet = createFakeBitcoin({ network: 'mainnet' });
  bitcoin.mineMany(5);
  const good = bitcoin.node(), late = bitcoin.node({ lag: 2 }), dead = bitcoin.node(), foreign = mainnet.node();
  dead.fault = 'silent';
  const nodes = createBitcoinNodes([{ name: 'dead', rpc: client(dead) }, { name: 'late', rpc: client(late) }, { name: 'good', rpc: client(good) }, { name: 'foreign', rpc: client(foreign) }]);
  const views = await nodes.look('regtest');
  assert.deepEqual(views.map((view) => [view.name, view.ok, view.height ?? null]), [['dead', false, null], ['late', true, 3], ['good', true, 5], ['foreign', false, null]]);
  assert.match(views[0].problem, /^UNAVAILABLE: /);
  assert.match(views[3].problem, /another Bitcoin network \(main\)/);
  assert.equal(views[2].bestHash, bitcoin.best.hash);
  assert.equal(views[2].time, bitcoin.best.time);
  assert.equal(views[2].work > views[1].work, true);
  // The newest block: the dead node fails, the late one does not know it, the good one gives it.
  const block = await nodes.first(views.filter((view) => view.name !== 'foreign'), (rpc) => rpc.block(bitcoin.best.hash));
  assert.equal(block.hash, bitcoin.best.hash);
  await assert.rejects(nodes.first([views[0]], (rpc) => rpc.bestHash()), refused('UNAVAILABLE'));
  await assert.rejects(nodes.first([], (rpc) => rpc.bestHash()), refused('UNAVAILABLE', /No Bitcoin node is usable/));
  assert.throws(() => createBitcoinNodes([{ name: 'a', rpc: client(good) }, { name: 'a', rpc: client(late) }]), /same name/);
});
