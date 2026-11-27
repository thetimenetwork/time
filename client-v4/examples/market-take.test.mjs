// The JavaScript example of a take (market-take.mjs), against the engine's own proven rows
// (verifier-v4/fixtures/market-engine.json: the state `trading` of client-v4/market-proofs.test.mjs), read through
// the installed verifier. What is held here: the dry run signs and sends nothing and says the payload the engine
// accepted; what to pay is read from a PROVEN fill; a gateway that changes one byte of that fill gets no payment
// out of the script; and the key the acting path would use signs the engine's take, byte for byte.
// Not run here: the acting path itself (the submission and the receipt), which needs a gateway and a chain.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import '../time-sdk.js';
import * as installed from '../proof-verifier.mjs';
import { scriptToAddress } from '../bitcoin-address.mjs';
import { main, keyFromEnvironment, bitcoinAmount, Refusal } from './market-take.mjs';

const SDK = globalThis.TimeSDK;
const wrapped = JSON.parse(await readFile(new URL('../../verifier-v4/fixtures/market-engine.json', import.meta.url), 'utf8'));
const vectors = JSON.parse(await readFile(new URL('../../spec/market-vectors.json', import.meta.url), 'utf8'));
const item = wrapped.cases.trading, vector = Object.fromEntries(vectors.actions.map((entry) => [entry.name, entry]));
const hex = (text) => Buffer.from(text).toString('hex');
// The fixture is of one moment: the verifier is given that moment as its clock, as in market-proofs.test.mjs.
const verifier = { verifyTrust: (trust) => installed.verifyTrust(trust, item.now_ms), verifyLightUpdate: (block, trust) => installed.verifyLightUpdate(block, trust, item.now_ms),
  verifyViewProof: (proof, trust, request) => installed.verifyViewProof(proof, trust, request, item.now_ms) };

/// One run of the command against a gateway that serves `proof` for every read. Returns the exit code, what was
/// written and what the gateway was asked.
async function run(argv, { proof = item.proof, environment = {} } = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'market-take-')), asked = [], written = [];
  const fetcher = async (url, options = {}) => {
    const { pathname } = new URL(url);
    asked.push(`${options.method ?? 'GET'} ${pathname}`);
    const answer = pathname === '/api/network' ? { protocolVersion: '4', networkId: item.trust.network_id, chainId: item.trust.chain_id } : pathname === '/api/view-proof' ? proof : { error: 'unexpected request' };
    return { ok: !answer.error, text: async () => JSON.stringify(answer) };
  };
  try {
    await writeFile(path.join(directory, 'trust.json'), JSON.stringify(item.trust));
    Object.assign(process.env, environment);
    const code = await main([...argv, '--gateway', 'https://gateway.example', '--trust', path.join(directory, 'trust.json'), '--bitcoin-network', 'regtest'], { write: (line) => written.push(line), verifier, fetcher });
    return { code, text: written.join('\n'), asked };
  } finally { for (const name of Object.keys(environment)) delete process.env[name]; await rm(directory, { recursive: true, force: true }); }
}

test('pay: what to pay is read from the proven fill, and only its payer is told to pay', async () => {
  const fill = item.market.fills['2'];
  const paid = await run(['pay', '--account', wrapped.accounts.buyer, '--fill', '2']);
  assert.equal(paid.code, 0, paid.text);
  assert.equal(bitcoinAmount(fill.sats), '0.00003000');
  assert.match(paid.text, new RegExp(`PAY ${fill.sats} satoshis \\(0\\.00003000 BTC\\) to ${await scriptToAddress(wrapped.scripts.serving, 'regtest')}\\n`));
  // start_height 5, 6 blocks to pay, 2 confirmations: the last height is 12 (SDK.marketFillLastHeight).
  assert.equal(SDK.marketFillLastHeight(fill), '12');
  assert.match(paid.text, new RegExp(`Confirmations asked: 2, reached by Bitcoin height 12 at the latest; the chain knows height ${item.bitcoin_best_height} now`));
  assert.match(paid.text, /Fill 2 \(proven\): 12 s for account 6/);
  assert.match(paid.text, /A part counts if it is at least 1000 satoshis/);
  assert.match(paid.text, /prove\.mjs CONFIG --fill 2/);
  assert.match(paid.text, /IF YOU HAVE PAID ALREADY, DO NOT PAY AGAIN/);
  assert.ok(paid.asked.every((request) => request.startsWith('GET ')), 'it only reads');
  // A fill against a buy order: its payer is the order's owner.
  const other = await run(['pay', '--account', wrapped.accounts.other, '--fill', '3']);
  assert.match(other.text, new RegExp(`PAY 2500 satoshis \\(0\\.00002500 BTC\\) to ${await scriptToAddress(wrapped.scripts.of_a_fill_against_a_buy_order, 'regtest')}`));
  // Somebody else's fill, a fill that has ended, a network that is not the chain's: nothing to pay.
  for (const [argv, words] of [[['pay', '--account', wrapped.accounts.seller, '--fill', '2'], /REFUSED: Fill 2 is not paid by account 5/], [['pay', '--account', wrapped.accounts.buyer, '--fill', '1'], /REFUSED: Fill 1 is proven absent[^\n]*PAY NOTHING/]]) {
    const refused = await run(argv);
    assert.equal(refused.code, 2);
    assert.match(refused.text, words);
    assert.doesNotMatch(refused.text, /PAY \d/);
  }
});

test('pay: a gateway that changes the fill it serves gets no payment out of the script', async () => {
  // The same answer with another receiving script in the row of fill 2: what a lying server would send to be paid itself.
  const key = hex('market/fill/') + (2n).toString(16).padStart(16, '0');
  const proof = JSON.parse(JSON.stringify(item.proof)), entry = proof.entries.find((candidate) => candidate.key_hex === key);
  assert.ok(entry, 'the fixture proves fill 2');
  const row = JSON.parse(Buffer.from(entry.value_b64, 'base64').toString('utf8'));
  assert.equal(row.script, wrapped.scripts.serving);
  entry.value_b64 = Buffer.from(JSON.stringify({ ...row, script: wrapped.scripts.unknown })).toString('base64');
  const lied = await run(['pay', '--account', wrapped.accounts.buyer, '--fill', '2'], { proof });
  assert.equal(lied.code, 1, lied.text);
  assert.match(lied.text, /^STOPPED: /);
  assert.doesNotMatch(lied.text, /PAY \d|bcrt1/);
  // Less to pay than the chain says, for the same address: refused the same way.
  entry.value_b64 = Buffer.from(JSON.stringify({ ...row, sats: '1' })).toString('base64');
  assert.equal((await run(['pay', '--account', wrapped.accounts.buyer, '--fill', '2'], { proof })).code, 1);
});

test('take: the dry run is the default, reads the proven order, and says the payload the engine accepted', async () => {
  const order = item.market.orders['1'];
  const argv = ['take', '--account', wrapped.accounts.buyer, '--order', '1', '--amount-micros', '20000000'];
  const dry = await run([...argv, '--limit-price', order.price]);
  assert.equal(dry.code, 0, dry.text);
  assert.ok(dry.text.includes(`kind 52, payload ${vector.take.payload_json}`), dry.text);
  assert.match(dry.text, /Order 1 of account 5 \(proven\): 20 s cost 5000 satoshis \(0\.00005000 BTC\)/);
  assert.match(dry.text, /A deposit of 1 s is locked/);
  assert.match(dry.text, /DRY RUN: nothing was signed and nothing was sent/);
  assert.ok(dry.text.includes(`first free address: ${await scriptToAddress(wrapped.scripts.listed, 'regtest')}`));
  assert.deepEqual([...new Set(dry.asked)].sort(), ['GET /api/network', 'GET /api/view-proof'], 'nothing was submitted');
  // The refusals, each before anything is signed.
  for (const [more, words] of [
    [['--limit-price', (BigInt(order.price) - 1n).toString()], /REFUSED: Order 1 asks 250000000, above your limit of 249999999: nothing is taken/],
    [['--limit-price', order.price, '--act'], /REFUSED: --key-env names an environment variable/],
    [['--limit-price', order.price, '--act', '--dry-run'], /REFUSED: Usage/],
  ]) {
    const refused = await run([...argv, ...more]);
    assert.equal(refused.code, 2, refused.text);
    assert.match(refused.text, words);
    assert.ok(!refused.asked.some((request) => request.startsWith('POST')));
  }
  assert.match((await run(['take', '--account', wrapped.accounts.seller, '--order', '1', '--amount-micros', '20000000', '--limit-price', order.price])).text, /REFUSED: Order 1 is not an open sell order of somebody else/);
  assert.match((await run(['take', '--account', wrapped.accounts.buyer, '--order', '3', '--amount-micros', '20000000', '--limit-price', order.price])).text, /REFUSED: Order 3 is proven absent/);
  assert.match((await run(['take', '--account', wrapped.accounts.buyer, '--order', '2', '--amount-micros', '20000000', '--limit-price', order.price])).text, /REFUSED: Order 2 is not an open sell order/);
  // To act it wants the two ceilings as well as the key; with them missing nothing is read of the account and nothing is signed.
  const noCeilings = await run([...argv, '--limit-price', order.price, '--act', '--key-env', 'MARKET_TAKE_TEST_KEY'], { environment: { MARKET_TAKE_TEST_KEY: vector.take.seed_hex } });
  assert.equal(noCeilings.code, 2, noCeilings.text);
  assert.match(noCeilings.text, /REFUSED: To act, give --key-env, --max-balance-micros and --max-daily-limit-micros/);
  assert.ok(!noCeilings.text.includes(vector.take.seed_hex));
});

test('the key comes from a named environment variable, leaves it, and signs the engine\'s take byte for byte', async () => {
  const entry = vector.take;
  process.env.MARKET_TAKE_TEST_KEY = entry.seed_hex;
  const key = await keyFromEnvironment('MARKET_TAKE_TEST_KEY');
  assert.equal(process.env.MARKET_TAKE_TEST_KEY, undefined, 'the variable is removed once it is read');
  assert.equal(key.publicKey, entry.public_key);
  assert.equal(key.privateKey.extractable, false);
  const payload = SDK.marketTake({ order: '1', amountMicros: '20000000', price: '250000000', to: '6' });
  const signed = await SDK.signAction({ networkId: vectors.network_id, kind: SDK.MARKET_KINDS.take, from: entry.from, nonce: entry.nonce, authEpoch: entry.auth_epoch, publicKey: key.publicKey, payload }, key.privateKey);
  assert.equal(Buffer.from(signed).toString('hex'), entry.signed_hex);
  // A variable that is not set, or that holds something else: a refusal that does not repeat what it held.
  await assert.rejects(keyFromEnvironment('MARKET_TAKE_TEST_NOT_SET'), Refusal);
  process.env.MARKET_TAKE_TEST_KEY = 'correct horse battery staple';
  await assert.rejects(keyFromEnvironment('MARKET_TAKE_TEST_KEY'), (error) => error instanceof Refusal && !/horse/.test(error.message));
  assert.equal(process.env.MARKET_TAKE_TEST_KEY, undefined);
});
