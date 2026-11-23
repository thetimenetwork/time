// The explorer's own checks (check.mjs) with the installed WebAssembly verifier, the SDK's light
// client and real signed material: the fixtures of verifier-v4, served by the real API service
// over a fake node (as client-v4/api.test.mjs does) or by a stand-in for the API.
// What passes here passes in a browser only if the browser loads the same verifier: see README.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import '../../client-v4/time-sdk.js';
import * as verifier from '../../client-v4/proof-verifier.mjs';
import { createLightClient } from '../../client-v4/light-client.mjs';
import { createApiService } from '../../client-v4/api.mjs';
import { IndexerError } from '../../client-v4/indexer.mjs';
import { createApi, ApiFailure } from './client.mjs';
import { createChecker, CheckFailure, readEnvelope } from './check.mjs';

const SDK = globalThis.TimeSDK;
const fixtures = new URL('../../verifier-v4/fixtures/', import.meta.url);
const chain = JSON.parse(await readFile(new URL('fast-receipt.json', fixtures), 'utf8'));
const proven = JSON.parse(await readFile(new URL('proof.json', fixtures), 'utf8'));
const sha = (bytes) => createHash('sha256').update(bytes).digest();
const hashOf = (height, index) => sha(Buffer.from(chain.txs[height][index], 'base64')).toString('hex').toUpperCase();
const clone = (value) => JSON.parse(JSON.stringify(value));
const failsWith = (reason) => (error) => { assert(error instanceof CheckFailure, `a CheckFailure, not ${error}`); assert.equal(error.reason, reason, String(error.detail?.message ?? error.detail)); return true; };

/// The real API service over a node that serves the four signed blocks of fast-receipt.json.
/// Its state has no history of blocks, as on a chain whose newest blocks are asked for.
async function lab(run, { tip = 4 } = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-explorer-check-'));
  const block = (h) => { const b = chain.blocks[Number(h) - 1]; if (!b || Number(h) > tip) throw new IndexerError('RPC_REFUSED', 'height is not available'); return b; };
  const rpc = async (method, parameters = {}) => {
    if (method === '/status') return { node_info: { network: chain.trust.chain_id }, sync_info: { latest_block_height: String(tip) } };
    if (method === '/block') return { block: { header: block(parameters.height).signed_header.header, data: { txs: chain.txs[parameters.height] } } };
    if (method === '/blockchain') { const metas = []; for (let h = Number(parameters.maxHeight); h >= Number(parameters.minHeight); h--) metas.push({ header: block(h).signed_header.header }); return { block_metas: metas }; }
    if (method === '/commit') return { signed_header: block(parameters.height ?? tip).signed_header };
    if (method === '/validators') { const h = Number(parameters.height); if (h > tip + 1) throw new IndexerError('RPC_REFUSED', 'height is not available'); return { block_height: parameters.height, total: '4', validators: h <= chain.blocks.length ? chain.blocks[h - 1].validators : chain.blocks.at(-1).next_validators }; }
    throw new IndexerError('RPC_REFUSED', 'not available on this node');
  };
  const service = await createApiService({ trust: chain.trust, rpc, verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false, pollMs: 5, now: () => chain.now_ms, rateLimit: { perSecond: 1000, burst: 100000 },
    readState: async (selection) => ({ verified: true, requested: selection, proof: { height: '3', entries: [] }, state: { network_id: chain.trust.network_id, height: '3', time_micros: '1000003000000', accounts: [], config: {} } }) });
  try {
    for (let i = 0; i < 50 && (service.store.high() ?? 0) < tip; i++) await service.indexer.step();
    await run({ service, api: createApi({ origin: service.url }) });
  } finally { await service.close(); await rm(directory, { recursive: true, force: true }); }
}
const checkerOf = (api, { trust = chain.trust, now = chain.now_ms, loadVerifier = async () => verifier } = {}) => createChecker({ api, loadTrust: async () => trust, loadVerifier, createLightClient, sdk: SDK, now: () => now });

test('an action in a new block is checked against the block\'s own signed header, from the page\'s trust anchor', async () => {
  await lab(async ({ api }) => {
    const checker = checkerOf(api);
    // Block 2 holds two transfers; block 3 follows it, so its header confirms their results.
    const first = await checker.checkAction(hashOf('2', 0));
    assert.deepEqual([first.hash, first.height, first.index, first.mode, first.resultsChecked, first.anchorHeight], [hashOf('2', 0), '2', 0, 'own-block', true, '3']);
    assert.deepEqual([first.action.kind, first.action.from, first.action.nonce, first.action.payload], [3, '7', '1', { to: '1', amount: '5' }]);
    // The frame of the bytes is read without the SDK, and the block's number of actions is fixed by the next block.
    assert.deepEqual([first.envelope, first.total], [{ kind: 3, sender: '7', nonce: '1', authEpoch: first.action.authEpoch, publicKey: first.action.publicKey }, '2']);
    assert.equal(Buffer.from(first.rawHex, 'hex').toString('base64'), chain.txs['2'][0]);
    // The newest block has no successor: inclusion is checked, its results are not yet.
    const newest = await checker.checkAction(hashOf('4', 0));
    assert.deepEqual([newest.height, newest.mode, newest.resultsChecked, newest.anchorHeight], ['4', 'own-block', false, '4']);
    // Without the next block nothing fixes how many actions the block has, and the same proof fits
    // more than one position: the check then gives no position at all.
    assert.deepEqual([newest.index, newest.total], [null, null]);
    // A lower-case hash is the same action.
    assert.equal((await checkerOf(api).checkAction(hashOf('2', 1).toLowerCase())).index, 1);
  });
});

test('a tampered answer does not pass: other bytes, another proof, another block, another network', async () => {
  await lab(async ({ api }) => {
    const hash = hashOf('2', 0), other = await api.action(hashOf('2', 1));
    const forged = (change) => checkerOf({ ...api, action: async (wanted) => { const answer = clone(await api.action(wanted)); change(answer); return answer; } }).checkAction(hash);
    // The untouched answer passes through the same wrapper: the refusals below come from the changes alone.
    assert.equal((await forged(() => {})).height, '2');
    const forgeries = {
      'the bytes of another action': (a) => { a.action.raw = other.action.raw; },
      'the whole proof of another action': (a) => { a.action = other.action; a.verify = other.verify; },
      'one changed byte': (a) => { const raw = Buffer.from(a.action.raw, 'base64'); raw[raw.length - 70] ^= 1; a.action.raw = raw.toString('base64'); },
      'a changed Merkle path': (a) => { a.verify.aunts = [Buffer.alloc(32, 7).toString('base64')]; },
      'another position in the block': (a) => { a.verify.index = 1; },
      'another block': (a) => { a.verify.height = '3'; },
      'no proof material': (a) => { delete a.verify; },
      'decoded fields that lie': (a) => { a.action.amount = '5000000'; a.action.recipient = '9'; }, // passes the check of the bytes; see below
    };
    for (const [name, change] of Object.entries(forgeries)) {
      if (name === 'decoded fields that lie') {
        // The check proves the bytes, and returns what the bytes say: the lie is not in its result.
        const result = await forged(change);
        assert.deepEqual(result.action.payload, { to: '1', amount: '5' }, name);
        continue;
      }
      await assert.rejects(forged(change), failsWith('refused'), name);
    }
    // A header that the validators did not sign.
    const badHeader = { ...api, lightBlock: async (h) => { const answer = clone(await api.lightBlock(h)); answer.light_block.signed_header.header.app_hash = '11'.repeat(32).toUpperCase(); return answer; } };
    await assert.rejects(checkerOf(badHeader).checkAction(hash), failsWith('refused'));
    // A page installed for another network, or with a trust anchor that has expired, checks nothing.
    await assert.rejects(checkerOf(api, { trust: { ...chain.trust, network_id: 'cd'.repeat(32) } }).checkAction(hash), failsWith('refused'));
    await assert.rejects(checkerOf(api, { now: chain.now_ms + 30 * 86400 * 1000 }).checkAction(hash), failsWith('trust_expired'));
    const told = checkerOf(api); told.expectNetwork('ef'.repeat(32));
    await assert.rejects(told.checkAction(hash), failsWith('wrong_network'));
  });
});

test('what cannot be checked is said as that, not as a failed proof', async () => {
  await lab(async ({ api }) => {
    const hash = hashOf('2', 0);
    await assert.rejects(checkerOf(api, { trust: null }).checkAction(hash), failsWith('no_trust'));
    await assert.rejects(checkerOf(api, { trust: { app_version: '4', network_id: 'xyz', chain_id: 'c' } }).checkAction(hash), failsWith('no_trust'));
    await assert.rejects(checkerOf(api, { loadVerifier: async () => { throw new Error('blocked'); } }).checkAction(hash), failsWith('no_verifier'));
    await assert.rejects(checkerOf(api, { loadVerifier: async () => ({ verifyViewProof() {} }) }).checkAction(hash), failsWith('no_verifier'));
    // The service is down, limits the page, or does not know the action.
    for (const status of [429, 503, 404]) {
      const down = { ...api, action: async () => { throw new ApiFailure('http', { status, code: 'x' }); } };
      await assert.rejects(checkerOf(down).checkAction(hash), (error) => failsWith('unavailable')(error) && error.detail.status === status);
    }
    await assert.rejects(checkerOf({ ...api, lightBlock: async () => { throw new ApiFailure('network'); } }).checkAction(hash), failsWith('unavailable'));
    await assert.rejects(checkerOf(api).checkAction('not a hash'), failsWith('refused'));
    // A verifier that fails to load once is loaded again at the next check.
    let loads = 0;
    const flaky = checkerOf(api, { loadVerifier: async () => { if (loads++ === 0) throw new Error('offline'); return verifier; } });
    await assert.rejects(flaky.checkAction(hash), failsWith('no_verifier'));
    assert.equal((await flaky.checkAction(hash)).height, '2');
  });
});

// ------------------------------------------------------------------ through the history of the state
/// A stand-in for the API that answers with the receipt and the state of proof.json.
function historyApi(change = () => {}) {
  const receipt = clone(proven.receipt), tx = receipt.tx;
  const hash = sha(Buffer.from(tx.tx, 'base64')).toString('hex').toUpperCase();
  const answers = {
    action: { action: { raw: tx.tx }, verify: { hash, height: String(tx.height), index: Number(tx.index), total: String(tx.proof.proof.total), root_hash: tx.proof.root_hash, leaf_hash: tx.proof.proof.leaf_hash, aunts: tx.proof.proof.aunts } },
    blockProof: { proof: { view_proof: receipt.anchor }, signed_header: receipt.signed_header, next_signed_header: receipt.next_signed_header },
  };
  change(answers);
  return { hash, api: { action: async () => clone(answers.action), blockProof: async () => clone(answers.blockProof), lightBlock: async () => { throw new ApiFailure('http', { status: 404, code: 'not_found' }); } } };
}
const provenChecker = (api) => checkerOf(api, { trust: proven.trust, now: proven.now_ms });

test('an older action is checked through the history of block hashes in the proven state', async () => {
  const { hash, api } = historyApi();
  const result = await provenChecker(api).checkAction(hash);
  assert.deepEqual([result.hash, result.mode, result.resultsChecked, result.height], [hash, 'history', true, String(proven.receipt.tx.height)]);
  assert.equal(result.blockHash.length, 64);
  assert.equal(Buffer.from(result.rawHex, 'hex').toString('base64'), proven.receipt.tx.tx);
  const forgeries = {
    'a changed history row': (a) => { const entry = a.blockProof.proof.view_proof.entries[0]; entry.value_b64 = Buffer.from('{"balance":"999"}').toString('base64'); },
    'a header of another block': (a) => { a.blockProof.signed_header = a.blockProof.next_signed_header; },
    'changed bytes': (a) => { const raw = Buffer.from(a.action.action.raw, 'base64'); raw[raw.length - 1] ^= 1; a.action.action.raw = raw.toString('base64'); },
    'a changed Merkle root': (a) => { a.action.verify.root_hash = 'AB'.repeat(32); },
    'no proof of the block': (a) => { a.blockProof.proof.view_proof = null; },
  };
  for (const [name, change] of Object.entries(forgeries)) {
    const forged = historyApi(change);
    await assert.rejects(provenChecker(forged.api).checkAction(forged.hash), failsWith('refused'), name);
  }
});

test('a state is checked for the question the page asks, and a tampered one is refused', async () => {
  const body = { account: { id: '0', name: 'alice', balance: '999999' }, proof: { query: { ids: ['31337'] }, view_proof: proven.proof } };
  const checker = provenChecker({});
  // The page passes its own question; the service's copy of it (`proof.query`) is not used.
  const result = await checker.checkState(async () => clone(body), proven.request);
  // What exists and what does not is in the verified result: the account, the number shown absent, each name with its number or null.
  assert.deepEqual([result.height, result.state.accounts.map((a) => [a.id, a.name, a.balance]), result.absent, result.names], ['5', [['0', 'alice', '0']], ['999'], { alice: '0', missing: null }]);
  // `found` is there for a page file of an earlier release (see check.mjs): it is true of every result and never repeats the status of the answer.
  assert.equal(result.found, true);
  // A proof made for one question does not answer another.
  await assert.rejects(provenChecker({}).checkState(async () => clone(body), { ids: ['0'], include_security: true }), failsWith('refused'));
  // One changed row.
  const forged = clone(body); forged.proof.view_proof.entries[0].value_b64 = Buffer.from('{"balance":"999"}').toString('base64');
  await assert.rejects(provenChecker({}).checkState(async () => forged, proven.request), failsWith('refused'));
  await assert.rejects(provenChecker({}).checkState(async () => ({ account: body.account }), proven.request), failsWith('refused'));
  // A 404 with a proof is checked too; one without a proof, or any other error, is "unavailable".
  const absent = await provenChecker({}).checkState(async () => { throw new ApiFailure('http', { status: 404, code: 'account_not_found', body: { proof: { view_proof: proven.proof } } }); }, proven.request);
  // The status decides nothing: this "404" carries a proof in which alice exists, and the result says so.
  assert.deepEqual([absent.state.accounts.map((a) => a.name), absent.absent, absent.names.alice, absent.found], [['alice'], ['999'], '0', true]);
  const other = await provenChecker({}).checkState(async () => { throw new ApiFailure('http', { status: 500, code: 'internal', body: { proof: { view_proof: proven.proof } } }); }, { names: ['missing'] });
  assert.deepEqual([other.state.accounts, other.names], [[], { missing: null }]);
  await assert.rejects(provenChecker({}).checkState(async () => { throw new ApiFailure('http', { status: 503, code: 'state_unavailable', retryAfter: 5 }); }, proven.request), failsWith('unavailable'));
  // What the page shows of its trust anchor.
  assert.deepEqual(await checker.trust(), { networkId: proven.trust.network_id, chainId: proven.trust.chain_id, genesisTimeMicros: proven.trust.genesis_time_micros, anchorHeight: proven.trust.checkpoint?.height ?? null, anchorHash: proven.trust.checkpoint?.block_hash?.toUpperCase() ?? null });
  assert.equal(await checkerOf({}, { trust: null }).trust(), null);
});

// ------------------------------------------------------------------ what decides the kind of a failure
test('the page\'s own trust is verified before the service is asked: an expired block or a wrong clock is found without any word of the service', async () => {
  const body = () => ({ proof: { view_proof: clone(proven.proof) } });
  const run = async (now) => { let asked = 0; const failure = await checkerOf({}, { trust: proven.trust, now }).checkState(async () => { asked += 1; return body(); }, { names: ['alice'] }).then(() => null, (error) => error); return [failure?.reason ?? 'checked', failure?.offered ?? null, asked]; };
  assert.deepEqual(await run(proven.now_ms), ['checked', null, 1]);
  // The trusted block is 30 days old: nothing is asked of the service, and nothing it could say is looked at.
  assert.deepEqual(await run(proven.now_ms + 30 * 86400 * 1000), ['trust_expired', false, 0]);
  // This device's clock is behind the chain's (the trusted block looks dated ahead): found the same way.
  assert.deepEqual(await run(proven.now_ms - 60000), ['clock', false, 0]);
  assert.deepEqual(await run(proven.now_ms - 15000), ['clock', false, 0]);
  // The clock is a minute ahead: the proof looks stale. It was offered and is not accepted, and it is not called a failed proof.
  assert.deepEqual(await run(proven.now_ms + 60000), ['clock', true, 1]);
  // A proof that does not verify is 'refused' whatever its error text contains: the kind of a failure is never read from text the service can shape.
  const forged = clone(proven.proof); forged.entries[2].value_b64 = Buffer.from(JSON.stringify({ id: '0', name: 'alice', balance: '3600000000000' })).toString('base64');
  for (const change of [(proof) => { proof.CHECKPOINT_REFRESH_REQUIRED = 1; }, (proof) => { proof.light_block.CHECKPOINT_REFRESH_REQUIRED = 1; }, (proof) => { proof.light_block['STALE_STATE: x'] = 1; }, (proof) => { proof.height = 'INVALID_CLOCK'; },
    (proof) => { proof.light_block.validators[0].pub_key = { type: 'CHECKPOINT_REFRESH_REQUIRED', value: proof.light_block.validators[0].pub_key.value }; }, (proof) => { proof.light_block.validators[0].name = 'STALE_STATE: fresh current authority proof is required'; }]) {
    const proof = clone(forged); change(proof);
    const failure = await provenChecker({}).checkState(async () => ({ proof: { view_proof: proof } }), { ids: ['0'] }).then(() => null, (error) => error);
    assert.deepEqual([failure.reason, failure.offered], ['refused', true], String(failure.detail).slice(0, 80));
  }
  // The network the service names is not the manifest's: nothing is asked, nothing shown.
  const told = provenChecker({}); told.expectNetwork('ef'.repeat(32));
  let asked = 0;
  await assert.rejects(told.checkState(async () => { asked += 1; return body(); }, { names: ['alice'] }), (error) => failsWith('wrong_network')(error) && error.offered === false && asked === 0);
  told.expectNetwork(proven.trust.network_id);
  assert.equal((await told.checkState(async () => body(), { names: ['alice'] })).height, '5');
});

test('a proof for an older block than the page has reached is asked for again after a pause, and is "behind", not a failed proof', async () => {
  const pauses = [];
  const checker = createChecker({ api: { lightBlock: async (h) => ({ light_block: chain.blocks[Number(h) - 1] }) }, loadTrust: async () => chain.trust, loadVerifier: async () => verifier, createLightClient, sdk: SDK, now: () => chain.now_ms, pause: async (ms) => { pauses.push(ms); }, pauseMs: 700 });
  // The page has followed the chain to block 4. (The state read itself fails afterwards, for another reason: the fixture's blocks are old and its proof is empty.)
  await assert.rejects(checker.checkState(async () => ({ proof: { view_proof: { height: '3', entries: [], light_block: chain.blocks[3] } } }), {}), (error) => error instanceof CheckFailure && error.reason !== 'behind');
  let asked = 0;
  await assert.rejects(checker.checkState(async () => { asked += 1; return { proof: { view_proof: { height: '2', entries: [], light_block: chain.blocks[2] } } }; }, {}), (error) => failsWith('behind')(error) && error.offered === true);
  assert.deepEqual([asked, pauses], [3, [700, 700]]);
  // A service that catches up between two tries is not held to its first answer.
  let round = 0;
  await assert.rejects(checker.checkState(async () => ({ proof: { view_proof: { height: '3', entries: [], light_block: chain.blocks[round++ === 0 ? 2 : 3] } } }), {}), (error) => error instanceof CheckFailure && error.reason !== 'behind');
  assert.deepEqual([round, pauses.length], [2, 3]);
});

test('a trust manifest that could not be loaded is asked for again; one that is not installed is not', async () => {
  let loads = 0;
  const flaky = createChecker({ api: {}, loadTrust: async () => { if (loads++ === 0) throw new Error('429'); return proven.trust; }, loadVerifier: async () => verifier, createLightClient, sdk: SDK, now: () => proven.now_ms });
  assert.equal(await flaky.trust(), null);
  assert.equal((await flaky.trust()).networkId, proven.trust.network_id);
  assert.equal((await flaky.checkState(async () => ({ proof: { view_proof: clone(proven.proof) } }), { names: ['alice'] })).height, '5');
  assert.equal(loads, 2);
  let asked = 0;
  const none = createChecker({ api: {}, loadTrust: async () => { asked += 1; return null; }, loadVerifier: async () => verifier, createLightClient, sdk: SDK });
  assert.equal(await none.trust(), null); assert.equal(await none.trust(), null);
  await assert.rejects(none.checkState(async () => ({}), {}), failsWith('no_trust'));
  assert.equal(asked, 1);
});

test('the frame of an action is read without the SDK, for the kinds the SDK does not read', () => {
  const bytes = SDK.concat(SDK.buildAction({ networkId: 'ab'.repeat(32), kind: 3, from: '7', nonce: '9', authEpoch: '2', publicKey: '11'.repeat(32), payload: { to: '5', amount: '5' } }), new Uint8Array(64));
  assert.deepEqual(readEnvelope(bytes), { networkId: 'ab'.repeat(32), kind: 3, sender: '7', nonce: '9', authEpoch: '2', publicKey: '11'.repeat(32) });
  const kindAt = new TextEncoder().encode('TCDEVNET-ACTION-V1\0').length + 32;
  for (const kind of [23, 63, 200]) {
    const copy = Uint8Array.from(bytes); copy[kindAt] = kind;
    assert.throws(() => SDK.decodeAction(copy), 'the SDK does not read this kind');
    assert.deepEqual(readEnvelope(copy), { networkId: 'ab'.repeat(32), kind, sender: '7', nonce: '9', authEpoch: '2', publicKey: '11'.repeat(32) });
  }
  // An action without a sender, and bytes that are not an action at all.
  assert.equal(readEnvelope(SDK.publicHeadersAction('ab'.repeat(32), [])).sender, null);
  for (const other of [bytes.subarray(0, bytes.length - 1), SDK.concat(bytes, Uint8Array.of(0)), new TextEncoder().encode('public fixture transaction'), new Uint8Array(0), null, 'text', Uint8Array.from(bytes, (byte, at) => (at === 0 ? 0 : byte))]) assert.equal(readEnvelope(other), null);
});

test('upgrade plans: asked with every read when the trust data says the network reports them, and never taken from silence', async () => {
  // verifier-v4/fixtures/upgrade.json: the same state with no upgrade row, with a scheduled plan, with a row in no known form, and under version 5.
  const upgrades = JSON.parse(await readFile(new URL('upgrade.json', fixtures), 'utf8')).views;
  const run = (view, trust, query = { names: ['alice'] }) => { const checker = checkerOf({}, { trust, now: view.now_ms }); return checker.checkState(async () => ({ proof: { view_proof: clone(view.proof) } }), query).then((result) => ({ checker, result }), (failure) => ({ checker, failure })); };
  const declared = (view) => ({ ...view.trust, nodes_report_upgrades: true });
  // The trust data does not say that the nodes report upgrades: the question is not asked, the checked state says nothing of upgrades, and reading a status from it is an error, not "no plan".
  const silent = await run(upgrades.plan, upgrades.plan.trust);
  assert.deepEqual([silent.checker.readsUpgrade, Object.hasOwn(silent.result.state, 'upgrade'), silent.result.state.accounts.map((account) => account.name)], [true, false, ['alice']]);
  assert.throws(() => silent.checker.upgradeStatus(silent.result.state), /without the upgrade entry/);
  // The trust data says so: every question carries that one, and the answer is proven either way.
  const none = await run(upgrades.absent, declared(upgrades.absent));
  assert.deepEqual([none.result.state.upgrade, none.checker.upgradeStatus(none.result.state).scheduled], [null, null]);
  const plan = await run(upgrades.plan, declared(upgrades.plan));
  assert.deepEqual([plan.checker.upgradeStatus(plan.result.state).scheduled.version, plan.result.state.accounts.map((account) => account.name)], ['5', ['alice']]);
  // A service that leaves the row out of its answer (here: the proof of a network without upgrade rows) is refused as a whole.
  const withheld = await run({ proof: proven.proof, now_ms: proven.now_ms }, { ...proven.trust, nodes_report_upgrades: true });
  assert.deepEqual([withheld.failure.reason, withheld.failure.offered], ['refused', true]);
  // A row in no known form is refused; a network under newer rules than this verifier implements is said to be that, and nothing of it is shown.
  assert.equal((await run(upgrades.malformed, declared(upgrades.malformed))).failure.reason, 'refused');
  const newer = await run(upgrades.version5, upgrades.version5.trust);
  assert.deepEqual([newer.failure.reason, newer.failure.offered], ['upgrade_required', true]);
  assert.match(newer.failure.detail, /^UPGRADE_REQUIRED: /);
  // An error that only carries those words (a forged field name) is not that: the mark is the verifier's own.
  const forged = clone(upgrades.plan.proof); forged['UPGRADE_REQUIRED: x'] = 1;
  assert.equal((await run({ proof: forged, now_ms: upgrades.plan.now_ms }, upgrades.plan.trust)).failure.reason, 'refused');
  // Trust data that says it in no accepted form is not a usable manifest.
  assert.equal((await run(upgrades.plan, { ...upgrades.plan.trust, nodes_report_upgrades: 'yes' })).failure.reason, 'no_trust');
  // An SDK from before upgrades asks nothing and reads nothing.
  const { upgradeStatusOf, nodesReportUpgrades, ...older } = SDK;
  const old = createChecker({ api: {}, loadTrust: async () => declared(upgrades.plan), loadVerifier: async () => verifier, createLightClient, sdk: older, now: () => upgrades.plan.now_ms });
  assert.equal(old.readsUpgrade, false);
  assert.equal(Object.hasOwn((await old.checkState(async () => ({ proof: { view_proof: clone(upgrades.plan.proof) } }), { names: ['alice'] })).state, 'upgrade'), false);
  assert.throws(() => old.upgradeStatus({}), /does not read upgrade plans/);
});

test('a verifier that does not run is found before the page\'s trust is judged with it, and is called that', async () => {
  // In a browser the module loads and the compiled verifier behind it only at its first call: that call failing.
  const refusing = Object.fromEntries(['verifyTrust', 'verifyLightUpdate', 'verifyViewProof', 'verifyReceipt', 'verifyFastReceipt'].map((name) => [name, async () => { throw new Error('WebAssembly.instantiate(): refused by the Content-Security-Policy'); }]));
  let asked = 0;
  const body = async () => { asked += 1; return { proof: { view_proof: clone(proven.proof) } }; };
  const failure = await checkerOf({}, { trust: proven.trust, now: proven.now_ms, loadVerifier: async () => refusing }).checkState(body, { names: ['alice'] }).then(() => null, (error) => error);
  assert.deepEqual([failure.reason, failure.offered, failure.detail, asked], ['no_verifier', false, 'WebAssembly.instantiate(): refused by the Content-Security-Policy', 0]);
  // One that answers anything else than its own refusal of a trust that is none does not count as running either.
  for (const answer of [async () => ({ ready: true }), async () => { throw new Error('CHECKPOINT_REFRESH_REQUIRED: x'); }, async () => { throw new Error('x INVALID_JSON: y'); }]) {
    const odd = await checkerOf({}, { trust: proven.trust, now: proven.now_ms, loadVerifier: async () => ({ ...verifier, verifyTrust: answer }) }).checkState(body, { names: ['alice'] }).then(() => null, (error) => error);
    assert.deepEqual([odd.reason, asked], ['no_verifier', 0]);
  }
  // It is tried again at the next check: a verifier that loads then is used.
  let loads = 0;
  const later = checkerOf({}, { trust: proven.trust, now: proven.now_ms, loadVerifier: async () => (loads++ === 0 ? refusing : verifier) });
  await assert.rejects(later.checkState(body, { names: ['alice'] }), failsWith('no_verifier'));
  assert.equal((await later.checkState(body, { names: ['alice'] })).height, '5');
});

test('a block the service cannot prove is "too new" only at the edge of the chain; an older one is said to be one this service cannot prove', async () => {
  await lab(async ({ api }) => {
    const hash = hashOf('2', 0);
    // The node of this service joined from a snapshot and holds no history for the block.
    const restored = { ...api, blockProof: async () => { throw new ApiFailure('http', { status: 404, code: 'history_not_held' }); } };
    await assert.rejects(checkerOf(restored).checkAction(hash), (error) => failsWith('not_kept')(error) && error.offered === true);
    // The service says "not in the history yet" of block 2 to a page that has already followed the chain to block 4: that is not a new block.
    const ahead = checkerOf(api);
    assert.equal((await ahead.checkAction(hashOf('4', 0))).height, '4');
    await assert.rejects(ahead.checkAction(hash), failsWith('not_kept'));
    // At the edge the page goes on by the block's own header; if the node cannot give that header yet, the block is too new.
    const early = { ...api, lightBlock: async (height) => { if (height === '4' || height === '5') throw new ApiFailure('http', { status: 404, code: 'not_found' }); return api.lightBlock(height); } };
    await assert.rejects(checkerOf(early).checkAction(hashOf('4', 0)), failsWith('too_new'));
    // One block below the page's reach is still the edge: the page stands at block 3, the action is in block 2.
    const near = checkerOf(api);
    assert.equal((await near.checkAction(hashOf('2', 1))).anchorHeight, '3');
    assert.equal((await near.checkAction(hash)).mode, 'own-block');
  });
});
