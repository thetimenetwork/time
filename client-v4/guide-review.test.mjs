// The review of docs/integration-guide.md (2026-11-18, after the guide's section on the nonce was rewritten): the
// review's own tests, brought into the tree. As the review wrote them they passed, because each asserted an answer
// that misled, or a reading of the guide that paid a withdrawal twice. Here:
// - where the service changed, the test asserts what the service answers now;
// - where only the guide changed, the test still asserts the answers an integrator really gets (they are the same
//   as before), names the sentence of the guide that now covers the case, and reads the guide as it is written today.
// Every assertion that differs from the review's is marked with a comment that starts with ADAPTED.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign as edSign } from 'node:crypto';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import './time-sdk.js';
import * as verifier from './proof-verifier.mjs';
import { describeAction, IndexerError } from './indexer.mjs';
import { createApiService, NEWER_ACTIONS } from './api.mjs';

const SDK = globalThis.TimeSDK;
const fixture = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/fast-receipt.json', import.meta.url), 'utf8'));
const guide = await readFile(new URL('../docs/integration-guide.md', import.meta.url), 'utf8');
const NETWORK = fixture.trust.network_id, CHAIN = fixture.trust.chain_id;
const sha = (bytes) => createHash('sha256').update(bytes).digest();
const txBytes = (height, index) => Buffer.from(fixture.txs[height][index], 'base64');
const hashOf = (height, index) => sha(txBytes(height, index)).toString('hex').toUpperCase();
/// The guide says this, in these words.
const guideSays = (sentence) => assert.ok(guide.includes(sentence), `the guide does not say: ${sentence}`);

// The harness of client-v4/api.test.mjs: a fake CometBFT RPC over real signed blocks.
function fakeRpc(state) {
  const block = (h) => { const b = fixture.blocks[Number(h) - 1]; if (!b || Number(h) > state.tip) throw new IndexerError('RPC_REFUSED', 'height is not available'); return b; };
  return async (method, parameters = {}) => {
    if (method === '/status') return { node_info: { network: CHAIN }, sync_info: { latest_block_height: String(state.tip) } };
    if (method === '/block') return { block: { header: block(parameters.height).signed_header.header, data: { txs: fixture.txs[parameters.height] } } };
    if (method === '/blockchain') { const metas = []; for (let h = Number(parameters.maxHeight); h >= Number(parameters.minHeight); h--) metas.push({ header: block(h).signed_header.header }); return { block_metas: metas }; }
    if (method === '/commit') return { signed_header: block(parameters.height ?? state.tip).signed_header };
    if (method === '/validators') { const h = Number(parameters.height); if (h > state.tip + 1) throw new IndexerError('RPC_REFUSED', 'height is not available'); return { block_height: parameters.height, total: '4', validators: h <= fixture.blocks.length ? fixture.blocks[h - 1].validators : fixture.blocks.at(-1).next_validators }; }
    if (method === '/broadcast_tx_sync') return state.broadcast(parameters);
    throw new IndexerError('RPC_REFUSED', 'not available on this node');
  };
}
async function lab(run, options = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'guide-review-'));
  const state = { tip: 4, clock: fixture.now_ms, broadcast: () => ({ code: 1, log: 'incorrect nonce or nonce exhausted' }), readState: null };
  let service;
  try {
    service = await createApiService({
      trust: fixture.trust, rpc: fakeRpc(state), verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false, pollMs: 5,
      now: () => state.clock, log: () => {}, readState: (selection) => state.readState(selection), rateLimit: { perSecond: 1000, burst: 100000 }, ...options,
    });
    await run({ service, state });
  } finally { await service?.close(); await rm(directory, { recursive: true, force: true }); }
}
const proves = (state, account, height = '3') => { state.readState = async (selection) => ({ verified: true, requested: selection, proof: { height, entries: [] }, state: { network_id: NETWORK, height, time_micros: '1000003000000', accounts: [account], config: {} } }); };
async function indexAll(service, height = 4) {
  for (let i = 0; i < 50 && (service.store.high() ?? 0) < height; i++) await service.indexer.step();
  assert.equal(service.store.high(), height);
}
async function call(service, route, options = {}) {
  const response = await fetch(service.url + route, options);
  const text = await response.text();
  let body = null; try { body = JSON.parse(text); } catch { /* not JSON */ }
  return { status: response.status, body };
}
const post = (service, raw) => call(service, '/v1/transactions', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tx: Buffer.from(raw).toString('base64') }) });
const unsignedAction = (kind, payload, more = {}) => Buffer.from(SDK.concat(SDK.buildAction({ networkId: NETWORK, from: '5', nonce: '1', authEpoch: '0', publicKey: 'bb'.repeat(32), kind, payload, ...more }), new Uint8Array(64)));
function signed(kind, payload, more = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const body = Buffer.from(SDK.buildAction({ networkId: NETWORK, kind, from: '5', nonce: '1', authEpoch: '0', publicKey: publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'), payload, ...more }));
  return Buffer.concat([body, edSign(null, body, privateKey)]);
}
function seed(service, blocks) {
  blocks.forEach((raws, i) => {
    const height = i + 1;
    const actions = raws.map((raw, idx) => ({ ...describeAction(raw, NETWORK), hash: sha(raw).toString('hex').toUpperCase(), raw, idx }));
    service.store.writeBlock({ previousChecked: height > 1, events: [], actions,
      block: { height, hash: sha(Buffer.from(`block ${height}`)).toString('hex'), previous_hash: height > 1 ? sha(Buffer.from(`block ${height - 1}`)).toString('hex') : '', time_micros: 1000000000000 + height * 1000000, time: new Date(1000000000 + height * 1000).toISOString().replace('Z', '000Z'), proposer: 'AA'.repeat(20), app_hash: 'BB'.repeat(32), data_hash: 'CC'.repeat(32) } });
  });
}
const PAYER = { id: '7', name: 'payer', balance: '85', nonce: '3', auth_epoch: '0', devices: [] };

/// Step 4 of the guide, read from the service's answers.
/// - `used`, `absent`, `noFault`: the three conditions step 4 had when the review was made, read literally. The review's
///   helper returned these and `all`, their conjunction, under which the guide said "can never be included".
/// - ADAPTED: the helper also reads step 4 as it is written today, from what the signer stored with the bytes (`signed`:
///   the kind, the nonce, the authority epoch and the state height at signing). `today` is what the guide now lets
///   the reader conclude.
async function stepFourSaysNeverIncluded(service, account, hash, signed) {
  const state = (await call(service, `/v1/accounts/${account}`)).body;                    // 1: a proof shows the nonce used; note S
  const used = BigInt(state.account.nonce) >= BigInt(signed.nonce), S = BigInt(state.state_height);
  const lookup = await call(service, `/v1/actions/${hash}`);                              // 2: 404 at an indexed height at or above S
  const absent = lookup.status === 404 && BigInt(lookup.body.index.indexed_height) >= S;
  const health = (await call(service, '/v1/health')).body;                                // 3: no indexer fault
  const noFault = !(health.reasons ?? []).includes('indexer_fault');
  const three = used && absent && noFault;
  let today;
  if ([72, 73, 74, 76].includes(signed.kind)) today = 'step 4 does not apply: the action carries no nonce';
  else if (!three) today = 'nothing yet';
  else {
    // 4: the index covers the whole time since the bytes were signed.
    const covers = BigInt(lookup.body.index.start_height) <= BigInt(signed.stateHeight);
    const activity = (await call(service, `/v1/accounts/${account}/activity?order=asc&limit=200`)).body;
    const carried = activity.items.some((item) => item.sender === account && item.nonce === signed.nonce);
    if (carried) today = 'another action carries the nonce: verify it';
    else if (!covers) today = 'conclude nothing: the index starts after the bytes were signed';
    else if (state.account.auth_epoch === signed.authEpoch) today = 'conclude nothing: an action used the nonce and this index does not show it';
    else today = 'look for the replacement of keys';
  }
  return { used, absent, noFault, three, today, lookup, state };
}

test('H1: an index that starts above the block of a withdrawal meets the three old conditions of step 4 for a withdrawal that is in a block; the fourth condition and the rule of the authority epoch stop the conclusion', async () => {
  // The fixture chain: account 7 sent nonce 1 and 2 in block 2 and nonce 3 in block 4.
  const hash = hashOf('2', 0), raw = txBytes('2', 0), action = SDK.decodeAction(new Uint8Array(raw));
  assert.deepEqual([action.from, action.nonce], ['7', '1']);
  // What the signer stored with the bytes: they were signed on the state of height 1, at authority epoch 0.
  const stored = { kind: action.kind, nonce: action.nonce, authEpoch: action.authEpoch, stateHeight: '1' };
  // An index from height 1 holds it.
  await lab(async ({ service, state }) => {
    await indexAll(service); proves(state, PAYER);
    const said = await stepFourSaysNeverIncluded(service, '7', hash, stored);
    assert.deepEqual([said.lookup.status, said.three], [200, false]);
  });
  // The same chain, an index rebuilt with start_height 3 (a new data directory after the old one was lost).
  await lab(async ({ service, state }) => {
    await indexAll(service); proves(state, PAYER);
    const said = await stepFourSaysNeverIncluded(service, '7', hash, stored);
    // The answers are what they were: the three conditions the guide had then all hold, for a withdrawal that is in a block.
    assert.deepEqual([said.used, said.absent, said.noFault, said.three], [true, true, true, true]);
    assert.deepEqual([said.lookup.body.index.start_height, said.lookup.body.index.indexed_height, said.state.state_height], ['3', '4', '3']);
    // "Find out what used it": no action of the account in the index carries nonce 1 ...
    const activity = (await call(service, '/v1/accounts/7/activity?order=asc&limit=200')).body;
    assert.equal(activity.items.some((item) => item.nonce === action.nonce), false);
    // ... and sending the bytes again names nothing either: the node's refusal comes back as it is.
    const again = await post(service, raw);
    assert.deepEqual([again.status, again.body.error.code], [422, 'rejected']);
    // The proof says, for whoever looks, that the authority epoch has not moved: no replacement happened.
    assert.equal(said.state.account.auth_epoch, '0');
    // ADAPTED: the review's test ended here, on `all` true: the guide then concluded "a replacement of the account's
    // keys consumed it, and the withdrawal was not made", and the withdrawal was signed and paid again. The guide now
    // has a fourth condition, which this index does not meet (it starts at 3; the bytes were signed at height 1) ...
    guideSays('4. **The index covers the whole time since you signed:** the `index.start_height` of that 404 is at or below the `state_height` you stored with the bytes when you signed them.');
    assert.equal(said.today, 'conclude nothing: the index starts after the bytes were signed');
    // ... and the rule that would stop the conclusion even for a reader who had stored no height: with the
    // authority epoch unchanged, an action used the nonce, and an index that shows none is not to be believed.
    guideSays('- **It is still the one you signed with.** No replacement happened. An action used the nonce and this index does not show it; it may be your withdrawal. **Conclude nothing,** sign nothing, and find out what is wrong with the index.');
    assert.equal((await stepFourSaysNeverIncluded(service, '7', hash, { ...stored, stateHeight: '3' })).today, 'conclude nothing: an action used the nonce and this index does not show it');
    assert.doesNotMatch(guide, /If no action carries it, a replacement of the account's keys consumed it/);
  }, { startHeight: 3 });
});

test('H2: an action without a nonce (a payment approved by several keys, kind 73) that only waits for a block meets the three old conditions of step 4; the guide now keeps step 4 away from it', async () => {
  await lab(async ({ service, state }) => {
    await indexAll(service);
    proves(state, { id: '5', name: 'exchange', balance: '100000000', nonce: '17', auth_epoch: '2', devices: [] });
    const pay = signed(73, { op: { type: 'pay', to: '7', amount: '2500000' }, expires_elapsed_micros: '3600000000', approvals: [] }, { nonce: '0', authEpoch: '0' });
    const hash = sha(pay).toString('hex').toUpperCase();
    // The node takes it into its waiting list.
    state.broadcast = () => ({ code: 0, hash });
    const sent = await post(service, pay);
    assert.deepEqual([sent.status, sent.body.status, sent.body.nonce], [202, 'submitted', '0']);
    // One second later, before any block: account.nonce (17) is "at or above" the nonce that was signed (0). The
    // answers are what they were, and the three conditions the guide had then all hold while the payment only waits.
    const said = await stepFourSaysNeverIncluded(service, '5', hash, { kind: 73, nonce: '0', authEpoch: '0', stateHeight: '3' });
    assert.deepEqual([said.used, said.absent, said.noFault, said.three], [true, true, true, true]);
    // ADAPTED: the review's test ended here, on `all` true ("can never be included": fresh approvals were collected, and
    // both payments were valid). The guide now says which actions steps 3 and 4 are for, and what holds for this one.
    guideSays('Four kinds carry no nonce (the field is 0) and no authority epoch: a freeze (72), an operation approved by several keys, which includes a payment above the limit with a second proof (73), the finishing of a replacement of keys (74) and a cancellation (76). Nothing below that speaks of "the nonce" holds for them, and **step 4 must never be applied to them**');
    assert.equal(said.today, 'step 4 does not apply: the action carries no nonce');
    guideSays('- A 404 for its hash says "not in a block this index holds", and nothing more. While it waits, the conditions of step 4 would all read as met.');
    guideSays('- Its bytes are dead once a proof shows a state time past its `expires_elapsed_micros`');
    guideSays('- So a replacement (a later expiry, say) is approved for **the version you stored**, never for a version read anew: then at most one of the two can be included, whatever became of the first.');
    // The sentence that was false for nonce 0 is gone: it is now said of actions that carry a nonce only.
    assert.doesNotMatch(guide, /or under the same nonce \("The nonce", point 3\): two actions with one nonce can never both be included\./);
  });
});

test('L1a: state_is_behind is true when the index holds an action of the account in a block above the proof, also when a replacement of keys used the nonce in between', async () => {
  await lab(async ({ service, state }) => {
    // Account 5: nonce 1 (block 1); a replacement of its keys (kind 73, carries nonce 0, consumes nonce 2: block 2);
    // then the new key's first action, nonce 3 (block 2).
    seed(service, [
      [unsignedAction(3, { to: '1', amount: '1' }, { nonce: '1' })],
      [unsignedAction(73, { op: { type: 'replace', keys: [], policy: {} }, expires_elapsed_micros: '9', approvals: [] }, { nonce: '0' }), unsignedAction(3, { to: '1', amount: '1' }, { nonce: '3', authEpoch: '1' })],
    ]);
    // The proof is one block behind: it shows nonce 1 (state of block 1).
    proves(state, { id: '5', name: 'exchange', balance: '0', nonce: '1', auth_epoch: '0', devices: [] }, '1');
    const body = (await call(service, '/v1/accounts/5')).body;
    assert.deepEqual([body.state_height, body.indexed_height, body.account.nonce], ['1', '2', '1']);
    // The index holds an action of the account with a nonce above the proven one, in a block above state_height ...
    const activity = (await call(service, '/v1/accounts/5/activity?order=asc')).body.items.map((item) => [item.height, item.kind, item.nonce]);
    assert.deepEqual(activity, [['1', 3, '1'], ['2', 73, '0'], ['2', 3, '3']]);
    // ADAPTED: the review asserted [false, []] here: the answer said there was none, because it looked for the action
    // with the proven nonce plus one (2), and a replacement uses a nonce without carrying it. The service now goes by
    // the height of the proof: both actions of block 2 are newer, the replacement among them.
    assert.deepEqual([body.indexed.state_is_behind, body.indexed.newer_actions.map((item) => [item.height, item.kind, item.nonce]), body.indexed.last_sent.nonce], [true, [['2', 73, '0'], ['2', 3, '3']], '3']);
  });
});

test('L1b: last_sent is the newest action the index holds, also when more than 16 are newer than the proof', async () => {
  await lab(async ({ service, state }) => {
    seed(service, Array.from({ length: 40 }, (_, i) => [unsignedAction(3, { to: '1', amount: '1' }, { nonce: String(i + 1) })]));
    proves(state, { id: '5', name: 'busy', balance: '0', nonce: '0', auth_epoch: '0', devices: [] });
    const body = (await call(service, '/v1/accounts/5')).body;
    // ADAPTED: the review asserted [String(NEWER_ACTIONS), NEWER_ACTIONS]: last_sent was the last of the list of 16,
    // with nonce 40 in the index. It is now the newest of all; the list still holds 16, the oldest above the proof.
    // (The proof of this test is of height 3, so those are the actions of blocks 4 to 19.)
    assert.deepEqual([body.indexed.last_sent.nonce, body.indexed.newer_actions.length], ['40', NEWER_ACTIONS]);
    assert.deepEqual([body.indexed.newer_actions[0].height, body.indexed.newer_actions.at(-1).height], ['4', '19']);
  });
});

test('M2: nonce_used says same_content for another withdrawal to the same customer of the same amount, and no longer says "it is done": one hash settles one withdrawal', async () => {
  await lab(async ({ service }) => {
    // Signer B paid withdrawal #2 (to 7, 2.5 s) with nonce 18. Signer A signed withdrawal #1 (to 7, 2.5 s) with nonce 18.
    const second = unsignedAction(3, { to: '7', amount: '2500000' }, { nonce: '18' });
    seed(service, [[second]]);
    const first = signed(3, { to: '7', amount: '2500000' }, { nonce: '18' });
    const answer = await post(service, first);
    // The answer an integrator gets is the same: the two withdrawals have the same kind and payload.
    assert.deepEqual([answer.status, answer.body.error.code, answer.body.used_by.same_content, answer.body.used_by.hash], [409, 'nonce_used', true, sha(second).toString('hex').toUpperCase()]);
    // ADAPTED: the review asserted the message /it is done\. Do not sign it again/: one payment on the chain, two
    // withdrawals marked paid. The message now says what decides, and the guide has the rule.
    assert.doesNotMatch(answer.body.error.message, /it is done/);
    assert.match(answer.body.error.message, /One hash is one payment: if used_by\.hash is not the hash of another payment in your records, this payment is made by it and nothing more is signed for it; if it is, this payment is not made\. Verify used_by\.hash before you act on either/);
    guideSays('**A hash settles one withdrawal:** if `used_by.hash` already settles another withdrawal of yours, this one is not paid; if it settles none, record it for this one, which is paid.');
    // The exchange's records, read by that rule: the hash settles withdrawal #2 already, so #1 is not paid by it.
    const settledBy = new Map([[answer.body.used_by.hash, 'withdrawal #2']]);
    assert.equal(settledBy.has(answer.body.used_by.hash) ? 'not paid: sign again with next_nonce' : 'paid', 'not paid: sign again with next_nonce');
  });
});
