// Adversarial review, part 2: what the page says after a check, with the builder's own fake
// checker (the page logic is what is under test here: describe.mjs, views.mjs, strings.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';
import '../../client-v4/time-sdk.js';
import { createStrings } from './strings.mjs';
import { createExplorer } from './views.mjs';
import { differences, describeAction } from './describe.mjs';
import { page, textOf, within, buttons, fakeTimers } from './review-fake-page.mjs';

const SDK = globalThis.TimeSDK;
const NETWORK = 'ab'.repeat(32), HASH = 'C3'.repeat(32), KEY = '1f'.repeat(32), KEY2 = '2e'.repeat(32);
const NOW = Date.UTC(2026, 10, 17, 12, 0, 0), micros = (ms) => String(ms * 1000), iso = (ms) => new Date(ms).toISOString().replace('Z', '000Z');
const GENESIS = micros(NOW - 3 * 3600 * 1000 - 4000);
const index = { network_id: NETWORK, chain_id: 'time-devnet-v4-test', start_height: '1', indexed_height: '120', indexed_block_time: iso(NOW - 4000), seconds_behind: 4 };
/// The decoded form of real bytes: built and read back by the SDK, so the shapes are the real ones.
const decoded = (kind, payload, from = '7') => SDK.decodeAction(SDK.concat(SDK.buildAction({ networkId: NETWORK, kind, from, nonce: '42', authEpoch: '3', publicKey: KEY2, payload }), new Uint8Array(64)));

async function open(hash, { api = {}, checker = {}, origin = '' } = {}) {
  const p = page(hash);
  const fullApi = { origin, status: async () => ({ network: { network_id: NETWORK, chain_id: 'time-devnet-v4-test', fee_micros: '1000' }, indexer: { indexed_height: '120', indexed_block_time: iso(NOW - 4000), seconds_behind: 4 } }),
    activity: async () => ({ items: [], has_more: false, index }), ...api };
  const fullChecker = { async trust() { return { networkId: NETWORK, chainId: 'time-devnet-v4-test', genesisTimeMicros: GENESIS, anchorHeight: '100', anchorHash: 'F0'.repeat(32) }; }, expectNetwork() {}, queries: [], ...checker };
  const explorer = createExplorer({ document: p.document, window: p.window, api: fullApi, checker: fullChecker, live: null, t: createStrings('en'), now: () => NOW, timers: fakeTimers(), locale: 'en-GB', timeZone: 'UTC' });
  await explorer.start();
  return { ...p, view: p.$('view'), text: () => textOf(p.$('view')), explorer, checker: fullChecker };
}
const served = (kind, payload, more = {}) => ({ source: 'index', proven: false, index, action: { hash: HASH, height: '118', index: 0, time: iso(NOW - 6000), kind, opaque: false, sender: '7', nonce: '42', recipient: null, amount: null, reference: null, transfers: false,
  fee_rule: 'network_fee', fee_micros: '1000', results_checked: true, request_hash: null, request_status: null, unattributed: false, public_key: KEY2, auth_epoch: '3', payload, raw: 'AAAA', repeated: 1, ...more }, verify: { hash: HASH, height: '118', index: 0, total: '1', root_hash: 'AB'.repeat(32), leaf_hash: 'AAAA', aunts: [] } });
const checked = (action, more = {}) => ({ async checkAction(hash) { return { hash, height: '118', index: 0, blockHash: 'AA'.repeat(32), mode: 'history', resultsChecked: true, anchorHeight: '121', rawHex: '00', action, ...more }; } });

test('F2: the service lies in the payload (stake amount, key added, daily limit, name, recovery helpers): after the check the page says its description AGREES with the checked bytes', async () => {
  const cases = [
    // [what, kind, what the bytes say, what the service says, a lie that is on the page]
    ['a stake of 1 s shown as 1,000 h', 5, { operator: '9', amount: '1000000', min_shares: '1' }, { operator: '9', amount: '3600000000000', min_shares: '1' }, /staked 1,000 h with the validator of account 9/],
    ['a stake with validator 9 shown as with validator 5', 5, { operator: '9', amount: '1000000', min_shares: '1' }, { operator: '5', amount: '1000000', min_shares: '1' }, /with the validator of account 5/],
    ['a key that may spend and manage shown as a harmless one', 8, { public_key: KEY, can_manage: true, can_spend: true, proof: '00'.repeat(64) }, { public_key: KEY2, can_manage: false, can_spend: false, proof: '00'.repeat(64) }, /May spend no May manage the account no/],
    ['a daily limit of 1,000 h shown as 1 min', 77, { daily_limit_micros: '3600000000000' }, { daily_limit_micros: '60000000' }, /set its daily limit to 1 min/],
    ['the name taken', 2, { name: 'alice', salt: '00'.repeat(32) }, { name: 'bob', salt: '00'.repeat(32) }, /took the name account name from the chain: @bob/],
    ['recovery helpers 1,2,3 shown as 4,5,6', 11, { guardians: ['1', '2', '3'], threshold: '2', delay_seconds: '86400' }, { guardians: ['4', '5', '6'], threshold: '2', delay_seconds: '86400' }, /Helper account 4/],
  ];
  const wrong = [];
  for (const [what, kind, truth, lie, shown] of cases) {
    const bytesSay = decoded(kind, truth);
    assert.deepEqual(differences(served(kind, lie).action, bytesSay), [], 'differences() sees nothing');
    const p = await open(`#/action/${HASH}`, { api: { action: async () => served(kind, lie) }, checker: checked(bytesSay) });
    assert.match(p.text(), shown, what);
    buttons(p.view, 'Check it yourself')[0].fire('click'); await p.explorer.settled();
    const result = textOf(within(p.view, 'check-result')[0]);
    if (/The service's description above agrees with the checked bytes\./.test(result) && !/does NOT agree/.test(result)) wrong.push(what);
  }
  console.log('said to agree although the description lies:', wrong);
  assert.deepEqual(wrong, [], 'the page vouched for a description that the checked bytes contradict');
});

test('F2b: the block, the position and the sender\'s action number shown above are not compared either', async () => {
  const bytesSay = decoded(3, { to: '5', amount: '5' });
  // The service shows block 118, position 1, nonce 7; the check proves block 9, position 4; the bytes carry nonce 42.
  const p = await open(`#/action/${HASH}`, { api: { action: async () => served(3, { to: '5', amount: '5' }, { recipient: '5', amount: '5', nonce: '7', transfers: true }) }, checker: checked(bytesSay, { height: '9', index: 3 }) });
  buttons(p.view, 'Check it yourself')[0].fire('click'); await p.explorer.settled();
  const text = p.text();
  console.log(text.match(/In block 118.*?Sender's action number 7/)?.[0], '|', text.match(/Checked: this action is in block 9[^.]*\./)?.[0], '|', text.match(/The service's description above agrees with the checked bytes\./)?.[0]);
  assert(!(/In block 118 Position in the block number 1 of 1/.test(text) && /Checked: this action is in block 9/.test(text) && /description above agrees with the checked bytes/.test(text)), 'block 118 above, block 9 proven, and the page says the description agrees');
});

test('F4: an account frozen by a guardian recovery (the engine refuses its actions) is shown as "Frozen no", checked in your browser', async () => {
  const account = { id: '7', name: 'payer', balance: '85000000', nonce: '42', auth_epoch: '3', devices: [{ public_key: KEY, can_manage: true, can_spend: true }] };
  const elapsed = 3 * 3600 * 1000000;
  // A recovery case that has reached its quorum: ready_elapsed_micros is set and it has not expired.
  // v5/src/engine.rs:2168 "account is frozen by threshold guardian recovery"; time-sdk.js perform(): "Guardian recovery freezes this account".
  const recovery = { target: '7', recovery_id: 'aa'.repeat(32), new_public_key: 'bb'.repeat(32), approvals: ['1', '2'], auth_epoch: '3', policy_version: '1', ready_elapsed_micros: String(elapsed + 3600 * 1000000), expires_elapsed_micros: String(elapsed + 7 * 86400 * 1000000) };
  const state = { network_id: NETWORK, height: '121', time_micros: micros(NOW - 3000), genesis: { genesis_time_micros: GENESIS }, accounts: [account], security: [], recovery_cases: [recovery], stake_owners: { 7: null }, candidates: { 7: null } };
  const checker = { async checkState(fetchBody, query) { return { body: await fetchBody(), found: true, state, absent: [], height: '121', timeMicros: micros(NOW - 3000), anchorHeight: '121' }; } };
  const p = await open('#/account/7', { api: { account: async () => ({ account, proof: {}, indexed: { totals: {} } }), accountState: async () => ({ account, proof: {} }) }, checker });
  const text = p.text();
  console.log(text.match(/Security and stake.*?Checked in your browser[^.]*\./)?.[0]);
  assert.doesNotMatch(text, /Frozen no /, 'the account cannot act until the recovery is cancelled or completed, and the page says "Frozen no"');
});

test('F7: the page states as checked that no upgrade is scheduled, but never asks the proof about the upgrade row', async () => {
  const queries = [];
  const pos = { active: [{ owner: '0', consensus_key: KEY, power: '2' }], scheduled: [], safety_hold: false };
  const checker = { async checkState(fetchBody, query) { queries.push(query); return { body: await fetchBody(), found: true, state: { network_id: NETWORK, height: '121', time_micros: micros(NOW - 3000), protocol_version: '4', genesis: { genesis_time_micros: GENESIS }, pos }, absent: [], height: '121', timeMicros: micros(NOW - 3000), anchorHeight: '121' }; } };
  const p = await open('#/validators', { api: { validators: async () => ({ pos, upgrade: null, protocol_version: '4', proof: {} }) }, checker });
  console.log('query:', JSON.stringify(queries), '|', p.text().match(/Scheduled upgrade.*$/)?.[0]);
  // The verifier of the upgrade branch (verifier-v4/src/view.rs there: `if request.include_upgrade { state["upgrade"] = ... }`) returns the row
  // only when asked; a proof that was not asked about the row says nothing about it.
  assert(!(/No upgrade of the rules is scheduled: the state of this network holds no upgrade plan/.test(p.text()) && !queries.some((q) => q.include_upgrade)), 'a statement about the state that no proof covered');
});

test('F8: served by the API (same origin), the footer still says the trusted block came "not from the service"', async () => {
  const p = await open('#/', { origin: '', api: { blocks: async () => ({ items: [], index }) } });
  const footer = textOf(p.$('trust-body'));
  console.log('api origin "" (the service serves the page and /explorer/trust-manifest.json) ->', footer.slice(0, 160));
  assert.doesNotMatch(footer, /not from the service/, 'when the service serves the page, the network id and the trusted block DO come from the service');
});

test('F9: a name typed into a shared link is shown in the box that says "account name from the chain" before any chain has said so', async () => {
  const checker = { async checkState() { await new Promise(() => {}); } }; // never answers
  const p = page('#/account/@pay_me_100h'), api = { origin: '', status: async () => ({}), account: async () => ({}) };
  const explorer = createExplorer({ document: p.document, window: p.window, api, checker: { ...checker, async trust() { return null; }, expectNetwork() {} }, live: null, t: createStrings('en'), now: () => NOW, timers: fakeTimers() });
  explorer.start(); await new Promise((resolve) => setTimeout(resolve, 20));
  console.log('while loading ->', textOf(p.$('view')));
  assert.doesNotMatch(textOf(p.$('view')), /account name from the chain: @pay_me_100h/);
});

test('numbers: a position or a count that is not a small whole number is put into the page\'s own sentence', async () => {
  const p = await open(`#/action/${HASH}`, { api: { action: async () => served(3, { to: '5', amount: '5' }, { index: 1e21, repeated: 1e21 }) }, checker: checked(null) });
  console.log(p.text().match(/Position in the block [^T]*/)?.[0], '|', p.text().match(/The same bytes appear[^.]*\./)?.[0]);
  assert.doesNotMatch(p.text(), /1e\+21/);
});
