// Second review, part A: what is still on the page after a pass, and what an answer without a
// proof is called. The page modules of commit 0d76ddf; real verifier where it matters.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import '../../client-v4/time-sdk.js';
import * as verifier from '../../client-v4/proof-verifier.mjs';
import { createLightClient } from '../../client-v4/light-client.mjs';
import { createStrings } from './strings.mjs';
import { createExplorer } from './views.mjs';
import { compareAction } from './describe.mjs';
import { ApiFailure } from './client.mjs';
import { createChecker, CheckFailure, readEnvelope } from './check.mjs';
import { page, textOf, within, buttons, fakeTimers, all } from './review-fake-page.mjs';

const SDK = globalThis.TimeSDK;
const proven = JSON.parse(await readFile(new URL('../../verifier-v4/fixtures/proof.json', import.meta.url), 'utf8'));
const clone = (value) => JSON.parse(JSON.stringify(value));
const sha = (bytes) => createHash('sha256').update(bytes).digest();
const NETWORK = proven.trust.network_id, KEY2 = '2e'.repeat(32);
const NOW = proven.now_ms;

async function open(hash, api, checker, { origin = 'https://api.example' } = {}) {
  const p = page(hash);
  const fullApi = { origin, status: async () => ({ network: { network_id: NETWORK, chain_id: proven.trust.chain_id }, indexer: {} }), activity: async () => ({ items: [], has_more: false }), accountState: async () => { throw new ApiFailure('http', { status: 503, retryAfter: 5 }); }, ...api };
  checker ??= createChecker({ api: fullApi, loadTrust: async () => proven.trust, loadVerifier: async () => verifier, createLightClient, sdk: SDK, now: () => NOW, pause: async () => {} });
  const explorer = createExplorer({ document: p.document, window: p.window, api: fullApi, checker, live: null, t: createStrings('en'), now: () => NOW, timers: fakeTimers(), locale: 'en-GB', timeZone: 'UTC' });
  await explorer.start();
  return { ...p, view: p.$('view'), text: () => textOf(p.$('view')), explorer, checker };
}
const signed = (kind, payload) => SDK.concat(SDK.buildAction({ networkId: NETWORK, kind, from: '7', nonce: '42', authEpoch: '3', publicKey: KEY2, payload }), new Uint8Array(64));
const HASH = 'C3'.repeat(32);
const served = (kind, payload, more = {}) => ({ source: 'index', proven: false, index: { indexed_height: '120' }, action: { hash: HASH, height: '118', index: 0, time: '2026-11-17T10:00:00.000000Z', kind, opaque: false, sender: '7', nonce: '42', recipient: null, amount: null, reference: null, transfers: false,
  fee_rule: 'network_fee', fee_micros: '1000', results_checked: true, request_hash: null, request_status: null, unattributed: false, public_key: KEY2, auth_epoch: '3', payload, raw: 'AAAA', repeated: 1, ...more }, verify: { hash: HASH, height: '118', index: 0, total: '1', root_hash: 'AB'.repeat(32), leaf_hash: 'AAAA', aunts: [] } });
const fakeChecker = (bytes, more = {}) => ({ async trust() { return { networkId: NETWORK, chainId: 'c', genesisTimeMicros: '1', anchorHeight: '100', anchorHash: 'F0'.repeat(32) }; }, expectNetwork() {}, readsUpgrade: false,
  async checkAction(hash) { let action = null; try { action = SDK.decodeAction(bytes); } catch { action = null; } return { hash, height: '118', index: 0, total: '1', blockHash: 'AA'.repeat(32), mode: 'history', resultsChecked: true, anchorHeight: '121', rawHex: Buffer.from(bytes).toString('hex'), action, envelope: readEnvelope(bytes), ...more }; } });

test('N1: after a pass the "signed bytes" on the page are still the service\'s first answer, not the checked bytes, and nothing marks them', async () => {
  const bytes = signed(3, { to: '5', amount: '5' });
  // The service's first answer carries other bytes under "raw" (here three zero bytes); the check then proves the real ones.
  const p = await open(`#/action/${HASH}`, { action: async () => served(3, { to: '5', amount: '5' }, { recipient: '5', amount: '5', transfers: true, raw: 'AAAA', repeated: 3 }) }, fakeChecker(bytes));
  buttons(p.view, 'Check it yourself')[0].fire('click'); await p.explorer.settled();
  const text = p.text();
  assert.match(text, /Checked: this action is in block 118 of the chain\./);
  const rawShown = text.match(/The signed bytes, in hexadecimal ([0-9a-f ]+)/)?.[1]?.replace(/\s/g, '');
  console.log('checked bytes begin', Buffer.from(bytes).toString('hex').slice(0, 24), '| shown as "The signed bytes":', rawShown, '|', text.match(/The same bytes appear[^.]*\./)?.[0]);
  assert.equal(rawShown, Buffer.from(bytes).toString('hex'), 'after a pass the bytes shown as "the signed bytes" are the checked ones (or are marked as the service\'s)');
});

test('N2: an answer 404 WITHOUT any proof, to a page that has its manifest and verifier, is stated in the page\'s own voice: "There is no such account."', async () => {
  for (const address of ['#/account/@alice', '#/account/0']) {
    const p = await open(address, { account: async () => { throw new ApiFailure('http', { status: 404, code: 'account_not_found' }); } });
    const text = p.text();
    console.log(address, '->', text);
    // alice (account 0) exists in the proof the honest service would have sent with its 404 or its 200.
    assert(!/There is no such account\./.test(text) || /service|not checked|no proof/i.test(text), 'a bare denial by the service, with no proof, is given without saying whose word it is');
  }
});

test('N3: the "find" view states what the service says about an account, also when the service names another network and the frame says nothing of its state is shown', async () => {
  const p = await open('#/find/7', { status: async () => ({ network: { network_id: 'ef'.repeat(32), chain_id: 'other' }, indexer: {} }), block: async () => { throw new ApiFailure('http', { status: 404 }); },
    account: async () => ({ account: { id: '7', name: 'paid_100h_ok' }, proof: {} }) });
  await p.explorer.settled();
  console.log(textOf(p.$('index-note')), '||', p.text());
  assert(!(/nothing of the service's state is shown/.test(textOf(p.$('index-note'))) && /named account name from the chain: @paid_100h_ok/.test(p.text())), 'the frame says nothing of the state is shown; the view shows an account name from the service, boxed as "from the chain"');
});

test('N4: without a manifest, an account whose number the service garbles is refused with "The proof the service gave verifies, but..." although no proof was looked at', async () => {
  const none = createChecker({ api: {}, loadTrust: async () => null, loadVerifier: async () => verifier, createLightClient, sdk: SDK, now: () => NOW });
  const p = await open('#/account/@alice', { account: async () => ({ account: { id: 7, name: 'alice', balance: '5' }, proof: {} }) }, none);
  console.log(p.text());
  assert.doesNotMatch(p.text(), /The proof the service gave verifies/);
});

test('N5: unchecked figures: the name of an account the page did not check is still announced as "account name from the chain"', async () => {
  const none = createChecker({ api: {}, loadTrust: async () => null, loadVerifier: async () => verifier, createLightClient, sdk: SDK, now: () => NOW });
  const p = await open('#/account/7', { account: async () => ({ account: { id: '7', name: 'rich_account', balance: '3600000000000', nonce: '1', devices: [] }, proof: {}, indexed: { totals: {} } }) }, none);
  const text = p.text();
  console.log(text.slice(0, 330));
  const facts = text.slice(0, text.indexOf('The service says'));
  console.log('before the note:', facts);
  assert.doesNotMatch(facts, /account name from the chain: @rich_account/, 'an unchecked name is the service\'s word, not "from the chain"');
});

test('holds (second round): the description after a pass is the bytes\'; bytes that only frame-read are marked; a 75 execute is called unconfirmed', async () => {
  // A service that lies everywhere it can.
  const bytes = signed(5, { operator: '9', amount: '1000000', min_shares: '1' });
  const p = await open(`#/action/${HASH}`, { action: async () => served(5, { operator: '5', amount: '3600000000000', min_shares: '1' }, { height: '117', nonce: '41' }) }, fakeChecker(bytes));
  assert.match(p.text(), /staked 1,000 h with the validator of account 5/);
  buttons(p.view, 'Check it yourself')[0].fire('click'); await p.explorer.settled();
  assert.doesNotMatch(p.text(), /1,000 h|account 5\b/);
  assert.match(p.text(), /account 7 staked 1 s with the validator of account 9\..*In block 118 .*Sender's action number 42 .*Read by this page from the checked bytes and the checked block\./);
  assert.match(p.text(), /does NOT agree with what was checked\. Differing: block, sender's action number, content\./);
  // The envelope reader: truncated, padded and foreign bytes are not read as a frame.
  const good = signed(3, { to: '5', amount: '5' });
  assert.deepEqual(readEnvelope(good), { networkId: NETWORK, kind: 3, sender: '7', nonce: '42', authEpoch: '3', publicKey: KEY2 });
  for (const bad of [good.subarray(0, good.length - 1), SDK.concat(good, new Uint8Array(1)), good.subarray(1), new Uint8Array(0), new Uint8Array(200), 'text', null]) assert.equal(readEnvelope(bad), null);
  const view = new Uint8Array(good.length + 8); view.set(good, 8); // a view into a larger buffer reads the same
  assert.deepEqual(readEnvelope(view.subarray(8)), readEnvelope(good));
  // Bytes with a longer declared length than they have, and with a shorter one.
  const lengthAt = new TextEncoder().encode('TCDEVNET-ACTION-V1\0').length + 32 + 1 + 24 + 32;
  for (const delta of [1, -1, 0x01000000]) { const copy = good.slice(); new DataView(copy.buffer).setUint32(lengthAt, new DataView(copy.buffer).getUint32(lengthAt) + delta); assert.equal(readEnvelope(copy), null); }
  // The SDK's reading and the frame agree on every action the SDK reads (so "decoded" never contradicts "envelope").
  for (const [kind, payload] of [[3, { to: '5', amount: '5' }], [77, { daily_limit_micros: '1' }], [75, { type: 'execute', id: '2' }]]) { const b = signed(kind, payload), d = SDK.decodeAction(b), e = readEnvelope(b); assert.deepEqual([e.kind, e.sender, e.nonce, e.authEpoch, e.publicKey, e.networkId], [d.kind, d.from, d.nonce, d.authEpoch, d.publicKey, d.networkId]); }
  // A content that is not the canonical form of what was signed is not read by the SDK at all: duplicate keys, other escapes, numbers written another way.
  const frame = good.subarray(0, lengthAt);
  const withBody = (text) => { const body = new TextEncoder().encode(text), out = new Uint8Array(lengthAt + 4 + body.length + 64); out.set(frame); new DataView(out.buffer).setUint32(lengthAt, body.length); out.set(body, lengthAt + 4); return out; };
  for (const body of ['{"to":"5","amount":"5","amount":"9"}', '{"amount":"5","to":"5"}', '{"to":"5","amount":"\\u0035"}', '{"to":"5", "amount":"5"}', '{"to":5,"amount":"5"}']) assert.throws(() => SDK.decodeAction(withBody(body)), undefined, body);
  const ext = good.slice(); ext[lengthAt - 32 - 24 - 1] = 77;
  const extBody = (text) => { const out = withBody(text); out[lengthAt - 32 - 24 - 1] = 77; return out; };
  for (const body of ['{"daily_limit_micros":"1","daily_limit_micros":"9"}', '{"daily_limit_micros":"\\u0031"}', '{ "daily_limit_micros":"1"}', '{"daily_limit_micros":1e0}']) assert.throws(() => SDK.decodeAction(extBody(body)), undefined, body);
  // compareAction: nothing the service states about the content escapes it.
  const d = SDK.decodeAction(signed(8, { public_key: KEY2, can_manage: true, can_spend: true, proof: '00'.repeat(64) }));
  const base = { kind: 8, sender: '7', nonce: '42', auth_epoch: '3', public_key: KEY2, height: '118', index: 0, payload: clone(d.payload) };
  assert.deepEqual(compareAction(base, { action: d, envelope: null, height: '118', index: 0 }), { read: 'content', differing: [], unconfirmed: [] });
  for (const [field, change] of [['payload', (s) => { s.payload.can_spend = false; }], ['payload', (s) => { s.payload.extra = 1; }], ['payload', (s) => { delete s.payload.proof; }], ['publicKey', (s) => { s.public_key = '11'.repeat(32); }], ['authEpoch', (s) => { s.auth_epoch = '4'; }], ['nonce', (s) => { s.nonce = 42; }], ['kind', (s) => { s.kind = '8'; }], ['height', (s) => { s.height = 118; }], ['position', (s) => { s.index = 1; }], ['recipient', (s) => { s.recipient = '5'; }]]) {
    const lie = clone(base); change(lie);
    assert(compareAction(lie, { action: d, envelope: null, height: '118', index: 0 }).differing.includes(field), field);
  }
});
