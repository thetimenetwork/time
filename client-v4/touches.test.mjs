// Which accounts an action touches and wakes (touches.mjs), and the API's hints for wallets that are built on it
// (api.mjs, GET /v1/touches): over the fake CometBFT RPC of api.test.mjs, which serves real signed blocks
// (verifier-v4/fixtures/fast-receipt.json: two transfers from account 7 to account 1 in block 2, one in block 4).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import './time-sdk.js';
import * as verifier from './proof-verifier.mjs';
import { IndexerError } from './indexer.mjs';
import { createApiService } from './api.mjs';
import { touchesOf, touchesOfBytes, WAKE_SENDER, WAKE_TARGET, ANONYMOUS } from './touches.mjs';

const SDK = globalThis.TimeSDK;
const fixture = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/fast-receipt.json', import.meta.url), 'utf8'));
const NETWORK = fixture.trust.network_id, CHAIN = fixture.trust.chain_id;
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const key = (n) => n.toString(16).padStart(2, '0').repeat(32);
/// The bytes of an action of account `from`, with a signature of zeros: what is read here is the bytes, not who signed.
const bytes = (kind, payload, from = '5') => SDK.concat(SDK.buildAction({ networkId: NETWORK, kind, from, nonce: '1', authEpoch: '0', publicKey: key(0xbb), payload }), new Uint8Array(64));
const of = (kind, payload, from) => touchesOfBytes(bytes(kind, payload, from), NETWORK);
const sorted = (result) => ({ touched: [...result.touched].sort(), wake: [...result.wake].sort() });

test('a payment touches its payer and its payee, and wakes nobody', () => {
  assert.deepEqual(sorted(of(3, { to: '9', amount: '5' })), { touched: ['5', '9'], wake: [] });
  assert.deepEqual(sorted(of(10, { to: '9', amount: '5', reference: 'ab'.repeat(32) })), { touched: ['5', '9'], wake: [] });
  // Staking names the validator's owner, and wakes nobody either.
  assert.deepEqual(sorted(of(5, { operator: '12', amount: '5', min_shares: '1' })), { touched: ['12', '5'], wake: [] });
  assert.deepEqual(sorted(of(6, { operator: '12', shares: '5', min_amount: '1' })), { touched: ['12', '5'], wake: [] });
});

test('the account-security kinds wake the account that sends them, and only that one', () => {
  for (const kind of [70, 71, 72, 74, 76, 77]) assert.deepEqual(of(kind, { x: '1' }), { touched: ['5'], wake: ['5'] }, String(kind));
  // A root operation that pays: the payee is touched, never woken; the account is woken, whoever of its keys approved.
  assert.deepEqual(sorted(of(73, { op: { type: 'pay', to: '9', amount: '7' }, expires_elapsed_micros: '1', approvals: [] })), { touched: ['5', '9'], wake: ['5'] });
  assert.deepEqual(of(73, { op: { type: 'replace', keys: [], policy: {} }, expires_elapsed_micros: '1', approvals: [] }), { touched: ['5'], wake: ['5'] });
  // A payment above the daily limit: asking for it touches the payee, who is not woken.
  assert.deepEqual(sorted(of(75, { type: 'request', to: '9', amount: '7' })), { touched: ['5', '9'], wake: ['5'] });
  assert.deepEqual(of(75, { type: 'execute', id: '3' }), { touched: ['5'], wake: ['5'] });
  assert.deepEqual([...WAKE_SENDER], [8, 9, 11, 14, 15, 16, 70, 71, 72, 73, 74, 75, 76, 77]);
});

test('protocol 4: keys and guardian recovery wake the account they change, and a guardian wakes the account it names', () => {
  assert.deepEqual(of(8, { public_key: key(1), can_manage: true, can_spend: true, proof: key(2) + key(2) }), { touched: ['5'], wake: ['5'] });
  assert.deepEqual(of(9, { public_key: key(1) }), { touched: ['5'], wake: ['5'] });
  assert.deepEqual(sorted(of(11, { guardians: ['3', '4'], threshold: '1', delay_seconds: '60' })), { touched: ['3', '4', '5'], wake: ['5'] });
  assert.deepEqual(sorted(of(12, { target: '9', policy_version: '1', accept: true }, '3')), { touched: ['3', '9'], wake: ['9'] });
  assert.deepEqual(sorted(of(13, { target: '9', policy_version: '1', recovery_id: key(3), new_public_key: key(4), expires_elapsed_micros: '100', proof: key(5) + key(5) }, '3')), { touched: ['3', '9'], wake: ['9'] });
  for (const [kind, payload] of [[14, {}], [15, { recovery_id: key(3) }], [16, {}]]) assert.deepEqual(of(kind, payload), { touched: ['5'], wake: ['5'] }, String(kind));
  assert.deepEqual([...WAKE_TARGET], [12, 13]);
});

test('what names no account touches nobody: a registration, the relay of headers, another network, bytes that are no action', () => {
  assert.deepEqual(of(2, { name: 'alice', salt: key(6) }, ANONYMOUS), { touched: [], wake: [] });
  assert.deepEqual(of(45, { name: 'alice', salt: key(6), security: { keys: [], policy: {} } }, ANONYMOUS), { touched: [], wake: [] });
  const other = SDK.concat(SDK.buildAction({ networkId: 'cd'.repeat(32), kind: 72, from: '5', nonce: '0', authEpoch: '0', publicKey: key(0xbb), payload: { x: '1' } }), new Uint8Array(64));
  assert.deepEqual(touchesOfBytes(other, NETWORK), { touched: [], wake: [] });
  for (const junk of [new Uint8Array(0), new Uint8Array(300), new TextEncoder().encode('TCDEVNET-ACTION-V1\0'), 'not bytes', null]) assert.deepEqual(touchesOfBytes(junk, NETWORK), { touched: [], wake: [] });
  // Malformed fields name nobody: no account number with a leading zero, a sign, or beyond the anonymous one.
  for (const to of ['09', '-1', ANONYMOUS, '1e3', 9, null]) assert.deepEqual(touchesOf({ kind: 3, from: '5', payload: { to, amount: '1' } }), { touched: ['5'], wake: [] }, String(to));
  assert.deepEqual(touchesOf({ kind: 13, from: '3', payload: { target: '007' } }), { touched: ['3'], wake: [] });
  assert.deepEqual(touchesOf(null), { touched: [], wake: [] });
});

test('an action whose payload this SDK cannot read still touches its sender, and wakes it only for a kind that wakes its sender', () => {
  // A kind the SDK does not know, in the frame of this network: its sender is in the frame.
  const known = bytes(3, { to: '9', amount: '5' }, '41');
  const unknown = Uint8Array.from(known); unknown[new TextEncoder().encode('TCDEVNET-ACTION-V1\0').length + 32] = 99;
  assert.throws(() => SDK.decodeAction(unknown));
  assert.deepEqual(touchesOfBytes(unknown, NETWORK), { touched: ['41'], wake: [] });
  // A frame whose length field does not match its bytes is not read at all.
  const cut = unknown.slice(0, unknown.length - 1);
  assert.deepEqual(touchesOfBytes(cut, NETWORK), { touched: [], wake: [] });
  // A freeze (72) whose payload this SDK cannot read: an action of the account's own keys still wakes it.
  const head = new TextEncoder().encode('TCDEVNET-ACTION-V1\0').length;
  const freeze = Uint8Array.from(bytes(72, { freezes: '0', version: '1', expires_elapsed_micros: '99' }, '41'));
  freeze[head + 93] = 0x5b; // the payload's first byte made "[": not a payload of a freeze
  assert.throws(() => SDK.decodeAction(freeze));
  assert.deepEqual(touchesOfBytes(freeze, NETWORK), { touched: ['41'], wake: ['41'] });
});

// ------------------------------------------------------------------ the API's hints for wallets
function fakeRpc(state) {
  const block = (h) => { const b = fixture.blocks[Number(h) - 1]; if (!b || Number(h) > state.tip) throw new IndexerError('RPC_REFUSED', 'height is not available'); return b; };
  return async (method, parameters = {}) => {
    if (method === '/status') return { node_info: { network: CHAIN }, sync_info: { latest_block_height: String(state.tip) } };
    if (method === '/block') return { block: { header: block(parameters.height).signed_header.header, data: { txs: fixture.txs[parameters.height] } } };
    if (method === '/blockchain') { const metas = []; for (let h = Number(parameters.maxHeight); h >= Number(parameters.minHeight); h--) metas.push({ header: block(h).signed_header.header }); return { block_metas: metas }; }
    if (method === '/commit') return { signed_header: block(parameters.height ?? state.tip).signed_header };
    if (method === '/validators') { const h = Number(parameters.height); if (h > state.tip + 1) throw new IndexerError('RPC_REFUSED', 'height is not available'); return { block_height: parameters.height, total: '4', validators: h <= fixture.blocks.length ? fixture.blocks[h - 1].validators : fixture.blocks.at(-1).next_validators }; }
    throw new IndexerError('RPC_REFUSED', 'not available on this node');
  };
}
async function lab(run, options = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-touches-'));
  const state = { tip: 4, clock: fixture.now_ms };
  let service;
  try {
    service = await createApiService({
      trust: fixture.trust, rpc: fakeRpc(state), verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false, pollMs: 5,
      now: () => state.clock, readState: async () => { throw new Error('no state here'); }, rateLimit: { perSecond: 1000, burst: 100000 }, trustedProxies: ['127.0.0.1'], ...options,
    });
    await run({ service, state });
  } finally { await service?.close(); await rm(directory, { recursive: true, force: true }); }
}
async function indexTo(service, height) { for (let i = 0; i < 50 && (service.store.high() ?? 0) < height; i++) await service.indexer.step(); assert.equal(service.store.high(), height); }
/// Reads a stream of server-sent events, keeping every line of every event as it came.
async function openStream(service, route, client = '203.0.113.9') {
  const controller = new AbortController();
  const response = await fetch(service.url + route, { headers: { 'X-Forwarded-For': client }, signal: controller.signal });
  if (response.status !== 200) return { status: response.status, body: await response.json(), close: async () => {} };
  const events = [], reader = response.body.getReader(), decoder = new TextDecoder();
  let buffer = '', raw = '';
  const reading = (async () => {
    try {
      for (;;) {
        const { done, value } = await reader.read(); if (done) break;
        const text = decoder.decode(value, { stream: true }); raw += text; buffer += text;
        for (let end; (end = buffer.indexOf('\n\n')) >= 0; buffer = buffer.slice(end + 2)) {
          const event = { lines: buffer.slice(0, end).split('\n') };
          for (const line of event.lines) { const at = line.indexOf(': '); if (at > 0) event[line.slice(0, at)] = line.slice(at + 2); }
          if (event.event) events.push({ event: event.event, id: event.id ?? null, data: JSON.parse(event.data), lines: event.lines });
        }
      }
    } catch { /* closed */ }
  })();
  return {
    status: 200, events, raw: () => raw,
    waitFor: async (count) => { for (let i = 0; i < 400 && events.length < count; i++) await pause(5); assert(events.length >= count, `only ${events.length} of ${count} events: ${JSON.stringify(events.map((e) => e.event))}`); },
    close: async () => { controller.abort(); await reading; },
  };
}
const health = async (service) => (await (await fetch(`${service.url}/v1/health`)).json()).touch_streams;

test('a wallet that follows its account hears "touched at height H" for the blocks that name it, and nothing else', async () => {
  await lab(async ({ service }) => {
    const shop = await openStream(service, '/v1/touches?account=1'), payer = await openStream(service, '/v1/touches?account=7', '203.0.113.10'), other = await openStream(service, '/v1/touches?account=55', '203.0.113.11');
    await Promise.all([shop.waitFor(1), payer.waitFor(1), other.waitFor(1)]);
    assert.deepEqual(shop.events[0].data, { source: 'index', proven: false, index: shop.events[0].data.index, account: '1', direction: null });
    assert.equal(await health(service), 3);
    await indexTo(service, 4);
    await Promise.all([shop.waitFor(3), payer.waitFor(3)]);
    await pause(30);
    // One hint per block that names the account, however many of its actions do (block 2 has two).
    assert.deepEqual(shop.events.slice(1).map((e) => e.data), [{ source: 'index', proven: false, account: '1', height: '2' }, { source: 'index', proven: false, account: '1', height: '4' }]);
    assert.deepEqual(payer.events.slice(1).map((e) => [e.data.account, e.data.height]), [['7', '2'], ['7', '4']]);
    assert.deepEqual(other.events.map((e) => e.event), ['hello']);
    // A hint carries the account, the height and that it is not proven: no amount, no name, no kind, no text. No event has an id.
    for (const event of [...shop.events, ...payer.events]) {
      assert.equal(event.id, null);
      assert.ok(!event.lines.some((line) => line.startsWith('id:')));
      if (event.event === 'touch') assert.deepEqual(Object.keys(event.data).sort(), ['account', 'height', 'proven', 'source']);
    }
    assert.ok(!/amount|kind|name|"to"|sender|recipient/.test(shop.raw().replace(/"index":\{[^}]*\}/, '')));
    await Promise.all([shop.close(), payer.close(), other.close()]);
    // Nothing is kept for a connection that closed.
    for (let i = 0; i < 100 && await health(service) !== 0; i++) await pause(5);
    assert.equal(await health(service), 0);
  });
});

test('nothing is sent again: a wallet that reconnects gets no touch of the past, and an id it names is not read', async () => {
  await lab(async ({ service }) => {
    await indexTo(service, 4);
    const back = await openStream(service, '/v1/touches?account=1');
    await back.waitFor(1); await pause(30);
    assert.deepEqual(back.events.map((e) => e.event), ['hello']);
    await back.close();
    // The way the event stream of payments resumes is no parameter here.
    for (const route of ['/v1/touches?account=1&after=2', '/v1/touches?account=1&direction=in', '/v1/touches', '/v1/touches?account=01', '/v1/touches?account=alice']) {
      const refused = await openStream(service, route);
      assert.equal(refused.status, 400, route);
    }
  });
});

test('a block the index reaches long after it was made is hinted to nobody', async () => {
  await lab(async ({ service, state }) => {
    state.clock = fixture.now_ms + 10 * 60 * 1000; // ten minutes later: the index is catching up
    const late = await openStream(service, '/v1/touches?account=1');
    await late.waitFor(1);
    await indexTo(service, 4); await pause(30);
    assert.deepEqual(late.events.map((e) => e.event), ['hello']);
    await late.close();
  });
});

test('places: a holder has at most its share, all of them are bounded, and when all are taken the holder with the most gives one up', async () => {
  await lab(async ({ service, state }) => {
    const open = [];
    for (let i = 0; i < 2; i++) open.push(await openStream(service, '/v1/touches?account=1', '198.51.100.7'));
    const third = await openStream(service, '/v1/touches?account=1', '198.51.100.7');
    assert.deepEqual([third.status, third.body.error.code], [503, 'too_many_streams']);
    // Within one IPv6 /56, every /64 is the same holder.
    open.push(await openStream(service, '/v1/touches?account=7', '2001:db8:0:100::1'), await openStream(service, '/v1/touches?account=7', '2001:db8:0:1ff::1'));
    assert.equal((await openStream(service, '/v1/touches?account=7', '2001:db8:0:1aa::1')).status, 503);
    // Four places in all, all taken. A newcomer is refused while every stream is young...
    assert.equal((await openStream(service, '/v1/touches?account=9', '192.0.2.1')).status, 503);
    // ...and later the holder with the most streams gives up its oldest one.
    state.clock += 6000;
    const newcomer = await openStream(service, '/v1/touches?account=9', '192.0.2.1');
    assert.equal(newcomer.status, 200);
    await open[0].waitFor(2);
    assert.deepEqual([open[0].events.at(-1).event, open[0].events.at(-1).data.reason], ['bye', 'evicted']);
    for (const s of [...open, newcomer]) await s.close();
  }, { maxTouchStreams: 4, maxTouchStreamsPerClient: 2 });
  await lab(async ({ service }) => {
    const off = await openStream(service, '/v1/touches?account=1');
    assert.deepEqual([off.status, off.body.error.code], [503, 'touches_off']);
  }, { maxTouchStreams: 0 });
  await assert.rejects(lab(async () => {}, { maxTouchStreamsPerClient: 0 }), /maxTouchStreamsPerClient/);
});

test('a stream is ended after its lifetime and kept open with comments meanwhile', async () => {
  await lab(async ({ service, state }) => {
    const s = await openStream(service, '/v1/touches?account=1');
    await s.waitFor(1);
    service.tendStreams();
    await pause(20);
    assert.match(s.raw(), /: keep-alive\n\n/);
    state.clock += 61 * 1000;
    service.tendStreams();
    await s.waitFor(2);
    assert.deepEqual([s.events[1].event, s.events[1].data.reason], ['bye', 'lifetime']);
    await s.close();
    assert.equal(await health(service), 0);
  }, { maxStreamSeconds: 60 });
});
