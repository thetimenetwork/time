// The gateway's two limits a second (server.mjs): the page's own files do not count against the limit of what asks the
// node. Opening the wallet asks for about forty files; under one limit of 50 for everything, two people opening it in
// the same second left each other a page with parts refused, which never started (a real browser, 2026-11-23).
import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createV4Servers } from './server.mjs';

const fixture = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/proof.json', import.meta.url), 'utf8'));
const b = fixture.proof.light_block;
const rpc = async (endpoint, p = {}) => {
  if (endpoint === '/commit') return { signed_header: b.signed_header };
  if (endpoint === '/validators') return { block_height: p.height, total: '4', validators: p.height === '6' ? b.validators : b.next_validators };
  if (endpoint === '/abci_query') return { response: { height: '5', code: 0, value: Buffer.from(JSON.stringify({ height: '5', root: b.signed_header.header.app_hash.toLowerCase(), entries: fixture.proof.entries, history_proofs: fixture.proof.history_proofs })).toString('base64') } };
  throw Error('Unexpected RPC');
};
const root = fileURLToPath(new URL('../', import.meta.url));
/// A gateway whose clock stands still, so that every request of a test falls in the same second.
async function withGateway(work) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-gateway-limits-')), originalNow = Date.now;
  let servers = null;
  try {
    Date.now = () => fixture.now_ms;
    servers = await createV4Servers({ root, manifest: { networkId: fixture.trust.network_id, chainId: fixture.trust.chain_id, trust: fixture.trust }, rpc, walletPort: 0, merchantPort: 0,
      checkpointPath: path.join(directory, 'checkpoint.json'), ordersPath: path.join(directory, 'orders.json'), upgradeCheck: { everyMs: 0 } });
    return await work(servers);
  } finally { Date.now = originalNow; await servers?.close(); await rm(directory, { recursive: true, force: true }); }
}
const statusOf = async (url) => { const response = await fetch(url); await response.arrayBuffer(); return response.status; };
const count = (list, value) => list.filter((status) => status === value).length;

test('three openings of the wallet in one second are all served, and what asks the node is still held to 50 a second', async () => {
  await withGateway(async (servers) => {
    const wallet = servers.walletListenOrigin;
    // The files of the page, as often as three openings ask for them, all within one second.
    const files = ['/', '/styles.css', '/app.js', '/alerts.mjs', '/sw.js', '/sdk/time-sdk.js'];
    const asked = []; for (let i = 0; i < 20; i++) for (const file of files) asked.push(statusOf(wallet + file));
    const served = await Promise.all(asked);
    assert.equal(served.length, 120);
    assert.equal(count(served, 200), 120, `a file of the page was refused: ${JSON.stringify([...new Set(served)])}`);
    // The files did not use up what the node's routes may take: 50 of those are answered in the same second, and the rest refused.
    const reads = []; for (let i = 0; i < 60; i++) reads.push(statusOf(wallet + '/api/network'));
    const answered = await Promise.all(reads);
    assert.equal(count(answered, 200), 50, `of 60 reads in one second: ${JSON.stringify(answered)}`);
    assert.equal(count(answered, 429), 10);
    // And the other way round: the page's files are still served while the node's routes are refused.
    assert.equal(await statusOf(wallet + '/styles.css'), 200);
    assert.equal(await statusOf(wallet + '/api/network'), 429);
  });
});

test('the page\'s files have a limit too, far above what people opening the wallet ask for', async () => {
  await withGateway(async (servers) => {
    const wallet = servers.walletListenOrigin, results = [];
    // In batches, so that the test does not open a thousand connections at once.
    for (let batch = 0; batch < 11; batch++) results.push(...await Promise.all(Array.from({ length: 100 }, () => statusOf(wallet + '/sw.js'))));
    assert.equal(count(results, 200), 1000);
    assert.equal(count(results, 429), 100);
  });
});

test('a POST counts as work whatever its path, and the shop\'s page has the same two limits of its own', async () => {
  await withGateway(async (servers) => {
    const shop = servers.merchantListenOrigin;
    const pages = await Promise.all(Array.from({ length: 80 }, () => statusOf(shop + '/')));
    assert.equal(count(pages, 200), 80);
    const posts = await Promise.all(Array.from({ length: 55 }, async () => { const response = await fetch(shop + '/not-a-route', { method: 'POST', body: '{}' }); await response.arrayBuffer(); return response.status; }));
    assert.equal(count(posts, 429), 5, `of 55 posts in one second: ${JSON.stringify([...new Set(posts)])}`);
  });
});
