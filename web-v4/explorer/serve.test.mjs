// The API service serving the explorer (the serve_explorer setting): only the fixed files, with
// the headers a page needs, and no path trick reaches anything else. Also the routes the explorer
// reads beyond the ones the API had, over the same fake node as client-v4/api.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { readFile, readdir, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import '../../client-v4/time-sdk.js';
import * as verifier from '../../client-v4/proof-verifier.mjs';
import { createLightClient } from '../../client-v4/light-client.mjs';
import { createApiService, EXPLORER_FILES, EXPLORER_CSP, checkExplorerJoin } from '../../client-v4/api.mjs';
import { IndexerError, describeAction } from '../../client-v4/indexer.mjs';
import { validateConfig, start } from '../../deploy/api/start.mjs';
import { createApi } from './client.mjs';
import { createChecker } from './check.mjs';
import { readJoin } from './format.mjs';

const root = new URL('../../', import.meta.url);
const chain = JSON.parse(await readFile(new URL('verifier-v4/fixtures/fast-receipt.json', root), 'utf8'));
const proven = JSON.parse(await readFile(new URL('verifier-v4/fixtures/proof.json', root), 'utf8'));
const sha = (bytes) => createHash('sha256').update(bytes).digest();

function fakeRpc(tip = 4) {
  const block = (h) => { const b = chain.blocks[Number(h) - 1]; if (!b || Number(h) > tip) throw new IndexerError('RPC_REFUSED', 'height is not available'); return b; };
  return async (method, parameters = {}) => {
    if (method === '/status') return { node_info: { network: chain.trust.chain_id }, sync_info: { latest_block_height: String(tip) } };
    if (method === '/block') return { block: { header: block(parameters.height).signed_header.header, data: { txs: chain.txs[parameters.height] } } };
    if (method === '/blockchain') { const metas = []; for (let h = Number(parameters.maxHeight); h >= Number(parameters.minHeight); h--) metas.push({ header: block(h).signed_header.header }); return { block_metas: metas }; }
    if (method === '/commit') return { signed_header: block(parameters.height ?? tip).signed_header };
    if (method === '/validators') { const h = Number(parameters.height); if (h > tip + 1) throw new IndexerError('RPC_REFUSED', 'height is not available'); return { block_height: parameters.height, total: '4', validators: h <= chain.blocks.length ? chain.blocks[h - 1].validators : chain.blocks.at(-1).next_validators }; }
    throw new IndexerError('RPC_REFUSED', 'not available on this node');
  };
}
const STATE = { network_id: chain.trust.network_id, height: '3', time_micros: '1000003000000', protocol_version: '4', genesis: { genesis_time_micros: '1000001000000' }, config: {} };
async function lab(run, options = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-explorer-serve-'));
  const service = await createApiService({ trust: chain.trust, rpc: fakeRpc(), verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false, pollMs: 5, now: () => chain.now_ms, rateLimit: { perSecond: 1000, burst: 100000 },
    readState: async (selection) => ({ verified: true, requested: selection, proof: { height: '3', entries: [] }, state: { ...STATE, accounts: [] } }), ...options });
  try {
    for (let i = 0; i < 50 && (service.store.high() ?? 0) < 4; i++) await service.indexer.step();
    await run(service);
  } finally { await service.close(); await rm(directory, { recursive: true, force: true }); }
}
/// A request with the exact target given: `fetch` would tidy up dot segments before sending.
const raw = (service, target, method = 'GET', headers = {}) => new Promise((resolve, reject) => {
  const url = new URL(service.url);
  const request = http.request({ host: url.hostname, port: url.port, path: target, method, headers }, (response) => { const chunks = []; response.on('data', (chunk) => chunks.push(chunk)); response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks) })); });
  request.on('error', reject); request.end();
});

test('off by default: without the setting the service serves no page', async () => {
  assert.equal(validateConfig({ rpc_url: 'http://127.0.0.1:26657/', trust: chain.trust, data_directory: path.resolve('/var/lib/time-api') }).serve_explorer, undefined);
  assert.equal(validateConfig({ rpc_url: 'http://127.0.0.1:26657/', trust: chain.trust, data_directory: path.resolve('/var/lib/time-api'), serve_explorer: true }).serve_explorer, true);
  assert.equal(validateConfig({ rpc_url: 'http://127.0.0.1:26657/', trust: chain.trust, data_directory: path.resolve('/var/lib/time-api'), serve_explorer: false }).serve_explorer, undefined);
  for (const value of ['yes', 1, null, 'true', {}]) assert.throws(() => validateConfig({ rpc_url: 'http://127.0.0.1:26657/', trust: chain.trust, data_directory: path.resolve('/var/lib/time-api'), serve_explorer: value }), /serve_explorer is true or false/);
  await lab(async (service) => {
    for (const target of ['/explorer/', '/explorer', '/explorer/app.js', '/explorer/trust-manifest.json', '/explorer/join.json', '/']) {
      const answer = await raw(service, target);
      assert.equal(answer.status, 404, target);
      assert.equal(JSON.parse(answer.body).error.code, 'unknown_route');
    }
  });
});

test('with the setting: exactly the fixed files, each with its type and the headers of a page', async () => {
  await lab(async (service) => {
    // Every file of the list is served, byte for byte, and the list names every file the page loads.
    for (const [name, location, type] of EXPLORER_FILES) {
      const answer = await raw(service, `/explorer/${name}`);
      assert.equal(answer.status, 200, name);
      assert.deepEqual(answer.body, await readFile(new URL(location, new URL('client-v4/', root))), name);
      assert.equal(answer.headers['content-type'], type, name);
      assert.equal(answer.headers['content-security-policy'], EXPLORER_CSP, name);
      // The page and its modules are asked about every time by their validator ("not changed" costs no
      // bytes), so that files of two releases never run together; only the compiled verifier is kept a while.
      const keep = type === 'application/wasm' ? 'max-age=300' : 'no-cache';
      assert.deepEqual([answer.headers['x-content-type-options'], answer.headers['x-frame-options'], answer.headers['referrer-policy'], answer.headers['cross-origin-resource-policy'], answer.headers['cache-control']], ['nosniff', 'DENY', 'no-referrer', 'same-origin', keep], name);
      assert.match(answer.headers.etag, /^"[0-9a-f]{32}"$/, name);
      const again = await raw(service, `/explorer/${name}`, 'GET', { 'If-None-Match': answer.headers.etag });
      assert.deepEqual([again.status, again.body.length, again.headers.etag, again.headers['content-security-policy'], again.headers['cache-control']], [304, 0, answer.headers.etag, EXPLORER_CSP, keep], name);
      // The validator is honoured as browsers and proxies send it: marked weak, in a list, or as "any".
      for (const sent of [`W/${answer.headers.etag}`, `"other", ${answer.headers.etag}`, `"a",W/${answer.headers.etag} , "b"`, '*']) assert.equal((await raw(service, `/explorer/${name}`, 'GET', { 'If-None-Match': sent })).status, 304, `${name} ${sent}`);
      for (const sent of [answer.headers.etag.slice(1, -1), `"x${answer.headers.etag.slice(1)}`, 'W/"other"', '']) assert.equal((await raw(service, `/explorer/${name}`, 'GET', { 'If-None-Match': sent })).status, 200, `${name} ${sent}`);
      assert.equal((await raw(service, `/explorer/${name}`, 'GET', { 'If-None-Match': '"00000000000000000000000000000000"' })).status, 200, name);
      assert.equal(answer.headers['access-control-allow-origin'], undefined, name);
    }
    // The policy: scripts and styles from this origin only, no inline code, no outside address, no framing.
    assert.match(EXPLORER_CSP, /^default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'$/);
    assert.doesNotMatch(EXPLORER_CSP, /unsafe-inline|'unsafe-eval'|\*|https?:|data:|blob:/);
    // The page's modules are all on the list: nothing it imports would be missing.
    const served = new Set(EXPLORER_FILES.map(([name]) => name));
    const modules = (await readdir(new URL('web-v4/explorer/', root))).filter((name) => /\.(?:mjs|js|css|html)$/.test(name) && !name.endsWith('.test.mjs') && !name.startsWith('review')); // review-fake-page.mjs and review2-old-views.mjs belong to the reviews' tests
    for (const name of modules) assert(served.has(name), `${name} is served`);
    for (const name of served) assert(!name.endsWith('.test.mjs') && !name.includes('README'), name);
    for (const name of modules.filter((file) => /\.m?js$/.test(file))) for (const [, imported] of (await readFile(new URL(`web-v4/explorer/${name}`, root), 'utf8')).matchAll(/(?:from|import\()\s*'\.\/([^']+)'/g)) assert(served.has(imported), `${name} imports ${imported}`);
    const html = await readFile(new URL('web-v4/explorer/index.html', root), 'utf8');
    for (const [, address] of html.matchAll(/\s(?:src|href)="([a-z][^"#]*)"/g)) assert(served.has(address), `index.html loads ${address}`);
    // The SDK's verifier module finds the compiled verifier where it looks for it, relative to itself.
    const loader = await readFile(new URL('client-v4/proof-verifier.mjs', root), 'utf8');
    for (const [, relative] of loader.matchAll(/new URL\('([^']+)',import\.meta\.url\)/g)) assert(served.has(new URL(relative, 'http://x/explorer/sdk/proof-verifier.mjs').pathname.replace('/explorer/', '')), relative);
    // The address without the last slash leads to the one with it.
    const moved = await raw(service, '/explorer');
    assert.deepEqual([moved.status, moved.headers.location], [308, '/explorer/']);
    // The API is still there, with its own headers.
    const status = await raw(service, '/v1/status');
    assert.deepEqual([status.status, status.headers['content-security-policy']], [200, "default-src 'none'; frame-ancestors 'none'"]);
  }, { explorer: true });
});

test('with the setting: nothing but those files, whatever the path says', async () => {
  await lab(async (service) => {
    const tricks = ['/explorer/../client-v4/api.mjs', '/explorer/..%2f..%2fdeploy/api/config.example.json', '/explorer/%2e%2e/%2e%2e/README.md', '/explorer/./app.js', '/explorer//app.js', '/explorer/sdk/../../deploy/api/start.mjs', '/explorer/sdk/server.mjs', '/explorer/sdk/api.mjs', '/explorer/sdk/indexer.mjs',
      '/explorer/views.test.mjs', '/explorer/README.md', '/explorer/app.js/', '/explorer/APP.JS', '/explorer/app.js%00.css', '/explorer/app.js?x=1', '/explorer/?x', '/explorer/app.js?', '/explorer/?', '/explorer?', '/explorer/index.html?', '/explorer/trust-manifest.json?', '/explorer/index.html#x', '/explorer\\app.js', '/explorer/..\\..\\README.md', '/explorer/web-v4/shared/verifier/../../../README.md',
      '/explorer/web-v4/shared/verifier/timecurrency_verifier_v4.d.ts', '/explorer/web-v4/wallet/app.js', '/explorer/index.sqlite', '/explorer/c:/windows/win.ini', '/explorer//etc/passwd', '//explorer/app.js', '/explorer/%61pp.js', '/explorer/app%2ejs', '/Explorer/', '/explorer/constructor', '/explorer/__proto__', '/explorerx', '/explorer/' + 'a'.repeat(3000)];
    for (const target of tricks) {
      const answer = await raw(service, target);
      assert([400, 404, 414].includes(answer.status), `${target} answered ${answer.status}`);
      const body = JSON.parse(answer.body);
      assert(['unknown_route', 'invalid_url', 'url_too_long'].includes(body.error.code), `${target}: ${body.error.code}`);
      assert(!answer.body.toString().includes('import '), target);
    }
    // Only GET: a page is not posted to, and another method gets no file.
    for (const method of ['POST', 'PUT', 'DELETE', 'HEAD']) assert.notEqual((await raw(service, '/explorer/app.js', method)).status, 200, method);
    // Another host name, and another site's page asking for the files, are refused as for the API.
    assert.equal((await raw(service, '/explorer/', 'GET', { Host: 'evil.example' })).status, 421);
    assert.equal((await raw(service, '/explorer/app.js', 'GET', { Origin: 'https://evil.example' })).status, 403);
  }, { explorer: true });
  // A page is a dozen files: each takes a tenth of what an API request takes from the caller's
  // allowance, so that loading the page leaves the allowance for the API. They are still limited.
  await lab(async (service) => {
    const statuses = [];
    for (let i = 0; i < 30; i++) statuses.push((await raw(service, i % 2 ? '/explorer/app.js' : '/explorer/')).status);
    const passed = statuses.indexOf(429);
    assert(passed >= 18 && passed <= 21, `an allowance of 2 was used up after ${passed} files`);
    assert(statuses.slice(0, passed).every((status) => status === 200) && statuses.slice(passed).every((status) => status === 429));
    const limited = await raw(service, '/explorer/styles.css');
    assert.deepEqual([limited.status, JSON.parse(limited.body).error.code, limited.headers['retry-after'] !== undefined], [429, 'rate_limited', true]);
  }, { explorer: true, rateLimit: { perSecond: 1, burst: 2 } });
  // What costs the service more is charged more: the compiled verifier by its size (a megabyte),
  // the trust manifest (it reads the database) and a path that names no file like an API request.
  // A "not changed" answer costs the small charge whatever the file.
  for (const [target, least, most, headers] of [['/explorer/web-v4/shared/verifier/timecurrency_verifier_v4_bg.wasm', 10, 20, {}], ['/explorer/trust-manifest.json', 60, 60, {}], ['/explorer/nothing.js', 60, 60, {}], ['/explorer/app.js?', 60, 60, {}]]) {
    await lab(async (service) => {
      let served = 0;
      for (; served < 700; served++) { const answer = await raw(service, target, 'GET', headers); if (answer.status === 429) break; }
      assert(served >= least && served <= most, `${target}: ${served} answers from an allowance of 60`);
    }, { explorer: true, rateLimit: {} });
  }
  await lab(async (service) => {
    const wasm = '/explorer/web-v4/shared/verifier/timecurrency_verifier_v4_bg.wasm', etag = (await raw(service, wasm)).headers.etag;
    let unchanged = 0;
    for (; unchanged < 700; unchanged++) { const answer = await raw(service, wasm, 'GET', { 'If-None-Match': etag }); if (answer.status !== 304) break; }
    assert(unchanged >= 500, `${unchanged} "not changed" answers for the verifier from what one download left of an allowance of 60`);
  }, { explorer: true, rateLimit: {} });
  // One load of the home page (its files, the manifest, the status, the lists, the stream) against the default allowance of 60.
  await lab(async (service) => {
    const html = await readFile(new URL('web-v4/explorer/index.html', root), 'utf8');
    const files = ['', ...[...html.matchAll(/\s(?:src|href)="([a-z][^"#]*)"/g)].map((match) => match[1]), 'strings.mjs', 'client.mjs', 'check.mjs', 'views.mjs', 'format.mjs', 'dom.mjs', 'route.mjs', 'describe.mjs', 'trust-manifest.json'];
    let loads = 0;
    for (; loads < 10; loads++) {
      const answers = [];
      for (const name of files) answers.push((await raw(service, `/explorer/${name}`)).status);
      for (const target of ['/v1/status', '/v1/blocks?limit=50', '/v1/validators', '/v1/validators']) answers.push((await raw(service, target)).status); // the two validators stand in for the stream's 10
      if (answers.some((status) => status !== 200)) break;
    }
    assert(loads >= 4, `${loads} loads of the home page from one address before anything was refused (it was 2)`);
  }, { explorer: true, rateLimit: {} });
});

test('the page\'s trust manifest is the configured one, moved to the newest block the service verified', async () => {
  await lab(async (service) => {
    const answer = await raw(service, '/explorer/trust-manifest.json');
    assert.equal(answer.status, 200);
    assert.equal(answer.headers['content-type'], 'application/json; charset=utf-8');
    // It moves with every verified block, so a browser never keeps it.
    assert.deepEqual([answer.headers['cache-control'], answer.headers.etag], ['no-store', undefined]);
    const manifest = JSON.parse(answer.body);
    // The indexer's light client has verified up to block 4: the page starts from there.
    assert.deepEqual([manifest.network_id, manifest.chain_id, manifest.app_version, manifest.checkpoint.height], [chain.trust.network_id, chain.trust.chain_id, '4', '4']);
    assert.equal(chain.trust.checkpoint ?? null, null, 'the configured manifest has no checkpoint: the one served was verified here');
    // A light client accepts it as its anchor, and it holds nothing but the manifest.
    const light = createLightClient({ trust: manifest, verifier, now: () => chain.now_ms, fetchBlock: async () => { throw new Error('not needed'); } });
    await light.ready();
    assert.equal(light.getCheckpoint().height, '4');
    assert.deepEqual(Object.keys(manifest).sort(), [...new Set([...Object.keys(chain.trust), 'checkpoint'])].sort());
    // A page that starts from it checks an action of the very block it starts at.
    const checker = createChecker({ api: createApi({ origin: service.url }), loadTrust: async () => manifest, loadVerifier: async () => verifier, createLightClient, sdk: globalThis.TimeSDK, now: () => chain.now_ms });
    const newest = await checker.checkAction(sha(Buffer.from(chain.txs['4'][0], 'base64')).toString('hex'));
    assert.deepEqual([newest.height, newest.mode, newest.anchorHeight], ['4', 'own-block', '4']);
  }, { explorer: true });
});

/// A port of this machine that the system itself chose and says is free. The start script's settings take a port
/// from 1024 up and no "any port", and a port picked at random can be one that another program holds.
const freePort = () => new Promise((resolve, reject) => {
  const probe = net.createServer();
  probe.once('error', reject);
  probe.listen(0, '127.0.0.1', () => { const { port } = probe.address(); probe.close((error) => (error ? reject(error) : resolve(port))); });
});

/// This network's facts for "Run a validator", as an operator sets them in explorer_join.
const JOIN = Object.freeze({ script_url: 'https://join.example/join/join.sh', wallet_url: 'https://wallet.example', chain_id: chain.trust.chain_id, min_self_bond_micros: '1000000',
  files: { node_sha256: 'a1'.repeat(32), cometbft_sha256: 'b2'.repeat(32), genesis_sha256: 'c3'.repeat(32) }, peers: [`${'0f'.repeat(20)}@203.0.113.7:26656`], pace: '500ms' });

test('the start script passes the settings on', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-explorer-start-'));
  const logs = [];
  const running = await start({ rpc_url: 'http://127.0.0.1:26657/', trust: chain.trust, data_directory: directory, port: await freePort(), serve_explorer: true, explorer_join: JOIN }, { rpc: fakeRpc(), log: (level, message, fields) => logs.push({ message, ...fields }), now: () => chain.now_ms, pollMs: 5, readState: async () => ({ verified: true, state: { ...STATE, accounts: [] } }) });
  try {
    const page = await raw(running, '/explorer/');
    assert.equal(page.status, 200);
    assert.match(page.body.toString(), /<title>Time explorer<\/title>/);
    const join = await raw(running, '/explorer/join.json');
    assert.deepEqual([join.status, JSON.parse(join.body)], [200, JOIN]);
    const started = logs.find((entry) => entry.message === 'time api started');
    assert.deepEqual([started.serve_explorer, started.explorer_join], [true, true]);
    assert(!JSON.stringify(started).includes('join.example'), 'the log says that the setting is there, not what it holds');
  } finally { await running.close(); await rm(directory, { recursive: true, force: true }); }
});

test('explorer_join: checked strictly at start, only with serve_explorer, and never quoted in a refusal', async () => {
  const base = { rpc_url: 'http://127.0.0.1:26657/', trust: chain.trust, data_directory: path.resolve('/var/lib/time-api'), serve_explorer: true };
  assert.deepEqual(validateConfig({ ...base, explorer_join: JOIN }).explorer_join, JOIN);
  const { pace, ...unpaced } = JOIN;
  assert.deepEqual(validateConfig({ ...base, explorer_join: unpaced }).explorer_join, unpaced, 'pace is optional');
  assert.equal(pace, '500ms');
  assert.equal(Object.hasOwn(validateConfig(base), 'explorer_join'), false);
  for (const serve of [undefined, false]) assert.throws(() => validateConfig({ ...base, serve_explorer: serve, explorer_join: JOIN }), /^Error: explorer_join is shown by the explorer this service serves: it needs "serve_explorer": true$/);
  const SECRET = 'zz9secret9zz';
  const refusals = [
    [{ script_url: `http://join.example/join/join.sh` }, /^explorer_join\.script_url is the https:\/\/ address of the join script/], [{ script_url: `https://${SECRET}.example/join/other.sh` }, /script_url/], [{ script_url: `https://${SECRET}:pw@join.example/join/join.sh` }, /script_url/],
    [{ script_url: `https://join.example/join/join.sh?${SECRET}` }, /script_url/], [{ script_url: `javascript:${SECRET}` }, /script_url/], [{ script_url: 'https://join.example:443/join/join.sh' }, /script_url/], [{ script_url: 7 }, /script_url/],
    [{ wallet_url: `https://wallet.example/${SECRET}` }, /^explorer_join\.wallet_url is the https:\/\/ origin of the wallet/], [{ wallet_url: 'https://wallet.example/' }, /wallet_url/], [{ wallet_url: `http://${SECRET}.example` }, /wallet_url/], [{ wallet_url: 'https://127.0.0.1' }, /wallet_url/],
    [{ chain_id: `<img src=x onerror=${SECRET}>` }, /^explorer_join\.chain_id is 3 to 64 of a-z, 0-9 and -$/], [{ chain_id: `time-devnet-v4-${SECRET}` }, /^explorer_join\.chain_id is not the chain id of trust/],
    [{ min_self_bond_micros: '0' }, /min_self_bond_micros/], [{ min_self_bond_micros: '1000000000000001' }, /min_self_bond_micros/], [{ min_self_bond_micros: 1000000 }, /min_self_bond_micros/],
    [{ files: { ...JOIN.files, node_sha256: SECRET } }, /^explorer_join\.files holds node_sha256, cometbft_sha256 and genesis_sha256/], [{ files: { ...JOIN.files, extra: 'a1'.repeat(32) } }, /files/], [{ files: { node_sha256: 'a1'.repeat(32) } }, /files/],
    [{ peers: [`${'0f'.repeat(20)}@${SECRET}.example:26656`] }, /^explorer_join\.peers lists 1 to 8 entry nodes/], [{ peers: [] }, /peers/], [{ peers: Array(9).fill(0).map((_, i) => `${'0f'.repeat(20)}@10.0.0.${i}:26656`) }, /peers/], [{ peers: [JOIN.peers[0], JOIN.peers[0]] }, /peers/],
    [{ pace: `${SECRET}` }, /^explorer_join\.pace is "100ms" to "999ms", or "1s" to "5s"$/], [{ pace: '6s' }, /pace/],
    [{ [SECRET]: 1 }, /^explorer_join takes script_url, wallet_url, chain_id, min_self_bond_micros, files, peers and pace, nothing else$/],
  ];
  for (const [change, words] of refusals) assert.throws(() => validateConfig({ ...base, explorer_join: { ...JOIN, ...change } }), (error) => words.test(error.message) && !error.message.includes(SECRET), JSON.stringify(change));
  const { peers: _, ...withoutPeers } = JOIN;
  assert.throws(() => validateConfig({ ...base, explorer_join: withoutPeers }), /^Error: explorer_join needs script_url, wallet_url, chain_id, min_self_bond_micros, files and peers$/);
  for (const value of [null, [], 'https://join.example/join/join.sh', 7, true]) assert.throws(() => validateConfig({ ...base, explorer_join: value }), /^Error: explorer_join is an object/, JSON.stringify(value));
  // The service itself takes it only with the explorer, and checks it the same way.
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-explorer-join-'));
  try {
    for (const [options, words] of [[{ explorerJoin: JOIN }, /needs serve_explorer/], [{ explorer: true, explorerJoin: { ...JOIN, chain_id: 'time-devnet-v4-other' } }, /not the chain id of trust/], [{ explorer: true, explorerJoin: { ...JOIN, wallet_url: 'http://wallet.example' } }, /wallet_url/]]) {
      await assert.rejects(createApiService({ trust: chain.trust, rpc: fakeRpc(), verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false, ...options }), words);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('/explorer/join.json: this network\'s facts exactly as set, with the headers of a page and never kept; without the setting no such file', async () => {
  await lab(async (service) => {
    const answer = await raw(service, '/explorer/join.json');
    assert.equal(answer.status, 200);
    // Exactly the object of the setting: nothing added, nothing left out, in its fixed order.
    assert.equal(answer.body.toString(), JSON.stringify(JOIN));
    assert.equal(answer.headers['content-type'], 'application/json; charset=utf-8');
    assert.deepEqual([answer.headers['cache-control'], answer.headers.etag, answer.headers['content-security-policy'], answer.headers['x-content-type-options'], answer.headers['x-frame-options'], answer.headers['referrer-policy'], answer.headers['cross-origin-resource-policy'], answer.headers['access-control-allow-origin']],
      ['no-store', undefined, EXPLORER_CSP, 'nosniff', 'DENY', 'no-referrer', 'same-origin', undefined]);
    // The page's own reading of the file takes it whole.
    assert.deepEqual(readJoin(answer.body.toString()), JOIN);
    // Its one address, and only with GET.
    for (const target of ['/explorer/join.json?', '/explorer/join.json?x=1', '/explorer/JOIN.json', '/explorer/join.json/', '/explorer/sdk/join.json', '/explorer//join.json', '/explorer/join%2ejson', '/explorer/./join.json', '/join.json', '/v1/join.json']) {
      const refused = await raw(service, target);
      assert([400, 404].includes(refused.status), `${target} answered ${refused.status}`);
      assert(!refused.body.toString().includes('join.example'), target);
    }
    for (const method of ['POST', 'PUT', 'DELETE', 'HEAD']) assert.notEqual((await raw(service, '/explorer/join.json', method)).status, 200, method);
    assert.equal((await raw(service, '/explorer/join.json', 'GET', { Host: 'evil.example' })).status, 421);
    assert.equal((await raw(service, '/explorer/join.json', 'GET', { Origin: 'https://evil.example' })).status, 403);
  }, { explorer: true, explorerJoin: JOIN });
  // Without the setting it is a file the explorer does not have: 404, as for any unknown name.
  await lab(async (service) => {
    const answer = await raw(service, '/explorer/join.json');
    assert.deepEqual([answer.status, JSON.parse(answer.body).error.code, answer.headers['cache-control']], [404, 'unknown_route', 'no-store']);
  }, { explorer: true });
  // A small answer fixed at start: it takes a tenth of an API request, like a small file.
  await lab(async (service) => {
    const statuses = [];
    for (let i = 0; i < 30; i++) statuses.push((await raw(service, '/explorer/join.json')).status);
    const passed = statuses.indexOf(429);
    assert(passed >= 18 && passed <= 21, `an allowance of 2 was used up after ${passed} answers`);
  }, { explorer: true, explorerJoin: JOIN, rateLimit: { perSecond: 1, burst: 2 } });
});

test('explorer_join and the page\'s join.json are held to the same rules: the service never serves what the page would refuse', () => {
  const addresses = ['https://wallet.example', 'https://wallet.example:8443', 'https://d4api.cloudfront.net', 'https://join.example/join/join.sh', 'https://join.example:8443/join/join.sh', 'https://localhost:9443',
    'http://wallet.example', 'https://wallet.example/', 'https://wallet.example:443', 'https://wallet.example:0', 'https://wallet.example:65536', 'https://user@wallet.example', 'https://Wallet.example', 'https://0x7f.1', 'https://127.0.0.1',
    'https://join.example/join/join.sh?', 'https://join.example/join/other.sh', 'https://join.example//join/join.sh', 'javascript:alert(1)', '//wallet.example', ' https://wallet.example', `https://${'a'.repeat(64)}.example`, 'https://wallet.example.', 7, null];
  const peers = [`${'0f'.repeat(20)}@203.0.113.7:26656`, `${'0f'.repeat(20)}@255.255.255.255:65535`, `${'0f'.repeat(20)}@256.0.0.1:26656`, `${'0f'.repeat(20)}@01.2.3.4:26656`, `${'0f'.repeat(20)}@1.2.3.4:65536`, `${'0F'.repeat(20)}@1.2.3.4:1`, `${'0f'.repeat(20)}@node.example:26656`, 7];
  const samples = [JOIN, null, [], 'x', { ...JOIN, extra: 1 }, { ...JOIN, pace: undefined }];
  for (const address of addresses) samples.push({ ...JOIN, script_url: address }, { ...JOIN, wallet_url: address });
  for (const peer of peers) samples.push({ ...JOIN, peers: [peer] }, { ...JOIN, peers: [JOIN.peers[0], peer] });
  for (const chainId of ['ab', 'abc', 'a'.repeat(64), 'a'.repeat(65), 'A-b', 'a_b', 7]) samples.push({ ...JOIN, chain_id: chainId });
  for (const bond of ['0', '1', '01', '1000000000000000', '1000000000000001', '1e6', 5]) samples.push({ ...JOIN, min_self_bond_micros: bond });
  for (const pace of ['99ms', '100ms', '999ms', '1000ms', '0s', '1s', '5s', '6s', 500, null]) samples.push({ ...JOIN, pace });
  for (const hash of ['a1'.repeat(32), 'A1'.repeat(32), 'a1'.repeat(31), 'g1'.repeat(32)]) samples.push({ ...JOIN, files: { ...JOIN.files, genesis_sha256: hash } });
  samples.push({ ...JOIN, files: { ...JOIN.files, extra: 'a1'.repeat(32) } }, { ...JOIN, peers: [] }, { ...JOIN, peers: Array(8).fill(0).map((_, i) => `${'0f'.repeat(20)}@10.0.0.${i}:1`) }, { ...JOIN, peers: Array(9).fill(0).map((_, i) => `${'0f'.repeat(20)}@10.0.0.${i}:1`) });
  let accepted = 0;
  for (const sample of samples) {
    let service = true;
    try { checkExplorerJoin(sample, sample?.chain_id); } catch { service = false; }
    const pageTakes = readJoin(JSON.stringify(sample)) !== null;
    assert.equal(service, pageTakes, JSON.stringify(sample));
    if (service) accepted += 1;
  }
  assert(accepted >= 20 && accepted < samples.length - 50, `${accepted} of ${samples.length} accepted`);
});

// ------------------------------------------------------------------ the routes the explorer reads
test('a light block by height, as the node gives it, for a caller\'s own light client', async () => {
  await lab(async (service) => {
    const answer = await raw(service, '/v1/light-blocks/2'), body = JSON.parse(answer.body);
    assert.deepEqual([answer.status, body.source, body.proven, body.height, body.light_block.signed_header.header.height, body.light_block.validators.length, body.light_block.next_validators.length], [200, 'node', false, '2', '2', 4, 4]);
    assert.match(body.verify.how, /unchecked/);
    // A light client that trusts only its manifest verifies it.
    const api = createApi({ origin: service.url });
    const light = createLightClient({ trust: chain.trust, verifier, now: () => chain.now_ms, fetchBlock: async (height) => (await api.lightBlock(String(height))).light_block });
    assert.equal((await light.updateTo('3')).height, '3');
    // Not there yet, and not a height.
    assert.deepEqual([(await raw(service, '/v1/light-blocks/9')).status, JSON.parse((await raw(service, '/v1/light-blocks/9')).body).error.code], [404, 'not_found']);
    for (const target of ['/v1/light-blocks/0', '/v1/light-blocks/latest', '/v1/light-blocks/02', '/v1/light-blocks/2?prove=1']) assert.equal((await raw(service, target)).status, 400, target);
    assert.equal((await raw(service, '/v1/light-blocks/')).status, 404);
  });
  // A node that does not answer is 503 with a wait, not a 500.
  await lab(async (service) => {
    const answer = await raw(service, '/v1/light-blocks/2');
    assert.deepEqual([answer.status, JSON.parse(answer.body).error.code, answer.headers['retry-after']], [503, 'node_unavailable', '5']);
  }, { rpc: (() => { const rpc = fakeRpc(); let indexed = false; return async (method, parameters) => { if (method === '/status') indexed = true; if (indexed && method === '/commit' && parameters.height === '2' && new Error().stack.includes('fromNode')) throw new Error('down'); return rpc(method, parameters); }; })() });
});

test('validators and an account\'s state are passed on with their proof, and nothing is made up when a row is missing', async () => {
  const pos = { active: [{ owner: '0', consensus_key: 'aa'.repeat(32), power: '10' }], scheduled: [], safety_hold: false };
  const account = { id: '7', name: 'payer', balance: '85', nonce: '3', auth_epoch: '0', devices: [{ public_key: 'bb'.repeat(32), can_manage: false, can_spend: true }] };
  const security = { account: '7', version: '1', policy: { threshold: '2', daily_limit_micros: '60', delay_seconds: '60', freeze_seconds: '60' }, frozen_until_elapsed_micros: '0', pending_payments: [], pending_limit: null, pending_root: null };
  const selections = [];
  const readState = async (selection) => {
    selections.push(selection);
    return { verified: true, requested: selection, proof: { height: '3', entries: [], light_block: {} }, state: { ...STATE, accounts: selection.ids?.[0] === '7' ? [account] : [], ...(selection.include_pos ? { pos } : {}), ...(selection.include_security ? { security: selection.ids[0] === '7' ? [security] : [] } : {}),
      stake_owners: selection.owners ? { [selection.owners[0]]: selection.owners[0] === '7' ? { owner: '7', positions: [{ candidate: '0', shares: '5' }], exits: [] } : null } : {}, candidates: selection.candidates ? { [selection.candidates[0]]: null } : {}, recovery_cases: [],
      canonical_blocks: selection.blocks ? Object.fromEntries(selection.blocks.filter((h) => Number(h) <= 3).map((h) => [h, { hash: sha(Buffer.from(h)).toString('hex'), time_micros: `100000${h}000000` }])) : {} } };
  };
  await lab(async (service) => {
    const get = async (target) => { const answer = await raw(service, target); return { status: answer.status, body: JSON.parse(answer.body) }; };
    const validators = await get('/v1/validators');
    assert.deepEqual([validators.status, validators.body.source, validators.body.state_height, validators.body.pos, validators.body.protocol_version, validators.body.proof.query], [200, 'state_proof', '3', pos, '4', { include_pos: true }]);
    // The installed SDK does not read the upgrade row, so the state was not asked about it: the
    // answer then has no `upgrade` at all. "Not read" is never written as "none".
    assert.equal(Object.hasOwn(validators.body, 'upgrade'), false);
    assert(validators.body.proof.view_proof, 'the proof is passed on');
    const state = await get('/v1/accounts/7/state');
    assert.deepEqual([state.status, state.body.source, state.body.account, state.body.security, state.body.stake.positions, state.body.validator, state.body.recovery_cases, state.body.genesis_time_micros], [200, 'state_proof', account, security, [{ candidate: '0', shares: '5' }], null, [], '1000001000000']);
    assert.deepEqual(state.body.proof.query, { ids: ['7'], owners: ['7'], candidates: ['7'], include_security: true });
    const absent = await get('/v1/accounts/8/state');
    assert.deepEqual([absent.status, absent.body.error.code, absent.body.source, Boolean(absent.body.proof.view_proof)], [404, 'account_not_found', 'state_proof', true]);
    for (const target of ['/v1/accounts/payer/state', '/v1/accounts/07/state', '/v1/accounts/7/state?full=1', '/v1/validators?height=2']) assert.equal((await get(target)).status, 400, target);
    // A block and its successor in the history of the state, with their signed headers.
    const block = await get('/v1/blocks/2/proof');
    assert.deepEqual([block.status, block.body.source, block.body.block, block.body.next_block.height, block.body.signed_header.header.height, block.body.next_signed_header.header.height, block.body.proof.query],
      [200, 'state_proof', { height: '2', hash: sha(Buffer.from('2')).toString('hex').toUpperCase(), time_micros: '1000002000000' }, '3', '2', '3', { blocks: ['2', '3'] }]);
    // Too new for the history: said as that, with the proof that was read.
    const fresh = await get('/v1/blocks/3/proof');
    assert.deepEqual([fresh.status, fresh.body.error.code, fresh.body.source, fresh.body.state_height], [404, 'not_in_history', 'state_proof', '3']);
    // The state is never asked about a block above its height (a real node cannot prove one): the
    // 404 carries the proof of the plain state, which shows how far it reaches.
    assert.deepEqual([fresh.body.proof.query, Boolean(fresh.body.proof.view_proof)], [{}, true]);
    assert(selections.every((selection) => !(selection.blocks ?? []).includes('4')), JSON.stringify(selections));
    assert.match(fresh.body.error.message, /too new/);
    assert.equal((await get('/v1/blocks/9/proof')).body.error.code, 'not_in_history');
    // A height that no longer fits a number the state could have is answered the same way, not with an error of the server.
    assert.deepEqual([(await get('/v1/blocks/9007199254740991/proof')).status, (await get('/v1/blocks/9007199254740991/proof')).body.error.code], [404, 'not_in_history']);
    // The state cannot be read: 503 with a wait, as for an account.
  }, { readState });
  await lab(async (service) => {
    for (const target of ['/v1/validators', '/v1/accounts/7/state', '/v1/blocks/2/proof']) {
      const answer = await raw(service, target);
      assert.deepEqual([answer.status, JSON.parse(answer.body).error.code, answer.headers['retry-after']], [503, 'state_unavailable', '5'], target);
    }
  }, { readState: async () => { throw new Error('node behind'); } });
});

test('end to end: the explorer\'s check, through the real service, of a state it proved with the real state reader', async () => {
  // The node of client-v4/api.test.mjs's state test: one light block and the state proof of proof.json.
  const light = proven.proof.light_block;
  const rpc = async (method, parameters = {}) => {
    if (method === '/commit') return { signed_header: light.signed_header };
    if (method === '/validators') return { block_height: parameters.height, total: String(light.validators.length), validators: parameters.height === light.signed_header.header.height ? light.validators : light.next_validators };
    if (method === '/abci_query') return { response: { code: 0, height: proven.proof.height, value: Buffer.from(JSON.stringify({ height: proven.proof.height, root: light.signed_header.header.app_hash.toLowerCase(), entries: proven.proof.entries, history_proofs: proven.proof.history_proofs })).toString('base64') } };
    throw new IndexerError('RPC_REFUSED', 'not available on this node');
  };
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-explorer-state-')), originalNow = Date.now;
  Date.now = () => proven.now_ms;
  let service;
  try {
    service = await createApiService({ trust: proven.trust, rpc, verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false });
    const api = createApi({ origin: service.url });
    const checker = createChecker({ api, loadTrust: async () => proven.trust, loadVerifier: async () => verifier, createLightClient, sdk: globalThis.TimeSDK, now: () => proven.now_ms });
    // By name: the page asks its own question ({ names: ['alice'] }) of the proof the service passes on.
    const found = await checker.checkState(() => api.account({ name: 'alice' }), { names: ['alice'] });
    assert.deepEqual([found.height, found.state.accounts.map((a) => [a.id, a.name, a.balance]), found.names], ['5', [['0', 'alice', '0']], { alice: '0' }]);
    assert.equal(found.body.source, 'state_proof');
    // The proof of one question does not pass as the answer to another.
    await assert.rejects(checker.checkState(() => api.account({ name: 'alice' }), { names: ['bob'] }), (error) => error.reason === 'refused');
  } finally { Date.now = originalNow; await service?.close(); await rm(directory, { recursive: true, force: true }); }
});

test('end to end with the real state reader: an action is checked through the history, and a block too new for it answers 404 with a proof of how far the state reaches', async () => {
  // The node of proof.json: the state at height 5 under the light block 6, its history proofs for blocks 1 and 2, and their two signed headers.
  const light = proven.proof.light_block, receipt = proven.receipt, bytes = Buffer.from(receipt.tx.tx, 'base64'), hash = sha(bytes).toString('hex').toUpperCase();
  const signed = { [receipt.signed_header.header.height]: receipt.signed_header, [receipt.next_signed_header.header.height]: receipt.next_signed_header, [light.signed_header.header.height]: light.signed_header };
  const asked = [];
  const rpc = async (method, parameters = {}) => {
    if (method === '/commit') { const found = signed[parameters.height ?? light.signed_header.header.height]; if (!found) throw new IndexerError('RPC_REFUSED', 'height is not available'); return { signed_header: found }; }
    if (method === '/validators') return { block_height: parameters.height, total: String(light.validators.length), validators: parameters.height === light.signed_header.header.height ? light.validators : light.next_validators };
    if (method === '/abci_query') { asked.push(JSON.parse(Buffer.from(parameters.data.slice(2), 'hex').toString('utf8'))); return { response: { code: 0, height: proven.proof.height, value: Buffer.from(JSON.stringify({ height: proven.proof.height, root: light.signed_header.header.app_hash.toLowerCase(), entries: proven.proof.entries, history_proofs: proven.proof.history_proofs })).toString('base64') } }; }
    throw new IndexerError('RPC_REFUSED', 'not available on this node');
  };
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-explorer-history-')), originalNow = Date.now;
  Date.now = () => proven.now_ms;
  let service;
  try {
    service = await createApiService({ trust: proven.trust, rpc, verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false, rateLimit: { perSecond: 1000, burst: 100000 } });
    // The index holds block 1 with the one action of the fixture (written as the indexer writes a block).
    service.store.writeBlock({ previousChecked: false, events: [], actions: [{ ...describeAction(bytes, proven.trust.network_id), hash, raw: bytes, idx: 0 }],
      block: { height: 1, hash: 'aa'.repeat(32), previous_hash: '', time_micros: 1000001000000, time: '1970-01-12T13:46:41.000000Z', proposer: 'AA'.repeat(20), app_hash: 'BB'.repeat(32), data_hash: 'CC'.repeat(32) } });
    const api = createApi({ origin: service.url });
    const checker = createChecker({ api, loadTrust: async () => proven.trust, loadVerifier: async () => verifier, createLightClient, sdk: globalThis.TimeSDK, now: () => proven.now_ms });
    // Service, real state reader, verifier and page together: the bytes are in block 1, by the history of the state.
    const result = await checker.checkAction(hash);
    assert.deepEqual([result.mode, result.height, result.index, result.total, result.resultsChecked, result.anchorHeight], ['history', '1', 0, '1', true, light.signed_header.header.height]);
    // These bytes are not an action at all: the check says so by reading neither content nor frame.
    assert.deepEqual([result.action, result.envelope, Buffer.from(result.rawHex, 'hex').toString()], [null, null, 'public fixture transaction']);
    // A block the state does not reach yet (5 is its height, so block 6 has no history proof):
    // 404 not_in_history with the proof of the plain state, never a question the node cannot answer.
    const fresh = await raw(service, '/v1/blocks/5/proof'), body = JSON.parse(fresh.body);
    assert.deepEqual([fresh.status, body.error.code, body.state_height], [404, 'not_in_history', '5']);
    // The question of that proof names nothing (the reader writes it out in full): no block, no account.
    assert(Object.values(body.proof.query).every((value) => value === false || (Array.isArray(value) && value.length === 0)), JSON.stringify(body.proof.query));
    assert.equal((await verifier.verifyViewProof(body.proof.view_proof, proven.trust, {}, proven.now_ms)).state.height, '5', 'the reader can check how far the state reaches');
    assert(asked.every((selection) => !(selection.blocks ?? []).some((height) => Number(height) > 5)), JSON.stringify(asked));
    // On that answer the page goes on by the block's own signed header: it asks for the light blocks.
    const heights = [];
    const watching = { ...api, action: async () => ({ action: { raw: 'AAAA' }, verify: { height: '5', index: 0, total: '1', root_hash: 'AB'.repeat(32), leaf_hash: 'AAAA', aunts: [] } }), lightBlock: async (height) => { heights.push(height); return api.lightBlock(height); } };
    await assert.rejects(createChecker({ api: watching, loadTrust: async () => proven.trust, loadVerifier: async () => verifier, createLightClient, sdk: globalThis.TimeSDK, now: () => proven.now_ms }).checkAction('AB'.repeat(32)));
    assert.deepEqual(heights, ['6', '5'], 'the fixture has no block 5 to go on with; the path was taken');
  } finally { Date.now = originalNow; await service?.close(); await rm(directory, { recursive: true, force: true }); }
});

test('identical questions share one read of the state for a moment; a failed read is not kept', async () => {
  let reads = 0, down = false, clock = chain.now_ms;
  const readState = async (selection) => { reads += 1; if (down) throw new Error('node behind'); return { verified: true, requested: selection, proof: { height: '3', entries: [] }, state: { ...STATE, accounts: selection.ids?.[0] === '7' ? [{ id: '7', name: 'payer', balance: '85', nonce: '3', auth_epoch: '0', devices: [] }] : [], pos: {}, canonical_blocks: { 2: { hash: 'aa'.repeat(32), time_micros: '1' }, 3: { hash: 'bb'.repeat(32), time_micros: '2' } } } }; };
  await lab(async (service) => {
    // Six readers at once, and one a moment later: one read.
    const together = await Promise.all(Array.from({ length: 6 }, () => raw(service, '/v1/validators')));
    assert.deepEqual([together.map((answer) => answer.status), reads], [[200, 200, 200, 200, 200, 200], 1]);
    assert.equal((await raw(service, '/v1/validators')).status, 200); assert.equal(reads, 1);
    // After the moment the state is read again: an answer is never older than that.
    clock += 1500;
    await raw(service, '/v1/validators'); assert.equal(reads, 2);
    // The proof of a block: once how far the state reaches, once the block; then neither again.
    for (let i = 0; i < 5; i++) assert.equal((await raw(service, '/v1/blocks/2/proof')).status, 200);
    assert.equal(reads, 4);
    for (let i = 0; i < 5; i++) assert.equal((await raw(service, '/v1/accounts/7/state')).status, 200);
    assert.equal(reads, 5);
    // The account route the API had is not shared: every request reads, as before.
    await raw(service, '/v1/accounts/7'); await raw(service, '/v1/accounts/7');
    assert.equal(reads, 7);
    // A read that fails is not kept: the next request reads again.
    down = true; clock += 1500;
    assert.equal((await raw(service, '/v1/validators')).status, 503);
    down = false;
    assert.equal((await raw(service, '/v1/validators')).status, 200);
  }, { now: () => clock, readState });
});

test('a page on another origin can read how long the service asks it to wait', async () => {
  await lab(async (service) => {
    const allowed = await raw(service, '/v1/status', 'GET', { Origin: 'https://explorer.example' });
    assert.deepEqual([allowed.status, allowed.headers['access-control-allow-origin'], allowed.headers['access-control-expose-headers']], [200, 'https://explorer.example', 'Retry-After']);
    const limited = await raw(service, '/v1/validators', 'GET', { Origin: 'https://explorer.example' });
    assert.deepEqual([limited.status, limited.headers['access-control-expose-headers'], limited.headers['retry-after'] !== undefined], [429, 'Retry-After', true]);
    // A site that is not on the list is refused as before, with no allow header (client-v4/api.test.mjs asserts that).
    const other = await raw(service, '/v1/status', 'GET', { Origin: 'https://evil.example' });
    assert.deepEqual([other.status, other.headers['access-control-allow-origin'], other.headers['access-control-expose-headers']], [403, undefined, undefined]);
  }, { corsOrigins: ['https://explorer.example'], rateLimit: { perSecond: 1, burst: 2 } });
});

test('the proof of a block: its age is no obstacle, and a node that holds no history for it says so', async () => {
  // A state at height 1000 that has dropped the rows of its blocks up to 900 (they are kept fourteen
  // days). The history proof of a block stays, so blocks 2 and 3 are proven like any other.
  const asked = [];
  let restoredAt = 0;
  const readState = async (selection) => {
    asked.push(selection);
    // A node that joined from a snapshot refuses a question about history at or below that height, in these words (v5/src/engine.rs).
    if ((selection.blocks ?? []).some((height) => Number(height) <= restoredAt)) throw new Error(`Could not obtain compatible certified V4 state: Pinned state unavailable: this node holds no block history at or below height ${restoredAt}: its state was restored from a snapshot of that height`);
    return { verified: true, requested: selection, proof: { height: '1000', entries: [], light_block: {} }, state: { ...STATE, height: '1000', history_pruned_through: '900', accounts: [],
      canonical_blocks: Object.fromEntries((selection.blocks ?? []).filter((height) => Number(height) <= 1000).map((height) => [height, { hash: sha(Buffer.from(height)).toString('hex'), time_micros: `10000${height}000000` }])) } };
  };
  await lab(async (service) => {
    const get = async (target) => { const answer = await raw(service, target); return { status: answer.status, body: JSON.parse(answer.body) }; };
    const old = await get('/v1/blocks/2/proof');
    assert.deepEqual([old.status, old.body.block.height, old.body.next_block.height, old.body.state_height], [200, '2', '3', '1000']);
    assert.deepEqual(asked, [{}, { blocks: ['2', '3'] }], 'the state is asked how far it reaches, then about the block: its dropped rows decide nothing');
    // Beyond the state's height: too new, said with the proof of the plain state.
    const beyond = await get('/v1/blocks/1000/proof');
    assert.deepEqual([beyond.status, beyond.body.error.code, beyond.body.state_height], [404, 'not_in_history', '1000']);
    // The node was restored from a snapshot at height 500: it holds no history at or below it, and the service says that, not "too new" and not "try later".
    restoredAt = 500;
    const lost = await get('/v1/blocks/400/proof');
    assert.deepEqual([lost.status, lost.body.error.code, Object.keys(lost.body)], [404, 'history_not_held', ['error']]);
    assert.match(lost.body.error.message, /holds no history for this block: it joined the network from a snapshot/);
    assert.doesNotMatch(JSON.stringify(lost.body), /Pinned state|restored from a snapshot of that height/, 'the node\'s own text is not passed on');
    assert.equal((await get('/v1/blocks/600/proof')).status, 404, 'above the restore the history is held (here the fake node has no such block: not found)');
    assert.equal((await get('/v1/blocks/600/proof')).body.error.code, 'not_found');
    // Any other failure of the state read stays what it was.
    restoredAt = 0;
  }, { readState });
  await lab(async (service) => {
    const answer = await raw(service, '/v1/blocks/2/proof');
    assert.deepEqual([answer.status, JSON.parse(answer.body).error.code], [503, 'state_unavailable']);
  }, { readState: async (selection) => { if (selection.blocks) throw new Error('node behind'); return { verified: true, requested: selection, proof: { height: '3', entries: [] }, state: { ...STATE, accounts: [] } }; } });
});
