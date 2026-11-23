// Review of the browser-check changes (commit 16d3e5d), client-v4 part:
// - the gateway's `registrationService` and the Content-Security-Policy of the wallet page built from it;
// - the API's own-origin rule (a request whose Origin is the very address asked).
// A test here that fails shows a defect; one that passes holds a property that had no test.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import './time-sdk.js';
import * as verifier from './proof-verifier.mjs';
import { createV4Servers } from './server.mjs';
import { createApiService } from './api.mjs';

const fixture = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/proof.json', import.meta.url), 'utf8'));
const b = fixture.proof.light_block;
const rpc = async (endpoint, p = {}) => {
  if (endpoint === '/commit') return { signed_header: b.signed_header };
  if (endpoint === '/validators') return { block_height: p.height, total: '4', validators: p.height === '6' ? b.validators : b.next_validators };
  if (endpoint === '/abci_query') return { response: { height: '5', code: 0, value: Buffer.from(JSON.stringify({ height: '5', root: b.signed_header.header.app_hash.toLowerCase(), entries: fixture.proof.entries, history_proofs: fixture.proof.history_proofs })).toString('base64') } };
  throw Error('Unexpected RPC');
};
const connectSources = (csp) => /connect-src ([^;]*);/.exec(csp)?.[1];

// The check in createV4Servers is `new URL(value).origin === value`. The URL parser keeps `*`, `;` and `,` in a
// host name, so these values pass as "canonical HTTPS origins" and go into the page's policy as written:
// - `https://*` is the CSP source "any host over https": the wallet page may then connect anywhere;
// - `https://*.example` is every name under example;
// - `;` ends connect-src and starts a directive of the value's choosing (here `sandbox`, which breaks the page);
// - `,` starts a second policy.
// None of them names one service the wallet could ask.
test('the registration service must be one host: a wildcard or a policy separator in the value is refused before a server starts', async () => {
  const accepted = [];
  for (const value of ['https://*', 'https://*.example', 'https://faucet.example;sandbox', 'https://faucet.example,default-src']) {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'time-review-browser-')), originalNow = Date.now;
    let servers = null;
    try {
      Date.now = () => fixture.now_ms;
      servers = await createV4Servers({ root: fileURLToPath(new URL('../', import.meta.url)), manifest: { networkId: fixture.trust.network_id, chainId: fixture.trust.chain_id, trust: fixture.trust }, rpc, walletPort: 0, merchantPort: 0,
        checkpointPath: path.join(directory, 'checkpoint.json'), ordersPath: path.join(directory, 'orders.json'), registrationService: value });
      const page = await fetch(`${servers.walletListenOrigin}/`); await page.arrayBuffer();
      accepted.push({ value, policy: page.headers.get('content-security-policy') });
    } catch (error) {
      assert.match(error.message, /registration service must be a canonical HTTPS origin/, value);
    } finally { Date.now = originalNow; await servers?.close(); await rm(directory, { recursive: true, force: true }); }
  }
  assert.deepEqual(accepted.map(({ value, policy }) => `${value} -> connect-src ${connectSources(policy)}`), [], 'createV4Servers started with these values and served the wallet page with this policy');
});

// ------------------------------------------------------------------ the API's own origin
function rawRequest(url, route, lines) {
  // Several headers of one name, written as given: http.request would merge or refuse them.
  const { port } = new URL(url);
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let text = '';
    socket.on('data', (chunk) => { text += chunk; });
    socket.on('end', () => resolve(Number(/^HTTP\/1\.1 (\d{3})/.exec(text)?.[1])));
    socket.on('error', reject);
    socket.connect(Number(port), '127.0.0.1', () => socket.end(`GET ${route} HTTP/1.1\r\n${lines.join('\r\n')}\r\nConnection: close\r\n\r\n`));
  });
}
async function api(run, options = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-review-api-'));
  let service;
  try {
    service = await createApiService({ trust: fixture.trust, rpc: async () => { throw new Error('no node in this test'); }, verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false,
      readState: async () => { throw new Error('no state in this test'); }, rateLimit: { perSecond: 1000, burst: 100000 }, ...options });
    await run(service);
  } finally { await service?.close(); await rm(directory, { recursive: true, force: true }); }
}
const ask = (service, headers, method = 'GET') => new Promise((resolve, reject) => {
  const { port } = new URL(service.url);
  const req = http.request({ host: '127.0.0.1', port, path: '/v1/status', method, headers }, (res) => { res.resume(); res.on('end', () => resolve({ status: res.statusCode, allow: res.headers['access-control-allow-origin'] ?? null })); });
  req.on('error', reject); req.end();
});

test('the API\'s own origin: only the address asked passes, also with several Origin headers, IPv6, a proxy that rewrites Host, and a preflight', async () => {
  await api(async (service) => {
    const { port } = new URL(service.url);
    // IPv6 loopback, the third name the code lists.
    assert.notEqual((await ask(service, { Host: `[::1]:${port}`, Origin: `http://[::1]:${port}` })).status, 403);
    // Two Origin headers, one of them the address asked: the server reads them joined, and that is no origin of its own.
    assert.equal(await rawRequest(service.url, '/v1/status', [`Host: 127.0.0.1:${port}`, `Origin: http://127.0.0.1:${port}`, `Origin: http://127.0.0.1:${port}`]), 403);
    assert.equal(await rawRequest(service.url, '/v1/status', [`Host: 127.0.0.1:${port}`, `Origin: http://127.0.0.1:${port}`, 'Origin: https://evil.example']), 403);
    // A preflight of the page's own origin gets no permission header: it needs none.
    const preflight = await ask(service, { Host: `127.0.0.1:${port}`, Origin: `http://127.0.0.1:${port}` }, 'OPTIONS');
    assert.deepEqual([preflight.status, preflight.allow], [204, null]);
  });
  await api(async (service) => {
    const { port } = new URL(service.url);
    // A TLS proxy that sends the upstream address as Host (nginx's default) makes the explorer's own page a foreign one,
    // as deploy/api/README.md says: refused.
    assert.equal((await ask(service, { Host: `127.0.0.1:${port}`, Origin: 'https://api.example' })).status, 403);
    // A proxy that drops the port (nginx `$host`) for a name on another port: refused as well.
    assert.equal((await ask(service, { Host: 'api.example', Origin: 'https://api.example:8443' })).status, 403);
    // The configured name under its own https origin passes, with no permission header.
    assert.deepEqual(await ask(service, { Host: 'api.example', Origin: 'https://api.example' }), { status: 200, allow: null });
  }, { hosts: ['api.example'] });
  await api(async (service) => {
    // With ["*"] the own origin still gets no permission header, and another origin gets "*".
    assert.deepEqual(await ask(service, { Host: 'api.example', Origin: 'https://api.example' }), { status: 200, allow: null });
    assert.deepEqual(await ask(service, { Host: 'api.example', Origin: 'https://evil.example' }), { status: 200, allow: '*' });
  }, { hosts: ['api.example'], corsOrigins: ['*'] });
});
