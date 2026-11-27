import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { serveVault, VAULT_FILES, VAULT_HEADERS, VAULT_HOST } from './vault-host.mjs';
import { buildVault, vaultStack } from '../deploy/vault/build.mjs';
import { CLIENT_FILES } from '../tools/release-v4.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));

test('the vault host serves only its static application and cryptography, with headers on failures too', async t => {
  const server = http.createServer((request, response) => void serveVault(root, request, response));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const origin = 'http://127.0.0.1:' + server.address().port;
  for (const [asset, file] of VAULT_FILES) {
    const response = await fetch(origin + asset);
    assert.equal(response.status, 200, asset);
    assert.deepEqual(Buffer.from(await response.arrayBuffer()), await readFile(path.join(root, file)), asset);
    for (const [name, value] of Object.entries(VAULT_HEADERS)) assert.equal(response.headers.get(name), value, asset);
    assert.equal(response.headers.get('access-control-allow-origin'), null);
    assert.match(response.headers.get('content-type'), file.endsWith('.html') ? /text\/html/ : file.endsWith('.css') ? /text\/css/ : /text\/javascript/);
  }
  for (const asset of ['/approve', '/api/network', '/wallet-lib/app.js', '/vendor/', '/sw.js', '/manager.test.mjs', '/?secret=never-used']) {
    const response = await fetch(origin + asset);
    assert.equal(response.status, 404, asset);
    assert.equal(await response.text(), '');
    assert.equal(response.headers.get('cache-control'), 'no-store');
  }
  const head = await fetch(origin + '/', { method: 'HEAD' });
  assert.equal(head.status, 200); assert.equal(await head.text(), '');
  assert.equal((await fetch(origin + '/', { method: 'POST', body: 'x' })).status, 405);
});

test('the testnet stack has an exact HTTPS host and static request allowlist, private read-only origin and shared browser policy', () => {
  const { Resources: r } = vaultStack();
  const c = r.Site.Properties.DistributionConfig;
  assert.deepEqual(c.Aliases, [VAULT_HOST]);
  assert.deepEqual(c.DefaultCacheBehavior.AllowedMethods, ['GET', 'HEAD']);
  assert.equal(c.DefaultCacheBehavior.ViewerProtocolPolicy, 'https-only');
  assert.equal(r.ReadAccess.Properties.OriginAccessControlConfig.SigningBehavior, 'always');
  assert.deepEqual(r.ReadPolicy.Properties.PolicyDocument.Statement.map(s => s.Action), ['s3:GetObject']);
  assert.ok(Object.values(r.Assets.Properties.PublicAccessBlockConfiguration).every(Boolean));
  const headers = r.Headers.Properties.ResponseHeadersPolicyConfig;
  assert.equal(headers.SecurityHeadersConfig.ContentSecurityPolicy.ContentSecurityPolicy, VAULT_HEADERS['Content-Security-Policy']);
  const filter = runInNewContext(r.HostCheck.Properties.FunctionCode + '\nhandler');
  const request = (uri, host = VAULT_HOST, querystring = {}) => ({ method: 'GET', uri, querystring, headers: { host: { value: host } } });
  for (const asset of VAULT_FILES.keys()) { const r = request(asset); assert.equal(filter({ request: r }), r); }
  for (const r of [request('/', 'wallet.testnet.thetimenetwork.org'), request('/', 'test.cloudfront.net'), request('/approve'), request('/', VAULT_HOST, { secret: { value: 'test' } })]) {
    assert.equal(filter({ request: r }).statusCode, 404);
  }
});

test('the deployment bundle contains the exact public asset bytes and the source distribution includes them', async t => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'time-vault-build-'));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const output = path.join(temp, 'out');
  await buildVault(root, output);
  const files = await readdir(path.join(output, 'assets'), { recursive: true, withFileTypes: true });
  assert.equal(files.filter(f => f.isFile()).length, VAULT_FILES.size);
  const published = JSON.parse(await readFile(path.join(root, 'public-manifest.json'), 'utf8')).publish.flatMap(g => g.paths);
  for (const [route, source] of VAULT_FILES) {
    assert.ok(CLIENT_FILES.includes(source) && published.includes(source), source);
    const file = path.join(output, 'assets', route === '/' ? 'index.html' : route.slice(1));
    assert.deepEqual(await readFile(file), await readFile(path.join(root, source)));
  }
  assert.deepEqual(JSON.parse(await readFile(path.join(output, 'testnet-stack.json'), 'utf8')), vaultStack());
  await assert.rejects(buildVault(root, output), { code: 'EEXIST' });
});
