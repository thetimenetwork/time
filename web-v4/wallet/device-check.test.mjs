// The page "Check this device" (device-check.html, device-check.js, device-check.css): that it can run under the
// wallet's Content-Security-Policy as the files are written (no inline script, style or handler, no remote address,
// no HTML written from strings), that it says things in plain words, and that the gateway serves it next to the wallet
// with the wallet's own headers and nothing that switches the device's check off: its Permissions-Policy lets the
// wallet's own origin make and use device keys.
// The check itself is device-key.test.mjs's; a real browser runs the page in campaign/lib/browser-device-check.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createV4Servers } from '../../client-v4/server.mjs';

const here = (name) => new URL(name, import.meta.url);
const html = await readFile(here('device-check.html'), 'utf8');
const script = await readFile(here('device-check.js'), 'utf8');
const style = await readFile(here('device-check.css'), 'utf8');
const logic = await readFile(here('device-key.mjs'), 'utf8');

test('the page runs under the wallet\'s policy as written: no inline script, style or handler, no remote address, no HTML from strings', () => {
  // Scripts: each one a file of this origin, none inline.
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
  assert.ok(scripts.length >= 1);
  for (const [, attributes, body] of scripts) { assert.match(attributes, /\bsrc="\/[a-z0-9./-]+"/, attributes); assert.equal(body.trim(), '', 'an inline script'); }
  assert.deepEqual(scripts.map(([, a]) => /src="([^"]+)"/.exec(a)[1]), ['/device-check.js']);
  // Styles: the wallet's own stylesheet and the page's small one, nothing inline.
  assert.deepEqual([...html.matchAll(/<link\b[^>]*\bhref="([^"]+)"/gi)].map((m) => m[1]), ['/styles.css', '/device-check.css']);
  assert.doesNotMatch(html, /<style\b/i);
  assert.doesNotMatch(html, /\sstyle\s*=/i);
  assert.doesNotMatch(html, /\son[a-z]+\s*=/i, 'an inline event handler');
  assert.doesNotMatch(html, /javascript:/i);
  for (const [name, text] of [['device-check.html', html], ['device-check.js', script], ['device-check.css', style], ['device-key.mjs', logic]]) {
    assert.doesNotMatch(text, /\b(?:https?|wss?):\/\//i, `${name} names a remote address`);
  }
  for (const [name, text] of [['device-check.html', html], ['device-check.css', style]]) assert.doesNotMatch(text, /@import|\burl\(/i, `${name} loads something from a stylesheet`);
  for (const [name, text] of [['device-check.js', script], ['device-key.mjs', logic]]) {
    assert.doesNotMatch(text, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|new Function|setAttribute\(\s*['"](?:style|on)|\.style\b/, name);
    // Imports: only this folder's own modules.
    for (const m of text.matchAll(/\bfrom\s*(['"])([^'"]+)\1|\bimport\s*\(\s*(['"])([^'"]+)\3/g)) assert.match(m[2] ?? m[4], /^\.\/[a-z0-9-]+\.mjs$/, name);
  }
  assert.deepEqual([...script.matchAll(/\bfrom\s*'([^']+)'/g)].map((m) => m[1]), ['./device-key.mjs']);
  assert.doesNotMatch(logic, /\bimport\b/, 'the module stands alone');
});

test('every element the script uses is on the page, and the page says what the owner asked for in plain words', () => {
  const ids = new Set([...html.matchAll(/\sid="([a-z0-9-]+)"/g)].map((m) => m[1]));
  const used = [...script.matchAll(/\$\('([a-z0-9-]+)'\)|'([a-z0-9-]+)'(?=[,\]][^\n]*\$\(id\))/g)].map((m) => m[1] ?? m[2]);
  assert.ok(used.length > 10);
  for (const id of used) assert.ok(ids.has(id), `the script uses #${id}, which the page does not have`);
  const text = html.replace(/<[^>]+>/g, ' ');
  assert.match(html, /<h1 id="check-title">Check this device<\/h1>/);
  assert.match(html, /<button id="check-start" type="button" disabled>Check this device<\/button>/);
  assert.match(text, /fingerprint, face or screen lock/);
  assert.match(text, /"Time device check"/);
  assert.match(text, /Nothing is sent anywhere and no account is touched\./);
  assert.match(text, /This report holds nothing about you\. Send it to the people who run this wallet if something did not work\./);
  assert.match(html, /<a href="\/">Back to the wallet<\/a>/);
  for (const [name, words] of [['device-check.html', text], ['device-check.js', script]]) {
    assert.doesNotMatch(words, /—/, `${name}: an em dash`);
    assert.doesNotMatch(words, /passkey/i, `${name}: "passkey" (the module's removeTestKey is the one place the device's own word is used)`);
  }
  // The report is copied by hand when the browser refuses: the refusal is caught and the text selected.
  assert.match(script, /catch \{[\s\S]{0,200}area\.select\(\)/);
  // The page's own stylesheet adds two rules, to the report box and to the labels of its own list.
  assert.deepEqual([...style.replace(/\/\*[\s\S]*?\*\//g, '').matchAll(/([^{}]+)\{/g)].map((m) => m[1].trim()), ['textarea.report', '.check-list .row > span:first-child']);
});

test('the gateway serves the page next to the wallet, with the wallet\'s policy, the right types, and a Permissions-Policy that leaves the check on', async () => {
  const fixture = JSON.parse(await readFile(here('../../verifier-v4/fixtures/proof.json'), 'utf8'));
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-device-check-'));
  const original = Date.now; Date.now = () => fixture.now_ms; let servers;
  const rpc = async () => { throw Error('Unconfigured test RPC'); };
  const get = (origin, pathname) => new Promise((resolve, reject) => {
    const u = new URL(pathname, origin);
    http.get({ hostname: '127.0.0.1', port: u.port, path: u.pathname, headers: { Host: u.host } }, (response) => {
      const chunks = []; response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks) }));
    }).on('error', reject);
  });
  try {
    servers = await createV4Servers({ root: fileURLToPath(here('../../')), manifest: { networkId: fixture.trust.network_id, chainId: fixture.trust.chain_id, trust: fixture.trust }, rpc, walletPort: 0, merchantPort: 0, checkpointPath: path.join(directory, 'checkpoint.json'), ordersPath: path.join(directory, 'orders.json'), upgradeCheck: { everyMs: 0 } });
    const wallet = await get(servers.walletOrigin, '/');
    assert.equal(wallet.status, 200);
    const policy = wallet.headers['content-security-policy'];
    assert.match(policy, /default-src 'none'; script-src 'self'/);
    for (const [pathname, type, file] of [['/device-check.html', 'text/html; charset=utf-8', 'device-check.html'], ['/wallet/device-check.html', 'text/html; charset=utf-8', 'device-check.html'],
      ['/device-check.js', 'text/javascript; charset=utf-8', 'device-check.js'], ['/device-key.mjs', 'text/javascript; charset=utf-8', 'device-key.mjs'], ['/device-check.css', 'text/css; charset=utf-8', 'device-check.css']]) {
      const answer = await get(servers.walletOrigin, pathname);
      assert.equal(answer.status, 200, pathname);
      assert.equal(answer.headers['content-type'], type, pathname);
      assert.equal(answer.headers['content-security-policy'], policy, `${pathname} has the wallet's policy`);
      assert.equal(answer.headers['x-content-type-options'], 'nosniff');
      // The gateway's Permissions-Policy (client-v4/server.mjs) turns off what a wallet does not use, and allows the
      // device's keys (WebAuthn) to the wallet's own origin: anything else there would switch the check off.
      const permissions = answer.headers['permissions-policy'];
      assert.match(permissions, /(?:^|, )publickey-credentials-create=\(self\)(?:,|$)/, `${pathname}: the page may make a device key`);
      assert.match(permissions, /(?:^|, )publickey-credentials-get=\(self\)(?:,|$)/, `${pathname}: the page may use a device key`);
      assert.equal(permissions.match(/publickey-credentials-/g).length, 2, `${pathname}: each said once`);
      assert.equal(answer.headers['feature-policy'], undefined);
      assert.deepEqual(answer.body, await readFile(here(file)), pathname);
    }
    // The tests stay out of reach, and the shop's origin does not serve the wallet's page.
    assert.equal((await get(servers.walletOrigin, '/device-key.test.mjs')).status, 404);
    assert.equal((await get(servers.merchantOrigin, '/device-check.html')).status, 404);
  } finally { await servers?.close(); Date.now = original; await rm(directory, { recursive: true, force: true }); }
});
