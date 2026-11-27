import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

export const VAULT_HOST = 'vault.testnet.thetimenetwork.org';
export const VAULT_FILES = new Map([
  ['/', 'web-v4/manager/index.html'],
  ['/app.mjs', 'web-v4/manager/app.mjs'],
  ['/store.mjs', 'web-v4/manager/store.mjs'],
  ['/manager.css', 'web-v4/manager/manager.css'],
  ...['device-key.mjs', 'vault.mjs', 'entropy.mjs'].map(name => ['/wallet-lib/' + name, 'web-v4/wallet/' + name]),
  ['/vendor/argon2-4.12.0.umd.min.js', 'web-v4/wallet/vendor/argon2-4.12.0.umd.min.js'],
]);
const MIME = { '.html': 'text/html', '.mjs': 'text/javascript', '.js': 'text/javascript', '.css': 'text/css' };
export const VAULT_HEADERS = Object.freeze({
  'Content-Security-Policy': "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), publickey-credentials-create=(self), publickey-credentials-get=(self)',
  'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff', 'Cross-Origin-Resource-Policy': 'same-origin',
});

// Only exact, public asset names reach disk. The vault has no server-side storage, API or request logs.
export async function serveVault(root, request, response) {
  const file = VAULT_FILES.get(request.url);
  const methodAllowed = request.method === 'GET' || request.method === 'HEAD';
  if (!methodAllowed || !file) {
    response.writeHead(methodAllowed ? 404 : 405, { ...VAULT_HEADERS, Allow: 'GET, HEAD' });
    return response.end();
  }
  try {
    const bytes = await readFile(path.join(root, file));
    response.writeHead(200, { ...VAULT_HEADERS, 'Content-Type': MIME[path.extname(file)] + '; charset=utf-8', 'Content-Length': bytes.length });
    response.end(request.method === 'HEAD' ? undefined : bytes);
  } catch {
    response.writeHead(503, VAULT_HEADERS);
    response.end();
  }
}

// Fixed loopback pair shared with the wallet's origin check. Reject any other Host, including a DNS alias.
export async function startLocalVault(root) {
  const server = http.createServer((request, response) => {
    if (request.headers.host !== 'localhost:8786') {
      response.writeHead(403, VAULT_HEADERS);
      return response.end();
    }
    return serveVault(root, request, response);
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(8786, '127.0.0.1', resolve); });
  return server;
}
