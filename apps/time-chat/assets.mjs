import { readFile } from 'node:fs/promises';

const files = new Map(
  Object.entries({
    '/': 'text/html',
    '/index.html': 'text/html',
    '/app.mjs': 'text/javascript',
    '/style.css': 'text/css',
    '/sw.js': 'text/javascript',
    '/manifest.webmanifest': 'application/manifest+json',
    '/icon.svg': 'image/svg+xml',
    '/icon-192.png': 'image/png',
    '/icon-512.png': 'image/png',
    '/vendor/time-sdk.js': 'text/javascript',
    '/vendor/openpgp.mjs': 'text/javascript',
    '/vendor/openpgp-license.txt': 'text/plain; charset=utf-8',
  })
);
export async function serveAsset(req, res, pathname) {
  const type = files.get(pathname);
  if (!type || !['GET', 'HEAD'].includes(req.method)) return false;
  const file = new URL(
    './dist' + (pathname === '/' ? '/index.html' : pathname),
    import.meta.url
  );
  const contents = await readFile(file);
  res.writeHead(200, {
    'Content-Type': type,
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy':
      "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
  });
  res.end(req.method === 'HEAD' ? undefined : contents);
  return true;
}
