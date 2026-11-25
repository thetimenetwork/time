// The wallet on a phone's Home Screen: its web app manifest (manifest.webmanifest), the PNG icons that
// tools/wallet-icons.mjs draws from the wallet's clock mark, and the two links of index.html that name them.
// The icons are files in the repository; this test reads each one and checks that it holds exactly the pixels the
// tool computes, so a changed file or a changed tool is caught here, and that nothing in it looks like a secret.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { inflateSync } from 'node:zlib';
import { ICONS, iconRows, crc32 } from '../../tools/wallet-icons.mjs';
import { inspect } from '../../tools/export-public.mjs';

const here = (name) => new URL(name, import.meta.url);
const SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/// The chunks of a PNG file, each with its type and data, after checking the signature and every chunk's CRC.
function chunks(bytes, name) {
  assert.deepEqual(bytes.subarray(0, 8), SIGNATURE, `${name}: PNG signature`);
  const found = [];
  for (let at = 8; at < bytes.length;) {
    const length = bytes.readUInt32BE(at), type = bytes.toString('latin1', at + 4, at + 8), data = bytes.subarray(at + 8, at + 8 + length);
    assert.equal(bytes.readUInt32BE(at + 8 + length), crc32(bytes.subarray(at + 4, at + 8 + length)), `${name}: CRC of ${type}`);
    found.push({ type, data }); at += 12 + length;
  }
  return found;
}

test('each icon is an opaque 8-bit RGB PNG of its size holding exactly the pixels tools/wallet-icons.mjs draws', async () => {
  assert.deepEqual(ICONS.map(([name, size]) => [name, size]), [['icon-192.png', 192], ['icon-512.png', 512], ['apple-touch-icon.png', 180]]);
  for (const [name, size] of ICONS) {
    const bytes = await readFile(here(`./icons/${name}`)), list = chunks(bytes, name);
    assert.deepEqual(list.map((c) => c.type), ['IHDR', 'IDAT', 'IEND'], name);
    const ihdr = list[0].data;
    assert.deepEqual([ihdr.readUInt32BE(0), ihdr.readUInt32BE(4), ...ihdr.subarray(8)], [size, size, 8, 2, 0, 0, 0], `${name}: ${size} x ${size}, 8-bit RGB, no interlace`);
    const rows = iconRows(size);
    assert.ok(inflateSync(list[1].data).equals(rows), `${name} differs from what node tools/wallet-icons.mjs draws: run it again`);
    const pixel = (x, y) => [...rows.subarray(y * (1 + size * 3) + 1 + x * 3, y * (1 + size * 3) + 4 + x * 3)];
    // The page's white in the corners, its ink inside the circle away from the hands, white on the long hand.
    assert.deepEqual(pixel(0, 0), [255, 255, 255], name);
    assert.deepEqual(pixel(Math.round(size * 0.3), Math.round(size * 0.7)), [0x22, 0x22, 0x22], name);
    assert.deepEqual(pixel(size / 2, Math.round(size * 0.35)), [255, 255, 255], name);
    assert.deepEqual(inspect(`web-v4/wallet/icons/${name}`, bytes), [], `${name}: nothing the public export refuses`);
  }
});

test('the manifest makes the wallet an app of its own on a Home Screen: name, standalone, its own scope, two icons', async () => {
  const manifest = JSON.parse(await readFile(here('./manifest.webmanifest'), 'utf8'));
  assert.deepEqual(manifest, {
    name: 'Time', short_name: 'Time', start_url: './', scope: './', display: 'standalone', background_color: '#ffffff', theme_color: '#ffffff',
    icons: [{ src: 'icons/icon-192.png', sizes: '192x192', type: 'image/png' }, { src: 'icons/icon-512.png', sizes: '512x512', type: 'image/png' }],
  });
  for (const icon of manifest.icons) {
    const bytes = await readFile(here(`./${icon.src}`)), side = bytes.readUInt32BE(16);
    assert.equal(icon.sizes, `${side}x${side}`, icon.src);
  }
});

test('the page names the manifest and the icon for an iPhone, from its own origin', async () => {
  const html = await readFile(here('./index.html'), 'utf8');
  const links = [...html.matchAll(/<link\b[^>]*>/g)].map((m) => m[0]);
  assert.ok(links.includes('<link rel="manifest" href="/manifest.webmanifest">'), 'manifest link');
  assert.ok(links.includes('<link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">'), 'apple-touch-icon link');
  assert.equal((await readFile(here('./icons/apple-touch-icon.png'))).readUInt32BE(16), 180);
  for (const link of links) assert.doesNotMatch(link, /https?:|\/\//, link);
});
