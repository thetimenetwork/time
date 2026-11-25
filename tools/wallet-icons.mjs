#!/usr/bin/env node
// The wallet's icons for a phone's Home Screen (web-v4/wallet/manifest.webmanifest and the apple-touch-icon), drawn
// from the wallet's own clock mark (web-v4/wallet/index.html, the `brand-mark` of the top bar: a circle of radius 10.5
// on a 24-unit box, its two hands `M12 6.5v6l4 2.3` with a line of 2 and round ends) and written as PNG files.
// Nothing but Node: the drawing is computed here pixel by pixel, and Node's zlib compresses it.
//
//   node tools/wallet-icons.mjs          writes web-v4/wallet/icons/icon-192.png, icon-512.png and apple-touch-icon.png
//
// The icon: the page's white canvas filling the whole square (a phone rounds the corners itself), and on it the mark in
// the page's ink (#222222), its hands in white, the circle taking 82% of the side, so that a launcher that cuts the
// icon to a circle keeps all of it. Each pixel is the share of 16 points inside it that fall on the ink.
// web-v4/wallet/icons.test.mjs checks that the files hold exactly these pixels.
import { deflateSync } from 'node:zlib';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ICONS = Object.freeze([['icon-192.png', 192], ['icon-512.png', 512], ['apple-touch-icon.png', 180]]);
const INK = [0x22, 0x22, 0x22], CANVAS = [0xff, 0xff, 0xff];
const SAMPLES = 4, SHARE = 0.82;
/// The distance from point p to the segment a-b.
function toSegment(px, py, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay, t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}
/// Whether a point of the 24-unit box is ink: inside the circle, and not on a hand.
function ink(u, v) {
  if ((u - 12) ** 2 + (v - 12) ** 2 > 10.5 ** 2) return false;
  const hand = Math.min(toSegment(u, v, 12, 6.5, 12, 12.5), toSegment(u, v, 12, 12.5, 16, 14.8));
  return hand > 1;
}
/// The rows of an icon of `size` pixels, each as PNG stores it: a filter byte (0, none) and red, green, blue per pixel.
export function iconRows(size) {
  const scale = (size * SHARE) / 21, rows = Buffer.alloc(size * (1 + size * 3));
  for (let y = 0; y < size; y++) {
    const at = y * (1 + size * 3); rows[at] = 0;
    for (let x = 0; x < size; x++) {
      let covered = 0;
      for (let sy = 0; sy < SAMPLES; sy++) for (let sx = 0; sx < SAMPLES; sx++) {
        const u = 12 + (x + (sx + 0.5) / SAMPLES - size / 2) / scale, v = 12 + (y + (sy + 0.5) / SAMPLES - size / 2) / scale;
        if (ink(u, v)) covered += 1;
      }
      const share = covered / (SAMPLES * SAMPLES);
      for (let c = 0; c < 3; c++) rows[at + 1 + x * 3 + c] = Math.round(CANVAS[c] + (INK[c] - CANVAS[c]) * share);
    }
  }
  return rows;
}
const CRC_TABLE = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
export function crc32(bytes) { let c = 0xffffffff; for (const b of bytes) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
function chunk(type, data) {
  const head = Buffer.alloc(8); head.writeUInt32BE(data.length, 0); head.write(type, 4, 'latin1');
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), data])), 0);
  return Buffer.concat([head, data, crc]);
}
/// A PNG file of the icon: 8-bit RGB, no alpha (a Home Screen icon is opaque), one IDAT.
export function iconPng(size) {
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4); ihdr[8] = 8; ihdr[9] = 2; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(iconRows(size), { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const folder = fileURLToPath(new URL('../web-v4/wallet/icons/', import.meta.url));
  await mkdir(folder, { recursive: true });
  for (const [name, size] of ICONS) { await writeFile(path.join(folder, name), iconPng(size)); console.log(`${name}: ${size} x ${size}`); }
}
