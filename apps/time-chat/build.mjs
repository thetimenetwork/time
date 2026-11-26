import { build } from 'esbuild';
import { mkdir, copyFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const timeRoot =
  process.env.TIME_ROOT || path.resolve(root, '../..');
await mkdir(path.join(root, 'dist/vendor'), { recursive: true });
await build({
  entryPoints: [path.join(root, 'public/app.mjs')],
  outfile: path.join(root, 'dist/app.mjs'),
  bundle: true,
  platform: 'browser',
  alias: { openpgp: '/vendor/openpgp.mjs' },
  external: ['/vendor/openpgp.mjs'],
  format: 'esm',
  target: 'es2022',
  legalComments: 'eof',
  minify: true,
});
for (const file of [
  'index.html',
  'style.css',
  'sw.js',
  'manifest.webmanifest',
  'icon.svg',
  'icon-192.png',
  'icon-512.png',
]) {
  await copyFile(
    path.join(root, 'public', file),
    path.join(root, 'dist', file)
  );
}
await copyFile(
  path.join(timeRoot, 'client-v4/time-sdk.js'),
  path.join(root, 'dist/vendor/time-sdk.js')
);
const library = path.join(root, 'node_modules/openpgp');
await copyFile(path.join(library, 'dist/openpgp.min.mjs'), path.join(root, 'dist/vendor/openpgp.mjs'));
await copyFile(path.join(library, 'LICENSE'), path.join(root, 'dist/vendor/openpgp-license.txt'));
