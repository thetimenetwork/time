import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ALLOWED, ACCEPTED, LOCKFILES, CONSENSUS_MODULE, OUTPUT, parseExpression, chooseLicense, manifestLicense, crateLicense, registryDirectories,
  goModules, escapeModulePath, goLicense, classifyText, vendoredJavaScript, buildInventory, render, failures, main
} from './licenses.mjs';
import { cargoPackages } from './release-v4.mjs';

const repository = fileURLToPath(new URL('../', import.meta.url));
const use = expression => chooseLicense(parseExpression(expression))?.use ?? null;
async function put(root, file, content = '') { await mkdir(path.dirname(path.join(root, file)), { recursive: true }); await writeFile(path.join(root, file), content); }
const MIT = 'Permission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the "Software"), to deal\n';
const MPL = 'Mozilla Public License, version 2.0\n\n1.12. "Secondary License" means the GNU General Public License, Version 2.0, the GNU Lesser General Public License, Version 2.1, the GNU Affero General Public License, Version 3.0\n';
const BSD3 = 'Redistribution and use in source and binary forms, with or without\nmodification, are permitted provided that the following conditions are met:\n * Neither the name of Example nor the names of its contributors may be used\n';
const BSD2 = 'Redistribution and use in source and binary forms, with or without\nmodification, are permitted provided that the following conditions are met:\n1. Redistributions of source code must retain the above copyright notice\n';
const GPL = '                    GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n';

// A small project: two lockfiles, a registry, a module cache and a vendored file.
async function project({ crates = {}, modules = {}, vendorLicense = MIT, vendorDeclared = 'MIT; see LICENSE.sample', extraVendorFile = null } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'time-licences-'));
  const names = Object.keys(crates);
  const lock = list => 'version = 4\n\n' + ['[[package]]\nname = "own-crate"\nversion = "0.1.0"\n', ...list.map(name => `[[package]]\nname = "${name.split('@')[0]}"\nversion = "${name.split('@')[1]}"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "${'a'.repeat(64)}"\n`)].join('\n');
  await put(root, 'Cargo.lock', lock(names));
  await put(root, 'sub/Cargo.lock', lock(names.slice(0, 1)));
  for (const [name, manifest] of Object.entries(crates)) if (manifest !== null) await put(root, 'registry/src/index.example-0000/' + name.replace('@', '-') + '/Cargo.toml', manifest);
  await put(root, 'consensus/go.mod', 'module github.com/cometbft/cometbft\n\ngo 1.26.0\n\nrequire (\n\tgithub.com/BurntSushi/toml v1.4.0\n\texample.org/indirect v0.1.0 // indirect\n)\n\nrequire example.org/single v1.0.0\n');
  await put(root, 'consensus/go.sum', 'github.com/BurntSushi/toml v1.4.0 h1:AAAA=\ngithub.com/BurntSushi/toml v1.4.0/go.mod h1:BBBB=\nexample.org/indirect v0.1.0/go.mod h1:CCCC=\nexample.org/single v1.0.0 h1:DDDD=\n');
  for (const [module, files] of Object.entries(modules)) for (const [file, text] of Object.entries(files)) await put(root, 'gocache/' + module + '/' + file, text);
  const code = 'vendored();\n';
  await put(root, 'web-v4/wallet/vendor/sample.min.js', code);
  await put(root, 'web-v4/wallet/vendor/LICENSE.sample', vendorLicense);
  await put(root, 'web-v4/wallet/vendor/PROVENANCE.json', JSON.stringify({ package: 'sample', version: '1.2.3', vendoredFile: 'sample.min.js', vendoredSHA256: createHash('sha256').update(code).digest('hex'), license: vendorDeclared }));
  if (extraVendorFile) await put(root, 'web-v4/wallet/vendor/' + extraVendorFile, 'x');
  return { root, options: { root, registries: [root], goModCache: path.join(root, 'gocache'), lockfiles: ['Cargo.lock', 'sub/Cargo.lock'] } };
}
const manifest = license => `[package]\nname = "x"\nversion = "1.0.0"\n${license}\n\n[dependencies.license]\nversion = "9"\n`;

test('a choice of licences is used under the first allowed one in allowlist order', () => {
  assert.equal(use('MIT OR Apache-2.0'), 'Apache-2.0');
  assert.equal(use('Apache-2.0 OR MIT'), 'Apache-2.0');
  assert.equal(use('MIT/Apache-2.0'), 'Apache-2.0');
  assert.equal(use('Unlicense OR MIT'), 'MIT');
  assert.equal(use('MIT OR Apache-2.0 OR LGPL-2.1-or-later'), 'Apache-2.0');
  assert.equal(use('Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT'), 'Apache-2.0');
  assert.equal(use('MIT OR GPL-3.0-only'), 'MIT');
});

test('every part of an AND must be allowed, and an exception counts only as the listed pair', () => {
  assert.equal(use('(MIT OR Apache-2.0) AND Unicode-3.0'), 'Apache-2.0 AND Unicode-3.0');
  assert.equal(use('MIT AND GPL-3.0-only'), null);
  assert.equal(use('MIT OR Apache-2.0 AND GPL-3.0-only'), 'MIT', 'AND binds tighter than OR');
  assert.equal(use('(MIT OR Apache-2.0) AND GPL-3.0-only'), null);
  assert.equal(use('Apache-2.0 WITH LLVM-exception'), 'Apache-2.0 WITH LLVM-exception');
  assert.equal(use('GPL-2.0-only WITH Classpath-exception-2.0'), null);
  assert.equal(use('MIT WITH Some-exception'), null, 'an allowed licence with an unknown exception is not the allowed licence');
});

test('licences that are not permissive, or not on the list, are refused', () => {
  for (const expression of ['GPL-3.0-only', 'GPL-2.0-or-later', 'LGPL-2.1-or-later', 'AGPL-3.0-only', 'MPL-2.0', 'EPL-2.0', 'MITNFA', 'SSPL-1.0', 'BUSL-1.1', 'Unlicense', 'mit']) assert.equal(use(expression), null, expression);
  for (const copyleft of ['GPL', 'LGPL', 'AGPL', 'MPL', 'EPL', 'SSPL', 'BUSL']) assert.ok(!ALLOWED.some(id => id.toUpperCase().startsWith(copyleft)), copyleft);
  // One package, by the owner's decision of 2026-11-19. Another line here is another decision.
  assert.deepEqual(ACCEPTED.map(({ kind, name, version, license }) => [kind, name, version, license].join(' ')), ['rust hex_lit 0.1.1 MITNFA']);
  for (const item of ACCEPTED) assert.match(item.reason, /accepted by the project owner on \d{4}-\d{2}-\d{2}/, item.name);
});

test('an expression that cannot be read is an error, never a pass', () => {
  for (const expression of ['', '   ', 'MIT OR', 'OR MIT', '(MIT', 'MIT)', 'MIT Apache-2.0', 'MIT AND', '(MIT OR Apache-2.0) WITH LLVM-exception', 'MIT WITH', 'see LICENSE file']) assert.throws(() => parseExpression(expression), /licence expression/, JSON.stringify(expression));
});

test('the licence is read from the [package] table only', () => {
  assert.deepEqual(manifestLicense(manifest('license = "MIT OR Apache-2.0"')), { license: 'MIT OR Apache-2.0', file: null });
  assert.deepEqual(manifestLicense(manifest('license-file = "LICENSE.txt"')), { license: null, file: 'LICENSE.txt' });
  assert.deepEqual(manifestLicense(manifest('')), { license: null, file: null });
  assert.deepEqual(manifestLicense('[dependencies]\nlicense = "GPL-3.0-only"\n\n[package]\nname = "x"\nlicense = \'MIT\' # chosen\n\n[features]\nlicense = "ISC"\n'), { license: 'MIT', file: null });
  assert.deepEqual(manifestLicense('[package]\r\nname = "x"\r\nlicense = "ISC"\r\n'), { license: 'ISC', file: null });
});

test('a crate is found in a CARGO_HOME, in registry/src, or in the folder of crates itself', async () => {
  const { root } = await project({ crates: { 'alpha@1.0.0': manifest('license = "MIT"') } });
  const inner = path.join(root, 'registry/src/index.example-0000');
  for (const location of [root, path.join(root, 'registry/src'), inner]) assert.equal(crateLicense(registryDirectories([location]), 'alpha', '1.0.0').declared, 'MIT', location);
  assert.match(crateLicense(registryDirectories([inner]), 'alpha', '2.0.0').problem, /not in the registry/);
  assert.match(crateLicense(registryDirectories([path.join(root, 'nowhere')]), 'alpha', '1.0.0').problem, /not in the registry/);
});

test('go.mod is read block by block, and go.sum says whether the source was fetched', () => {
  const modules = goModules('module m\n\nrequire (\n\tgithub.com/BurntSushi/toml v1.4.0\n\texample.org/b v0.1.0 // indirect\n)\n\nrequire example.org/c v1.0.0\n\nretract (\n\tv0.38.14\n)\n', 'github.com/BurntSushi/toml v1.4.0 h1:A=\ngithub.com/BurntSushi/toml v1.4.0/go.mod h1:B=\nexample.org/b v0.1.0/go.mod h1:C=\n');
  assert.deepEqual(modules, [
    { path: 'example.org/b', version: 'v0.1.0', direct: false, source_in_go_sum: false },
    { path: 'example.org/c', version: 'v1.0.0', direct: true, source_in_go_sum: false },
    { path: 'github.com/BurntSushi/toml', version: 'v1.4.0', direct: true, source_in_go_sum: true }
  ]);
  assert.throws(() => goModules('module m\n\nreplace example.org/a => ../a\n', ''), /replace/);
  assert.equal(escapeModulePath('github.com/BurntSushi/toml'), 'github.com/!burnt!sushi/toml');
});

test('licence texts are recognised by their own sentences, and a mention of another licence is not that licence', () => {
  assert.equal(classifyText(MIT), 'MIT');
  assert.equal(classifyText(BSD3), 'BSD-3-Clause');
  assert.equal(classifyText(BSD2), 'BSD-2-Clause');
  assert.equal(classifyText(MPL), 'MPL-2.0', 'MPL-2.0 names the GNU licences without being one');
  assert.equal(classifyText(GPL), 'GPL');
  assert.equal(classifyText(MIT + '\n---\n' + BSD3), 'MIT AND BSD-3-Clause');
  assert.equal(classifyText('All rights reserved.'), null);
});

test('a Go module is "to check" unless a licence file in the module cache is recognised', async () => {
  const { root } = await project({ modules: { 'github.com/!burnt!sushi/toml@v1.4.0': { COPYING: MIT }, 'example.org/single@v1.0.0': { LICENSE: 'Custom terms.' }, 'example.org/two@v1.0.0': { LICENSE: MIT, 'LICENSE-THIRD-PARTY': MPL }, 'example.org/none@v1.0.0': { 'README.md': 'x' } } });
  const cache = path.join(root, 'gocache');
  assert.deepEqual(goLicense(cache, 'github.com/BurntSushi/toml', 'v1.4.0'), { detected: 'MIT', note: 'read from COPYING' });
  assert.match(goLicense(cache, 'example.org/single', 'v1.0.0').note, /^to check: LICENSE is not a text/);
  assert.equal(goLicense(cache, 'example.org/two', 'v1.0.0').detected, 'MIT AND MPL-2.0', 'every licence file counts');
  assert.match(goLicense(cache, 'example.org/none', 'v1.0.0').note, /^to check: no licence file/);
  assert.match(goLicense(cache, 'example.org/absent', 'v1.0.0').note, /^to check: not in the module cache/);
  assert.match(goLicense(null, 'example.org/absent', 'v1.0.0').note, /^to check: no module cache given/);
});

test('the vendored file must have the recorded hash, the declared licence and nothing beside it', async () => {
  const good = await project();
  assert.deepEqual(vendoredJavaScript(good.root)[0].problems, []);
  assert.equal(vendoredJavaScript(good.root)[0].declared, 'MIT');
  await writeFile(path.join(good.root, 'web-v4/wallet/vendor/sample.min.js'), 'changed();\n');
  assert.match(vendoredJavaScript(good.root)[0].problems.join(), /does not have the hash/);
  const other = await project({ vendorLicense: MPL });
  assert.match(vendoredJavaScript(other.root)[0].problems.join(), /says MIT but LICENSE\.sample reads like MPL-2\.0/);
  const extra = await project({ extraVendorFile: 'second.min.js' });
  assert.match(vendoredJavaScript(extra.root)[0].problems.join(), /second\.min\.js is not described/);
  assert.match(failures(buildInventory(extra.options)).join(), /second\.min\.js/, 'an undescribed vendored file fails the check');
});

test('the inventory passes when everything is allowed, and lists each crate once with its lockfiles', async () => {
  const { options } = await project({ crates: { 'alpha@1.0.0': manifest('license = "MIT OR Apache-2.0"'), 'beta@2.0.0': manifest('license = "BSD-3-Clause"') }, modules: { 'github.com/!burnt!sushi/toml@v1.4.0': { LICENSE: MIT } } });
  const inventory = buildInventory(options);
  assert.deepEqual(inventory.rust.map(crate => [crate.name, crate.use, crate.lockfiles.join()]), [['alpha', 'Apache-2.0', '(root),sub'], ['beta', 'BSD-3-Clause', '(root)']]);
  assert.deepEqual(inventory.own.map(crate => crate.name), ['own-crate']);
  assert.deepEqual(inventory.go.map(module => [module.path, module.use]), [[CONSENSUS_MODULE.path, null], ['example.org/indirect', null], ['example.org/single', null], ['github.com/BurntSushi/toml', 'MIT']]);
  assert.deepEqual(failures(inventory), []);
  assert.deepEqual(failures(inventory, { strict: true }), [], 'a Go module that is to check never fails the run');
  const text = render(inventory);
  for (const expected of ['| alpha | 1.0.0 | MIT OR Apache-2.0 | Apache-2.0 | (root), sub |', '| github.com/BurntSushi/toml | v1.4.0 | directly | yes | MIT | read from LICENSE |', '| example.org/indirect | v0.1.0 | indirectly | no | to check | not in the module cache |', '| sample | 1.2.3 | web-v4/wallet/vendor/sample.min.js |', '`own-crate`']) assert.ok(text.includes(expected), expected);
  assert.ok(!text.includes(options.root) && !text.includes(tmpdir()), 'no local path in the output');
  assert.equal(render(buildInventory(options)), text, 'the output is deterministic');
});

test('a licence outside the allowlist fails the check, for a crate, a Go module and vendored code', async () => {
  const { options } = await project({ crates: { 'alpha@1.0.0': manifest('license = "GPL-3.0-only"'), 'beta@2.0.0': manifest('license = "MIT AND MPL-2.0"') }, modules: { 'github.com/!burnt!sushi/toml@v1.4.0': { LICENSE: MPL } }, vendorLicense: GPL, vendorDeclared: 'GPL-3.0-only' });
  const inventory = buildInventory(options);
  assert.deepEqual(inventory.outside.map(item => [item.kind, item.name, item.license]), [['rust', 'alpha', 'GPL-3.0-only'], ['rust', 'beta', 'MIT AND MPL-2.0'], ['go', 'github.com/BurntSushi/toml', 'MPL-2.0'], ['js', 'sample', 'GPL-3.0-only']]);
  assert.equal(failures(inventory).filter(line => /not on the allowlist/.test(line)).length, 4);
  assert.ok(render(inventory).includes('OUTSIDE THE ALLOWLIST'));
});

test('a crate whose licence cannot be read is listed, and fails only a strict run', async () => {
  const { options } = await project({ crates: { 'alpha@1.0.0': manifest('license-file = "LICENSE.txt"'), 'beta@2.0.0': manifest(''), 'gamma@3.0.0': null, 'delta@4.0.0': manifest('license = "see the file"') } });
  const inventory = buildInventory(options);
  assert.deepEqual(inventory.undetermined.filter(item => item.kind === 'rust').map(item => item.name), ['alpha', 'beta', 'gamma']);
  assert.deepEqual(inventory.outside.map(item => item.name), ['delta'], 'an unreadable expression is outside the allowlist');
  assert.equal(failures(inventory).length, 1);
  assert.equal(failures(inventory, { strict: true }).length, 4);
});

test('one package can be accepted by exact name, version and licence, with a reason', async () => {
  const { options } = await project({ crates: { 'alpha@1.0.0': manifest('license = "MITNFA"'), 'beta@2.0.0': manifest('license = "MITNFA"') } });
  const accepted = [{ kind: 'rust', name: 'alpha', version: '1.0.0', license: 'MITNFA', reason: 'read on 2026-11-17: MIT with a rule about attribution' }];
  const inventory = buildInventory({ ...options, accepted });
  assert.deepEqual(inventory.outside.map(item => item.name), ['beta'], 'the acceptance covers one package, not the licence');
  assert.deepEqual(inventory.exceptions.map(item => item.name), ['alpha']);
  assert.ok(render(inventory).includes('read on 2026-11-17'));
  assert.deepEqual(buildInventory({ ...options, accepted: [{ ...accepted[0], version: '1.0.1' }] }).outside.map(item => item.name), ['alpha', 'beta'], 'another version is not accepted');
  assert.throws(() => buildInventory({ ...options, accepted: [{ ...accepted[0], reason: '' }] }), /needs a reason/);
});

test('the command exits 0, 1 or 2 and needs a registry', async () => {
  const good = await project({ crates: { 'alpha@1.0.0': manifest('license = "MIT"') } });
  const bad = await project({ crates: { 'alpha@1.0.0': manifest('license = "GPL-3.0-only"') } });
  const quiet = async action => { const log = console.log, error = console.error; console.log = console.error = () => {}; try { return await action(); } finally { console.log = log; console.error = error; } };
  // The lockfile list is fixed in the tool, so the command is tried on this repository's lockfiles with an empty registry.
  assert.equal(await quiet(() => main(['--registry', path.join(good.root, 'nowhere')], {})), 2);
  assert.equal(await quiet(() => main([], {})), 2);
  assert.equal(await quiet(() => main(['--unknown', 'x'], {})), 2);
  assert.equal(await quiet(() => main(['--help'], {})), 0);
  assert.deepEqual(failures(buildInventory(good.options)), []);
  assert.equal(failures(buildInventory(bad.options)).length, 1);
});

// ---- This repository ---------------------------------------------------------

test('the lockfile list is every Cargo.lock that public-manifest.json publishes', async () => {
  const published = JSON.parse(await readFile(path.join(repository, 'public-manifest.json'), 'utf8')).publish.flatMap(group => group.paths).filter(file => file.endsWith('Cargo.lock'));
  assert.deepEqual([...LOCKFILES].sort(), published.sort());
});

test('the committed inventory names every locked crate, every Go module and the vendored file', async () => {
  const text = await readFile(path.join(repository, OUTPUT), 'utf8');
  assert.ok(!text.includes('\r'), 'LF line endings');
  for (const lock of LOCKFILES) for (const pkg of cargoPackages(await readFile(path.join(repository, lock), 'utf8'))) {
    if (pkg.source === 'workspace') assert.ok(text.includes('`' + pkg.name + '`'), 'own crate ' + pkg.name);
    else assert.ok(text.includes('| ' + pkg.name + ' | ' + pkg.version + ' | '), lock + ': ' + pkg.name + ' ' + pkg.version + ' is missing: run node tools/licenses.mjs --out ' + OUTPUT);
  }
  const modules = goModules(await readFile(path.join(repository, 'consensus/go.mod'), 'utf8'), await readFile(path.join(repository, 'consensus/go.sum'), 'utf8'));
  assert.ok(modules.length > 100);
  for (const module of [CONSENSUS_MODULE, ...modules]) assert.ok(text.includes('| ' + module.path + ' | ' + module.version + ' | '), module.path + ' ' + module.version);
  assert.match(await readFile(path.join(repository, 'consensus/BUILD.md'), 'utf8'), new RegExp('\\*\\*' + CONSENSUS_MODULE.version.replaceAll('.', '\\.') + '\\*\\*'), 'the consensus version in the tool is the one BUILD.md pins');
  const [vendored] = vendoredJavaScript(repository);
  assert.deepEqual(vendored.problems, []);
  assert.ok(text.includes('| ' + vendored.name + ' | ' + vendored.version + ' | ' + vendored.file + ' | ' + vendored.sha256 + ' | MIT | '));
  assert.ok(!/[A-Za-z]:\\|\/Users\/|\/home\//.test(text), 'no local path in the committed inventory');
});
