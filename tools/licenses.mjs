#!/usr/bin/env node
// Third-party licence inventory.
//
// Reads what the published crates lock (Cargo.lock), what the consensus build
// pins (consensus/go.mod, consensus/go.sum) and what the wallet vendors
// (web-v4/wallet/vendor), finds each package's licence, and fails when one is
// outside the allowlist below. It reports what the packages' authors declare;
// it is not a legal review.
//
// The licences are read from copies on disk, never from the network:
//   --registry DIR       a Cargo registry: CARGO_HOME, its registry/src, or the
//                        directory that holds the NAME-VERSION folders
//                        (or TIME_CARGO_REGISTRY, or CARGO_HOME)
//   --go-mod-cache DIR   a Go module cache (or GOMODCACHE, or GOPATH/pkg/mod);
//                        optional: without it every Go module is "to check"
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { cargoPackages } from './release-v4.mjs';

// Permissive licences accepted without a second look, in order of preference
// when a package offers a choice. Adding a line here is a licensing decision.
export const ALLOWED = Object.freeze([
  'Apache-2.0', 'MIT', 'MIT-0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', '0BSD', 'Zlib', 'BSL-1.0',
  'Unicode-3.0', 'Unicode-DFS-2016', 'CC0-1.0',
  'Apache-2.0 WITH LLVM-exception'
]);
// One package accepted under a licence that is not on the list, after someone
// read it. Exact kind ('rust', 'go' or 'js'), name, version and licence; a
// reason is required. Only the project owner adds a line.
export const ACCEPTED = Object.freeze([
  // { kind: 'rust', name: 'example', version: '1.0.0', license: 'MPL-2.0', reason: 'who read it, when, why it is acceptable' }
  { kind: 'rust', name: 'hex_lit', version: '0.1.1', license: 'MITNFA',
    reason: 'accepted by the project owner on 2026-11-19. SPDX "MIT +no-false-attribs": the MIT licence with one more condition, that a copy changed in substance must not keep the original author\'s addresses for bug reports. Used unchanged, as a dependency of the bitcoin crate. The crate ships no licence text of its own' }
]);
// Every Cargo.lock of a published crate. tools/licenses.test.mjs checks this
// list against public-manifest.json.
export const LOCKFILES = Object.freeze([
  'Cargo.lock', 'v2/Cargo.lock', 'v4/Cargo.lock', 'v5/Cargo.lock', 'pos/Cargo.lock', 'treasury/Cargo.lock',
  'bitcoin-bridge/Cargo.lock', 'history/Cargo.lock', 'registration/Cargo.lock', 'verifier-v4/Cargo.lock'
]);
// consensus/go.mod is the main module's own file, so it does not name its version.
export const CONSENSUS_MODULE = Object.freeze({ path: 'github.com/cometbft/cometbft', version: 'v0.38.26' });
export const VENDOR_DIR = 'web-v4/wallet/vendor';
export const OUTPUT = 'THIRD-PARTY-LICENSES.md';

const byText = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

// ---- SPDX expressions -------------------------------------------------------

// Grammar: or := and ('OR' and)*; and := with ('AND' with)*; with := atom ['WITH' id];
// atom := id | '(' or ')'. The old Cargo form "MIT/Apache-2.0" means OR.
export function parseExpression(text) {
  if (typeof text !== 'string' || !text.trim()) throw new Error('Empty licence expression');
  const tokens = text.replace(/\//g, ' OR ').match(/\(|\)|[^\s()]+/g) ?? [];
  let at = 0;
  const word = value => tokens[at] !== undefined && tokens[at].toUpperCase() === value;
  const id = () => {
    const token = tokens[at++];
    if (token === undefined || !/^[A-Za-z0-9][A-Za-z0-9.+-]*$/.test(token) || ['AND', 'OR', 'WITH'].includes(token.toUpperCase())) throw new Error('Unreadable licence expression: ' + text);
    return token;
  };
  const atom = () => {
    if (tokens[at] === '(') { at++; const inner = or(); if (tokens[at++] !== ')') throw new Error('Unreadable licence expression: ' + text); return inner; }
    return { id: id() };
  };
  const withClause = () => { const left = atom(); if (!word('WITH')) return left; at++; if (!left.id) throw new Error('Unreadable licence expression: ' + text); return { id: left.id + ' WITH ' + id() }; };
  const and = () => { const parts = [withClause()]; while (word('AND')) { at++; parts.push(withClause()); } return parts.length === 1 ? parts[0] : { and: parts }; };
  const or = () => { const parts = [and()]; while (word('OR')) { at++; parts.push(and()); } return parts.length === 1 ? parts[0] : { or: parts }; };
  const tree = or();
  if (at !== tokens.length) throw new Error('Unreadable licence expression: ' + text);
  return tree;
}

// The terms we would use the package under, or null when no allowed choice exists.
// AND needs every part; OR needs one, and the allowlist order picks among several.
export function chooseLicense(tree, allowed = ALLOWED) {
  if (tree.id) return allowed.includes(tree.id) ? { use: tree.id, rank: allowed.indexOf(tree.id) } : null;
  if (tree.and) {
    const parts = tree.and.map(part => chooseLicense(part, allowed));
    return parts.every(Boolean) ? { use: parts.map(part => part.use).join(' AND '), rank: Math.max(...parts.map(part => part.rank)) } : null;
  }
  const parts = tree.or.map(part => chooseLicense(part, allowed)).filter(Boolean);
  return parts.length ? parts.reduce((best, part) => (part.rank < best.rank ? part : best)) : null;
}

// ---- Rust crates ------------------------------------------------------------

// Accepts CARGO_HOME, CARGO_HOME/registry/src, or a directory of NAME-VERSION folders.
export function registryDirectories(locations) {
  const found = [];
  const children = dir => { try { return readdirSync(dir, { withFileTypes: true }).filter(entry => entry.isDirectory()).map(entry => path.join(dir, entry.name)); } catch { return []; } };
  for (const location of locations) {
    const base = path.resolve(location);
    found.push(base, ...children(base), ...children(path.join(base, 'registry', 'src')));
  }
  return found;
}

// The licence a crate declares in the [package] table of its manifest.
export function manifestLicense(toml) {
  const lines = toml.split(/\r?\n/);
  let inPackage = false, license = null, file = null;
  for (const line of lines) {
    const table = /^\s*\[\[?([^\]]+)\]\]?\s*(?:#.*)?$/.exec(line);
    if (table) { inPackage = table[1].trim() === 'package'; continue; }
    if (!inPackage) continue;
    const field = /^\s*(license|license-file)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)')\s*(?:#.*)?$/.exec(line);
    if (!field) continue;
    const value = field[2] !== undefined ? field[2].replace(/\\(.)/g, '$1') : field[3];
    if (field[1] === 'license') license = value; else file = value;
  }
  return { license, file };
}

export function crateLicense(directories, name, version) {
  for (const directory of directories) {
    const manifest = path.join(directory, name + '-' + version, 'Cargo.toml');
    if (!existsSync(manifest)) continue;
    const { license, file } = manifestLicense(readFileSync(manifest, 'utf8'));
    if (license) return { declared: license };
    if (file) {
      let guess = null;
      try { guess = classifyText(readFileSync(path.join(path.dirname(manifest), file), 'utf8')); } catch { /* reported as unread */ }
      return { declared: null, problem: 'declares only a licence file (' + file + (guess ? ', which reads like ' + guess : '') + ')' };
    }
    return { declared: null, problem: 'declares no licence' };
  }
  return { declared: null, problem: 'not in the registry given (a crate for another platform is not downloaded by a build)' };
}

// ---- Go modules -------------------------------------------------------------

export function goModules(goMod, goSum) {
  const required = new Map();
  let block = false;
  if (/^\s*replace\b/m.test(goMod)) throw new Error('go.mod has a replace directive: this tool does not follow it');
  for (const raw of goMod.split(/\r?\n/)) {
    const line = raw.trim();
    if (/^require\s*\($/.test(line)) { block = true; continue; }
    if (block && line === ')') { block = false; continue; }
    const entry = block ? /^(\S+)\s+(v\S+)(\s*\/\/\s*indirect)?/.exec(line) : /^require\s+(\S+)\s+(v\S+)(\s*\/\/\s*indirect)?/.exec(line);
    if (entry) required.set(entry[1], { path: entry[1], version: entry[2], direct: !entry[3] });
  }
  // A line without "/go.mod" is the hash of the module's source: Go fetched the source.
  const fetched = new Set();
  for (const line of goSum.split(/\r?\n/)) {
    const [name, version, sum] = line.trim().split(/\s+/);
    if (sum && !version.endsWith('/go.mod')) fetched.add(name + '@' + version);
  }
  return [...required.values()].map(module => ({ ...module, source_in_go_sum: fetched.has(module.path + '@' + module.version) })).sort((a, b) => byText(a.path, b.path));
}

// The module cache writes an upper-case letter as "!" and its lower-case form.
export const escapeModulePath = value => value.replace(/[A-Z]/g, letter => '!' + letter.toLowerCase());

export function goLicense(cache, modulePath, version) {
  if (!cache) return { detected: null, note: 'to check: no module cache given' };
  const directory = path.join(cache, ...escapeModulePath(modulePath).split('/').slice(0, -1), escapeModulePath(modulePath).split('/').at(-1) + '@' + escapeModulePath(version));
  let names;
  try { names = readdirSync(directory); } catch { return { detected: null, note: 'to check: not in the module cache' }; }
  const files = names.filter(name => /^(?:licen[sc]e|copying|unlicense)(?:[.-].*)?$/i.test(name)).sort(byText);
  if (!files.length) return { detected: null, note: 'to check: no licence file at the top of the module' };
  const detected = new Set();
  for (const file of files) {
    let text;
    try { if (!statSync(path.join(directory, file)).isFile()) continue; text = readFileSync(path.join(directory, file), 'utf8'); } catch { continue; }
    const id = classifyText(text);
    if (!id) return { detected: null, note: 'to check: ' + file + ' is not a text this tool recognises' };
    detected.add(id);
  }
  if (!detected.size) return { detected: null, note: 'to check: no readable licence file' };
  return { detected: [...detected].sort(byText).join(' AND '), note: 'read from ' + files.join(', ') };
}

// Recognises a licence by the sentences that only it contains. Anything else is
// left for a person. A file that holds several licences is reported as all of them.
export function classifyText(text) {
  const flat = text.replace(/\s+/g, ' ');
  const has = pattern => pattern.test(flat);
  const found = [];
  // The GNU licences by their title line, in capitals: other licences (MPL-2.0) only mention them.
  if (has(/GNU AFFERO GENERAL PUBLIC LICENSE Version/)) found.push('AGPL');
  if (has(/GNU (?:LESSER|LIBRARY) GENERAL PUBLIC LICENSE Version/)) found.push('LGPL');
  if (has(/GNU GENERAL PUBLIC LICENSE Version/)) found.push('GPL');
  if (has(/Mozilla Public License,? [Vv]ersion 2\.0/)) found.push('MPL-2.0');
  if (has(/Eclipse Public License/i)) found.push('EPL');
  if (has(/Apache License,? Version 2\.0/i) && has(/TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION/)) found.push('Apache-2.0');
  if (has(/Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files/i)) found.push('MIT');
  if (has(/Permission to use, copy, modify, and(?:\/or)? distribute this software for any purpose with or without fee is hereby granted/i)) found.push('ISC');
  if (has(/Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met/i)) {
    found.push(has(/Neither the name|may not be used to endorse or promote products|The names? of .{0,80} may not be used/i) ? 'BSD-3-Clause' : 'BSD-2-Clause');
  }
  if (has(/This is free and unencumbered software released into the public domain/i)) found.push('Unlicense');
  if (has(/CC0 1\.0 Universal/i)) found.push('CC0-1.0');
  if (has(/Boost Software License - Version 1\.0/i)) found.push('BSL-1.0');
  if (has(/Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely/i)) found.push('Zlib');
  return found.length ? found.join(' AND ') : null;
}

// ---- JavaScript vendored in the wallet ---------------------------------------

export function vendoredJavaScript(root, vendor = VENDOR_DIR) {
  const directory = path.join(root, vendor), problems = [];
  const names = readdirSync(directory).sort(byText);
  const provenance = JSON.parse(readFileSync(path.join(directory, 'PROVENANCE.json'), 'utf8'));
  const declared = String(provenance.license ?? '').split(';')[0].trim();
  const licenseFiles = names.filter(name => /^LICENSE(?:\.|$)/.test(name));
  const file = provenance.vendoredFile;
  let detected = null;
  if (!licenseFiles.length) problems.push('no licence file next to the vendored code');
  else detected = classifyText(readFileSync(path.join(directory, licenseFiles[0]), 'utf8'));
  if (!file || !names.includes(file)) problems.push('PROVENANCE.json names a file that is not there');
  else if (sha256(readFileSync(path.join(directory, file))) !== provenance.vendoredSHA256) problems.push(file + ' does not have the hash PROVENANCE.json records');
  if (licenseFiles.length && detected !== declared) problems.push('PROVENANCE.json says ' + (declared || 'nothing') + ' but ' + licenseFiles[0] + ' reads like ' + (detected ?? 'no licence this tool recognises'));
  const expected = new Set(['PROVENANCE.json', file, ...licenseFiles, ...names.filter(name => /^README\./.test(name))]);
  for (const name of names) if (!expected.has(name)) problems.push(name + ' is not described by PROVENANCE.json');
  return [{ name: provenance.package, version: provenance.version, file: vendor + '/' + file, declared, license_file: licenseFiles[0] ? vendor + '/' + licenseFiles[0] : null, sha256: provenance.vendoredSHA256, problems }];
}

// ---- Inventory ---------------------------------------------------------------

function judge(kind, name, version, expression, allowed, accepted) {
  let choice = null, unreadable = null;
  try { choice = chooseLicense(parseExpression(expression), allowed); } catch (error) { unreadable = error.message; }
  if (choice) return { use: choice.use };
  const exception = accepted.find(item => item.kind === kind && item.name === name && item.version === version && item.license === expression);
  if (exception) {
    if (!exception.reason) throw new Error('An accepted package needs a reason: ' + name);
    return { use: expression, accepted: exception.reason };
  }
  return { outside: unreadable ?? 'not on the allowlist' };
}

export function buildInventory({ root, registries = [], goModCache = null, lockfiles = LOCKFILES, allowed = ALLOWED, accepted = ACCEPTED }) {
  const directories = registryDirectories(registries);
  const crates = new Map(), own = new Map();
  for (const lock of lockfiles) {
    const label = lock === 'Cargo.lock' ? '(root)' : path.posix.dirname(lock);
    for (const pkg of cargoPackages(readFileSync(path.join(root, lock), 'utf8'))) {
      const target = pkg.source === 'workspace' ? own : crates, key = pkg.name + '@' + pkg.version;
      if (!target.has(key)) target.set(key, { name: pkg.name, version: pkg.version, source: pkg.source, lockfiles: [] });
      target.get(key).lockfiles.push(label);
    }
  }
  const outside = [], undetermined = [], exceptions = [];
  const rust = [...crates.values()].sort((a, b) => byText(a.name, b.name) || byText(a.version, b.version)).map(crate => {
    const found = crateLicense(directories, crate.name, crate.version);
    if (!found.declared) { undetermined.push({ kind: 'rust', name: crate.name, version: crate.version, why: found.problem }); return { ...crate, declared: null, use: null, note: found.problem }; }
    const verdict = judge('rust', crate.name, crate.version, found.declared, allowed, accepted);
    if (verdict.outside) outside.push({ kind: 'rust', name: crate.name, version: crate.version, license: found.declared, why: verdict.outside });
    if (verdict.accepted) exceptions.push({ kind: 'rust', name: crate.name, version: crate.version, license: found.declared, reason: verdict.accepted });
    return { ...crate, declared: found.declared, use: verdict.use ?? null };
  });
  const modules = [{ ...CONSENSUS_MODULE, direct: true, source_in_go_sum: true, main: true }, ...goModules(readFileSync(path.join(root, 'consensus/go.mod'), 'utf8'), readFileSync(path.join(root, 'consensus/go.sum'), 'utf8'))];
  const go = modules.map(module => {
    const found = goLicense(goModCache, module.path, module.version);
    if (!found.detected) { undetermined.push({ kind: 'go', name: module.path, version: module.version, why: found.note }); return { ...module, detected: null, use: null, note: found.note }; }
    const verdict = judge('go', module.path, module.version, found.detected, allowed, accepted);
    if (verdict.outside) outside.push({ kind: 'go', name: module.path, version: module.version, license: found.detected, why: verdict.outside });
    if (verdict.accepted) exceptions.push({ kind: 'go', name: module.path, version: module.version, license: found.detected, reason: verdict.accepted });
    return { ...module, detected: found.detected, use: verdict.use ?? null, note: found.note };
  });
  const js = vendoredJavaScript(root).map(item => {
    for (const problem of item.problems) undetermined.push({ kind: 'js', name: item.name, version: item.version, why: problem });
    if (!item.declared) return { ...item, use: null };
    const verdict = judge('js', item.name, item.version, item.declared, allowed, accepted);
    if (verdict.outside) outside.push({ kind: 'js', name: item.name, version: item.version, license: item.declared, why: verdict.outside });
    if (verdict.accepted) exceptions.push({ kind: 'js', name: item.name, version: item.version, license: item.declared, reason: verdict.accepted });
    return { ...item, use: verdict.use ?? null };
  });
  return { lockfiles: [...lockfiles], own: [...own.values()].sort((a, b) => byText(a.name, b.name)), rust, go, js, outside, undetermined, exceptions, go_cache_given: Boolean(goModCache) };
}

function tally(items) {
  const counts = new Map();
  for (const item of items) { const stated = item.declared ?? item.detected; const key = item.use ?? (stated ? 'outside the allowlist (' + stated + ')' : 'to check'); counts.set(key, (counts.get(key) ?? 0) + 1); }
  return [...counts].sort((a, b) => b[1] - a[1] || byText(a[0], b[0]));
}
const cell = value => String(value).replace(/\|/g, '\\|');

export function render(inventory) {
  const { rust, go, js, own, outside, undetermined, exceptions } = inventory, out = [];
  const table = (head, rows) => { out.push('| ' + head.join(' | ') + ' |', '|' + head.map(() => '---').join('|') + '|', ...rows.map(row => '| ' + row.map(cell).join(' | ') + ' |'), ''); };
  out.push('# Third-party licences', '',
    'Generated by `node tools/licenses.mjs`. Do not edit by hand: change the lockfiles or the tool and run it again (see "Third-party licences" in `README.md`).', '',
    'What this is:', '',
    '- The licence each package **declares**, read from a copy of the package on disk. It is an inventory, not a legal review.',
    '- Rust: every crate in the `Cargo.lock` of a published crate (' + inventory.lockfiles.map(lock => '`' + lock + '`').join(', ') + '). A lockfile also holds test-only crates and crates for other platforms, so this is more than what ends up in a binary.',
    '- Go: the consensus binary is CometBFT, built from upstream source with the module versions in `consensus/go.mod`. Its source is not in this repository. The licence of a module is recognised from the licence file in a Go module cache when one is given; otherwise it is marked "to check".',
    '- JavaScript: the code vendored in `' + VENDOR_DIR + '`. Nothing else is vendored and no npm package is installed.',
    '- "Used under" is the choice made where a package offers several licences. The allowlist of permissive licences is in `tools/licenses.mjs`.', '');
  out.push('## Summary', '');
  table(['Kind', 'Packages', 'By licence used'], [
    ['Rust crates', rust.length, tally(rust).map(([name, count]) => count + ' × ' + name).join('; ')],
    ['Go modules', go.length, tally(go).map(([name, count]) => count + ' × ' + name).join('; ')],
    ['Vendored JavaScript', js.length, tally(js).map(([name, count]) => count + ' × ' + name).join('; ')]
  ]);
  out.push('## Needs a human look', '');
  if (!outside.length && !undetermined.length) out.push('Nothing.', '');
  if (outside.length) { out.push('Licence outside the allowlist (the check fails on these):', ''); table(['Kind', 'Package', 'Version', 'Licence', 'Why'], outside.map(item => [item.kind, item.name, item.version, item.license, item.why])); }
  if (undetermined.length) {
    const others = undetermined.filter(item => item.kind !== 'go'), modules = undetermined.filter(item => item.kind === 'go');
    if (others.length) { out.push('Licence not determined:', ''); table(['Kind', 'Package', 'Version', 'Why'], others.map(item => [item.kind, item.name, item.version, item.why])); }
    if (modules.length) out.push(modules.length + ' Go module' + (modules.length === 1 ? ' is' : 's are') + ' marked "to check" in the Go table below.', '');
  }
  if (exceptions.length) { out.push('Accepted one by one, outside the allowlist:', ''); table(['Kind', 'Package', 'Version', 'Licence', 'Reason'], exceptions.map(item => [item.kind, item.name, item.version, item.license, item.reason])); }
  out.push('## Rust crates', '');
  table(['Crate', 'Version', 'Declared licence', 'Used under', 'Locked by'], rust.map(crate => [crate.name, crate.version, crate.declared ?? 'not determined: ' + crate.note, crate.use ?? (crate.declared ? 'OUTSIDE THE ALLOWLIST' : 'to check'), crate.lockfiles.join(', ')]));
  out.push('## Go modules of the consensus build', '',
    '"Source fetched" says whether `consensus/go.sum` holds a hash of the module\'s source. Without one, Go only read the module\'s `go.mod` and none of its code is in the binary.', '');
  table(['Module', 'Version', 'Required', 'Source fetched', 'Licence', 'How it was found'], go.map(module => [module.path, module.version, module.main ? 'main module' : module.direct ? 'directly' : 'indirectly', module.source_in_go_sum ? 'yes' : 'no', module.detected ? (module.use ? module.detected : module.detected + ' (OUTSIDE THE ALLOWLIST)') : 'to check', module.note.replace(/^to check: /, '')]));
  out.push('## JavaScript vendored in the wallet', '');
  table(['Package', 'Version', 'File', 'SHA-256', 'Licence', 'Licence text'], js.map(item => [item.name, item.version, item.file, item.sha256, item.declared || 'not determined', item.license_file ?? 'missing']));
  out.push('## This project\'s own crates', '', 'These are the project itself, under the Apache License 2.0 (`LICENSE`): ' + own.map(crate => '`' + crate.name + '`').join(', ') + '.', '');
  return out.join('\n');
}

// Fails on a licence outside the allowlist. With strict, also on a Rust crate or
// vendored file whose licence could not be read. A Go module that is "to check"
// never fails the run: the module cache is optional.
export function failures(inventory, { strict = false } = {}) {
  const list = inventory.outside.map(item => item.kind + ' ' + item.name + ' ' + item.version + ': ' + item.license + ' (' + item.why + ')');
  for (const item of inventory.undetermined) if (item.kind === 'js' || (strict && item.kind === 'rust')) list.push(item.kind + ' ' + item.name + ' ' + item.version + ': ' + item.why);
  return list;
}

const USAGE = `node tools/licenses.mjs --registry DIR [--go-mod-cache DIR] [--out ${OUTPUT}] [--strict]
  --registry DIR       Cargo registry to read licences from: a CARGO_HOME, its registry/src, or the
                       directory holding the NAME-VERSION folders. May be given more than once.
                       Default: TIME_CARGO_REGISTRY, then CARGO_HOME, then ~/.cargo.
  --go-mod-cache DIR   Go module cache. Default: GOMODCACHE, then GOPATH/pkg/mod. Optional.
  --out FILE           Write the inventory there. Without it, only the summary is printed.
  --strict             Also fail when the licence of a Rust crate could not be read.`;

export function main(argv = process.argv.slice(2), env = process.env) {
  const options = { registries: [], goModCache: null, out: null, strict: false, root: fileURLToPath(new URL('../', import.meta.url)) };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === '--help') { console.log(USAGE); return 0; }
    if (flag === '--strict') { options.strict = true; continue; }
    const value = argv[++i];
    if (!value) { console.error('Missing value for ' + flag + '\n' + USAGE); return 2; }
    if (flag === '--registry') options.registries.push(value);
    else if (flag === '--go-mod-cache') options.goModCache = value;
    else if (flag === '--out') options.out = value;
    else if (flag === '--root') options.root = value;
    else { console.error('Unknown option ' + flag + '\n' + USAGE); return 2; }
  }
  if (!options.registries.length) {
    const home = env.HOME ?? env.USERPROFILE;
    const fallback = env.TIME_CARGO_REGISTRY ?? env.CARGO_HOME ?? (home ? path.join(home, '.cargo') : null);
    if (fallback) options.registries.push(fallback);
  }
  if (!options.registries.length || !options.registries.some(location => existsSync(location))) { console.error('No Cargo registry found. Run "cargo fetch --locked" for each lockfile first, then pass --registry.\n' + USAGE); return 2; }
  if (!options.goModCache) options.goModCache = env.GOMODCACHE ?? (env.GOPATH ? path.join(env.GOPATH.split(path.delimiter)[0], 'pkg', 'mod') : null);
  if (options.goModCache && !existsSync(options.goModCache)) options.goModCache = null;
  const inventory = buildInventory(options);
  if (options.out) writeFileSync(path.resolve(options.out), render(inventory));
  const failed = failures(inventory, options);
  const summary = kind => tally(inventory[kind]).map(([name, count]) => count + ' ' + name).join(', ');
  console.log('Rust crates: ' + inventory.rust.length + ' (' + summary('rust') + ')');
  console.log('Go modules: ' + inventory.go.length + ' (' + summary('go') + ')' + (inventory.go_cache_given ? '' : ' - no module cache given'));
  console.log('Vendored JavaScript: ' + inventory.js.length + ' (' + summary('js') + ')');
  for (const item of inventory.undetermined.filter(item => item.kind !== 'go')) console.log('To check: ' + item.kind + ' ' + item.name + ' ' + item.version + ': ' + item.why);
  for (const item of inventory.exceptions) console.log('Accepted: ' + item.kind + ' ' + item.name + ' ' + item.version + ' under ' + item.license + ': ' + item.reason);
  if (options.out) console.log('Wrote ' + options.out);
  if (failed.length) { console.error('\nLicence check failed:\n' + failed.map(line => '  ' + line).join('\n')); return 1; }
  console.log('Licence check passed: nothing outside the allowlist.');
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main();
