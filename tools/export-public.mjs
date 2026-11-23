#!/usr/bin/env node
// Publication export. Copies exactly the files named in public-manifest.json
// into a NEW, empty directory outside the repository, and refuses to finish if
// any of them holds something that must not be published. Nothing is copied
// unless every file passes. This tool never pushes, uploads or creates a
// repository: what happens to the directory is the owner's step.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdir, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
// The file-name rules of the release packager: no runtime or tool directories,
// no secret-looking names (.env, *.pem, *.key, private*, secret*, seed*, ...).
import { safeRelative } from './release-v4.mjs';

export const MANIFEST = 'public-manifest.json';
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const byText = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// ---- What must not be published ----------------------------------------------

const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----/g;
// Access key ids (AKIA long-term, ASIA temporary) and a secret written next to its name.
const AWS_KEY = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g;
const AWS_SECRET = /aws_secret_access_key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{20,}/gi;
// Twelve digits that stand alone. A run inside a longer number, a hex string or
// an identifier is not an account number; one between ':', '.', '-', '/', quotes
// or spaces can be, and the tool cannot tell an account from an amount.
const TWELVE_DIGITS = /(?<![0-9A-Za-z_])[0-9]{12}(?![0-9A-Za-z_])/g;
const EMAIL = /[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}/g;
// A user's folder on some machine: a drive letter, then Users and a name; or a
// name under the Users or the home directory of a Unix system.
const LOCAL_PATH = /[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s"'<>|]+|\/Users\/[A-Za-z0-9._-]+\/|(?<![A-Za-z0-9._-])\/home\/[A-Za-z0-9._-]+\//g;
// A document that still waits for the owner's name, contact or decision. The
// marker is put together here so that this file does not contain it.
const PLACEHOLDER = new RegExp('\\[OWNER TO ' + 'SET[^\\]]*\\]', 'g');
const CREDENTIAL_FIELD =/^(?:priv_key|private_key|privateKey|secret_key|secretKey|signing_key|mnemonic|seed|password|passphrase|cookie|access_token|refresh_token|api_key|apiKey)$/;

const mask = (value, keep = 4) => (value.length <= keep * 2 ? '*'.repeat(value.length) : value.slice(0, keep) + '*'.repeat(value.length - keep * 2) + value.slice(-keep));
const lineOf = (text, index) => { let line = 1; for (let i = text.indexOf('\n'); i !== -1 && i < index; i = text.indexOf('\n', i + 1)) line++; return line; };

function listed(list, file, value) {
  return (list ?? []).some(entry => (entry.path === undefined || entry.path === file) && (entry.value === undefined || entry.value === value));
}
function emailAllowed(list, address) {
  const lower = address.toLowerCase();
  return (list ?? []).some(entry => { const allowed = String(entry.address ?? entry).toLowerCase(); return allowed.startsWith('*@') ? lower.endsWith(allowed.slice(1)) || lower.split('@')[1].endsWith('.' + allowed.slice(2)) : lower === allowed; });
}

// Every reason not to publish these bytes under this name. `scan` is the
// manifest's allowlists; `forbidden` are extra strings the owner supplies at run
// time (a name, a handle, an account number) so that they need not be written here.
export function inspect(file, bytes, scan = {}, forbidden = []) {
  const findings = [], add = (rule, detail, index, text) => findings.push({ rule, detail, line: index === null ? null : lineOf(text, index) });
  try { safeRelative(file); } catch (error) { add('secret-name', error.message, null); }
  const text = bytes.toString('latin1');
  const fixture = (scan.key_fixtures ?? []).some(entry => entry.path === file);
  for (const match of text.matchAll(PEM_BLOCK)) {
    if (fixture) continue;
    add(/PRIVATE KEY/.test(match[1]) ? 'private-key' : 'pem-block', 'BEGIN ' + match[1], match.index, text);
  }
  for (const match of text.matchAll(AWS_KEY)) add('aws-access-key', mask(match[0]), match.index, text);
  for (const match of text.matchAll(AWS_SECRET)) add('aws-secret-key', 'aws_secret_access_key = (hidden)', match.index, text);
  // The manifest itself holds the numbers it allowlists.
  const own = file === MANIFEST ? (scan.not_account_numbers ?? []).map(entry => entry.value) : [];
  for (const match of text.matchAll(TWELVE_DIGITS)) if (!listed(scan.not_account_numbers, file, match[0]) && !own.includes(match[0])) add('aws-account-number', mask(match[0], 2), match.index, text);
  // A third party's licence text is reproduced as it is, addresses included: exempt
  // from the email rule only, and only while it has exactly the recorded bytes.
  const thirdParty = (scan.third_party_texts ?? []).some(entry => entry.path === file && entry.sha256 === sha256(bytes));
  for (const match of text.matchAll(EMAIL)) if (!thirdParty && !emailAllowed(scan.email_allowlist, match[0])) add('email', match[0].replace(/^(.)[^@]*/, '$1***'), match.index, text);
  for (const match of text.matchAll(LOCAL_PATH)) if (!listed(scan.path_allowlist, file, match[0])) add('local-path', match[0].replace(/(Users[\\/]+|\/home\/)(.).*/, '$1$2***'), match.index, text);
  for (const match of text.matchAll(PLACEHOLDER)) add('unfilled-placeholder', match[0].length > 60 ? match[0].slice(0, 57) + '...' : match[0], match.index, text);
  if (file.endsWith('.json') && !fixture) {
    let parsed = null;
    try { parsed = JSON.parse(bytes.toString('utf8').replace(/^\uFEFF/, '')); } catch { /* not JSON: the text rules above still applied */ }
    const walk = node => {
      if (!node || typeof node !== 'object') return;
      for (const [key, item] of Object.entries(node)) {
        if (CREDENTIAL_FIELD.test(key) && item !== null && item !== '' && item !== false) add('credential-field', 'JSON field "' + key + '"', null);
        walk(item);
      }
    };
    walk(parsed);
  }
  const lower = text.toLowerCase();
  for (const word of forbidden) { const index = lower.indexOf(word.toLowerCase()); if (word && index !== -1) add('forbidden-string', 'a string from the forbid file (entry ' + (forbidden.indexOf(word) + 1) + ')', index, text); }
  return findings;
}

// ---- Manifest -----------------------------------------------------------------

export function readManifest(text) {
  const manifest = JSON.parse(text);
  if (manifest.schema_version !== 1 || !Array.isArray(manifest.publish) || !Array.isArray(manifest.withheld)) throw new Error('Unsupported publication manifest');
  const files = [];
  for (const group of manifest.publish) {
    if (typeof group.group !== 'string' || !Array.isArray(group.paths)) throw new Error('A publish group needs a name and paths');
    for (const file of group.paths) {
      if (typeof file !== 'string' || !/^[A-Za-z0-9._/-]+$/.test(file) || file.startsWith('/') || file.endsWith('/') || file.split('/').some(part => !part || part === '.' || part === '..')) throw new Error('Not an exact relative file path: ' + file);
      files.push({ path: file, group: group.group });
    }
  }
  const seen = new Set();
  for (const file of files) { const key = file.path.toLowerCase(); if (seen.has(key)) throw new Error('Listed twice: ' + file.path); seen.add(key); }
  for (const entry of manifest.withheld) if (!Array.isArray(entry.paths) || typeof entry.reason !== 'string' || !entry.reason) throw new Error('A withheld entry needs paths and a reason');
  for (const entry of manifest.withheld) for (const prefix of entry.paths) for (const file of files) if (file.path === prefix || (prefix.endsWith('/') && file.path.startsWith(prefix))) throw new Error('Both published and withheld: ' + file.path);
  return { ...manifest, files };
}
const withheldBy = (manifest, file) => manifest.withheld.find(entry => entry.paths.some(prefix => file === prefix || (prefix.endsWith('/') && file.startsWith(prefix))));

// Files git tracks, or null when this is not a git checkout (an exported copy).
export function trackedFiles(root) {
  try { return execFileSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true }).split('\0').filter(Boolean); } catch { return null; }
}

async function regularFile(root, relative) {
  let current = root;
  for (const part of relative.split('/')) { current = path.join(current, part); if ((await lstat(current)).isSymbolicLink()) throw new Error('is or lies behind a symbolic link'); }
  const info = await lstat(current);
  if (!info.isFile() || info.nlink !== 1) throw new Error('is not a single-link regular file');
  return current;
}

// ---- Export --------------------------------------------------------------------

// Returns { published, refused, undecided, missing }. Copies only when all three
// problem lists are empty, unless skipRefused asks for the clean files alone
// (the result is then marked incomplete and still counts as a failure).
export async function exportPublic({ root, out, manifestPath = null, forbidden = [], skipRefused = false, tracked = undefined }) {
  root = await realpath(root); out = path.resolve(out);
  const inside = path.relative(root, out);
  if (!inside || (!inside.startsWith('..') && !path.isAbsolute(inside))) throw new Error('The output directory must be outside the repository');
  try { if ((await readdir(out)).length) throw new Error('The output directory must be new or empty'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const manifest = readManifest(await readFile(manifestPath ?? path.join(root, MANIFEST), 'utf8'));
  const refused = [], clean = [], missing = [];
  for (const file of manifest.files) {
    let bytes;
    try { bytes = await readFile(await regularFile(root, file.path)); } catch (error) { if (error.code === 'ENOENT') missing.push(file.path); else refused.push({ path: file.path, group: file.group, findings: [{ rule: 'not-a-plain-file', detail: error.message, line: null }] }); continue; }
    const findings = inspect(file.path, bytes, manifest.scan, forbidden);
    if (findings.length) refused.push({ path: file.path, group: file.group, findings }); else clean.push({ ...file, bytes });
  }
  if (tracked === undefined) tracked = trackedFiles(root);
  const listedPaths = new Set(manifest.files.map(file => file.path));
  const undecided = (tracked ?? []).filter(file => !listedPaths.has(file) && !withheldBy(manifest, file)).sort(byText);
  const complete = !refused.length && !missing.length && !undecided.length;
  const published = [];
  if (complete || skipRefused) {
    for (const file of clean) {
      const target = path.join(out, file.path);
      await mkdir(path.dirname(target), { recursive: true });
      await writeFile(target, file.bytes, { flag: 'wx' });
      if (sha256(await readFile(target)) !== sha256(file.bytes)) throw new Error('Copy differs from source: ' + file.path);
      published.push({ path: file.path, group: file.group, size: file.bytes.length, sha256: sha256(file.bytes) });
    }
    if (!complete) await writeFile(path.join(out, 'EXPORT-INCOMPLETE.txt'), 'This export is NOT complete and must not be published.\nThe scan refused or could not find:\n' + [...refused.map(item => item.path), ...missing, ...undecided].map(file => '  ' + file).join('\n') + '\n', { flag: 'wx' });
  }
  return { complete, out, published, refused, missing, undecided, withheld: manifest.withheld, git: tracked !== null, considered: manifest.files.length };
}

export function report(result) {
  const lines = [], groups = new Map();
  for (const file of result.published) groups.set(file.group, [...(groups.get(file.group) ?? []), file]);
  lines.push(result.complete ? 'PUBLISHED to ' + result.out : result.published.length ? 'INCOMPLETE copy in ' + result.out + ' (do not publish it)' : 'NOTHING COPIED');
  lines.push('', 'Files in the manifest: ' + result.considered + '. Copied: ' + result.published.length + ' (' + result.published.reduce((sum, file) => sum + file.size, 0) + ' bytes).');
  for (const [group, files] of groups) lines.push('  ' + String(files.length).padStart(4) + '  ' + group);
  lines.push('', 'Refused by the scan: ' + result.refused.length + ' file' + (result.refused.length === 1 ? '' : 's') + '.');
  for (const item of result.refused) {
    const rules = new Map();
    for (const finding of item.findings) { const key = finding.rule + ': ' + finding.detail; if (!rules.has(key)) rules.set(key, []); rules.get(key).push(finding.line); }
    lines.push('  ' + item.path);
    for (const [key, where] of rules) { const at = where.filter(line => line !== null); lines.push('      ' + key + (at.length ? ' (line ' + at.slice(0, 5).join(', ') + (at.length > 5 ? ', and ' + (at.length - 5) + ' more' : '') + ')' : '')); }
  }
  if (result.missing.length) lines.push('', 'In the manifest but not found:', ...result.missing.map(file => '  ' + file));
  if (result.undecided.length) lines.push('', 'Tracked by git, neither published nor withheld (decide, then add each to ' + MANIFEST + '):', ...result.undecided.map(file => '  ' + file));
  if (!result.git) lines.push('', 'Not a git checkout: could not look for files the manifest does not mention.');
  lines.push('', 'Withheld by the manifest:');
  for (const entry of result.withheld) lines.push('  ' + entry.paths.join(', ') + '\n      ' + entry.reason);
  lines.push('', result.complete ? 'The scan refused nothing. Read the directory before you publish it; this tool has published nothing.' : 'REFUSED: the export is not finished. Fix the files or the manifest and run it again into a new directory.');
  return lines.join('\n');
}

const USAGE = `node tools/export-public.mjs --out NEW_EMPTY_DIRECTORY [--manifest ${MANIFEST}] [--forbid-file FILE] [--skip-refused]
  --out DIR            Where the copy goes: a new or empty directory outside the repository.
  --manifest FILE      The list of files to publish. Default: ${MANIFEST} at the repository root.
  --forbid-file FILE   A local file, one string per line (a name, a handle, an account number),
                       that no published file may contain. Keep it outside the repository.
  --skip-refused       Copy the files that pass and mark the copy incomplete. Still fails.`;

export async function main(argv = process.argv.slice(2)) {
  const options = { root: fileURLToPath(new URL('../', import.meta.url)), out: null, manifestPath: null, forbidden: [], skipRefused: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === '--help') { console.log(USAGE); return 0; }
    if (flag === '--skip-refused') { options.skipRefused = true; continue; }
    const value = argv[++i];
    if (!value) { console.error('Missing value for ' + flag + '\n' + USAGE); return 2; }
    if (flag === '--out') options.out = value;
    else if (flag === '--manifest') options.manifestPath = value;
    else if (flag === '--root') options.root = value;
    else if (flag === '--forbid-file') options.forbidden = (await readFile(value, 'utf8')).split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    else { console.error('Unknown option ' + flag + '\n' + USAGE); return 2; }
  }
  if (!options.out) { console.error(USAGE); return 2; }
  const result = await exportPublic(options);
  console.log(report(result));
  return result.complete ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().then(code => { process.exitCode = code; }, error => { console.error(error.message); process.exitCode = 1; });
