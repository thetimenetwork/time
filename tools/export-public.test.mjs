import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MANIFEST, inspect, readManifest, exportPublic, report, trackedFiles, main } from './export-public.mjs';
import { safeRelative } from './release-v4.mjs';

const repository = fileURLToPath(new URL('../', import.meta.url));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const rules = (file, text, scan, forbidden) => [...new Set(inspect(file, Buffer.from(text), scan, forbidden).map(finding => finding.rule))].sort();
// Assembled at run time so that this file does not itself contain what the scan refuses.
const BEGIN = '-----BEGIN ', END = '-----';
const privateKey = BEGIN + 'PRIVATE KEY' + END + '\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n';
const accessKey = 'AKIA' + 'IOSFODNN7EXAMPLE';
const account = '1234' + '5678' + '9012';
const at = (user, host) => user + '@' + host;
const address = at('someone', 'mail.test-domain.io');
const windowsPath = 'C:' + '\\Users\\' + 'somebody\\project';

async function put(root, file, content = '') { await mkdir(path.dirname(path.join(root, file)), { recursive: true }); await writeFile(path.join(root, file), content); }
async function listFiles(directory, prefix = '') {
  const found = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) { const relative = prefix + entry.name; if (entry.isDirectory()) found.push(...await listFiles(path.join(directory, entry.name), relative + '/')); else found.push(relative); }
  return found.sort();
}
async function project(files, manifest = {}) {
  const base = await mkdtemp(path.join(tmpdir(), 'time-export-')), root = path.join(base, 'repo');
  for (const [file, content] of Object.entries(files)) await put(root, file, content);
  const body = { schema_version: 1, publish: [{ group: 'All', paths: Object.keys(files).filter(file => !(manifest.withheld ?? []).some(entry => entry.paths.includes(file))) }], withheld: [], scan: {}, ...manifest };
  await put(root, MANIFEST, JSON.stringify(body));
  return { base, root, out: path.join(base, 'out') };
}

test('a private key or any other PEM block is refused unless the file is a listed fixture', () => {
  for (const label of ['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'OPENSSH PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'PGP PRIVATE KEY BLOCK']) assert.deepEqual(rules('a.txt', 'x\n' + BEGIN + label + END + '\n'), ['private-key'], label);
  for (const label of ['CERTIFICATE', 'PUBLIC KEY', 'CERTIFICATE REQUEST']) assert.deepEqual(rules('a.txt', BEGIN + label + END), ['pem-block'], label);
  assert.deepEqual(rules('tests/key.fixture.txt', privateKey, { key_fixtures: [{ path: 'tests/key.fixture.txt', reason: 'test key' }] }), []);
  assert.deepEqual(rules('tests/other.txt', privateKey, { key_fixtures: [{ path: 'tests/key.fixture.txt', reason: 'test key' }] }), ['private-key'], 'the fixture list names files, not kinds');
  assert.deepEqual(rules('a.txt', 'no key here: BEGIN PRIVATE KEY'), []);
});

test('an AWS access key or secret is refused, also inside a fixture', () => {
  assert.deepEqual(rules('a.mjs', 'const id = "' + accessKey + '";'), ['aws-access-key']);
  assert.deepEqual(rules('a.mjs', 'ASIA' + 'ABCDEFGHIJKLMNOP'), ['aws-access-key']);
  assert.deepEqual(rules('a.ini', 'aws_secret_access_key = ' + 'wJalrXUtnFEMI/K7MDENG/bPxRfiCY' + 'EXAMPLEKEY'), ['aws-secret-key']);
  assert.deepEqual(rules('f.txt', accessKey, { key_fixtures: [{ path: 'f.txt' }] }), ['aws-access-key']);
  assert.deepEqual(rules('a.mjs', 'AKIA' + 'short'), []);
  assert.ok(!JSON.stringify(inspect('a.mjs', Buffer.from(accessKey))).includes(accessKey), 'a finding never repeats the key');
});

test('twelve digits standing alone are refused; a run inside a longer token is not', () => {
  for (const text of ['arn:aws:iam::' + account + ':role/x', "const ACCOUNT='" + account + "';", 'bucket-' + account + '-eu', account + '.dkr.ecr.eu-west-3.amazonaws.com', '"owner": ' + account]) assert.deepEqual(rules('a.mjs', text), ['aws-account-number'], text);
  for (const text of ['1' + account, account + '5', 'a3f0' + account + 'bc', 'id_' + account, '100_000_000_000', '12345678901', 'sha256 ' + 'c90f68a2032029c7176077669410aeae']) assert.deepEqual(rules('a.mjs', text), [], text);
  assert.ok(!JSON.stringify(inspect('a.mjs', Buffer.from(account))).includes(account), 'a finding never repeats the number');
  const scan = { not_account_numbers: [{ value: '604800000000', reason: 'seven days in microseconds' }, { path: 'only/here.json', value: account, reason: 'test' }] };
  assert.deepEqual(rules('anywhere.rs', '"604800000000"', scan), []);
  assert.deepEqual(rules('only/here.json', '"' + account + '"', scan), []);
  assert.deepEqual(rules('elsewhere.json', '"' + account + '"', scan), ['aws-account-number']);
});

test('an email address is refused unless allowlisted; versions and image names are not addresses', () => {
  assert.deepEqual(rules('a.md', 'write to ' + address), ['email']);
  const scan = { email_allowlist: [{ address: '*@example.com' }, { address: '*@example' }, { address: at('exact', 'allowed.test-domain.io') }] };
  for (const text of ['https://user:pass@example.com/', 'a@sub.example.com', 'https://u:p@wallet.example', at('Exact', 'Allowed.Test-Domain.io')]) assert.deepEqual(rules('a.mjs', text, scan), [], text);
  for (const text of [address, at('x', 'notexample.com'), at('x', 'example.com.evil.io'), at('other', 'allowed.test-domain.io')]) assert.deepEqual(rules('a.mjs', text, scan), ['email'], text);
  for (const text of ['hash-wasm@4.12.0', 'rust@sha256:' + 'a'.repeat(64), 'github.com/cometbft/cometbft@v0.38.26', '@scope/package', 'user@localhost']) assert.deepEqual(rules('a.mjs', text), [], text);
});

test("a third party's licence text may keep its addresses only while its bytes are the recorded ones", () => {
  const text = 'MIT License\nThanks to ' + address + '\n';
  const scan = { third_party_texts: [{ path: 'vendor/LICENSE.x', sha256: sha256(Buffer.from(text)), reason: 'licence text' }] };
  assert.deepEqual(rules('vendor/LICENSE.x', text, scan), []);
  assert.deepEqual(rules('vendor/LICENSE.x', text + 'added: ' + address, scan), ['email'], 'a changed file is scanned again');
  assert.deepEqual(rules('vendor/other.txt', text, scan), ['email']);
  assert.deepEqual(rules('vendor/LICENSE.x', text + windowsPath, { third_party_texts: [{ path: 'vendor/LICENSE.x', sha256: sha256(Buffer.from(text + windowsPath)) }] }), ['local-path'], 'only the email rule is lifted');
});

test("a path inside someone's user folder is refused, in every spelling", () => {
  for (const text of [windowsPath, windowsPath.replaceAll('\\', '\\\\'), windowsPath.replaceAll('\\', '/'), 'd:' + '\\Users\\' + 'x', '/Users/' + 'somebody/src', '/c/Users/' + 'somebody/src', 'cd /home/' + 'somebody/src', '"/home/' + 'ubuntu/time"']) assert.deepEqual(rules('a.md', text), ['local-path'], text);
  for (const text of ['C:\\Program Files\\Amazon', 'https://site.example/home/page/', '/data/ledger/v5-state', 'Users and homes', '/home/', '/opt/time-v4']) assert.deepEqual(rules('a.md', text), [], text);
  assert.deepEqual(rules('a.md', '/home/' + 'time/', { path_allowlist: [{ value: '/home/' + 'time/', reason: 'the service user of the unit file' }] }), []);
  assert.ok(!JSON.stringify(inspect('a.md', Buffer.from(windowsPath))).includes('somebody'), 'a finding does not repeat the user name');
  assert.deepEqual(rules('lib.wasm', Buffer.concat([Buffer.from([0, 97, 115, 109, 1, 0, 0, 0, 255, 254]), Buffer.from(windowsPath + '\\.cargo\\registry\\src\\lib.rs'), Buffer.from([0, 255])]).toString('latin1')), ['local-path'], 'compiled files are scanned as bytes');
});

test('JSON credential fields are refused, as in the release packager', () => {
  for (const key of ['priv_key', 'private_key', 'privateKey', 'mnemonic', 'seed', 'password', 'cookie', 'access_token', 'refresh_token', 'secret_key', 'passphrase', 'api_key']) {
    assert.deepEqual(rules('a.json', JSON.stringify({ outer: [{ [key]: 'value' }] })), ['credential-field'], key);
    assert.deepEqual(rules('a.json', JSON.stringify({ [key]: '' })), [], key + ' empty');
    assert.deepEqual(rules('a.json', JSON.stringify({ [key]: null })), [], key + ' null');
  }
  assert.deepEqual(rules('a.json', JSON.stringify({ public_key: 'ab', password_rules: 'x' })), []);
  assert.deepEqual(rules('a.json', '{not json'), [], 'unreadable JSON is still scanned as text');
  assert.deepEqual(rules('a.json', '{not json ' + accessKey), ['aws-access-key']);
});

test('a file name the release packager treats as secret is refused here too', () => {
  for (const file of ['.env', 'config/.env.production', 'keys/validator.pem', 'node.key', 'wallet.dat', 'private-notes.md', 'docs/secret.txt', 'seed.json', 'a/credential-store.mjs', 'secrets/readme.md', '.local/lab/x.json', '.tools/bin/x', 'target/debug/x', 'node_modules/a/index.js', 'has space.md', '../outside.md', 'a/./b.md', 'C:/x.md']) {
    assert.throws(() => safeRelative(file), undefined, file);
    assert.ok(rules(file, 'harmless').includes('secret-name'), file);
  }
  for (const file of ['README.md', '.github/workflows/ci.yml', 'v5/src/security.rs', 'deploy/keygen.mjs', 'client-v4/account-security.mjs', 'tools/export-public.mjs']) {
    assert.equal(safeRelative(file), file);
    assert.deepEqual(rules(file, 'harmless'), [], file);
  }
});

test('strings from the forbid file are refused in any letter case, and the report does not repeat them', () => {
  const findings = inspect('a.md', Buffer.from('Written by JANE Example.'), {}, ['Jane Example', 'acct-77']);
  assert.deepEqual(findings.map(finding => finding.rule), ['forbidden-string']);
  assert.ok(!JSON.stringify(findings).toLowerCase().includes('jane'));
  assert.deepEqual(rules('a.md', 'nothing here', {}, ['Jane Example']), []);
});

test('a document with a placeholder the owner has not filled is refused', () => {
  const marker = '[OWNER TO ' + 'SET: copyright holder]';
  assert.deepEqual(rules('NOTICE', 'Copyright 2026 ' + marker + '\n'), ['unfilled-placeholder']);
  assert.deepEqual(inspect('NOTICE', Buffer.from('a\nb ' + marker)).map(finding => [finding.detail, finding.line]), [[marker, 2]]);
  assert.deepEqual(rules('NOTICE', 'Copyright 2026 Example Foundation\n'), []);
});

test('the manifest lists exact files once, and never both publishes and withholds one', () => {
  const manifest = body => JSON.stringify({ schema_version: 1, publish: [{ group: 'g', paths: ['a.md'] }], withheld: [], ...body });
  assert.deepEqual(readManifest(manifest({})).files, [{ path: 'a.md', group: 'g' }]);
  for (const paths of [['dir/'], ['../a.md'], ['/a.md'], ['a/../b.md'], ['a//b.md'], ['*.md'], ['a b.md'], ['a.md', 'a.md'], ['a.md', 'A.md'], [7]]) assert.throws(() => readManifest(manifest({ publish: [{ group: 'g', paths }] })), undefined, JSON.stringify(paths));
  assert.throws(() => readManifest(manifest({ withheld: [{ paths: ['a.md'], reason: 'r' }] })), /Both published and withheld/);
  assert.throws(() => readManifest(manifest({ publish: [{ group: 'g', paths: ['dir/a.md'] }], withheld: [{ paths: ['dir/'], reason: 'r' }] })), /Both published and withheld/);
  assert.throws(() => readManifest(manifest({ withheld: [{ paths: ['x/'] }] })), /needs paths and a reason/);
  assert.throws(() => readManifest(manifest({ schema_version: 2 })), /Unsupported/);
  assert.throws(() => readManifest(JSON.stringify({ schema_version: 1, publish: [] })), /Unsupported/);
});

test('a clean export copies exactly the listed files, byte for byte', async () => {
  const binary = Buffer.from([0, 255, 13, 10, 13, 0, 128]);
  const { root, out } = await project({ 'README.md': 'line one\r\nline two\n', 'src/lib.rs': 'fn main() {}\n', 'web/a.wasm': binary, 'notes/private-plan.md': 'not listed' }, { publish: [{ group: 'Docs', paths: ['README.md'] }, { group: 'Code', paths: ['src/lib.rs', 'web/a.wasm'] }] });
  await put(root, 'untracked.txt', 'never copied');
  const result = await exportPublic({ root, out, tracked: null });
  assert.equal(result.complete, true);
  assert.deepEqual(await listFiles(out), ['README.md', 'src/lib.rs', 'web/a.wasm']);
  assert.equal((await readFile(path.join(out, 'README.md'))).toString('latin1'), 'line one\r\nline two\n', 'line endings are kept');
  assert.deepEqual(await readFile(path.join(out, 'web/a.wasm')), binary);
  assert.deepEqual(result.published.map(file => [file.path, file.group, file.sha256]), [['README.md', 'Docs', sha256(Buffer.from('line one\r\nline two\n'))], ['src/lib.rs', 'Code', sha256(Buffer.from('fn main() {}\n'))], ['web/a.wasm', 'Code', sha256(binary)]]);
  assert.match(report(result), /^PUBLISHED to /);
  assert.match(report(result), /Refused by the scan: 0 files\./);
  assert.match(report(result), /Not a git checkout/);
});

test('one refused file stops the whole export: nothing is copied', async () => {
  const { root, out } = await project({ 'README.md': 'fine\n', 'deploy/notes.md': 'account ' + account + '\n', 'tools/run.mjs': 'const key = "' + accessKey + '";\n// ' + windowsPath + '\n' });
  const result = await exportPublic({ root, out, tracked: null });
  assert.equal(result.complete, false);
  assert.deepEqual(result.published, []);
  await assert.rejects(readdir(out), { code: 'ENOENT' });
  assert.deepEqual(result.refused.map(item => [item.path, [...new Set(item.findings.map(finding => finding.rule))].sort()]), [['deploy/notes.md', ['aws-account-number']], ['tools/run.mjs', ['aws-access-key', 'local-path']]]);
  const text = report(result);
  assert.match(text, /^NOTHING COPIED/);
  assert.match(text, /Refused by the scan: 2 files\./);
  assert.match(text, /tools\/run\.mjs\n\s+aws-access-key: AKIA\*+MPLE \(line 1\)\n\s+local-path: .*\(line 2\)/);
  assert.match(text, /REFUSED: the export is not finished/);
  assert.ok(!text.includes(accessKey) && !text.includes(account) && !text.includes('somebody'));
});

test('--skip-refused copies the clean files, marks the copy incomplete and still fails', async () => {
  const { root, out } = await project({ 'README.md': 'fine\n', 'deploy/notes.md': 'account ' + account + '\n' });
  const result = await exportPublic({ root, out, tracked: null, skipRefused: true });
  assert.equal(result.complete, false);
  assert.deepEqual(await listFiles(out), ['EXPORT-INCOMPLETE.txt', 'README.md']);
  assert.match(await readFile(path.join(out, 'EXPORT-INCOMPLETE.txt'), 'utf8'), /NOT complete and must not be published[\s\S]*deploy\/notes\.md/);
  assert.match(report(result), /^INCOMPLETE copy in /);
});

test('a listed file that is missing, or a tracked file nobody decided on, stops the export', async () => {
  const missing = await project({ 'README.md': 'fine\n' }, { publish: [{ group: 'All', paths: ['README.md', 'gone.md'] }] });
  const first = await exportPublic({ root: missing.root, out: missing.out, tracked: null });
  assert.equal(first.complete, false);
  assert.deepEqual(first.missing, ['gone.md']);
  await assert.rejects(readdir(missing.out), { code: 'ENOENT' });
  const undecided = await project({ 'README.md': 'fine\n', 'old/a.md': 'x', 'old/b.md': 'x', 'new-file.mjs': 'x', 'logs/run.log': 'x' }, { publish: [{ group: 'All', paths: ['README.md'] }], withheld: [{ paths: ['old/', 'logs/run.log'], reason: 'superseded' }] });
  const second = await exportPublic({ root: undecided.root, out: undecided.out, tracked: ['README.md', 'old/a.md', 'old/b.md', 'new-file.mjs', 'logs/run.log', MANIFEST] });
  assert.equal(second.complete, false);
  assert.deepEqual(second.undecided, ['new-file.mjs', MANIFEST].sort());
  assert.match(report(second), /neither published nor withheld[\s\S]*new-file\.mjs/);
});

test('the output must be a new or empty directory outside the repository', async () => {
  const { base, root, out } = await project({ 'README.md': 'fine\n' });
  await assert.rejects(exportPublic({ root, out: path.join(root, 'public'), tracked: null }), /outside the repository/);
  await assert.rejects(exportPublic({ root, out: root, tracked: null }), /outside the repository/);
  await put(base, 'full/existing.txt', 'keep me');
  await assert.rejects(exportPublic({ root, out: path.join(base, 'full'), tracked: null }), /new or empty/);
  assert.equal(await readFile(path.join(base, 'full/existing.txt'), 'utf8'), 'keep me');
  await mkdir(path.join(base, 'empty'));
  assert.equal((await exportPublic({ root, out: path.join(base, 'empty'), tracked: null })).complete, true);
  assert.equal((await exportPublic({ root, out, tracked: null })).complete, true);
});

test('a symbolic link is never followed', async t => {
  const { base, root, out } = await project({ 'README.md': 'fine\n', 'real.md': 'x' }, { publish: [{ group: 'All', paths: ['README.md', 'link.md'] }] });
  await put(base, 'outside.md', 'outside the repository');
  try { await symlink(path.join(base, 'outside.md'), path.join(root, 'link.md')); } catch { t.skip('this account cannot create symbolic links'); return; }
  const result = await exportPublic({ root, out, tracked: null });
  assert.equal(result.complete, false);
  assert.deepEqual(result.refused.map(item => [item.path, item.findings[0].rule]), [['link.md', 'not-a-plain-file']]);
});

test('the command needs --out, and its exit code says whether the export finished', async () => {
  const quiet = async action => { const log = console.log, error = console.error; console.log = console.error = () => {}; try { return await action(); } finally { console.log = log; console.error = error; } };
  assert.equal(await quiet(() => main([])), 2);
  assert.equal(await quiet(() => main(['--out'])), 2);
  assert.equal(await quiet(() => main(['--unknown', 'x'])), 2);
  assert.equal(await quiet(() => main(['--help'])), 0);
  const good = await project({ 'README.md': 'fine\n' }), bad = await project({ 'README.md': 'mail ' + address + '\n' });
  assert.equal(await quiet(() => main(['--root', good.root, '--out', good.out])), 0);
  assert.equal(await quiet(() => main(['--root', bad.root, '--out', bad.out])), 1);
  await put(bad.base, 'forbid.txt', 'fine\n');
  assert.equal(await quiet(() => main(['--root', good.root, '--out', path.join(good.base, 'second'), '--forbid-file', path.join(bad.base, 'forbid.txt')])), 1);
});

// ---- This repository ---------------------------------------------------------

// Files the scan refuses today: none. The owner's blanks in the documents were
// filled on 23 November 2026; a file the scan refuses is now a fault. The
// compiled verifier is built by tools/build-verifier.mjs, which maps local paths
// away and refuses an output that still holds one.
const KNOWN_REFUSALS = {};

test('public-manifest.json is well formed, and every allowlist entry has a reason', async () => {
  const text = await readFile(path.join(repository, MANIFEST), 'utf8'), manifest = readManifest(text);
  assert.ok(!text.includes('\r'));
  assert.ok(manifest.files.length > 300);
  for (const file of manifest.files) assert.equal(safeRelative(file.path), file.path);
  for (const list of ['key_fixtures', 'third_party_texts', 'email_allowlist', 'not_account_numbers', 'path_allowlist']) for (const entry of manifest.scan[list]) assert.ok(typeof entry.reason === 'string' && entry.reason.length > 10, list + ': ' + JSON.stringify(entry));
  for (const entry of manifest.scan.email_allowlist) assert.match(entry.address, /^\*@example(?:\.(?:com|org|net))?$/, 'only names reserved for examples are allowlisted');
  for (const required of ['LICENSE', 'NOTICE', 'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'GOVERNANCE.md', 'CODE_OF_CONDUCT.md', 'CHANGELOG.md', 'docs/publishing.md', 'THIRD-PARTY-LICENSES.md', MANIFEST, 'rust-toolchain.toml', 'v5/Cargo.lock', 'campaign/lib/genesis.mjs']) assert.ok(manifest.files.some(file => file.path === required), required);
});

test('every file git tracks is either published or withheld by the manifest', async t => {
  const tracked = trackedFiles(repository);
  if (tracked === null || !tracked.includes(MANIFEST)) { t.skip('not a git checkout of this repository'); return; }
  const manifest = readManifest(await readFile(path.join(repository, MANIFEST), 'utf8')), published = new Set(manifest.files.map(file => file.path));
  const withheld = file => manifest.withheld.some(entry => entry.paths.some(prefix => file === prefix || (prefix.endsWith('/') && file.startsWith(prefix))));
  assert.deepEqual(tracked.filter(file => !published.has(file) && !withheld(file)), [], 'decide for each: add it to publish or to withheld in ' + MANIFEST);
  assert.deepEqual([...published].filter(file => !tracked.includes(file)), [], 'published but not tracked by git');
});

// The publication of 25 November 2026 failed its checks on GitHub: a published test imported the test network's proxy,
// which is withheld, and could not load there. Here every file was present, so nothing showed it. A published test file
// may import, by a relative path, published files only.
test('no published test imports a file that is not published', async () => {
  const manifest = readManifest(await readFile(path.join(repository, MANIFEST), 'utf8')), published = new Set(manifest.files.map(file => file.path));
  const missing = [];
  for (const file of manifest.files.filter(entry => /\.test\.m?js$/.test(entry.path))) {
    const text = await readFile(path.join(repository, file.path), 'utf8');
    const specs = new Set([...text.matchAll(/(?:from\s+|import\s*\(\s*|import\s+)['"](\.{1,2}\/[^'"]+)['"]/g)].map(found => found[1]));
    for (const spec of specs) {
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(file.path), spec));
      if (!published.has(target)) missing.push(`${file.path} imports ${target}`);
    }
  }
  assert.deepEqual(missing, [], 'publish the imported file, or withhold the test with it, in ' + MANIFEST);
});

test('the scan refuses nothing in the published files except the known open points', async () => {
  const manifest = readManifest(await readFile(path.join(repository, MANIFEST), 'utf8')), refused = {};
  for (const file of manifest.files) {
    const found = [...new Set(inspect(file.path, await readFile(path.join(repository, file.path)), manifest.scan).map(finding => finding.rule))].sort();
    if (found.length) refused[file.path] = found;
  }
  assert.deepEqual(refused, KNOWN_REFUSALS);
});

test('the Apache licence text is the canonical one, and the top-level documents state the status', async () => {
  const license = await readFile(path.join(repository, 'LICENSE'));
  assert.equal(sha256(license), 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30');
  assert.match(license.toString('utf8'), /Apache License\s+Version 2\.0, January 2004/);
  const readme = await readFile(path.join(repository, 'README.md'), 'utf8');
  for (const statement of [/has not launched/, /development chains only/, /publicLaunchAllowed=false/, /no external audit/, /real value/, /Apache License, Version 2\.0/]) assert.match(readme, statement);
  assert.match(await readFile(path.join(repository, 'SECURITY.md'), 'utf8'), /no external audit/);
});
