// The list of repository checks (tools/ci-checks.mjs) and the workflow that runs it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, globSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CRATES, checks, emptyPatterns, main, runCheck, wasmBindgenVersion } from './ci-checks.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const workflow = readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
const all = checks();
const quiet = (fn) => { const log = console.log, error = console.error, lines = []; console.log = console.error = (...words) => lines.push(words.join(' ')); try { return [fn(), lines]; } finally { console.log = log; console.error = error; } };

test('every check has one name, a group and a command; every crate it names is there', () => {
  assert.equal(new Set(all.map((check) => check.name)).size, all.length);
  for (const check of all) {
    assert.match(check.name, /^[a-z0-9-]+$/);
    assert(['rust', 'node', 'build', 'licences'].includes(check.group), check.name);
    assert(check.run.length > 0 && check.run.every((command) => Array.isArray(command) && command.length > 1), check.name);
  }
  for (const crate of CRATES) {
    assert(existsSync(path.join(root, crate.manifest)), crate.manifest);
    assert(existsSync(path.join(root, path.dirname(crate.manifest), 'Cargo.lock')), crate.manifest + ' has no lockfile beside it');
    assert(all.some((check) => check.name === 'rust-' + crate.name));
  }
  // Every cargo command is locked: a check never picks other crate versions than the lockfile's.
  for (const check of all) for (const command of [...check.run, ...(check.setup ?? []).map((step) => (Array.isArray(step) ? step : step.run))]) if (command[0] === 'cargo') assert(command.includes('--locked'), command.join(' '));
});

test('the rehearsal build of the engine has a build directory of its own', () => {
  const rehearsal = all.find((check) => check.name === 'rust-v5-rehearsal');
  assert(rehearsal.run[0].includes('rehearsal-v5'));
  assert(rehearsal.env.CARGO_TARGET_DIR && rehearsal.env.CARGO_TARGET_DIR !== 'v5/target');
  assert.match(readFileSync(path.join(root, 'v5', 'Cargo.toml'), 'utf8'), /^rehearsal-v5 = \[\]/m);
});

test('every test file of the repository is run by a check, and every pattern finds files', () => {
  const patterns = all.flatMap((check) => check.run.filter((command) => command[0] === 'node' && command[1] === '--test').flatMap((command) => command.slice(2)));
  const covered = new Set(patterns.flatMap((pattern) => globSync(pattern, { cwd: root }).map((file) => file.split(path.sep).join('/'))));
  const present = globSync('{client-v4,deploy,web-v4,tools,campaign}/**/*.test.mjs', { cwd: root, exclude: (name) => name === 'node_modules' || name === 'vendor' }).map((file) => file.split(path.sep).join('/'));
  assert(present.length > 40, 'the search for test files found too few: ' + present.length);
  assert.deepEqual(present.filter((file) => !covered.has(file)), [], 'test files no check runs');
  for (const check of all) for (const command of check.run) {
    const empty = emptyPatterns(command, root);
    if (check.onlyWith && !existsSync(path.join(root, check.onlyWith))) continue;
    // The harness check names two folders and needs files in one of them.
    if (check.onlyWith) assert(empty.length < command.length - 2, check.name + ' finds no test file');
    else assert.deepEqual(empty, [], check.name);
  }
});

test('the workflow starts checks only through the list, and starts every one of them', () => {
  const lines = workflow.split(/\r?\n/).map((line) => line.replace(/#.*$/, ''));
  const called = new Set();
  const matrix = /check:\s*\[([^\]]*)\]/.exec(workflow);
  assert(matrix, 'the workflow has no matrix of checks');
  const fromMatrix = matrix[1].split(',').map((word) => word.trim()).filter(Boolean);
  for (const line of lines) {
    const at = line.indexOf('node tools/ci-checks.mjs');
    if (at === -1) continue;
    const words = line.slice(at).trim().split(/\s+/).slice(2);
    for (let i = 0; i < words.length; i++) {
      const word = words[i];
      if (word === '--group') { const group = words[++i]; const members = all.filter((check) => check.group === group); assert(members.length, 'no group ' + group); for (const check of members) called.add(check.name); }
      else if (word === '${{' ) { assert.equal(words.slice(i, i + 3).join(' '), '${{ matrix.check }}'); for (const name of fromMatrix) called.add(name); i += 2; }
      else if (word.startsWith('--')) assert(['--setup', '--keep-going'].includes(word), 'the workflow passes ' + word);
      else called.add(word);
    }
  }
  for (const name of called) assert(all.some((check) => check.name === name), 'the workflow names a check that does not exist: ' + name);
  assert.deepEqual(all.map((check) => check.name).filter((name) => !called.has(name)), [], 'checks the workflow never starts');
  // No test or build command beside the list: a second copy of a command is how the two drift apart.
  for (const line of lines) {
    const run = /^\s*(?:-\s*)?run:\s*(.*)$/.exec(line)?.[1] ?? (/^\s{8,}(cargo|node)\s/.test(line) ? line.trim() : null);
    if (!run) continue;
    assert(!/\bcargo (test|build|fetch|install)\b/.test(run), 'the workflow runs cargo itself: ' + run);
    assert(!/\bnode --test\b/.test(run), 'the workflow runs tests itself: ' + run);
  }
});

test('the wasm-bindgen version is read from the verifier lockfile', () => {
  assert.match(wasmBindgenVersion(), /^0\.2\.[0-9]+$/);
  assert.equal(wasmBindgenVersion('\n[[package]]\nname = "wasm-bindgen"\nversion = "0.2.999"\n'), '0.2.999');
  assert.equal(wasmBindgenVersion('\r\n[[package]]\r\nname = "wasm-bindgen"\r\nversion = "0.2.7"\r\n'), '0.2.7');
  // A crate whose name only starts the same way is not it.
  assert.throws(() => wasmBindgenVersion('\nname = "wasm-bindgen-macro"\nversion = "0.2.1"\n'), /names no wasm-bindgen version/);
});

test('a check that fails is reported as failed, with its exit code, and later commands do not run', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ci-checks-'));
  try {
    const marker = path.join(directory, 'ran');
    const failing = { name: 'x', group: 'node', run: [['node', '-e', 'process.exit(3)'], ['node', '-e', `require('fs').writeFileSync(${JSON.stringify(marker)}, '')`]] };
    const result = runCheck(failing, { logDir: directory });
    assert.equal(result.ok, false);
    assert.equal(result.steps.length, 1);
    assert.equal(result.steps[0].exit, 3);
    assert.equal(existsSync(marker), false);
    const passing = runCheck({ name: 'y', group: 'node', setup: [['node', '-e', `require('fs').writeFileSync(${JSON.stringify(marker)}, '')`]], run: [['node', '-e', 'console.log("said")']] }, { logDir: directory });
    assert.equal(passing.ok, true);
    assert.equal(existsSync(marker), false, 'setup commands run only when asked');
    assert.match(readFileSync(path.join(directory, 'y.log'), 'utf8'), /said/);
    assert.equal(runCheck({ name: 'z', group: 'node', setup: [['node', '-e', 'process.exit(1)']], run: [['node', '-e', '']] }, { logDir: directory, setup: true }).ok, false, 'a failed setup fails the check');
    // An exit code a check names as "in part" passes with the reason; the same code from any other check fails
    // (the first lines of this test), and a later command that fails still fails the check.
    const partly = { exit: 3, reason: 'left out here' };
    const inPart = runCheck({ name: 'p', group: 'build', partly, run: [['node', '-e', 'process.exit(3)']] }, { logDir: directory });
    assert.equal(inPart.ok, true);
    assert.equal(inPart.partly, 'left out here');
    assert.equal(runCheck({ name: 'q', group: 'build', partly, run: [['node', '-e', '']] }, { logDir: directory }).partly, undefined, 'a full pass is not "in part"');
    const thenFails = runCheck({ name: 'r', group: 'build', partly, run: [['node', '-e', 'process.exit(3)'], ['node', '-e', 'process.exit(1)']] }, { logDir: directory });
    assert.equal(thenFails.ok, false);
    assert.equal(thenFails.partly, undefined);
    assert.equal(runCheck({ name: 's', group: 'build', partly, run: [['node', '-e', 'process.exit(1)']] }, { logDir: directory }).ok, false);
    // The verifier build is the one check that has such a code: the tool's 3, "the .wasm file was not compared".
    assert.deepEqual(all.filter((check) => check.partly).map((check) => [check.name, check.partly.exit]), [['verifier-build', 3]]);
    assert.match(all.find((check) => check.name === 'verifier-build').partly.reason, /NOT compared here/);
    // A program that is not installed is a failure with a reason, not a crash.
    const missing = runCheck({ name: 'w', group: 'node', run: [['no-such-program-ci-checks', '--version']] }, { logDir: directory });
    assert.equal(missing.ok, false);
    assert.equal(missing.steps[0].exit, null);
    assert(missing.steps[0].error);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('a test pattern that matches nothing fails the check instead of passing without running anything', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ci-checks-'));
  try {
    mkdirSync(path.join(directory, 'a'));
    writeFileSync(path.join(directory, 'a', 'one.test.mjs'), '');
    assert.deepEqual(emptyPatterns(['node', '--test', 'a/*.test.mjs', 'b/*.test.mjs'], directory), ['b/*.test.mjs']);
    assert.deepEqual(emptyPatterns(['cargo', 'test', 'b/*.test.mjs'], directory), []);
    const result = runCheck({ name: 'x', group: 'node', run: [['node', '--test', 'no-such-folder/*.test.mjs']] }, { logDir: directory });
    assert.equal(result.ok, false);
    assert.match(result.steps[0].error, /no file matches no-such-folder/);
    // A check for a part that a copy of the repository does not hold is skipped there, and says so.
    const skipped = runCheck({ name: 'h', group: 'node', onlyWith: 'not-here/file.mjs', run: [['node', '--test', 'not-here/*.test.mjs']] }, { logDir: directory, base: directory });
    assert.equal(skipped.ok, true);
    assert.match(skipped.skipped, /not-here\/file\.mjs is not in this copy/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('wrong usage runs nothing and exits with 2', () => {
  for (const argv of [[], ['no-such-check'], ['--group', 'no-such-group'], ['--json'], ['--frobnicate']]) assert.equal(quiet(() => main(argv))[0], 2, argv.join(' '));
  const [code, lines] = quiet(() => main(['--list']));
  assert.equal(code, 0);
  assert.deepEqual(lines.map((line) => line.split('\t')[0]), all.map((check) => check.name));
});
