#!/usr/bin/env node
// The repository's checks, in one list. The continuous-integration workflow (.github/workflows/ci.yml), a
// contributor's machine and the project's own Linux test run all start them through this file, so that "the
// checks pass" means the same commands everywhere.
//
//   node tools/ci-checks.mjs --list                 the names, one per line, with their group
//   node tools/ci-checks.mjs NAME [NAME ...]        run these checks
//   node tools/ci-checks.mjs --group rust           run every check of a group (rust, node, build, licences)
//   node tools/ci-checks.mjs --all                  run every check, one after the other
// Options:
//   --setup          run each check's setup commands first (installing a tool, fetching crates). They need the
//                    network; the checks themselves do not, except the first build of a crate.
//   --keep-going     with several checks, run them all even after one fails
//   --json FILE      write what ran (name, commands, exit codes, seconds) to FILE
//   --log-dir DIR    write each check's output to DIR/NAME.log instead of the terminal
//
// Exit code 0: every check that ran passed. 1: at least one failed. 2: wrong usage, nothing ran.
// A check that this system can only do in part (verifier-build anywhere but on Linux x86-64) counts as passed,
// is printed as PASSED IN PART with what was left out, and carries `partly` in the JSON file.
//
// What is not here: installing Rust and Node themselves. The versions are in rust-toolchain.toml,
// verifier-v4/rust-toolchain.toml and the workflow (Node 26).
import { spawnSync } from 'node:child_process';
import { existsSync, globSync, mkdirSync, openSync, closeSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Every crate with its own lockfile. `licences` fetches them all; `rust-*` tests them.
export const CRATES = [
  { name: 'v5', manifest: 'v5/Cargo.toml', note: 'the engine' },
  { name: 'pos', manifest: 'pos/Cargo.toml', note: 'staking' },
  { name: 'verifier-v4', manifest: 'verifier-v4/Cargo.toml', extra: ['--lib'], note: 'the light-client verifier' },
  { name: 'timecurrency-node', manifest: 'Cargo.toml', note: 'the first ledger crate, which v5 depends on' },
  { name: 'history', manifest: 'history/Cargo.toml' },
  { name: 'registration', manifest: 'registration/Cargo.toml' },
  { name: 'treasury', manifest: 'treasury/Cargo.toml' },
  { name: 'bitcoin-bridge', manifest: 'bitcoin-bridge/Cargo.toml' },
  { name: 'v4', manifest: 'v4/Cargo.toml', note: 'the protocol-4 application: the engine tests compare with it' },
  { name: 'v2', manifest: 'v2/Cargo.toml', note: 'a dev-dependency of the engine tests' },
];

/// The wasm-bindgen version the verifier is locked to: the command-line tool must be the same one.
export function wasmBindgenVersion(lock = readFileSync(path.join(root, 'verifier-v4', 'Cargo.lock'), 'utf8')) {
  const found = /\nname = "wasm-bindgen"\r?\nversion = "([0-9][0-9A-Za-z.+-]*)"/.exec(lock);
  if (!found) throw Error('verifier-v4/Cargo.lock names no wasm-bindgen version');
  return found[1];
}

const cargoTest = (crate) => ['cargo', 'test', '--locked', '--manifest-path', crate.manifest, ...(crate.extra ?? [])];

export function checks() {
  const list = [];
  for (const crate of CRATES) list.push({ name: 'rust-' + crate.name, group: 'rust', note: crate.note, run: [cargoTest(crate)] });
  list.push({
    name: 'rust-v5-rehearsal', group: 'rust',
    note: 'the engine built with a version 5 that has the rules of version 4, as upgrade rehearsals use it',
    // Its own build directory: the default build and this one make a node binary of the same name, and tests
    // that start the binary must not pick up the other one.
    env: { CARGO_TARGET_DIR: 'v5/target-rehearsal' },
    run: [['cargo', 'test', '--locked', '--manifest-path', 'v5/Cargo.toml', '--features', 'rehearsal-v5']],
  });
  list.push({
    name: 'rust-fuzz-harness', group: 'rust',
    note: 'every fuzz target run as an ordinary test, on its kept inputs and on generated ones (docs/fuzzing.md); skipped in a copy of the repository that does not hold the targets',
    // Not among CRATES: fuzz/ is not published (public-manifest.json says why), so the licence inventory, which
    // reads the published lockfiles, does not read this one. The harness itself adds no crate to those of the
    // engine and the verifier; libFuzzer's crates are in fuzz/Cargo.lock, which only `cargo fuzz` uses.
    onlyWith: 'fuzz/harness/Cargo.toml', run: [['cargo', 'test', '--locked', '--manifest-path', 'fuzz/harness/Cargo.toml']],
  });
  list.push({ name: 'node-clients', group: 'node', note: 'SDK, light client, servers, API, faucet, alert watch, gateway, wallet, explorer',
    run: [['node', '--test', 'client-v4/*.test.mjs', 'deploy/gateway/*.test.mjs', 'web-v4/wallet/*.test.mjs', 'web-v4/explorer/*.test.mjs']] });
  list.push({ name: 'node-release', group: 'node', note: 'release packagers, the genesis ceremony, and the deployment kit\'s own tests beside them (deploy/*.test.mjs)',
    run: [['node', '--test', 'tools/release-v4.test.mjs', 'tools/release-v5.test.mjs', 'tools/genesis-v5.test.mjs', 'deploy/*.test.mjs']] });
  list.push({ name: 'node-lease', group: 'node', note: 'the signer-lease controller and its host agent, with the kit\'s guard judging what it issues; random schedules of crashes, restores and moves',
    run: [['node', '--test', 'deploy/lease-controller/*.test.mjs']] });
  list.push({ name: 'node-repository', group: 'node', note: 'licence inventory, publication export, verifier build tool, this list',
    run: [['node', '--test', 'tools/licenses.test.mjs', 'tools/export-public.test.mjs', 'tools/build-verifier.test.mjs', 'tools/ci-checks.test.mjs']] });
  list.push({ name: 'node-harness', group: 'node', note: 'the cloud test harness; skipped in a copy of the repository that does not hold it',
    // testnet/ is the public test network's deployment, which is built from the harness and kept with it.
    onlyWith: 'campaign/lib/genesis.mjs', run: [['node', '--test', 'campaign/*.test.mjs', 'campaign/lib/*.test.mjs', 'testnet/*.test.mjs']] });
  list.push({
    name: 'verifier-build', group: 'build',
    note: 'rebuilds the compiled verifier and compares it, byte for byte, with the copy in web-v4/shared/verifier; the .wasm file is compared on Linux x86-64 only',
    // The tool's exit code 3: on a system other than Linux x86-64 the .wasm file was not compared.
    partly: { exit: 3, reason: 'the .wasm file is compared on Linux x86-64 only and was NOT compared here; the other files are what the source builds' },
    setup: [
      ['rustup', 'target', 'add', 'wasm32-unknown-unknown'],
      { unless: ['wasm-bindgen', '--version'], prints: 'wasm-bindgen ' + wasmBindgenVersion(), run: ['cargo', 'install', 'wasm-bindgen-cli', '--version', wasmBindgenVersion(), '--locked'] },
      ['cargo', 'fetch', '--locked', '--manifest-path', 'verifier-v4/Cargo.toml'],
    ],
    run: [['node', 'tools/build-verifier.mjs', '--check']],
  });
  list.push({
    name: 'licences', group: 'licences',
    // Rust crates and the JavaScript vendored in the wallet. Without a Go module cache the Go modules are listed
    // as "to check" and are not judged: run the tool with --go-mod-cache for that.
    note: 'every dependency against the licence allowlist',
    setup: CRATES.map((crate) => ['cargo', 'fetch', '--locked', '--manifest-path', crate.manifest]),
    run: [['node', 'tools/licenses.mjs', '--registry', process.env.CARGO_HOME ?? path.join(process.env.HOME ?? process.env.USERPROFILE ?? '', '.cargo'), '--strict']],
  });
  return list;
}

// On Windows `cargo`, `rustup` and `wasm-bindgen` are .exe files and are found without a shell; `node` is this
// program. No command goes through a shell, so nothing in a path or an argument is interpreted.
function start(command, { env, log }) {
  const [program, ...rest] = command;
  const file = program === 'node' ? process.execPath : program;
  const stdio = log === null ? 'inherit' : ['ignore', log, log];
  const began = Date.now();
  const result = spawnSync(file, rest, { cwd: root, env: { ...process.env, ...env }, stdio, windowsHide: true });
  return { command: command.join(' '), exit: result.error ? null : result.status, error: result.error ? String(result.error.message) : undefined, seconds: Math.round((Date.now() - began) / 100) / 10 };
}

/// The file patterns of a `node --test` command that match nothing. The test runner ignores such a pattern
/// without a word, so a mistyped one would run no test and pass.
export function emptyPatterns(command, base = root) {
  if (command[0] !== 'node' || command[1] !== '--test') return [];
  return command.slice(2).filter((pattern) => !pattern.startsWith('-') && globSync(pattern, { cwd: base }).length === 0);
}

function setupNeeded(step, context) {
  if (Array.isArray(step)) return step;
  // { unless, prints, run }: skip `run` when `unless` already prints exactly `prints`.
  const [program, ...rest] = step.unless;
  const probe = spawnSync(program, rest, { cwd: root, env: { ...process.env, ...context.env }, encoding: 'utf8', windowsHide: true });
  return !probe.error && probe.status === 0 && probe.stdout.trim() === step.prints ? null : step.run;
}

export function runCheck(check, { setup = false, logDir = null, base = root } = {}) {
  const env = check.env ?? {};
  if (check.onlyWith && !existsSync(path.join(base, check.onlyWith))) return { name: check.name, group: check.group, ok: true, skipped: `${check.onlyWith} is not in this copy`, seconds: 0, steps: [] };
  let log = null;
  if (logDir !== null) { mkdirSync(logDir, { recursive: true }); log = openSync(path.join(logDir, check.name + '.log'), 'a'); }
  const steps = [];
  let ok = true, partly = null;
  try {
    if (setup) for (const step of check.setup ?? []) {
      const command = setupNeeded(step, { env });
      if (command === null) continue;
      const done = { ...start(command, { env, log }), setup: true };
      steps.push(done);
      if (done.exit !== 0) { ok = false; break; }
    }
    if (ok) for (const command of check.run) {
      // For the harness, one pattern with files is enough: its tests may all be in one folder.
      const empty = emptyPatterns(command, base), all = command.slice(2).filter((word) => !word.startsWith('-'));
      if (empty.length && (!check.onlyWith || empty.length === all.length)) { steps.push({ command: command.join(' '), exit: null, error: 'no file matches ' + empty.join(', '), seconds: 0 }); ok = false; break; }
      const done = start(empty.length ? command.filter((word) => !empty.includes(word)) : command, { env, log });
      steps.push(done);
      // A check may name one exit code that means "passed as far as this system can tell", with the reason.
      if (check.partly && done.exit === check.partly.exit) { partly = check.partly.reason; continue; }
      if (done.exit !== 0) { ok = false; break; }
    }
  } finally { if (log !== null) closeSync(log); }
  return { name: check.name, group: check.group, ok, ...(ok && partly ? { partly } : {}), seconds: Math.round(steps.reduce((sum, step) => sum + step.seconds, 0) * 10) / 10, steps };
}

const USAGE = 'node tools/ci-checks.mjs --list | --all | --group GROUP | NAME [NAME ...]  [--setup] [--keep-going] [--json FILE] [--log-dir DIR]';

export function main(argv = process.argv.slice(2)) {
  const all = checks(), wanted = [];
  const options = { setup: false, keepGoing: false, json: null, logDir: null, list: false };
  for (let i = 0; i < argv.length; i++) {
    const word = argv[i];
    if (word === '--list') options.list = true;
    else if (word === '--all') wanted.push(...all);
    else if (word === '--setup') options.setup = true;
    else if (word === '--keep-going') options.keepGoing = true;
    else if (word === '--group' || word === '--json' || word === '--log-dir') {
      const value = argv[++i];
      if (!value) { console.error('Missing value for ' + word + '\n' + USAGE); return 2; }
      if (word === '--json') options.json = path.resolve(value);
      else if (word === '--log-dir') options.logDir = path.resolve(value);
      else {
        const group = all.filter((check) => check.group === value);
        if (!group.length) { console.error('No group named ' + value + '\n' + USAGE); return 2; }
        wanted.push(...group);
      }
    } else if (word.startsWith('-')) { console.error('Unknown option ' + word + '\n' + USAGE); return 2; }
    else {
      const check = all.find((item) => item.name === word);
      if (!check) { console.error('No check named ' + word + ' (see --list)'); return 2; }
      wanted.push(check);
    }
  }
  if (options.list) { for (const check of all) console.log(`${check.name}\t${check.group}${check.note ? '\t' + check.note : ''}`); return 0; }
  const chosen = [...new Set(wanted)];
  if (!chosen.length) { console.error(USAGE); return 2; }
  const results = [];
  for (const check of chosen) {
    console.log(`== ${check.name}`);
    const result = runCheck(check, options);
    results.push(result);
    console.log(`== ${check.name}: ${result.skipped ? 'skipped, ' + result.skipped : !result.ok ? 'FAILED' : result.partly ? 'PASSED IN PART (' + result.partly + ')' : 'passed'} in ${result.seconds} s`);
    for (const step of result.steps) if (step.error) console.log('   ' + step.command + ': ' + step.error);
    if (options.json) writeFileSync(options.json, JSON.stringify({ complete: false, results }, null, 1) + '\n');
    if (!result.ok && !options.keepGoing) break;
  }
  const ran = results.length === chosen.length, ok = ran && results.every((result) => result.ok);
  if (options.json) writeFileSync(options.json, JSON.stringify({ complete: ran, ok, results }, null, 1) + '\n');
  return ok ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main();
