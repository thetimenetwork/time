#!/usr/bin/env node
// Builds the light-client verifier (verifier-v4) to WebAssembly for the wallet and shop pages, and writes it to
// web-v4/shared/verifier.
//
//   node tools/build-verifier.mjs           build and replace the compiled copy (on Linux x86-64 only)
//   node tools/build-verifier.mjs --check   build and compare with the compiled copy; changes nothing
//   node tools/build-verifier.mjs --local   on another system: replace the compiled copy with this system's
//                                           build, to try a change. Such a copy must not be committed.
// Exit codes of --check:
//   0  the compiled copy is what this source builds
//   1  a file differs
//   3  only on a system other than Linux x86-64: the files that do not depend on the building system are the
//      same, and the .wasm file was NOT compared
// Exit code 2 means that nothing could be built or written (the reason is printed), not that a file differs.
//
// The bytes of the compiled copy are defined by a build on Linux x86-64 (REFERENCE below). A build on another
// system gives a different .wasm file from the same source with the same toolchain. Measured in November 2026
// between Windows and Linux, on the two files side by side:
// - The source file names the compiler records for panic messages keep the building system's separator below
//   the mapped folder: /cargo\registry\src\... on Windows, /cargo/registry/src/... on Linux. 49 of the 89
//   names in the file differ in nothing else.
// - The hash Cargo gives each crate is part of every function's name, and it differs with the system that
//   builds (for the standard library, which comes compiled, it is the same). The functions then come out in
//   another order, and the code differs with them.
// Neither can be set from here. The glue files (.js, .d.ts) are the same on both systems, and --check compares
// them everywhere. So on another system --check cannot say that the .wasm file is what the source builds: it
// says that it did not compare it, and exits with 3. The project's continuous integration runs on Linux.
//
// On Linux x86-64 the same source gives the same bytes in whatever folder the repository is checked out. Two
// things are needed for that:
// - The compiler records source file paths in the binary (for panic messages). They are mapped to fixed names
//   (/time, /cargo, /rustup), so the result does not name the machine or the person that built it.
// - Cargo mixes the location of every local crate into the hashes that name the compiled items. For a crate
//   inside the workspace it uses the path relative to the workspace root; for one outside it uses the absolute
//   path, which no path mapping changes. verifier-v4 depends on ../history, which lies outside its own root. So
//   the build does not run in the repository: the script copies verifier-v4/ and history/ side by side into a
//   new staging folder, under a workspace manifest it writes at the staging root, and builds there. Every path
//   Cargo hashes is then relative to that root. The lockfile is verifier-v4/Cargo.lock, copied to the root and
//   used with --locked, so no dependency can change; the crate layout and lockfiles of the repository are not
//   touched.
// The script refuses to keep an output that still holds a local path.
//
// The staging folder gets a short name (tv-XXXXXX) in the system's temporary folder. On Windows the linker and
// other tools fail on a path longer than 259 characters (the linker says LNK1104, "cannot open file"), and the
// build makes paths of up to 160 characters below the staging folder. So on Windows a staging folder longer than
// 98 characters is not used: the script tries the next place (the user's own temporary folder, then the home
// folder), and when none is short enough it says so and stops before compiling. To choose the place yourself,
// set TIME_VERIFIER_STAGE to a short folder that exists (for example C:\tv). The place does not change the
// bytes: every path is mapped away or relative to the staging root.
//
// It uses the toolchain in .tools when that folder exists (the project's pinned copy), otherwise `cargo` and
// `wasm-bindgen` from the path; the versions must be the ones in rust-toolchain.toml and verifier-v4/Cargo.lock.
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, writeFile, readdir, copyFile, cp, rm, realpath } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tools = path.join(root, '.tools');
const local = existsSync(path.join(tools, 'cargo', 'bin'));
const exe = process.platform === 'win32' ? '.exe' : '';
const cargoHome = local ? path.join(tools, 'cargo') : (process.env.CARGO_HOME ?? path.join(os.homedir(), '.cargo'));
const rustupHome = local ? path.join(tools, 'rustup') : (process.env.RUSTUP_HOME ?? path.join(os.homedir(), '.rustup'));
const cargo = local ? path.join(cargoHome, 'bin', 'cargo' + exe) : 'cargo';
const bindgen = local ? path.join(cargoHome, 'bin', 'wasm-bindgen' + exe) : 'wasm-bindgen';
const out = path.join(root, 'web-v4', 'shared', 'verifier');
const CRATE = 'verifier-v4', LOCAL_DEPENDENCIES = ['history'];
// The longest path the build makes below the staging folder was measured at 142 characters (a fingerprint file
// of tendermint-light-client-verifier); 160 leaves room for a longer crate name. Windows' limit for a whole path
// is 259 characters.
const STAGE_PREFIX = 'tv-', DEEPEST = 160, WINDOWS_PATH_LIMIT = 259;
/// The longest a staging folder's own path may be on Windows.
export const STAGING_LIMIT = WINDOWS_PATH_LIMIT - 1 - DEEPEST;

/// The system whose build defines the bytes of the compiled copy.
export const REFERENCE = Object.freeze({ platform: 'linux', arch: 'x64', name: 'Linux x86-64' });
const thisSystem = () => ({ platform: process.platform, arch: process.arch });
export const onReference = ({ platform, arch } = thisSystem()) => platform === REFERENCE.platform && arch === REFERENCE.arch;
/// Whether the bytes of a built file depend on the system that built it.
export const dependsOnSystem = (name) => name.endsWith('.wasm');

/// Why a build may not replace the compiled copy on this system, or null when it may.
export function writeRefusal({ local = false, system = thisSystem() } = {}) {
  if (local || onReference(system)) return null;
  return `this system (${system.platform} ${system.arch}) is not ${REFERENCE.name}, whose build defines the compiled copy; nothing was built or written. To compare what can be compared here, run it with --check. To try a change here, --local writes this system's build over the compiled copy; do not commit that copy.`;
}

/// What --check says and exits with: `names` are the built files, `different` those that differ from the
/// compiled copy. Off the reference system a .wasm file that differs is what a right copy looks like and what a
/// wrong one looks like, so the answer says that it was not compared; it is never "the same as the source".
export function checkOutcome(names, different, { system = thisSystem(), where = 'web-v4/shared/verifier' } = {}) {
  const here = onReference(system);
  const judged = here ? different : different.filter((name) => !dependsOnSystem(name));
  if (judged.length) {
    const next = here
      ? 'Run node tools/build-verifier.mjs and commit the result.'
      : `These files do not depend on the system that builds them. The compiled copy that is committed comes from a build on ${REFERENCE.name}: build it there (node tools/build-verifier.mjs) and commit that result.`;
    return { code: 1, error: `The compiled verifier differs from what this source builds: ${judged.join(', ')}. ${next}` };
  }
  if (here) return { code: 0, line: `${names.join(', ')} in ${where} are what this source builds` };
  const compared = names.filter((name) => !dependsOnSystem(name)), left = names.filter(dependsOnSystem);
  // The one thing such a file does show here: a copy equal to this system's build is not the reference build.
  const ours = left.filter((name) => !different.includes(name));
  if (ours.length) return { code: 1, error: `${ours.join(', ')} in ${where} is the build of this system (${system.platform} ${system.arch}), so it is not the build of ${REFERENCE.name} that belongs there (was it written with --local?). "git checkout -- ${where.split('\\').join('/')}" puts the committed copy back; if this copy is the committed one, build on ${REFERENCE.name} and commit that result.` };
  return { code: 3, line: `NOT COMPARED on this system (${system.platform} ${system.arch}): ${left.join(', ')}. Its bytes are defined by a build on ${REFERENCE.name}; a build here gives a different file from the same source. The same as this source builds: ${compared.join(', ')}. Run this check on ${REFERENCE.name} to compare everything.` };
}

/// Why this staging folder cannot be used, in plain words, or null when it can. Only Windows has the limit.
export function stagingProblem(directory, platform = process.platform) {
  if (platform !== 'win32' || directory.length <= STAGING_LIMIT) return null;
  return `the staging folder ${directory} is ${directory.length} characters long, and on Windows it may be at most ${STAGING_LIMIT}: the build makes paths of up to ${DEEPEST} characters below it, and the linker fails on a path longer than ${WINDOWS_PATH_LIMIT} characters (error LNK1104, "cannot open file")`;
}

/// The first local path in `text`, or null: one of this machine's `folders` (in either slash form, any letter
/// case), or any path under a user folder.
/// A folder counts when a separator follows it, as in every path below it. A folder with a long name of its own
/// also counts bare. A short one does not: on Linux the home of root is /root and the temporary folder is /tmp,
/// and such words are part of ordinary text too. The verifier itself says "history frontier/root mismatch", which
/// stopped the first build on Linux, run as root.
export function localPathIn(text, folders) {
  const lower = text.toLowerCase();
  for (const folder of new Set(folders.flatMap((p) => [p, p.replaceAll('\\', '/')]))) {
    const needle = folder.toLowerCase().replace(/[\\/]+$/, '');
    if (needle.length < 2) continue;
    if (lower.includes(needle + '/') || lower.includes(needle + '\\') || (needle.length >= 12 && lower.includes(needle))) return folder;
  }
  return /[A-Za-z]:\\Users\\|\/(?:home|Users)\/[^/\s]+\//.exec(text)?.[0] ?? null;
}

/// The folders in which a staging folder is tried, in order. TIME_VERIFIER_STAGE, when set, is the only one.
export function stagingBases({ platform = process.platform, env = process.env, tmp = os.tmpdir(), home = os.homedir() } = {}) {
  const p = platform === 'win32' ? path.win32 : path.posix;
  if (env.TIME_VERIFIER_STAGE) return [p.resolve(env.TIME_VERIFIER_STAGE)];
  const bases = [tmp];
  // A temporary folder that was moved somewhere deep (a sandbox, a build agent) is the usual cause of a long
  // path. The user's own temporary folder and the home folder are short.
  if (platform === 'win32') bases.push(...[env.LOCALAPPDATA && p.join(env.LOCALAPPDATA, 'Temp'), home].filter(Boolean));
  return [...new Set(bases)];
}

/// Makes the staging folder in the first place that is short enough, and returns its real path.
async function stagingFolder() {
  const tried = [];
  for (const base of stagingBases()) {
    // Judged before anything is made: the name adds the prefix and six characters.
    const early = stagingProblem(path.join(base, STAGE_PREFIX + 'xxxxxx'));
    if (early) { tried.push(early); continue; }
    let made;
    try { made = await mkdtemp(path.join(base, STAGE_PREFIX)); } catch (error) { tried.push(`no folder could be made in ${base} (${error.code ?? error.message})`); continue; }
    // The real path: the compiler sees the folder under the name the system resolves it to.
    const directory = await realpath(made), late = stagingProblem(directory);
    if (!late) return directory;
    await rm(made, { recursive: true, force: true });
    tried.push(late);
  }
  throw Error(`No staging folder can be used: ${tried.join('; ')}. Set TIME_VERIFIER_STAGE to a short folder that exists (for example C:\\tv on Windows) and run again. Nothing was compiled.`);
}

/// The workspace manifest of the staging folder and the verifier's own manifest without its profile sections.
/// Cargo reads profiles from the workspace root only, so the verifier's `[profile.*]` tables move there
/// unchanged (overflow checks stay on in the release build).
export function stagingManifests(crateManifest) {
  const lines = crateManifest.split(/\r?\n/), kept = [], profiles = [];
  let inProfile = false;
  for (const line of lines) {
    const table = /^\s*\[\[?([^\]]+)\]\]?\s*$/.exec(line);
    if (table) inProfile = table[1].trim() === 'profile' || table[1].trim().startsWith('profile.');
    (inProfile ? profiles : kept).push(line);
  }
  if (/^\s*\[workspace\]/m.test(crateManifest)) throw Error(`${CRATE}/Cargo.toml declares a workspace of its own`);
  // `history` is a dependency by path, not a member: as a member its test-only dependencies would have to be in
  // the lockfile, and the lockfile is the verifier's, unchanged.
  const workspace = ['[workspace]', `members = ["${CRATE}"]`, `exclude = [${LOCAL_DEPENDENCIES.map((name) => `"${name}"`).join(', ')}]`, 'resolver = "3"', '', ...profiles].join('\n').trimEnd() + '\n';
  return { workspace, crate: kept.join('\n').trimEnd() + '\n' };
}

/// Copies what the build reads into a new staging folder and returns its path.
async function stage() {
  const directory = await stagingFolder();
  const sources = (from) => (source) => path.relative(from, source).split(path.sep)[0] !== 'target';
  for (const name of [CRATE, ...LOCAL_DEPENDENCIES]) await cp(path.join(root, name), path.join(directory, name), { recursive: true, filter: sources(path.join(root, name)) });
  const manifests = stagingManifests(await readFile(path.join(root, CRATE, 'Cargo.toml'), 'utf8'));
  await writeFile(path.join(directory, 'Cargo.toml'), manifests.workspace);
  await writeFile(path.join(directory, CRATE, 'Cargo.toml'), manifests.crate);
  await copyFile(path.join(root, CRATE, 'Cargo.lock'), path.join(directory, 'Cargo.lock'));
  // The toolchain is chosen from the folder cargo runs in.
  await copyFile(path.join(root, CRATE, 'rust-toolchain.toml'), path.join(directory, 'rust-toolchain.toml'));
  // A lockfile next to a member is ignored in a workspace; removing the copies keeps that plain.
  for (const name of [CRATE, ...LOCAL_DEPENDENCIES]) await rm(path.join(directory, name, 'Cargo.lock'), { force: true });
  return directory;
}

/// Builds in a new staging folder and returns the files of the compiled copy: name -> bytes.
export async function build({ quiet = false } = {}) {
  const directory = await stage();
  try {
    // Later prefixes win, so the two tool folders come after the staging root.
    const remap = [[directory, '/time'], [cargoHome, '/cargo'], [rustupHome, '/rustup']];
    const env = {
      ...process.env,
      CARGO_HOME: cargoHome,
      RUSTUP_HOME: rustupHome,
      CARGO_TARGET_DIR: path.join(directory, 'target'),
      // Separated by the unit separator, so a path with a space stays one flag.
      CARGO_ENCODED_RUSTFLAGS: remap.map(([from, to]) => `--remap-path-prefix=${from}=${to}`).join('\x1f'),
    };
    delete env.RUSTFLAGS;
    const run = (file, args) => execFileSync(file, args, { cwd: directory, env, stdio: quiet ? ['ignore', 'ignore', 'inherit'] : 'inherit' });
    try {
      run(cargo, ['build', '--offline', '--locked', '--release', '--target', 'wasm32-unknown-unknown', '--lib', '--package', 'timecurrency-verifier-v4']);
    } catch (error) {
      // The linker's own message for a path that is too long does not say so.
      if (process.platform === 'win32') throw Error(`The build failed in the staging folder ${directory} (${directory.length} characters). If the output above says LNK1104 or names a file that cannot be opened, a path is too long for Windows: set TIME_VERIFIER_STAGE to a shorter folder that exists (for example C:\\tv) and run again.`, { cause: error });
      throw error;
    }
    const scratch = path.join(directory, 'bindgen');
    await mkdir(scratch);
    run(bindgen, ['--target', 'web', '--out-dir', scratch, path.join(directory, 'target', 'wasm32-unknown-unknown', 'release', 'timecurrency_verifier_v4.wasm')]);
    const names = (await readdir(scratch)).sort(), files = new Map();
    // What must not appear: this machine's folders, in either slash form, and any path under a user folder.
    const folders = [root, directory, cargoHome, rustupHome, os.homedir(), os.tmpdir()];
    for (const name of names) {
      const bytes = await readFile(path.join(scratch, name)), text = bytes.toString('latin1');
      const found = localPathIn(text, folders);
      if (found) throw Error(`${name} still holds a local path (${found}); nothing was written`);
      files.set(name, bytes);
    }
    return files;
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

/// The names of built files that differ from the compiled copy in web-v4/shared/verifier (or are missing there).
export async function differences(files) {
  const different = [];
  for (const [name, bytes] of files) {
    const committed = await readFile(path.join(out, name)).catch(() => null);
    if (!committed || !committed.equals(bytes)) different.push(name);
  }
  return different;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length === 1 && !['--check', '--local'].includes(args[0]))) { console.error('Usage: node tools/build-verifier.mjs [--check | --local]'); process.exit(2); }
  const check = args[0] === '--check', local = args[0] === '--local';
  // Said before anything is compiled: the build takes minutes.
  const refusal = check ? null : writeRefusal({ local });
  if (refusal) { console.error(`build-verifier: ${refusal}`); process.exit(2); }
  // One plain line, and a code of its own: a build that could not run is not "the copy differs".
  const files = await build().catch((error) => { console.error(`build-verifier: ${error.message}`); process.exit(2); });
  const different = await differences(files);
  if (check) {
    const outcome = checkOutcome([...files.keys()], different, { where: path.relative(root, out) });
    if (outcome.error) console.error(outcome.error); else console.log(outcome.line);
    process.exit(outcome.code);
  } else {
    for (const [name, bytes] of files) await writeFile(path.join(out, name), bytes);
    console.log(`wrote ${[...files.keys()].join(', ')} to ${path.relative(root, out)}${different.length ? ` (changed: ${different.join(', ')})` : ' (unchanged)'}`);
    if (!onReference()) console.log(`This is the build of ${process.platform} ${process.arch}, not of ${REFERENCE.name}: do not commit it. "git checkout -- ${path.relative(root, out).split(path.sep).join('/')}" puts the committed copy back.`);
  }
}
