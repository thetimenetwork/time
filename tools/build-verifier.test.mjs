// tools/build-verifier.mjs builds the compiled verifier from a staging folder, so that on Linux
// x86-64 the same source gives the same bytes in whatever folder the repository is checked out.
// These tests cover what can be checked without compiling: the manifests the staging folder gets,
// the command, and what the check says on each system. The proof itself is a build on Linux
// x86-64: `node tools/build-verifier.mjs --check` rebuilds in a new folder and fails if the
// result differs from the committed copy.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { stagingManifests, stagingBases, stagingProblem, localPathIn, STAGING_LIMIT, REFERENCE, onReference, dependsOnSystem, checkOutcome, writeRefusal } from './build-verifier.mjs';

const here = (relative) => new URL(relative, import.meta.url);

test('the staging workspace has the verifier as its only member, keeps the lockfile valid, and carries the release profile', async () => {
  const manifest = await readFile(here('../verifier-v4/Cargo.toml'), 'utf8');
  const { workspace, crate } = stagingManifests(manifest);
  // Every path Cargo hashes is relative to the workspace root: the verifier is a member, and
  // `history` (../history from the verifier) lies inside the root as a dependency by path. It is
  // not a member, because a member's test-only dependencies would have to be in the lockfile.
  assert.equal(workspace, '[workspace]\nmembers = ["verifier-v4"]\nexclude = ["history"]\nresolver = "3"\n\n[profile.release]\n# Arithmetic overflow stops verification instead of wrapping.\noverflow-checks = true\n');
  // The verifier's own manifest is unchanged but for the profile, which Cargo reads from the root only.
  assert.equal(crate.includes('[profile'), false);
  assert.equal(crate.includes('overflow-checks'), false);
  const kept = manifest.slice(0, manifest.indexOf('[profile.release]')).trimEnd() + '\n';
  assert.equal(crate, kept.replace(/\r\n/g, '\n'));
  assert.match(crate, /^history = \{ package = "time-history", path = "\.\.\/history", default-features = false \}$/m);
  // The repository's own layout is what the staging copies: nothing in it declares a workspace.
  assert.equal(/^\s*\[workspace\]/m.test(manifest), false);
  assert.throws(() => stagingManifests(manifest + '\n[workspace]\n'), /declares a workspace of its own/);
  // A manifest with several profile tables, and tables after them, keeps each on its side.
  const mixed = stagingManifests('[package]\nname = "x"\n[profile.release]\nlto = true\n[profile.dev.package.y]\nopt-level = 3\n[dependencies]\nserde = "1"\n');
  assert.equal(mixed.crate, '[package]\nname = "x"\n[dependencies]\nserde = "1"\n');
  assert.match(mixed.workspace, /\n\[profile\.release\]\nlto = true\n\[profile\.dev\.package\.y\]\nopt-level = 3\n$/);
});

test('the build is locked, offline, mapped to fixed names, and can be checked against the committed copy', async () => {
  const script = await readFile(here('./build-verifier.mjs'), 'utf8');
  assert.match(script, /\n      run\(cargo, \['build', '--offline', '--locked', '--release', '--target', 'wasm32-unknown-unknown', '--lib', '--package', 'timecurrency-verifier-v4'\]\);/);
  // The lockfile is the verifier's own, copied to the staging root; the repository's files are only read.
  assert.match(script, /copyFile\(path\.join\(root, CRATE, 'Cargo\.lock'\), path\.join\(directory, 'Cargo\.lock'\)\)/);
  assert.match(script, /const remap = \[\[directory, '\/time'\], \[cargoHome, '\/cargo'\], \[rustupHome, '\/rustup'\]\];/);
  assert.match(script, /cwd: directory/);
  assert.equal(/cwd: (?:crate|root)\b/.test(script), false, 'nothing is built inside the repository');
  // --check exits with what checkOutcome decides, and a build that may not replace the copy is refused before
  // anything is compiled.
  assert.match(script, /const outcome = checkOutcome\(\[\.\.\.files\.keys\(\)\], different, \{ where: path\.relative\(root, out\) \}\);\s*if \(outcome\.error\) console\.error\(outcome\.error\); else console\.log\(outcome\.line\);\s*process\.exit\(outcome\.code\);/);
  assert.match(script, /const refusal = check \? null : writeRefusal\(\{ local \}\);\s*if \(refusal\) \{ console\.error\(`build-verifier: \$\{refusal\}`\); process\.exit\(2\); \}\s*\/\/[^\n]*\n\s*const files = await build\(\)/);
  assert.match(script, /still holds a local path/);
});

test('the compiled copy is the build of Linux x86-64: elsewhere the .wasm file is not compared, and the check says so', () => {
  const names = ['v.d.ts', 'v.js', 'v_bg.wasm', 'v_bg.wasm.d.ts'];
  const linux = { platform: 'linux', arch: 'x64' }, windows = { platform: 'win32', arch: 'x64' };
  assert.deepEqual(REFERENCE, { platform: 'linux', arch: 'x64', name: 'Linux x86-64' });
  assert.equal(onReference(linux), true);
  for (const system of [windows, { platform: 'darwin', arch: 'arm64' }, { platform: 'linux', arch: 'arm64' }]) assert.equal(onReference(system), false);
  assert.deepEqual(names.filter(dependsOnSystem), ['v_bg.wasm'], 'the description of the .wasm file (.wasm.d.ts) is text and is compared everywhere');

  // On the reference system: the same is 0, any difference is 1.
  assert.deepEqual(checkOutcome(names, [], { system: linux, where: 'web-v4/shared/verifier' }), { code: 0, line: 'v.d.ts, v.js, v_bg.wasm, v_bg.wasm.d.ts in web-v4/shared/verifier are what this source builds' });
  const differs = checkOutcome(names, ['v_bg.wasm'], { system: linux });
  assert.equal(differs.code, 1);
  assert.equal(differs.error, 'The compiled verifier differs from what this source builds: v_bg.wasm. Run node tools/build-verifier.mjs and commit the result.');

  // Elsewhere, with the .wasm file different (as it is for a right copy): 3, never 0, and the line says what
  // was left out. Nothing in it reads as "the copy is what the source builds".
  const partly = checkOutcome(names, ['v_bg.wasm'], { system: windows });
  assert.equal(partly.code, 3);
  assert.match(partly.line, /^NOT COMPARED on this system \(win32 x64\): v_bg\.wasm\. /);
  assert.match(partly.line, /The same as this source builds: v\.d\.ts, v\.js, v_bg\.wasm\.d\.ts\. Run this check on Linux x86-64 to compare everything\.$/);
  assert.equal(partly.error, undefined);
  // A glue file that differs is a failure everywhere, and the advice is not "build here and commit".
  const glue = checkOutcome(names, ['v.js', 'v_bg.wasm'], { system: windows });
  assert.equal(glue.code, 1);
  assert.match(glue.error, /differs from what this source builds: v\.js\. /);
  assert.equal(glue.error.includes('v_bg.wasm'), false);
  assert.match(glue.error, /build it there \(node tools\/build-verifier\.mjs\) and commit that result\.$/);
  // A .wasm file equal to this system's build is not the reference build: a copy written with --local.
  const local = checkOutcome(names, [], { system: windows, where: 'web-v4\\shared\\verifier' });
  assert.equal(local.code, 1);
  assert.match(local.error, /^v_bg\.wasm in web-v4\\shared\\verifier is the build of this system \(win32 x64\), so it is not the build of Linux x86-64/);
  assert.match(local.error, /"git checkout -- web-v4\/shared\/verifier" puts the committed copy back/);

  // Replacing the copy: on the reference system, or with --local; otherwise refused with what to do instead.
  assert.equal(writeRefusal({ system: linux }), null);
  assert.equal(writeRefusal({ system: windows, local: true }), null);
  const refusal = writeRefusal({ system: windows });
  assert.match(refusal, /^this system \(win32 x64\) is not Linux x86-64, whose build defines the compiled copy; nothing was built or written\./);
  assert.match(refusal, /--check/);
  assert.match(refusal, /--local writes this system's build over the compiled copy; do not commit that copy\.$/);
});

test('the staging folder is short, and a path too long for the Windows linker is said plainly before anything is compiled', async () => {
  // 259 characters for a whole path on Windows, up to 160 below the staging folder, and a separator.
  assert.equal(STAGING_LIMIT, 98);
  const at = (length) => 'C:\\' + 'x'.repeat(length - 3);
  assert.equal(stagingProblem(at(98), 'win32'), null);
  const problem = stagingProblem(at(99), 'win32');
  assert.equal(problem, `the staging folder ${at(99)} is 99 characters long, and on Windows it may be at most 98: the build makes paths of up to 160 characters below it, and the linker fails on a path longer than 259 characters (error LNK1104, "cannot open file")`);
  // The folder the reviewer's build failed in, about 130 characters, is refused; other systems have no such limit.
  assert.match(stagingProblem(at(130), 'win32'), /LNK1104/);
  for (const platform of ['linux', 'darwin']) assert.equal(stagingProblem('/' + 'x'.repeat(400), platform), null);
  // Where it is tried, in order: the temporary folder, and on Windows the user's own and the home folder.
  // (The folders here are spelled so that the publication scan does not take them for a person's own path.)
  const deep = 'D:\\people\\someone\\AppData\\Local\\Temp\\agent\\' + 'a'.repeat(90);
  assert.deepEqual(stagingBases({ platform: 'win32', env: { LOCALAPPDATA: 'D:\\people\\someone\\AppData\\Local' }, tmp: deep, home: 'D:\\people\\someone' }), [deep, 'D:\\people\\someone\\AppData\\Local\\Temp', 'D:\\people\\someone']);
  assert.deepEqual(stagingBases({ platform: 'win32', env: { LOCALAPPDATA: 'D:\\people\\someone\\AppData\\Local' }, tmp: 'D:\\people\\someone\\AppData\\Local\\Temp', home: 'D:\\people\\someone' }), ['D:\\people\\someone\\AppData\\Local\\Temp', 'D:\\people\\someone']);
  assert.deepEqual(stagingBases({ platform: 'linux', env: { LOCALAPPDATA: '/ignored' }, tmp: '/tmp', home: '/srv/someone' }), ['/tmp']);
  // TIME_VERIFIER_STAGE is the only place when it is set.
  assert.deepEqual(stagingBases({ platform: 'win32', env: { TIME_VERIFIER_STAGE: 'C:\\tv', LOCALAPPDATA: 'C:\\x' }, tmp: deep, home: 'D:\\people\\someone' }), ['C:\\tv']);
  assert.deepEqual(stagingBases({ platform: 'linux', env: { TIME_VERIFIER_STAGE: '/var/tv' }, tmp: '/tmp', home: '/srv/someone' }), ['/var/tv']);
  // The name is short, the folder is judged before it is made and again under its real name, and
  // a failed build on Windows names the cause the linker does not.
  const script = await readFile(here('./build-verifier.mjs'), 'utf8');
  assert.match(script, /const STAGE_PREFIX = 'tv-', DEEPEST = 160, WINDOWS_PATH_LIMIT = 259;/);
  assert.match(script, /const early = stagingProblem\(path\.join\(base, STAGE_PREFIX \+ 'xxxxxx'\)\);\s*if \(early\) \{ tried\.push\(early\); continue; \}/);
  assert.match(script, /const directory = await realpath\(made\), late = stagingProblem\(directory\);/);
  assert.match(script, /Set TIME_VERIFIER_STAGE to a short folder that exists \(for example C:\\\\tv on Windows\) and run again\. Nothing was compiled\./);
  assert.match(script, /If the output above says LNK1104 or names a file that cannot be opened, a path is too long for Windows/);
  assert.equal(script.includes('time-verifier-stage-'), false, 'the long folder name is gone');
  // A build that could not run prints its reason on one line and exits with 2, never with the 1 of "the copy differs".
  assert.match(script, /const files = await build\(\)\.catch\(\(error\) => \{ console\.error\(`build-verifier: \$\{error\.message\}`\); process\.exit\(2\); \}\);/);
});

test('a local path is found as a path, and a short folder name inside ordinary text is not one', () => {
  // The first Linux build ran as root: the home folder is /root, and the verifier's own message holds "/root".
  const linux = ['/repo', '/tmp/tv-Cq8u3c', '/root/.cargo', '/root/.rustup', '/root', '/tmp'];
  assert.equal(localPathIn('history proof bounds\0history frontier/root mismatch\0history shape/version bounds', linux), null);
  assert.equal(localPathIn('a temporary/tmp value and a /tmpfile', linux), null);
  assert.equal(localPathIn('panicked at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde-1.0.0/src/lib.rs', linux), '/root/.cargo');
  assert.equal(localPathIn('built in /root/work/src/lib.rs', linux), '/root');
  assert.equal(localPathIn('src at /tmp/tv-Cq8u3c/verifier-v4/src/lib.rs', linux), '/tmp/tv-Cq8u3c');
  assert.equal(localPathIn('left in /tmp/other', linux), '/tmp');
  assert.equal(localPathIn('the folder /tmp/tv-Cq8u3c alone', linux), '/tmp/tv-Cq8u3c', 'a folder with a name of its own counts bare');
  // Windows: either slash form, any letter case, and any user folder.
  const windows = [String.raw`C:\work\time-repository`, String.raw`C:\Temp\tv-ab12cd`];
  assert.equal(localPathIn('at c:/work/time-repository/verifier-v4/src/light.rs', windows), 'C:/work/time-repository');
  assert.equal(localPathIn(String.raw`at C:\WORK\TIME-REPOSITORY\x`, windows), String.raw`C:\work\time-repository`);
  // These two examples are put together from parts, so that this file itself holds no path of a user folder:
  // the publication scan (tools/export-public.mjs) would refuse it.
  const users = 'Us' + 'ers', home = '/ho' + 'me';
  assert.equal(localPathIn(`at D:\\${users}\\another\\x.rs`, windows), `D:\\${users}\\`);
  assert.equal(localPathIn(`at ${home}/builder/x.rs and /${users}/mac/x.rs`, []), `${home}/builder/`);
  // The fixed names the build maps every folder to are not local paths.
  assert.equal(localPathIn('/time/verifier-v4/src/light.rs /cargo/registry/src/x /rustup/toolchains/y', [...linux, ...windows]), null);
});
