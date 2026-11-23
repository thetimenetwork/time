// A chain that stood (deploy/README.md, "A chain that stood"; docs/emergency-fix.md): the resume order, what each
// launcher does with it, the CometBFT configuration of the one start without the double-sign look, and what the
// documents tell an operator to type. Without Docker, CometBFT or a node: the launcher's decisions are made from files,
// and these tests make the files. The kit's other tests are in tools/release-v5.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  cometConfig, prepareCometHome, childOutcome, checkSettingsKeys, heightAndRoot, resumeOrder, checkResumeOrder, writeResumeOrder, savedHeight, lastExit, recordExit, noteExit, standstillEnd, resumeDecision, markResumeUsed,
  DOUBLE_SIGN_CHECK_HEIGHT, RESUME_FILE, RESUME_KIND, RESUME_USED, LAST_EXIT_FILE,
} from './operator.mjs';

const here = (file) => fileURLToPath(new URL(file, import.meta.url));
const ROOT = 'ab'.repeat(32), H = '1084';
const settings = (extra = {}) => ({
  release_manifest: '/operator/release.json', release_id: 'cd'.repeat(32), genesis_file: '/operator/genesis.json', genesis_sha256: 'ef'.repeat(32), chain_id: 'time-devnet-v4-resume',
  validator_public_key_hex: '12'.repeat(32), signer_identity: 'signer', signer_lease_file: '/operator/lease/signer-lease.json', trust_file: '/operator/trust.json',
  sentry_peers: [`${'a'.repeat(40)}@one:26656`, `${'b'.repeat(40)}@two:26656`], ...extra,
});
/// A host's volumes as the launchers see them: the operator directory, the ledger volume, the consensus volume.
async function host({ saved = [H], exit = { code: 4, asked: false }, order = H + ':' + ROOT, orderSettings = settings() } = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), 'time-resume-')), operator = path.join(dir, 'operator'), ledger = path.join(dir, 'ledger'), comet = path.join(dir, 'comet');
  for (const d of [operator, path.join(ledger, 'v5-state.v5state'), comet]) await mkdir(d, { recursive: true });
  for (const h of saved) await writeFile(path.join(ledger, 'v5-state.v5state', `state-${String(h).padStart(20, '0')}.snap`), 'x');
  // How the node's last run ended, recorded at the height of the state it saved then (by default, where it is now).
  if (exit) await recordExit(ledger, { saved_height: saved.length ? saved.map(BigInt).reduce((a, b) => (a > b ? a : b)).toString() : null, ...exit, ended_utc: '2026-11-23T10:00:00.000Z' });
  await writeFile(path.join(operator, 'settings.json'), JSON.stringify(orderSettings));
  const file = path.join(operator, 'resume.json');
  if (order) await writeResumeOrder(path.join(operator, 'settings.json'), order, { now: Date.parse('2026-11-23T10:05:00.000Z') });
  return { dir, ledger, comet, file, decide: (kind, s = settings()) => resumeDecision(kind, s, { ledger, comet: kind === 'comet' ? comet : null, file }), close: () => rm(dir, { recursive: true, force: true }) };
}

test('the order names a height and a root in the node\'s own form of --expect-root, and this one validator', () => {
  assert.deepEqual(heightAndRoot(`1:${ROOT}`), { height: '1', root: ROOT });
  assert.deepEqual(heightAndRoot(`9223372036854775807:${ROOT}`), { height: '9223372036854775807', root: ROOT });
  for (const bad of [`0:${ROOT}`, `01:${ROOT}`, `+1:${ROOT}`, `1:${ROOT.toUpperCase()}`, `1:${ROOT.slice(1)}`, `1 :${ROOT}`, ROOT, `9223372036854775808:${ROOT}`, `1:${ROOT}:x`, '', undefined]) assert.throws(() => heightAndRoot(bad), /HEIGHT:ROOT needs a block height/, String(bad));
  const order = resumeOrder(settings(), `${H}:${ROOT}`, { now: Date.parse('2026-11-23T10:00:00.000Z'), id: '0f'.repeat(16) });
  assert.deepEqual(order, { schema_version: 1, kind: RESUME_KIND, order_id: '0f'.repeat(16), chain_id: 'time-devnet-v4-resume', genesis_sha256: 'ef'.repeat(32), validator_public_key_hex: '12'.repeat(32), release_id: 'cd'.repeat(32), height: H, root: ROOT, written_utc: '2026-11-23T10:00:00.000Z' });
  assert.equal(checkResumeOrder(order, settings()), order);
  // A node that goes on from H does not stop at or before it: stop_after_height must go first.
  assert.throws(() => resumeOrder(settings({ stop_after_height: 1084 }), `${H}:${ROOT}`), /remove it from the settings first/);
  assert.equal(resumeOrder(settings({ stop_after_height: 1085 }), `${H}:${ROOT}`).height, H);
  for (const [name, value] of [['chain_id', 'time-devnet-v4-other'], ['genesis_sha256', '00'.repeat(32)], ['validator_public_key_hex', '34'.repeat(32)], ['release_id', '56'.repeat(32)]]) assert.throws(() => checkResumeOrder(order, settings({ [name]: value })), /written for another/, name);
  for (const broken of [{ ...order, extra: 1 }, { ...order, kind: 'other' }, { ...order, order_id: 'x' }, { ...order, height: '0' }, { ...order, root: 'AB'.repeat(32) }, null, []]) assert.throws(() => checkResumeOrder(broken, settings()), /not one this kit writes|HEIGHT:ROOT/);
  assert.equal(path.basename(RESUME_FILE), 'resume.json');
  assert.equal(path.dirname(RESUME_FILE), '/operator', 'the containers read it where they read the settings');
});

test('writing an order: beside the settings file, readable by the containers\' user, never over another order', async () => {
  const h = await host({ order: null });
  try {
    const settingsFile = path.join(path.dirname(h.file), 'settings.json');
    const { file, order } = await writeResumeOrder(settingsFile, `${H}:${ROOT}`);
    assert.equal(file, h.file);
    assert.deepEqual(JSON.parse(await readFile(file, 'utf8')), order);
    if (process.platform !== 'win32') assert.equal((await stat(file)).mode & 0o777, 0o644);
    await assert.rejects(writeResumeOrder(settingsFile, `${H}:${ROOT}`), /exists already\. An order is used by one start: remove the old one on purpose/);
    // The settings are read as the guard reads them: a key it does not know is refused here too.
    await writeFile(settingsFile, JSON.stringify(settings({ stop_after_heigth: 5 })));
    await assert.rejects(writeResumeOrder(settingsFile, `${H}:${ROOT}`), /Unknown operator setting/);
    assert.deepEqual(checkSettingsKeys(settings()), settings(), 'no settings key was added for the order');
  } finally { await h.close(); }
});

test('CometBFT\'s configuration differs in one line for the one start of an order, and only for v5', () => {
  const s = settings(), plain = cometConfig(s, 'v5'), order = resumeOrder(s, `${H}:${ROOT}`, { id: '0f'.repeat(16) }), resumed = cometConfig(s, 'v5', order);
  assert.equal(DOUBLE_SIGN_CHECK_HEIGHT, 100);
  assert.match(plain, /^double_sign_check_height = 100$/m);
  assert.match(resumed, /^double_sign_check_height = 0$/m);
  assert.doesNotMatch(resumed, /^double_sign_check_height = 100$/m);
  const changed = resumed.split('\n').filter((line) => !plain.split('\n').includes(line));
  assert.deepEqual(changed.filter((line) => !line.startsWith('#')), ['double_sign_check_height = 0']);
  assert.ok(changed.some((line) => line.includes(`resume order ${'0f'.repeat(16)} for height ${H} and root ${ROOT}`)), 'the configuration names the order it was written for');
  assert.equal(resumed.split('\n').filter((line) => !line.startsWith('#')).join('\n'), plain.split('\n').filter((line) => !line.startsWith('#')).join('\n').replace('double_sign_check_height = 100', 'double_sign_check_height = 0'));
  assert.equal(cometConfig(s, 'v4'), cometConfig(s), 'v4 unchanged');
  assert.throws(() => cometConfig(s, 'v4', order), /only to v5/);
});

test('the start after the order writes the configuration with the look off; the next start writes it on again', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'time-resume-home-')), genesis = Buffer.from('{"genesis":1}');
  try {
    const s = settings({ genesis_sha256: (await import('node:crypto')).createHash('sha256').update(genesis).digest('hex') }), order = resumeOrder(s, `${H}:${ROOT}`);
    await prepareCometHome(dir, s, 'v5', genesis, order);
    assert.match(await readFile(path.join(dir, 'config', 'config.toml'), 'utf8'), /^double_sign_check_height = 0$/m);
    await prepareCometHome(dir, s, 'v5', genesis);
    assert.match(await readFile(path.join(dir, 'config', 'config.toml'), 'utf8'), /^double_sign_check_height = 100$/m);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('the node launcher: --expect-root while the saved state is at or below the height; an order left behind changes nothing later', async () => {
  for (const [saved, applies] of [[[H], true], [['1000', '1084'], true], [['900'], true], [['1084', '1090'], false], [[], false]]) {
    const h = await host({ saved });
    try {
      const d = await h.decide('app');
      assert.equal(d.applies, applies, saved.join(','));
      if (applies) assert.deepEqual([d.expectRoot, d.doubleSignCheckOff], [`${H}:${ROOT}`, false]);
      else assert.match(d.why, saved.length ? /past it: it does not apply, and this start runs as any other/ : /holds no saved state/);
    } finally { await h.close(); }
  }
  const none = await host({ order: null });
  try { assert.deepEqual(await none.decide('app'), { applies: false, why: 'no resume order' }); } finally { await none.close(); }
  // Where it applies it must be for these settings, and the settings must not stop the node at or below the height.
  const h = await host();
  try {
    await assert.rejects(h.decide('app', settings({ release_id: '56'.repeat(32) })), /written for another release id/);
    await assert.rejects(h.decide('comet', settings({ chain_id: 'time-devnet-v4-other' })), /written for another chain id/);
    await assert.rejects(h.decide('app', settings({ stop_after_height: 1084 })), /remove it from the settings/);
    await writeFile(h.file, '{"kind":');
    await assert.rejects(h.decide('app'), /cannot be read/);
  } finally { await h.close(); }
});

test('the consensus launcher: the look is off for one start, only after a node that ended by itself, and never twice for one order', async () => {
  for (const exit of [{ code: 4, asked: false }, { code: 1, asked: false }]) {
    const h = await host({ exit });
    try {
      const d = await h.decide('comet');
      assert.deepEqual([d.applies, d.doubleSignCheckOff, d.expectRoot], [true, true, `${H}:${ROOT}`]);
      await markResumeUsed(d, '2026-11-23T10:06:00.000Z');
      assert.equal(JSON.parse(await readFile(path.join(h.comet, RESUME_USED, `${d.order.order_id}.json`), 'utf8')).order_id, d.order.order_id);
      // The next start with the same order: the node still gets --expect-root while it is at the height, the look stays on.
      const again = await h.decide('comet');
      assert.deepEqual([again.applies, again.doubleSignCheckOff], [true, false]);
      assert.match(again.why, /was used by an earlier start: double_sign_check_height stays 100/);
      await assert.rejects(markResumeUsed(d, 'later'), { code: 'EEXIST' }, 'two starts can never both use one order');
    } finally { await h.close(); }
  }
  // After a clean stop, a lost CometBFT, a kill, a stop that was asked for, no record, or an end at a height after which
  // the state moved on: no start.
  for (const exit of [{ code: 0, asked: false }, { code: 3, asked: false }, { code: null, asked: false }, { code: 4, asked: true }, null, { code: 4, asked: false, saved_height: '1000' }]) {
    const h = await host({ exit });
    try {
      await assert.rejects(h.decide('comet'), /is for a validator whose node ended by itself[^]*Nothing was started[^]*set stop_after_height to 1084 and start the stack once/, JSON.stringify(exit));
      assert.equal((await h.decide('app')).applies, true, 'the node launcher passes the root all the same: it only refuses more');
    } finally { await h.close(); }
  }
});

test('each end of the node is recorded in the ledger volume; an end at a height stays until the state moves past it', async () => {
  const h = await host({ exit: null });
  try {
    assert.equal(LAST_EXIT_FILE, 'node-last-exit.json');
    assert.equal(await lastExit(h.ledger), null);
    assert.equal(await savedHeight(h.ledger), 1084n);
    const at = Date.parse('2026-11-23T11:00:00.000Z');
    // STOPPED AS ASKED at 1084: kept with the height of the state the node saved.
    assert.deepEqual(await noteExit(h.ledger, { code: 4, asked: false }, { now: at }), { code: 4, asked: false, saved_height: '1084', ended_utc: '2026-11-23T11:00:00.000Z' });
    assert.equal(standstillEnd(await lastExit(h.ledger)), true);
    // A start that went nowhere (CometBFT refused it, the node lost CometBFT, the stack was stopped): the end at the
    // height is kept, so that a resume order still works afterwards.
    for (const end of [{ code: 3, asked: false }, { code: 0, asked: true }, { code: null, asked: true }]) assert.equal((await noteExit(h.ledger, end)).code, 4, JSON.stringify(end));
    // The state moved on: the next end replaces it, whatever it was.
    await writeFile(path.join(h.ledger, 'v5-state.v5state', `state-${'1200'.padStart(20, '0')}.snap`), 'x');
    assert.deepEqual(await noteExit(h.ledger, { code: 0, asked: true }, { now: at }), { code: 0, asked: true, saved_height: '1200', ended_utc: '2026-11-23T11:00:00.000Z' });
    assert.equal(standstillEnd(await lastExit(h.ledger)), false);
    for (const record of [null, { code: 4, asked: false }, { code: 4, asked: false, saved_height: null }, { code: 2, asked: false, saved_height: '5' }, { code: 1, asked: false, saved_height: '5' }]) assert.equal(standstillEnd(record), record?.code === 1);
  } finally { await h.close(); }
  // The launcher's own order of work (run()): the decision after the volume checks; the used mark before CometBFT's
  // configuration; --expect-root only where an order applies; each end of the node noted when it ends; and the lease
  // checked again right before the start, as before.
  const source = await readFile(here('./operator.mjs'), 'utf8'), body = source.slice(source.indexOf('async function run('));
  const at = (text) => { const i = body.indexOf(text); assert.ok(i > 0, text); return i; };
  assert.ok(at('await checkVolumes(') < at('await resumeDecision(') && at('await resumeDecision(') < at('await markResumeUsed(') && at('await markResumeUsed(') < at('await prepareCometHome('));
  assert.ok(body.includes("if(kind==='app'&&resume.applies)args.push('--expect-root',resume.expectRoot);const{lease:startLease}=await guard(settings);if(stopping)return;child=spawn(executable,args,{stdio:'inherit'});"));
  assert.ok(at('await noteExit(') > at('child.once(\'exit\',resolve)'));
  assert.ok(body.includes('asked:stopping||Boolean(guardFailure)'), 'a stop the launcher asked for is never taken for an end by itself');
});

test('exit code 4 names the three causes of STOPPED AT A SWITCH; exit code 1 under an order says not to start that validator', () => {
  const four = (() => { try { childOutcome('app', 'v5', 4); } catch (error) { return error; } })();
  assert.equal(four.exitCode, 4);
  for (const words of ['STOPPED AT A SWITCH: a decided block carries an emergency switch', 'The second line says which of three causes', '(1) A decided block carries an emergency switch to a version this release does not implement: Install the fix release', '(2) This is a fix release, and the decided block at its switch height is not its switch block', '(3) This is a fix release, and the state is already past its switch height', 'start the release the state was made by', 'resume-order SETTINGS HEIGHT:ROOT']) assert.ok(four.message.includes(words), words);
  assert.throws(() => childOutcome('app', 'v5', 1, {}, `${H}:${ROOT}`), (error) => /^Node child process failed: time-node-v5 exited with code 1 on a start with --expect-root 1084:/.test(error.message) && /Do not start this validator: tell the coordinators/.test(error.message));
  assert.throws(() => childOutcome('app', 'v5', 1, {}), (error) => error.message === 'Node child process failed');
});

test('the documents say what an operator types in each emergency case with the kit', async () => {
  const readme = await readFile(here('./README.md'), 'utf8'), production = await readFile(here('./PRODUCTION-V5.md'), 'utf8'), emergency = await readFile(here('../docs/emergency-fix.md'), 'utf8');
  for (const [name, text] of [['deploy/README.md', readme], ['docs/emergency-fix.md', emergency], ['deploy/PRODUCTION-V5.md', production]]) {
    assert.ok(text.includes('operator.mjs resume-order /etc/time-v5/operator/settings.json'), name);
  }
  assert.match(readme, /\*\*A chain that stood\.\*\*/);
  for (const words of ['double_sign_check_height', 'node-last-exit.json', 'resume-orders-used', 'Who could misuse it']) assert.ok(readme.includes(words), words);
  for (const kind of ['### Kind A with the kit', '### Kind B with the kit', '### Kind C with the kit']) assert.ok(emergency.includes(kind), kind);
  assert.doesNotMatch(emergency, /The kit cannot restart a chain that stood\./);
  assert.doesNotMatch(emergency, /With the kit this flag cannot be given yet/);
  assert.doesNotMatch(production, /this kit lacks two things it needs/);
});

test('the faucet and the alert watch say what the settings of a network change for them', async () => {
  const faucet = await readFile(here('./faucet/README.md'), 'utf8'), watch = await readFile(here('./watch/README.md'), 'utf8');
  assert.match(faucet, /the developer signs, with the new key and in a later block, the registration the commitment names/);
  assert.match(faucet, /\*\*The registration that carries the account's keys \(kind 45\),\*\* on a network whose genesis has `protected_registration`/);
  assert.match(faucet, /### Waits that survive a stop\n/);
  assert.match(watch, /The message then says "at the earliest" after the date, and the event carries `earliest: true`/);
  assert.match(watch, /On any other network nothing of this changes, and no event carries `earliest`/);
});
