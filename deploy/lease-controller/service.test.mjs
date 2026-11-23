// The parts of the signer-lease controller that touch files and the network: the numbered state
// files, a crash around the one durable step, writers that race, the service on localhost, the
// host agent (deploy/lease-agent.mjs) with the kit's real guard, the lock and the command line.
// docs/design/signer-lease-controller.md, sections 5.2, 8 and 15.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdir, mkdtemp, readFile, readdir, rename, stat, symlink, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { guard } from '../operator.mjs';
import { json } from '../lib.mjs';
import { KEY_PURPOSES, generateKeyRecord, newNonce, readKeyFile, writeKeyFile } from '../lease-protocol.mjs';
import { LEASE_FILE_MODE, RETRY_MS, Refused, hostView, round, run, status, validateAgentConfig } from '../lease-agent.mjs';
import { applyStart, approveRelease, assign, emptyState, timing } from './core.mjs';
import { Conflict, KEPT_FILES, claim, fileStore } from './store.mjs';
import { Fatal, MAX_WAITING, createController, start, validateConfig } from './start.mjs';
import { USAGE, runCommand } from './ctl.mjs';
import { ask, manifest, operatorDirectory, world } from './fixtures.mjs';

const T0 = Date.parse('2026-12-01T00:00:00.000Z'), S = 1000, START_WAIT = 360 * S, SPACING = 31 * S;
const temporary = (name) => mkdtemp(path.join(tmpdir(), 'time-lease-' + name + '-'));
const stateFiles = async (directory) => (await readdir(path.join(directory, 'state'))).filter((name) => name.startsWith('state-')).sort();
const newestState = async (directory) => (await fileStore(directory).read()).state;

/// A controller over real files, with a clock the test moves. `hooks` fail the durable step.
async function controllerOn(w, directory, clock, hooks = {}) {
  const controller = createController({ config: w.config, store: fileStore(directory, hooks), sign: w.sign, now: () => clock.now });
  await controller.open();
  return controller;
}
/// A state directory in which release one is approved, key 0 belongs to host-a and the wait is over.
async function readyDirectory(w = world()) {
  const directory = await temporary('state'), clock = { now: T0 }, key = w.validatorKeys[0];
  let state = emptyState(w.config, clock.now);
  state = assign(approveRelease(state, w.releases.one), w.config, key, 'host-a', clock.now);
  await fileStore(directory).write(1, state, null);
  const controller = await controllerOn(w, directory, clock);
  clock.now += START_WAIT;
  return { w, directory, clock, key, controller };
}

test('state files: numbered, whole, never overwritten, and the newest is never skipped', async () => {
  const directory = await temporary('store'), store = fileStore(directory);
  assert.equal(await store.read(), null); assert.equal(await store.latest(), 0);
  const one = await store.write(1, { a: 1 }, null), two = await store.write(2, { a: 2 }, one);
  // Every file names the checksum of the state it was made from.
  assert.deepEqual(await store.read(), { seq: 2, state: { a: 2 }, sha256: two, parent: one });
  assert.deepEqual(await store.readAt(1), { seq: 1, state: { a: 1 }, sha256: one, parent: null }); assert.equal(await store.readAt(7), null);
  await assert.rejects(store.write(3, { a: 3 }), /names the checksum of the state it was made from/);
  // Two writers of one number: the second is told, and the first one's file is untouched.
  await assert.rejects(store.write(2, { a: 'other' }, one), Conflict);
  await assert.rejects(fileStore(directory).write(1, { a: 'old' }, null), Conflict);
  const racing = await Promise.allSettled([fileStore(directory).write(3, { by: 'one' }, two), fileStore(directory).write(3, { by: 'two' }, two)]);
  assert.deepEqual(racing.map((result) => result.status).sort(), ['fulfilled', 'rejected']);
  assert.ok(racing.find((result) => result.status === 'rejected').reason instanceof Conflict);
  assert.deepEqual(await stateFiles(directory), ['state-00000000000000000001.json', 'state-00000000000000000002.json', 'state-00000000000000000003.json']);
  assert.equal((await readdir(path.join(directory, 'state'))).some((name) => name.endsWith('.tmp')), false);
  // A value the state must never hold is refused before anything is written.
  await assert.rejects(store.write(4, { a: 1.5 }, two), /Noncanonical/); assert.equal(await store.latest(), 3);
  // A damaged newest file stops everything: no silent fall back to number 2.
  const newest = path.join(directory, 'state', 'state-00000000000000000003.json'), text = await readFile(newest, 'utf8');
  await writeFile(newest, text.replace('"by"', '"bx"'));
  await assert.rejects(store.read(), /controller state file cannot be used.*does not fall back to an older state by itself/s);
  await writeFile(newest, text.slice(0, 20));
  await assert.rejects(store.read(), /cannot be used/);
  await writeFile(newest, text);
  // Old files go; the newest KEPT_FILES stay.
  let parent = (await store.read()).sha256;
  for (let seq = 4; seq <= KEPT_FILES + 10; seq++) parent = await store.write(seq, { a: seq }, parent);
  // Writing removes nothing: a command must never remove a file a running service has not followed.
  assert.equal((await stateFiles(directory)).length, KEPT_FILES + 10);
  // The service removes what lies KEPT_FILES behind the file it holds.
  await store.prune(10);
  const kept = await stateFiles(directory);
  assert.equal(kept.length, KEPT_FILES); assert.equal(kept.at(-1), 'state-' + String(KEPT_FILES + 10).padStart(20, '0') + '.json');
});

test('a crash between "state written" and "lease sent": the lease is recorded, never arrives, and is sent again to the same request', async () => {
  const { w, directory, clock, key } = await readyDirectory();
  const crashing = await controllerOn(w, directory, clock, { afterLink: () => { throw new Error('power lost'); } }).catch(() => null);
  // The start itself wrote a state and "crashed" after it; open again without the fault to go on.
  assert.equal(crashing, null);
  let crash = false;
  const controller = await controllerOn(w, directory, clock, { afterLink: () => { if (crash) throw new Error('power lost after the link'); } });
  clock.now += START_WAIT;
  const nonce = newNonce(), request = () => ask(w, 'host-a', key, { timeMs: clock.now, nonce }), before = await fileStore(directory).latest();
  crash = true;
  await assert.rejects(controller.submit(request()), /power lost after the link/);
  // Nothing was returned. The state on disk holds the lease and its expiry.
  assert.equal(await fileStore(directory).latest(), before + 1);
  const recorded = (await newestState(directory)).keys[key];
  assert.equal(recorded.tenure_leases, 1); assert.equal(recorded.last_expires_ms, clock.now + 240 * S); assert.equal(recorded.request_nonce, nonce);
  // A new process starts 20 s later. The key's lease still runs, so its tenure goes on.
  clock.now += 20 * S;
  const restarted = await controllerOn(w, directory, clock);
  const again = await restarted.submit(request());
  assert.equal(again.status, 'granted'); assert.equal(again.lease.payload.lease_id, recorded.lease_id, 'the same lease, not a second one');
  assert.equal((await restarted.submit(ask(w, 'host-b', key, { timeMs: clock.now }))).code, 'NOT_HOLDER');
});

test('the reverse order cannot be produced: a write that fails sends nothing, and every lease that is answered is already on disk', async () => {
  const { w, directory, clock, key } = await readyDirectory();
  let fail = false; const order = [];
  const controller = await controllerOn(w, directory, clock, { beforeLink: () => { if (fail) throw new Error('disk full'); }, afterLink: (seq) => order.push('durable ' + seq) });
  clock.now += START_WAIT; order.length = 0;
  const seq = await fileStore(directory).latest();
  fail = true;
  await assert.rejects(controller.submit(ask(w, 'host-a', key, { timeMs: clock.now })), /disk full/);
  assert.equal(await fileStore(directory).latest(), seq); assert.equal((await newestState(directory)).keys[key].tenure_leases, 0);
  assert.equal((await readdir(path.join(directory, 'state'))).some((name) => name.endsWith('.tmp')), false);
  // The controller lives on and serves the next request from the unchanged state.
  fail = false; let previous = '';
  for (let i = 0; i < 5; i++) {
    const reply = await controller.submit(ask(w, 'host-a', key, { timeMs: clock.now, previous }));
    order.push('answered');
    assert.equal(reply.status, 'granted');
    const disk = (await newestState(directory)).keys[key];
    assert.equal(disk.lease_id, reply.lease.payload.lease_id); assert.ok(disk.last_expires_ms >= Date.parse(reply.lease.payload.expires_utc));
    previous = reply.lease.payload.lease_id; clock.now += SPACING;
  }
  assert.deepEqual(order.filter((item) => item !== 'answered').length, 5);
  for (let i = 0; i < order.length; i += 2) { assert.match(order[i], /^durable /); assert.equal(order[i + 1], 'answered'); }
});

test('two requests racing for one key: the same request twice gets one lease; two machines with one host key freeze the key', async () => {
  const { w, directory, clock, key, controller } = await readyDirectory();
  const first = (await controller.submit(ask(w, 'host-a', key, { timeMs: clock.now }))).lease.payload;
  clock.now += SPACING;
  // The same request delivered twice at once.
  const request = ask(w, 'host-a', key, { timeMs: clock.now, previous: first.lease_id }), files = (await stateFiles(directory)).length;
  const [one, two] = await Promise.all([controller.submit(request), controller.submit(request)]);
  assert.equal(one.status, 'granted'); assert.equal(two.code, 'CLOCK', 'the second copy is a recording of the first'); assert.equal((await stateFiles(directory)).length, files + 1);
  clock.now += SPACING;
  // Two machines hold that lease and ask at once with their own nonces: one is served, then the key is frozen.
  const race = await Promise.all([controller.submit(ask(w, 'host-a', key, { timeMs: clock.now, previous: one.lease.payload.lease_id })), controller.submit(ask(w, 'host-a', key, { timeMs: clock.now + 1, previous: one.lease.payload.lease_id }))]);
  assert.deepEqual(race.map((reply) => reply.status).sort(), ['granted', 'refused']);
  assert.equal(race.find((reply) => reply.status === 'refused').code, 'FROZEN');
  assert.ok((await newestState(directory)).keys[key].frozen);
  // A host and the holder racing: only the holder is served.
  const other = await readyDirectory(w), both = await Promise.all([other.controller.submit(ask(w, 'host-b', other.key, { timeMs: other.clock.now })), other.controller.submit(ask(w, 'host-a', other.key, { timeMs: other.clock.now }))]);
  assert.deepEqual(both.map((reply) => reply.code ?? reply.status), ['NOT_HOLDER', 'granted']);
});

test('two writers on one state directory stay consistent: two services, and a move beside a renewal', async () => {
  const { w, directory, clock, key, controller } = await readyDirectory();
  // A second service on the same files (the lock is not used here: it is not what keeps them apart).
  // It starts while the key waits for its first lease, so its start changes nothing but the wait.
  const second = createController({ config: w.config, store: fileStore(directory), sign: w.sign, now: () => clock.now });
  await second.open(); clock.now += START_WAIT;
  const request = ask(w, 'host-a', key, { timeMs: clock.now });
  const answers = await Promise.all([controller.submit(request), second.submit(request)]);
  assert.deepEqual(answers.map((answer) => answer.code ?? answer.status).sort(), ['CLOCK', 'granted'], 'one lease, whoever wrote it; the other copy of the request is refused as a recording');
  assert.equal((await newestState(directory)).keys[key].tenure_leases, 1);
  // The operator moves the key at the very moment the holder renews. Whichever is written first,
  // the new holder waits for the last lease that was issued, and the old holder gets nothing after.
  for (let trial = 0; trial < 8; trial++) {
    clock.now += SPACING;
    const state = (await newestState(directory)).keys[key], from = state.holder.host_id, to = from === 'host-a' ? 'host-b' : 'host-a';
    if (state.tenure_leases === 0) { clock.now = Math.max(clock.now, state.not_before_ms); assert.equal((await controller.submit(ask(w, from, key, { timeMs: clock.now }))).status, 'granted'); clock.now += SPACING; }
    const held = (await newestState(directory)).keys[key];
    const [renewal, moved] = await Promise.all([
      (trial % 2 ? controller : second).submit(ask(w, from, key, { timeMs: clock.now, previous: held.lease_id })),
      runCommand(w.config, ['move', key, to, '--from', from], { store: fileStore(directory), now: () => clock.now }),
    ]);
    assert.equal(moved.changed, true);
    const after = (await newestState(directory)).keys[key];
    assert.equal(after.holder.host_id, to);
    if (renewal.status === 'granted') assert.ok(after.not_before_ms >= Date.parse(renewal.lease.payload.expires_utc) + timing(w.config).marginMs, 'the move waits for the lease that raced it');
    else assert.equal(renewal.code, 'NOT_HOLDER');
    assert.equal(after.not_before_ms, after.last_expires_ms + timing(w.config).marginMs);
    assert.equal((await controller.submit(ask(w, from, key, { timeMs: clock.now + 1 }))).code, 'NOT_HOLDER');
  }
});

test('a service whose state files are replaced by older ones stops; a state of another network or engine is refused at the start', async () => {
  const { w, directory, clock, key, controller } = await readyDirectory();
  assert.equal((await controller.submit(ask(w, 'host-a', key, { timeMs: clock.now }))).status, 'granted');
  const files = await stateFiles(directory);
  await unlink(path.join(directory, 'state', files.at(-1)));
  await assert.rejects(controller.submit(ask(w, 'host-a', key, { timeMs: clock.now })), (error) => error instanceof Fatal && /state files were replaced while the controller ran \(the newest file is older/.test(error.message));
  // A stopped controller answers nothing more, whatever is asked.
  await assert.rejects(controller.submit(ask(w, 'host-b', key, { timeMs: clock.now })), Fatal);
  const other = { ...w, config: { ...w.config, network: { ...w.config.network, engine: 'v4' } } };
  await assert.rejects(controllerOn(other, directory, clock), /bound to engine v5.*never signs a v4 lease/);
  await assert.rejects(runCommand(other.config, ['list'], { store: fileStore(directory) }), /bound to engine v5/);
});

// ---- The service and the agent, on localhost ---------------------------------------

const quiet = () => { const lines = []; const log = (level, message, fields = {}) => lines.push({ level, message, ...fields }); log.lines = lines; return log; };

/// A service on a free local port, a validator host directory whose settings name its files as
/// the containers see them (/operator/...), and the agent's config for that host.
async function deployment({ w = world(), authority = undefined } = {}) {
  const clock = { now: T0 }, now = () => clock.now, log = quiet(), fatal = [];
  const config = { ...w.config, data_directory: await temporary('service') };
  const running = await start(config, { authority: authority ?? w.authority, now, log, port: 0, exitOnLost: false, onFatal: (error) => fatal.push(error) });
  const key = w.validatorKeys[0], checked = validateConfig(config), command = (...words) => runCommand(checked, words, { now, readManifest: async () => w.releases.one });
  const host = await operatorDirectory(w, 'host-a', key);
  const container = Object.fromEntries(Object.entries(host.settings).map(([name, value]) => [name, typeof value === 'string' && value.startsWith(host.directory) ? '/operator/' + path.basename(value) : value]));
  await writeFile(host.settingsFile, JSON.stringify(container));
  const agent = validateAgentConfig({ controller_url: running.url, host_id: 'host-a', host_key_file: path.join(await temporary('agent'), 'host-key.json'), settings_file: host.settingsFile, operator_directory: host.directory });
  const inject = { key: w.hostKeys['host-a'], now };
  return { w, clock, now, log, fatal, config: checked, running, key, command, host, agent, inject, leaseFile: host.settings.signer_lease_file };
}
const leftovers = async (directory) => (await readdir(directory)).filter((name) => name.endsWith('.tmp'));

test('the service and the agent: a lease is asked for, checked by the real guard, installed whole and renewed', async () => {
  const d = await deployment();
  try {
    assert.equal(await (await fetch(d.running.url + '/health')).json().then((body) => body.status), 'ok');
    // Nothing is approved or assigned yet: each refusal reaches the agent with what to do.
    await assert.rejects(round(d.agent, d.inject), (error) => error instanceof Refused && error.code === 'RELEASE_NOT_APPROVED');
    await d.command('approve-release', 'release.json');
    await assert.rejects(round(d.agent, d.inject), (error) => error.code === 'KEY_NOT_ASSIGNED' && /assign /.test(error.message));
    const assigned = await d.command('assign', d.key, 'host-a');
    assert.equal(assigned.result.state, 'WAITING'); assert.equal(assigned.result.seconds_until_first_lease, 360);
    await assert.rejects(round(d.agent, d.inject), (error) => error.code === 'WAIT' && error.retryAfterMs === START_WAIT);
    assert.deepEqual(await status(d.agent, d.inject).then((s) => s.valid), false);
    d.clock.now += START_WAIT;
    // A candidate file that a killed agent left behind is removed; it was never the lease file.
    await writeFile(path.join(d.host.directory, '.signer-lease.json.4242.left-behind.tmp'), 'half a lea');
    const first = await round(d.agent, d.inject);
    assert.deepEqual(await leftovers(d.host.directory), []);
    assert.equal(first.installed, true); assert.equal(first.expires_ms, d.clock.now + 240 * S);
    // The lease file is what the kit's guard accepts, for exactly this host's settings.
    const view = hostView(await json(d.host.settingsFile), d.host.directory), accepted = await guard(view, d.clock.now);
    assert.equal(accepted.lease.lease_id, first.lease_id); assert.equal(accepted.lease.host_id, 'host-a'); assert.equal(accepted.engine, 'v5');
    assert.deepEqual(await status(d.agent, d.inject), { valid: true, seconds_left: 240, lease_id: first.lease_id, fence_token: first.fence_token, expires_utc: new Date(first.expires_ms).toISOString() });
    // Too early for a new lease: the installed one stays.
    d.clock.now += S;
    await assert.rejects(round(d.agent, d.inject), (error) => error.code === 'TOO_SOON' && error.retryAfterMs === SPACING - S && /It is unsigned/.test(error.message));
    assert.equal((await json(d.leaseFile)).payload.lease_id, first.lease_id);
    // Renewals, while another process reads the lease file as fast as it can: it never sees a part.
    let reading = true, reads = 0;
    const reader = (async () => { while (reading) { try { JSON.parse(await readFile(d.leaseFile, 'utf8')); reads++; } catch (error) { if (!['EPERM', 'EBUSY', 'EACCES'].includes(error.code)) throw error; } await new Promise((resolve) => setImmediate(resolve)); } })();
    let last = first;
    for (let i = 0; i < 12; i++) { d.clock.now += 60 * S; const next = await round(d.agent, d.inject); assert.equal(next.installed, true); assert.notEqual(next.lease_id, last.lease_id); assert.equal(next.fence_token, first.fence_token); last = next; }
    reading = false; await reader; assert.ok(reads > 10);
    assert.deepEqual(await leftovers(d.host.directory), []);
    // After the lease has ended the guard refuses, and status says so.
    d.clock.now += 240 * S;
    const ended = await status(d.agent, d.inject);
    assert.equal(ended.valid, false); assert.match(ended.reason, /expired or future-dated/);
    assert.equal((await round(d.agent, d.inject)).installed, true, 'the holder gets a lease again when it asks');
    // The log: what happened, and nothing of the leases' signatures.
    assert.ok(d.log.lines.some((line) => line.message === 'lease issued' && line.host === 'host-a' && line.lease_id === first.lease_id));
    assert.ok(d.log.lines.some((line) => line.message === 'request refused' && line.code === 'TOO_SOON'));
    assert.ok(d.log.lines.some((line) => line.level === 'warn' && /operator's declaration alone/.test(line.message)));
    assert.ok(!JSON.stringify(d.log.lines).includes('signature'));
    assert.deepEqual(d.fatal, []);
  } finally { await d.running.close(); }
});

test('the service refuses what is not a lease request, without issuing anything', async () => {
  const d = await deployment();
  try {
    const post = (body, method = 'POST', url = '/v1/lease') => fetch(d.running.url + url, { method, body, headers: { 'content-type': 'application/json' } }).then(async (response) => [response.status, await response.json()]);
    assert.deepEqual((await post('{"not":"a request"}')).map((part) => part.code ?? part), [400, 'BAD_REQUEST']);
    assert.equal((await post('not json'))[0], 400);
    assert.equal((await post('x'.repeat(20 * 1024)))[0], 413);
    assert.equal((await post(undefined, 'GET', '/v1/lease'))[0], 404);
    assert.equal((await post('{}', 'POST', '/v1/admin'))[0], 404);
    const unknown = await post(JSON.stringify(ask(d.w, 'host-a', d.key, { timeMs: d.clock.now })));
    assert.deepEqual([unknown[0], unknown[1].code], [409, 'RELEASE_NOT_APPROVED']);
  } finally { await d.running.close(); }
});

test('the agent installs nothing that is not this host\'s own fresh lease from a pinned authority', async () => {
  const d = await deployment();
  try {
    await d.command('approve-release', 'release.json'); await d.command('assign', d.key, 'host-a');
    d.clock.now += START_WAIT;
    const first = await round(d.agent, d.inject), installed = await readFile(d.leaseFile, 'utf8');
    d.clock.now += 60 * S;
    // What the controller would really answer, so that each forgery differs in one thing only.
    const answerOf = async (url, options) => { const response = await fetch(url, options); return { status: response.status, reply: await response.json() }; };
    const forge = (change) => async (url, options) => { const { reply } = await answerOf(url, options); return new Response(JSON.stringify(await change(reply, JSON.parse(options.body))), { status: 200 }); };
    const refusedBy = async (change, pattern) => {
      d.clock.now += S; // the agent's repeats are dated later than its first request
      await assert.rejects(round(d.agent, { ...d.inject, fetcher: forge(change) }), pattern);
      assert.equal(await readFile(d.leaseFile, 'utf8'), installed, 'the installed lease is untouched'); assert.deepEqual(await leftovers(d.host.directory), []);
    };
    const resign = (reply, patch) => ({ status: 'granted', lease: d.w.sign({ ...reply.lease.payload, ...patch }) });
    // A lease issued to another host, and one that answers another request (an older lease put in its place).
    await refusedBy((reply) => resign(reply, { host_id: 'host-b' }), /not the answer to this host's request/);
    await refusedBy(() => ({ status: 'granted', lease: JSON.parse(installed) }), /not the answer to this host's request/);
    // The right nonce, but for another key, release, signer, genesis or engine: the guard refuses each.
    await refusedBy((reply) => resign(reply, { validator_public_key_hex: d.w.validatorKeys[1] }), /guard refuses the lease.*scope mismatch: validator_public_key_hex/);
    await refusedBy((reply) => resign(reply, { release_id: d.w.releases.two.release_id }), /scope mismatch: release_id/);
    await refusedBy((reply) => resign(reply, { signer_identity: 'signer-of-host-b' }), /scope mismatch: signer_identity/);
    await refusedBy((reply) => resign(reply, { genesis_sha256: 'e'.repeat(64) }), /scope mismatch: genesis_sha256/);
    await refusedBy((reply) => { const { engine, ...rest } = reply.lease.payload; return { status: 'granted', lease: d.w.sign(rest) }; }, /scope mismatch: engine/);
    // An authority the trust file does not pin; a changed payload; a lifetime above five minutes; no enforcement claim.
    const stranger = world();
    await refusedBy((reply) => ({ status: 'granted', lease: stranger.sign(reply.lease.payload) }), /guard refuses the lease.*Invalid signed attestation/);
    await refusedBy((reply) => ({ status: 'granted', lease: { ...reply.lease, payload: { ...reply.lease.payload, expires_utc: new Date(d.clock.now + 3600 * S).toISOString() } } }), /Invalid signed attestation/);
    await refusedBy((reply) => resign(reply, { expires_utc: new Date(d.clock.now + 290 * S).toISOString() }), /lifetime must not exceed five minutes/);
    await refusedBy((reply) => resign(reply, { enforcement: 'GUARD_ONLY' }), /Per-signature fencing enforcement attestation required/);
    // A lease dated ahead of this host's clock, with the hint about the clock; a lower token; an earlier end.
    await refusedBy((reply) => resign(reply, { issued_utc: new Date(d.clock.now + 1).toISOString() }), /future-dated.*clock is behind: check NTP/);
    await refusedBy((reply) => resign(reply, { fence_token: String(BigInt(first.fence_token) - 1n) }), /lower fence token/);
    await refusedBy((reply) => resign(reply, { expires_utc: new Date(first.expires_ms - 1).toISOString() }), /ends before the installed one/);
    // A genuine lease that the controller no longer sends (it is past renew_by_utc): an old answer, held back.
    await refusedBy((reply) => resign(reply, { renew_by_utc: new Date(d.clock.now).toISOString() }), /no longer sends.*old answer/);
    await refusedBy((reply) => resign(reply, { renew_by_utc: 'soon' }), /no longer sends/);
    // Answers that are no answers.
    await refusedBy(() => ({ status: 'granted' }), /unexpected form/);
    await assert.rejects(round(d.agent, { ...d.inject, fetcher: async () => new Response('<html>', { status: 502 }) }), /not JSON \(HTTP status 502\)/);
    await assert.rejects(round(d.agent, { ...d.inject, fetcher: async () => new Response('x'.repeat(70 * 1024)) }), /too large/);
    await assert.rejects(round(d.agent, { ...d.inject, fetcher: async () => { throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }); } }), /could not be reached: ECONNREFUSED/);
    assert.equal(await readFile(d.leaseFile, 'utf8'), installed);
    // After all that the true answer is still installed: the forgeries used up nothing.
    const next = await round(d.agent, d.inject);
    assert.equal(next.installed, true); assert.notEqual(next.lease_id, first.lease_id);
    assert.equal((await d.command('list')).result.keys[0].state, 'LEASED');
  } finally { await d.running.close(); }
});

test('the agent repeats a request with the same nonce, so a lost answer costs nothing and a lost agent state freezes the key', async () => {
  const d = await deployment();
  try {
    await d.command('approve-release', 'release.json'); await d.command('assign', d.key, 'host-a');
    d.clock.now += START_WAIT;
    const first = await round(d.agent, d.inject);
    d.clock.now += 60 * S;
    // The answer is lost on the way back, twice.
    const lost = async (url, options) => { await fetch(url, options); throw new TypeError('fetch failed'); };
    await assert.rejects(round(d.agent, { ...d.inject, fetcher: lost }), /could not be reached/);
    d.clock.now += RETRY_MS;
    await assert.rejects(round(d.agent, { ...d.inject, fetcher: lost }), /could not be reached/);
    const pending = JSON.parse(await readFile(d.agent.state_file, 'utf8'));
    assert.equal(pending.previous_lease_id, first.lease_id);
    d.clock.now += RETRY_MS;
    const second = await round(d.agent, d.inject);
    assert.equal(second.installed, true);
    assert.equal((await json(d.leaseFile)).payload.request_nonce, pending.nonce, 'the lease that was issued for the first try');
    assert.equal((await d.command('list')).result.keys[0].leases_in_this_tenure, 2);
    // The agent state is deleted while an answer is outstanding, as on a machine restored from an image.
    d.clock.now += 60 * S;
    await assert.rejects(round(d.agent, { ...d.inject, fetcher: lost }), /could not be reached/);
    await unlink(d.agent.state_file);
    d.clock.now += RETRY_MS;
    await assert.rejects(round(d.agent, d.inject), (error) => error.code === 'FROZEN' && /unfreeze /.test(error.message));
    assert.equal((await d.command('list')).result.keys[0].state, 'FROZEN');
    assert.ok(d.log.lines.some((line) => line.level === 'error' && /a key was frozen/.test(line.message) && line.host === 'host-a'), 'a freeze is an error in the controller\'s log');
    const thawed = await d.command('unfreeze', d.key);
    assert.equal(thawed.result.state, 'WAITING');
    d.clock.now += thawed.result.seconds_until_first_lease * S;
    const third = await round(d.agent, d.inject);
    assert.ok(BigInt(third.fence_token) > BigInt(first.fence_token));
  } finally { await d.running.close(); }
});

test('the agent\'s loop: a quarter of the lease between requests, ten seconds after a failure, and the log says when the validator stops', async () => {
  const d = await deployment();
  try {
    await d.command('approve-release', 'release.json'); await d.command('assign', d.key, 'host-a');
    d.clock.now += START_WAIT;
    const stop = new AbortController(), log = quiet(), waits = [];
    let down = false;
    const fetcher = (url, options) => (down ? Promise.reject(Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } })) : fetch(url, options));
    const sleep = async (ms) => { waits.push(ms); d.clock.now += ms; if (waits.length === 3) down = true; if (waits.length === 6) stop.abort(); };
    await run(d.agent, { ...d.inject, fetcher, log, sleep, signal: stop.signal });
    assert.deepEqual(waits, [60 * S, 60 * S, 60 * S, RETRY_MS, RETRY_MS, RETRY_MS]);
    const failed = log.lines.filter((line) => line.level === 'error');
    assert.equal(failed.length, 3);
    assert.match(failed[0].message, /no new lease: The controller could not be reached: ECONNREFUSED/);
    assert.deepEqual(failed.map((line) => [line.installed_lease_valid, line.installed_lease_seconds_left]), [[true, 180], [true, 170], [true, 160]]);
    assert.equal(failed[0].validator_stops_when_it_ends, true);
    assert.equal(log.lines.at(-1).message, 'lease agent stopped');
  } finally { await d.running.close(); }
});

test('agent config and settings paths', async () => {
  const base = { controller_url: 'https://lease.example:8960', host_id: 'host-a', host_key_file: path.resolve('/etc/time-v5/lease/host-key.json'), settings_file: path.resolve('/etc/time-v5/operator/settings.json') };
  const checked = validateAgentConfig(base);
  assert.equal(checked.controller_url, 'https://lease.example:8960'); assert.equal(checked.state_file, path.join(path.dirname(base.host_key_file), 'lease-agent-state.json')); assert.equal(checked.operator_directory, null);
  assert.throws(() => validateAgentConfig({ ...base, controller_url: 'http://10.0.0.5:8960' }), /plain http:\/\/ to another machine.*"allow_plain_http": true/);
  assert.equal(validateAgentConfig({ ...base, controller_url: 'http://10.0.0.5:8960', allow_plain_http: true }).controller_url, 'http://10.0.0.5:8960');
  assert.equal(validateAgentConfig({ ...base, controller_url: 'http://127.0.0.1:8960' }).controller_url, 'http://127.0.0.1:8960');
  for (const url of ['https://lease.example/path', 'https://user:word@lease.example', 'ftp://lease.example', 'lease.example:8960']) assert.throws(() => validateAgentConfig({ ...base, controller_url: url }), /controller_url/);
  assert.throws(() => validateAgentConfig({ ...base, renew_seconds: 5 }), /Unknown config setting/);
  assert.throws(() => validateAgentConfig({ ...base, host_id: 'Host A' }), /host_id/);
  assert.throws(() => validateAgentConfig({ ...base, settings_file: 'settings.json' }), /absolute path/);
  // Paths under /operator/ are read from the host's directory; nothing else is touched.
  const settings = { release_manifest: '/operator/release.json', release_id: 'x', genesis_file: '/operator/genesis.json', signer_lease_file: '/operator/signer-lease.json', trust_file: '/srv/elsewhere/trust.json', chain_id: 'c' };
  const directory = path.resolve('/etc/time-v5/operator'), view = hostView(settings, directory);
  assert.equal(view.release_manifest, path.join(directory, 'release.json')); assert.equal(view.signer_lease_file, path.join(directory, 'signer-lease.json')); assert.equal(view.trust_file, '/srv/elsewhere/trust.json'); assert.equal(view.chain_id, 'c');
  assert.equal(hostView(settings, null), settings);
  assert.throws(() => hostView({ ...settings, genesis_file: '/operator/../etc/passwd' }, directory), /unusual path/);
  assert.throws(() => hostView({ ...settings, lease_file: 'x' }, directory), /Unknown operator setting/);
});

test('the example configs name every setting and are refused until every placeholder is filled in', async () => {
  const here = (name) => new URL(name, import.meta.url), w = world();
  const example = JSON.parse(await readFile(here('./config.example.json'), 'utf8'));
  assert.deepEqual(Object.keys(example).sort(), ['authority_key_file', 'clock_skew_seconds', 'data_directory', 'fence_domain', 'host', 'hosts', 'lease_seconds', 'network', 'port', 'stop_seconds']);
  const absolute = { ...example, data_directory: path.resolve(example.data_directory), authority_key_file: path.resolve(example.authority_key_file) };
  assert.throws(() => validateConfig(absolute), /fence_domain/);
  const filled = { ...absolute, fence_domain: 'controller-eu-1', network: w.config.network, hosts: [{ ...w.config.hosts[0], signer_fencing: example.hosts[0].signer_fencing }] };
  // The last placeholder left is the declaration about the signer: nothing fills it in for the operator.
  assert.throws(() => validateConfig(filled), /signer_fencing is "EVERY_SIGNATURE" or "NOT_DECLARED".*README/);
  for (const [field, pattern] of [['network', /network\.genesis_sha256|network\.engine/], ['hosts', /host 0/]]) assert.throws(() => validateConfig({ ...filled, hosts: w.config.hosts, [field]: example[field] }), pattern);
  const checked = validateConfig({ ...filled, hosts: [{ ...w.config.hosts[0], signer_fencing: 'NOT_DECLARED' }] });
  assert.deepEqual([checked.lease_seconds, checked.clock_skew_seconds, checked.stop_seconds, checked.port, checked.host], [240, 10, 40, 8960, '127.0.0.1']);
  const agent = JSON.parse(await readFile(here('../lease-agent.example.json'), 'utf8'));
  assert.deepEqual(Object.keys(agent).sort(), ['allow_plain_http', 'controller_url', 'host_id', 'host_key_file', 'operator_directory', 'request_timeout_seconds', 'settings_file', 'state_file']);
  const paths = Object.fromEntries(['host_key_file', 'settings_file', 'operator_directory', 'state_file'].map((name) => [name, path.resolve(agent[name])]));
  assert.throws(() => validateAgentConfig({ ...agent, ...paths }), /controller_url|host_id/);
  assert.throws(() => validateAgentConfig({ ...agent, ...paths, controller_url: 'https://lease.example:8960' }), /host_id/);
  assert.equal(validateAgentConfig({ ...agent, ...paths, controller_url: 'https://lease.example:8960', host_id: 'val-eu-1' }).request_timeout_seconds, 10);
  // The operator's guide names every setting, every command and every refusal.
  const readme = await readFile(here('./README.md'), 'utf8'), design = await readFile(here('../../docs/design/signer-lease-controller.md'), 'utf8');
  for (const name of [...Object.keys(example), ...Object.keys(agent), 'network.engine', 'signer_fencing', 'signer_identity']) assert.ok(readme.includes('`' + name), name);
  for (const command of ['keygen authority', 'list', 'assign KEY HOST', 'move KEY NEW_HOST --from OLD_HOST', 'unfreeze KEY', 'refence KEY', 'approve-release', 'retire-release', '--again', '--above', 'clock-was-ahead']) assert.ok(readme.includes(command), command);
  // What the documents may not say without its conditions (review, finding 7).
  const kit = await readFile(here('../README.md'), 'utf8');
  for (const text of [readme, kit, design]) { assert.ok(!/two hosts never hold a valid lease/.test(text)); assert.ok(!/the one mistake the controller cannot catch/.test(text)); assert.ok(!/it issues nothing for 360 s/.test(text)); }
  for (const text of [readme, kit]) assert.match(text, /copied to (another|a second) machine together with the settings/);
  const codes = /The codes: ([A-Z_`, ]+)\./.exec(design)[1].split(',').map((code) => code.trim().replace(/`/g, ''));
  assert.equal(codes.length, 17);
  for (const code of codes) assert.ok(readme.includes('| `' + code + '` |'), code);
  const core = await readFile(here('./core.mjs'), 'utf8'), service = await readFile(here('./start.mjs'), 'utf8');
  for (const code of codes) assert.ok((core + service).includes("'" + code + "'"), 'the code ' + code + ' is given somewhere');
});

test('the agent, the service and the command line import nothing outside deploy/, so a release context can run them', async () => {
  const root = new URL('../../', import.meta.url), seen = new Set(), queue = ['deploy/lease-agent.mjs', 'deploy/lease-controller/start.mjs', 'deploy/lease-controller/ctl.mjs'];
  while (queue.length) {
    const file = queue.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    const text = await readFile(new URL(file, root), 'utf8');
    // Import and re-export statements at the start of a line, and import("...") anywhere.
    for (const match of text.matchAll(/(?:^\s*(?:import|export)\s[^'";]*?\bfrom\s*|^\s*import\s*|\bimport\(\s*)(['"])([^'"]+)\1/gm)) {
      if (match[2].startsWith('node:')) continue;
      assert.ok(match[2].startsWith('./') || match[2].startsWith('../'), file + ' imports the package ' + match[2]);
      queue.push(path.posix.normalize(path.posix.join(path.posix.dirname(file), match[2])));
    }
  }
  for (const file of seen) assert.match(file, /^deploy\/[a-z-]+(?:\/[a-z-]+)?\.mjs$/, file);
  for (const file of ['deploy/lib.mjs', 'deploy/operator.mjs', 'deploy/lease-protocol.mjs', 'deploy/lease-controller/core.mjs', 'deploy/lease-controller/store.mjs']) assert.ok(seen.has(file), file);
  // The agent alone needs only the kit's top-level files: it is what runs on a validator host.
  const agent = await readFile(new URL('deploy/lease-agent.mjs', root), 'utf8');
  assert.deepEqual([...agent.matchAll(/^import\s[^'";]*?\bfrom\s*'(\.[^']+)'/gm)].map((match) => match[1]).sort(), ['./lease-protocol.mjs', './lib.mjs', './operator.mjs']);
  assert.ok(!/\bimport\(/.test(agent));
});

test('key files: made once, readable by the owner only, and of one purpose', async () => {
  const directory = await temporary('keys'), file = path.join(directory, 'authority.json');
  const record = generateKeyRecord(KEY_PURPOSES.authority, 'lease-authority-1'), made = await writeKeyFile(file, record);
  assert.deepEqual(made, { purpose: 'signer-lease-authority', id: 'lease-authority-1', public_key_hex: record.public_key_hex });
  await assert.rejects(writeKeyFile(file, generateKeyRecord(KEY_PURPOSES.authority, 'other')), /already there and is kept/);
  const key = await readKeyFile(file, KEY_PURPOSES.authority);
  assert.equal(key.id, 'lease-authority-1'); assert.equal(key.publicKeyHex, record.public_key_hex);
  await assert.rejects(readKeyFile(file, KEY_PURPOSES.host), /not a signer-lease-host key/);
  await assert.rejects(readKeyFile(path.join(directory, 'missing.json'), KEY_PURPOSES.host), /could not be read/);
  assert.throws(() => generateKeyRecord(KEY_PURPOSES.host, 'Bad Id'), /The id is/);
  assert.throws(() => generateKeyRecord('consensus', 'x'), /Unknown key purpose/);
  const damaged = path.join(directory, 'damaged.json');
  await writeFile(damaged, JSON.stringify({ ...record, public_key_hex: 'a'.repeat(64) }), { mode: 0o600 });
  await assert.rejects(readKeyFile(damaged, KEY_PURPOSES.authority), /public key is not the one of its secret/);
  if (process.platform !== 'win32') {
    const open = path.join(directory, 'open.json');
    await writeFile(open, JSON.stringify(record), { mode: 0o644 });
    await assert.rejects(readKeyFile(open, KEY_PURPOSES.authority), /read by other users.*chmod 600/);
  }
  // A service started from the key file signs with it, and its log never holds the secret.
  const w = world(), log = quiet(), config = { ...w.config, data_directory: await temporary('service'), authority_key_file: file };
  const running = await start(config, { log, port: 0, exitOnLost: false });
  try {
    const started = log.lines.find((line) => line.message === 'signer-lease controller started');
    assert.equal(started.authority, 'lease-authority-1'); assert.equal(started.authority_public_key_hex, record.public_key_hex); assert.equal(started.start_wait_seconds, 360); assert.equal(started.state_was_empty, true);
    assert.ok(!JSON.stringify(log.lines).includes(record.secret_hex));
  } finally { await running.close(); }
});

test('one service per state directory', async () => {
  const w = world(), config = { ...w.config, data_directory: await temporary('lock') }, inject = { authority: w.authority, log: quiet(), port: 0, exitOnLost: false };
  const first = await start(config, inject);
  try { await assert.rejects(start(config, inject), /Another lease controller \(process \d+\) uses|This process already serves/); } finally { await first.close(); }
  // After a clean stop the directory can be served again; the start rule ran a second time.
  const second = await start(config, inject);
  try { assert.equal(second.controller.current().seq, 2); } finally { await second.close(); }
  // A lock whose holder is gone is taken; a holder that finds its lock taken is told once.
  const directory = await temporary('lock');
  await writeFile(path.join(directory, 'controller.lock'), JSON.stringify({ pid: 2 ** 22 + 7, run: 'gone', beat: Date.now() }));
  let lost = null;
  const release = await claim(directory, { beatMs: 20, onLost: (why) => { lost = why; } });
  await writeFile(path.join(directory, 'controller.lock'), JSON.stringify({ pid: process.pid, run: 'someone-else', beat: Date.now() }));
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.equal(lost, 'another process holds the lock');
  await release();
  assert.equal(JSON.parse(await readFile(path.join(directory, 'controller.lock'), 'utf8')).run, 'someone-else', 'a lock that is not ours is left alone');
});

test('the command line: every action, and refusals that say what to do instead', async () => {
  const w = world(), clock = { now: T0 }, config = validateConfig({ ...w.config, data_directory: await temporary('ctl') }), [key, other] = w.validatorKeys;
  const run = (...words) => runCommand(config, words, { now: () => clock.now, readManifest: async (file) => ({ 'one.json': w.releases.one, 'two.json': w.releases.two, 'v4.json': manifest('v4', 'one') })[file] ?? Promise.reject(new Error('no such file')) });
  const refused = (promise, pattern) => assert.rejects(promise, (error) => error.constructor.name === 'CommandRefused' && pattern.test(error.message));
  assert.match((await run('list')).result.note, /no state yet/);
  await refused(run(), /Usage:/); await refused(run('frobnicate'), /Usage:/); await refused(run('assign', key), /Usage:/);
  await refused(run('approve-release', 'missing.json'), /could not be read/);
  await refused(run('approve-release', 'v4.json'), /runs engine v4.*network runs v5/);
  assert.equal((await run('approve-release', 'one.json')).result.approved, w.releases.one.release_id);
  await refused(run('approve-release', 'one.json'), /already approved.*--again/);
  await refused(run('approve-release', 'one.json', '--force'), /Unknown option --force/);
  await refused(run('assign', key, 'host-z'), /lists no host "host-z".*the hosts are: host-a, host-b, host-c/);
  const assigned = await run('assign', key, 'host-a');
  assert.deepEqual([assigned.changed, assigned.result.done, assigned.result.holder, assigned.result.state, assigned.result.seconds_until_first_lease, assigned.result.margin_seconds], [true, 'assign', 'host-a', 'WAITING', 360, 60]);
  await refused(run('assign', key, 'host-b'), /is held by host host-a.*move /);
  await refused(run('move', key, 'host-b'), /Say which host holds the key now/);
  await refused(run('move', key, 'host-b', '--from'), /--from needs a value/);
  await refused(run('move', key, 'host-b', '--from', 'host-c'), /held by host host-a, not by host-c\. Nothing was changed/);
  const moved = await run('move', key, 'host-b', '--from', 'host-a');
  assert.equal(moved.result.holder, 'host-b'); assert.match(moved.result.before_the_new_host_starts, /Move the signer's record of what it last signed together with the key/);
  await refused(run('unfreeze', key), /not frozen/);
  await refused(run('refence', other), /no holder/);
  await refused(run('refence', key, '--above', '12x'), /--above takes a fence token/);
  const token = BigInt((await run('list')).result.keys[0].fence_token);
  assert.equal(BigInt((await run('refence', key, '--above', String(token + 1000n))).result.fence_token), token + 1001n);
  assert.equal((await run('approve-release', 'two.json')).result.releases.length, 2);
  assert.deepEqual((await run('retire-release', w.releases.one.release_id)).result.releases.map((item) => item.release_id), [w.releases.two.release_id]);
  await refused(run('retire-release', w.releases.one.release_id), /not approved here/);
  assert.equal((await run('unassign', key)).result.holder, null);
  await refused(run('unassign', key), /no holder/);
  const listed = (await run('list')).result;
  assert.deepEqual([listed.keys.length, listed.keys[0].state, listed.network.engine, listed.fence_domain], [1, 'NO_HOLDER', 'v5', 'test-domain']);
  assert.match(USAGE, /move KEY HOST --from OLD/);
  // A command given while the state belongs to another network changes nothing.
  await assert.rejects(runCommand({ ...config, fence_domain: 'other-domain' }, ['assign', other, 'host-c'], { now: () => clock.now }), /domain/);
  assert.equal((await run('list')).result.keys.length, 1);
});

test('a start rule that meets a first start, a restart and an empty directory writes its state before it answers', async () => {
  const w = world(), directory = await temporary('start'), clock = { now: T0 };
  const first = await controllerOn(w, directory, clock);
  assert.equal(first.current().seq, 1); assert.equal(first.current().state.floor_ms, T0 + 300 * S);
  assert.deepEqual(await newestState(directory), applyStart(emptyState(w.config, T0), w.config, T0));
  await assert.rejects(createController({ config: w.config, store: fileStore(directory), sign: w.sign }).submit({}), /not open/);
  clock.now += 5 * S;
  const second = await controllerOn(w, directory, clock);
  assert.equal(second.current().seq, 2); assert.equal((await newestState(directory)).floor_ms, T0 + 305 * S);
  await rename(path.join(directory, 'state'), path.join(directory, 'state-set-aside'));
  await assert.rejects(second.submit(ask(w, 'host-a', w.validatorKeys[0], { timeMs: clock.now })), Fatal);
});

// ---- After the review: the clock, the line of state files, limits ------------------

test('a wall clock changed under the running service stops it; a state written with a later clock is refused at the start and by every command; "clock-was-ahead" is the way out', async () => {
  const w = world(), directory = await temporary('clock'), key = w.validatorKeys[0];
  // Two clocks, as on a real machine: the wall clock can be set; elapsed time cannot.
  const clock = { wall: T0, elapsed: 0 }, now = () => clock.wall, monotonic = () => clock.elapsed, pass = (ms) => { clock.wall += ms; clock.elapsed += ms; };
  const config = validateConfig({ ...w.config, data_directory: directory }), command = (...words) => runCommand(config, words, { now, readManifest: async () => w.releases.one });
  const open = async () => { const controller = createController({ config, store: fileStore(directory), sign: w.sign, now, monotonic }); await controller.open(); return controller; };
  const wait = async () => (await command('list')).result.keys[0].seconds_until_first_lease;
  let controller = await open();
  await command('approve-release', 'release.json'); await command('assign', key, 'host-a');
  pass(START_WAIT);
  const first = (await controller.submit(ask(w, 'host-a', key, { timeMs: clock.wall }))).lease.payload;
  // Every state a service writes carries its clock: that is what a later start compares with.
  assert.equal((await fileStore(directory).read()).state.clock_ms, clock.wall);
  // A clock that moves inside the skew, in either direction, stops nothing.
  clock.wall += 10 * S; controller.checkWallClock(); clock.wall -= 20 * S; controller.checkWallClock(); clock.wall += 10 * S;
  // The clock is set forward by 11 s (or the machine was suspended that long). A request arrives
  // BEFORE the timer has looked at the clock: the check before every answer stops the service
  // there. Nothing is written, and nothing is answered from then on.
  pass(SPACING); clock.wall += 11 * S;
  const changed = (by) => (error) => error instanceof Fatal && new RegExp(`clock was changed by ${by} s while the controller ran.*start the controller again`, 's').test(error.message);
  const written = (await fileStore(directory).read()).seq;
  await assert.rejects(controller.submit(ask(w, 'host-a', key, { timeMs: clock.wall, previous: first.lease_id })), changed(11));
  assert.equal((await fileStore(directory).read()).seq, written, 'the refused request wrote nothing');
  assert.throws(() => controller.checkWallClock(), changed(11));
  clock.wall -= 11 * S;
  await assert.rejects(controller.submit(ask(w, 'host-a', key, { timeMs: clock.wall, previous: first.lease_id })), Fatal, 'a stopped controller stays stopped');
  clock.wall += 11 * S;
  // A new start counts on the clock as it is now. The recorded lease still runs: its holder goes on.
  controller = await open();
  const second = (await controller.submit(ask(w, 'host-a', key, { timeMs: clock.wall, previous: first.lease_id }))).lease.payload;
  assert.equal(second.fence_token, first.fence_token);
  // Set back by 11 s, and this time the look at the clock comes first: the same stop.
  clock.wall -= 11 * S; assert.throws(() => controller.checkWallClock(), changed(-11)); clock.wall += 11 * S;

  // The machine reboots with its clock an hour AHEAD, and the service is started.
  pass(1000 * S); clock.wall += 3600 * S;
  controller = await open();
  assert.equal(await wait(), 360);
  // The clock is corrected. The running service stops; a new start is refused, and so is every
  // command, because the state holds times an hour later than the clock: one of the two is wrong.
  clock.wall -= 3600 * S;
  assert.throws(() => controller.checkWallClock(), Fatal);
  const refusal = (error) => error.constructor.name === 'ClockRefused' && /FIRST check this machine's clock against a time source you trust.*If this clock is behind: correct it.*"clock-was-ahead"/s.test(error.message);
  await assert.rejects(open(), refusal);
  for (const words of [['move', key, 'host-b', '--from', 'host-a'], ['refence', key], ['unassign', key], ['approve-release', 'release.json', '--again'], ['assign', w.validatorKeys[1], 'host-c']]) await assert.rejects(command(...words), refusal);
  const listed = (await command('list')).result;
  assert.match(listed.warning, /FIRST check this machine's clock/); assert.equal(listed.keys[0].seconds_until_first_lease, 3960, 'what the wrong clock left behind');
  // The operator has checked the clock and says so. Every cover is counted again from this clock.
  const corrected = await command('clock-was-ahead');
  assert.equal(Date.parse(corrected.result.keys[0].first_lease_not_before_utc), clock.wall + 360 * S);
  assert.equal(corrected.result.keys[0].a_lease_dated_by_the_wrong_clock_is_waited_for_until_utc, undefined);
  await assert.rejects(command('clock-was-ahead'), /nothing to correct/);
  controller = await open();
  assert.equal(await wait(), 360);
  assert.ok(BigInt((await command('list')).result.keys[0].fence_token) > BigInt(second.fence_token), 'tokens only rise');
  pass(360 * S);
  const third = (await controller.submit(ask(w, 'host-a', key, { timeMs: clock.wall }))).lease.payload;
  assert.equal(third.host_id, 'host-a');

  // The harder case: the hosts' clocks were ahead with the controller's, so a lease was handed
  // out with dates an hour in the future. It is recorded, and it is waited for to its end.
  pass(1000 * S); clock.wall += 3600 * S;
  controller = await open(); pass(360 * S);
  const future = (await controller.submit(ask(w, 'host-a', key, { timeMs: clock.wall }))).lease.payload;
  clock.wall -= 3600 * S;
  await assert.rejects(open(), refusal);
  const kept = (await command('clock-was-ahead')).result.keys[0];
  assert.equal(kept.a_lease_dated_by_the_wrong_clock_is_waited_for_until_utc, future.expires_utc);
  // The holder's tenure goes on: it holds that lease. Everyone else waits for the lease's end.
  assert.equal(kept.the_holders_lease_still_runs_and_its_tenure_goes_on_until_utc, future.expires_utc); assert.equal(kept.first_lease_not_before_utc, undefined);
  controller = await open();
  await command('move', key, 'host-b', '--from', 'host-a');
  assert.ok(await wait() > 3600, 'another host waits until that lease has ended on a right clock');
  // The dates of the last grant and the last request were an hour ahead too. They are brought
  // back to the clock, or a holder with a right clock would be refused for an hour.
  const again = await open(), rebased = await fileStore(directory).read();
  assert.ok(Object.values(rebased.state.keys).every((item) => item.last_grant_ms <= clock.wall && item.last_request_ms <= clock.wall));
  await command('move', key, 'host-a', '--from', 'host-b');
  assert.equal((await again.submit(ask(w, 'host-b', key, { timeMs: clock.wall }))).code, 'NOT_HOLDER');
});

test('the service timer: a clock set under a running service ends it within a second, and its log says what to do', async () => {
  const w = world(), clock = { wall: Date.now(), offset: 0 }, log = quiet(), fatal = [];
  const running = await start({ ...w.config, data_directory: await temporary('timer') }, { authority: w.authority, now: () => Date.now() + clock.offset, monotonic: () => performance.now(), log, port: 0, exitOnLost: false, onFatal: (error) => fatal.push(error) });
  try {
    clock.offset = 30 * S;
    for (let i = 0; i < 40 && !fatal.length; i++) await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(fatal.length, 1); assert.ok(fatal[0] instanceof Fatal); assert.match(fatal[0].message, /clock was changed by 30 s/);
    const answer = await fetch(running.url + '/v1/lease', { method: 'POST', body: JSON.stringify(ask(w, 'host-a', w.validatorKeys[0], { timeMs: Date.now() })) });
    assert.equal(answer.status, 503); assert.equal((await answer.json()).code, 'BUSY');
    // The timeouts that keep a slow or silent connection from holding the service.
    assert.deepEqual([running.server.requestTimeout, running.server.headersTimeout, running.server.keepAliveTimeout], [10_000, 5_000, 2_000]);
  } finally { await running.close(); }
});

test('a running service follows only its own line of state files: a file of another line under its number, or a gap, stops it; what its own commands wrote is followed', async () => {
  const { w, directory, clock, key, controller } = await readyDirectory(), store = fileStore(directory);
  const first = (await controller.submit(ask(w, 'host-a', key, { timeMs: clock.now }))).lease.payload;
  // A command writes two newer files. The service reads them before its next answer.
  await runCommand(w.config, ['assign', w.validatorKeys[1], 'host-b'], { store, now: () => clock.now });
  await runCommand(w.config, ['unassign', w.validatorKeys[1]], { store, now: () => clock.now });
  clock.now += SPACING;
  assert.equal((await controller.submit(ask(w, 'host-a', key, { timeMs: clock.now, previous: first.lease_id }))).status, 'granted');
  assert.equal(controller.current().seq, await store.latest());
  // The newest file is taken away and another state is written under the same number.
  const newest = await store.read(), file = path.join(directory, 'state', (await stateFiles(directory)).at(-1));
  await unlink(file);
  await store.write(newest.seq, { ...newest.state, floor_ms: newest.state.floor_ms + 1 }, newest.parent);
  await assert.rejects(controller.submit(ask(w, 'host-a', key, { timeMs: clock.now + 1 })), (error) => error instanceof Fatal && /newest file is not the one the controller wrote.*follows only its own line/s.test(error.message));
  // A newer file that does not name the file before it, and a newer file after a gap.
  for (const make of [async (files, held) => files.write(held.seq + 1, held.state, 'f'.repeat(64)), async (files, held) => files.write(held.seq + 2, held.state, held.sha256)]) {
    const other = await readyDirectory(w), files = fileStore(other.directory);
    await make(files, await files.read());
    await assert.rejects(other.controller.submit(ask(w, 'host-a', other.key, { timeMs: other.clock.now })), (error) => error instanceof Fatal && /was not made from the file before it|is missing/.test(error.message));
  }
});

test('at most 64 requests wait for the one that is being decided; the rest are told at once to ask again', async () => {
  const { w, directory, clock, key } = await readyDirectory(), files = fileStore(directory);
  let held = false, release = null;
  const gate = new Promise((resolve) => { release = resolve; });
  const controller = createController({ config: w.config, store: { ...files, read: async () => { if (held) await gate; return files.read(); } }, sign: w.sign, now: () => clock.now });
  await controller.open(); clock.now += START_WAIT; held = true;
  const answers = Array.from({ length: MAX_WAITING + 10 }, (_, i) => controller.submit(ask(w, 'host-b', key, { timeMs: clock.now + i })));
  const early = await Promise.all(answers.slice(MAX_WAITING));
  assert.deepEqual(early.map((answer) => answer.code), Array(10).fill('BUSY'));
  release();
  assert.deepEqual((await Promise.all(answers.slice(0, MAX_WAITING))).map((answer) => answer.code), Array(MAX_WAITING).fill('NOT_HOLDER'));
  assert.equal((await controller.submit(ask(w, 'host-a', key, { timeMs: clock.now }))).status, 'granted');
});

test('the agent follows no redirect, reads no key file through a link or of unusual size, and asks nothing when it cannot read its lease file', async () => {
  const d = await deployment();
  try {
    await d.command('approve-release', 'release.json'); await d.command('assign', d.key, 'host-a');
    d.clock.now += START_WAIT;
    // A server on the path answers 307 and points to another address.
    let reached = 0;
    const elsewhere = createServer((request, response) => { reached++; response.end('{}'); }), redirector = createServer((request, response) => { response.writeHead(307, { location: `http://127.0.0.1:${elsewhere.address().port}/v1/lease` }); response.end(); });
    await new Promise((resolve) => elsewhere.listen(0, '127.0.0.1', resolve)); await new Promise((resolve) => redirector.listen(0, '127.0.0.1', resolve));
    try {
      const redirected = validateAgentConfig({ ...Object.fromEntries(Object.entries(d.agent).filter(([, value]) => value !== null)), controller_url: `http://127.0.0.1:${redirector.address().port}` });
      await assert.rejects(round(redirected, d.inject), /could not be reached/);
      assert.equal(reached, 0);
    } finally { elsewhere.close(); redirector.close(); }
    // The host key file: a real, small, regular file.
    const directory = await temporary('host-key'), file = path.join(directory, 'host-key.json'), record = generateKeyRecord(KEY_PURPOSES.host, 'host-a');
    await writeKeyFile(file, record);
    await writeFile(path.join(directory, 'large.json'), JSON.stringify({ ...record, padding: 'x'.repeat(5000) }), { mode: 0o600 });
    await assert.rejects(readKeyFile(path.join(directory, 'large.json'), KEY_PURPOSES.host), /small regular file, not a link/);
    await assert.rejects(readKeyFile(directory, KEY_PURPOSES.host), /small regular file, not a link/);
    const linked = await symlink(file, path.join(directory, 'link.json')).then(() => true, (error) => { if (error.code === 'EPERM') return false; throw error; });
    if (linked) await assert.rejects(readKeyFile(path.join(directory, 'link.json'), KEY_PURPOSES.host), /small regular file, not a link/);
    // With the key from its file the agent works; the file was made for this host id only.
    const withFile = { ...d.agent, host_key_file: file }, first = await round(withFile, { now: d.now }).catch((error) => error);
    assert.match(first.message, /BAD_SIGNATURE/, 'the controller knows another key for host-a: the file key is read and used');
    await assert.rejects(round({ ...withFile, host_id: 'host-b' }, { now: d.now }), /made for another host id/);
    // An empty lease file counts as no lease file (a tool made it to set its owner): the first
    // lease is asked for and installed over it.
    await mkdir(path.dirname(d.leaseFile), { recursive: true }); await writeFile(d.leaseFile, '');
    assert.equal((await round(d.agent, d.inject)).installed, true);
    assert.equal((await json(d.leaseFile)).payload.host_id, 'host-a');
    // A lease file that is there and cannot be read as a lease: the round is given up before anything is sent.
    d.clock.now += 60 * S;
    const good = await readFile(d.leaseFile, 'utf8');
    let sent = 0;
    const counting = (url, options) => { sent++; return fetch(url, options); };
    for (const content of [' ', '{"payload":{}}', good.slice(0, 40), '[]']) {
      await writeFile(d.leaseFile, content);
      await assert.rejects(round(d.agent, { ...d.inject, fetcher: counting }), /installed lease file cannot be read as a lease.*Nothing was asked/s);
    }
    assert.equal(sent, 0);
    await writeFile(d.leaseFile, good);
    assert.equal((await round(d.agent, { ...d.inject, fetcher: counting })).installed, true); assert.equal(sent, 1);
    assert.equal((await d.command('list')).result.keys[0].state, 'LEASED');
  } finally { await d.running.close(); }
});

test('the lease lives in a directory of its own: the agent writes nowhere else, and the file is readable for the containers whatever the umask', async () => {
  const d = await deployment();
  try {
    await d.command('approve-release', 'release.json'); await d.command('assign', d.key, 'host-a');
    d.clock.now += START_WAIT;
    // The settings name the lease in a subdirectory. Only that directory needs to be writable for the agent.
    const settings = JSON.parse(await readFile(d.host.settingsFile, 'utf8'));
    await mkdir(path.join(d.host.directory, 'lease'));
    await writeFile(d.host.settingsFile, JSON.stringify({ ...settings, signer_lease_file: '/operator/lease/signer-lease.json' }));
    const before = (await readdir(d.host.directory)).sort(), old = process.platform === 'win32' ? null : process.umask(0o077);
    let installed;
    try { installed = await round(d.agent, d.inject); d.clock.now += 60 * S; installed = await round(d.agent, d.inject); } finally { if (old !== null) process.umask(old); }
    assert.equal(installed.installed, true);
    assert.deepEqual((await readdir(d.host.directory)).sort(), before, 'nothing was created beside the settings and the trust file');
    assert.deepEqual(await readdir(path.join(d.host.directory, 'lease')), ['signer-lease.json']);
    const file = path.join(d.host.directory, 'lease', 'signer-lease.json');
    assert.deepEqual(Object.keys(JSON.parse(await readFile(file, 'utf8'))).sort(), ['issuer', 'payload', 'signature']);
    assert.equal(LEASE_FILE_MODE, 0o644);
    if (process.platform !== 'win32') assert.equal((await stat(file)).mode & 0o777, 0o644, 'readable for the containers\' user under a umask of 077');
    // The guard, with the settings as the containers see them mapped to this host, accepts it.
    assert.equal((await guard(hostView(JSON.parse(await readFile(d.host.settingsFile, 'utf8')), d.host.directory), d.clock.now)).lease.lease_id, installed.lease_id);
  } finally { await d.running.close(); }
});

// ---- After the second review --------------------------------------------------------

test('a state the command line wrote on a later clock is not followed; many commands between two requests are followed, and old files go only behind what the service holds', async () => {
  const { w, directory, clock, key, controller } = await readyDirectory(), store = fileStore(directory);
  const first = (await controller.submit(ask(w, 'host-a', key, { timeMs: clock.now }))).lease.payload;
  // Fifty commands before the next request: more than the 32 files a service keeps behind itself.
  for (let i = 0; i < 25; i++) { await runCommand(w.config, ['assign', w.validatorKeys[1], 'host-b'], { store, now: () => clock.now }); await runCommand(w.config, ['unassign', w.validatorKeys[1]], { store, now: () => clock.now }); }
  assert.ok((await stateFiles(directory)).length > 50, 'a command removes no file');
  clock.now += SPACING;
  assert.equal((await controller.submit(ask(w, 'host-a', key, { timeMs: clock.now, previous: first.lease_id }))).status, 'granted');
  assert.equal((await stateFiles(directory)).length, KEPT_FILES, 'the service followed them all and then removed what lies behind it');
  // A newer file of the service's own line, but stamped with a clock an hour ahead.
  const held = await store.read();
  await store.write(held.seq + 1, { ...held.state, clock_ms: clock.now + 3600 * S }, held.sha256);
  await assert.rejects(controller.submit(ask(w, 'host-a', key, { timeMs: clock.now + 1 })), (error) => error instanceof Fatal && /FIRST check this machine's clock/.test(error.message));
});
