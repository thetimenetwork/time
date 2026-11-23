// Second independent review, of the fixes made after the first one (branch lease-controller at
// a491504): the controller's clock checks, the command "clock-was-ahead", the rule against
// recordings, and the line of state files a running service follows.
//
// A test named FINDING states something the design claims, or an operator relies on, and FAILS
// against the code under review: the failure is the finding. A test named HELD is an attack that
// did not work, and passes. Nothing here changes the code under review.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { guard } from '../operator.mjs';
import { newNonce } from '../lease-protocol.mjs';
import { approveRelease, assign, decide, emptyState, validateState } from './core.mjs';
import { Fatal, createController, validateConfig } from './start.mjs';
import { fileStore, memoryStore } from './store.mjs';
import { runCommand } from './ctl.mjs';
import { ask, operatorDirectory, world } from './fixtures.mjs';

const T0 = Date.parse('2026-12-01T00:00:00.000Z');
const S = 1000, SKEW = 10 * S, LEASE = 240 * S, MARGIN = 60 * S, SPACING = 31 * S, START_WAIT = 300 * S + MARGIN;

/// Whether the kit's real guard accepts `lease` on `hostId` at `hostNow`.
async function guardAccepts(w, hostId, key, lease, hostNow) {
  const host = await operatorDirectory(w, hostId, key);
  await writeFile(host.settings.signer_lease_file, JSON.stringify(lease));
  try { await guard(host.settings, hostNow); return true; } catch { return false; }
}
/// One controller machine: a state directory in memory, a wall clock the test sets, and the
/// commands and services that run on it. Every service is a new process (its own clock baseline).
function machine(w, { store = memoryStore(), at = T0 } = {}) {
  const m = { clock: at, store, config: validateConfig(w.config), service: null };
  m.now = () => m.clock;
  m.command = (...words) => runCommand(m.config, words, { store: m.store, now: m.now, readManifest: async () => w.releases.one });
  m.start = async () => { m.service = createController({ config: m.config, store: m.store, sign: w.sign, now: m.now }); await m.service.open(); return m.service; };
  m.ask = (hostId, key, options = {}) => m.service.submit(ask(w, hostId, key, { timeMs: m.clock, ...options }));
  m.key = async (key) => (await m.command('list')).result.keys.find((item) => item.validator_public_key_hex === key);
  return m;
}

// ---- Findings --------------------------------------------------------------------

test('FINDING (outside A1): after "clock-was-ahead", a copy of the state from the minutes the clock was ahead is still taken for "running" at a later start; its holder gets a lease while the new holder\'s is live', async () => {
  const w = world(), key = w.validatorKeys[0], m = machine(w);
  await m.start(); await m.command('approve-release', 'release.json'); await m.command('assign', key, 'host-a');
  m.clock += START_WAIT + 1 * S;
  let held = (await m.ask('host-a', key)).lease;
  m.clock += 60 * S; held = (await m.ask('host-a', key, { previous: held.payload.lease_id })).lease;
  const R = m.clock; // true time of host-a's last lease; it ends at R + 240 s
  // True time R + 10 s. The machine's clock jumps 200 s ahead (a bad time source). The service
  // stops, as it must, and its supervisor starts it again while the clock is still ahead.
  m.clock = R + 10 * S + 200 * S; await m.start();
  // The operator's routine copy of the state directory is taken in these seconds.
  const copy = structuredClone(m.store.disk);
  // R + 15 s: the clock is corrected. The start is refused; the operator checks the clock and
  // runs the documented way out (README, "After the clock was wrong"), then starts.
  m.clock = R + 15 * S;
  await assert.rejects(m.start(), /FIRST check this machine's clock/);
  m.clock = R + 20 * S; await m.command('clock-was-ahead');
  m.clock = R + 25 * S; await m.start();
  // host-a is to be replaced. The key is moved; host-b gets its first lease when the wait is over.
  m.clock = R + 30 * S; await m.command('move', key, 'host-b', '--from', 'host-a');
  m.clock = Date.parse((await m.key(key)).first_lease_not_before_utc);
  const given = await m.ask('host-b', key);
  assert.equal(given.status, 'granted'); assert.ok(m.clock >= R + LEASE + MARGIN, 'host-b waited for host-a\'s lease');
  // 25 s later the controller's disk is lost. The copy is put back (README, "Restored from a
  // copy": "Start the controller"; "A start is always safe: the start rule applies").
  m.clock += 25 * S;
  const restored = machine(w, { store: memoryStore(structuredClone(copy)), at: m.clock });
  await restored.start();
  const state = (await restored.key(key)).state;
  // host-a still runs its agent and asks, naming the last lease it was given.
  restored.clock += 1 * S;
  const again = await restored.ask('host-a', key, { previous: held.payload.lease_id });
  const both = again.status === 'granted' && await guardAccepts(w, 'host-b', key, given.lease, restored.clock) && await guardAccepts(w, 'host-a', key, again.lease, restored.clock);
  assert.deepEqual({ key_after_the_start: state, host_a: again.code ?? again.status, both_leases_accepted_by_the_real_guard: both }, { key_after_the_start: 'WAITING', host_a: 'WAIT', both_leases_accepted_by_the_real_guard: false },
    `host-b's lease runs for ${(Date.parse(given.lease.payload.expires_utc) - restored.clock) / 1000} s more`);
});

test('FINDING (outside A1): a copy of the state restored on a machine whose clock is four minutes behind: the start takes an ended tenure for "running", and the start after the clock is corrected still does; the old holder gets a lease while the lease of the new holder is live', async () => {
  const w = world(), key = w.validatorKeys[0], old = machine(w);
  await old.start(); await old.command('approve-release', 'release.json'); await old.command('assign', key, 'host-a');
  old.clock += START_WAIT + 1 * S;
  const held = (await old.ask('host-a', key)).lease, issued = old.clock;
  // Five seconds later the operator's routine copy of the state is taken; ten seconds after that
  // the key is moved to host-b. host-a's validator is stopped; its agent still runs.
  old.clock = issued + 5 * S; const copy = structuredClone(old.store.disk);
  old.clock = issued + 15 * S; await old.command('move', key, 'host-b', '--from', 'host-a');
  old.clock = Date.parse((await old.key(key)).first_lease_not_before_utc);
  let given = (await old.ask('host-b', key)).lease;
  for (let i = 0; i < 2; i++) { old.clock += 60 * S; given = (await old.ask('host-b', key, { previous: given.payload.lease_id })).lease; }
  // The controller's machine is lost. A replacement boots ten seconds later with its clock 250 s
  // behind; the copy, seven minutes old, is put on it and the service is started. The copy was
  // written before that clock's reading, so the start is not refused, and on that clock host-a's
  // lease "still runs".
  const trueTime = { now: old.clock + 15 * S }, behind = { ms: 250 * S }, elapsed = { now: 0 }, store = memoryStore(copy), config = validateConfig(w.config);
  const wall = () => trueTime.now - behind.ms, pass = (ms) => { trueTime.now += ms; elapsed.now += ms; };
  const open = async () => { const service = createController({ config, store, sign: w.sign, now: wall, monotonic: () => elapsed.now }); await service.open(); return service; };
  let service = await open();
  pass(5 * S);
  // While the clock is wrong, a host with a right clock is refused: the tripwire works.
  assert.equal((await service.submit(ask(w, 'host-a', key, { timeMs: trueTime.now, previous: held.payload.lease_id }))).code, 'CLOCK');
  // NTP steps the clock right. The service stops, as designed, and its supervisor starts it again.
  pass(5 * S); behind.ms = 0;
  await assert.rejects(service.submit(ask(w, 'host-a', key, { timeMs: trueTime.now, previous: held.payload.lease_id })), Fatal);
  service = await open();
  // Design 5.5: "a service started while its clock was behind does not keep the waits it counted
  // from that clock: they end with the process." The wait did; the decision "running" did not.
  pass(1 * S);
  const again = await service.submit(ask(w, 'host-a', key, { timeMs: trueTime.now, previous: held.payload.lease_id }));
  const both = again.status === 'granted' && await guardAccepts(w, 'host-b', key, given, trueTime.now) && await guardAccepts(w, 'host-a', key, again.lease, trueTime.now);
  assert.deepEqual({ host_a: again.code ?? again.status, both_leases_accepted_by_the_real_guard: both }, { host_a: 'WAIT', both_leases_accepted_by_the_real_guard: false },
    `host-b's lease runs for ${(Date.parse(given.payload.expires_utc) - trueTime.now) / 1000} s more`);
});

test('FINDING (outside A1; availability): a clock that is a minute ahead for a few seconds, with the supervisor restarting the service inside them: the documented way out ends every tenure, and a validator whose lease had minutes left must stop; waiting 50 s and starting would have kept it', async () => {
  const w = world(), key = w.validatorKeys[0], m = machine(w);
  await m.start(); await m.command('approve-release', 'release.json'); await m.command('assign', key, 'host-a');
  m.clock += START_WAIT + 1 * S;
  let held = (await m.ask('host-a', key)).lease;
  m.clock += 60 * S; held = (await m.ask('host-a', key, { previous: held.payload.lease_id })).lease;
  const R = m.clock;
  // R + 10 s: the clock reads 60 s ahead; the service stops and is started again by its supervisor.
  m.clock = R + 70 * S; await m.start();
  const disk = structuredClone(m.store.disk);
  // R + 15 s: the clock is right again; the service stops again; every start is refused.
  m.clock = R + 15 * S;
  await assert.rejects(m.start(), /run "clock-was-ahead"/);
  // What the README tells the operator to do ("After the clock was wrong", third case). It says the
  // command writes every wait "as a start with the right clock would have written it".
  m.clock = R + 20 * S; await m.command('clock-was-ahead');
  m.clock = R + 25 * S; await m.start();
  m.clock = R + 60 * S;
  const told = await m.ask('host-a', key, { previous: held.payload.lease_id }), view = await m.key(key);
  // What a start with the right clock does write, 46 s later, once the clock has passed the
  // state's last stamp less one skew: host-a's lease still runs, so its tenure goes on.
  const patient = machine(w, { store: memoryStore(disk), at: R + 61 * S });
  await patient.start();
  assert.equal((await patient.ask('host-a', key, { previous: held.payload.lease_id })).status, 'granted');
  // host-a's lease has 180 s left at R + 60 s. After "clock-was-ahead" its next lease is minutes away.
  assert.deepEqual({ after_the_documented_way_out: told.code ?? told.status, next_lease_before_the_held_one_ends: Date.parse(view.first_lease_not_before_utc) < Date.parse(held.payload.expires_utc) }, { after_the_documented_way_out: 'granted', next_lease_before_the_held_one_ends: true },
    `host-a must wait ${view.seconds_until_first_lease} s; its lease ends in ${(Date.parse(held.payload.expires_utc) - m.clock) / 1000} s`);
});

test('FINDING: the time the first state write takes is counted as a change of the clock; with clock_skew_seconds 1 and a slow disk the service stops at once, at every start', async () => {
  const w = world({ settings: { clock_skew_seconds: 1 } }), time = { now: T0 }, inner = memoryStore();
  // One clock for both readings: the wall clock is never set in this test. Writing and syncing a
  // state file takes 1.5 s on this disk.
  const slow = { ...inner, write: async (...parts) => { time.now += 1500; return inner.write(...parts); } };
  const controller = createController({ config: validateConfig(w.config), store: slow, sign: w.sign, now: () => time.now, monotonic: () => time.now - T0 });
  await controller.open();
  time.now += 1 * S;
  assert.doesNotThrow(() => controller.checkWallClock(), 'the wall clock and the elapsed time moved together; nobody set the clock');
});

test('FINDING: more than 32 commands between two requests (a first set-up before any agent runs) and the service stops at its next request: the files it would follow were removed by the store itself', async () => {
  const w = world(), key = w.validatorKeys[0], directory = await mkdtemp(path.join(tmpdir(), 'time-lease-review2-')), m = machine(w, { store: fileStore(directory) });
  await m.start();
  await m.command('approve-release', 'release.json'); await m.command('assign', key, 'host-a');
  // 31 more changes, 33 in all (here: a new token each time; any commands will do). The store
  // keeps the newest 32 files, so file number 2, the first the service would follow, is gone.
  for (let i = 0; i < 31; i++) await m.command('refence', key);
  m.clock += START_WAIT + 400 * S;
  // Nobody touched the state directory but the service and the command line.
  await assert.doesNotReject(m.ask('host-a', key), 'the service stopped at the first request');
});

test('FINDING (inside A1): a recording can still freeze a key when the host\'s clock was set back by less than a skew between two of its requests (design 8.1 and 12: "A recording never freezes a key")', () => {
  const w = world(), key = w.validatorKeys[0];
  let state = assign(approveRelease(emptyState(w.config, T0), w.releases.one), w.config, key, 'host-a', T0), now = T0 + START_WAIT, hostAhead = 4 * S;
  const request = (options) => { const { reply, next } = decide(state, w.config, ask(w, 'host-a', key, { timeMs: now + hostAhead, ...options }), now, w.sign); if (next) state = validateState(next); return reply; };
  const first = request({}).lease.payload;
  // The host's clock is 4 s ahead of true time, which A1 allows. It renews; the answer is lost;
  // it repeats the request every ten seconds, and the third repeat is answered.
  now += 60 * S;
  const nonce = newNonce(), second = request({ previous: first.lease_id, nonce }).lease.payload;
  let recorded;
  for (let i = 0; i < 3; i++) { now += 10 * S; recorded = ask(w, 'host-a', key, { timeMs: now + hostAhead, previous: first.lease_id, nonce }); assert.equal(decide(state, w.config, recorded, now, w.sign).reply.lease.payload.lease_id, second.lease_id); }
  // NTP sets the host's clock back by 8 s: it is now 4 s behind true time, still inside A1. Two
  // seconds later the agent is restarted ("Restarting the agent is harmless") and asks at once.
  hostAhead = -4 * S; now += 2 * S;
  assert.equal(request({ previous: second.lease_id }).status, 'granted');
  // One second later the recorded repeat arrives again. It is dated after the request that was
  // just served, so the new rule lets it through, and it names a lease that is two leases old.
  now += 1 * S;
  const before = JSON.stringify(state), { reply, next } = decide(state, w.config, recorded, now, w.sign);
  assert.notEqual(reply.code, 'FROZEN', reply.message);
  assert.equal(next === null ? before : JSON.stringify(next), before);
});

// ---- Attacks that held -----------------------------------------------------------

test('HELD: "clock-was-ahead" given by mistake on a clock that is BEHIND lets no lease out early, and a corrected clock ends the process that counted on the wrong one', async () => {
  const w = world(), key = w.validatorKeys[0], m = machine(w);
  await m.start(); await m.command('approve-release', 'release.json'); await m.command('assign', key, 'host-a');
  m.clock += START_WAIT + 1 * S;
  const held = (await m.ask('host-a', key)).lease, R = m.clock, expiry = Date.parse(held.payload.expires_utc);
  // The machine reboots. Its clock reads ten minutes behind. The start is refused.
  const behind = 600 * S; m.clock = R + 20 * S - behind;
  await assert.rejects(m.start(), /FIRST check this machine's clock/);
  // The mistake: the operator does not check and runs the command meant for the opposite case.
  const done = await m.command('clock-was-ahead');
  assert.match(JSON.stringify(done.result), /a_lease_dated_by_the_wrong_clock_is_waited_for_until_utc/);
  // A service starts on the wrong clock, with a monotonic clock of its own this time.
  const mono = { now: 0 }, service = createController({ config: m.config, store: m.store, sign: w.sign, now: m.now, monotonic: () => mono.now });
  await service.open();
  await m.command('move', key, 'host-b', '--from', 'host-a');
  const tick = (ms) => { m.clock += ms; mono.now += ms; };
  // host-b with a right clock is refused as long as the controller's clock is wrong; host-b with
  // the same wrong clock waits until that clock has passed the end of host-a's lease plus the margin.
  for (let passed = 20 * S; passed < 900 * S; passed += 10 * S) {
    tick(10 * S);
    const trueTime = m.clock + behind;
    for (const hostClock of [trueTime, m.clock]) {
      const reply = await service.submit(ask(w, 'host-b', key, { timeMs: hostClock }));
      if (reply.status === 'granted') assert.ok(trueTime >= expiry + MARGIN, `granted ${(expiry + MARGIN - trueTime) / 1000} s early`);
    }
  }
  // NTP steps the clock right: the process that counted its waits on the wrong clock stops.
  m.clock += behind;
  await assert.rejects(service.submit(ask(w, 'host-b', key, { timeMs: m.clock })), Fatal);
});

test('HELD: the wall clock is compared with elapsed time before every answer; one skew is tolerated, one millisecond more is not, and a stopped service answers nothing', async () => {
  const w = world(), key = w.validatorKeys[0], wall = { now: T0 }, mono = { now: 5_000_000 }, store = memoryStore();
  const config = validateConfig(w.config), command = (...words) => runCommand(config, words, { store, now: () => wall.now, readManifest: async () => w.releases.one });
  const service = createController({ config, store, sign: w.sign, now: () => wall.now, monotonic: () => mono.now });
  await service.open(); await command('approve-release', 'release.json'); await command('assign', key, 'host-a');
  const tick = (ms) => { wall.now += ms; mono.now += ms; };
  tick(START_WAIT + S);
  const first = (await service.submit(ask(w, 'host-a', key, { timeMs: wall.now }))).lease.payload;
  // Stepped forward by exactly one skew, then back by two: each time one skew from the start.
  tick(SPACING); wall.now += SKEW;
  const second = await service.submit(ask(w, 'host-a', key, { timeMs: wall.now, previous: first.lease_id }));
  assert.equal(second.status, 'granted');
  tick(SPACING + SKEW); wall.now -= 2 * SKEW;
  assert.equal((await service.submit(ask(w, 'host-a', key, { timeMs: wall.now + 3 * SKEW, previous: second.lease.payload.lease_id }))).code, 'CLOCK');
  // One millisecond further back: the service stops before it decides anything, also for a
  // request that would only get the stored lease again, and stays stopped when the clock returns.
  wall.now -= 1;
  const disk = store.disk.length;
  await assert.rejects(service.submit(ask(w, 'host-a', key, { timeMs: wall.now, previous: first.lease_id, nonce: second.lease.payload.request_nonce })), Fatal);
  wall.now += SKEW;
  await assert.rejects(service.submit(ask(w, 'host-a', key, { timeMs: wall.now, previous: second.lease.payload.lease_id })), Fatal);
  assert.throws(() => service.checkWallClock(), Fatal); assert.equal(store.disk.length, disk);
});

test('HELD: two services and the command line on one directory of real files follow each other for 60 changes; a file from another line, under a new number or an old one, stops the service that meets it', async () => {
  const w = world(), key = w.validatorKeys[0], directory = await mkdtemp(path.join(tmpdir(), 'time-lease-review2-')), clock = { now: T0 }, now = () => clock.now;
  const config = validateConfig({ ...w.config, data_directory: directory }), command = (...words) => runCommand(config, words, { now, readManifest: async () => w.releases.one });
  const open = async () => { const service = createController({ config, store: fileStore(directory), sign: w.sign, now }); await service.open(); return service; };
  const one = await open();
  await command('approve-release', 'release.json'); await command('assign', key, 'host-a');
  const two = await open();
  clock.now += START_WAIT + S;
  let previous = '';
  for (let i = 0; i < 20; i++) {
    const reply = await (i % 2 ? one : two).submit(ask(w, 'host-a', key, { timeMs: clock.now, previous }));
    assert.equal(reply.status, 'granted', reply.message); previous = reply.lease.payload.lease_id;
    await command('approve-release', 'release.json', '--again'); await command('assign', w.validatorKeys[1], 'host-c'); await command('unassign', w.validatorKeys[1]);
    clock.now += SPACING;
  }
  // A file made from an older state, written under the next number by another store on the same directory.
  const files = fileStore(directory), newest = await files.read(), older = await files.readAt(newest.seq - 3);
  await files.write(newest.seq + 1, older.state, older.sha256);
  await assert.rejects(one.submit(ask(w, 'host-a', key, { timeMs: clock.now, previous })), (error) => error instanceof Fatal && /was not made from the file before it/.test(error.message));
  await assert.rejects(two.submit(ask(w, 'host-a', key, { timeMs: clock.now, previous })), Fatal);
});

test('HELD: a key that enters the state after a restore takes its token and its wait from the command, above what the lost line of states issued', async () => {
  const w = world(), key = w.validatorKeys[1], m = machine(w);
  await m.start(); await m.command('approve-release', 'release.json');
  const copy = structuredClone(m.store.disk);
  // After the copy: the key is given to host-b long after the start, so nothing waits beyond the
  // five minutes of a new key, and host-b holds a lease whose token is that clock plus five minutes.
  m.clock += 1000 * S; await m.command('assign', key, 'host-b');
  m.clock = Date.parse((await m.key(key)).first_lease_not_before_utc);
  const old = (await m.ask('host-b', key)).lease.payload;
  // The disk is lost; the copy, which does not know the key, is put back on a machine whose
  // clock reads a whole skew earlier, three seconds later.
  const restored = machine(w, { store: memoryStore(copy), at: m.clock + 3 * S - SKEW });
  await restored.start(); restored.clock += 1 * S; await restored.command('assign', key, 'host-c');
  const view = await restored.key(key);
  assert.ok(BigInt(view.fence_token) > BigInt(old.fence_token));
  assert.ok(Date.parse(view.first_lease_not_before_utc) >= Date.parse(old.expires_utc) + 40 * S + SKEW);
});
