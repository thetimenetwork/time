// How the kit's launcher ends a child whose signer lease is no longer valid
// (leaseWatch in deploy/operator.mjs; docs/design/signer-lease-controller.md, 10.2 and 14).
// The rule: the child may run until the expiry of the last lease that verified, and must be
// dead a bounded time after it. The margin of the lease controller is derived from that bound.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { GUARD_KILL_MS, GUARD_PERIOD_MS, guard, leaseWatch } from '../operator.mjs';
import { validateConfig } from './start.mjs';
import { operatorDirectory, world } from './fixtures.mjs';

const S = 1000, BOUND = GUARD_PERIOD_MS + GUARD_KILL_MS;
const valid = (expires) => ({ lease: { expires_utc: new Date(expires).toISOString() } });
const unreadable = () => Object.assign(new Error('EIO: i/o error, open'), { code: 'EIO', syscall: 'open' });
const refusal = () => new Error('Attestation expired or future-dated');

/// A scheduler the test moves (the monotonic clock: timers count on it), a wall clock that can be
/// stepped apart from it, and a child that records the signals it is sent with the time of each.
function bench({ hardKill = true, validUntilMs, onFailure } = {}) {
  const b = { time: 0, step: 0, timers: [], signals: [], failures: [], child: { exitCode: null, signalCode: null, kill(signal) { b.signals.push([b.time, signal]); return true; } } };
  b.wall = () => b.time + b.step;
  b.at = (when, callback) => { b.timers.push({ when, callback }); };
  b.watch = (check) => leaseWatch({
    check, child: b.child, hardKill, validUntilMs, now: b.wall,
    onFailure: onFailure ?? ((error) => { b.failures.push([b.time, error.message]); b.child.kill('SIGTERM'); }),
    every: (callback, ms) => { const tick = (when) => b.at(when, () => { callback(); tick(when + ms); }); tick(b.time + ms); },
    after: (callback, ms) => { b.at(b.time + ms, callback); return { unref() {} }; },
  });
  b.run = async (until) => {
    for (;;) {
      const due = b.timers.filter((timer) => timer.when <= until).sort((x, y) => x.when - y.when)[0];
      if (!due) break;
      b.timers.splice(b.timers.indexOf(due), 1); b.time = Math.max(b.time, due.when); due.callback();
      for (let i = 0; i < 20; i++) await null;
    }
    b.time = until;
  };
  /// A check like guard(): it takes `duration` (null: for ever) and then judges the lease that
  /// ends at `expires` against the wall clock as it reads THEN. Past the expiry it does `after`.
  b.check = (duration, expires, after) => () => new Promise((resolve, reject) => {
    if (duration === null) return;
    b.at(b.time + duration, () => { if (b.wall() < expires) resolve(valid(expires)); else if (after === 'refuse') reject(refusal()); else if (after === 'unreadable') reject(unreadable()); });
  });
  b.sent = (signal) => b.signals.filter(([, name]) => name === signal).map(([time]) => time);
  return b;
}

test('the numbers: five seconds between checks, ten to the kill, and a stop time in the controller config of at least twice their sum', () => {
  assert.deepEqual([GUARD_PERIOD_MS, GUARD_KILL_MS, BOUND], [5000, 10000, 15000]);
  const w = world(), base = { data_directory: w.config.data_directory, authority_key_file: w.config.authority_key_file, fence_domain: 'd', network: w.config.network, hosts: w.config.hosts };
  assert.throws(() => validateConfig({ ...base, stop_seconds: 29 }), /stop_seconds is a whole number from 30/);
  assert.ok(validateConfig({ ...base, stop_seconds: 30 }).stop_seconds * S >= 2 * BOUND);
});

test('the bound: SIGTERM within five seconds and SIGKILL within fifteen of the expiry of the last lease that verified, for checks of every duration and whatever they do afterwards', async () => {
  // The lease ends 1 ms before a check, at a check, 1 ms after one, and between two.
  for (const expires of [100 * S - 1, 100 * S, 100 * S + 1, 102 * S + 500]) {
    for (const duration of [0, 1, 2500, 4999, 5000, 5001, 9900, 12 * S, 30 * S, 45 * S, null]) {
      for (const after of ['refuse', 'hang', 'unreadable']) {
        const b = bench({ validUntilMs: expires }), name = JSON.stringify({ expires, duration, after });
        b.watch(b.check(duration, expires, after));
        await b.run(expires - 1);
        assert.deepEqual(b.signals, [], name + ': nothing is sent while the lease runs');
        await b.run(expires + 100 * S);
        const [term] = b.sent('SIGTERM'), [kill] = b.sent('SIGKILL');
        assert.ok(term >= expires && term - expires < GUARD_PERIOD_MS, name + ': SIGTERM ' + (term - expires) + ' ms after the expiry');
        assert.equal(kill, term + GUARD_KILL_MS, name + ': SIGKILL exactly the grace after SIGTERM');
        assert.ok(kill - expires < BOUND, name);
        assert.deepEqual([b.signals.length, b.failures.length], [2, 1], name + ': each once');
      }
    }
  }
});

test('a renewed lease keeps the child running; the stop comes within the bound of the LAST lease that verified, also when the checks are slow and overlap', async () => {
  for (const duration of [0, 4 * S, 9 * S, 31 * S]) {
    // An agent installs a lease of 240 s every 60 s until 600 s. A check that returns reports the
    // lease that was in the file when it looked.
    const b = bench({ validUntilMs: 240 * S }), newest = () => Math.min(Math.floor(b.wall() / (60 * S)), 10) * 60 * S + 240 * S;
    b.watch(() => new Promise((resolve, reject) => b.at(b.time + duration, () => (b.wall() < newest() ? resolve(valid(newest())) : reject(refusal())))));
    const last = 600 * S + 240 * S;
    await b.run(last - 1);
    assert.deepEqual(b.signals, [], 'duration ' + duration);
    await b.run(last + 100 * S);
    assert.ok(b.sent('SIGTERM')[0] - last < GUARD_PERIOD_MS && b.sent('SIGKILL')[0] - last < BOUND, 'duration ' + duration);
  }
  // A slow check that verified a lease which ended while it ran moves nothing.
  const b = bench({ validUntilMs: 100 * S });
  b.watch(() => new Promise((resolve) => b.at(b.time + 9900, () => resolve(valid(100 * S)))));
  await b.run(300 * S);
  assert.deepEqual([b.sent('SIGTERM')[0], b.sent('SIGKILL')[0]], [100 * S, 110 * S]);
  // An older lease read after a newer one does not shorten what the newer one allowed.
  const c = bench({ validUntilMs: 100 * S }); let calls = 0;
  c.watch(() => Promise.resolve(valid(++calls === 1 ? 340 * S : 100 * S)));
  await c.run(339 * S); assert.deepEqual(c.signals, []);
  await c.run(400 * S); assert.equal(c.sent('SIGTERM')[0], 340 * S);
});

test('nothing but the end of the lease or a refusal stops a child: not a clock that is stepped, a launcher that did not run, checks that do not return, or files that cannot be read', async () => {
  const renewing = (b) => () => Promise.resolve(valid(b.wall() + 180 * S));
  // The wall clock is stepped forward by 13 s, and back by 10 s.
  for (const step of [13 * S, -10 * S]) { const b = bench(); b.watch(renewing(b)); await b.run(100 * S); b.step += step; await b.run(400 * S); assert.deepEqual(b.signals, [], 'step ' + step); }
  // The launcher, or the whole machine, does not run for 13 s and for 100 s: its timers fire late.
  for (const pause of [13 * S, 100 * S]) { const b = bench(); b.watch(renewing(b)); await b.run(100 * S); b.timers.forEach((timer) => { timer.when += pause; }); b.time += pause; await b.run(400 * S); assert.deepEqual(b.signals, [], 'pause ' + pause); }
  // The operator directory does not answer for 16 s, or gives errors for 100 s, while the lease has minutes left.
  const stalled = bench(); stalled.watch(() => (stalled.time >= 100 * S && stalled.time < 116 * S ? new Promise((resolve) => stalled.at(116 * S, () => resolve(valid(stalled.wall() + 180 * S)))) : Promise.resolve(valid(stalled.wall() + 180 * S))));
  await stalled.run(400 * S); assert.deepEqual(stalled.signals, []);
  const failing = bench(); failing.watch(() => (failing.time >= 100 * S && failing.time < 200 * S ? Promise.reject(Object.assign(new Error('ENOENT: no such file'), { code: 'ENOENT', syscall: 'lstat' })) : Promise.resolve(valid(failing.wall() + 180 * S))));
  await failing.run(400 * S); assert.deepEqual(failing.signals, []);
  // But a lease that cannot be read is not thereby extended: errors that last past its end stop the child, within the bound.
  const gone = bench(); let ends = 0;
  gone.watch(() => (gone.time < 100 * S ? Promise.resolve(valid(ends = gone.wall() + 180 * S)) : Promise.reject(unreadable())));
  await gone.run(600 * S);
  assert.equal(ends, 275 * S); assert.deepEqual([gone.sent('SIGTERM')[0], gone.sent('SIGKILL')[0]], [275 * S, 285 * S]);
  // And a clock stepped forward PAST the end of the lease does stop it: the lease has ended on that clock.
  const jumped = bench({ validUntilMs: 240 * S }); jumped.watch(() => new Promise(() => {}));
  await jumped.run(100 * S); jumped.step += 200 * S; await jumped.run(200 * S);
  assert.deepEqual(jumped.sent('SIGTERM'), [105 * S]);
});

test('a check that refuses what it read stops the child at once, although the last lease that verified has minutes left', async () => {
  // The authority was removed from the trust file, or the settings were changed: a definite refusal.
  for (const message of ['Attestation authority/role is not independently pinned', 'Attestation scope mismatch: release_id', 'Invalid signed attestation', 'Expected bounded regular JSON file', 'Unexpected end of JSON input']) {
    const b = bench({ validUntilMs: 340 * S });
    b.watch(() => (b.time < 100 * S ? Promise.resolve(valid(340 * S)) : Promise.reject(new Error(message))));
    await b.run(300 * S);
    assert.deepEqual(b.signals, [[100 * S, 'SIGTERM'], [110 * S, 'SIGKILL']], message); assert.deepEqual(b.failures, [[100 * S, message]]);
  }
  // Only an error of the file system is "could not read". Any other error that happens to carry a code is a refusal.
  for (const error of [Object.assign(new Error('invalid'), { code: 'ERR_INVALID_ARG_TYPE' }), Object.assign(new Error('odd'), { code: 'EIO' }), Object.assign(new Error('odd'), { syscall: 'open' })]) {
    const b = bench({ validUntilMs: 340 * S });
    b.watch(() => (b.time < 100 * S ? Promise.resolve(valid(340 * S)) : Promise.reject(error)));
    await b.run(300 * S);
    assert.deepEqual(b.signals, [[100 * S, 'SIGTERM'], [110 * S, 'SIGKILL']], String(error.code ?? error.syscall));
  }
  // A check that says "valid" without naming the lease is no verification: it counts as a refusal.
  const silent = bench({ validUntilMs: 340 * S }); silent.watch(() => Promise.resolve());
  await silent.run(60 * S); assert.match(silent.failures[0][1], /named no expiry/); assert.equal(silent.sent('SIGTERM')[0], 5 * S);
  // The node (app) child is sent SIGTERM only, so that it can write its final snapshot. A consensus child that stopped is not killed.
  const node = bench({ hardKill: false, validUntilMs: 100 * S }); node.watch(() => new Promise(() => {}));
  await node.run(300 * S); assert.deepEqual(node.signals, [[100 * S, 'SIGTERM']]);
  for (const ended of [{ exitCode: 0 }, { signalCode: 'SIGTERM' }]) {
    const b = bench({ validUntilMs: 100 * S }); b.watch(() => new Promise(() => {}));
    await b.run(101 * S); Object.assign(b.child, ended); await b.run(300 * S);
    assert.deepEqual(b.signals, [[100 * S, 'SIGTERM']]);
  }
});

test('the kill is armed before the callback that reports the failure, so a callback that throws cannot keep it from coming', async () => {
  const b = bench({ validUntilMs: 100 * S, onFailure: () => { throw new Error('the launcher could not report the failure'); } });
  b.watch(() => new Promise(() => {}));
  // The callback's error does not escape the timer either: an uncaught error would end the
  // launcher, and its kill timer with it.
  await b.run(300 * S);
  assert.deepEqual(b.signals, [[110 * S, 'SIGKILL']]);
});

test('the real guard reports the lease it verified, judged against the clock when it has read its files', async () => {
  const w = world(), key = w.validatorKeys[0], host = await operatorDirectory(w, 'host-a', key), now = Date.now();
  const lease = w.sign({ kind: 'signer_lease', release_id: w.releases.one.release_id, genesis_sha256: w.config.network.genesis_sha256, chain_id: w.chainId, validator_public_key_hex: key, signer_identity: 'signer-of-host-a', engine: 'v5', enforcement: 'EVERY_SIGNATURE', fence_domain: 'test-domain', fence_token: '1', lease_id: 'one', issued_utc: new Date(now - 60 * S).toISOString(), expires_utc: new Date(now + 120 * S).toISOString() });
  await writeFile(host.settings.signer_lease_file, JSON.stringify(lease));
  // What leaseWatch reads from a check: the expiry of the lease that verified.
  assert.equal((await guard(host.settings)).lease.expires_utc, lease.payload.expires_utc);
  assert.equal((await guard(host.settings, now + 119 * S)).lease.lease_id, 'one');
  await assert.rejects(guard(host.settings, now + 120 * S), /expired or future-dated/);
  // An error of the file system carries the system call it failed in; a refusal does not.
  const missing = await guard({ ...host.settings, signer_lease_file: host.settings.signer_lease_file + '.missing' }).catch((error) => error);
  assert.deepEqual([missing.code, typeof missing.syscall], ['ENOENT', 'string']);
  const refused = await guard(host.settings, now + 121 * S).catch((error) => error);
  assert.deepEqual([refused.code, refused.syscall], [undefined, undefined]);
});

test('the launcher uses this watch for both children, seeds it with the lease it verified before the start, and kills only the consensus child', async () => {
  const source = await readFile(new URL('../operator.mjs', import.meta.url), 'utf8'), body = source.slice(source.indexOf('async function run('));
  assert.ok(body.includes("leaseWatch({check:()=>guard(settings),child,hardKill:kind==='comet',validUntilMs:Date.parse(startLease.expires_utc),onFailure:error=>{guardFailure=error;stop();}})"));
  // The lease is verified again immediately before the child is started: nothing lies between that check and spawn but a look at a stop signal.
  assert.ok(body.includes("const{lease:startLease}=await guard(settings);if(stopping)return;child=spawn(executable,args,{stdio:'inherit'});"));
  assert.ok(!/setInterval\(\(\)=>guard\(/.test(source), 'no second, older timer');
  assert.ok(body.indexOf('await guard(') < body.indexOf('spawn(') && body.indexOf('spawn(') < body.indexOf('leaseWatch('), 'the first check still comes before the child exists');
  // No rule of the watch measures an interval between two readings of the wall clock.
  const watch = source.slice(source.indexOf('export function leaseWatch('), source.indexOf('async function run('));
  assert.deepEqual(watch.match(/[a-zA-Z=(-]*now\(\)[^;]*/g).map((use) => use.replace(/\s/g, '')), ['left=expires-now()', 'if(now()>=validUntil)stop(ended())'], 'the wall clock is read to compare it with an expiry and to take a lease\'s remaining life from an expiry; never twice to measure an interval');
  assert.ok(watch.indexOf("after(()=>{") > 0 && watch.indexOf("after(()=>{") < watch.indexOf('onFailure(error)'), 'the kill timer is armed before the callback');
});

test('a lease counts on two clocks: a wall clock set back after it verified does not lengthen it, and a lease that has ended when the watch is created stops the child at once', async () => {
  // The lease ends at 300 s. At 200 s the host's clock is set back by 60 s (second review, N2).
  for (const mode of ['refuse', 'hang', 'unreadable']) {
    const b = bench({ validUntilMs: 300 * S });
    b.watch(b.check(0, 300 * S, mode));
    await b.run(200 * S); b.step -= 60 * S; await b.run(600 * S);
    // In true time (the scheduler's) the lease ended at 300 s: stopped then, not 60 s later.
    assert.deepEqual([b.sent('SIGTERM')[0], b.sent('SIGKILL')[0]], [300 * S, 310 * S], mode);
  }
  // A lease that is verified again after the clock was set back keeps its first deadline; a
  // newer lease gets a deadline of its own, counted from the moment it verified.
  const renewed = bench({ validUntilMs: 300 * S });
  renewed.watch(() => Promise.resolve(valid(renewed.time < 250 * S ? 300 * S : 540 * S)));
  await renewed.run(200 * S); renewed.step -= 60 * S; await renewed.run(299 * S);
  assert.deepEqual(renewed.signals, []);
  // The newer lease verified at 250 s, when the stepped clock read 190 s: 350 s of life, so 600 s.
  await renewed.run(599 * S); assert.deepEqual(renewed.signals, []);
  await renewed.run(700 * S); assert.equal(renewed.sent('SIGTERM')[0], 600 * S);
  // Set forward, the wall clock reaches the expiry first: that deadline counts.
  const forward = bench({ validUntilMs: 300 * S }); forward.watch(() => new Promise(() => {}));
  await forward.run(100 * S); forward.step += 100 * S; await forward.run(600 * S);
  assert.equal(forward.sent('SIGTERM')[0], 200 * S);
  // The lease ended while the launcher prepared the start (N7): no wait for the first check.
  for (const late of [0, 1, 2 * S]) {
    const b = bench({ validUntilMs: 100 * S });
    await b.run(100 * S + late); b.watch(() => new Promise(() => {})); await b.run(300 * S);
    assert.deepEqual(b.signals, [[100 * S + late, 'SIGTERM'], [110 * S + late, 'SIGKILL']], 'late by ' + late);
  }
  // What is not seen, and is stated: a clock that was set back BEFORE the lease first verified.
  const blind = bench(); blind.step = -60 * S;
  blind.watch(() => Promise.resolve(valid(300 * S)));
  await blind.run(1000 * S);
  assert.equal(blind.sent('SIGTERM')[0], 360 * S, 'the lease is counted from the wrong clock it first verified on');
});

test('a real process that ignores SIGTERM is gone after the kill', { skip: process.platform === 'win32' ? 'Windows ends a process on any signal: nothing can ignore SIGTERM there' : false }, async () => {
  const child = spawn(process.execPath, ['-e', 'process.on("SIGTERM", () => {}); console.log("ready"); setInterval(() => {}, 1000);'], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((resolve) => child.stdout.once('data', resolve));
  const exit = new Promise((resolve) => child.once('exit', (code, signal) => resolve(signal)));
  // The watch itself, with its times divided by one hundred, and a lease that has ended.
  const timer = leaseWatch({ check: () => Promise.reject(refusal()), child, hardKill: true, validUntilMs: Date.now() - 1, onFailure: () => child.kill('SIGTERM'), every: (callback, ms) => setInterval(callback, ms / 100), after: (callback, ms) => setTimeout(callback, ms / 100) });
  try { assert.equal(await exit, 'SIGKILL'); } finally { clearInterval(timer); }
});
