// Independent review of the change to the guard (leaseWatch in deploy/operator.mjs): does a
// validator stop within the time the controller's margin assumes, and can the change stop a
// healthy one?
//
// FINDING tests fail against the code under review: the failure is the finding. HELD tests pass.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, rm, writeFile } from 'node:fs/promises';
// ADAPTED: this import also named GUARD_STALE_MS, which the corrected watch no longer has (see STATED_BOUND below).
import { GUARD_KILL_MS, GUARD_PERIOD_MS, guard, leaseWatch } from '../operator.mjs';
import { sha256 } from '../lib.mjs';
import { approveRelease, assign, decide, emptyState } from './core.mjs';
import { ask, operatorDirectory, world } from './fixtures.mjs';

// ADAPTED: STATED_BOUND was GUARD_PERIOD_MS + GUARD_STALE_MS + GUARD_KILL_MS = 27 s, the bound the
// design stated for the watch under review. The corrected watch has no staleness rule (and no
// GUARD_STALE_MS): the child runs until the expiry of the last lease that verified. The bound the
// design states now is GUARD_PERIOD_MS + GUARD_KILL_MS = 15 s after that expiry. Every assertion
// below that names STATED_BOUND is therefore stricter than it was.
const S = 1000, STATED_BOUND = GUARD_PERIOD_MS + GUARD_KILL_MS;

/// A scheduler the test moves, a wall clock that can be stepped apart from it, and a child that
/// records the signals it is sent. `check` is built by the test.
function bench() {
  const b = { time: 0, step: 0, timers: [], signals: [], failures: [], child: { exitCode: null, signalCode: null, kill(signal) { b.signals.push([b.time, signal]); return true; } } };
  b.wall = () => b.time + b.step;
  b.at = (when, callback) => { b.timers.push({ when, callback }); };
  b.watch = (check, hardKill = true) => leaseWatch({
    check, child: b.child, hardKill, now: b.wall, onFailure: (error) => { b.failures.push([b.time, error.message]); b.child.kill('SIGTERM'); },
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
  /// A check like guard(): it reads the clock when it is CALLED (guard's default parameter
  /// `now=Date.now()`), takes `duration()` to read its files, and then judges the lease against
  /// the clock value it read at the start.
  // ADAPTED (here and in every check below that answers "valid"): the checks of this bench
  // resolved with nothing. The corrected watch asks which lease verified, as guard() tells it
  // (`{lease: {expires_utc}}`), because the rule it enforces is "run until the expiry of the last
  // lease that verified". `b.valid(expiry)` is that answer. What each test asserts is unchanged.
  b.valid = (expires) => ({ lease: { expires_utc: new Date(expires).toISOString() } });
  b.guardLike = (duration, leaseEnds) => () => new Promise((resolve, reject) => {
    const began = b.wall();
    b.at(b.time + duration(), () => (began < leaseEnds() ? resolve(b.valid(leaseEnds())) : reject(new Error('Attestation expired or future-dated'))));
  });
  return b;
}

test('FINDING: the real guard judges a lease against the clock it read when it was called; a check that is slow answers "valid" after the lease has ended', async () => {
  // A genesis large enough that hashing and parsing it takes far longer than the lease has left.
  const w = world(), key = w.validatorKeys[0];
  w.genesisText = JSON.stringify({ ...JSON.parse(w.genesisText), padding: 'x'.repeat(96 * 1024 * 1024) });
  w.config.network.genesis_sha256 = sha256(Buffer.from(w.genesisText));
  const host = await operatorDirectory(w, 'host-a', key);
  try {
    const sign = (expires) => w.sign({ kind: 'signer_lease', release_id: w.releases.one.release_id, genesis_sha256: w.config.network.genesis_sha256, chain_id: w.chainId, validator_public_key_hex: key, signer_identity: 'signer-of-host-a', engine: 'v5', enforcement: 'EVERY_SIGNATURE', fence_domain: 'test-domain', fence_token: '1', lease_id: 'review', issued_utc: new Date(Date.now() - 60 * S).toISOString(), expires_utc: new Date(expires).toISOString() });
    // The lease has 25 ms left when the check starts.
    const expires = Date.now() + 25;
    await writeFile(host.settings.signer_lease_file, JSON.stringify(sign(expires)));
    let verdict = 'refused';
    try { await guard(host.settings); verdict = 'accepted'; } catch { /* refused */ }
    const late = Date.now() - expires;
    assert.ok(late > 0, 'the check must have outlasted the lease for this test to say anything');
    assert.equal(verdict, 'refused', `guard() answered "valid" ${late} ms after the lease had ended`);
  } finally { await rm(host.directory, { recursive: true, force: true }); }
});

test('FINDING: checks that are slow but return never count as "stale", so CometBFT is killed long after the 27 s the design derives stop_seconds from', async () => {
  // The host's disk degrades: each check takes two seconds longer than the one before, up to 45 s.
  // Checks overlap (one starts every five seconds), one finishes every five to seven seconds, and
  // "has not succeeded for 12 s" is never true, although no check has LOOKED at the clock for 45 s.
  const b = bench(), ends = 400 * S + 1;
  let started = 0;
  b.watch(b.guardLike(() => Math.min(45 * S, 2 * S * started++), () => ends));
  await b.run(ends - 1);
  assert.deepEqual(b.failures, [], 'nothing fails while the lease runs');
  await b.run(ends + 200 * S);
  const killed = b.signals.find(([, signal]) => signal === 'SIGKILL')?.[0] ?? Infinity, term = b.signals.find(([, signal]) => signal === 'SIGTERM')?.[0] ?? Infinity;
  // Design, section 14: "CometBFT has been sent SIGKILL at most 27 s after its lease ended on the
  // host's clock, plus the time one check takes ... That is why stop_seconds may not be set below 30."
  // With the defaults the next holder's first lease can be live 50 s (skew + stop_seconds) after
  // this one ended; with the smallest config (skew 1 s, stop 30 s) 31 s after.
  assert.ok(killed - ends <= STATED_BOUND, `SIGTERM came ${(term - ends) / 1000} s and SIGKILL ${(killed - ends) / 1000} s after the lease ended`);
});

test('FINDING: one check that returns late, followed by a file system that stops answering, moves the kill from 27 s to 35 s after the lease ended', async () => {
  const b = bench(), ends = 100 * S + 1;
  // Every check is instant, except the one that starts 1 ms before the lease ends: it takes 9.9 s
  // and says "valid" (it read the clock at its start). Every later check never returns.
  // ADAPTED: the two checks that answer "valid" resolved with nothing; they now report the lease that ends at `ends`.
  b.watch(() => { const began = b.wall(); if (began < 100 * S) return Promise.resolve(b.valid(ends)); if (began < ends) return new Promise((resolve) => b.at(b.time + 9900, () => resolve(b.valid(ends)))); return new Promise(() => {}); });
  await b.run(300 * S);
  const killed = b.signals.find(([, signal]) => signal === 'SIGKILL')?.[0] ?? Infinity;
  assert.ok(killed - ends <= STATED_BOUND, `SIGKILL came ${(killed - ends) / 1000} s after the lease ended`);
});

test('FINDING (false stop): a wall clock stepped forward by 13 s, or a launcher frozen for 13 s, stops a validator whose lease has minutes left and whose every check succeeds', async () => {
  // The staleness rule compares Date.now() values. Before this change a step forward stopped
  // nothing unless it passed the lease's end. Nothing restarts by itself, so the same step on
  // many hosts (one bad time source corrected at once) stops them all.
  const stepped = bench();
  // ADAPTED: each check reports a lease with three minutes left, as the comment below describes it.
  stepped.watch(() => Promise.resolve(stepped.valid(stepped.wall() + 180 * S)));
  await stepped.run(100 * S);
  stepped.step += 13 * S; // NTP steps the clock; the lease, issued for 240 s, has about three minutes left
  await stepped.run(160 * S);
  // The same for a process (or a whole virtual machine) that does not run for 13 s: a live
  // migration, a snapshot freeze, a debugger. Its timers fire late, the clock has moved on.
  const frozen = bench();
  // ADAPTED: as above, each check reports a lease with three minutes left.
  frozen.watch(() => Promise.resolve(frozen.valid(frozen.wall() + 180 * S)));
  await frozen.run(100 * S);
  frozen.timers.forEach((timer) => { timer.when += 13 * S; }); frozen.time += 13 * S;
  await frozen.run(160 * S);
  assert.deepEqual({ after_a_step: stepped.signals, after_a_freeze: frozen.signals }, { after_a_step: [], after_a_freeze: [] });
});

test('FINDING (false stop): an operator directory that does not answer for 16 s and then recovers stops the validator, although the lease it could not re-read has minutes left', async () => {
  // Before the change such a stall stopped nothing: the checks returned late and passed.
  const b = bench();
  // ADAPTED: each check that returns reports a lease with three minutes left ("has minutes left").
  b.watch(() => (b.time >= 100 * S && b.time < 116 * S ? new Promise((resolve) => b.at(116 * S, () => resolve(b.valid(b.wall() + 180 * S)))) : Promise.resolve(b.valid(b.wall() + 180 * S))));
  await b.run(300 * S);
  assert.deepEqual(b.signals, [], 'the lease was valid throughout; the validator was stopped and must be started by hand');
});

test('HELD: a check that fails or never returns leads to SIGTERM and, for the consensus child, SIGKILL, inside the stated bound when checks are instant', async () => {
  for (const mode of ['fails', 'hangs']) {
    const b = bench(), ends = 100 * S + 1;
    // ADAPTED: the check that answers "valid" resolved with nothing; it now reports the lease that ends at `ends`.
    b.watch(() => (b.wall() < ends ? Promise.resolve(b.valid(ends)) : mode === 'fails' ? Promise.reject(new Error('Attestation expired or future-dated')) : new Promise(() => {})));
    await b.run(300 * S);
    assert.deepEqual(b.signals.map(([, signal]) => signal), ['SIGTERM', 'SIGKILL'], mode);
    assert.ok(b.signals[1][0] - ends <= STATED_BOUND, mode + ': ' + (b.signals[1][0] - ends));
    assert.equal(b.failures.length, 1);
  }
  // Inside A1 a clock may step back by a whole skew. With checks that hang, the staleness rule
  // then fires later by that much: 27 s + skew. The margin's spare skew covers it.
  // ADAPTED: there is no staleness rule now. What stays true, and is asserted unchanged below, is
  // that a wall clock set back by a skew moves the stop later by that much: the lease's expiry is
  // a time on that clock, so the bound becomes 15 s + skew.
  const b = bench(), ends = 100 * S + 1;
  b.watch(() => (b.time < ends ? Promise.resolve(b.valid(ends)) : new Promise(() => {})));
  await b.run(ends); b.step -= 10 * S; await b.run(300 * S);
  // ADAPTED (second review, N2): this line asserted `<= STATED_BOUND + 10 s && > STATED_BOUND`: that a
  // wall clock set back by a skew moves the stop LATER by that much. The second review calls that a
  // fault (a host clock set back keeps a validator running past its lease). A verified lease now also
  // ends when its remaining life has passed on the monotonic clock, so the step back delays nothing:
  // the kill comes inside the stated bound.
  assert.ok(b.signals.at(-1)[0] - ends <= STATED_BOUND);
});

test('HELD: the real guard refuses a lease file that is a directory, empty, cut off, not an object, too large, expired, or not yet valid', async () => {
  const w = world(), key = w.validatorKeys[0], T0 = Date.parse('2026-12-01T00:00:00.000Z');
  let state = assign(approveRelease(emptyState(w.config, T0), w.releases.one), w.config, key, 'host-a', T0);
  const now = T0 + 360 * S, lease = decide(state, w.config, ask(w, 'host-a', key, { timeMs: now }), now, w.sign).reply.lease;
  const host = await operatorDirectory(w, 'host-a', key), file = host.settings.signer_lease_file, text = JSON.stringify(lease);
  await writeFile(file, text);
  assert.equal((await guard(host.settings, now)).lease.lease_id, lease.payload.lease_id);
  await assert.rejects(guard(host.settings, now + 240 * S), /expired or future-dated/);
  await assert.rejects(guard(host.settings, now - 20 * S - 1), /expired or future-dated/);
  for (const content of ['', text.slice(0, text.length / 2), 'null', '[]', '"lease"', JSON.stringify({ ...lease, signature: undefined }), text + ' '.repeat(4 * 1024 * 1024)]) { await writeFile(file, content); await assert.rejects(guard(host.settings, now)); }
  await rm(file); await assert.rejects(guard(host.settings, now), /ENOENT/);
  await mkdir(file); await assert.rejects(guard(host.settings, now), /Expected bounded regular JSON file/);
});
