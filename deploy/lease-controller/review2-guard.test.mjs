// Second independent review: the rewritten guard watch (leaseWatch in deploy/operator.mjs).
// The rule it must enforce (design 14.1): a child may run until the expiry of the last lease that
// verified and must be dead a bounded time after it; only a refusal of a file that was read stops
// it early; a hanging or unreadable check is not a refusal.
//
// FINDING tests fail against the code under review: the failure is the finding. HELD tests pass.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { GUARD_KILL_MS, GUARD_PERIOD_MS, guard, leaseWatch } from '../operator.mjs';
import { approveRelease, assign, decide, emptyState } from './core.mjs';
import { ask, manifest, operatorDirectory, random, world } from './fixtures.mjs';

const S = 1000, HALF_SKEW = 5 * S;
const valid = (expires) => ({ lease: { expires_utc: new Date(expires).toISOString() } });
const fsError = () => Object.assign(new Error('EIO: i/o error, read'), { code: 'EIO', syscall: 'read' });

/// A scheduler the test moves (true time, and the clock timers count on), a wall clock that can
/// be stepped apart from it, and a child that records each signal with the true time and the
/// wall clock's reading.
function bench({ validUntilMs, hardKill = true } = {}) {
  const b = { time: 0, step: 0, timers: [], signals: [], refusals: [], child: { exitCode: null, signalCode: null, kill(signal) { b.signals.push({ signal, time: b.time, wall: b.wall() }); return true; } } };
  b.wall = () => b.time + b.step;
  b.at = (when, callback) => { b.timers.push({ when, callback }); };
  b.watch = (check) => leaseWatch({
    check, child: b.child, hardKill, validUntilMs, now: b.wall, onFailure: () => { b.child.kill('SIGTERM'); },
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
  b.first = (signal) => b.signals.find((item) => item.signal === signal);
  return b;
}

// ---- Findings --------------------------------------------------------------------

test('FINDING (outside A1): a wall clock set back by 60 s lets the validator run 60 s past its lease in true time; the watch counts no deadline on the monotonic clock, and the margin\'s spare is 35 s', async () => {
  // The old holder's last lease ends at 300 s. The key was moved, so no newer lease comes, and
  // the lease in the file is minutes old: the guard does not find it "future-dated" either.
  const b = bench({ validUntilMs: 300 * S });
  b.watch(() => (b.wall() < 300 * S ? Promise.resolve(valid(300 * S)) : Promise.reject(new Error('Attestation expired or future-dated'))));
  await b.run(200 * S);
  b.step -= 60 * S; // the host's clock is set back; nothing on the host notices
  await b.run(600 * S);
  const term = b.first('SIGTERM'), kill = b.first('SIGKILL');
  // In true time the lease ended at 300 s. Design 14.1: SIGKILL "before E + skew/2 + 15 s" in true
  // time, and the next holder's first lease can be live skew + stop_seconds = 50 s after E.
  // A deadline counted on the monotonic clock from the moment the lease verified (remaining life
  // then, plus nothing) would have ended the child at 300 s whatever the wall clock did.
  assert.ok(kill.time <= 300 * S + HALF_SKEW + GUARD_PERIOD_MS + GUARD_KILL_MS, `SIGTERM at true time ${term.time / 1000} s and SIGKILL at ${kill.time / 1000} s; the lease ended at 300 s`);
});

test('FINDING (low): a lease that ended while the launcher prepared the start is noticed only at the first tick; the bound "told to stop less than 5 s after the expiry" is passed by the time the set-up took', async () => {
  // run() verifies the lease, then makes directories, takes the lock, checks the volumes and
  // writes CometBFT's home, then starts the child and the watch. Here that took 3 s on a slow
  // volume and the lease, which had 1 s left when it verified, ended 2 s before the child started.
  const b = bench({ validUntilMs: 100 * S });
  await b.run(102 * S);
  b.watch(() => Promise.reject(new Error('Attestation expired or future-dated'))); // run() does this right after spawn()
  await b.run(200 * S);
  const term = b.first('SIGTERM'), kill = b.first('SIGKILL');
  assert.ok(term.wall - 100 * S < GUARD_PERIOD_MS && kill.wall - 100 * S < GUARD_PERIOD_MS + GUARD_KILL_MS, `the child, started after its lease had ended, got SIGTERM ${(term.wall - 100 * S) / 1000} s and SIGKILL ${(kill.wall - 100 * S) / 1000} s after the expiry`);
});

test('FINDING (document): design 14.1 says a clock that is stepped "stops nothing as long as the lease has not ended"; a clock set back by more than the lease\'s age plus two skews stops the child at once, because the real guard then refuses the lease as future-dated', async () => {
  const w = world(), key = w.validatorKeys[0], T0 = Date.parse('2026-12-01T00:00:00.000Z');
  const state = assign(approveRelease(emptyState(w.config, T0), w.releases.one), w.config, key, 'host-a', T0), issuedAt = T0 + 360 * S;
  const lease = decide(state, w.config, ask(w, 'host-a', key, { timeMs: issuedAt }), issuedAt, w.sign).reply.lease;
  const host = await operatorDirectory(w, 'host-a', key);
  await writeFile(host.settings.signer_lease_file, JSON.stringify(lease));
  try {
    // The watch with the real guard as its check, on the bench's wall clock. The lease is 30 s old.
    const b = bench({ validUntilMs: Date.parse(lease.payload.expires_utc) });
    b.time = issuedAt + 30 * S;
    b.watch(() => guard(host.settings, b.wall()));
    const settle = async (ms) => { const end = b.time + ms; while (b.time < end) { await b.run(Math.min(end, b.time + S)); await new Promise((resolve) => setTimeout(resolve, 20)); } };
    await settle(20 * S);
    assert.deepEqual(b.signals, []);
    b.step -= 90 * S; // set back by more than the lease's age (50 s) plus the back-dating (20 s)
    await settle(15 * S);
    // Stopping here is the safe thing to do. The sentence in the design is what is wrong.
    // ADAPTED: this line asserted that NOTHING was sent (`b.signals` empty), which is what the
    // wrong sentence in design 14.1 promised. The code was right and is unchanged in this; the
    // sentence was corrected. The test now asserts the safe behaviour (the child is told to stop
    // within one check of the step back) and that the design says that and no longer the other.
    assert.equal(b.signals[0]?.signal, 'SIGTERM', `the lease is dated in the future on the host's clock (${(Date.parse(lease.payload.issued_utc) - b.wall()) / 1000} s ahead): the guard refuses it and the child must be stopped`);
    assert.ok(b.signals[0].time - (issuedAt + 50 * S) <= GUARD_PERIOD_MS, 'at the first check after the step back');
    const design = await readFile(new URL('../../docs/design/signer-lease-controller.md', import.meta.url), 'utf8');
    assert.ok(!design.includes('stops nothing as long as the lease has not ended'), 'the wrong sentence is gone');
    assert.match(design, /set back by more than the lease's age plus two skews[^.]*stops the child at once/);
  } finally { await rm(host.directory, { recursive: true, force: true }); }
});

// ---- Attacks that held -----------------------------------------------------------

test('HELD: 400 random schedules of checks (instant, slow, overlapping, hanging, unreadable), renewals that stop at some moment, and a wall clock that is stepped inside A1: nothing is sent while a verified lease runs, and SIGTERM comes within 5 s, SIGKILL exactly 10 s later', async () => {
  const STEP = 100; // every event of a schedule falls on a multiple of 100 ms
  for (let seed = 1; seed <= 400; seed++) {
    const r = random(seed), first = r.int(20, 240) * S, b = bench({ validUntilMs: first });
    // The lease file: an agent installs a lease of 240 s every 60 s (wall clock) until `lastRenewal`.
    const lastRenewal = r.int(0, 8) * 60 * S, file = { issued: -20 * S, expires: first };
    const renew = (at) => { if (at > lastRenewal) return; b.at(at, () => { if (b.wall() + 240 * S > file.expires) { file.issued = b.wall() - 20 * S; file.expires = b.wall() + 240 * S; } renew(at + 60 * S); }); };
    renew(r.int(1, 59) * S);
    // The wall clock: within half a skew of true time, set to a new offset at random moments.
    b.step = r.int(-50, 50) * STEP;
    for (let at = r.int(1, 90) * S; at < 1000 * S; at += r.int(1, 120) * S) b.at(at + 50, () => { b.step = r.chance(0.3) ? (r.chance(0.5) ? HALF_SKEW : -HALF_SKEW) : r.int(-50, 50) * STEP; });
    // What the test itself knows: the latest expiry any check has reported as verified.
    // ADAPTED (this line and the three marked below): the test knew only the wall-clock expiry of
    // the last verified lease, because the watch under review had no other deadline. After finding
    // N2 a verified lease also ends when its remaining life, as it was when it first verified, has
    // passed on the monotonic clock. `deadline` is that moment in the scheduler's time.
    let verified = first, refusedAt = null, deadline = first - b.wall();
    b.watch(() => new Promise((resolve, reject) => {
      const kind = r.next(), duration = kind < 0.5 ? 0 : kind < 0.75 ? r.int(1, 49) * STEP : kind < 0.9 ? r.int(50, 450) * STEP : null;
      if (duration === null) return; // never returns
      const unreadable = r.chance(0.12);
      b.at(b.time + duration, () => {
        if (unreadable) return reject(fsError());
        // guard() reads the lease file last and judges it against the clock as it reads then.
        // ADAPTED: was `verified = Math.max(verified, file.expires)`; the deadline of a newer lease is noted with it.
        if (file.issued <= b.wall() && b.wall() < file.expires) { if (file.expires > verified) { verified = file.expires; deadline = b.time + file.expires - b.wall(); } return resolve(valid(file.expires)); }
        refusedAt ??= b.time; reject(new Error('Attestation expired or future-dated'));
      });
    }));
    let expiredSince = null;
    for (let at = STEP; at <= 1400 * S && b.signals.length < 2; at += STEP) {
      const before = verified, deadlineBefore = deadline;
      await b.run(at);
      const term = b.first('SIGTERM');
      if (term && term.time === at) {
        // Either the wall clock had reached the expiry of the last verified lease, or a check refused at this moment.
        // ADAPTED: asserted `term.wall >= before || refusedAt === at`: SIGTERM only when the wall
        // clock had reached the expiry, or a check refused. With N2's fix the third cause is the
        // monotonic deadline; inside A1 it comes at most one skew before the wall-clock expiry
        // (after a clock set back), and that is asserted too, so the check is no looser than before.
        assert.ok(term.wall >= before || refusedAt === at || term.time >= deadlineBefore, `seed ${seed}: SIGTERM at ${at} ms with ${before - term.wall} ms of a verified lease left on the wall clock, ${deadlineBefore - term.time} ms on the monotonic clock, and no refusal`);
        if (refusedAt !== at) assert.ok(before - term.wall <= 2 * HALF_SKEW, `seed ${seed}: stopped ${before - term.wall} ms before the lease's end on the wall clock`);
      }
      if (!term) {
        if (b.wall() >= verified) { expiredSince ??= at; assert.ok(at - expiredSince < GUARD_PERIOD_MS + STEP, `seed ${seed}: the lease ended ${at - expiredSince} ms ago on the wall clock and nothing was sent`); } else expiredSince = null;
      }
    }
    const term = b.first('SIGTERM'), kill = b.first('SIGKILL');
    assert.ok(term && kill, `seed ${seed}: the child was stopped in the end`);
    assert.equal(kill.time - term.time, GUARD_KILL_MS, `seed ${seed}`);
    assert.equal(b.signals.length, 2, `seed ${seed}: each signal once`);
  }
});

test('HELD: the real guard\'s errors fall on the right side: a file that is not there or cannot be opened is "unreadable"; a removed authority, another release, a cut-off or changed lease, a lease path that is a directory are refusals', async () => {
  const w = world(), key = w.validatorKeys[0], T0 = Date.parse('2026-12-01T00:00:00.000Z');
  const state = assign(approveRelease(emptyState(w.config, T0), w.releases.one), w.config, key, 'host-a', T0), now = T0 + 360 * S;
  const lease = decide(state, w.config, ask(w, 'host-a', key, { timeMs: now }), now, w.sign).reply.lease, text = JSON.stringify(lease);
  const unreadable = (error) => typeof error?.code === 'string' && typeof error?.syscall === 'string'; // the watch's own test
  const verdict = async (prepare) => {
    const host = await operatorDirectory(w, 'host-a', key);
    await writeFile(host.settings.signer_lease_file, text);
    await prepare(host.settings);
    try { await guard(host.settings, now); return 'verified'; } catch (error) { return unreadable(error) ? 'unreadable' : 'refusal'; } finally { await rm(host.directory, { recursive: true, force: true }); }
  };
  assert.equal(await verdict(async () => {}), 'verified');
  for (const name of ['signer_lease_file', 'trust_file', 'release_manifest', 'genesis_file']) assert.equal(await verdict((settings) => rm(settings[name])), 'unreadable', name);
  assert.equal(await verdict((settings) => writeFile(settings.trust_file, JSON.stringify({ ...w.trust, authorities: [] }))), 'refusal');
  assert.equal(await verdict((settings) => writeFile(settings.release_manifest, JSON.stringify(manifest('v5', 'two')))), 'refusal');
  assert.equal(await verdict((settings) => writeFile(settings.signer_lease_file, text.slice(0, 200))), 'refusal');
  assert.equal(await verdict((settings) => writeFile(settings.signer_lease_file, text.replace(/"fence_token":"\d+"/, '"fence_token":"1"'))), 'refusal');
  assert.equal(await verdict(async (settings) => { await rm(settings.signer_lease_file); await mkdir(settings.signer_lease_file); }), 'refusal');
  assert.equal(await verdict((settings) => writeFile(settings.trust_file, '{"authorities":')), 'refusal');
  // The order of reading matters for one case: with the lease file gone, a removed authority is
  // not seen, because the trust file's content is judged only together with a lease.
  assert.equal(await verdict(async (settings) => { await writeFile(settings.trust_file, JSON.stringify({ ...w.trust, authorities: [] })); await rm(settings.signer_lease_file); }), 'unreadable');
});
