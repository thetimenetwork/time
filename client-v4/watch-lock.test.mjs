// The lock of a data directory (`claim` in deploy/watch/start.mjs, which the alert watch and the
// API service share) and its heartbeat.
//
// Two races were in it:
// - A heartbeat already in flight looked at the lock, found it its own, and replaced it later.
//   A release in between removed the lock, and the heartbeat then put it back: the lock outlived
//   its release, and the same process could not claim the directory again.
// - The same gap, across a stall of the process: another run took over the stale lock, and the
//   old heartbeat, resuming, put its own lock over the new holder's. The new holder then found a
//   foreign lock and stopped, exit code 75. (Under a loaded machine this killed the test file
//   security-watch-review3.test.mjs at its test T5.)
//
// These tests provoke both without sleeping. The heartbeat is fired by hand (`interval`, `cancel`
// stand in for the timer) and held at the point where its new lock is written but not yet in
// place (`pause`), while the test releases the lock or lets another run take it.
import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { claim } from '../deploy/watch/start.mjs';

/// A promise and the function that settles it.
function gate() { let open; const passed = new Promise((resolve) => { open = resolve; }); return { passed, open }; }
/// A few turns of the event loop: everything that could run without the gate has run.
async function turns(count = 5) { for (let i = 0; i < count; i++) await new Promise((resolve) => setImmediate(resolve)); }
/// Claims `directory` with a heartbeat the test fires by hand and can hold before it replaces the lock.
async function held(directory, options = {}) {
  const timer = { callback: null, cancelled: 0 }, lostWith = [], pauses = [];
  let hold = null, reached = null;
  const release = await claim(directory, {
    exitOnLost: false, onLost: (why) => { lostWith.push(why); },
    interval: (callback) => { timer.callback = callback; return timer; },
    cancel: () => { timer.cancelled += 1; },
    pause: async (point) => { pauses.push(point); if (hold) { reached.open(); await hold.passed; } },
    ...options,
  });
  return {
    release, lostWith, pauses, timer, file: path.join(directory, 'watch.lock'),
    /// Fires the timer's callback, as the timer would (also after it was cancelled: a callback
    /// that was already queued still runs). Resolves when that heartbeat has ended.
    beat: () => Promise.resolve(timer.callback()),
    /// The next heartbeat stops before it replaces the lock. Resolves when it has got there;
    /// `go()` lets it continue.
    holdNext() { hold = gate(); reached = gate(); const waiting = hold; return { there: reached.passed, go: () => { hold = null; waiting.open(); } }; },
  };
}
const lockOf = async (file) => JSON.parse(await readFile(file, 'utf8'));
/// Waits for a condition, not for a time: reads until `done(value)` holds and returns the last value read, giving
/// up after `limitMs` so that a condition that never comes fails the assertion that follows. On Windows another
/// program (a virus scanner) can hold a file open for a moment: it then cannot be replaced or read, and a deleted
/// file stays listed.
async function eventually(read, done, limitMs = 15000) {
  const until = Date.now() + limitMs;
  for (;;) {
    let value, failed = null;
    try { value = await read(); } catch (error) { failed = error; }
    if (!failed && done(value)) return value;
    if (Date.now() >= until) { if (failed) throw failed; return value; }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
async function scratch(run) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-lock-race-'));
  // Windows keeps a deleted file listed while another program (a virus scanner) has it open.
  try { await run(directory); } finally { await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }); }
}

test('the lock: a heartbeat rewrites the lock of its own run and leaves nothing else behind', async () => {
  await scratch(async (directory) => {
    let clock = 1_000_000;
    const lock = await held(directory, { now: () => clock });
    const first = await lockOf(lock.file);
    assert.deepEqual([first.pid, first.beat], [process.pid, 1_000_000]);
    // On Windows a replacement is refused (EPERM) for as long as another program, such as a virus
    // scanner, has the lock open. The heartbeat then leaves the lock as it is and the next one
    // writes it. So the heartbeat is fired until the beat has moved: the test waits for that, with
    // a pause between two heartbeats, and not for a number of tries that a slow scanner outlasts.
    clock += 10_000;
    const second = await eventually(async () => { await lock.beat(); return lockOf(lock.file); }, (seen) => seen.beat !== first.beat);
    // Should the beat not move, the failure says what the lock itself saw: whether it gave itself up, and which files are there.
    assert.deepEqual([second.run, second.beat], [first.run, 1_010_000], `the heartbeat did not rewrite the lock: lost with ${JSON.stringify(lock.lostWith)}, heartbeats that reached the write ${lock.pauses.length}, files ${JSON.stringify(await readdir(directory).catch((error) => error.code))}`);
    assert.ok(lock.pauses.length >= 1 && lock.pauses.every((point) => point === 'heartbeat-written'));
    assert.deepEqual(await eventually(() => readdir(directory), (names) => names.length === 1), ['watch.lock'], 'no temporary file is left');
    assert.deepEqual(lock.lostWith, []);
    await lock.release();
    assert.deepEqual(await eventually(() => readdir(directory), (names) => names.length === 0), []);
    assert.equal(lock.timer.cancelled, 1);
  });
});

test('the lock: release waits for a heartbeat in flight, and that heartbeat does not put the lock back', async () => {
  await scratch(async (directory) => {
    const lock = await held(directory);
    // A heartbeat has looked at the lock, found it its own, and written its replacement.
    const stopped = lock.holdNext(), beating = lock.beat();
    await stopped.there;
    assert.equal((await readdir(directory)).length, 2, 'the lock and the heartbeat\'s temporary file');
    // Now the lock is released.
    let released = false;
    const releasing = lock.release().then(() => { released = true; });
    await turns();
    assert.equal(released, false, 'release resolved while a heartbeat of this process could still write the lock');
    // The heartbeat goes on. It must find the release and replace nothing.
    stopped.go();
    await releasing; await beating;
    await assert.rejects(readFile(lock.file, 'utf8'), { code: 'ENOENT' }, 'the heartbeat put the lock back after its release');
    assert.deepEqual(await readdir(directory), [], 'nothing is left in the directory');
    // A timer callback that was already queued when the timer was stopped does nothing.
    await lock.beat(); await turns();
    assert.deepEqual(await readdir(directory), []);
    assert.deepEqual(lock.pauses, ['heartbeat-written'], 'no heartbeat started after the release');
    assert.deepEqual(lock.lostWith, [], 'a release is not a loss');
    // Releasing twice is one release, and the same process can claim the directory again.
    await lock.release();
    const again = await claim(directory, { interval: () => ({}), cancel: () => {} });
    assert.equal((await lockOf(lock.file)).pid, process.pid);
    await again();
    assert.deepEqual(await readdir(directory), []);
  });
});

test('the lock: a heartbeat that resumes after another run took over does not replace the new holder\'s lock', async () => {
  await scratch(async (directory) => {
    const other = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 20000)'], { stdio: 'ignore' });
    try {
      const lock = await held(directory);
      // The heartbeat looked (the lock was its own) and is then held up: the process stalls.
      const stopped = lock.holdNext(), beating = lock.beat();
      await stopped.there;
      // Meanwhile another run takes the stale lock over and holds it.
      const theirs = JSON.stringify({ pid: other.pid, run: 'the-run-that-took-over', beat: Date.now() });
      await writeFile(lock.file, theirs);
      // The stalled process resumes.
      stopped.go(); await beating; await turns();
      assert.equal(await readFile(lock.file, 'utf8'), theirs, 'the old heartbeat put its lock over the new holder\'s');
      assert.deepEqual(lock.lostWith, ['another process holds the lock'], 'and it knows that it lost the lock');
      assert.deepEqual(await readdir(directory), ['watch.lock']);
      // Having lost, it never writes again, and its release leaves the other run's lock alone.
      await lock.beat(); await turns();
      await lock.release();
      assert.equal(await readFile(lock.file, 'utf8'), theirs);
      assert.deepEqual(lock.lostWith.length, 1);
      // The new holder is alive and its beat is fresh: this process cannot claim the directory.
      await assert.rejects(claim(directory), /Another watch/);
    } finally { other.kill(); }
  });
});

test('the lock: a heartbeat that finds the lock gone does not recreate it', async () => {
  await scratch(async (directory) => {
    const lock = await held(directory);
    const stopped = lock.holdNext(), beating = lock.beat();
    await stopped.there;
    await rm(lock.file); // taken aside by a run that is taking over, or removed by an operator
    stopped.go(); await beating; await turns();
    assert.deepEqual(await readdir(directory), [], 'the heartbeat recreated a lock it no longer held');
    assert.deepEqual(lock.lostWith, ['the lock file is gone']);
    await lock.release();
    assert.deepEqual(await readdir(directory), []);
  });
});

test('the lock: one heartbeat runs at a time', async () => {
  await scratch(async (directory) => {
    const lock = await held(directory);
    const stopped = lock.holdNext(), first = lock.beat();
    await stopped.there;
    // The timer fires again while the first heartbeat is still under way (a slow disk).
    const second = lock.beat(), third = lock.beat();
    await turns();
    assert.deepEqual(lock.pauses, ['heartbeat-written'], 'a second heartbeat started beside the first');
    stopped.go(); await Promise.all([first, second, third]);
    assert.deepEqual(lock.pauses, ['heartbeat-written']);
    // The next one runs as usual.
    await lock.beat();
    assert.deepEqual(lock.pauses, ['heartbeat-written', 'heartbeat-written']);
    await lock.release();
    assert.deepEqual(await readdir(directory), []);
  });
});

test('the lock: a stale lock of another live process is still taken over, and a fresh one is left alone', async () => {
  await scratch(async (directory) => {
    const other = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 20000)'], { stdio: 'ignore' });
    const file = path.join(directory, 'watch.lock');
    try {
      // Fresh: refused, and the lock is untouched.
      const fresh = JSON.stringify({ pid: other.pid, run: 'another', beat: Date.now() });
      await writeFile(file, fresh);
      await assert.rejects(claim(directory), /Another watch/);
      assert.equal(await readFile(file, 'utf8'), fresh);
      assert.deepEqual(await readdir(directory), ['watch.lock'], 'nothing was taken aside and left there');
      // Stale (its beat is older than three beats): taken.
      await writeFile(file, JSON.stringify({ pid: other.pid, run: 'another', beat: Date.now() - 31_000 }));
      const lock = await held(directory);
      assert.equal((await lockOf(file)).pid, process.pid);
      assert.deepEqual(await readdir(directory), ['watch.lock']);
      await lock.release();
      assert.deepEqual(await readdir(directory), []);
    } finally { other.kill(); }
  });
});
