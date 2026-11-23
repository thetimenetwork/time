// Where the controller keeps its state (docs/design/signer-lease-controller.md, section 5.2):
// one file per change, numbered, never overwritten. A change is written to a temporary file,
// synced, and hard-linked to the name with the next number; the link fails if that number
// exists. So two writers (the service and the command line, or two services by mistake) can
// never both write number n + 1, and a reader sees a whole file or none.
import { link, mkdir, open, readdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { readFileSync, renameSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { canonical, sha256 } from '../lib.mjs';

/// Another writer wrote this number first. Read the newest state and decide again.
export class Conflict extends Error { constructor() { super('Another writer changed the controller state first'); } }

export const KEPT_FILES = 32;
const NAME = /^state-([0-9]{20})\.json$/;
const fileName = (seq) => 'state-' + String(seq).padStart(20, '0') + '.json';
const checksum = (state) => sha256(Buffer.from(canonical(state)));

/// A store over `directory`/state. `hooks` are for tests: `beforeLink()` and `afterLink()` run
/// around the one step that makes a change durable, and may throw to stand in for a crash.
///
/// Every file names the checksum of the state it was made from (`parent`). A reader that holds
/// one state can so tell whether a newer file continues it, or belongs to another line of files
/// that was put into the directory (design, 5.2).
export function fileStore(directory, hooks = {}) {
  const folder = path.join(directory, 'state');
  const numbers = async () => {
    let names;
    try { names = await readdir(folder); } catch (error) { if (error.code === 'ENOENT') return []; throw error; }
    return names.map((name) => NAME.exec(name)).filter(Boolean).map((match) => Number(match[1])).sort((a, b) => a - b);
  };
  const load = async (seq) => {
    const file = path.join(folder, fileName(seq));
    let parsed;
    try { parsed = JSON.parse(await readFile(file, 'utf8')); } catch (error) { if (error.code === 'ENOENT') return null; parsed = { error: error.code ?? 'not JSON' }; }
    if (!parsed || parsed.seq !== seq || typeof parsed.sha256 !== 'string' || !(parsed.parent === null || typeof parsed.parent === 'string') || !parsed.state || checksum(parsed.state) !== parsed.sha256) {
      throw new Error(`A controller state file cannot be used: ${file} (${parsed?.error ?? 'its checksum, number or parent is wrong'}). The controller does not fall back to an older state by itself. Keep the file for inspection. If it is the newest and you decide to go on from the state before it, stop the controller, move this file out of the directory and start the controller: the start rule then treats the state as an old one (README, "After the state was lost or restored").`);
    }
    return { seq, state: parsed.state, sha256: parsed.sha256, parent: parsed.parent };
  };
  return {
    folder,
    /// The number of the newest state file, or 0 when there is none.
    async latest() { return (await numbers()).at(-1) ?? 0; },
    /// The newest state as `{seq, state, sha256, parent}`, or null when there is none. A newest
    /// file that cannot be read is an error: nothing falls back to an older state by itself.
    async read() { const seq = (await numbers()).at(-1); return seq === undefined ? null : load(seq); },
    /// The state of one number, in the same form, or null when that file is not there.
    readAt: load,
    /// Writes `state` as number `seq`, made from the state whose checksum is `parent` (null for
    /// the first). Resolves, with the new checksum, only when the file and its directory entry
    /// are synced. Throws Conflict when that number exists.
    async write(seq, state, parent) {
      if (!(parent === null || typeof parent === 'string')) throw new Error('A state names the checksum of the state it was made from');
      await mkdir(folder, { recursive: true, mode: 0o700 });
      const temporary = path.join(folder, `.${process.pid}.${randomUUID()}.tmp`), final = path.join(folder, fileName(seq)), sum = checksum(state);
      const handle = await open(temporary, 'wx', 0o600);
      try { await handle.writeFile(JSON.stringify({ seq, parent, sha256: sum, state }) + '\n'); await handle.sync(); } finally { await handle.close(); }
      try {
        await hooks.beforeLink?.(seq);
        try { await link(temporary, final); } catch (error) {
          if (error.code === 'EEXIST') throw new Conflict();
          if (['EPERM', 'ENOTSUP', 'ENOSYS', 'EXDEV'].includes(error.code)) throw new Error('The state directory must be on a file system with hard links (' + error.code + ')');
          throw error;
        }
      } finally { await unlink(temporary).catch(() => {}); }
      if (process.platform !== 'win32') { const dir = await open(folder, 'r'); try { await dir.sync(); } finally { await dir.close(); } }
      await hooks.afterLink?.(seq);
      return sum;
    },
    /// Removes the files whose number is at most `below`. Failures do not matter. Only a service
    /// calls this, and only below what it holds itself (KEPT_FILES back): a command never removes
    /// a file that a running service still has to follow.
    async prune(below) { for (const old of (await numbers().catch(() => [])).filter((number) => number <= below)) await unlink(path.join(folder, fileName(old))).catch(() => {}); },
  };
}

/// A store in memory, for tests and simulations: the same contract as fileStore. `disk` is the
/// list of the files there are, oldest first.
export function memoryStore(disk = []) {
  const view = (entry) => (entry ? { seq: entry.seq, state: JSON.parse(entry.text), sha256: entry.sha256, parent: entry.parent } : null);
  return {
    disk,
    async latest() { return disk.at(-1)?.seq ?? 0; },
    async read() { return view(disk.at(-1)); },
    async readAt(seq) { return view(disk.find((entry) => entry.seq === seq)); },
    async write(seq, state, parent) {
      if (!(parent === null || typeof parent === 'string')) throw new Error('A state names the checksum of the state it was made from');
      if ((disk.at(-1)?.seq ?? 0) >= seq) throw new Conflict();
      const sum = checksum(state);
      disk.push({ seq, text: JSON.stringify(state), sha256: sum, parent });
      return sum;
    },
    async prune(below) { while (disk.length > 1 && disk[0].seq <= below) disk.shift(); },
  };
}
// ---- One service per directory ----------------------------------------------------

/// This run of this process. A lock that names our pid but another run was left by an earlier
/// process that had the same pid (a restarted container is pid 1 again): it is stale.
const RUN = randomUUID();
export const LOCK_BEAT_MS = 10_000;
export const LOCK_LOST_EXIT = 75;

/// Claims `directory` for this service. Safety does not rest on this lock (numbered state files
/// keep two writers consistent); it refuses a second service early and tells the operator.
/// - The lock {pid, run, beat} is written whole to a temporary file and linked into place.
/// - It is stale when it cannot be read, when its beat is older than 3 beats, when its pid is
///   dead, or when it names this pid with another run.
/// - A stale lock is taken by renaming it aside and checking that what was renamed is what was
///   judged stale.
/// - Every beat the holder rewrites its time. If it finds the lock gone or another run's, it
///   calls `onLost(why)` once and writes no more.
/// Returns the function that releases the lock.
export async function claim(directory, { beatMs = LOCK_BEAT_MS, onLost = () => {}, now = Date.now } = {}) {
  const file = path.join(directory, 'controller.lock'), mine = () => JSON.stringify({ pid: process.pid, run: RUN, beat: now() });
  const place = async () => {
    const temporary = `${file}.${process.pid}.${randomUUID()}.tmp`;
    await writeFile(temporary, mine(), { mode: 0o600, flag: 'wx' });
    try { await link(temporary, file); } finally { await unlink(temporary).catch(() => {}); }
  };
  let held = false;
  for (let tries = 0; tries < 5 && !held; tries++) {
    try { await place(); held = true; break; } catch (error) { if (error.code !== 'EEXIST') throw error; }
    let text = null, holder = null;
    try { text = await readFile(file, 'utf8'); holder = JSON.parse(text); } catch (error) { if (error.code === 'ENOENT') continue; holder = null; }
    const pid = holder?.pid;
    if (pid === process.pid && holder?.run === RUN) throw new Error(`This process already serves ${directory}`);
    const fresh = Number.isFinite(holder?.beat) && now() - holder.beat <= 3 * beatMs;
    let alive = false;
    if (Number.isInteger(pid) && pid > 0 && pid !== process.pid) { try { process.kill(pid, 0); alive = true; } catch (error) { alive = error.code === 'EPERM'; } }
    if (fresh && alive) throw new Error(`Another lease controller (process ${pid}) uses ${directory}. Never run two controllers for one key. If that process is the one that should run, do nothing; if it is a leftover, stop it first.`);
    const aside = `${file}.stale.${process.pid}.${randomUUID()}`;
    try { await rename(file, aside); } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
    const taken = await readFile(aside, 'utf8').catch(() => null);
    if (taken !== text) await link(aside, file).catch(() => {}); // another starter's fresh lock: put it back
    await unlink(aside).catch(() => {});
  }
  if (!held) throw new Error(`Could not claim ${directory}`);

  let over = false, busy = null;
  const beat = async () => {
    const next = `${file}.${process.pid}.beat`;
    try { await writeFile(next, mine(), { mode: 0o600 }); } catch { return; }
    // The look at whose lock it is and the replacement are synchronous and adjacent: nothing
    // this process does can come between them, so it never writes over a lock it has lost.
    let outcome = 'over';
    if (!over) {
      try { if (JSON.parse(readFileSync(file, 'utf8'))?.run !== RUN) outcome = 'taken'; else { renameSync(next, file); outcome = 'ours'; } }
      catch (error) { outcome = error.code === 'ENOENT' ? 'gone' : 'retry'; } // busy or half-replaced: the next beat looks again
    }
    if (outcome !== 'ours') await unlink(next).catch(() => {});
    if (outcome === 'taken' || outcome === 'gone') { over = true; clearInterval(timer); await onLost(outcome === 'gone' ? 'the lock file is gone' : 'another process holds the lock'); }
  };
  const timer = setInterval(() => { busy ??= beat().catch(() => {}).finally(() => { busy = null; }); }, beatMs);
  timer.unref?.();
  return async () => {
    if (over) return;
    over = true; clearInterval(timer); await busy;
    try { if (JSON.parse(await readFile(file, 'utf8')).run === RUN) await unlink(file); } catch { /* gone already */ }
  };
}
