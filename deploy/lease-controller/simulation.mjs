// A simulated world for the signer-lease controller: the schedules of safety.test.mjs.
// docs/design/signer-lease-controller.md, section 4 (the claims) and section 15.
//
// True time; four hosts and the controllers' machines, each with a clock that is anywhere within
// half a skew of true time, often exactly at the edge, and moves. Requests AND answers that are
// delayed, lost, repeated and replayed. Controllers that are killed, that die just before and
// just after they write the state, whose disk reports errors; one or two live processes on one
// state directory; a start from the current state, from ANY state ever written, or from none,
// with settings that change between starts; state files replaced under a running service;
// commands on a restored or lost state before and after the start; two releases; hosts that lose
// their agent state. An operator who gives, moves, takes away, unfreezes and re-tokens keys at
// random moments. The real controller code runs (createController over a store in memory), and
// every lease a host installs is checked by the kit's own attestation check on that host's clock.
//
// After every step: claim S1 (no two hosts with a live lease for one key, and the distance of the
// stop time between them), claim S2 (fence tokens), and that a key is frozen only for a cause the
// design names: a host that lost its lease or agent state, or a controller state that was put back.
import assert from 'node:assert/strict';
import { signed } from '../lib.mjs';
import { GUARD_MAX_LEASE_MS, newNonce } from '../lease-protocol.mjs';
import { CommandRefused, approveRelease, assign, checkBinding, checkClock, decide, emptyState, move, refence, stamped, timing, unassign, unfreeze, validateState } from './core.mjs';
import { Fatal, createController } from './start.mjs';
import { memoryStore } from './store.mjs';
import { ask, random, world } from './fixtures.mjs';

const T0 = Date.parse('2026-12-01T00:00:00.000Z'), S = 1000;
/// The settings a controller may be started with. The skew is the same in all: it is a statement
/// about the clocks (assumption A1), not something a restart changes.
const SETTINGS = [{ lease_seconds: 240, stop_seconds: 40 }, { lease_seconds: 124, stop_seconds: 30 }, { lease_seconds: 280, stop_seconds: 60 }, { lease_seconds: 240, stop_seconds: 30 }];
const LEAST_STOP_MS = 30 * S;

/// Runs one schedule. Throws an assertion error, with the seed and the step, at the first
/// moment a claim does not hold. `sabotage` removes one rule of the controller.
export async function simulate(seed, steps, sabotage = null) {
  const r = random(seed), w = world({ hosts: ['host-a', 'host-b', 'host-c', 'host-d'], validators: 2 }), half = timing(w.config).skewMs / 2;
  // A clock is anywhere within half a skew of true time (assumption A1), and often exactly at an edge.
  const offset = () => (r.chance(0.3) ? (r.chance(0.5) ? half : -half) : r.int(-half, half));
  // `disk` is the state directory: one array for the whole run, changed in place. `epoch` counts
  // how often its content was put back or lost.
  const sim = { tau: T0, config: w.config, disk: [], epoch: 0, everything: [], controllers: [], sent: [], inFlight: [], answers: [], recent: [], lastIssued: {}, lastHolder: {}, twoApproved: false };
  const stats = { steps, requests: 0, granted: 0, installed: 0, refused: {}, holderChanges: 0, starts: 0, secondProcesses: 0, restores: 0, wipes: 0, replacedUnderService: 0, fatal: 0, crashesBeforeWrite: 0, crashesAfterWrite: 0, writeErrors: 0, kills: 0, frozenAfterHostLoss: 0, frozenAfterRestore: 0, commands: 0, commandsBeforeStart: 0, replays: 0, lateAnswers: 0, releaseSwitches: 0, settingsChanges: 0 };
  const hosts = w.config.hosts.map((host) => ({ id: host.id, offset: offset(), wants: r.pick(w.validatorKeys), release: w.releases.one, installed: null, pending: null, lost: false, excused: false }));
  let step = 0;
  const fail = (message) => assert.fail(`seed ${seed}, step ${step}${sabotage ? ', sabotage ' + sabotage : ''}: ${message}`);

  /// The store of one controller process, or of a command when `process` is null. Everything
  /// ever written is kept. A controller's write can be made to fail:
  /// - 'before' and 'after': the process dies at that point;
  /// - 'error-before' and 'error-after': the write reports an error and the process lives on (a
  ///   full disk; a directory that could not be synced after the file was already linked).
  const store = (process = null) => {
    const inner = memoryStore(sim.disk), dies = () => { sim.controllers = sim.controllers.filter((item) => item !== process); };
    return {
      // Old files are removed as the real store removes them: by a service, behind what it holds.
      latest: () => inner.latest(), read: () => inner.read(), readAt: (seq) => inner.readAt(seq), prune: (below) => inner.prune(below),
      async write(seq, state, parent) {
        const failure = process?.failNext ?? null;
        if (process) process.failNext = null;
        if (failure === 'before') { dies(); stats.crashesBeforeWrite++; throw new Error('crash before the state was written'); }
        if (failure === 'error-before') { stats.writeErrors++; throw new Error('the disk refused the write'); }
        const sum = await inner.write(seq, state, parent);
        sim.everything.push({ ...sim.disk.at(-1) });
        if (failure === 'after') { dies(); stats.crashesAfterWrite++; throw new Error('crash after the state was written'); }
        if (failure === 'error-after') { stats.writeErrors++; throw new Error('the write was reported as failed after it was done'); }
        return sum;
      },
    };
  };
  /// The newest state on disk, parsed once per file.
  let parsedOf = null, parsed = null;
  const newest = () => { const last = sim.disk.at(-1) ?? null; if (last !== parsedOf) { parsedOf = last; parsed = last ? JSON.parse(last.text) : null; } return parsed; };
  const holderOf = (key) => newest()?.keys[key]?.holder?.host_id;

  /// A controller process starts on the state directory, on a machine with a clock of its own.
  async function start() {
    const process = { offset: offset(), failNext: null }, before = newest();
    process.api = createController({ config: sim.config, store: store(process), sign: w.sign, now: () => sim.tau + process.offset, monotonic: () => sim.tau });
    await process.api.open();
    if (sabotage === 'no-start-rule' && before) await store().write(sim.disk.at(-1).seq + 1, before, sim.disk.at(-1).sha256);
    sim.controllers.push(process); stats.starts++;
  }
  /// One of the operator's commands, the way ctl.mjs applies it: on the newest state, as a new
  /// number that names its parent, on the clock of the machine the state directory is on.
  async function command(change) {
    const files = store(), loaded = await files.read(), at = sim.tau + (sim.controllers[0]?.offset ?? sim.commandOffset ?? 0);
    const base = loaded ? checkBinding(validateState(loaded.state), sim.config) : emptyState(sim.config, at);
    let next;
    try { checkClock(base, sim.config, at); next = change(base, at); } catch (error) { if (error instanceof CommandRefused) return false; throw error; }
    await files.write((loaded?.seq ?? 0) + 1, stamped(next, at), loaded?.sha256 ?? null); stats.commands++;
    return true;
  }
  const randomCommand = (kinds) => {
    const key = r.pick(w.validatorKeys), host = r.pick(hosts).id, holder = holderOf(key), kind = r.pick(kinds);
    if (kind === 'assign') return command((state, at) => assign(state, sim.config, key, host, at));
    if (kind === 'move') return command((state, at) => move(state, sim.config, key, host, holder, at));
    if (kind === 'unassign') return command((state, at) => unassign(state, sim.config, key, at));
    if (kind === 'unfreeze') return command((state, at) => unfreeze(state, sim.config, key, at));
    return command((state, at) => refence(state, sim.config, key, at));
  };

  /// What the agent and the guard do with an answer, on the host's clock.
  function receive(host, reply) {
    if (reply?.status !== 'granted') return;
    const lease = reply.lease, payload = lease.payload, hostNow = sim.tau + host.offset;
    if (payload.host_id !== host.id || payload.request_nonce !== host.pending?.nonce) return;
    try { signed(lease, w.trust, { kind: 'signer_lease', release_id: host.release.release_id, genesis_sha256: w.config.network.genesis_sha256, chain_id: w.chainId, validator_public_key_hex: host.wants, signer_identity: 'signer-of-' + host.id, engine: 'v5' }, hostNow); } catch { return; }
    const issued = Date.parse(payload.issued_utc), expires = Date.parse(payload.expires_utc), key = payload.validator_public_key_hex;
    if (expires - issued > GUARD_MAX_LEASE_MS || payload.enforcement !== 'EVERY_SIGNATURE') fail('the controller issued a lease the guard refuses');
    // The agent's own rules (lease-agent.mjs): not a lease the controller no longer sends, not a
    // lower token, not an older lease of the same tenure.
    if (!(hostNow < Date.parse(payload.renew_by_utc))) return;
    const held = host.installed?.payload;
    if (held && held.fence_domain === payload.fence_domain) {
      if (BigInt(payload.fence_token) < BigInt(held.fence_token) || payload.lease_id === held.lease_id) return;
      if (payload.fence_token === held.fence_token && !(expires > Date.parse(held.expires_utc))) return;
    }
    // Claim S1 at the moment a lease becomes live on a host: every lease another host ever had
    // for this key was last live at least the stop time ago. A lease can be live on its host
    // until half a skew of true time after its expiry.
    for (const other of sim.recent) if (other.key === key && other.host !== host.id && sim.tau < other.expires + half + LEAST_STOP_MS) fail(`host ${host.id} got a live lease for a key while the lease of ${other.host} (expires ${new Date(other.expires).toISOString()}) was live or ended less than the stop time ago; true time ${new Date(sim.tau).toISOString()}`);
    if (sim.lastHolder[key] && sim.lastHolder[key] !== host.id) stats.holderChanges++;
    sim.lastHolder[key] = host.id;
    sim.recent.push({ key, host: host.id, issued, expires });
    host.installed = lease; host.lost = false; host.excused = false; stats.installed++;
  }
  /// Hands a request to a controller process, if one runs, and returns its answer or null.
  /// `recording` is set when the request is a recording sent again, not one the host sends now:
  /// it says what was true when the request was made.
  async function deliver(envelope, host, recording = null) {
    const process = sim.controllers.length ? r.pick(sim.controllers) : null;
    if (!process) return null;
    if (sabotage === 'no-wait') {
      const last = JSON.parse(sim.disk.at(-1).text);
      if (Object.values(last.keys).some((key) => key.not_before_ms > 0)) { for (const key of Object.values(last.keys)) key.not_before_ms = 0; await store().write(sim.disk.at(-1).seq + 1, last, sim.disk.at(-1).sha256); }
    }
    const before = newest(), failing = process.failNext;
    let reply;
    try { reply = await process.api.submit(envelope); } catch (error) {
      // The controller stopped itself: its state files were replaced under it.
      if (error instanceof Fatal) { sim.controllers = sim.controllers.filter((item) => item !== process); stats.fatal++; return null; }
      // The controller crashed or could not write. With the rule in force nothing was sent.
      if (sabotage !== 'send-before-write' || !['before', 'error-before'].includes(failing) || !before) return null;
      reply = decide(before, sim.config, envelope, sim.tau + process.offset, w.sign).reply;
    }
    stats.requests++;
    if (reply.status === 'granted') {
      stats.granted++;
      // Claim S2, in the order of issue.
      const payload = reply.lease.payload, key = payload.validator_public_key_hex, last = sim.lastIssued[key], token = BigInt(payload.fence_token);
      if (last && token < last.token) fail('a fence token went down');
      if (last && last.host !== payload.host_id && token <= last.token) fail('a lease for another host does not carry a higher fence token');
      sim.lastIssued[key] = { host: payload.host_id, token };
    } else {
      stats.refused[reply.code] = (stats.refused[reply.code] ?? 0) + 1;
      if (/now frozen/.test(reply.message)) {
        // A key is frozen for a cause the design names, and for no other: the host lost its
        // lease file or agent state, or the controller's state was put back or lost since the
        // host last installed a lease. Never because of a recording, a delay or a repeat.
        // A recording may bring a freeze forward that had a cause when it was made, or that has one
        // because the state was put back since. A recording alone is never a cause.
        const lost = host.lost || recording?.lost, excused = host.excused || recording?.excused;
        if (lost) stats.frozenAfterHostLoss++; else if (excused) stats.frozenAfterRestore++;
        else fail(recording ? 'a recorded request froze a key' : `a key was frozen without a cause: host ${host.id} lost nothing and the controller's state was not put back`);
      }
    }
    return reply;
  }
  function request(host) {
    const previous = host.installed?.payload.lease_id ?? '';
    if (host.pending?.previous !== previous) host.pending = { previous, nonce: newNonce() };
    const envelope = ask(w, host.id, host.wants, { timeMs: sim.tau + host.offset, nonce: host.pending.nonce, previous, release: host.release });
    sim.sent.push({ host, envelope, lost: host.lost, excused: host.excused }); if (sim.sent.length > 200) sim.sent.shift();
    return envelope;
  }
  /// An older state, or none, is put into the state directory.
  async function putBack() {
    sim.epoch++; sim.commandOffset = offset();
    if (r.chance(0.15) || !sim.everything.length) { sim.disk.length = 0; stats.wipes++; sim.twoApproved = false; await command((state) => approveRelease(state, w.releases.one)); }
    // Mostly a recent state, in which leases still run; otherwise any state ever written.
    else { const entry = r.chance(0.6) ? r.pick(sim.everything.slice(-12)) : r.pick(sim.everything); sim.disk.length = 0; sim.disk.push({ ...entry }); sim.twoApproved = JSON.parse(entry.text).releases.length > 1; stats.restores++; }
    // A put-back is a cause for a freeze only for a host whose lease the state now in place does
    // not know as the last one issued for its key. A host whose newest lease is still the
    // state's newest lost nothing by it.
    const back = newest();
    for (const host of hosts) { const held = host.installed?.payload; if (!held || back?.keys[held.validator_public_key_hex]?.lease_id !== held.lease_id) host.excused = true; }
    // Often the operator gives commands on that state before a service is started on it.
    for (let i = r.int(0, 3); i > 0; i--) if (await randomCommand(['assign', 'move', 'move', 'unassign'])) stats.commandsBeforeStart++;
  }

  // Two kinds of schedule. Even seeds are calm: a controller lives for a long time, leases flow,
  // and what goes wrong goes wrong while they run. Odd seeds are stormy: crashes, restores and
  // commands follow each other faster than the waits they cause.
  const calm = seed % 2 === 0;
  const weights = calm
    ? { tick: 0.33, ask: 0.44, late: 0.04, lateAnswer: 0.03, replay: 0.05, failure: 0.004, restore: 0.004, replaceUnder: 0.0005, second: 0.001, command: 0.03, release: 0.004, hostClock: 0.035, machineClock: 0.025, hostLoss: 0.001 }
    : { tick: 0.33, ask: 0.38, late: 0.04, lateAnswer: 0.03, replay: 0.05, failure: 0.02, restore: 0.01, replaceUnder: 0.002, second: 0.003, command: 0.06, release: 0.006, hostClock: 0.04, machineClock: 0.021, hostLoss: 0.005 };
  const event = () => { let x = r.next(); for (const [name, weight] of Object.entries(weights)) { if (x < weight) return name; x -= weight; } return 'nothing'; };

  await command((state) => approveRelease(state, w.releases.one));
  await start();
  for (step = 1; step <= steps; step++) {
    // A service that is down is usually started again soon, sometimes with other settings.
    if (!sim.controllers.length && r.chance(0.5)) { if (r.chance(0.3)) { sim.config = { ...w.config, ...r.pick(SETTINGS) }; stats.settingsChanges++; } await start(); }
    const what = event();
    if (what === 'tick') sim.tau += r.chance(0.7) ? r.int(1, 15) * S : r.chance(0.83) ? r.int(15, 60) * S : r.int(100, 420) * S + r.int(0, 999);
    else if (what === 'ask') {
      // A host asks. Mostly a host that holds a key and is set up for it; sometimes any host for any key.
      const holders = hosts.filter((host) => w.validatorKeys.some((key) => holderOf(key) === host.id)), host = holders.length && r.chance(0.7) ? r.pick(holders) : r.pick(hosts);
      const held = w.validatorKeys.find((key) => holderOf(key) === host.id);
      if (held && r.chance(0.9)) host.wants = held; else if (r.chance(0.3)) host.wants = r.pick(w.validatorKeys);
      const envelope = request(host), fate = r.next();
      if (fate < 0.8) { const reply = await deliver(envelope, host), then = r.next(); if (then < 0.8) receive(host, reply); else if (then < 0.9 && reply) sim.answers.push({ host, reply }); }
      else if (fate < 0.9) sim.inFlight.push({ host, envelope });
    } else if (what === 'late') {
      if (sim.inFlight.length) { const { host, envelope } = sim.inFlight.splice(r.int(0, sim.inFlight.length - 1), 1)[0]; receive(host, await deliver(envelope, host)); }
    } else if (what === 'lateAnswer') {
      // An answer that was held back on the way arrives now, in any order, or is sent a second time.
      if (sim.answers.length) { const index = r.int(0, sim.answers.length - 1), { host, reply } = sim.answers[index]; if (r.chance(0.7)) sim.answers.splice(index, 1); stats.lateAnswers++; receive(host, reply); }
    } else if (what === 'replay') {
      // A recording is sent again: often one of the newest requests, while its date is still fresh.
      if (sim.sent.length) { const recording = r.chance(0.5) ? r.pick(sim.sent.slice(-5)) : r.pick(sim.sent); stats.replays++; const reply = await deliver(recording.envelope, recording.host, recording); if (r.chance(0.5)) receive(recording.host, reply); }
    } else if (what === 'failure') {
      if (sim.controllers.length) { const process = r.pick(sim.controllers), kind = r.next(); if (kind < 0.3) { sim.controllers = sim.controllers.filter((item) => item !== process); stats.kills++; } else process.failNext = kind < 0.5 ? 'before' : kind < 0.7 ? 'after' : kind < 0.85 ? 'error-before' : 'error-after'; }
    } else if (what === 'restore') {
      // Every controller process is stopped for good (assumption A2); then the state is put back.
      sim.controllers = []; await putBack();
      if (r.chance(0.3)) { sim.config = { ...w.config, ...r.pick(SETTINGS) }; stats.settingsChanges++; }
      await start();
    } else if (what === 'replaceUnder') {
      // The mistake: the state files are put back while a service runs on them. The service
      // must not follow them; it stops at its next request, and a start comes later.
      if (sim.controllers.length) { stats.replacedUnderService++; await putBack(); }
    } else if (what === 'second') {
      // A second process on the same state directory (the lock failed, or the directory is shared).
      if (sim.controllers.length === 1) { await start(); stats.secondProcesses++; }
    } else if (what === 'command') await randomCommand(['assign', 'assign', 'assign', 'move', 'move', 'unassign', 'unfreeze', 'unfreeze', 'unfreeze', 'unfreeze', 'refence']);
    else if (what === 'release') {
      // The next release is approved; hosts install it one by one; now and then one goes back.
      if (!sim.twoApproved) { if (await command((state) => approveRelease(state, w.releases.two))) sim.twoApproved = true; }
      else { const host = r.pick(hosts); host.release = r.chance(0.9) ? w.releases.two : w.releases.one; stats.releaseSwitches++; }
    } else if (what === 'hostClock') r.pick(hosts).offset = offset();
    else if (what === 'machineClock') { if (sim.controllers.length) r.pick(sim.controllers).offset = offset(); }
    else if (what === 'hostLoss') { const host = r.pick(hosts); host.pending = null; host.lost = true; if (r.chance(0.5)) host.installed = null; }

    // Claim S1 at every step, on the hosts' own clocks as they are now: at most one host finds
    // a lease for a key live.
    sim.recent = sim.recent.filter((lease) => sim.tau < lease.expires + half + LEAST_STOP_MS + 600 * S);
    for (const key of w.validatorKeys) {
      const live = new Set(sim.recent.filter((lease) => { const clock = sim.tau + hosts.find((host) => host.id === lease.host).offset; return lease.key === key && lease.issued <= clock && clock < lease.expires; }).map((lease) => lease.host));
      if (live.size > 1) fail(`hosts ${[...live].join(' and ')} both hold a live lease for one key`);
    }
  }
  return stats;
}
