// Second independent review: the host agent's new rules (deploy/lease-agent.mjs) against the
// service on localhost: `renew_by_utc`, the leases the controller remembers as replaced, and the
// agent's refusal to ask when it cannot read the installed lease.
//
// FINDING tests fail against the code under review: the failure is the finding. HELD tests pass.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { guard } from '../operator.mjs';
import { json } from '../lib.mjs';
import { Refused, hostView, round, validateAgentConfig } from '../lease-agent.mjs';
import { start, validateConfig } from './start.mjs';
import { runCommand } from './ctl.mjs';
import { operatorDirectory, world } from './fixtures.mjs';

const T0 = Date.parse('2026-12-01T00:00:00.000Z'), S = 1000, START_WAIT = 360 * S;
const temporary = (name) => mkdtemp(path.join(tmpdir(), 'time-lease-review2-' + name + '-'));

/// A service on a free local port, one validator host directory, the agent's config, and a clock
/// the test moves (one clock for the controller's wall clock and its elapsed time). Release
/// approved, key assigned to host-a, the wait over. `prepare` runs before the agent's first round.
async function deployment({ prepare = async () => {} } = {}) {
  const w = world(), clock = { now: T0 }, now = () => clock.now;
  const config = { ...w.config, data_directory: await temporary('service') };
  const running = await start(config, { authority: w.authority, now, monotonic: now, log: () => {}, port: 0, exitOnLost: false, onFatal: () => {} });
  const key = w.validatorKeys[0], checked = validateConfig(config), command = (...words) => runCommand(checked, words, { now, readManifest: async () => w.releases.one });
  const host = await operatorDirectory(w, 'host-a', key);
  const container = Object.fromEntries(Object.entries(host.settings).map(([name, value]) => [name, typeof value === 'string' && value.startsWith(host.directory) ? '/operator/' + path.basename(value) : value]));
  await writeFile(host.settingsFile, JSON.stringify(container));
  const agent = validateAgentConfig({ controller_url: running.url, host_id: 'host-a', host_key_file: path.join(await temporary('agent'), 'host-key.json'), settings_file: host.settingsFile, operator_directory: host.directory });
  await command('approve-release', 'release.json'); const assigned = await command('assign', key, 'host-a');
  clock.now += assigned.result.seconds_until_first_lease * S;
  const d = { w, clock, now, running, key, command, host, agent, leaseFile: host.settings.signer_lease_file };
  await prepare(d);
  /// One round of the agent, whose clock is `hostAhead` ms ahead of the controller's.
  d.round = (hostAhead = 0, fetcher = undefined) => round(agent, { key: w.hostKeys['host-a'], now: () => clock.now + hostAhead, ...(fetcher ? { fetcher } : {}) })
    .then((result) => (result.installed ? 'installed' : 'kept'), (error) => (error instanceof Refused ? error.code : error.message));
  d.keyState = async () => (await command('list')).result.keys.find((item) => item.validator_public_key_hex === key).state;
  d.installed = async () => JSON.parse(await readFile(d.leaseFile, 'utf8')).payload;
  /// Whether the kit's guard accepts the installed lease on the host's clock.
  d.guarded = async (hostAhead = 0) => guard(hostView(await json(host.settingsFile), host.directory), clock.now + hostAhead).then(() => true, () => false);
  return d;
}

// ---- Findings --------------------------------------------------------------------

test('FINDING (low): an empty lease file, as a provisioning tool leaves it when it creates the file to set its owner, keeps the agent from ever asking for the first lease', async () => {
  const d = await deployment({ prepare: (deployed) => writeFile(deployed.leaseFile, '') });
  try {
    const rounds = [];
    for (let i = 0; i < 3; i++) { rounds.push(await d.round()); d.clock.now += 10 * S; }
    // Before the first review's fix the agent asked, naming no lease, and got the tenure's first
    // lease. A file that holds nothing was never a lease and can hide no second machine. The
    // message also says "the key is then frozen and needs unfreeze", which is not so for a first lease.
    assert.deepEqual({ rounds: rounds.map((item) => item.slice(0, 48)), key: await d.keyState() }, { rounds: ['installed', 'TOO_SOON', 'TOO_SOON'], key: 'LEASED' });
  } finally { await d.running.close(); }
});

// ---- Attacks that held -----------------------------------------------------------

test('HELD: with the host\'s clock one skew behind, someone on the path gets an earlier lease for the same request installed in the last seconds before its end; the key is not frozen and the host is served again', async () => {
  const d = await deployment();
  try {
    const behind = -9 * S;
    assert.equal(await d.round(behind), 'installed');
    d.clock.now += 60 * S;
    // The renewal's answer is kept and dropped; 221 s later the controller replaces that lease.
    let kept = null, fresh = null;
    assert.match(await d.round(behind, async (url, options) => { kept = await (await fetch(url, options)).json(); throw new TypeError('fetch failed'); }), /could not be reached/);
    d.clock.now += 221 * S;
    const swapped = await d.round(behind, async (url, options) => { fresh = await (await fetch(url, options)).json(); return new Response(JSON.stringify(kept), { status: 200 }); });
    assert.notEqual(fresh.lease.payload.lease_id, kept.lease.payload.lease_id);
    // On the host's clock the earlier lease is not yet past renew_by_utc, so it is installed (design 8.2 says so).
    assert.equal(swapped, 'installed'); assert.equal((await d.installed()).lease_id, kept.lease.payload.lease_id);
    // The host now names a lease the controller has replaced. That is accepted; nothing is frozen.
    const outcomes = [];
    for (let i = 0; i < 5; i++) { d.clock.now += 10 * S; outcomes.push(await d.round(behind)); }
    assert.ok(outcomes.includes('installed'), JSON.stringify(outcomes)); assert.ok(outcomes.every((item) => item === 'installed' || item === 'TOO_SOON' || item === 'kept'), JSON.stringify(outcomes));
    assert.equal(await d.keyState(), 'LEASED'); assert.equal(await d.guarded(behind), true);
    // The same exchange with a host clock that is not behind: the earlier lease is refused.
    const e = await deployment();
    try {
      assert.equal(await e.round(), 'installed'); e.clock.now += 60 * S;
      let old = null;
      await e.round(0, async (url, options) => { old = await (await fetch(url, options)).json(); throw new TypeError('fetch failed'); });
      e.clock.now += 221 * S;
      assert.match(await e.round(0, async (url, options) => { await fetch(url, options); return new Response(JSON.stringify(old), { status: 200 }); }), /no longer sends/);
      e.clock.now += 10 * S;
      assert.equal(await e.round(), 'installed'); assert.equal(await e.keyState(), 'LEASED');
    } finally { await e.running.close(); }
  } finally { await d.running.close(); }
});

test('HELD: an honest agent is never refused for long by the new rules: clocks a skew ahead or behind, answers lost for minutes, the end of a lease, requests arriving twice', async () => {
  for (const hostAhead of [9 * S, 0, -9 * S]) {
    const d = await deployment();
    try {
      assert.equal(await d.round(hostAhead), 'installed', 'first, clock ' + hostAhead);
      // Twenty minutes of the agent's own loop: ask, wait a quarter of what is left or ten seconds.
      // Every answer in minutes 3 to 6 and 11 to 13 is lost on the way back; one request in five
      // is delivered a second time, a second after the first.
      let lost = 0, waitedWithoutLease = 0, call = 0;
      for (let passed = 0; passed < 1200 * S;) {
        const minute = passed / (60 * S), losing = (minute >= 3 && minute < 6) || (minute >= 11 && minute < 13), twice = ++call % 5 === 0;
        const outcome = await d.round(hostAhead, async (url, options) => {
          const response = await fetch(url, options);
          if (twice) { d.clock.now += 1 * S; await (await fetch(url, options)).arrayBuffer(); d.clock.now -= 1 * S; }
          if (losing) { await response.arrayBuffer(); throw new TypeError('fetch failed'); }
          return response;
        });
        if (losing) lost++;
        const left = Date.parse((await d.installed()).expires_utc) - (d.clock.now + hostAhead), wait = outcome === 'installed' || outcome === 'kept' ? Math.min(120 * S, Math.max(5 * S, Math.floor(left / 4))) : 10 * S;
        if (!(await d.guarded(hostAhead))) waitedWithoutLease += wait;
        assert.notEqual(await d.keyState(), 'FROZEN', `clock ${hostAhead}, after ${passed / 1000} s: ${outcome}`);
        d.clock.now += wait; passed += wait;
      }
      assert.ok(lost > 20);
      // The validator is without a lease only while the answers are lost for longer than a lease
      // lasts, and for no more than three rounds after they come through again.
      assert.ok(waitedWithoutLease <= 40 * S, `clock ${hostAhead}: ${waitedWithoutLease / 1000} s without a valid lease`);
      assert.equal(await d.round(hostAhead) === 'installed' || await d.guarded(hostAhead), true);
    } finally { await d.running.close(); }
  }
});
