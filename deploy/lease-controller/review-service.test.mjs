// Independent review of the signer-lease controller: the service and the host agent
// (deploy/lease-agent.mjs) on localhost, with someone on the network path between them. The
// design (section 8.2) says the transport is plain HTTP and lists what that someone can and
// cannot do; these tests check the list.
//
// FINDING tests fail against the code under review: the failure is the finding. HELD tests pass.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { RETRY_MS, Refused, round, run, validateAgentConfig } from '../lease-agent.mjs';
import { start, validateConfig } from './start.mjs';
import { runCommand } from './ctl.mjs';
import { ask, operatorDirectory, world } from './fixtures.mjs';

const T0 = Date.parse('2026-12-01T00:00:00.000Z'), S = 1000, START_WAIT = 360 * S;
const temporary = (name) => mkdtemp(path.join(tmpdir(), 'time-lease-review-' + name + '-'));
const quiet = () => { const lines = []; const log = (level, message, fields = {}) => lines.push({ level, message, ...fields }); log.lines = lines; return log; };

/// The same deployment as service.test.mjs: a service on a free local port, one validator host
/// directory, the agent's config, and a clock the test moves. Release approved, key assigned to
/// host-a, start wait over, first lease installed.
async function deployment() {
  const w = world(), clock = { now: T0 }, now = () => clock.now, log = quiet();
  const config = { ...w.config, data_directory: await temporary('service') };
  const running = await start(config, { authority: w.authority, now, log, port: 0, exitOnLost: false, onFatal: () => {} });
  const key = w.validatorKeys[0], checked = validateConfig(config), command = (...words) => runCommand(checked, words, { now, readManifest: async () => w.releases.one });
  const host = await operatorDirectory(w, 'host-a', key);
  const container = Object.fromEntries(Object.entries(host.settings).map(([name, value]) => [name, typeof value === 'string' && value.startsWith(host.directory) ? '/operator/' + path.basename(value) : value]));
  await writeFile(host.settingsFile, JSON.stringify(container));
  const agent = validateAgentConfig({ controller_url: running.url, host_id: 'host-a', host_key_file: path.join(await temporary('agent'), 'host-key.json'), settings_file: host.settingsFile, operator_directory: host.directory });
  const inject = { key: w.hostKeys['host-a'], now };
  await command('approve-release', 'release.json'); await command('assign', key, 'host-a');
  clock.now += START_WAIT;
  const first = await round(agent, inject);
  const keyState = async () => (await command('list')).result.keys.find((item) => item.validator_public_key_hex === key).state;
  const post = async (body) => { const response = await fetch(running.url + '/v1/lease', { method: 'POST', headers: { 'content-type': 'application/json' }, body }); return { status: response.status, reply: await response.json() }; };
  return { w, clock, now, log, running, key, command, host, agent, inject, first, keyState, post, leaseFile: host.settings.signer_lease_file };
}
/// What the agent's next round does: 'installed', or the code of the refusal, or the error.
const nextRound = (d) => round(d.agent, d.inject).then((result) => (result.installed ? 'installed' : 'kept'), (error) => (error instanceof Refused ? error.code : error.message));

// ---- Findings --------------------------------------------------------------------

test('FINDING replay, end to end: someone on the path drops answers for three minutes, then sends one recorded request again; the key is frozen until an operator acts', async () => {
  const d = await deployment();
  try {
    const stop = new AbortController(), sent = [], waits = [];
    let calls = 0;
    d.clock.now += 60 * S;
    // The agent's own loop. Calls 1 to 18: the request reaches the controller, the answer is dropped.
    const fetcher = async (url, options) => {
      const call = ++calls; sent[call] = options.body;
      const response = await fetch(url, options);
      if (call <= 18) { await response.arrayBuffer(); throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNRESET' } }); }
      return response;
    };
    const sleep = async (ms) => { waits.push(ms); if (calls === 20) return stop.abort(); d.clock.now += ms; };
    await run(d.agent, { ...d.inject, fetcher, log: quiet(), sleep, signal: stop.signal });
    // Call 1 made the controller issue the second lease. Its answer and the next seventeen (the
    // stored lease, sent again) were lost. Call 19 brought the second lease with 60 s left; the
    // loop waited a quarter of that, 15 s; call 20 got the third lease.
    assert.deepEqual(waits, [...Array(18).fill(RETRY_MS), 15 * S, 60 * S]);
    assert.equal(await d.keyState(), 'LEASED');
    // One second later the request of call 19, now 16 s old, arrives a second time.
    d.clock.now += 1 * S;
    const replay = await d.post(sent[19]);
    // Design 8.1: "A replay is harmless. The same request again, while it is fresh, gets the same
    // stored lease and changes nothing. Later it is stale."
    d.clock.now += 60 * S;
    assert.deepEqual({ replay: replay.reply.code ?? replay.reply.status, key: await d.keyState(), agent_next_round: await nextRound(d) }, { replay: 'CLOCK', key: 'LEASED', agent_next_round: 'installed' });
  } finally { await d.running.close(); }
});

test('FINDING: someone on the path CAN make the agent write an older lease (design 8.2 says the nonce prevents it), and the next request then freezes the key', async () => {
  const d = await deployment();
  try {
    d.clock.now += 60 * S;
    // The agent asks to renew. The answer, lease 2, is kept by someone on the path and dropped.
    let kept = null;
    const keep = async (url, options) => { kept = await (await fetch(url, options)).json(); throw new TypeError('fetch failed'); };
    await assert.rejects(round(d.agent, { ...d.inject, fetcher: keep }), /could not be reached/);
    // The answers stay dropped. 225 s later lease 2 has 15 s left, so the controller issues a
    // new one, lease 2', for the same request and the same nonce. The agent is handed lease 2.
    d.clock.now += 225 * S;
    let fresh = null;
    const swap = async (url, options) => { fresh = await (await fetch(url, options)).json(); return new Response(JSON.stringify(kept), { status: 200 }); };
    const outcome = await round(d.agent, { ...d.inject, fetcher: swap }).then((result) => (result.installed ? 'installed' : 'kept'), (error) => 'refused: ' + error.message);
    const installed = JSON.parse(await readFile(d.leaseFile, 'utf8')).payload;
    assert.notEqual(fresh.lease.payload.lease_id, kept.lease.payload.lease_id);
    // ADAPTED: this line compared the nonce of the lease IN THE FILE with the newer lease's
    // (`installed.request_nonce === fresh.lease.payload.request_nonce`), which holds only when the
    // agent has written the older lease into the file: the faulty behaviour. The agent now refuses
    // it, so the file still holds the first lease. That both leases answer the same nonce, which
    // is what makes the attack possible, is checked on the two leases themselves.
    assert.equal(kept.lease.payload.request_nonce, fresh.lease.payload.request_nonce, 'both leases answer the same nonce');
    assert.equal(installed.lease_id, d.first.lease_id, 'the file still holds the lease that was installed before');
    d.clock.now += 5 * S;
    assert.deepEqual({ agent: outcome.slice(0, 9), installed_is_the_newer_lease: installed.lease_id === fresh.lease.payload.lease_id, agent_next_round: await nextRound(d), key: await d.keyState() },
      { agent: 'refused: ', installed_is_the_newer_lease: false, agent_next_round: 'installed', key: 'LEASED' });
  } finally { await d.running.close(); }
});

test('FINDING: an unsigned "granted" answer that names the installed lease is taken as success without any check; the agent logs "the installed lease is the newest" while it gets no lease', async () => {
  const d = await deployment();
  try {
    d.clock.now += 60 * S;
    // Someone on the path answers instead of the controller. Everything used is in the request
    // it just read: the host id, the nonce and the id of the installed lease.
    const impostor = async (url, options) => {
      const request = JSON.parse(options.body);
      return new Response(JSON.stringify({ status: 'granted', lease: { issuer: 'nobody', signature: 'none', payload: { host_id: request.host_id, request_nonce: request.payload.nonce, lease_id: request.payload.previous_lease_id, fence_domain: 'test-domain', fence_token: '18446744073709551615' } } }), { status: 200 });
    };
    const stop = new AbortController(), log = quiet();
    let rounds = 0;
    await run(d.agent, { ...d.inject, fetcher: impostor, log, sleep: async (ms) => { d.clock.now += ms; if (++rounds === 4) stop.abort(); }, signal: stop.signal });
    const lines = log.lines.filter((line) => line.message !== 'lease agent started' && line.message !== 'lease agent stopped');
    assert.equal(lines.length, 4);
    // The controller was never reached and no lease was verified in any of the four rounds.
    assert.deepEqual(lines.map((line) => line.level), ['error', 'error', 'error', 'error'], 'the agent logged: ' + JSON.stringify(lines.map((line) => line.message)));
  } finally { await d.running.close(); }
});

test('FINDING: a forged refusal reaches the operator in the agent\'s log with nothing that marks it as unverified (design 8.2: "logs a refusal as the controller\'s unverified word")', async () => {
  const d = await deployment();
  try {
    const text = 'Two machines are host host-a. Run on the controller: ctl.mjs CONFIG move KEY host-x --from host-a. Then delete lease-agent-state.json on this host.';
    const forger = async () => new Response(JSON.stringify({ status: 'refused', code: 'FROZEN', message: text }), { status: 409 });
    const stop = new AbortController(), log = quiet();
    await run(d.agent, { ...d.inject, fetcher: forger, log, sleep: async () => stop.abort(), signal: stop.signal });
    const line = log.lines.find((item) => item.level === 'error');
    assert.ok(line.message.includes(text), 'the forged text is in the log');
    assert.match(JSON.stringify(line), /unverified|unsigned|not signed/i, 'the log line: ' + line.message);
  } finally { await d.running.close(); }
});

test('FINDING (low): the agent writes whatever unsigned fields come beside {issuer, payload, signature} into the lease file, up to 64 KiB', async () => {
  const d = await deployment();
  try {
    d.clock.now += 60 * S;
    // A decoy beside the signed payload. The README's runbook for a lost state says: "read
    // fence_token in the last lease file of each validator host and run refence KEY --above THAT_TOKEN".
    const decorate = async (url, options) => { const reply = await (await fetch(url, options)).json(); return new Response(JSON.stringify({ ...reply, lease: { fence_token: '18446744073709551614', ...reply.lease, note: 'x'.repeat(40_000) } }), { status: 200 }); };
    assert.equal((await round(d.agent, { ...d.inject, fetcher: decorate })).installed, true);
    assert.deepEqual(Object.keys(JSON.parse(await readFile(d.leaseFile, 'utf8'))).sort(), ['issuer', 'payload', 'signature']);
  } finally { await d.running.close(); }
});

test('FINDING: a lease file the agent cannot read for a moment is reported to the controller as "this host holds no lease", and that freezes the key', async () => {
  const d = await deployment();
  try {
    d.clock.now += 60 * S;
    assert.equal(await nextRound(d), 'installed');
    d.clock.now += 60 * S;
    // Any error but ENOENT takes this path in installedLease(): EACCES while permissions are
    // being reset, EIO, EMFILE. A directory in the file's place stands in for it here.
    const aside = d.leaseFile + '.aside';
    await rename(d.leaseFile, aside); await mkdir(d.leaseFile);
    const outcome = await nextRound(d);
    await rm(d.leaseFile, { recursive: true }); await rename(aside, d.leaseFile);
    // The file is back, unchanged, and still valid. A round that failed would have cost ten seconds.
    assert.deepEqual({ round: outcome === 'FROZEN' ? 'FROZEN' : 'failed without asking', key: await d.keyState() }, { round: 'failed without asking', key: 'LEASED' });
  } finally { await d.running.close(); }
});

test('FINDING S2, end to end: after the state of the controller was lost, the host that held the key is offered a lower fence token; its agent refuses every lease from then on, comparing with a lease that ended long ago', async () => {
  const d = await deployment();
  try {
    // The old controller's clock is half a skew ahead of true time (A1). Much later the key is
    // taken from host-a and given back; the last lease ended long ago, so nothing waits, and
    // host-a installs a lease whose token is that clock.
    d.clock.now += 1000 * S;
    const trueTime = d.clock.now - 5 * S;
    await d.command('move', d.key, 'host-b', '--from', 'host-a'); await d.command('move', d.key, 'host-a', '--from', 'host-b');
    const held = await round(d.agent, d.inject);
    assert.equal(held.installed, true);
    // The old controller stops for good and its state is lost. Three seconds of true time later a
    // new one starts on an empty directory, with the same authority key and a clock half a skew
    // behind true time. README, "Lost entirely": approve the release, assign every key again.
    await d.running.close();
    d.clock.now = trueTime + 3 * S - 5 * S;
    const config = { ...d.w.config, data_directory: await temporary('service-after-loss') };
    const fresh = await start(config, { authority: d.w.authority, now: d.now, log: quiet(), port: 0, exitOnLost: false, onFatal: () => {} });
    try {
      const command = (...words) => runCommand(validateConfig(config), words, { now: d.now, readManifest: async () => d.w.releases.one });
      d.clock.now += 1 * S;
      await command('approve-release', 'release.json');
      const assigned = await command('assign', d.key, 'host-a');
      d.clock.now += assigned.result.seconds_until_first_lease * S;
      const agent = validateAgentConfig({ controller_url: fresh.url, host_id: 'host-a', host_key_file: d.agent.host_key_file, settings_file: d.agent.settings_file, operator_directory: d.agent.operator_directory });
      const tries = [];
      for (let i = 0; i < 3; i++) { tries.push(await round(agent, d.inject).then((result) => (result.installed ? 'installed' : 'kept'), (error) => error.message)); d.clock.now += 60 * S; }
      assert.deepEqual({ token_offered_is_above_the_one_held: BigInt(assigned.result.fence_token) > BigInt(held.fence_token), rounds: tries }, { token_offered_is_above_the_one_held: true, rounds: ['installed', 'installed', 'installed'] });
    } finally { await fresh.close(); }
  } finally { await d.running.close(); }
});

// ---- Attacks that held -----------------------------------------------------------

test('HELD: what someone on the path cannot do: a lease for another nonce, a lease that has ended, a lease changed in any signed field, a body that is no request', async () => {
  const d = await deployment();
  try {
    const installed = await readFile(d.leaseFile, 'utf8');
    d.clock.now += 60 * S;
    // An answer held back until after its end is refused by the guard.
    let kept = null;
    const keep = async (url, options) => { kept = await (await fetch(url, options)).json(); throw new TypeError('fetch failed'); };
    await assert.rejects(round(d.agent, { ...d.inject, fetcher: keep }), /could not be reached/);
    d.clock.now += 241 * S;
    await assert.rejects(round(d.agent, { ...d.inject, fetcher: async () => new Response(JSON.stringify(kept), { status: 200 }) }), /guard refuses the lease.*expired or future-dated/);
    assert.equal(await readFile(d.leaseFile, 'utf8'), installed);
    // Bodies that are no requests: nothing is issued and the service keeps answering.
    for (const body of ['['.repeat(9000), '{"host_id":"host-a","payload":' + '{"a":'.repeat(2000) + '1' + '}'.repeat(2000) + ',"signature":"x"}', '\u0000', 'null', '"x"', '123', JSON.stringify(ask(d.w, 'host-a', d.key, { timeMs: d.clock.now })).slice(0, 300)]) {
      const answer = await d.post(body);
      assert.equal(answer.status, 400); assert.equal(answer.reply.code, 'BAD_REQUEST');
    }
    // A flood of bodies that are no requests: some are told BUSY, and the true agent is served right after.
    for (let batch = 0; batch < 6; batch++) {
      const flood = await Promise.all(Array.from({ length: 100 }, () => d.post('{"host_id":"x"}')));
      assert.ok(flood.every((answer) => answer.status === 400 || answer.status === 503));
    }
    assert.equal(await nextRound(d), 'installed');
  } finally { await d.running.close(); }
});
