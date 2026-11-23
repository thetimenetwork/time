// Independent review of the signer-lease controller: the decisions (core.mjs) and the service's
// handling of its state (start.mjs, store.mjs, ctl.mjs).
//
// A test named FINDING states something the design claims, or an operator relies on, and FAILS
// against the code under review: the failure is the finding. A test named HELD is an attack that
// did not work, and passes. Nothing here changes the code under review.
import test from 'node:test';
import assert from 'node:assert/strict';
import { sign as edSign } from 'node:crypto';
import { cp, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { guard } from '../operator.mjs';
import { GUARD_MAX_LEASE_MS, checkRequestShape, newNonce, requestBytes, verifyRequest } from '../lease-protocol.mjs';
import { applyStart, approveRelease, assign, decide, emptyState, move, timing, validateState } from './core.mjs';
import { createController, validateConfig } from './start.mjs';
import { fileStore, memoryStore } from './store.mjs';
import { runCommand } from './ctl.mjs';
import { ask, operatorDirectory, world } from './fixtures.mjs';

const T0 = Date.parse('2026-12-01T00:00:00.000Z');
const S = 1000, SKEW = 10 * S, LEASE = 240 * S, STOP = 40 * S, MARGIN = 2 * SKEW + STOP, SPACING = 3 * SKEW + S, START_WAIT = 300 * S + MARGIN;

/// The same bench as core.test.mjs: a state, a clock the test moves, and the pure functions.
function bench(w, at = T0) {
  const self = {
    state: emptyState(w.config, at), now: at,
    advance(ms) { self.now += ms; return self; },
    command(change, ...rest) { self.state = change(self.state, ...rest); return self; },
    request(envelope) { const { reply, next } = decide(self.state, w.config, envelope, self.now, w.sign); if (next) self.state = validateState(next); return reply; },
    ask(hostId, validatorKey, options = {}) { return self.request(ask(w, hostId, validatorKey, { timeMs: self.now, ...options })); },
  };
  return self;
}
function ready(w = world()) {
  const b = bench(w), key = w.validatorKeys[0];
  b.command(approveRelease, w.releases.one).command(assign, w.config, key, 'host-a', b.now);
  b.advance(START_WAIT);
  return { w, b, key };
}
const granted = (reply) => { assert.equal(reply.status, 'granted', reply.message); return reply.lease.payload; };
/// Whether the kit's real guard accepts `lease` on `hostId` at `hostNow`.
async function guardAccepts(w, hostId, key, lease, hostNow) {
  const host = await operatorDirectory(w, hostId, key);
  await writeFile(host.settings.signer_lease_file, JSON.stringify(lease));
  try { await guard(host.settings, hostNow); return true; } catch { return false; }
}

// ---- Findings --------------------------------------------------------------------

test('FINDING replay: a recorded request that is sent again while fresh freezes the key (design 8.1: "A replay is harmless")', () => {
  const { w, b, key } = ready();
  const first = granted(b.ask('host-a', key));
  // The agent renews after a quarter of the lease. The controller issues the second lease; the
  // answer is lost on the way back.
  b.advance(60 * S);
  const nonce = newNonce(), second = granted(b.ask('host-a', key, { previous: first.lease_id, nonce }));
  // The agent repeats the request every ten seconds with the same nonce (lease-agent.mjs, RETRY_MS)
  // and the controller sends the stored lease each time. Someone on the network path, who by
  // section 8.2 "can drop or delay traffic", drops the answers for 180 s and then lets one through.
  let recorded;
  for (let i = 0; i < 18; i++) { b.advance(10 * S); recorded = ask(w, 'host-a', key, { timeMs: b.now, previous: first.lease_id, nonce }); assert.equal(granted(b.request(recorded)).lease_id, second.lease_id); }
  // The host installs the second lease with 60 s left. The agent's loop then waits
  // max(5 s, a quarter of what is left) = 15 s and asks again, naming the second lease.
  const left = Date.parse(second.expires_utc) - b.now;
  assert.equal(left, 60 * S);
  b.advance(Math.max(5 * S, Math.floor(left / 4)));
  granted(b.ask('host-a', key, { previous: second.lease_id }));
  // One second later the recorded request (16 s old, so inside the freshness window) arrives again.
  b.advance(1 * S);
  const before = JSON.stringify(b.state), replayed = b.request(recorded);
  assert.notEqual(replayed.code, 'FROZEN', 'the replay froze the key: ' + replayed.message);
  assert.equal(JSON.stringify(b.state), before, 'a replay changes nothing');
});

test('FINDING S2: a controller that lost its state gives a key a LOWER fence token than the lost controller put into a lease seconds before, with every clock inside A1', () => {
  const { w, b, key } = ready();
  granted(b.ask('host-a', key));
  // Much later. The old controller's clock is half a skew ahead of true time, which A1 allows.
  // The operator moves the key; the last lease ended long ago, so host-b gets a lease at once,
  // with a token taken from that clock.
  const trueTime = b.advance(1000 * S).now;
  b.now = trueTime + SKEW / 2;
  b.command(move, w.config, key, 'host-b', 'host-a', b.now);
  const old = granted(b.ask('host-b', key));
  assert.equal(old.fence_token, String(trueTime + SKEW / 2));
  // The old controller stops for good (A2) and its state is lost. Three seconds of true time
  // later a new controller starts on a machine whose clock is half a skew behind true time, on an
  // empty data directory (README, "Lost entirely"): the service starts, then the operator
  // approves the release and assigns the key again.
  const fresh = bench(w, trueTime + 3 * S - SKEW / 2);
  fresh.state = applyStart(fresh.state, w.config, fresh.now); // createController.open() on an empty directory
  const startedAt = fresh.now;
  fresh.advance(1 * S).command(approveRelease, w.releases.one).command(assign, w.config, key, 'host-c', fresh.now);
  // S1 is kept: the key waits.
  // ADAPTED: this line asserted `not_before_ms === startedAt + START_WAIT`, a wait counted from the
  // controller's START. Taking every wait from the clock at the start is what finding 1 names as
  // its cause, so a key that enters the state now waits START_WAIT counted from the command that
  // brings it in, which is one second later here. The wait is never shorter than what was asserted.
  assert.equal(fresh.state.keys[key].not_before_ms, startedAt + 1 * S + START_WAIT);
  assert.ok(fresh.state.keys[key].not_before_ms >= startedAt + START_WAIT);
  fresh.now = fresh.state.keys[key].not_before_ms;
  const next = granted(fresh.ask('host-c', key));
  // Design, section 12, "The state is lost": "Tokens come from the clock plus five minutes."
  // Section 5.4: "It takes its clock plus five minutes, and under A1 that is above the clock of
  // any earlier controller at any earlier moment".
  // Claim S2: a lease for another host carries a strictly higher token.
  const seen = { token_is_clock_plus_five_minutes: BigInt(next.fence_token) >= BigInt(startedAt + GUARD_MAX_LEASE_MS), token_above_the_one_issued_before: BigInt(next.fence_token) > BigInt(old.fence_token) };
  assert.deepEqual(seen, { token_is_clock_plus_five_minutes: true, token_above_the_one_issued_before: true }, `host-c's token ${next.fence_token} against host-b's ${old.fence_token}; the new controller started at ${startedAt}`);
});

test('FINDING (outside A1, and nothing checks it): a controller that starts while its machine clock is behind skips the whole start wait once the clock is corrected; two hosts then hold leases the real guard accepts at the same moment', async () => {
  const { w, b, key } = ready();
  // The old controller issues a lease to host-a and, a second later, is lost with its state.
  const tau = b.now, held = b.ask('host-a', key).lease;
  // A replacement machine boots. The service is started before NTP has set the clock, which
  // reads ten minutes behind (a machine without a battery clock reads the time of its last shutdown).
  const clock = { now: tau + 5 * S - 600 * S }, now = () => clock.now, store = memoryStore();
  const controller = createController({ config: w.config, store, sign: w.sign, now });
  await controller.open();
  // Seconds later NTP steps the clock to the right time. The service is not restarted.
  clock.now = tau + 20 * S;
  // README, "Lost entirely": "Approve the release and assign every key again. Each waits 360 s
  // from the start." The operator gives the key to the host that is up.
  const config = validateConfig(w.config), command = (...words) => runCommand(config, words, { store, now, readManifest: async () => w.releases.one });
  await command('approve-release', 'release.json');
  const assigned = await command('assign', key, 'host-b');
  clock.now = tau + 30 * S;
  const reply = await controller.submit(ask(w, 'host-b', key, { timeMs: clock.now }));
  const both = reply.status === 'granted' && await guardAccepts(w, 'host-a', key, held, clock.now) && await guardAccepts(w, 'host-b', key, reply.lease, clock.now);
  assert.deepEqual({ state_after_assign: assigned.result.state, both_leases_accepted_by_the_real_guard: both }, { state_after_assign: 'WAITING', both_leases_accepted_by_the_real_guard: false }, 'host-a and host-b both hold a lease the real guard accepts, 30 s after the old controller stopped');
});

test('FINDING: state files put back under a RUNNING service and then changed by commands are followed without the start rule; two hosts hold leases the real guard accepts at the same moment', async () => {
  const w = world(), key = w.validatorKeys[0], directory = await mkdtemp(path.join(tmpdir(), 'time-lease-review-')), clock = { now: T0 }, now = () => clock.now;
  const config = validateConfig({ ...w.config, data_directory: directory }), command = (...words) => runCommand(config, words, { now, readManifest: async () => w.releases.one });
  const controller = createController({ config, store: fileStore(directory), sign: w.sign, now });
  await controller.open();
  await command('approve-release', 'release.json'); await command('assign', key, 'host-a');
  clock.now += START_WAIT;
  const first = (await controller.submit(ask(w, 'host-a', key, { timeMs: clock.now }))).lease;
  // The operator copies the state directory (a backup).
  const backup = await mkdtemp(path.join(tmpdir(), 'time-lease-review-backup-'));
  await cp(path.join(directory, 'state'), backup, { recursive: true });
  // host-a renews twice. Its newest lease ends 360 s after the first one was issued.
  let last = first;
  for (let i = 0; i < 2; i++) { clock.now += 60 * S; last = (await controller.submit(ask(w, 'host-a', key, { timeMs: clock.now, previous: last.payload.lease_id }))).lease; }
  // The mistake: the operator puts the backup back WITHOUT stopping the service, and gives three
  // commands (the newest file number then passes the number the service holds in memory).
  clock.now += 5 * S;
  await rm(path.join(directory, 'state'), { recursive: true }); await cp(backup, path.join(directory, 'state'), { recursive: true });
  await command('move', key, 'host-b', '--from', 'host-a');
  await command('assign', w.validatorKeys[1], 'host-c');
  await command('unassign', w.validatorKeys[1]);
  // Design 5.2: "If the newest file is older than its own, the files were replaced under it: it
  // stops." Here the newest file is newer, and the service follows it as if it were its own.
  const moved = (await fileStore(directory).read()).state.keys[key];
  clock.now = moved.not_before_ms;
  let reply = null, stopped = false;
  try { reply = await controller.submit(ask(w, 'host-b', key, { timeMs: clock.now })); } catch { stopped = true; }
  const both = !stopped && reply.status === 'granted' && await guardAccepts(w, 'host-a', key, last, clock.now) && await guardAccepts(w, 'host-b', key, reply.lease, clock.now);
  assert.equal(both, false, `host-b was given a lease ${(Date.parse(last.payload.expires_utc) - clock.now) / 1000} s before host-a's lease ends; the service neither stopped nor applied the start rule`);
});

test('FINDING (outside A1, and nothing checks it): one start while the machine clock reads an hour ahead makes every key wait an hour, also after a restart with the right clock; no command shortens it', async () => {
  const w = world(), key = w.validatorKeys[0], clock = { now: T0 }, now = () => clock.now, store = memoryStore();
  const config = validateConfig(w.config), command = (...words) => runCommand(config, words, { store, now, readManifest: async () => w.releases.one });
  const open = async () => { const controller = createController({ config, store, sign: w.sign, now }); await controller.open(); return controller; };
  let controller = await open();
  await command('approve-release', 'release.json'); await command('assign', key, 'host-a');
  clock.now += START_WAIT;
  assert.equal((await controller.submit(ask(w, 'host-a', key, { timeMs: clock.now }))).status, 'granted');
  // The machine reboots. The service comes up before the clock is set; it reads an hour ahead.
  const right = clock.now + 30 * S;
  clock.now = right + 3600 * S; controller = await open();
  // The clock is corrected and the operator restarts the service.
  // ADAPTED: here the test restarted the service and went on (`controller = await open()`), which
  // relied on a start that accepts a state written with a later clock. The corrected service
  // refuses that start and every command, as required, and says what to check; the operator
  // checks the clock and runs the documented way out, "clock-was-ahead", and then starts. The
  // assertion at the end is unchanged: after that, no wait is longer than the start wait.
  clock.now = right + 20 * S;
  await assert.rejects(open(), /FIRST check this machine's clock.*"clock-was-ahead"/s);
  await assert.rejects(command('refence', key), /FIRST check this machine's clock/);
  await assert.rejects(command('assign', w.validatorKeys[1], 'host-c'), /FIRST check this machine's clock/);
  assert.match((await command('list')).result.warning, /FIRST check this machine's clock/);
  await command('clock-was-ahead');
  controller = await open();
  const waits = { after_restart: (await command('list')).result.keys[0].seconds_until_first_lease };
  // What an operator can try. Each is a new tenure that keeps the old not_before or adds to it.
  await command('refence', key); waits.after_refence = (await command('list')).result.keys[0].seconds_until_first_lease;
  await command('move', key, 'host-b', '--from', 'host-a'); waits.after_move = (await command('list')).result.keys[0].seconds_until_first_lease;
  await command('unassign', key); await command('assign', key, 'host-a'); waits.after_unassign_and_assign = (await command('list')).result.keys[0].seconds_until_first_lease;
  // The design's longest wait is the start wait, 360 s. Here only deleting the state ends it.
  for (const [name, seconds] of Object.entries(waits)) assert.ok(seconds <= 360, name + ': the key waits ' + seconds + ' s; all: ' + JSON.stringify(waits));
});

test('FINDING (operator trap): one "refence --above" near the largest token is accepted, and the controller can then never start again on its state', async () => {
  const w = world(), key = w.validatorKeys[0], clock = { now: T0 }, now = () => clock.now, store = memoryStore();
  const config = validateConfig(w.config), command = (...words) => runCommand(config, words, { store, now, readManifest: async () => w.releases.one });
  await createController({ config, store, sign: w.sign, now }).open();
  await command('approve-release', 'release.json'); await command('assign', key, 'host-a');
  // A digit too many, or a decoy read from a lease file (see review-service.test.mjs).
  // ADAPTED: these two lines asserted that the command is ACCEPTED and yields the largest token
  // (`done.result.fence_token === '18446744073709551615'`). The corrected command refuses a floor
  // that no clock could have produced, as required ("bound it"). The other half of the finding,
  // that one key must never keep the controller from starting, is still checked below: the state
  // the faulty command left behind, a key that holds the largest token, is put in place directly.
  await assert.rejects(command('refence', key, '--above', '18446744073709551614'), /not a fence token this controller could have issued/);
  await assert.rejects(command('refence', key, '--above', String(clock.now + 101 * 366 * 86_400_000)), /not a fence token this controller could have issued/);
  const loaded = await store.read(), poisoned = structuredClone(loaded.state);
  poisoned.keys[key].fence_token = '18446744073709551615';
  await command('assign', w.validatorKeys[1], 'host-b');
  const newest = await store.read();
  await store.write(newest.seq + 1, { ...newest.state, keys: { ...newest.state.keys, [key]: poisoned.keys[key] } }, newest.sha256);
  clock.now += 60 * S;
  // Every later start, and every later move, unassign, unfreeze or refence of that key, throws.
  await assert.doesNotReject(createController({ config, store, sign: w.sign, now }).open(), 'the service cannot start: applyStart throws for the whole state');
  // The key that cannot get a new token is frozen and says why; the other key is not touched by it.
  const after = (await command('list')).result.keys;
  assert.equal(after.find((item) => item.validator_public_key_hex === key).state, 'FROZEN');
  assert.match(after.find((item) => item.validator_public_key_hex === key).frozen_because, /largest number/);
  assert.equal(after.find((item) => item.validator_public_key_hex === w.validatorKeys[1]).state, 'WAITING');
});

test('FINDING (low): a signed request dated beyond the range of a JavaScript date makes decide() throw instead of refusing', () => {
  const { w, b, key } = ready();
  // 8.7e15 is a safe integer, so the form check passes; new Date(8.7e15).toISOString() throws.
  assert.doesNotThrow(() => b.request(ask(w, 'host-a', key, { timeMs: 8_700_000_000_000_000 })));
});

// ---- Attacks that held -----------------------------------------------------------

test('HELD: JSON tricks in a request are refused before anything is decided', () => {
  const { w, b, key } = ready(), good = ask(w, 'host-a', key, { timeMs: b.now }), text = JSON.stringify(good);
  const refusedAs = (envelope, code) => { const before = JSON.stringify(b.state), reply = b.request(envelope); assert.equal(reply.status, 'refused'); assert.equal(reply.code, code, reply.message); assert.equal(JSON.stringify(b.state), before); };
  // __proto__ as an own key of the envelope and of the payload, as JSON.parse makes it.
  refusedAs(JSON.parse(text.replace('{"host_id"', '{"__proto__":{"host_id":"host-b"},"host_id"')), 'BAD_REQUEST');
  refusedAs(JSON.parse(text.replace('"payload":{', '"payload":{"__proto__":{"engine":"v5"},')), 'BAD_REQUEST');
  // Arrays for objects, numbers as strings, strings as numbers, a nested object for a string.
  refusedAs([good.host_id, good.payload, good.signature], 'BAD_REQUEST');
  refusedAs({ ...good, payload: Object.entries(good.payload) }, 'BAD_REQUEST');
  refusedAs({ ...good, payload: { ...good.payload, time_ms: String(good.payload.time_ms) } }, 'BAD_REQUEST');
  refusedAs({ ...good, payload: { ...good.payload, version: '1' } }, 'BAD_REQUEST');
  refusedAs({ ...good, payload: { ...good.payload, nonce: 123 } }, 'BAD_REQUEST');
  refusedAs({ ...good, payload: { ...good.payload, host_id: { toString: () => 'host-a' } } }, 'BAD_REQUEST');
  refusedAs({ ...good, payload: { ...good.payload, time_ms: 1.5 } }, 'BAD_REQUEST');
  refusedAs({ ...good, payload: { ...good.payload, time_ms: 2 ** 53 } }, 'BAD_REQUEST');
  // Unicode look-alikes and upper case in names; a consensus key in upper case.
  refusedAs({ ...good, host_id: 'host-а', payload: { ...good.payload, host_id: 'host-а' } }, 'BAD_REQUEST'); // Cyrillic a
  refusedAs({ ...good, host_id: 'Host-A', payload: { ...good.payload, host_id: 'Host-A' } }, 'BAD_REQUEST');
  refusedAs({ ...good, payload: { ...good.payload, validator_public_key_hex: key.toUpperCase() } }, 'BAD_REQUEST');
  // A duplicate key: the parser keeps the last one, and the signature is over the parsed value,
  // so the request is judged as what it parses to. Here that is another key than the signed one.
  refusedAs(JSON.parse(text.replace('"validator_public_key_hex":', `"validator_public_key_hex":"${w.validatorKeys[1]}","validator_public_key_hex_":`).replace('"validator_public_key_hex_":', '"x":')), 'BAD_REQUEST');
  refusedAs(JSON.parse(text.replace(`"validator_public_key_hex":"${key}"`, `"validator_public_key_hex":"${key}","validator_public_key_hex":"${w.validatorKeys[1]}"`)), 'BAD_SIGNATURE');
  // The true request is still served afterwards.
  granted(b.request(good));
});

test('HELD: a changed, truncated or malleated signature does not verify; NOTE: sixteen base64 spellings of one signature are accepted', () => {
  const { w, b, key } = ready(), good = ask(w, 'host-a', key, { timeMs: b.now }), publicKey = w.hostKeys['host-a'].publicKeyHex;
  assert.equal(verifyRequest(good, publicKey), true);
  const raw = Buffer.from(good.signature, 'base64');
  // S + L (the classic Ed25519 malleation): refused by the library.
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const s = BigInt('0x' + Buffer.from(raw.subarray(32)).reverse().toString('hex')) + L;
  const malleated = Buffer.concat([raw.subarray(0, 32), Buffer.from(s.toString(16).padStart(64, '0'), 'hex').reverse()]);
  assert.equal(verifyRequest({ ...good, signature: malleated.toString('base64') }, publicKey), false);
  // A signature over the payload with the ATTESTATION prefix, or without a prefix, is not a request signature.
  for (const bytes of [Buffer.from('TIME-OPERATOR-ATTESTATION-V1\0' + requestBytes(good.payload).toString().split('\0')[1]), Buffer.from(requestBytes(good.payload).toString().split('\0')[1])]) {
    assert.equal(verifyRequest({ ...good, signature: edSign(null, bytes, w.hostKeys['host-a'].privateKey).toString('base64') }, publicKey), false);
  }
  assert.throws(() => checkRequestShape({ ...good, signature: good.signature.slice(0, 80) }), /signature/);
  assert.throws(() => checkRequestShape({ ...good, signature: good.signature.replace(/==$/, '') }), /signature/);
  // NOTE (low): the last character before "==" carries four bits that no decoder reads. The
  // form check /^[A-Za-z0-9+/]{86}==$/ (also in lib.mjs, where the error says "Noncanonical")
  // accepts all sixteen spellings. Nothing here keys on the signature text, so this is harmless.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', lastChar = good.signature[85];
  const others = [...alphabet].filter((c) => c !== lastChar && (alphabet.indexOf(c) >> 4) === (alphabet.indexOf(lastChar) >> 4));
  assert.equal(others.length, 15);
  for (const c of others) assert.equal(verifyRequest({ ...good, signature: good.signature.slice(0, 85) + c + '==' }, publicKey), true);
});

test('HELD: a host that is not the holder can neither get, freeze nor delay another host\'s key, whatever it names', () => {
  const { w, b, key } = ready(), first = granted(b.ask('host-a', key));
  b.advance(SPACING);
  const before = JSON.stringify(b.state);
  for (const options of [{}, { previous: first.lease_id }, { previous: 'x', nonce: first.request_nonce }, { previous: first.lease_id, nonce: first.request_nonce }, { scope: { signer_identity: 'signer-of-host-a' } }]) {
    const reply = b.ask('host-b', key, options);
    assert.equal(reply.code, 'NOT_HOLDER'); assert.equal(JSON.stringify(b.state), before);
  }
  // host-b signs a request that names host-a: the envelope and the payload must agree, and the signature must be host-a's.
  const forged = ask(w, 'host-a', key, { timeMs: b.now, previous: first.lease_id, key: w.hostKeys['host-b'] });
  assert.equal(b.request(forged).code, 'BAD_SIGNATURE'); assert.equal(JSON.stringify(b.state), before);
  granted(b.ask('host-a', key, { previous: first.lease_id }));
});

test('HELD: a config edited between two starts (a shorter lease, a smaller skew and stop time) does not shorten the wait for a lease of the earlier process', () => {
  // The earlier process ran with the longest lease a config allows.
  const long = world({ settings: { lease_seconds: 280, clock_skew_seconds: 10, stop_seconds: 40 } }), { b, key } = ready(long);
  const held = granted(b.ask('host-a', key)), expiry = Date.parse(held.expires_utc);
  // It is stopped one second later and started with the smallest margin a config allows.
  const short = { ...long.config, lease_seconds: 60, clock_skew_seconds: 1, stop_seconds: 30 }, s = b.advance(S).now;
  let state = applyStart(b.state, short, s);
  state = move(state, short, key, 'host-b', 'host-a', s + S);
  assert.ok(state.keys[key].not_before_ms >= expiry + timing(short).marginMs);
  // And from an old copy, in which the lease is not recorded at all.
  const fromOld = applyStart(emptyState(short, s), short, s), assigned = assign(approveRelease(fromOld, long.releases.one), short, key, 'host-b', s + S);
  assert.ok(assigned.keys[key].not_before_ms >= expiry + timing(short).marginMs);
});

test('HELD: the controller\'s clock stepping back by a whole skew between two grants never shortens a wait', () => {
  const { w, b, key } = ready(), first = granted(b.ask('host-a', key));
  b.advance(SPACING);
  const second = granted(b.ask('host-a', key, { previous: first.lease_id })), expiry = Date.parse(second.expires_utc);
  // The clock steps back by one skew (from the upper edge of A1 to the lower). The next lease ends
  // EARLIER than the one before it; last_expires must not follow it down.
  b.now += SPACING - SKEW;
  const refusedSoon = b.ask('host-a', key, { previous: second.lease_id });
  assert.equal(refusedSoon.code, 'TOO_SOON');
  b.now += SKEW;
  const third = granted(b.ask('host-a', key, { previous: second.lease_id }));
  b.now -= SKEW; // and back again before the move
  b.command(move, w.config, key, 'host-b', 'host-a', b.now);
  assert.ok(b.state.keys[key].not_before_ms >= Math.max(expiry, Date.parse(third.expires_utc)) + MARGIN);
});
