// The decisions of the signer-lease controller (core.mjs), with an injected clock, and the
// kit's real guard (deploy/operator.mjs) judging what the controller issues.
// docs/design/signer-lease-controller.md, sections 4 to 8 and 15.
import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { guard } from '../operator.mjs';
import { signed } from '../lib.mjs';
import { GUARD_MAX_LEASE_MS, newNonce } from '../lease-protocol.mjs';
import { CommandRefused, applyStart, approveRelease, assign, checkBinding, decide, emptyState, move, rebaseClock, refence, retireRelease, summary, timing, unassign, unfreeze, validateState } from './core.mjs';
import { signer, validateConfig } from './start.mjs';
import { ask, keyPair, manifest, operatorDirectory, world } from './fixtures.mjs';

const T0 = Date.parse('2026-12-01T00:00:00.000Z');
const S = 1000, SKEW = 10 * S, LEASE = 240 * S, STOP = 40 * S, MARGIN = 2 * SKEW + STOP, SPACING = 3 * SKEW + S;

/// A controller without files: a state, a clock that only the test moves, and the pure functions.
function bench(w, at = T0) {
  const self = {
    state: emptyState(w.config, at), now: at,
    advance(ms) { self.now += ms; return self; },
    command(change, ...rest) { self.state = change(self.state, ...rest); return self; },
    request(envelope) { const { reply, next } = decide(self.state, w.config, envelope, self.now, w.sign); if (next) self.state = validateState(next); return reply; },
    /// Host `hostId` asks with its clock at the controller's, holding `previous`.
    ask(hostId, validatorKey, options = {}) { return self.request(ask(w, hostId, validatorKey, { timeMs: self.now, ...options })); },
  };
  return self;
}
/// Release one approved, key 0 given to host-a, and the start wait over.
function ready(w = world()) {
  const b = bench(w), key = w.validatorKeys[0];
  b.command(approveRelease, w.releases.one).command(assign, w.config, key, 'host-a', b.now);
  b.advance(GUARD_MAX_LEASE_MS + MARGIN);
  return { w, b, key };
}
const granted = (reply) => { assert.equal(reply.status, 'granted', reply.message); return reply.lease.payload; };
const refusedWith = (reply, code, pattern) => { assert.equal(reply.status, 'refused'); assert.equal(reply.code, code, reply.message); if (pattern) assert.match(reply.message, pattern); return reply; };

test('the numbers of the design follow from the three settings, and a config that breaks the guard\'s limit is refused', () => {
  const w = world(), t = timing(w.config);
  assert.deepEqual(t, { leaseMs: LEASE, skewMs: SKEW, stopMs: STOP, backdateMs: 2 * SKEW, marginMs: MARGIN, startWaitMs: 300 * S + MARGIN, spacingMs: SPACING });
  assert.equal(GUARD_MAX_LEASE_MS, 300 * S);
  const base = { data_directory: w.config.data_directory, authority_key_file: w.config.authority_key_file, fence_domain: 'd', network: w.config.network, hosts: w.config.hosts };
  const checked = validateConfig(base);
  assert.deepEqual([checked.lease_seconds, checked.clock_skew_seconds, checked.stop_seconds, checked.host, checked.port], [240, 10, 40, '127.0.0.1', 8960]);
  assert.throws(() => validateConfig({ ...base, lease_seconds: 280, clock_skew_seconds: 11 }), /must not pass 300/);
  assert.equal(validateConfig({ ...base, lease_seconds: 280, clock_skew_seconds: 10 }).lease_seconds, 280);
  assert.throws(() => validateConfig({ ...base, lease_seconds: 120, clock_skew_seconds: 10 }), /four times/);
  assert.throws(() => validateConfig({ ...base, stop_seconds: 29 }), /stop_seconds/);
  assert.throws(() => validateConfig({ ...base, clock_skew_seconds: 21 }), /clock_skew_seconds/);
  assert.throws(() => validateConfig({ ...base, lease_second: 240 }), /Unknown config setting/);
  assert.throws(() => validateConfig({ ...base, network: { ...base.network, engine: 'v6' } }), /engine is "v4" or "v5"/);
  assert.throws(() => validateConfig({ ...base, network: { chain_id: 'x', genesis_sha256: base.network.genesis_sha256 } }), /network is/);
  // The declaration about the signer is never filled in for the operator.
  for (const value of [undefined, 'REPLACE_AFTER_READING_THE_README', 'every_signature', true]) assert.throws(() => validateConfig({ ...base, hosts: [{ ...base.hosts[0], signer_fencing: value }] }), /signer_fencing is "EVERY_SIGNATURE" or "NOT_DECLARED"/);
  for (const field of ['id', 'public_key_hex', 'signer_identity']) assert.throws(() => validateConfig({ ...base, hosts: [base.hosts[0], { ...base.hosts[1], [field]: base.hosts[0][field] }] }), new RegExp('same ' + field));
  assert.throws(() => validateConfig({ ...base, hosts: [{ ...base.hosts[0], extra: 1 }] }), /only id, public_key_hex/);
});

test('a first lease waits for the start wait, then carries every field the guard and the agent need', () => {
  const w = world(), b = bench(w), key = w.validatorKeys[0];
  b.command(approveRelease, w.releases.one).command(assign, w.config, key, 'host-a', b.now);
  assert.equal(b.state.keys[key].not_before_ms, T0 + 300 * S + MARGIN);
  const early = refusedWith(b.advance(300 * S + MARGIN - 1).ask('host-a', key), 'WAIT', /Nothing shortens this wait/);
  assert.equal(early.retry_after_ms, 1000);
  const nonce = newNonce(), payload = granted(b.advance(1).ask('host-a', key, { nonce }));
  assert.deepEqual(Object.keys(payload).sort(), ['chain_id', 'enforcement', 'enforcement_basis', 'engine', 'expires_utc', 'fence_domain', 'fence_token', 'genesis_sha256', 'host_id', 'issued_utc', 'kind', 'lease_id', 'release_id', 'renew_by_utc', 'request_nonce', 'signer_identity', 'validator_public_key_hex']);
  assert.equal(Date.parse(payload.renew_by_utc), b.now + LEASE - 2 * SKEW, 'the controller sends this lease again until two skews before its end');
  assert.equal(payload.kind, 'signer_lease'); assert.equal(payload.engine, 'v5'); assert.equal(payload.enforcement, 'EVERY_SIGNATURE'); assert.equal(payload.enforcement_basis, 'OPERATOR_DECLARATION');
  assert.equal(payload.host_id, 'host-a'); assert.equal(payload.request_nonce, nonce); assert.equal(payload.signer_identity, 'signer-of-host-a'); assert.equal(payload.fence_domain, 'test-domain');
  assert.equal(Date.parse(payload.issued_utc), b.now - 2 * SKEW); assert.equal(Date.parse(payload.expires_utc), b.now + LEASE);
  assert.ok(Date.parse(payload.expires_utc) - Date.parse(payload.issued_utc) <= GUARD_MAX_LEASE_MS);
  // The key entered the state by that command: its token is the command's clock plus five minutes.
  assert.match(payload.lease_id, /^[a-f0-9]{32}$/); assert.equal(payload.fence_token, String(T0 + 300 * S));
  assert.equal(b.state.keys[key].last_expires_ms, b.now + LEASE);
});

test('every refusal of section 7 is given, with what to do', () => {
  const { w, b, key } = ready(), other = w.validatorKeys[1];
  refusedWith(b.request({ host_id: 'host-a' }), 'BAD_REQUEST');
  refusedWith(b.request(null), 'BAD_REQUEST');
  const good = ask(w, 'host-a', key, { timeMs: b.now });
  refusedWith(b.request({ ...good, extra: 1 }), 'BAD_REQUEST');
  refusedWith(b.request({ ...good, payload: { ...good.payload, version: 2 } }), 'BAD_REQUEST');
  refusedWith(b.request({ ...good, payload: { ...good.payload, more: 'x' } }), 'BAD_REQUEST');
  refusedWith(b.request({ ...good, payload: { ...good.payload, engine: 'v4' } }), 'BAD_REQUEST');
  refusedWith(b.request({ ...good, payload: { ...good.payload, time_ms: String(b.now) } }), 'BAD_REQUEST');
  refusedWith(b.request({ ...good, host_id: 'host-b' }), 'BAD_REQUEST');
  const stranger = keyPair('host-z');
  refusedWith(b.request(ask(w, 'host-z', key, { timeMs: b.now, key: stranger })), 'UNKNOWN_HOST', /Add the host/);
  // Signed by another key, and a signed payload changed afterwards.
  refusedWith(b.request(ask(w, 'host-a', key, { timeMs: b.now, key: w.hostKeys['host-b'] })), 'BAD_SIGNATURE');
  refusedWith(b.request({ ...good, payload: { ...good.payload, validator_public_key_hex: other } }), 'BAD_SIGNATURE');
  refusedWith(b.ask('host-a', key, { scope: { chain_id: 'time-devnet-v4-other' } }), 'WRONG_NETWORK');
  refusedWith(b.ask('host-a', key, { scope: { genesis_sha256: 'f'.repeat(64) } }), 'WRONG_NETWORK');
  refusedWith(b.ask('host-a', key, { release: manifest('v4', 'one') }), 'WRONG_ENGINE', /would start the other engine/);
  refusedWith(b.ask('host-a', key, { release: w.releases.two }), 'RELEASE_NOT_APPROVED', /approve-release/);
  refusedWith(b.ask('host-a', other), 'KEY_NOT_ASSIGNED', /assign /);
  // A host asks for another host's key.
  refusedWith(b.ask('host-b', key), 'NOT_HOLDER', /held by host host-a.*move /);
  refusedWith(b.ask('host-a', key, { scope: { signer_identity: 'signer-of-host-b' } }), 'SIGNER_MISMATCH');
  assert.equal(b.state.keys[key].tenure_leases, 0, 'no refusal issued anything');
  // The declaration about the signer is missing for this host.
  const undeclared = { ...w, config: { ...w.config, hosts: w.config.hosts.map((host) => (host.id === 'host-a' ? { ...host, signer_fencing: 'NOT_DECLARED' } : host)) } };
  const reply = decide(b.state, undeclared.config, ask(w, 'host-a', key, { timeMs: b.now }), b.now, w.sign);
  refusedWith(reply.reply, 'SIGNER_NOT_DECLARED', /does not write that claim on its own/); assert.equal(reply.next, null);
  // The host key registered for the holder was replaced in the config.
  const replaced = keyPair('host-a'), swapped = { ...w.config, hosts: w.config.hosts.map((host) => (host.id === 'host-a' ? { ...host, public_key_hex: replaced.publicKeyHex } : host)) };
  refusedWith(decide(b.state, swapped, ask(w, 'host-a', key, { timeMs: b.now, key: replaced }), b.now, w.sign).reply, 'HOST_KEY_CHANGED', /move .* host-a --from host-a/);
  // The old key no longer signs for the host either.
  refusedWith(decide(b.state, swapped, ask(w, 'host-a', key, { timeMs: b.now }), b.now, w.sign).reply, 'BAD_SIGNATURE');
});

test('a request is fresh from one skew ahead to two skews behind, at the edges exactly', () => {
  const { b, key } = ready();
  refusedWith(b.ask('host-a', key, { timeMs: b.now + SKEW + 1 }), 'CLOCK', /Check NTP/);
  refusedWith(b.ask('host-a', key, { timeMs: b.now - 2 * SKEW - 1 }), 'CLOCK');
  const first = granted(b.ask('host-a', key, { timeMs: b.now + SKEW }));
  b.advance(SPACING);
  granted(b.ask('host-a', key, { timeMs: b.now - 2 * SKEW, previous: first.lease_id }));
});

test('a recorded request sent again is refused or answered with the stored lease; it changes nothing and never freezes the key', () => {
  const { w, b, key } = ready();
  const request = ask(w, 'host-a', key, { timeMs: b.now }), first = b.request(request), before = JSON.stringify(b.state), T = b.now;
  granted(first);
  // The same bytes again: at once, later while the date is fresh, and when it is stale. Each is
  // dated not later than the request that got the lease, so each is refused.
  for (const delay of [0, 1, 2 * SKEW - 1, 2 * SKEW + 1]) { b.now = T + delay; refusedWith(b.request(request), 'CLOCK', /recording/); assert.equal(JSON.stringify(b.state), before); }
  // The host's own repeats carry a new date and the same nonce: they get the stored lease.
  b.now = T + 10 * S; assert.deepEqual(b.request(ask(w, 'host-a', key, { timeMs: b.now, nonce: request.payload.nonce })), first);
  b.now = T + 20 * S; const repeat = ask(w, 'host-a', key, { timeMs: b.now, nonce: request.payload.nonce });
  assert.deepEqual(b.request(repeat), first);
  // A recording of that repeat, sent while nothing newer was issued, gets the stored lease too.
  b.now = T + 25 * S; assert.deepEqual(b.request(repeat), first); assert.equal(JSON.stringify(b.state), before);
  // The host installs the lease and renews. Its request is dated later than the recording.
  b.now = T + SPACING;
  const second = granted(b.ask('host-a', key, { previous: first.lease.payload.lease_id })), after = JSON.stringify(b.state);
  assert.equal(b.state.keys[key].last_request_ms, T + SPACING);
  // The recording is 12 s old, inside the freshness window, and names a lease that is no longer
  // the last one issued. It is refused as a recording. It is not taken for a second machine.
  b.now = T + SPACING + S;
  refusedWith(b.request(repeat), 'CLOCK', /not later than the last request that got a new lease/);
  assert.equal(JSON.stringify(b.state), after); assert.equal(b.state.keys[key].frozen, null);
  // The same when the controller's clock is set back to the moment the recording was made.
  b.now = repeat.payload.time_ms; refusedWith(b.request(repeat), 'CLOCK'); assert.equal(JSON.stringify(b.state), after);
  b.now = T + 2 * SPACING; granted(b.ask('host-a', key, { previous: second.lease_id }));
});

test('a stored lease is sent again until two skews before its end, to the millisecond; then a new one takes its place and the host may name either', () => {
  const { w, b, key } = ready(), first = granted(b.ask('host-a', key)), nonce = newNonce();
  b.advance(SPACING);
  const lost = granted(b.ask('host-a', key, { previous: first.lease_id, nonce })), end = Date.parse(lost.expires_utc);
  assert.equal(Date.parse(lost.renew_by_utc), end - 2 * SKEW);
  b.now = end - 2 * SKEW - 1;
  assert.equal(granted(b.ask('host-a', key, { previous: first.lease_id, nonce })).lease_id, lost.lease_id, 'one millisecond before renew_by: the stored lease');
  b.now = end - 2 * SKEW;
  const replaced = granted(b.ask('host-a', key, { previous: first.lease_id, nonce }));
  assert.notEqual(replaced.lease_id, lost.lease_id, 'at renew_by: a new lease in its place');
  assert.deepEqual(b.state.keys[key].replaced_lease_ids, [lost.lease_id]);
  // The host had installed the lease that was replaced (its answer was held back on the way).
  // Naming it is not the mark of a second machine.
  b.advance(SPACING);
  const next = granted(b.ask('host-a', key, { previous: lost.lease_id }));
  assert.equal(b.state.keys[key].frozen, null); assert.deepEqual(b.state.keys[key].replaced_lease_ids, []);
  // A lease from before that request is still the mark of one.
  refusedWith(b.advance(SPACING).ask('host-a', key, { previous: first.lease_id }), 'FROZEN', /now frozen/);
  assert.ok(next.lease_id);
});

test('the time of the last grant and the recorded expiries never go down, also when the clock is set back before a lease is replaced', () => {
  const { w, b, key } = ready(), nonce = newNonce();
  b.command(approveRelease, w.releases.two).advance(60 * S);
  const T = b.now, one = granted(b.ask('host-a', key, { nonce }));
  // The controller's clock is set back by half a skew. The host, which changed its settings to
  // release two, repeats its request: the stored lease names another release, so a new one is
  // issued in its place at once, at a clock value below the last grant.
  b.now = T - SKEW / 2;
  const two = granted(b.request(ask(w, 'host-a', key, { timeMs: T + 1, nonce, release: w.releases.two })));
  assert.equal(two.release_id, w.releases.two.release_id);
  const state = b.state.keys[key];
  assert.equal(state.last_grant_ms, T); assert.equal(state.last_expires_ms, Date.parse(one.expires_utc)); assert.equal(state.issued_expires_ms, Date.parse(one.expires_utc)); assert.equal(state.last_request_ms, T + 1);
  // So the next new lease is spaced from the true last grant, not from the clock that was set back.
  b.now = T + SPACING - SKEW / 2 - 1; refusedWith(b.ask('host-a', key, { timeMs: T + SPACING, previous: two.lease_id, release: w.releases.two }), 'TOO_SOON');
});

test('moving a frozen key ends the freeze: the new holder waits and is then served', () => {
  const { w, b, key } = ready(), first = granted(b.ask('host-a', key));
  b.advance(SPACING);
  const second = granted(b.ask('host-a', key, { previous: first.lease_id }));
  refusedWith(b.advance(S).ask('host-a', key, { previous: first.lease_id }), 'FROZEN');
  b.command(move, w.config, key, 'host-b', 'host-a', b.now);
  assert.equal(b.state.keys[key].frozen, null);
  refusedWith(b.ask('host-b', key), 'WAIT');
  b.now = Date.parse(second.expires_utc) + MARGIN;
  assert.equal(granted(b.ask('host-b', key)).host_id, 'host-b');
  // Taking a frozen key away from its holder ends the freeze too.
  const again = ready(), lease = granted(again.b.ask('host-a', again.key));
  refusedWith(again.b.advance(SPACING).ask('host-a', again.key, { previous: 'not-the-last-lease' }), 'FROZEN');
  again.b.command(unassign, again.w.config, again.key, again.b.now);
  assert.equal(again.b.state.keys[again.key].frozen, null); assert.ok(lease.lease_id);
});

test('an answer that was lost is sent again for the same nonce; a stored lease that ended is replaced', () => {
  const { w, b, key } = ready();
  const first = granted(b.ask('host-a', key)), nonce = newNonce();
  b.advance(SPACING);
  const lost = granted(b.ask('host-a', key, { previous: first.lease_id, nonce }));
  // The host still holds the first lease and repeats its request, with a new time and signature.
  b.advance(15 * S);
  const again = granted(b.ask('host-a', key, { previous: first.lease_id, nonce }));
  assert.equal(again.lease_id, lost.lease_id);
  // Much later the stored lease has ended: the same request gets a new lease in its place.
  b.advance(LEASE);
  const replaced = granted(b.ask('host-a', key, { previous: first.lease_id, nonce }));
  assert.notEqual(replaced.lease_id, lost.lease_id); assert.equal(replaced.fence_token, lost.fence_token);
  assert.equal(b.state.keys[key].previous_lease_id, first.lease_id);
  b.advance(SPACING); granted(b.ask('host-a', key, { previous: replaced.lease_id }));
  assert.equal(b.state.keys[key].frozen, null);
});

test('new leases for one key are at least three skews and a second apart', () => {
  const { b, key } = ready(), first = granted(b.ask('host-a', key));
  const soon = refusedWith(b.advance(SPACING - 1).ask('host-a', key, { previous: first.lease_id }), 'TOO_SOON', /installed lease is still good/);
  assert.equal(soon.retry_after_ms, 1000);
  granted(b.advance(1).ask('host-a', key, { previous: first.lease_id }));
});

test('a copy of a host is noticed at its first request, the key is frozen, and unfreeze starts a new tenure', () => {
  const { w, b, key } = ready(), first = granted(b.ask('host-a', key));
  b.advance(SPACING);
  // The original and its copy both hold the first lease. The original renews.
  const second = granted(b.ask('host-a', key, { previous: first.lease_id }));
  // The copy asks: a new nonce, and a lease that is no longer the last one issued.
  refusedWith(b.advance(5 * S).ask('host-a', key, { previous: first.lease_id }), 'FROZEN', /cloned or restored machine.*unfreeze /);
  assert.ok(b.state.keys[key].frozen);
  const frozenAt = b.now, lastExpiry = Date.parse(second.expires_utc);
  // From now on neither machine gets a lease, so both stop when the leases they hold run out.
  b.advance(SPACING);
  refusedWith(b.ask('host-a', key, { previous: second.lease_id }), 'FROZEN'); refusedWith(b.ask('host-a', key, { previous: first.lease_id }), 'FROZEN');
  assert.equal(b.state.keys[key].last_expires_ms, lastExpiry, 'nothing was issued after the freeze');
  assert.ok(lastExpiry <= frozenAt + LEASE);
  assert.throws(() => refence(b.state, w.config, key, b.now), /frozen. Use: unfreeze/);
  b.command(unfreeze, w.config, key, b.now);
  assert.ok(BigInt(b.state.keys[key].fence_token) > BigInt(second.fence_token));
  assert.equal(b.state.keys[key].not_before_ms, lastExpiry + MARGIN);
  refusedWith(b.ask('host-a', key, { previous: second.lease_id }), 'WAIT');
  b.now = lastExpiry + MARGIN;
  // The first lease of the new tenure does not depend on what the host holds.
  const third = granted(b.ask('host-a', key, { previous: 'anything-the-host-has' }));
  assert.equal(third.fence_token, b.state.keys[key].fence_token);
  assert.throws(() => unfreeze(b.state, w.config, key, b.now), /not frozen/);
});

test('a copy made while a request was open shares that one answer, and is noticed one request later', () => {
  const { b, key } = ready(), first = granted(b.ask('host-a', key)), nonce = newNonce();
  b.advance(SPACING);
  // Both machines hold the first lease and the same stored nonce: they get the same lease.
  const one = granted(b.ask('host-a', key, { previous: first.lease_id, nonce }));
  const two = granted(b.advance(2 * S).ask('host-a', key, { previous: first.lease_id, nonce }));
  assert.equal(two.lease_id, one.lease_id);
  // From here each draws its own nonce. The first to ask is served, the second freezes the key.
  b.advance(SPACING);
  const third = granted(b.ask('host-a', key, { previous: one.lease_id }));
  refusedWith(b.advance(S).ask('host-a', key, { previous: one.lease_id }), 'FROZEN', /now frozen/);
  refusedWith(b.advance(SPACING).ask('host-a', key, { previous: third.lease_id }), 'FROZEN');
});

test('a moved key: the old host is refused at once, the new host waits for the last lease plus the margin, the token rises', () => {
  const { w, b, key } = ready(), first = granted(b.ask('host-a', key));
  b.advance(SPACING);
  const last = granted(b.ask('host-a', key, { previous: first.lease_id })), lastExpiry = Date.parse(last.expires_utc);
  b.advance(7 * S);
  assert.throws(() => move(b.state, w.config, key, 'host-b', undefined, b.now), /--from HOST/);
  assert.throws(() => move(b.state, w.config, key, 'host-b', 'host-c', b.now), /held by host host-a, not by host-c. Nothing was changed/);
  assert.throws(() => move(b.state, w.config, key, 'host-a', 'host-a', b.now), /refence/);
  assert.throws(() => move(b.state, w.config, key, 'host-x', 'host-a', b.now), /lists no host "host-x"/);
  assert.throws(() => assign(b.state, w.config, key, 'host-b', b.now), /is held by host host-a.*move /);
  b.command(move, w.config, key, 'host-b', 'host-a', b.now);
  refusedWith(b.advance(SPACING).ask('host-a', key, { previous: last.lease_id }), 'NOT_HOLDER');
  assert.equal(b.state.keys[key].not_before_ms, lastExpiry + MARGIN);
  b.now = lastExpiry + MARGIN - 1;
  refusedWith(b.ask('host-b', key), 'WAIT');
  b.now = lastExpiry + MARGIN;
  const moved = granted(b.ask('host-b', key));
  assert.ok(BigInt(moved.fence_token) > BigInt(last.fence_token));
  assert.equal(moved.host_id, 'host-b'); assert.equal(moved.signer_identity, 'signer-of-host-b');
  // Section 4: host-a's clock may be half a skew behind true time and the controller's half a
  // skew ahead. The old lease is then live until expiry + skew/2 of true time, and the new one
  // issued no earlier than expiry + margin - skew/2. The distance is at least stop_seconds.
  assert.ok((lastExpiry + MARGIN - SKEW / 2) - (lastExpiry + SKEW / 2) >= STOP);
  // Moving back is a move like any other: it waits again.
  b.advance(10 * S).command(move, w.config, key, 'host-a', 'host-b', b.now);
  refusedWith(b.ask('host-a', key, { previous: last.lease_id }), 'WAIT');
  assert.equal(b.state.keys[key].not_before_ms, Date.parse(moved.expires_utc) + MARGIN);
});

test('one key per host, keys without a holder, and a new fence token on request', () => {
  const { w, b, key } = ready(), other = w.validatorKeys[1];
  assert.throws(() => assign(b.state, w.config, other, 'host-a', b.now), /already holds consensus key/);
  assert.throws(() => assign(b.state, w.config, 'not-a-key', 'host-b', b.now), /64 lower-case hexadecimal/);
  b.command(assign, w.config, other, 'host-b', b.now);
  assert.throws(() => move(b.state, w.config, other, 'host-a', 'host-b', b.now), /already holds consensus key/);
  const lease = granted(b.ask('host-a', key));
  b.command(unassign, w.config, key, b.now);
  refusedWith(b.advance(SPACING).ask('host-a', key, { previous: lease.lease_id }), 'KEY_NOT_ASSIGNED');
  assert.throws(() => unassign(b.state, w.config, key, b.now), /no holder/);
  assert.throws(() => refence(b.state, w.config, key, b.now), /no holder/);
  // Given again, even to the same host, it waits for the last lease.
  b.command(assign, w.config, key, 'host-a', b.now);
  assert.equal(b.state.keys[key].not_before_ms, Date.parse(lease.expires_utc) + MARGIN);
  // refence: a higher token for the same holder, above a floor the operator names.
  const before = BigInt(b.state.keys[key].fence_token), floor = before + 5_000_000n;
  b.command(refence, w.config, key, b.now, floor);
  assert.equal(BigInt(b.state.keys[key].fence_token), floor + 1n);
  b.command(refence, w.config, key, b.now);
  assert.equal(BigInt(b.state.keys[key].fence_token), floor + 2n, 'never down, also when the clock is below the token');
  assert.throws(() => refence(b.state, w.config, key, b.now, 18446744073709551615n), /not a fence token this controller could have issued/);
  assert.throws(() => refence(b.state, w.config, key, b.now, BigInt(b.now) + 101n * 366n * 86_400_000n), /more than a hundred years ahead/);
});

test('an upgrade: the next release is approved, a key goes forward to it and never back', () => {
  const { w, b, key } = ready(), one = w.releases.one, two = w.releases.two;
  const first = granted(b.ask('host-a', key));
  refusedWith(b.advance(SPACING).ask('host-a', key, { release: two, previous: first.lease_id }), 'RELEASE_NOT_APPROVED');
  assert.throws(() => approveRelease(b.state, one), /already approved.*--again/);
  assert.throws(() => approveRelease(b.state, { ...two, release_id: one.release_id }), /not a release manifest this kit accepts/);
  assert.throws(() => approveRelease(b.state, manifest('v4', 'two')), /runs engine v4.*network runs v5.*refused/);
  b.command(approveRelease, two);
  // Before the host has installed the new release it goes on with the old one.
  const second = granted(b.ask('host-a', key, { previous: first.lease_id }));
  assert.equal(second.release_id, one.release_id);
  // The host installs release two and its agent asks for it: same host, no wait.
  const third = granted(b.advance(SPACING).ask('host-a', key, { release: two, previous: second.lease_id }));
  assert.equal(third.release_id, two.release_id); assert.equal(third.fence_token, second.fence_token);
  // Back to release one: refused, until the operator approves it anew.
  refusedWith(b.advance(SPACING).ask('host-a', key, { release: one, previous: third.lease_id }), 'RELEASE_ROLLBACK', /--again/);
  assert.throws(() => retireRelease(b.state, two.release_id), /would stop when their leases run out/);
  b.command(retireRelease, one.release_id);
  refusedWith(b.ask('host-a', key, { release: one, previous: third.lease_id }), 'RELEASE_NOT_APPROVED');
  assert.throws(() => retireRelease(b.state, one.release_id), /not approved here/);
  b.command(approveRelease, one, { again: true });
  assert.equal(granted(b.ask('host-a', key, { release: one, previous: third.lease_id })).release_id, one.release_id);
  // A repeated request that names another release than the stored lease gets no stored lease.
  const nonce = newNonce(), fourth = b.state.keys[key].lease_id;
  b.advance(SPACING); b.command(approveRelease, two, { again: true });
  const lost = granted(b.ask('host-a', key, { release: one, previous: fourth, nonce }));
  const switched = granted(b.advance(5 * S).ask('host-a', key, { release: two, previous: fourth, nonce }));
  assert.equal(lost.release_id, one.release_id); assert.equal(switched.release_id, two.release_id);
  refusedWith(b.ask('host-a', key, { release: one, previous: fourth, nonce }), 'RELEASE_ROLLBACK');
});

test('a controller state is bound to one network, one engine and one fence domain', () => {
  const v4 = world({ engine: 'v4' }), b = bench(v4), key = v4.validatorKeys[0];
  // The refusal the kit asks for: no v5 lease for a network that runs version 4.
  assert.throws(() => approveRelease(b.state, manifest('v5', 'one')), /runs engine v5.*network runs v4.*refused/);
  b.command(approveRelease, v4.releases.one).command(assign, v4.config, key, 'host-a', b.now).advance(300 * S + MARGIN);
  refusedWith(b.ask('host-a', key, { release: manifest('v5', 'one') }), 'WRONG_ENGINE');
  const payload = granted(b.ask('host-a', key));
  assert.equal(Object.hasOwn(payload, 'engine'), false, 'a v4 lease carries no engine field');
  assert.equal(checkBinding(b.state, v4.config), b.state);
  assert.throws(() => checkBinding(b.state, { ...v4.config, network: { ...v4.config.network, engine: 'v5' } }), /bound to engine v4.*never signs a v5 lease/);
  assert.throws(() => checkBinding(b.state, { ...v4.config, network: { ...v4.config.network, genesis_sha256: 'e'.repeat(64) } }), /another network/);
  assert.throws(() => checkBinding(b.state, { ...v4.config, network: { ...v4.config.network, chain_id: 'time-devnet-v4-x' } }), /another network/);
  assert.throws(() => checkBinding(b.state, { ...v4.config, fence_domain: 'other' }), /domain/);
});

test('the start rule: a running lease goes on, everything else starts a new tenure and waits five minutes plus the margin', () => {
  const { w, b, key } = ready(), other = w.validatorKeys[1];
  b.command(assign, w.config, other, 'host-b', b.now);
  const first = granted(b.ask('host-a', key)), expiry = Date.parse(first.expires_utc), tokenBefore = BigInt(b.state.keys[other].fence_token);
  // A restart 30 s later. Key 0 has a running lease; key 1 was given to host-b and never leased.
  const s = b.advance(30 * S).now;
  b.state = validateState(applyStart(b.state, w.config, s));
  assert.equal(b.state.floor_ms, s + 300 * S);
  assert.equal(b.state.keys[key].fence_token, first.fence_token); assert.equal(b.state.keys[key].tenure_leases, 1);
  assert.equal(b.state.keys[key].last_expires_ms, s + 300 * S, 'a lost process may have renewed until the start');
  assert.equal(b.state.keys[other].not_before_ms, s + 300 * S + MARGIN);
  assert.ok(BigInt(b.state.keys[other].fence_token) >= BigInt(s + 300 * S) && BigInt(b.state.keys[other].fence_token) > tokenBefore, 'above any token a lost process can have issued');
  // The holder of the running lease renews at once.
  const second = granted(b.advance(SPACING).ask('host-a', key, { previous: first.lease_id }));
  // A move made after the restart waits for leases this state may not know.
  b.command(move, w.config, key, 'host-c', 'host-a', b.now);
  assert.equal(b.state.keys[key].not_before_ms, Math.max(Date.parse(second.expires_utc), s + 300 * S) + MARGIN);
  refusedWith(b.ask('host-b', other), 'WAIT');
  b.now = s + 300 * S + MARGIN; granted(b.ask('host-b', other));
  // A start after every lease has ended: all keys wait, with new tokens.
  const cold = b.advance(1000 * S).now, tokens = Object.fromEntries(Object.entries(b.state.keys).map(([id, k]) => [id, BigInt(k.fence_token)]));
  b.state = applyStart(b.state, w.config, cold);
  for (const [id, k] of Object.entries(b.state.keys)) { assert.equal(k.not_before_ms, cold + 300 * S + MARGIN); assert.equal(k.tenure_leases, 0); assert.ok(BigInt(k.fence_token) > tokens[id]); }
  assert.ok(expiry < cold);
  // A second start right after does not shorten anything.
  const again = applyStart(b.state, w.config, cold + S);
  for (const k of Object.values(again.keys)) assert.equal(k.not_before_ms, cold + S + 300 * S + MARGIN);
});

test('a controller that lost its state takes tokens above everything it issued, and the operator can name a floor', () => {
  const { w, b, key } = ready(), lease = granted(b.ask('host-a', key));
  // The state is gone. A new controller starts on another machine whose clock is a full skew behind.
  const lost = bench(w, b.now + 5 * S - SKEW);
  lost.state = applyStart(lost.state, w.config, lost.now);
  lost.command(approveRelease, w.releases.one).command(assign, w.config, key, 'host-b', lost.now);
  assert.ok(BigInt(lost.state.keys[key].fence_token) > BigInt(lease.fence_token));
  // It issues nothing for the key before the lost lease has ended everywhere, plus the margin.
  assert.ok(lost.state.keys[key].not_before_ms >= Date.parse(lease.expires_utc) + STOP + SKEW);
  refusedWith(lost.ask('host-b', key), 'WAIT');
  // The operator does not trust the old clock and names the highest token a host still shows.
  const shown = BigInt(lease.fence_token) + 86_400_000n;
  lost.command(refence, w.config, key, lost.now, shown);
  assert.equal(BigInt(lost.state.keys[key].fence_token), shown + 1n);
  assert.equal(summary(lost.state, lost.now).keys[0].state, 'WAITING');
});

test('a replacement controller whose clock is behind outranks and outwaits what the old one issued seconds before it stopped', () => {
  const { w, b, key } = ready();
  granted(b.ask('host-a', key));
  const copy = b.state; // the copy of the state that will be restored
  const trueTime = b.advance(1000 * S).now;
  // The old controller's clock is half a skew ahead of true time. The key's lease ended long ago,
  // so a move takes effect at once: host-b gets a lease, with a token from that clock.
  b.now = trueTime + SKEW / 2;
  b.command(move, w.config, key, 'host-b', 'host-a', b.now);
  const given = granted(b.ask('host-b', key));
  assert.equal(given.fence_token, String(b.now));
  // It stops. Two seconds later a replacement starts from the old copy, on a machine whose clock
  // is half a skew behind true time. Its clock reads LESS than the token host-b holds.
  const replacement = bench(w, trueTime + 2 * S - SKEW / 2);
  assert.ok(BigInt(replacement.now) < BigInt(given.fence_token));
  replacement.state = applyStart(copy, w.config, replacement.now);
  const restarted = replacement.state.keys[key];
  assert.equal(restarted.holder.host_id, 'host-a', 'the old copy still names host-a');
  // Claim S2: the lease host-a will get carries a higher token than the one host-b holds.
  assert.ok(BigInt(restarted.fence_token) > BigInt(given.fence_token));
  // Claim S1: host-b finds its lease live until half a skew of true time after its expiry. The
  // replacement issues to host-a when its clock, half a skew behind, reaches not_before.
  const lastLive = Date.parse(given.expires_utc) + SKEW / 2, firstIssue = restarted.not_before_ms + SKEW / 2;
  assert.ok(firstIssue - lastLive >= STOP, String(firstIssue - lastLive));
  refusedWith(replacement.ask('host-a', key), 'WAIT'); refusedWith(replacement.ask('host-b', key), 'NOT_HOLDER');
});

test('summary shows what an operator needs', () => {
  const { w, b, key } = ready();
  assert.equal(summary(b.state, b.now).keys[0].state, 'READY');
  const lease = granted(b.ask('host-a', key)), view = summary(b.state, b.now);
  assert.deepEqual(view.network, w.config.network); assert.equal(view.releases[0].release_id, w.releases.one.release_id);
  assert.deepEqual([view.keys[0].holder, view.keys[0].state, view.keys[0].fence_token, view.keys[0].last_lease_expires_utc], ['host-a', 'LEASED', lease.fence_token, lease.expires_utc]);
  assert.equal(summary(b.state, b.now + LEASE).keys[0].state, 'LEASE_ENDED');
  assert.ok(!JSON.stringify(view).includes('signature'));
  assert.ok(new CommandRefused('x') instanceof Error);
});

// ---- The kit's guard judges the controller's leases -------------------------------

/// Installs `lease` as the host's lease file and returns the guard's verdict at `hostNow`.
async function guardAt(host, lease, hostNow, settings = host.settings) {
  await writeFile(host.settings.signer_lease_file, JSON.stringify(lease));
  return guard(settings, hostNow);
}

test('the real guard accepts what the controller issues, on a v5 and on a v4 network', async () => {
  for (const engine of ['v5', 'v4']) {
    const w = world({ engine }), { b, key } = ready(w), reply = b.ask('host-a', key);
    const host = await operatorDirectory(w, 'host-a', key), accepted = await guardAt(host, reply.lease, b.now);
    assert.equal(accepted.engine, engine); assert.equal(accepted.lease.lease_id, reply.lease.payload.lease_id); assert.equal(accepted.lease.fence_token, reply.lease.payload.fence_token);
  }
});

test('the real guard accepts the longest lease a config allows, and a lease is live on every clock inside the bound', async () => {
  const w = world({ settings: { lease_seconds: 280, clock_skew_seconds: 10 } }), { b, key } = ready(w), reply = b.ask('host-a', key), host = await operatorDirectory(w, 'host-a', key);
  assert.equal(Date.parse(reply.lease.payload.expires_utc) - Date.parse(reply.lease.payload.issued_utc), GUARD_MAX_LEASE_MS);
  // A host clock up to two skews behind the controller's finds the lease already issued.
  for (const offset of [-2 * SKEW, -SKEW, 0, SKEW, 280 * S - 1]) assert.equal((await guardAt(host, reply.lease, b.now + offset)).lease.lease_id, reply.lease.payload.lease_id);
  // One millisecond further on either side the guard, which has no tolerance, refuses.
  await assert.rejects(guardAt(host, reply.lease, b.now - 2 * SKEW - 1), /expired or future-dated/);
  await assert.rejects(guardAt(host, reply.lease, b.now + 280 * S), /expired or future-dated/);
});

test('the real guard refuses a controller lease on a host whose settings name anything else', async () => {
  const w = world(), { b, key } = ready(w), reply = b.ask('host-a', key), host = await operatorDirectory(w, 'host-a', key);
  assert.ok(await guardAt(host, reply.lease, b.now));
  // Another consensus key, signer identity, chain: the settings of another host.
  await assert.rejects(guardAt(host, reply.lease, b.now, { ...host.settings, validator_public_key_hex: w.validatorKeys[1] }), /scope mismatch: validator_public_key_hex/);
  await assert.rejects(guardAt(host, reply.lease, b.now, { ...host.settings, signer_identity: 'signer-of-host-b' }), /scope mismatch: signer_identity/);
  // Another release, genesis and engine: each in an operator directory of its own.
  const twoHost = await operatorDirectory(w, 'host-a', key, { release: w.releases.two });
  await assert.rejects(guardAt(twoHost, reply.lease, b.now), /scope mismatch: release_id/);
  const otherNetwork = world(), elsewhere = await operatorDirectory({ ...otherNetwork, trust: w.trust }, 'host-a', otherNetwork.validatorKeys[0]);
  await assert.rejects(guardAt(elsewhere, reply.lease, b.now), /scope mismatch: genesis_sha256/);
  const v4Host = await operatorDirectory(w, 'host-a', key, { release: manifest('v4', 'one') });
  await assert.rejects(guardAt(v4Host, reply.lease, b.now), /scope mismatch: release_id|scope mismatch: engine/);
  // An authority the host's trust file does not pin, or pins for another role.
  const unpinned = await operatorDirectory(w, 'host-a', key, { trust: { ...w.trust, authorities: [] } });
  await assert.rejects(guardAt(unpinned, reply.lease, b.now), /authority\/role is not independently pinned/);
  const wrongRole = await operatorDirectory(w, 'host-a', key, { trust: { ...w.trust, authorities: [{ ...w.trust.authorities[0], roles: ['signer_floor'] }] } });
  await assert.rejects(guardAt(wrongRole, reply.lease, b.now), /authority\/role is not independently pinned/);
  // A lease changed after signing.
  await assert.rejects(guardAt(host, { ...reply.lease, payload: { ...reply.lease.payload, fence_token: '1' } }, b.now), /Invalid signed attestation/);
  // The engine field decides alone when everything else matches: a v5 lease on a v4 release.
  const v4World = world({ engine: 'v4' }), v4Ready = ready(v4World), v4Reply = v4Ready.b.ask('host-a', v4Ready.key), v4Directory = await operatorDirectory(v4World, 'host-a', v4Ready.key);
  const forged = v4World.sign({ ...v4Reply.lease.payload, engine: 'v5' });
  await assert.rejects(guardAt(v4Directory, forged, v4Ready.b.now), /scope mismatch: engine/);
});

test('rotating the authority: both are pinned for a while, then the old one is removed and its leases are refused at once', async () => {
  const { w, b, key } = ready(), host = await operatorDirectory(w, 'host-a', key), next = keyPair('lease-authority-2');
  const entry = { id: next.id, organization: 'operating-organization', public_key_hex: next.publicKeyHex, roles: ['signer_lease'] };
  const pin = (authorities) => writeFile(host.settings.trust_file, JSON.stringify({ ...w.trust, authorities }));
  const first = b.ask('host-a', key).lease;
  // Step 2: every host pins both. Step 3: the controller signs with the new key.
  await pin([...w.trust.authorities, entry]);
  assert.equal((await guardAt(host, first, b.now)).lease.lease_id, first.payload.lease_id);
  const second = decide(b.state, w.config, ask(w, 'host-a', key, { timeMs: b.advance(SPACING).now, previous: first.payload.lease_id }), b.now, signer(next)).reply.lease;
  assert.equal(second.issuer, 'lease-authority-2');
  assert.equal((await guardAt(host, second, b.now)).lease.lease_id, second.payload.lease_id);
  // A lease that names the new authority and carries the old key's signature is not valid.
  await assert.rejects(guardAt(host, { ...w.sign(second.payload), issuer: next.id }, b.now), /Invalid signed attestation/);
  // Step 4: the old authority is removed. The guard reads the trust file at every check.
  await pin([entry]);
  await assert.rejects(guardAt(host, first, b.now), /authority\/role is not independently pinned/);
  assert.equal((await guardAt(host, second, b.now)).lease.lease_id, second.payload.lease_id);
  assert.equal(signed(second, { authorities: [entry] }, { kind: 'signer_lease' }, b.now).authority.id, next.id);
});

test('the nonce of an earlier request that got a lease is refused once a later request was served, whatever its date; the open request and a new nonce are judged as before', () => {
  const { w, b, key } = ready(), first = granted(b.ask('host-a', key)), old = newNonce();
  b.advance(SPACING);
  const second = granted(b.ask('host-a', key, { previous: first.lease_id, nonce: old }));
  b.advance(SPACING);
  const open = newNonce(), third = granted(b.ask('host-a', key, { previous: second.lease_id, nonce: open }));
  assert.deepEqual(b.state.keys[key].served_nonces.slice(-2), [old, open]);
  const before = JSON.stringify(b.state);
  // The earlier request again, dated LATER than the last served one (a host clock set back in
  // between makes a recording look like this): refused, nothing changes, nothing is frozen.
  refusedWith(b.advance(S).ask('host-a', key, { previous: first.lease_id, nonce: old }), 'CLOCK', /answered before/);
  assert.equal(JSON.stringify(b.state), before);
  // The open request repeated gets the stored lease; a nonce never seen, with an old lease, is a second machine.
  assert.equal(granted(b.ask('host-a', key, { previous: second.lease_id, nonce: open })).lease_id, third.lease_id);
  refusedWith(b.ask('host-a', key, { previous: first.lease_id }), 'FROZEN', /now frozen/);
  // At most eight are remembered, the newest last.
  const many = ready(); let previous = '';
  for (let i = 0; i < 12; i++) { previous = granted(many.b.ask('host-a', many.key, { previous })).lease_id; many.b.advance(SPACING); }
  assert.equal(many.b.state.keys[many.key].served_nonces.length, 8); assert.equal(many.b.state.keys[many.key].served_nonces.at(-1), many.b.state.keys[many.key].request_nonce);
});

test('a start judges "running" by a lease that was really issued, never by a cover: a cover raised by a start, or by a start on a wrong clock, keeps no tenure alive', () => {
  const { w, b, key } = ready(), lease = granted(b.ask('host-a', key)), expiry = Date.parse(lease.expires_utc);
  // A start 30 s later raises the cover to five minutes from then, past the lease's end.
  b.advance(30 * S); b.state = applyStart(b.state, w.config, b.now);
  assert.ok(b.state.keys[key].last_expires_ms > expiry); assert.equal(b.state.keys[key].issued_expires_ms, expiry);
  // A second start after the lease's end, inside that cover: the tenure does not go on.
  b.now = expiry + S; const after = applyStart(b.state, w.config, b.now).keys[key];
  assert.equal(after.tenure_leases, 0); assert.equal(after.not_before_ms, b.now + 300 * S + MARGIN);
  // One millisecond before the lease's end it does.
  assert.equal(applyStart(b.state, w.config, expiry - 1).keys[key].tenure_leases, 1);
  // "clock-was-ahead": a tenure whose issued lease still runs goes on; one whose lease ended starts anew.
  // The clock was a minute ahead at a start, while the lease still ran on it.
  const ahead = applyStart(b.state, w.config, expiry - 100 * S + 60 * S), running = rebaseClock(ahead, w.config, expiry - 100 * S);
  assert.equal(running.state.keys[key].tenure_leases, 1); assert.equal(running.state.keys[key].fence_token, lease.fence_token);
  assert.equal(running.report[0].the_holders_lease_still_runs_and_its_tenure_goes_on_until_utc, lease.expires_utc);
  // The clock was an hour ahead at a start: on it the lease had ended, and it has ended now.
  const ended = rebaseClock(applyStart(b.state, w.config, expiry + 3600 * S), w.config, expiry);
  assert.equal(ended.state.keys[key].tenure_leases, 0); assert.equal(ended.state.keys[key].not_before_ms, expiry + 300 * S + MARGIN);
  assert.ok(BigInt(ended.state.keys[key].fence_token) > BigInt(lease.fence_token));
});
