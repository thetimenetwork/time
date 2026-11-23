// The decisions of the signer-lease controller, as functions of a state, a clock value and an
// input. Nothing here reads a clock, a file or the network: the service (start.mjs), the command
// line (ctl.mjs) and the tests pass everything in. docs/design/signer-lease-controller.md is the
// specification; section numbers below are its sections.
//
// The three rules that carry the safety property (section 4):
//   1. a lease goes only to the holder of the key's tenure, and not before the tenure's not_before;
//   2. every new tenure sets not_before = last_expires + margin (newTenure);
//   3. at every start, last_expires is raised to cover leases a lost process may have issued, and
//      every key without a running lease starts a new tenure (applyStart).
import { randomBytes } from 'node:crypto';
import { validateRelease, releaseEngine } from '../lib.mjs';
import { GUARD_MAX_LEASE_MS, NAME, checkRequestShape, verifyRequest } from '../lease-protocol.mjs';

const HEX32 = /^[a-f0-9]{64}$/;
const U64_MAX = 18446744073709551615n;
/// How many leases replaced in place for one request are remembered (decide, the repeated request).
const REPLACED_KEPT = 8;
/// How many nonces of requests that got a new lease are remembered per key. New leases are at
/// least three skews apart and a request is fresh for three, so the nonce of any request that
/// can still be fresh is among the last two; eight is room to spare.
const NONCES_KEPT = 8;
/// A fence token is a clock reading in milliseconds. A floor further ahead of the clock than this
/// is a typing mistake, not a token: a hundred years.
export const TOKEN_FLOOR_AHEAD_MS = 100 * 366 * 86_400_000;
const short = (hex) => hex.slice(0, 16);
const utc = (ms) => new Date(ms).toISOString();

/// The times that follow from the three settings (section 3.2), in milliseconds.
export function timing(config) {
  const skewMs = config.clock_skew_seconds * 1000, stopMs = config.stop_seconds * 1000, leaseMs = config.lease_seconds * 1000;
  const marginMs = 2 * skewMs + stopMs;
  return { leaseMs, skewMs, stopMs, backdateMs: 2 * skewMs, marginMs, startWaitMs: GUARD_MAX_LEASE_MS + marginMs, spacingMs: 3 * skewMs + 1000 };
}

/// An operator's command that is refused. The message says what to do instead.
export class CommandRefused extends Error {}

// ---- The state -------------------------------------------------------------------

/// The state of a controller that knows nothing. A key that enters it later is treated as if a
/// lease for it might run until `floor_ms`: an empty state looks exactly like a lost one.
export function emptyState(config, now) {
  return {
    schema_version: 1,
    network: { chain_id: config.network.chain_id, genesis_sha256: config.network.genesis_sha256, engine: config.network.engine },
    fence_domain: config.fence_domain, releases: [], next_release_order: 1, floor_ms: now + GUARD_MAX_LEASE_MS, clock_ms: now, keys: {},
  };
}

/// A key that enters the state. The state knows nothing about it, so a lease for it may be
/// running, issued by a process whose state is lost: it is covered for five minutes from NOW, on
/// the clock of the command that brings the key in. The clock at the last start is not relied on
/// alone: it may have been wrong (design, 5.5).
const emptyKey = (state, now) => ({
  holder: null, fence_token: '0', not_before_ms: 0, tenure_leases: 0, last_expires_ms: Math.max(state.floor_ms, now + GUARD_MAX_LEASE_MS), issued_expires_ms: 0, last_grant_ms: 0, last_request_ms: 0,
  lease: null, lease_id: '', previous_lease_id: '', replaced_lease_ids: [], request_nonce: '', served_nonces: [], release_id: null, release_order: 0, frozen: null,
});

/// `state` as a writer whose clock reads `now` leaves it: `clock_ms` is the latest clock reading
/// of any process that wrote this line of states.
export const stamped = (state, now) => ({ ...state, clock_ms: Math.max(state.clock_ms, now) });

/// A state that holds a time later than the clock cannot be continued or changed: one of the two
/// clock readings is wrong, and every wait is counted on the clock (design, 5.5).
export class ClockRefused extends Error {}
export function checkClock(state, config, now) {
  const ahead = state.clock_ms - now;
  if (ahead > timing(config).skewMs) throw new ClockRefused(`The newest controller state was written when the clock read ${utc(state.clock_ms)}. This machine's clock reads ${utc(now)}, which is ${Math.round(ahead / 1000)} s earlier. One of the two readings is wrong, and every wait is counted on the clock, so nothing is done. FIRST check this machine's clock against a time source you trust (NTP). If this clock is behind: correct it and try again. If this clock is right, the clock was ahead when the state was written: run "clock-was-ahead" (README, "After the clock was wrong") and try again.`);
  return state;
}

/// Refuses a state that is not in the form this program writes. A state file carries a checksum,
/// so this catches a program error or a file of another version, not a flipped bit.
export function validateState(state) {
  const bad = (what) => { throw new Error('The controller state has an unexpected form (' + what + ')'); };
  const time = (value) => Number.isSafeInteger(value) && value >= 0;
  if (!state || typeof state !== 'object' || state.schema_version !== 1) bad('schema_version');
  const network = state.network;
  if (!network || typeof network.chain_id !== 'string' || !HEX32.test(network.genesis_sha256 ?? '') || !['v4', 'v5'].includes(network.engine)) bad('network');
  if (typeof state.fence_domain !== 'string' || !NAME.test(state.fence_domain)) bad('fence_domain');
  if (!Array.isArray(state.releases) || !Number.isSafeInteger(state.next_release_order) || !time(state.floor_ms) || !time(state.clock_ms)) bad('releases');
  for (const release of state.releases) if (!release || !HEX32.test(release.release_id ?? '') || !['v4', 'v5'].includes(release.engine) || !Number.isSafeInteger(release.order) || release.order >= state.next_release_order) bad('release');
  if (!state.keys || typeof state.keys !== 'object' || Array.isArray(state.keys)) bad('keys');
  for (const [id, key] of Object.entries(state.keys)) {
    if (!HEX32.test(id) || !key || typeof key !== 'object') bad('key');
    if (key.holder !== null && (typeof key.holder?.host_id !== 'string' || !NAME.test(key.holder.host_id) || !HEX32.test(key.holder.public_key_hex ?? ''))) bad('holder');
    if (typeof key.fence_token !== 'string' || !/^(?:0|[1-9][0-9]{0,19})$/.test(key.fence_token) || BigInt(key.fence_token) > U64_MAX) bad('fence_token');
    for (const name of ['not_before_ms', 'last_expires_ms', 'issued_expires_ms', 'last_grant_ms', 'last_request_ms', 'tenure_leases', 'release_order']) if (!time(key[name])) bad(name);
    for (const name of ['lease_id', 'previous_lease_id', 'request_nonce']) if (typeof key[name] !== 'string') bad(name);
    if (!Array.isArray(key.replaced_lease_ids) || key.replaced_lease_ids.length > REPLACED_KEPT || key.replaced_lease_ids.some((item) => typeof item !== 'string')) bad('replaced_lease_ids');
    if (!Array.isArray(key.served_nonces) || key.served_nonces.length > NONCES_KEPT || key.served_nonces.some((item) => typeof item !== 'string')) bad('served_nonces');
    if (key.lease !== null && (typeof key.lease !== 'object' || typeof key.lease.payload?.expires_utc !== 'string')) bad('lease');
    if (key.release_id !== null && !HEX32.test(key.release_id)) bad('release_id');
    if (key.frozen !== null && (!time(key.frozen?.at_ms) || typeof key.frozen.reason !== 'string')) bad('frozen');
  }
  return state;
}

/// A state belongs to one network, one engine and one fence domain for ever (section 7, point 2).
export function checkBinding(state, config) {
  const a = state.network, b = config.network;
  if (a.chain_id !== b.chain_id || a.genesis_sha256 !== b.genesis_sha256) throw new Error(`This state directory belongs to chain ${a.chain_id} (genesis ${a.genesis_sha256}); the config names another network. One controller state serves one network: use a new data_directory, a new fence_domain and a new authority key for another one.`);
  if (a.engine !== b.engine) throw new Error(`This state directory is bound to engine ${a.engine} for genesis ${a.genesis_sha256}; the config says ${b.engine}. A network runs one engine. The controller never signs a ${b.engine} lease for it: a ${b.engine} release would start the other engine on this network. If this is another network, it has another genesis; use a new data_directory.`);
  if (state.fence_domain !== config.fence_domain) throw new Error(`This state directory issues fence tokens in the domain ${state.fence_domain}; the config names ${config.fence_domain}. Tokens are compared inside one domain only. Keep the domain of this state, or use a new data_directory.`);
  return state;
}

/// Rule 2. A new tenure: a higher token taken from the clock, and no lease before every lease
/// issued so far has ended everywhere and the old validator has had time to stop.
/// `tokenClock` is the clock value the token is taken from: the clock itself for a command, and
/// the clock plus five minutes at a start, which is above every token a process whose state is
/// lost can have put into a lease (section 5.4).
function newTenure(key, tokenClock, marginMs, { holder = key.holder, above = 0n } = {}) {
  let token = BigInt(key.fence_token) + 1n;
  if (BigInt(tokenClock) > token) token = BigInt(tokenClock);
  if (above + 1n > token) token = above + 1n;
  if (token > U64_MAX) throw new CommandRefused('The fence token would pass the largest 64-bit number');
  return { ...key, holder, fence_token: token.toString(), not_before_ms: Math.max(key.not_before_ms, key.last_expires_ms + marginMs), tenure_leases: 0 };
}

/// Rule 3, the start rule (section 5.3). `now` is the controller's clock at the start.
export function applyStart(state, config, now) {
  const { marginMs } = timing(config), horizon = now + GUARD_MAX_LEASE_MS, keys = {};
  for (const [id, key] of Object.entries(state.keys)) {
    // A lease this line of states really issued still runs, and it is a lease of the current
    // tenure: the tenure goes on. The test is on issued_expires_ms, a date taken from a lease,
    // never on last_expires_ms: that is a cover, which a start on a wrong clock writes too high
    // and which "clock-was-ahead" lowers, so it says nothing about what runs.
    const running = now < key.issued_expires_ms && key.tenure_leases > 0;
    const covered = { ...key, last_expires_ms: Math.max(key.last_expires_ms, horizon) };
    if (running) { keys[id] = covered; continue; }
    // One key never keeps the controller from starting: a key whose token cannot rise is frozen.
    try { keys[id] = newTenure(covered, horizon, marginMs); } catch (error) {
      if (!(error instanceof CommandRefused)) throw error;
      keys[id] = { ...covered, tenure_leases: 0, not_before_ms: Math.max(covered.not_before_ms, covered.last_expires_ms + marginMs), frozen: covered.frozen ?? { at_ms: now, reason: 'its fence token is the largest number there is and cannot rise for a new tenure. This key can get no lease in this fence domain any more.' } };
    }
  }
  return stamped({ ...state, floor_ms: Math.max(state.floor_ms, horizon), keys }, now);
}

/// The way out after a start, or a command, made while the machine's clock was AHEAD (design,
/// 5.5): the state then holds waits and covers counted from a clock that was wrong. `now` is a
/// clock the operator has just checked. Every cover the start rule wrote is replaced by the same
/// cover counted from `now`, as a start with the right clock would have written it. Nothing goes
/// below the expiry of a lease this state records as issued (`issued_expires_ms`): a lease that
/// was handed out with dates from the wrong clock is still waited for, to its last millisecond.
/// Tokens only rise. Returns the new state and, per key, what was done.
export function rebaseClock(state, config, now) {
  const { marginMs, skewMs } = timing(config), horizon = now + GUARD_MAX_LEASE_MS, keys = {}, report = [];
  if (state.clock_ms - now <= skewMs) throw new CommandRefused(`The state holds no time later than this machine's clock (it was last written at ${utc(state.clock_ms)}; the clock reads ${utc(now)}). There is nothing to correct.`);
  for (const [id, key] of Object.entries(state.keys)) {
    // What a start on this clock writes (applyStart), with one difference: the covers are set, not
    // only raised, because the ones in the state were counted from the wrong clock.
    const running = now < key.issued_expires_ms && key.tenure_leases > 0, last_expires_ms = Math.max(key.issued_expires_ms, horizon);
    // Dates of requests and grants later than this clock would refuse every request until then.
    const covered = { ...key, last_expires_ms, last_grant_ms: Math.min(key.last_grant_ms, now), last_request_ms: Math.min(key.last_request_ms, now) };
    if (running) keys[id] = { ...covered, not_before_ms: Math.min(key.not_before_ms, now) };
    else {
      let token = BigInt(key.fence_token) + 1n; if (BigInt(horizon) > token) token = BigInt(horizon);
      keys[id] = { ...covered, not_before_ms: last_expires_ms + marginMs, tenure_leases: 0, fence_token: (token > U64_MAX ? U64_MAX : token).toString() };
    }
    report.push({
      validator_public_key_hex: id, holder: key.holder?.host_id ?? null,
      ...(running ? { the_holders_lease_still_runs_and_its_tenure_goes_on_until_utc: utc(key.issued_expires_ms) } : { first_lease_not_before_utc: utc(last_expires_ms + marginMs) }),
      // A lease that ends later than any lease issued on this clock could: it was dated by the wrong clock.
      ...(key.issued_expires_ms > horizon ? { a_lease_dated_by_the_wrong_clock_is_waited_for_until_utc: utc(key.issued_expires_ms) } : {}),
    });
  }
  return { state: { ...state, floor_ms: horizon, clock_ms: now, keys }, report };
}

// ---- A request for a lease -------------------------------------------------------

const refused = (code, message, retryAfterMs) => ({ status: 'refused', code, message, ...(retryAfterMs === undefined ? {} : { retry_after_ms: Math.max(1000, Math.ceil(retryAfterMs)) }) });

/// Decides one request. Returns `{reply, next, event}`: the answer, the state to write BEFORE
/// the answer is sent (null when nothing changes), and what to log. `sign(payload)` returns the
/// attestation `{issuer, payload, signature}`.
export function decide(state, config, envelope, now, sign) {
  const t = timing(config), no = (code, message, retry) => ({ reply: refused(code, message, retry), next: null, event: { code } });
  let request;
  try { request = checkRequestShape(envelope); } catch (error) { return no('BAD_REQUEST', error.message); }
  const host = config.hosts.find((item) => item.id === request.host_id);
  if (!host) return no('UNKNOWN_HOST', 'This controller knows no host of that id. Add the host with its public key to "hosts" in the controller config and restart the controller.');
  if (!verifyRequest(envelope, host.public_key_hex)) return no('BAD_SIGNATURE', `The request does not carry the signature of the key registered for host ${host.id}. If the host key was replaced, register the new public key and give the key to the host again with: move KEY ${host.id} --from ${host.id}`);
  const id = request.validator_public_key_hex, key = state.keys[id];
  const where = { code: null, host: host.id, key: short(id) }, deny = (code, message, retry) => ({ reply: refused(code, message, retry), next: null, event: { ...where, code } });
  // Freshness, against the later of the clock and the key's last grant: a request older than the
  // last grant can never become fresh again, even if the controller's clock is set back.
  const lag = Math.max(now, key?.last_grant_ms ?? 0) - request.time_ms;
  if (lag < -t.skewMs || lag > 2 * t.skewMs) return deny('CLOCK', `The request is dated ${utc(request.time_ms)}; the controller's clock reads ${utc(now)}. A request is accepted from ${t.skewMs / 1000} s ahead to ${2 * t.skewMs / 1000} s behind. Check NTP on the host and on the controller. A request repeated from a recording is refused the same way.`);
  if (request.chain_id !== state.network.chain_id || request.genesis_sha256 !== state.network.genesis_sha256) return deny('WRONG_NETWORK', `This controller serves chain ${state.network.chain_id} with genesis ${state.network.genesis_sha256}. The host's settings name another chain or genesis. Check chain_id and genesis_sha256 in the operator settings.`);
  const engine = request.engine ?? 'v4';
  if (engine !== state.network.engine) return deny('WRONG_ENGINE', `This network runs engine ${state.network.engine}. The host's pinned release runs ${engine}. A lease for it would start the other engine on this network, so none is signed. Pin a ${state.network.engine} release on the host.`);
  const release = state.releases.find((item) => item.release_id === request.release_id);
  if (!release) return deny('RELEASE_NOT_APPROVED', `Release ${request.release_id} is not approved on this controller. If this is the release the validators should run, approve it with: approve-release RELEASE.json`);
  if (release.engine !== engine) return deny('WRONG_ENGINE', 'The approved release and the request name different engines.');
  if (!key || !key.holder) return deny('KEY_NOT_ASSIGNED', `No host holds consensus key ${id} on this controller. Give it to this host with: assign ${id} ${host.id}`);
  if (key.holder.host_id !== host.id) return deny('NOT_HOLDER', `Consensus key ${id} is held by host ${key.holder.host_id}, not by ${host.id}. Only the holder gets leases. To move the key, stop the validator on ${key.holder.host_id}, move the signer's state with the key, and run: move ${id} ${host.id} --from ${key.holder.host_id}`);
  if (key.holder.public_key_hex !== host.public_key_hex) return deny('HOST_KEY_CHANGED', `Host ${host.id} held this key under another host key. A host with a new key is a new holder and must wait like one: move ${id} ${host.id} --from ${host.id}`);
  if (request.signer_identity !== host.signer_identity) return deny('SIGNER_MISMATCH', `The host's settings name a signer identity other than the one registered for host ${host.id}. A lease names the signer it is for. Correct signer_identity in the operator settings or in the controller config.`);
  if (host.signer_fencing !== 'EVERY_SIGNATURE') return deny('SIGNER_NOT_DECLARED', `The controller config does not declare that the signer of host ${host.id} enforces fencing at every signature. The kit's guard accepts only leases that say so, and this controller does not write that claim on its own. Read "The declaration about the signer" in deploy/lease-controller/README.md.`);
  if (key.frozen) return deny('FROZEN', `Consensus key ${id} is frozen since ${utc(key.frozen.at_ms)}: ${key.frozen.reason} No lease is issued until an operator has made sure that exactly one machine is host ${host.id} and has run: unfreeze ${id}`);
  if (key.release_id !== null && release.order < key.release_order) return deny('RELEASE_ROLLBACK', `This key already had a lease for release ${key.release_id}, approved after ${request.release_id}. A key does not go back to an earlier release. If going back is intended, approve it anew with: approve-release RELEASE.json --again`);
  if (now < key.not_before_ms) return deny('WAIT', `The first lease of this tenure can be issued at ${utc(key.not_before_ms)}, when every earlier lease for the key has ended on every clock and the former validator has had time to stop. Nothing shortens this wait.`, key.not_before_ms - now);
  // A request dated at or before the last one that got a new lease is a recording sent again, or
  // comes from a host whose clock was set back. It is refused and changes nothing: without this
  // rule a recorded repeat of an earlier request could look like a second machine (section 8.1).
  if (request.time_ms <= key.last_request_ms) return deny('CLOCK', `The request is dated ${utc(request.time_ms)}, not later than the last request that got a new lease for this key (${utc(key.last_request_ms)}). A request repeated from a recording is refused like this, and so is one from a host whose clock was set back; in that case it passes by itself.`);
  // The nonce of an EARLIER request that got a lease, while a later request has been served since:
  // a recording of that earlier request, or a machine that still repeats it. A host's clock may be
  // set back inside the allowed skew, so the date alone does not show this. It is refused; a second
  // machine that acts as this host draws a nonce the controller has never served, and is caught below.
  if (request.nonce !== key.request_nonce && key.served_nonces.includes(request.nonce)) return deny('CLOCK', 'The request repeats one that was answered before, and a later request for this key has been served since. A request repeated from a recording is refused like this. A host that keeps asking like this did not install the lease it was given: look at its agent\'s log.');

  const issue = (previousLeaseId, replaced = []) => {
    const expires = now + t.leaseMs;
    const payload = {
      kind: 'signer_lease', release_id: request.release_id, genesis_sha256: request.genesis_sha256, chain_id: request.chain_id, validator_public_key_hex: id,
      signer_identity: host.signer_identity, ...(engine === 'v5' ? { engine: 'v5' } : {}), enforcement: 'EVERY_SIGNATURE', enforcement_basis: 'OPERATOR_DECLARATION',
      fence_domain: state.fence_domain, fence_token: key.fence_token, lease_id: randomBytes(16).toString('hex'), host_id: host.id, request_nonce: request.nonce,
      // renew_by_utc: until then the controller sends this lease again for the same request;
      // after it a new lease takes its place. The agent installs no lease that is past it.
      issued_utc: utc(now - t.backdateMs), expires_utc: utc(expires), renew_by_utc: utc(expires - t.backdateMs),
    };
    const lease = sign(payload);
    const nextKey = {
      ...key, tenure_leases: key.tenure_leases + 1, last_expires_ms: Math.max(key.last_expires_ms, expires), issued_expires_ms: Math.max(key.issued_expires_ms, expires),
      last_grant_ms: Math.max(key.last_grant_ms, now), last_request_ms: Math.max(key.last_request_ms, request.time_ms),
      lease, lease_id: payload.lease_id, previous_lease_id: previousLeaseId, replaced_lease_ids: replaced, request_nonce: request.nonce,
      served_nonces: [...key.served_nonces.filter((nonce) => nonce !== request.nonce), request.nonce].slice(-NONCES_KEPT), release_id: release.release_id, release_order: release.order,
    };
    return { reply: { status: 'granted', lease }, next: { ...state, keys: { ...state.keys, [id]: nextKey } }, event: { ...where, code: 'GRANTED', lease_id: payload.lease_id, fence_token: key.fence_token, expires_utc: payload.expires_utc, release: short(release.release_id) } };
  };

  // The same request again (section 8.1): the host did not get, or did not install, the answer.
  if (key.tenure_leases > 0 && request.nonce === key.request_nonce && request.previous_lease_id === key.previous_lease_id) {
    const stored = key.lease;
    if (stored.payload.release_id === request.release_id && stored.payload.signer_identity === host.signer_identity && Date.parse(stored.payload.expires_utc) - now > t.backdateMs) return { reply: { status: 'granted', lease: stored }, next: null, event: { ...where, code: 'REPEATED', lease_id: key.lease_id } };
    // The stored lease is about to end, or names another release or signer: a new one in its
    // place. The host may have installed the one that is replaced, so its id stays a good answer
    // to "which lease do you hold" (below).
    return issue(key.previous_lease_id, [...key.replaced_lease_ids, key.lease_id].slice(-REPLACED_KEPT));
  }
  // The host holds the last lease issued or one it replaced, or this is the tenure's first lease.
  if (key.tenure_leases === 0 || request.previous_lease_id === key.lease_id || key.replaced_lease_ids.includes(request.previous_lease_id)) {
    const wait = key.last_grant_ms + t.spacingMs - now;
    if (wait > 0) return deny('TOO_SOON', `The last new lease for this key is less than ${t.spacingMs / 1000} s old. The installed lease is still good; ask again later.`, wait);
    return issue(request.previous_lease_id);
  }
  // A fresh, signed request with a new nonce that does not name the last lease issued: two
  // machines act as this host, or the host lost its lease file or its agent state (section 8.4).
  const reason = `a request of host ${host.id} named a lease that is not the last one issued for this key. Either a second machine has this host's key (a cloned or restored machine), or the host's lease file or agent state was replaced.`;
  const frozenKey = { ...key, frozen: { at_ms: now, reason } };
  return { reply: refused('FROZEN', `Consensus key ${id} is now frozen: ${reason} No lease is issued until an operator has made sure that exactly one machine is host ${host.id} and has run: unfreeze ${id}`), next: { ...state, keys: { ...state.keys, [id]: frozenKey } }, event: { ...where, code: 'FROZEN_NOW' } };
}

// ---- The operator's commands (section 6, section 7) -------------------------------

const keyId = (value) => { if (typeof value !== 'string' || !HEX32.test(value)) throw new CommandRefused('A consensus key is 64 lower-case hexadecimal characters (validator_public_key_hex of the operator settings)'); return value; };
function hostOf(config, id) {
  const host = config.hosts.find((item) => item.id === id);
  if (!host) throw new CommandRefused(`The controller config lists no host "${id}". Add it to "hosts" with its public key first; the hosts are: ${config.hosts.map((item) => item.id).join(', ') || '(none)'}`);
  return host;
}
function oneKeyPerHost(state, hostId, except) {
  const other = Object.entries(state.keys).find(([id, key]) => id !== except && key.holder?.host_id === hostId);
  if (other) throw new CommandRefused(`Host ${hostId} already holds consensus key ${other[0]}. A validator host runs one validator. Move or unassign that key first, or use another host.`);
}
const withKey = (state, id, key) => ({ ...state, keys: { ...state.keys, [id]: key } });

export function assign(state, config, id, hostId, now) {
  keyId(id); const host = hostOf(config, hostId), entering = !state.keys[id], key = state.keys[id] ?? emptyKey(state, now);
  if (key.holder) throw new CommandRefused(`Consensus key ${id} is held by host ${key.holder.host_id}. To give it to another host: move ${id} ${hostId} --from ${key.holder.host_id}`);
  oneKeyPerHost(state, hostId, id);
  // A key the state does not know takes its token like a key at a start: from the clock plus
  // five minutes, or the last start's floor if that is higher. A process whose state is lost may
  // have put a token from a clock up to one skew ahead of this one into a lease (design, 5.4).
  const tokenClock = entering ? Math.max(now + GUARD_MAX_LEASE_MS, state.floor_ms) : now;
  return withKey(state, id, newTenure(key, tokenClock, timing(config).marginMs, { holder: { host_id: host.id, public_key_hex: host.public_key_hex } }));
}

export function move(state, config, id, hostId, fromId, now) {
  keyId(id); const host = hostOf(config, hostId), key = state.keys[id];
  if (!key?.holder) throw new CommandRefused(`Consensus key ${id} has no holder. Use: assign ${id} ${hostId}`);
  if (fromId === undefined) throw new CommandRefused(`Say which host holds the key now: move ${id} ${hostId} --from HOST. It is refused unless HOST is the holder, so that a move is never made on a wrong belief.`);
  if (key.holder.host_id !== fromId) throw new CommandRefused(`Consensus key ${id} is held by host ${key.holder.host_id}, not by ${fromId}. Nothing was changed. Run "list" and check which machine runs this validator.`);
  if (hostId === fromId && key.holder.public_key_hex === host.public_key_hex) throw new CommandRefused(`Host ${hostId} already holds this key under the same host key. For a new fence token on the same host use: refence ${id}`);
  oneKeyPerHost(state, hostId, id);
  return withKey(state, id, { ...newTenure(key, now, timing(config).marginMs, { holder: { host_id: host.id, public_key_hex: host.public_key_hex } }), frozen: null });
}

export function unassign(state, config, id, now) {
  keyId(id); const key = state.keys[id];
  if (!key?.holder) throw new CommandRefused(`Consensus key ${id} has no holder.`);
  return withKey(state, id, { ...newTenure(key, now, timing(config).marginMs, { holder: null }), frozen: null });
}

export function unfreeze(state, config, id, now) {
  keyId(id); const key = state.keys[id];
  if (!key?.frozen) throw new CommandRefused(`Consensus key ${id} is not frozen.`);
  return withKey(state, id, { ...newTenure(key, now, timing(config).marginMs), frozen: null });
}

/// A new tenure for the same holder: a new fence token, above `above` if given.
export function refence(state, config, id, now, above = 0n) {
  keyId(id); const key = state.keys[id];
  if (!key?.holder) throw new CommandRefused(`Consensus key ${id} has no holder. Use: assign ${id} HOST`);
  if (key.frozen) throw new CommandRefused(`Consensus key ${id} is frozen. Use: unfreeze ${id}`);
  if (above > BigInt(now) + BigInt(TOKEN_FLOOR_AHEAD_MS)) throw new CommandRefused(`${above} is not a fence token this controller could have issued. A token is a clock reading in milliseconds (the clock now reads ${now}); this number lies more than a hundred years ahead. Read "fence_token" inside "payload" of the host's last lease file again.`);
  return withKey(state, id, newTenure(key, now, timing(config).marginMs, { above }));
}

export function approveRelease(state, manifest, { again = false } = {}) {
  let engine;
  try { validateRelease(manifest); engine = releaseEngine(manifest); } catch (error) { throw new CommandRefused(`The file is not a release manifest this kit accepts (${error.message}). Pass the release.json the release tool wrote.`); }
  if (engine !== state.network.engine) throw new CommandRefused(`Release ${manifest.release_id} runs engine ${engine}. This controller's network runs ${state.network.engine}. Approving it would let the other engine start on this network; it is refused. A ${engine} network has its own genesis and its own controller state.`);
  const known = state.releases.some((item) => item.release_id === manifest.release_id);
  if (known && !again) throw new CommandRefused(`Release ${manifest.release_id} is already approved. To let keys that run a later release go back to it, pass --again.`);
  const releases = [...state.releases.filter((item) => item.release_id !== manifest.release_id), { release_id: manifest.release_id, engine, order: state.next_release_order }];
  return { ...state, releases, next_release_order: state.next_release_order + 1 };
}

export function retireRelease(state, releaseId) {
  if (!state.releases.some((item) => item.release_id === releaseId)) throw new CommandRefused(`Release ${releaseId} is not approved here. Run "list" for the approved releases.`);
  const using = Object.entries(state.keys).filter(([, key]) => key.holder && key.release_id === releaseId).map(([id]) => id);
  if (using.length) throw new CommandRefused(`These keys last had a lease for release ${releaseId}: ${using.join(', ')}. Their validators would stop when their leases run out. Install the next release on those hosts first, or unassign the keys.`);
  return { ...state, releases: state.releases.filter((item) => item.release_id !== releaseId) };
}

/// What `list` prints: everything an operator needs, and nothing secret (the state holds none).
export function summary(state, now) {
  return {
    network: state.network, fence_domain: state.fence_domain, now_utc: utc(now), state_last_written_utc: utc(state.clock_ms),
    releases: [...state.releases].sort((a, b) => a.order - b.order).map((item) => ({ release_id: item.release_id, engine: item.engine, approval_order: item.order })),
    keys: Object.entries(state.keys).sort(([a], [b]) => (a < b ? -1 : 1)).map(([id, key]) => ({
      validator_public_key_hex: id, holder: key.holder?.host_id ?? null, fence_token: key.fence_token, release_id: key.release_id,
      state: key.frozen ? 'FROZEN' : !key.holder ? 'NO_HOLDER' : now < key.not_before_ms ? 'WAITING' : key.tenure_leases === 0 ? 'READY' : now < Date.parse(key.lease.payload.expires_utc) ? 'LEASED' : 'LEASE_ENDED',
      ...(key.frozen ? { frozen_since_utc: utc(key.frozen.at_ms), frozen_because: key.frozen.reason } : {}),
      first_lease_not_before_utc: utc(key.not_before_ms), seconds_until_first_lease: Math.max(0, Math.ceil((key.not_before_ms - now) / 1000)),
      last_lease_expires_utc: key.lease && key.tenure_leases > 0 ? key.lease.payload.expires_utc : null, leases_in_this_tenure: key.tenure_leases,
    })),
  };
}
