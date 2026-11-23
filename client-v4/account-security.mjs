// Account security for wallets: separate keys for signing in, spending and recovery.
//
// This is the wallet's side of the engine rules in v5/src/security.rs. It builds the
// exact bytes those rules verify (a key's acceptance of its role, an approval of a root
// operation) and the payloads of the eight actions, each in its one accepted form.
// Nothing here talks to a network or keeps a key: callers pass WebCrypto Ed25519 keys.
import './time-sdk.js';

const SDK = globalThis.TimeSDK;
const utf8 = new TextEncoder();
const fail = (message) => { throw new Error(message); };
const u64 = (value) => { const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, BigInt(SDK.decimal(String(value)))); return out; };
const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const signHex = async (privateKey, message) => SDK.bytesToHex(new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, message)));

export const KIND = Object.freeze({ secure: 70, signin: 71, freeze: 72, root: 73, finalize: 74, payment: 75, cancel: 76, limit: 77 });
/// Kinds that take the account's next nonce. The others carry nonce and authority epoch zero.
export const SEQUENCED = Object.freeze(new Set([KIND.secure, KIND.signin, KIND.payment, KIND.limit]));
export const ROLES = Object.freeze(['signin', 'spend', 'recover']);
const DAY_MICROS = 86_400_000_000n;
const ROLE_BYTE = { signin: 0, spend: 1, recover: 2 };

/// The role of a device row: 'signin', 'spend', 'recover', or null for a protocol-4 key with both powers.
export function roleOf(device) {
  if (device.can_manage && device.can_spend) return null;
  return device.can_manage ? 'recover' : device.can_spend ? 'spend' : 'signin';
}
/// True if an account has adopted the security rules (it comes with a security row in verified state).
export function securityOf(state, accountId) {
  return (state.security || []).find((row) => row.account === String(accountId)) || null;
}

// ------------------------------------------------------------------ what keys sign
/// What the holder of a key signs to accept a role on an account.
export function keyMessage({ networkId, accountId, role, publicKey }) {
  if (!(role in ROLE_BYTE)) fail('Unknown role');
  return SDK.concat(utf8.encode('TCDEVNET-ACCOUNT-KEY-V1\0'), SDK.hexToBytes(networkId, 32), u64(accountId), Uint8Array.of(ROLE_BYTE[role]), SDK.hexToBytes(publicKey, 32));
}
/// A key entry for a set of keys, carrying its holder's acceptance.
export async function acceptRole({ networkId, accountId, role, publicKey, privateKey }) {
  return { public_key: publicKey, role, proof: await signHex(privateKey, keyMessage({ networkId, accountId, role, publicKey })) };
}
/// A key entry for the set of keys of a registration that creates its account protected (kind 45, on a
/// network with `protected_registration`): the key accepts its role on the account that the registration
/// key `registrationKey` is about to create. That account has no number yet, so the acceptance names the
/// registration key (`TimeSDK.registrationRoleBytes`); it is good for that registration and nothing else.
/// `TimeSDK.protectedNameCommitment` and `TimeSDK.signProtectedRegistration` take the set built from these.
export async function acceptRegistrationRole({ networkId, registrationKey, role, publicKey, privateKey }) {
  return { public_key: publicKey, role, proof: await signHex(privateKey, SDK.registrationRoleBytes({ networkId, registrationKey, role, publicKey })) };
}
/// A key that is already on the account in this role needs no new acceptance. In a replacement,
/// a sign-in key kept this way is left out if a spend key has removed it in the meantime; a
/// spend or recovery key kept this way must still be there. To be sure a sign-in key is in the
/// new set whatever happens meanwhile, pass its acceptance (`acceptRole`) instead.
export const keepKey = (publicKey, role) => ({ public_key: publicKey, role });
/// The one accepted order of a list of keys or approvals: by public key.
export function sortByKey(list) {
  const sorted = [...list].sort((a, b) => (a.public_key < b.public_key ? -1 : a.public_key > b.public_key ? 1 : 0));
  for (let i = 1; i < sorted.length; i++) if (sorted[i].public_key === sorted[i - 1].public_key) fail('A key appears twice');
  return sorted;
}
const canonical = (value) => utf8.encode(JSON.stringify(sortedValue(value)));
function sortedValue(value) {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(sortedValue);
  if (value && typeof value === 'object') { const out = {}; for (const key of Object.keys(value).sort()) out[key] = sortedValue(value[key]); return out; }
  fail('Payloads hold strings, lists and objects only');
}
/// What a key signs to approve a root operation. `approvers` are the public keys of everyone
/// who approves: the approval is worthless with any other set.
export async function rootMessage({ networkId, accountId, version, expiresElapsedMicros, operation, approvers }) {
  const keys = [...approvers].sort();
  for (let i = 1; i < keys.length; i++) if (keys[i] === keys[i - 1]) fail('An approver appears twice');
  return SDK.concat(
    utf8.encode('TCDEVNET-ACCOUNT-ROOT-V1\0'), SDK.hexToBytes(networkId, 32), u64(accountId), u64(version), u64(expiresElapsedMicros),
    await sha256(canonical(operation)), await sha256(SDK.concat(...keys.map((key) => SDK.hexToBytes(key, 32)))),
  );
}
export async function approve({ networkId, accountId, version, expiresElapsedMicros, operation, approvers, publicKey, privateKey }) {
  if (!approvers.includes(publicKey)) fail('The approving key is not in the list of approvers');
  return { public_key: publicKey, signature: await signHex(privateKey, await rootMessage({ networkId, accountId, version, expiresElapsedMicros, operation, approvers })) };
}

// ------------------------------------------------------------------ payloads
const d = (value) => SDK.decimal(String(value));
export function policy({ threshold, dailyLimitMicros, delaySeconds, freezeSeconds }) {
  return { threshold: d(threshold), daily_limit_micros: d(dailyLimitMicros), delay_seconds: d(delaySeconds), freeze_seconds: d(freezeSeconds) };
}
export const operations = Object.freeze({
  /// A whole new set of keys and policy. At once with a spend key among the approvers; otherwise after the wait.
  replace: (keys, rules) => ({ type: 'replace', keys: sortByKey(keys), policy: rules }),
  /// Calls off a replacement that is waiting.
  cancel: () => ({ type: 'cancel' }),
  /// Lifts the freeze the approvers saw (`freezes` is the count in the security row).
  unfreeze: (freezes) => ({ type: 'unfreeze', freezes: d(freezes) }),
  /// A payment above the daily limit, at once. Its approvals are valid for an hour at most.
  pay: (to, amountMicros) => ({ type: 'pay', to: d(to), amount: d(amountMicros) }),
});
export const payloads = Object.freeze({
  secure: (keys, rules) => ({ keys: sortByKey(keys), policy: rules }),
  /// Adds and removes sign-in keys, at once: how a spend key alone answers a stolen login.
  signin: ({ add = [], remove = [] }) => ({ add: sortByKey(add).map(({ public_key, proof }) => ({ public_key, proof })), remove: [...remove].sort() }),
  /// A freeze names the freeze count and the version of the settings it is signed for (both are
  /// in the security row), and a date after which it is void. Nodes admit it only if that date
  /// is at least 30 seconds ahead; a few minutes is a good choice.
  freeze: (security, expiresElapsedMicros) => ({ freezes: d(security.freezes), version: d(security.version), expires_elapsed_micros: d(expiresElapsedMicros) }),
  root: (operation, expiresElapsedMicros, approvals) => ({ op: operation, expires_elapsed_micros: d(expiresElapsedMicros), approvals: sortByKey(approvals) }),
  finalize: (security) => ({ version: d(security.version) }),
  paymentRequest: (to, amountMicros) => ({ type: 'request', to: d(to), amount: d(amountMicros) }),
  paymentExecute: (id) => ({ type: 'execute', id: d(id) }),
  cancelPayment: (id) => ({ type: 'payment', id: d(id) }),
  cancelRaise: (id) => ({ type: 'limit', id: d(id) }),
  limit: (dailyLimitMicros) => ({ daily_limit_micros: d(dailyLimitMicros) }),
});

/// Signs one of the eight actions. Kinds that take a nonce use the account row's next one;
/// protective kinds (freeze, root, finalize, cancel) carry none, so that nothing else the
/// account does can keep them out. Sign-in keys sign none of them: the chain accepts
/// protective actions from spend and recovery keys only.
///
/// What an action costs the account: the fee of the network, a setting of its genesis that comes
/// with verified state (`TimeSDK.networkFee(state)`; 1000 microseconds unless the network set a
/// lower one). A freeze, a cancellation, a replacement asked for by recovery keys alone and
/// finishing one cost the fee or, if the account has less, what it has. Every other root
/// operation needs the full fee in the account.
export async function signSecurityAction({ networkId, kind, account, publicKey, privateKey, payload }) {
  if (!Object.values(KIND).includes(kind)) fail('Not an account security action');
  const sequenced = SEQUENCED.has(kind);
  return SDK.signAction({
    networkId, kind, from: String(account.id), publicKey, payload,
    nonce: sequenced ? (BigInt(account.nonce) + 1n).toString() : '0',
    authEpoch: sequenced ? String(account.auth_epoch) : '0',
  }, privateKey);
}

// ------------------------------------------------------------------ reading a security row
// `nowElapsedMicros` in the three functions below is the clock the account security rules read:
// `TimeSDK.securityNow(state)`. On a network whose waits survive a stop (`waits_survive_stops`) that is
// the chain's time minus the total of its stops, and the moments a security row stores are moments on
// that clock; on any other network it is the chain's time since genesis, as it always was. Passing the
// chain's time on a network with the rule reads a freeze as over, a wait as due and the allowance as
// refilled too early, by the total of the stops. For a date to show, use `TimeSDK.securityDeadline`.
/// What the spend keys may still move at `nowElapsedMicros` (the daily limit refills evenly over 24 hours).
export function allowance(security, nowElapsedMicros) {
  let limit = BigInt(security.policy.daily_limit_micros), level = BigInt(security.allowance_micros), since = BigInt(security.allowance_elapsed_micros);
  const now = BigInt(nowElapsedMicros), raise = security.pending_limit;
  const fill = (from, to, cap) => { const waited = to > from ? to - from : 0n; let refill = cap * waited / DAY_MICROS; if (refill > cap) refill = cap; const sum = level + refill; return sum > cap ? cap : sum; };
  if (raise && BigInt(raise.ready_elapsed_micros) <= now) { level = fill(since, BigInt(raise.ready_elapsed_micros), limit); since = BigInt(raise.ready_elapsed_micros); limit = BigInt(raise.daily_limit_micros); }
  return fill(since, now, limit);
}
/// Whether outgoing payments are stopped: by a freeze, or while a replacement of the keys waits.
export function frozen(security, nowElapsedMicros) {
  const now = BigInt(nowElapsedMicros), waiting = security.pending_root;
  return now < BigInt(security.frozen_until_elapsed_micros) || Boolean(waiting && BigInt(waiting.expires_elapsed_micros) >= now);
}
/// The login rule for websites: why `publicKey` may not sign in as `account` now, or null if
/// it may. `security` is the account's security row from verified state, or null if it has
/// none. Only an account none of whose keys holds both powers can have one: read the state of
/// such an account with `include_security`, so that the row or its absence is proven.
/// - An account that has adopted the security rules signs in with a sign-in key only. Keys
///   that can spend or recover do not belong on every device that signs in.
/// - Nobody signs in while the account is frozen. A freeze is how the owner stops everything
///   when a device is gone, and the sign-in key on that device went with it.
/// - Any other account signs in with any of its keys, as in protocol 4.
export function signInRefusal({ account, security, publicKey, nowElapsedMicros }) {
  const device = account.devices.find((row) => row.public_key === publicKey);
  if (!device) return 'This key is not a key of the account';
  if (!security) return null;
  if (roleOf(device) !== 'signin') return 'This key can spend or recover: sign in with a sign-in key';
  if (frozen(security, nowElapsedMicros)) return 'The account is frozen: nobody signs in until the freeze ends or its keys are replaced';
  return null;
}
/// The proofs a list of approving keys amounts to: all spend keys together count once, each recovery key once.
export function proofs(account, approverKeys) {
  let recover = 0, spend = false;
  for (const key of approverKeys) {
    const device = account.devices.find((row) => row.public_key === key) || fail('An approver is not a key of the account');
    const role = roleOf(device);
    if (role === 'recover') recover += 1; else if (role === 'spend') spend = true; else fail('Only spend and recovery keys approve');
  }
  return { count: recover + (spend ? 1 : 0), spend };
}
