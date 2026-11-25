// Which accounts an action touches, and which of them it may wake, read from the action's bytes alone.
//
// Two services use it. The API sends a connected wallet a hint, "your account was touched at height H"
// (api.mjs, GET /v1/touches); the alert service wakes a closed wallet with a browser push that claims nothing
// (alert-push.mjs). Neither tells what happened: the wallet reads its account's state with a proof and works out
// what it says itself (web-v4/wallet/alerts.mjs). A hint too many costs the wallet one read that finds nothing new;
// a hint too few is the only failure. So where the bytes leave a doubt, the account is named.
//
// ---- touched (the hint)
// A block touches account N when it includes an action
//   - sent by N: its `from`, for every kind except the three that have no account yet or none at all (2, a reveal
//     that registers; 40, the public relay of bitcoin headers; 45, a registration that carries its keys), whose
//     `from` is the anonymous account 18446744073709551615. The account-security kinds 70 to 77 are always sent by the
//     account whose security row they change (v5/src/security.rs, `apply`: `host.account(action.from)`): also a
//     replacement of the keys that recovery keys alone ask for (73) and its finishing by a key of the new set (74);
//   - that pays N: 3 a transfer and 10 a payment to a shop (`to`), 73 a root operation whose operation is `pay`
//     (`op.to`), and 75 a payment above the daily limit when it is asked for (`type: request`, `to`: a payment to N
//     now waits);
//   - that names N in protocol 4's guardian recovery: 11 a policy names its guardians (`guardians`), 12 a guardian's
//     consent and 13 a guardian's approval name the account to recover (`target`; an approval starts the wait of a
//     recovery, src/ledger/recovery.rs);
//   - that names N as the owner of a validator: 5 a stake and 6 its withdrawal (`operator`).
// What the bytes do not name is not hinted. None of it changes the security row or the keys of that account:
//   - the account a registration creates (2, 45): it has no number before its block; the wallet that registers
//     reads its own state;
//   - the recipient of a waiting payment that goes through (75 `execute` names the payment by its number only).
//     The API adds it where its index tied the payment to its request (indexer.mjs, followWaiting);
//   - the recipient of a waiting payment that is cancelled (76) or dropped by a freeze or a replacement;
//   - the owner of a validator that double-sign evidence (20) names by its consensus address, and the accounts
//     that rewards and stake movements credit without an action of theirs.
// An action whose payload this SDK cannot decode (a kind it does not know) still has its frame: its sender is
// touched.
//
// ---- woken (the push)
// A push wakes an account's browsers only for an action that changes its keys or its security row, or starts a
// wait on it, and only an action that a key of the account, or a guardian the account itself named and who
// accepted, can cause. A stranger cannot make a person's phone ring:
//   - sent by the account itself: 8 a key added and 9 a key removed, 11 a guardian policy, 14 a guardian recovery
//     cancelled, 15 one finished (its keys are replaced), 16 pending authority cancelled (protocol 4); and 70 to 77,
//     the account-security kinds (rules adopted, sign-in keys, a freeze, a root operation, a replacement finished,
//     a payment above the limit, a cancellation, the daily limit);
//   - 12 and 13 wake their `target`: the engine takes them only from a guardian the target named, and an approval
//     only from one that accepted (src/ledger/recovery.rs, `ConsentRecovery`, `ApproveRecovery`).
// Payments in either direction wake nobody: not a transfer (3), a payment to a shop (10), a stake (5, 6), nor the
// recipient of a root payment (73 `pay`) or of a waiting one (75). An action in a block was taken by the engine:
// a block of this chain commits to successful results for every action it includes, which the alert service
// checks before it wakes anybody (alert-push.mjs, verifyBlock).
import './time-sdk.js';

const SDK = globalThis.TimeSDK;
/// The sender of the actions that have no account.
export const ANONYMOUS = '18446744073709551615';
const DOMAIN = new TextEncoder().encode('TCDEVNET-ACTION-V1\0');
/// Kinds whose sender is woken: protocol 4's keys and guardian recovery, and the account-security kinds.
export const WAKE_SENDER = Object.freeze([8, 9, 11, 14, 15, 16, 70, 71, 72, 73, 74, 75, 76, 77]);
/// Kinds that wake the account they name as `target`: a guardian's consent and approval.
export const WAKE_TARGET = Object.freeze([12, 13]);

const isAccount = (value) => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) < BigInt(ANONYMOUS);
const record = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

/// The accounts a decoded action touches and those it wakes, each as a list of account numbers in decimal, each
/// once. `action` is what TimeSDK.decodeAction gives: { kind, from, payload }.
export function touchesOf(action) {
  const touched = new Set(), wake = new Set();
  if (!record(action) || !Number.isInteger(action.kind)) return { touched: [], wake: [] };
  const { kind, from } = action, payload = record(action.payload) ? action.payload : {};
  const touch = (value) => { if (isAccount(value)) touched.add(value); };
  touch(from);
  if (kind === 3 || kind === 10) touch(payload.to);
  if (kind === 73 && record(payload.op) && payload.op.type === 'pay') touch(payload.op.to);
  if (kind === 75 && payload.type === 'request') touch(payload.to);
  if (kind === 11 && Array.isArray(payload.guardians)) payload.guardians.slice(0, 16).forEach(touch);
  if (kind === 12 || kind === 13) touch(payload.target);
  if (kind === 5 || kind === 6) touch(payload.operator);
  if (WAKE_SENDER.includes(kind) && isAccount(from)) wake.add(from);
  if (WAKE_TARGET.includes(kind) && isAccount(payload.target)) wake.add(payload.target);
  return { touched: [...touched], wake: [...wake] };
}

/// The same from the bytes of a signed action of network `networkId` (hexadecimal). Bytes the SDK cannot decode
/// but that have the frame of an action of this network touch their sender, and wake it when the frame's kind is one
/// that wakes its sender (WAKE_SENDER): an SDK older than the chain, or a payload it cannot read, must not silence the
/// alert of an action of the account's own keys. Only the sender's key could have made such an action, so nobody else
/// is made to ring. Anything else touches nobody.
export function touchesOfBytes(bytes, networkId) {
  const raw = bytes instanceof Uint8Array ? bytes : new Uint8Array(0);
  let action = null;
  try { action = SDK.decodeAction(raw); } catch { action = null; }
  if (action) return action.networkId === networkId ? touchesOf(action) : { touched: [], wake: [] };
  // The frame: domain, network (32), kind (1), from (8), nonce (8), authority epoch (8), key (32), length (4),
  // payload, signature (64).
  const head = DOMAIN.length;
  if (raw.length < head + 93 + 64 || !DOMAIN.every((byte, i) => raw[i] === byte)) return { touched: [], wake: [] };
  if (SDK.bytesToHex(raw.subarray(head, head + 32)) !== networkId) return { touched: [], wake: [] };
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  if (view.getUint32(head + 89) !== raw.length - head - 93 - 64) return { touched: [], wake: [] };
  const from = view.getBigUint64(head + 33).toString(), kind = raw[head + 32];
  if (!isAccount(from)) return { touched: [], wake: [] };
  return { touched: [from], wake: WAKE_SENDER.includes(kind) ? [from] : [] };
}
