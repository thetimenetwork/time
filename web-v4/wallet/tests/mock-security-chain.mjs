// The rules of a protected account, for the wallet's own tests and its preview: what the engine does with a payment
// of the payment key and with the actions of kinds 72, 73, 75, 76 and 77.
//
// This is a reading of v5/src/security.rs (`apply`, `Security::level`, `settle`, `charge`, `install`), written on
// 2026-11-22 for protection-card.test.mjs and preview-server.mjs. It is not the engine, and nothing here shows that
// the engine takes an action: the engine's own tests (v5/tests/security.rs) and a run on a network do. What it holds
// in place is that the wallet signs what these rules, as read, accept, and says what they then do. Refusals carry the
// engine's words. Left out: the expiry margin of the mempool, a validator safety hold, kinds 70, 71 and 74, a
// replacement asked for by recovery keys alone beyond making it wait, and the check that a new set of keys is sorted.
//
// Rows are the JSON of proven state: every number a decimal string. `now` is elapsed microseconds since genesis.
export const DAY_MICROS = 86400000000n;
const MICROS = 1000000n, MONTH_MICROS = 30n * DAY_MICROS;
const refuse = message => { throw new Error(message); };
const ensure = (condition, message) => { if (!condition) refuse(message); };
const roleOf = device => (device.can_manage && device.can_spend ? null : device.can_manage ? 'recover' : device.can_spend ? 'spend' : 'signin');
const flags = role => ({ can_manage: role === 'recover', can_spend: role === 'spend' });

/// What the spend keys may still move at `now` (`Security::level`): the allowance refills evenly over 24 hours.
export function level(row, now) {
  const limit = BigInt(row.policy.daily_limit_micros), since = BigInt(row.allowance_elapsed_micros), waited = now > since ? now - since : 0n;
  let refill = limit * waited / DAY_MICROS; if (refill > limit) refill = limit;
  const sum = BigInt(row.allowance_micros) + refill;
  return sum > limit ? limit : sum;
}
/// Brings the row up to `now` (`Security::settle`): a raise that has waited applies; a replacement nobody finished is dropped.
export function settle(row, now) {
  const raise = row.pending_limit;
  if (raise && BigInt(raise.ready_elapsed_micros) <= now) {
    row.allowance_micros = level(row, BigInt(raise.ready_elapsed_micros)).toString(); row.allowance_elapsed_micros = raise.ready_elapsed_micros;
    row.policy.daily_limit_micros = raise.daily_limit_micros; row.pending_limit = null;
  }
  if (row.pending_root && BigInt(row.pending_root.expires_elapsed_micros) < now) row.pending_root = null;
}
export const frozen = (row, now) => now < BigInt(row.frozen_until_elapsed_micros) || Boolean(row.pending_root);
function charge(row, outflow, now) {
  const left = level(row, now);
  ensure(outflow <= left, 'over the daily limit of this account: use a payment that waits, or a second proof');
  row.allowance_micros = (left - outflow).toString(); row.allowance_elapsed_micros = now.toString();
}
const dropWaiting = row => { row.pending_payments = []; row.pending_limit = null; };
const takeId = row => { const id = row.next_id; row.next_id = (BigInt(id) + 1n).toString(); return id; };
const bump = (object, field) => { object[field] = (BigInt(object[field]) + 1n).toString(); };

/// A chain of accounts and security rows that applies decoded actions (TimeSDK.decodeAction).
/// `sdk`: TimeSDK. `security`: client-v4/account-security.mjs, whose messages the signatures inside a payload are
/// checked against, as the engine checks them. `fee`: the network's fee in microseconds.
export function createSecurityChain({ sdk, security, networkId, accounts, rows, fee = 1000n }) {
  const find = id => accounts.find(item => item.id === String(id));
  async function verified(publicKey, signature, message) {
    const key = await crypto.subtle.importKey('raw', sdk.hexToBytes(publicKey, 32), 'Ed25519', false, ['verify']);
    return crypto.subtle.verify('Ed25519', key, sdk.hexToBytes(signature, 64), message);
  }
  function pay(from, to, amount) { from.balance = (BigInt(from.balance) - amount).toString(); to.balance = (BigInt(to.balance) + amount).toString(); }
  /// The fee: in full, or what the account has if that is less (`reduced`).
  function settleFee(account, reduced) {
    const due = reduced && BigInt(account.balance) < fee ? BigInt(account.balance) : fee;
    ensure(BigInt(account.balance) >= due, 'insufficient funds for fee');
    account.balance = (BigInt(account.balance) - due).toString();
  }
  const sequenced = (account, action) => ensure(BigInt(action.nonce) === BigInt(account.nonce) + 1n && action.authEpoch === account.auth_epoch, 'stale authority or incorrect nonce');
  const unsequenced = action => ensure(action.nonce === '0' && action.authEpoch === '0', 'a protective action carries no nonce');

  /// Applies one action of a protected account at `now`, or throws with the reason. Nothing is changed by an action that is refused.
  async function apply(action, now) {
    const original = find(action.from); ensure(original && rows[original.id], 'account has not adopted the security rules');
    // Worked on copies, written back only when the action went through.
    const account = structuredClone(original), row = structuredClone(rows[account.id]), p = action.payload;
    const device = account.devices.find(item => item.public_key === action.publicKey), role = device ? roleOf(device) : undefined;
    let credit = null;
    settle(row, now);
    const guards = () => ensure(role === 'spend' || role === 'recover', 'a spend or recovery key of this account is required');
    if (action.kind === sdk.KINDS.transfer || action.kind === sdk.KINDS.merchant_payment) {
      ensure(role === 'spend', 'device is not authorized'); sequenced(account, action);
      const amount = BigInt(p.amount), to = find(p.to);
      ensure(to && to.id !== account.id && amount > 0n, 'invalid payment amount or recipient');
      ensure(BigInt(account.balance) >= amount + fee, 'insufficient liquid funds');
      ensure(!frozen(row, now), 'account is frozen'); charge(row, amount + fee, now);
      account.nonce = action.nonce; settleFee(account, false); credit = [to.id, amount];
    } else if (action.kind === 72) {
      guards(); unsequenced(action);
      ensure(BigInt(p.expires_elapsed_micros) > now && BigInt(p.expires_elapsed_micros) <= now + MONTH_MICROS, 'expired, expiring too soon to be included, or dated too far ahead');
      ensure(p.freezes === row.freezes, 'the account has been frozen since: read its state again');
      ensure(p.version === row.version, 'the security settings have changed: read them again');
      const length = BigInt(row.policy.freeze_seconds) * MICROS, until = BigInt(row.frozen_until_elapsed_micros);
      ensure((until > now ? until - now : 0n) <= length / 2n, 'account is already frozen');
      bump(row, 'freezes'); row.frozen_until_elapsed_micros = (now + length).toString(); dropWaiting(row); settleFee(account, true);
    } else if (action.kind === 73) {
      guards(); unsequenced(action);
      ensure(BigInt(p.expires_elapsed_micros) > now && BigInt(p.expires_elapsed_micros) <= now + MONTH_MICROS, 'expired, expiring too soon to be included, or dated too far ahead');
      let recover = 0, spend = false;
      for (const approval of p.approvals) {
        const approver = account.devices.find(item => item.public_key === approval.public_key); ensure(approver, 'approval from a key that is not on the account');
        const approverRole = roleOf(approver); ensure(approverRole === 'spend' || approverRole === 'recover', 'only spend and recovery keys approve root operations');
        if (approverRole === 'spend') spend = true; else recover += 1;
      }
      ensure(BigInt(recover + (spend ? 1 : 0)) >= BigInt(row.policy.threshold), 'not enough proofs for a root operation');
      const op = p.op, reduced = !spend && op.type === 'replace';
      ensure(reduced || BigInt(account.balance) >= fee, 'insufficient funds for fee');
      const message = await security.rootMessage({ networkId, accountId: account.id, version: row.version, expiresElapsedMicros: p.expires_elapsed_micros, operation: op, approvers: p.approvals.map(item => item.public_key) });
      const prove = async () => { for (const approval of p.approvals) ensure(await verified(approval.public_key, approval.signature, message), 'signature does not verify'); };
      if (op.type === 'replace') {
        ensure(Object.keys(op).sort().join() === 'keys,policy,type' && Object.keys(op.policy).sort().join() === 'daily_limit_micros,delay_seconds,freeze_seconds,threshold', 'payload is not in its one accepted form');
        const devices = [];
        for (const key of op.keys) {
          ensure(['signin', 'spend', 'recover'].includes(key.role), 'unknown role');
          const kept = account.devices.some(item => item.public_key === key.public_key && roleOf(item) === key.role);
          if (key.proof === undefined && !kept) { ensure(key.role === 'signin' && !account.devices.some(item => item.public_key === key.public_key), 'a new key, or a key in a new role, must carry its holder\'s acceptance'); continue; }
          devices.push({ public_key: key.public_key, ...flags(key.role) });
        }
        const recovering = devices.filter(item => roleOf(item) === 'recover').length;
        ensure(devices.some(item => roleOf(item) === 'spend'), 'at least one spend key is required');
        ensure(BigInt(op.policy.threshold) >= 2n && BigInt(op.policy.threshold) <= BigInt(recovering), 'the threshold is at least two and at most the number of recovery keys');
        await prove();
        for (const key of op.keys) if (key.proof !== undefined) ensure(await verified(key.public_key, key.proof, security.keyMessage({ networkId, accountId: account.id, role: key.role, publicKey: key.public_key })), 'signature does not verify');
        if (spend) {
          // `install`: the new keys and policy are in force at once; every wait and freeze ends; the allowance is not filled.
          const left = level(row, now), limit = BigInt(op.policy.daily_limit_micros);
          row.allowance_micros = (left < limit ? left : limit).toString(); row.allowance_elapsed_micros = now.toString();
          row.policy = structuredClone(op.policy); row.frozen_until_elapsed_micros = '0'; dropWaiting(row); row.pending_root = null;
          account.devices = devices; bump(account, 'nonce'); bump(account, 'auth_epoch');
        } else {
          ensure(!row.pending_root, 'a replacement is already waiting: cancel it first');
          const ready = now + BigInt(row.policy.delay_seconds) * MICROS;
          row.pending_root = { devices, policy: structuredClone(op.policy), ready_elapsed_micros: ready.toString(), expires_elapsed_micros: (ready + DAY_MICROS).toString() }; dropWaiting(row);
        }
      } else if (op.type === 'cancel') { ensure(row.pending_root, 'no replacement is waiting'); await prove(); row.pending_root = null; }
      else if (op.type === 'unfreeze') {
        ensure(spend, 'a spend key must take part');
        ensure(op.freezes === row.freezes && BigInt(row.frozen_until_elapsed_micros) > now, 'account is not frozen, or has been frozen again since');
        await prove(); row.frozen_until_elapsed_micros = '0';
      } else if (op.type === 'pay') {
        ensure(spend, 'a spend key must take part');
        ensure(BigInt(p.expires_elapsed_micros) <= now + 3600n * MICROS, 'expired, expiring too soon to be included, or dated too far ahead');
        ensure(!row.pending_root, 'a replacement of the keys is waiting');
        const amount = BigInt(op.amount), to = find(op.to);
        ensure(to && to.id !== account.id && amount > 0n, 'invalid payment amount or recipient');
        ensure(BigInt(account.balance) >= amount + fee, 'insufficient liquid funds');
        await prove(); credit = [to.id, amount];
      } else refuse('payload is not in its one accepted form');
      bump(row, 'version'); settleFee(account, reduced);
    } else if (action.kind === 75) {
      ensure(role === 'spend', 'a spend key is required'); sequenced(account, action);
      ensure(!frozen(row, now), 'account is frozen');
      // The fee of either step comes out of the daily limit.
      charge(row, fee, now);
      if (p.type === 'request') {
        const to = find(p.to); ensure(to && to.id !== account.id && BigInt(p.amount) > 0n, 'invalid payment amount or recipient');
        ensure(row.pending_payments.length < 4, 'too many payments are waiting');
        row.pending_payments.push({ id: takeId(row), to: to.id, amount: p.amount, ready_elapsed_micros: (now + BigInt(row.policy.delay_seconds) * MICROS).toString() });
      } else {
        const at = row.pending_payments.findIndex(item => item.id === p.id); ensure(at >= 0, 'no such waiting payment');
        const [payment] = row.pending_payments.splice(at, 1);
        ensure(now >= BigInt(payment.ready_elapsed_micros), 'the waiting period is not over');
        ensure(BigInt(account.balance) >= BigInt(payment.amount) + fee, 'insufficient liquid funds');
        credit = [payment.to, BigInt(payment.amount)];
      }
      account.nonce = action.nonce; settleFee(account, false);
    } else if (action.kind === 76) {
      guards(); unsequenced(action);
      if (p.type === 'payment') { const at = row.pending_payments.findIndex(item => item.id === p.id); ensure(at >= 0, 'no such waiting payment'); row.pending_payments.splice(at, 1); }
      else { ensure(row.pending_limit && row.pending_limit.id === p.id, 'no such raise of the limit is waiting'); row.pending_limit = null; }
      settleFee(account, true);
    } else if (action.kind === 77) {
      ensure(role === 'spend', 'a spend key is required'); sequenced(account, action);
      ensure(p.daily_limit_micros !== row.policy.daily_limit_micros, 'the limit already has this value');
      ensure(!frozen(row, now), 'account is frozen');
      // The fee of this action is charged to the allowance before the limit changes.
      charge(row, fee, now);
      const next = BigInt(p.daily_limit_micros);
      if (next < BigInt(row.policy.daily_limit_micros)) {
        // Lowering protects: at once, and it cuts what is left.
        row.policy.daily_limit_micros = p.daily_limit_micros; if (BigInt(row.allowance_micros) > next) row.allowance_micros = next.toString(); row.pending_limit = null;
      } else row.pending_limit = { id: takeId(row), daily_limit_micros: p.daily_limit_micros, ready_elapsed_micros: (now + BigInt(row.policy.delay_seconds) * MICROS).toString() };
      account.nonce = action.nonce; settleFee(account, false);
    } else refuse('unsupported action');
    ensure(BigInt(row.allowance_micros) <= BigInt(row.policy.daily_limit_micros), 'invalid security row');
    Object.assign(original, account); rows[original.id] = row;
    if (credit) { const to = find(credit[0]); pay(original, to, credit[1]); }
  }
  return { apply, takes: action => Boolean(rows[action.from]) };
}
