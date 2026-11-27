// An action in plain words. Takes an action as the API gives it (a list item, or the detail with
// its payload) or as the SDK decodes proven bytes, and returns which sentence of the strings table
// says it and the values that go into the sentence. No text of the action is ever part of the
// sentence itself: every value is checked here and handed over with its type, and the page shows
// each type in its own fixed way.
import { isAccountId, isMicros, isReference, isKey, isName, isHash } from './format.mjs';

const invalid = Object.freeze({ type: 'invalid' });
const account = (value) => (isAccountId(value) ? { type: 'account', id: value } : invalid);
const amount = (value) => (isMicros(value) ? { type: 'amount', micros: value } : invalid);
const reference = (value) => (isReference(value) ? { type: 'reference', hex: value } : invalid);
const key = (value) => (isKey(value) ? { type: 'key', hex: value } : invalid);
const number = (value) => (isMicros(value) ? { type: 'number', value } : Number.isSafeInteger(value) && value >= 0 ? { type: 'number', value: String(value) } : invalid);
const name = (value) => (isName(value) ? { type: 'name', name: value } : invalid);
/// A number of seconds from a policy, shown as an amount of time.
const seconds = (value) => (isMicros(value) && BigInt(value) <= 18446744073709n ? { type: 'amount', micros: (BigInt(value) * 1000000n).toString() } : invalid);
const percentOfBps = (value) => (Number.isInteger(value) && value >= 0 && value <= 10000 ? { type: 'percent', value: `${Math.floor(value / 100)}.${String(value % 100).padStart(2, '0')}` } : invalid);
const role = (value) => (['signin', 'spend', 'recover'].includes(value) ? { type: 'role', role: value } : invalid);
/// The hash of a specification: 64 lower-case hexadecimal characters.
const hash = (value) => (isKey(value) ? { type: 'hash', hex: value } : invalid);
/// A moment the chain gives as time since the start of the network, in microseconds.
const sinceStart = (value) => (isMicros(value) ? { type: 'sinceStart', micros: value } : invalid);
const object = (value) => (value && typeof value === 'object' && !Array.isArray(value) ? value : null);
const list = (value, max = 64) => (Array.isArray(value) ? value.slice(0, max) : []);

/// The kinds this page can put into words, and what each is about. A kind that is not here is
/// shown as "an action this page cannot read", with its number.
export const CATEGORIES = Object.freeze({
  1: 'name', 2: 'name', 44: 'name', 45: 'name',
  3: 'payment', 10: 'payment',
  4: 'auction', 41: 'auction', 42: 'auction', 40: 'auction',
  5: 'stake', 6: 'stake', 7: 'stake', 18: 'stake', 19: 'stake', 21: 'stake',
  17: 'validator', 24: 'validator', 20: 'validator', 80: 'validator',
  8: 'keys', 9: 'keys', 70: 'keys', 71: 'keys', 74: 'keys',
  11: 'recovery', 12: 'recovery', 13: 'recovery', 14: 'recovery', 15: 'recovery', 16: 'recovery',
  60: 'treasury', 61: 'treasury', 62: 'treasury',
  72: 'security', 73: 'security', 77: 'security',
  75: 'pending', 76: 'pending',
  // The market of seconds against bitcoin (spec/market.md, section 6), on a network that has it.
  50: 'market', 51: 'market', 52: 'market', 53: 'market', 54: 'market', 55: 'market', 56: 'market', 57: 'market', 58: 'market',
});
const REQUEST_STATUS = Object.freeze(['waiting', 'completed', 'cancelled', 'dropped', 'ended', 'unknown']);

/// The same fields whether the action comes from the API (sender, recipient, amount, reference,
/// payload) or from the SDK's decoder of proven bytes (from, payload).
function normalise(action) {
  const source = object(action) ?? {};
  const payload = object(source.payload);
  if (source.from !== undefined && source.sender === undefined) {
    // Decoded bytes: the facts are read from the payload as the indexer reads them.
    const kind = source.kind, op = object(payload?.op);
    const pay = kind === 3 || kind === 10 ? payload : kind === 73 && op?.type === 'pay' ? op : kind === 75 && payload?.type === 'request' ? payload : null;
    return { kind, opaque: false, sender: source.from === '18446744073709551615' ? null : source.from, payload, recipient: pay?.to ?? null, amount: pay?.amount ?? null,
      reference: kind === 10 ? payload?.reference ?? null : null, requestStatus: null, requestHash: null, unattributed: false, decoded: true };
  }
  return { kind: source.kind, opaque: source.opaque === true, sender: source.sender ?? null, payload, recipient: source.recipient ?? null, amount: source.amount ?? null, reference: source.reference ?? null,
    requestStatus: source.request_status ?? null, requestHash: source.request_hash ?? null, unattributed: source.unattributed === true, decoded: false };
}

/// Returns { category, sentence, params, status, details }:
/// - `sentence`: the entry of the strings table, with {from}, {to}, {amount}... placeholders;
/// - `params`: the typed values for the placeholders;
/// - `status`: for a payment that waits, how it ended as far as the index knows (an entry name), or null;
/// - `details`: further facts from the payload, as [{ label, value }].
export function describeAction(action) {
  const a = normalise(action);
  const kind = Number.isInteger(a.kind) && a.kind >= 0 && a.kind <= 255 ? a.kind : null;
  const from = a.sender === null ? { type: 'nobody' } : account(a.sender);
  const p = a.payload ?? {}, details = [];
  const add = (label, value) => { if (value && value.type !== 'invalid') details.push({ label, value }); };
  const out = (sentence, params = {}, status = null) => ({ category: CATEGORIES[kind] ?? 'unknown', kind, sentence, params: { from, ...params }, status, details });
  if (kind === null) return { category: 'unknown', kind: null, sentence: 'act.unreadable', params: { from }, status: null, details };
  // A signal the index holds without its content (an index filled before the service read this
  // kind keeps such rows): the kind alone says what it is about, not which of its two forms it has.
  if (a.opaque && kind === 80) return out('act.signalPlain');
  if (a.opaque || !Object.hasOwn(CATEGORIES, kind)) return { category: 'unknown', kind, sentence: 'act.opaque', params: { from, kind: number(kind) }, status: null, details };
  const to = account(a.recipient), sum = amount(a.amount);
  switch (kind) {
    case 3: return out('act.transfer', { to, amount: sum });
    case 10: return out(isReference(a.reference) ? 'act.shopPayment' : 'act.transfer', { to, amount: sum, reference: reference(a.reference) });
    case 1: add('detail.expires', amount(p.expires_elapsed_micros)); return out('act.commit');
    case 2: return out(isName(p.name) ? 'act.reveal' : 'act.revealPlain', { name: name(p.name) });
    case 44: add('detail.newKey', key(p.public_key)); return out('act.sponsor');
    case 45: {
      // A registration that creates its account with separate keys and a daily limit from its first block (on a
      // network with `protected_registration`): the name, and the keys and the rules as the adopting action (70)
      // carries them. A list item comes without content.
      const security = object(p.security) ?? {}, policy = object(security.policy) ?? {};
      for (const entry of list(security.keys, 16)) { const row = object(entry) ?? {}; if (isKey(row.public_key) && role(row.role).type === 'role') details.push({ label: `detail.key.${row.role}`, value: key(row.public_key) }); }
      add('detail.dailyLimit', amount(policy.daily_limit_micros)); add('detail.delay', seconds(policy.delay_seconds)); add('detail.freezeLength', seconds(policy.freeze_seconds)); add('detail.threshold', number(policy.threshold));
      return out(isName(p.name) ? 'act.registerProtected' : 'act.registerProtectedPlain', { name: name(p.name) });
    }
    case 4: return out(a.payload ? 'act.bid' : 'act.bidPlain', { weight: number(p.weight), epoch: number(p.epoch) });
    case 41: return out('act.bitcoinBid');
    case 42: return out('act.claimAuction');
    case 40: return out('act.bitcoinHeaders');
    case 5: return out(a.payload ? 'act.delegate' : 'act.delegatePlain', { validator: account(p.operator), amount: amount(p.amount) });
    case 6: add('detail.shares', number(p.shares)); return out(a.payload ? 'act.undelegate' : 'act.undelegatePlain', { validator: account(p.operator) });
    case 7: add('detail.entry', number(p.entry)); return out('act.withdraw');
    case 18: return out(a.payload ? 'act.selfBond' : 'act.selfBondPlain', { amount: amount(p.amount) });
    case 19: return out(a.payload ? 'act.selfUnbond' : 'act.selfUnbondPlain', { amount: amount(p.amount) });
    case 21: add('detail.entry', number(p.entry)); return out('act.withdrawStake');
    case 17: add('detail.consensusKey', key(p.consensus_key)); add('detail.commission', percentOfBps(p.commission_bps)); return out('act.registerValidator');
    case 24: return out('act.retireValidator');
    case 20: return out('act.doubleVote');
    // The market of seconds against bitcoin. A list item comes without content, so each kind has a sentence that
    // needs none; an order's side and the seconds of an order or a fill are said when the content is there. A
    // price is millionths of a satoshi for one second, and satoshis are a plain number: neither is an amount of time.
    case 50: {
      add('detail.marketPrice', number(p.price)); add('detail.marketMinSats', number(p.min_sats));
      if ((p.side === 'sell' || p.side === 'buy') && isMicros(p.amount_micros)) return out(p.side === 'sell' ? 'act.marketSellOrder' : 'act.marketBuyOrder', { amount: amount(p.amount_micros) });
      return out('act.marketOrder');
    }
    case 51: add('detail.marketOrder', number(p.order)); return out('act.marketCancel');
    case 52: add('detail.marketOrder', number(p.order)); add('detail.marketSats', number(p.sats)); add('detail.marketTo', account(p.to)); return out(isMicros(p.amount_micros) ? 'act.marketTake' : 'act.marketTakePlain', { amount: amount(p.amount_micros) });
    case 53: add('detail.marketOrder', number(p.order)); add('detail.marketSats', number(p.sats)); return out(isMicros(p.amount_micros) ? 'act.marketSell' : 'act.marketSellPlain', { amount: amount(p.amount_micros) });
    case 54: add('detail.marketFill', number(p.fill)); return out('act.marketProof');
    case 55: add('detail.marketFill', number(p.fill)); return out('act.marketExpire');
    case 56: add('detail.marketFill', number(p.fill)); return out('act.marketRelease');
    case 57: add('detail.marketFill', number(p.fill)); return out('act.marketSettle');
    case 58: add('detail.marketOrder', number(p.order)); return out('act.marketScripts');
    case 80: {
      // A validator's signal about a change of the rules (docs/design/upgrade-mechanism.md): its
      // content is the plan it supports (the next version, the hash of its specification, the
      // start time) or nothing at all, which withdraws. A list item comes without content.
      if (!a.payload) return out('act.signalPlain');
      if (Object.keys(a.payload).length === 0) return out('act.signalWithdraw');
      if (!isMicros(p.version) || !isKey(p.spec) || !isMicros(p.activate_elapsed_micros)) return out('act.signalPlain');
      add('detail.signalStart', sinceStart(p.activate_elapsed_micros)); add('detail.signalSpec', hash(p.spec));
      return out('act.signalSupport', { version: number(p.version) });
    }
    case 8: add('detail.key', key(p.public_key)); add('detail.canSpend', typeof p.can_spend === 'boolean' ? { type: 'yesno', value: p.can_spend } : invalid); add('detail.canManage', typeof p.can_manage === 'boolean' ? { type: 'yesno', value: p.can_manage } : invalid); return out('act.addKey');
    case 9: add('detail.key', key(p.public_key)); return out('act.removeKey');
    case 11: add('detail.threshold', number(p.threshold)); add('detail.delay', seconds(p.delay_seconds)); for (const guardian of list(p.guardians, 5)) add('detail.guardian', account(guardian)); return out('act.setRecovery');
    case 12: return out(p.accept === false ? 'act.declineRecovery' : a.payload ? 'act.consentRecovery' : 'act.consentRecoveryPlain', { target: account(p.target) });
    case 13: add('detail.newKey', key(p.new_public_key)); return out(a.payload ? 'act.approveRecovery' : 'act.approveRecoveryPlain', { target: account(p.target) });
    case 14: return out('act.cancelRecovery');
    case 15: return out('act.finalizeRecovery');
    case 16: return out('act.cancelPending');
    case 60: return out('act.treasuryPropose');
    case 61: return out('act.treasuryActivate');
    case 62: return out('act.treasuryControl');
    case 70: {
      const policy = object(p.policy) ?? {};
      for (const entry of list(p.keys, 16)) { const row = object(entry) ?? {}; if (isKey(row.public_key) && role(row.role).type === 'role') details.push({ label: `detail.key.${row.role}`, value: key(row.public_key) }); }
      add('detail.dailyLimit', amount(policy.daily_limit_micros)); add('detail.delay', seconds(policy.delay_seconds)); add('detail.freezeLength', seconds(policy.freeze_seconds)); add('detail.threshold', number(policy.threshold));
      return out('act.secure');
    }
    case 71: {
      for (const entry of list(p.add, 16)) add('detail.keyAdded', key(object(entry)?.public_key));
      for (const removed of list(p.remove, 16)) add('detail.keyRemoved', key(removed));
      return out('act.signinKeys');
    }
    case 72: return out('act.freeze');
    case 73: {
      const op = object(p.op) ?? {};
      for (const approval of list(p.approvals, 16)) add('detail.approvedBy', key(object(approval)?.public_key));
      if (to.type === 'account' && sum.type === 'amount') return out('act.rootPay', { to, amount: sum });
      if (op.type === 'replace') {
        const policy = object(op.policy) ?? {};
        for (const entry of list(op.keys, 16)) { const row = object(entry) ?? {}; if (isKey(row.public_key) && role(row.role).type === 'role') details.push({ label: `detail.key.${row.role}`, value: key(row.public_key) }); }
        add('detail.dailyLimit', amount(policy.daily_limit_micros));
        return out('act.rootReplace');
      }
      if (op.type === 'cancel') return out('act.rootCancel');
      if (op.type === 'unfreeze') return out('act.rootUnfreeze');
      return out('act.rootPlain');
    }
    case 74: return out('act.finalizeReplacement');
    case 77: return out(isMicros(p.daily_limit_micros) ? 'act.dailyLimit' : 'act.dailyLimitPlain', { amount: amount(p.daily_limit_micros) });
    case 75: {
      const status = REQUEST_STATUS.includes(a.requestStatus) ? `pending.${a.requestStatus}` : null;
      if (isHash(a.requestHash)) details.push({ label: 'detail.request', value: { type: 'action', hash: a.requestHash.toUpperCase() } });
      if (p.type === 'request' || (!a.payload && a.requestStatus !== null)) return out('act.waitingRequest', { to, amount: sum }, a.decoded ? null : status ?? 'pending.unknown');
      add('detail.waitingId', number(p.id));
      if (to.type === 'account' && sum.type === 'amount') return out('act.waitingExecute', { to, amount: sum });
      // Proven bytes of a completion carry a number only: they name neither recipient nor amount.
      if (a.decoded && p.type === 'execute') return out('act.waitingExecuteBytes');
      if (p.type === 'execute' || a.unattributed) return out('act.waitingExecutePlain');
      return out('act.waitingPlain');
    }
    case 76: add('detail.waitingId', number(p.id)); return out(p.type === 'payment' ? 'act.cancelWaitingPayment' : p.type === 'limit' ? 'act.cancelWaitingLimit' : 'act.cancelWaiting');
    default: return out('act.opaque', { kind: number(kind) });
  }
}

/// The five facts of a list item (kind, sender, recipient, amount, reference) as the index states
/// them and as proven bytes state them, compared. Returns the names of those that differ. This
/// is one part of a comparison, not all of it: `compareAction` is what the page relies on.
export function differences(indexed, decoded) {
  const a = normalise(indexed), b = normalise(decoded), out = [];
  for (const field of ['kind', 'sender', 'recipient', 'amount', 'reference']) {
    // The index lists the recipient and amount of a completed waiting payment (75 execute) from
    // the request it tied it to: the bytes of the completion do not carry them.
    if (a.kind === 75 && b.payload?.type === 'execute' && (field === 'recipient' || field === 'amount')) continue;
    if ((a[field] ?? null) !== (b[field] ?? null)) out.push(field);
  }
  return out;
}

const sorted = (value) => (Array.isArray(value) ? value.map(sorted) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])])) : value);
const same = (a, b) => JSON.stringify(sorted(a)) === JSON.stringify(sorted(b));
/// Everything the service said about an action, held against what was checked.
/// - `served`: the action as the API gave it (kind, sender, nonce, auth_epoch, public_key,
///   payload, height, index, and the indexed recipient, amount and reference).
/// - `proven`: the result of the check: `action` (the SDK's reading of the proven bytes, or
///   null), `envelope` (the frame of the bytes, or null), `height`, `index` (null if not fixed).
/// Returns { read, differing, unconfirmed }:
/// - `read`: 'content' (the bytes were read in full), 'frame' (only kind, sender and the numbers
///   of the frame could be read) or 'nothing';
/// - `differing`: what the service said and the checked bytes or block contradict;
/// - `unconfirmed`: what the service said and the bytes do not carry at all (the recipient and
///   amount of a completed waiting payment: the bytes of the completion hold a number only).
/// A description may be called confirmed only if `read` is 'content' and both lists are empty.
export function compareAction(served, proven) {
  const said = object(served) ?? {}, decoded = object(proven?.action), frame = decoded ? { kind: decoded.kind, sender: decoded.from === '18446744073709551615' ? null : decoded.from, nonce: decoded.nonce, authEpoch: decoded.authEpoch, publicKey: decoded.publicKey } : object(proven?.envelope);
  const differing = [], unconfirmed = [];
  if (said.height !== proven?.height) differing.push('height');
  if (proven?.index !== null && proven?.index !== undefined && said.index !== proven.index) differing.push('position');
  if (!frame) return { read: 'nothing', differing, unconfirmed };
  if (said.kind !== frame.kind) differing.push('kind');
  if ((said.sender ?? null) !== (frame.sender ?? null)) differing.push('sender');
  if ((said.nonce ?? null) !== (frame.nonce ?? null)) differing.push('nonce');
  // The service states these two only in the detail of an action; where it is silent nothing was shown.
  if (said.auth_epoch !== undefined && said.auth_epoch !== null && said.auth_epoch !== frame.authEpoch) differing.push('authEpoch');
  if (said.public_key !== undefined && said.public_key !== null && said.public_key !== frame.publicKey) differing.push('publicKey');
  if (!decoded) return { read: 'frame', differing, unconfirmed };
  if (said.payload !== undefined && said.payload !== null && !same(said.payload, decoded.payload)) differing.push('payload');
  const bytes = normalise(decoded), index = normalise(said);
  for (const field of ['recipient', 'amount', 'reference']) {
    if ((index[field] ?? null) === (bytes[field] ?? null)) continue;
    if (bytes.kind === 75 && bytes.payload?.type === 'execute' && field !== 'reference') unconfirmed.push(field); else differing.push(field);
  }
  return { read: 'content', differing, unconfirmed };
}
