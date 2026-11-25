export class GenerationFence {
  #generation = 0;
  bump() { return ++this.#generation; }
  capture() { const captured = this.#generation; return () => { if (captured !== this.#generation) throw new Error('Session changed. Please unlock and try again.'); }; }
}
/// How long the wallet waits without use: then it locks an open account (app.js, scheduleIdleLock), and hides the recovery
/// papers of a sign-up that has made no account yet (signup-ui.mjs). Five minutes.
export const IDLE_LOCK_MS = 5 * 60 * 1000;
export function parseSeconds(input) {
  if (typeof input !== 'string' || !/^(?:0|[1-9][0-9]{0,13})(?:\.[0-9]{1,6})?$/.test(input)) throw new Error('Enter seconds with up to six decimal places.');
  const [whole, part = ''] = input.split('.');
  const value = BigInt(whole) * 1000000n + BigInt(part.padEnd(6, '0'));
  if (value <= 0n || value > 18446744073709551615n) throw new Error('Amount is outside the supported range.');
  return value.toString();
}
export function formatSeconds(micros) {
  const value = BigInt(micros ?? '0'); const fraction = (value % 1000000n).toString().padStart(6, '0').replace(/0+$/, '');
  return `${value / 1000000n}${fraction ? `.${fraction}` : ''}`;
}
/// What the approval window says of a request from a website that is not in one of the forms below: one fixed
/// sentence, and nothing the website sent (web audit of November 2026, W-1). Before, only the type was checked here,
/// and the window wrote the website's `to` and `amount` into its own sentence.
export const APPROVAL_NOT_UNDERSTOOD = 'This website sent a request the wallet does not understand. Nothing was shown or signed.';
const HEX64 = /^[0-9a-f]{64}$/, U64_TEXT = /^(0|[1-9][0-9]{0,19})$/, MAX_U64 = 18446744073709551615n;
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const u64 = (value, positive = false) => typeof value === 'string' && U64_TEXT.test(value) && BigInt(value) <= MAX_U64 && (!positive || value !== '0');
/// A payment, as the merchant SDK's requestWallet carries it: `networkId` (64 lowercase hex), `to` (an account
/// number), `amount` (micro-seconds, more than zero) and `orderId` (the reference the SDK's orderReference makes, 64
/// lowercase hex). The demo blog (web-v4/merchant/app.js) also sends `fee` (micro-seconds), `description` (a text) and
/// `expiresAt` (milliseconds): taken in those forms, and never shown. Any other field is refused.
function paymentForm(r) {
  const allowed = new Set(['type', 'networkId', 'to', 'amount', 'orderId', 'fee', 'description', 'expiresAt']);
  return Object.keys(r).every(key => allowed.has(key)) && typeof r.networkId === 'string' && HEX64.test(r.networkId) && u64(r.to) && u64(r.amount, true)
    && typeof r.orderId === 'string' && HEX64.test(r.orderId) && (r.fee === undefined || u64(r.fee))
    && (r.description === undefined || (typeof r.description === 'string' && r.description.length <= 200)) && (r.expiresAt === undefined || (Number.isSafeInteger(r.expiresAt) && r.expiresAt >= 0));
}
/// A login, exactly as a website's server issues its challenge (client-v4/server-auth.mjs): for this website's own
/// origin, with a nonce of 64 lowercase hex and two times in milliseconds.
function loginForm(r, origin) {
  const c = r.challenge;
  return Object.keys(r).sort().join(',') === 'challenge,type' && record(c) && Object.keys(c).sort().join(',') === 'expiresAt,issuedAt,networkId,nonce,origin,purpose'
    && c.purpose === 'login' && c.origin === origin && typeof c.networkId === 'string' && HEX64.test(c.networkId) && typeof c.nonce === 'string' && HEX64.test(c.nonce)
    && Number.isSafeInteger(c.issuedAt) && Number.isSafeInteger(c.expiresAt) && c.expiresAt > c.issuedAt;
}
export function acceptApprovalEvent(event, opener) {
  if (!opener || event.source !== opener || !event.origin || event.origin === 'null') throw new Error('Request must come from the opening website.');
  const url = new URL(event.origin);
  if (url.origin !== event.origin || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) throw new Error('Website must use HTTPS or a loopback development origin.');
  const message = event.data;
  if (!record(message) || Object.keys(message).sort().join(',') !== 'id,request,type,version' || message.type !== 'time:request' || message.version !== 1 || typeof message.id !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/.test(message.id) || !record(message.request)) throw new Error(APPROVAL_NOT_UNDERSTOOD);
  const r = message.request;
  if (!(r.type === 'payment' ? paymentForm(r) : r.type === 'login' ? loginForm(r, event.origin) : false)) throw new Error(APPROVAL_NOT_UNDERSTOOD);
  return { id: message.id, request: structuredClone(r), origin: event.origin };
}
export async function withSigningLock(locks, networkId, accountId, callback) {
  if (!locks?.request) throw new Error('This browser needs Web Locks for safe multi-tab signing. Use a current Chrome, Edge or Firefox.');
  return locks.request(`timecurrency:sign:${networkId}:${accountId}`, { mode: 'exclusive' }, callback);
}
export class PendingReservations {
  constructor(storage, prefix = 'timecurrency.pending.v1:') { this.storage = storage; this.prefix = prefix; }
  key(network, account) { return this.prefix + network + ':' + account; }
  get(network, account) {
    const raw = this.storage.getItem(this.key(network, account));
    if (!raw) return null;
    let record; try { record = JSON.parse(raw); } catch { throw new Error('Pending transaction storage is damaged; do not sign again until reconciled.'); }
    if (!record || !/^[0-9a-f]{64}$/i.test(record.hash) || !/^(0|[1-9][0-9]*)$/.test(record.nonce) || typeof record.authEpoch !== 'string' || !/^(0|[1-9][0-9]*)$/.test(record.authEpoch) || typeof record.tx !== 'string' || record.tx.length > 768*1024) throw new Error('Invalid pending transaction; reconciliation is required.');
    return record;
  }
  put(network, account, record) {
    if (this.get(network, account)) throw new Error('A transaction is already pending. Resolve it before signing another.');
    this.storage.setItem(this.key(network, account), JSON.stringify(record));
  }
  clear(network, account, expectedHash) {
    const pending = this.get(network, account);
    if (pending && pending.hash !== expectedHash) throw new Error('Pending transaction changed in another tab.');
    this.storage.removeItem(this.key(network, account));
  }
}
export class PaymentMarkers {
  constructor(storage, prefix = 'timecurrency.order.v1:') { this.storage = storage; this.prefix = prefix; }
  key(network, account, reference) { if (!/^[0-9a-f]{64}$/.test(reference)) throw new Error('Invalid payment reference.'); return `${this.prefix}${network}:${account}:${reference}`; }
  get(network, account, reference) {
    const raw = this.storage.getItem(this.key(network, account, reference)); if (!raw) return null;
    let record; try { record = JSON.parse(raw); } catch { throw new Error('Payment marker is damaged. Refusing to pay this order again.'); }
    if (!record || Object.keys(record).sort().join(',') !== 'at,hash,origin,status' || !/^[0-9a-f]{64}$/i.test(record.hash) || !['pending', 'verified'].includes(record.status) || typeof record.origin !== 'string' || record.origin.length > 1024 || !Number.isSafeInteger(record.at)) throw new Error('Payment marker is invalid. Refusing to pay this order again.');
    return record;
  }
  reserve(network, account, reference, hash, origin = 'unknown') {
    const previous = this.get(network, account, reference);
    if (previous) { if (previous.hash.toUpperCase() !== hash.toUpperCase()) throw new Error('This order already has a different signed payment. Recheck its receipt; do not pay twice.'); return previous; }
    const record = { hash: hash.toUpperCase(), origin, status: 'pending', at: Date.now() };
    this.storage.setItem(this.key(network, account, reference), JSON.stringify(record)); return record;
  }
  markVerified(network, account, reference, hash) {
    const record = this.reserve(network, account, reference, hash);
    this.storage.setItem(this.key(network, account, reference), JSON.stringify({ ...record, status: 'verified' }));
  }
}
