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
export function acceptApprovalEvent(event, opener) {
  if (!opener || event.source !== opener || !event.origin || event.origin === 'null') throw new Error('Request must come from the opening website.');
  const url = new URL(event.origin);
  if (url.origin !== event.origin || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) throw new Error('Website must use HTTPS or a loopback development origin.');
  const message = event.data;
  if (!message || message.type !== 'time:request' || message.version !== 1 || typeof message.id !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/.test(message.id) || !message.request) throw new Error('Invalid website request.');
  const r = message.request;
  if (!['login', 'payment', 'grant'].includes(r.type)) throw new Error('Unsupported approval type.');
  if (r.type === 'login' && r.challenge?.origin !== event.origin) throw new Error('Login audience does not match the requesting website.');
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
