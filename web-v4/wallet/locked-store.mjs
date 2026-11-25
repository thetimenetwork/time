// What this browser keeps of an account that says what the account did or whom it paid, readable only while the wallet
// is unlocked (since 24 November 2026): the newest 40 actions this browser checked (the activity), the names the account
// paid from here (names.mjs), and the marks of the orders of websites it paid (a website's order is never paid twice).
// Before, these were in the browser's storage in the clear, for anyone who could read it while the wallet was locked.
//
// How:
// - A data key per account (32 random bytes) encrypts each record with AES-256-GCM, a fresh random IV for each write,
//   and the record's place (its kind, the network, the account's name) and the data key's id as additional data: a
//   record moved to another place, or to another account, does not open.
// - The data key is stored wrapped, once for each login key of this browser that may open it, under that login key's
//   storage key (vault.mjs, storageKeyFrom: HKDF-SHA-256 of the login key's seed). That key exists only while the login
//   key's secret is in memory, at unlock or when the key is made; the data key is imported so that it cannot be
//   exported. A vault keeps its format.
// - When this browser makes a new login key while the account is open (a new login password, protecting the account,
//   asking another device for a login, the end of a sign-up), the data key is wrapped for that key too (`adopt`): the
//   history survives the change. Wraps of keys this browser no longer holds go at the next unlock.
// - A login key without a wrap (keys made by a recovery, a backup of another key, a store someone damaged) cannot read
//   what was kept: a new data key starts empty records, and the old ones go. The activity then says that it knows
//   nothing before (`since: null`), so that the Alerts panel does not count actions this browser did send as signed
//   elsewhere (alerts.mjs, `sent`); app.js sets `since` to the account's nonce at its first verified reading.
// - Records written in the clear by an earlier version are encrypted at the first unlock, and the plain copy is removed
//   only after the encrypted one was written: a page closed half way loses nothing, and the next unlock does it again.
//
// Writing is asynchronous now. Each write is queued at once, in order, with the keys of the session that asked for it,
// so that a lock or a page that hides (which drop the session) does not lose it; under a Web Lock per account it reads
// the stored record, merges (the three records only grow: a union), encrypts and writes. Several tabs of one account
// share the data key; a tab hears another's writes through the `storage` event (`storageEvent`) and merges them in.
//
// Places, per network and account name (localStorage):
//   timecurrency.store-key.v1:<network id>:<name>   {"v":1,"id":<32 hex>,"wraps":{<login public key>:{"iv","data"}}}
//   timecurrency.activity.v2:<network id>:<name>    {"v":1,"kid":<id>,"iv","data"}   {since, items}
//   timecurrency.names.v2:<network id>:<name>       the same                          {paid}
//   timecurrency.orders.v2:<network id>:<name>      the same                          {markers: {<reference>: {...}}}
// The account's name is in these places, as it is in the vault's: hiding the name itself is a change of its own. Every
// place is named by `placeOf`, so that such a change has one function to change.
import { b64, fromB64, hex } from './vault.mjs';
import { paidNamesFrom } from './names.mjs';

export const KEY_PREFIX = 'timecurrency.store-key.v1:';
export const PLACES = Object.freeze({ activity: 'timecurrency.activity.v2:', names: 'timecurrency.names.v2:', orders: 'timecurrency.orders.v2:' });
/// Where earlier versions kept the same in the clear: activity and names by account name, orders by account number.
export const PLAIN = Object.freeze({ activity: 'timecurrency.activity.v1:', names: 'timecurrency.names.v1:', orders: 'timecurrency.order.v1:' });
export const KINDS = Object.freeze(['activity', 'names', 'orders']);
export const MAX_ACTIVITY = 40;
export const MAX_ORDERS = 200;
const HEX64 = /^[0-9a-f]{64}$/, HASH = /^[0-9A-Fa-f]{64}$/, DECIMAL = /^(0|[1-9][0-9]{0,19})$/, NONCE = /^[1-9][0-9]{0,19}$/, REF = /^[0-9a-f]{64}$/;
const MAX_RECORD = 512 * 1024;
const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', { fatal: true });

/// The place of a record of `kind` ('key' for the wrapped data key) of an account of a network.
export const placeOf = (kind, networkId, name) => `${kind === 'key' ? KEY_PREFIX : PLACES[kind]}${networkId}:${name}`;

// ------------------------------------------------------------------ the records
/// One action of the activity, cleaned: its hash, block, label, time and, when it took one, the account's nonce.
function activityItem(a) {
  if (!a || typeof a !== 'object' || typeof a.hash !== 'string' || !HASH.test(a.hash)) return null;
  const item = { hash: a.hash, height: String(a.height ?? '').slice(0, 24), label: typeof a.label === 'string' ? a.label.slice(0, 300) : '', at: Number.isSafeInteger(a.at) ? a.at : 0 };
  if (typeof a.nonce === 'string' && NONCE.test(a.nonce)) item.nonce = a.nonce;
  return item;
}
const sameHash = (a, b) => a.toUpperCase() === b.toUpperCase();
function cleanItems(list) {
  const byHash = new Map();
  for (const a of list) { const item = activityItem(a); if (item) { byHash.delete(item.hash.toUpperCase()); byHash.set(item.hash.toUpperCase(), item); } }
  return [...byHash.values()].slice(-MAX_ACTIVITY);
}
/// The activity out of what was stored: the plain list of an earlier version (complete from the start: `since` "0"), or
/// the record {since, items}. `since` is the account's nonce from which this browser's list holds every action it sent,
/// or null when it does not know.
export function activityFrom(value) {
  if (Array.isArray(value)) return { since: '0', items: cleanItems(value) };
  const since = value?.since === null || value?.since === undefined || !DECIMAL.test(String(value.since)) ? null : String(value.since);
  return { since, items: cleanItems(Array.isArray(value?.items) ? value.items : []) };
}
/// The activity with one more action, as its newest; the same action again moves to the end.
export function withReceipt(value, item) {
  const clean = activityItem(item); if (!clean) return value;
  return { since: value.since, items: cleanItems([...value.items.filter(a => !sameHash(a.hash, clean.hash)), clean]) };
}
const lowerSince = (a, b) => (a === null ? b : b === null ? a : BigInt(a) <= BigInt(b) ? a : b);
/// Two lists of one account in one: every action of both (the newer word on the same action wins), by time, the newest 40.
export function mergeActivity(a, b) {
  const byHash = new Map();
  for (const item of [...a.items, ...b.items]) byHash.set(item.hash.toUpperCase(), item);
  return { since: lowerSince(a.since, b.since), items: [...byHash.values()].sort((x, y) => x.at - y.at).slice(-MAX_ACTIVITY) };
}
/// How many actions of `value` took a nonce above `markerNonce`: what alerts.mjs calls `sent`. Null when the list does not
/// know everything this browser sent since that nonce (it starts later, or does not know where it starts).
export function sentSinceOf(value, markerNonce) {
  try {
    if (!value || value.since === null || !DECIMAL.test(String(value.since)) || !DECIMAL.test(String(markerNonce))) return null;
    const marker = BigInt(markerNonce); if (marker < BigInt(value.since)) return null;
    return value.items.filter(item => typeof item.nonce === 'string' && NONCE.test(item.nonce) && BigInt(item.nonce) > marker).length;
  } catch { return null; }
}
/// Two lists of paid names in one: the names only the stored one has first, then the other's in its order.
export function mergeNames(a, b) { return { paid: paidNamesFrom({ paid: [...a.paid.filter(name => !b.paid.includes(name)), ...b.paid] }) }; }
/// One mark of an order, as guards.mjs (PaymentMarkers) kept it, with the account it was paid from.
function orderMark(m) {
  if (!m || typeof m !== 'object' || !DECIMAL.test(String(m.account)) || typeof m.hash !== 'string' || !HASH.test(m.hash) || !['pending', 'verified'].includes(m.status)
    || typeof m.origin !== 'string' || m.origin.length > 1024 || !Number.isSafeInteger(m.at)) return null;
  return { account: String(m.account), hash: m.hash.toUpperCase(), origin: m.origin, status: m.status, at: m.at };
}
const newestOrders = markers => { const entries = Object.entries(markers); return entries.length <= MAX_ORDERS ? markers : Object.fromEntries(entries.sort((x, y) => x[1].at - y[1].at).slice(-MAX_ORDERS)); };
export function ordersFrom(value) {
  const markers = {};
  if (value?.markers && typeof value.markers === 'object') for (const [ref, m] of Object.entries(value.markers)) { const clean = REF.test(ref) ? orderMark(m) : null; if (clean) markers[ref] = clean; }
  return { markers: newestOrders(markers) };
}
/// Two sets of marks in one. The same payment of an order: verified if either says so. Two different payments of one
/// order: the one kept first stays, and the wallet refuses to pay that order again.
export function mergeOrders(a, b) {
  const markers = { ...a.markers };
  for (const [ref, m] of Object.entries(b.markers)) {
    const old = markers[ref];
    if (!old) markers[ref] = m;
    else if (old.hash === m.hash && old.account === m.account) markers[ref] = { ...old, status: old.status === 'verified' || m.status === 'verified' ? 'verified' : 'pending', at: Math.min(old.at, m.at) };
  }
  return { markers: newestOrders(markers) };
}
const RECORDS = {
  activity: { empty: since => ({ since, items: [] }), from: activityFrom, merge: mergeActivity },
  names: { empty: () => ({ paid: [] }), from: value => ({ paid: paidNamesFrom(value) }), merge: mergeNames },
  orders: { empty: () => ({ markers: {} }), from: ordersFrom, merge: mergeOrders },
};
const emptyValues = since => ({ activity: RECORDS.activity.empty(since), names: RECORDS.names.empty(), orders: RECORDS.orders.empty() });
const clone = value => JSON.parse(JSON.stringify(value));

// ------------------------------------------------------------------ encryption
async function seal(cryptoImpl, key, aad, bytes) {
  const iv = cryptoImpl.getRandomValues(new Uint8Array(12));
  const data = await cryptoImpl.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(aad), tagLength: 128 }, key, bytes);
  return { iv: b64(iv), data: b64(data) };
}
async function unseal(cryptoImpl, key, aad, sealed) {
  const iv = fromB64(sealed.iv, 12), data = fromB64(sealed.data, MAX_RECORD);
  if (iv.length !== 12 || data.length < 16) throw new Error('Invalid record');
  return new Uint8Array(await cryptoImpl.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(aad), tagLength: 128 }, key, data));
}
/// The record of the wrapped data key, strictly, or null.
function keyRecordFrom(text) {
  if (typeof text !== 'string' || text.length > 65536) return null;
  let r; try { r = JSON.parse(text); } catch { return null; }
  if (!r || r.v !== 1 || typeof r.id !== 'string' || !/^[0-9a-f]{32}$/.test(r.id) || !r.wraps || typeof r.wraps !== 'object' || Array.isArray(r.wraps)) return null;
  const wraps = {};
  for (const [publicKey, w] of Object.entries(r.wraps)) if (HEX64.test(publicKey) && w && typeof w.iv === 'string' && typeof w.data === 'string') wraps[publicKey] = { iv: w.iv, data: w.data };
  return { v: 1, id: r.id, wraps };
}
function sealedFrom(text) {
  if (typeof text !== 'string' || text.length > MAX_RECORD * 2) return null;
  let r; try { r = JSON.parse(text); } catch { return null; }
  return r && r.v === 1 && typeof r.kid === 'string' && typeof r.iv === 'string' && typeof r.data === 'string' ? r : null;
}
const keyAad = (networkId, name, publicKey, id) => `${placeOf('key', networkId, name)}\0${publicKey}\0${id}`;
const recordAad = (kind, networkId, name, id) => `${placeOf(kind, networkId, name)}\0${id}`;
async function wrapFor(cryptoImpl, storageKey, aad, raw) { return seal(cryptoImpl, storageKey, aad, raw); }
async function unwrapWith(cryptoImpl, storageKey, aad, wrap) {
  const raw = await unseal(cryptoImpl, storageKey, aad, wrap);
  if (raw.length !== 32) { raw.fill(0); throw new Error('Invalid data key'); }
  return raw;
}
function keysOf(storage) {
  try {
    if (typeof storage.key === 'function' && Number.isInteger(storage.length)) { const keys = []; for (let i = 0; i < storage.length; i++) { const k = storage.key(i); if (k !== null) keys.push(k); } return keys; }
    return Object.keys(storage);
  } catch { return []; }
}

/// Reads what is kept for an account with a login key's storage key, and writes nothing: for tests and checks only.
export async function peek({ storage, networkId, name, publicKey, storageKey, cryptoImpl = globalThis.crypto }) {
  const record = keyRecordFrom(storage.getItem(placeOf('key', networkId, name))), wrap = record?.wraps[publicKey];
  if (!wrap) return null;
  const raw = await unwrapWith(cryptoImpl, storageKey, keyAad(networkId, name, publicKey, record.id), wrap);
  let dataKey; try { dataKey = await cryptoImpl.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']); } finally { raw.fill(0); }
  const values = {};
  for (const kind of KINDS) {
    const sealed = sealedFrom(storage.getItem(placeOf(kind, networkId, name)));
    values[kind] = sealed && sealed.kid === record.id ? RECORDS[kind].from(JSON.parse(decoder.decode(await unseal(cryptoImpl, dataKey, recordAad(kind, networkId, name, record.id), sealed)))) : null;
  }
  return values;
}

// ------------------------------------------------------------------ the store of the open account
/// `storage`: localStorage. `locks`: navigator.locks (without it, one tab is assumed). `onChange(kind)`: what the open
/// account keeps changed by a write of another tab (merged in).
export function createPrivateStore({ storage, locks = null, cryptoImpl = globalThis.crypto, onChange = () => {} }) {
  let session = null, generation = 0, queue = Promise.resolve();
  const get = key => { try { return storage.getItem(key); } catch { return null; } };
  const drop = key => { try { storage.removeItem(key); } catch { /* nothing to remove */ } };
  const withLock = (s, work) => (locks?.request ? locks.request(`timecurrency:private-store:${s.networkId}:${s.name}`, { mode: 'exclusive' }, work) : work());
  /// Queues `work` after everything queued before it; the queue itself never fails.
  const enqueue = work => { const job = queue.then(work); queue = job.then(() => {}, () => {}); return job; };
  const notify = kind => queueMicrotask(() => { try { onChange(kind); } catch { /* the page's own fault */ } });
  const place = (kind, s) => placeOf(kind, s.networkId, s.name);

  async function readRecord(s, kind) {
    const text = get(place(kind, s)); if (text === null) return { state: 'absent' };
    const sealed = sealedFrom(text); if (!sealed) return { state: 'damaged' };
    if (sealed.kid !== s.id) return { state: 'foreign' };
    try { return { state: 'ok', value: RECORDS[kind].from(JSON.parse(decoder.decode(await unseal(cryptoImpl, s.dataKey, recordAad(kind, s.networkId, s.name, s.id), sealed)))) }; }
    catch { return { state: 'damaged' }; }
  }
  /// What another tab wrote, merged into this session's memory; the page hears of a change.
  function take(s, kind, value) {
    const before = JSON.stringify(s.values[kind]);
    s.values[kind] = RECORDS[kind].merge(s.values[kind], value);
    if (s === session && JSON.stringify(s.values[kind]) !== before) notify(kind);
  }
  /// Whether the data key of this session is still the account's: another tab may have started a new one (keys made by a
  /// recovery). A session that is not stops writing.
  function stillOurs(s) { const record = keyRecordFrom(get(place('key', s))); if (record && record.id !== s.id) { s.stale = true; return false; } return true; }

  async function openUnderLock(s, keep) {
    let record = keyRecordFrom(get(place('key', s))), raw = null;
    const mine = record?.wraps[s.publicKey];
    if (mine) { try { raw = await unwrapWith(cryptoImpl, s.kek, keyAad(s.networkId, s.name, s.publicKey, record.id), mine); } catch { raw = null; } }
    try {
      if (raw) { s.id = record.id; s.wrap = mine; }
      else {
        s.lost = record !== null || KINDS.some(kind => get(place(kind, s)) !== null);
        // Another login key this browser holds can read what was kept (one kept aside for a change of keys): it stays for
        // that key, and this session keeps its history in memory only.
        if (record && Object.keys(record.wraps).some(k => k !== s.publicKey && keep.includes(k))) throw new Error('Kept for another login key of this browser');
        // What was kept cannot be read with this key: a new data key, and the old records go.
        raw = cryptoImpl.getRandomValues(new Uint8Array(32)); s.id = hex(cryptoImpl.getRandomValues(new Uint8Array(16)));
        s.wrap = await wrapFor(cryptoImpl, s.kek, keyAad(s.networkId, s.name, s.publicKey, s.id), raw);
        record = { v: 1, id: s.id, wraps: { [s.publicKey]: s.wrap } };
        for (const kind of KINDS) drop(place(kind, s));
        storage.setItem(place('key', s), JSON.stringify(record));
      }
      // Wraps for login keys this browser no longer holds go.
      const kept = new Set([s.publicKey, ...keep.filter(k => typeof k === 'string' && HEX64.test(k))]);
      if (Object.keys(record.wraps).some(k => !kept.has(k))) {
        record.wraps = Object.fromEntries(Object.entries(record.wraps).filter(([k]) => kept.has(k)));
        try { storage.setItem(place('key', s), JSON.stringify(record)); } catch { /* they go next time */ }
      }
      s.dataKey = await cryptoImpl.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    } finally { raw?.fill(0); }
    for (const kind of KINDS) {
      const read = await readRecord(s, kind);
      if (read.state === 'ok') s.values[kind] = read.value;
      else {
        s.values[kind] = RECORDS[kind].empty(s.lost || read.state !== 'absent' ? null : '0');
        if (read.state !== 'absent') drop(place(kind, s));
      }
    }
  }
  /// The plain records of an earlier version: merged in, written encrypted, and removed once that write is done.
  async function migratePlain(s) {
    for (const kind of ['activity', 'names']) {
      const key = `${PLAIN[kind]}${s.networkId}:${s.name}`, text = get(key); if (text === null) continue;
      let parsed = null; try { parsed = JSON.parse(text); } catch { parsed = null; }
      if (kind === 'activity') s.values.activity = { since: s.values.activity.since, items: mergeActivity(s.values.activity, activityFrom(Array.isArray(parsed) ? parsed : [])).items };
      else s.values.names = mergeNames(s.values.names, { paid: paidNamesFrom(parsed) });
      if (await write(kind, s) === true) drop(key);
    }
  }

  /// Opens what is kept of an account with the storage key of the login key `publicKey` (vault.mjs). `keep`: the public
  /// keys of the other login keys this browser holds for the account (kept aside, or asked of another device). Never
  /// fails: a store that cannot be opened is one of this page's memory only. Returns { lost }: whether something kept
  /// could not be read with this key.
  async function open({ networkId, name, publicKey, storageKey, keep = [] }) {
    close();
    const g = generation, s = { networkId, name, publicKey, kek: storageKey ?? null, id: null, wrap: null, dataKey: null, values: emptyValues('0'), lost: false, stale: false, memory: false, claimed: new Set(), unsaved: new Set() };
    session = s;
    try {
      if (!s.kek || !HEX64.test(String(publicKey))) throw new Error('No storage key');
      await enqueue(() => withLock(s, () => openUnderLock(s, keep)));
      if (g === generation) await migratePlain(s);
    } catch { s.dataKey = null; s.memory = true; s.values = emptyValues(null); }
    return { lost: s.lost, memory: s.memory };
  }
  /// The wallet locked, or the page hides: the session is dropped at once. What was queued is written all the same, with
  /// the keys it was queued with; then those keys are let go.
  function close() {
    generation++;
    const s = session; session = null;
    if (s) enqueue(() => { s.dataKey = s.kek = s.wrap = null; s.values = emptyValues(null); });
  }
  /// Queues a write of what the session holds of `kind`. Resolves to true once it is written, false if writing failed,
  /// null where nothing can be written (no account open, or one of this page's memory only).
  function write(kind, s = session) {
    if (!s || !s.dataKey || s.stale) return Promise.resolve(null);
    const value = clone(s.values[kind]);
    return enqueue(() => withLock(s, async () => {
      if (!s.dataKey || s.stale || !stillOurs(s)) return null;
      const read = await readRecord(s, kind);
      const merged = read.state === 'ok' ? RECORDS[kind].merge(read.value, value) : value;
      const sealed = await seal(cryptoImpl, s.dataKey, recordAad(kind, s.networkId, s.name, s.id), encoder.encode(JSON.stringify(merged)));
      storage.setItem(place(kind, s), JSON.stringify({ v: 1, kid: s.id, ...sealed }));
      take(s, kind, merged);
      return true;
    })).catch(() => false).then(result => { if (result === false) s.unsaved.add(kind); else if (result === true) s.unsaved.delete(kind); return result; });
  }
  /// Whether the last write of `kind` failed (a full or refused storage): the page writes it again at the next occasion.
  const unsaved = kind => Boolean(session?.unsaved.has(kind));
  /// Changes what the open account keeps of `kind` now, and writes it (see `write`).
  function update(kind, change) {
    const s = session; if (!s) return Promise.resolve(null);
    s.values[kind] = RECORDS[kind].from(change(clone(s.values[kind])));
    return write(kind, s);
  }
  /// Reads `kind` again from the storage, after what was queued before: what another tab wrote is merged in.
  function sync(kind) {
    const s = session; if (!s) return Promise.resolve();
    return enqueue(async () => {
      if (s !== session || !s.dataKey || s.stale) return;
      const read = await readRecord(s, kind);
      if (read.state === 'ok') take(s, kind, read.value); else if (read.state === 'foreign') stillOurs(s);
    }).catch(() => {});
  }
  /// The page's `storage` event: a record of the open account written by another tab.
  function storageEvent(event) {
    const s = session; if (!s || typeof event?.key !== 'string') return;
    for (const kind of KINDS) if (event.key === place(kind, s)) sync(kind);
    if (event.key === place('key', s)) { const record = keyRecordFrom(event.newValue); if (record && record.id !== s.id) s.stale = true; }
  }
  /// Lets another login key of this browser (`publicKey`, made while this account is open) open what is kept: the data
  /// key wrapped under its storage key. False when it could not be done.
  function adopt({ networkId = null, name = null, publicKey, storageKey }) {
    const s = session;
    if (!s || !s.dataKey || s.stale || !storageKey || !HEX64.test(String(publicKey)) || (networkId !== null && networkId !== s.networkId) || (name !== null && name !== s.name)) return Promise.resolve(false);
    return enqueue(() => withLock(s, async () => {
      if (!s.kek) return false;
      const record = keyRecordFrom(get(place('key', s))) ?? { v: 1, id: s.id, wraps: { [s.publicKey]: s.wrap } };
      if (record.id !== s.id) { s.stale = true; return false; }
      const raw = await unwrapWith(cryptoImpl, s.kek, keyAad(s.networkId, s.name, s.publicKey, s.id), s.wrap);
      try { record.wraps[publicKey] = await wrapFor(cryptoImpl, storageKey, keyAad(s.networkId, s.name, publicKey, s.id), raw); } finally { raw.fill(0); }
      storage.setItem(place('key', s), JSON.stringify(record));
      return true;
    })).catch(() => false);
  }
  /// The marks of orders an earlier version kept in the clear for account number `accountId`: merged in, written
  /// encrypted, then removed. Once per account and session.
  function claimOrders(networkId, accountId) {
    const s = session, account = String(accountId);
    if (!s || networkId !== s.networkId || !DECIMAL.test(account) || s.claimed.has(account)) return Promise.resolve(null);
    s.claimed.add(account);
    const prefix = `${PLAIN.orders}${networkId}:${account}:`, keys = keysOf(storage).filter(key => key.startsWith(prefix));
    if (!keys.length) return Promise.resolve(null);
    const found = {};
    for (const key of keys) {
      const ref = key.slice(prefix.length); if (!REF.test(ref)) continue;
      let m = null; try { m = JSON.parse(get(key)); } catch { m = null; }
      // A damaged mark refused to pay its order again: it still does (a payment no hash can match).
      found[ref] = orderMark({ ...(m && typeof m === 'object' ? m : {}), account }) ?? { account, hash: '0'.repeat(64), origin: 'unknown', status: 'pending', at: 0 };
    }
    s.values.orders = mergeOrders(s.values.orders, { markers: found });
    return write('orders', s).then(result => { if (result === true) for (const key of keys) drop(key); return result; });
  }
  /// Whether this session reads and writes what the browser keeps: false for one of the page's memory only, and for one
  /// whose data key another tab replaced (stale).
  const sees = s => Boolean(s && s.dataKey && !s.stale && !s.memory);
  /// What the open account keeps of `kind` now (a value to read, not to change), or an empty one. A session that does not
  /// see what the browser keeps cannot know what other tabs of this browser sent: its activity says that it does not know
  /// where it starts, whatever it holds, and the Alerts panel then counts no action as signed elsewhere (sentSinceOf).
  const value = kind => {
    if (!session) return RECORDS[kind].empty(null);
    if (kind === 'activity' && session.dataKey && !session.stale) stillOurs(session);
    return kind === 'activity' && !sees(session) ? { ...session.values.activity, since: null } : session.values[kind];
  };
  /// Everything queued so far, written.
  const flushed = () => queue;
  return { open, close, write, update, sync, storageEvent, adopt, claimOrders, value, flushed, unsaved, sees: () => sees(session), isOpen: () => Boolean(session), memoryOnly: () => Boolean(session?.memory) };
}

// ------------------------------------------------------------------ the marks of orders paid, in the store
/// The same as guards.mjs (PaymentMarkers) for signing.mjs and app.js, kept in the store of the open account: before a
/// website's order is signed, the wallet says plainly that this browser has already paid it. `sync(network, account)` reads
/// what another tab marked, and claims the plain marks of earlier versions; `reserve` resolves once the mark is written,
/// and refuses when the store could not write it. In a session that does not see the store (the page's memory only, or
/// stale) the mark lives in this page's memory: nothing is written in the clear, and no payment is refused for it.
///
/// Why that is safe: the mark is a courtesy, not the protection. The chain pays an order once at most. Since protocol
/// version 4 the engine takes a website payment only if its reference carries the sender's next nonce and an expiry
/// within a day (v5/src/engine.rs, MerchantPayment: "merchant reference reserved another sender nonce", "expired or
/// exceeds one day"): a second payment of the same order needs the same nonce, which the first one uses up, or which only
/// one of the two can take. And the SDK takes no quote on a network before that rule (TimeSDK.checkMerchantQuote, called
/// by signing.mjs and app.js before anything is signed): client-v4/orders.test.mjs, "V4 wallet preflight rejects consumed
/// nonce, expired quote and overly long quote", and client-v4/sdk.test.mjs, "nonce references require application four
/// and the exact next nonce", pin that refusal; upgrade.test.mjs pins the call in signing.mjs and app.js.
export function orderMarkers(store) {
  const checked = reference => { if (typeof reference !== 'string' || !REF.test(reference)) throw new Error('Invalid payment reference.'); return reference; };
  function get(network, account, reference) {
    const m = store.value('orders').markers[checked(reference)];
    return m && m.account === String(account) ? { hash: m.hash, origin: m.origin, status: m.status, at: m.at } : null;
  }
  function mark(network, account, reference, hash, origin, status) {
    const previous = get(network, account, reference);
    if (previous && previous.hash.toUpperCase() !== String(hash).toUpperCase()) throw new Error('This order already has a different signed payment. Recheck its receipt; do not pay twice.');
    const record = previous ? { ...previous, status: status === 'verified' ? 'verified' : previous.status } : { hash: String(hash).toUpperCase(), origin: String(origin).slice(0, 1024), status, at: Date.now() };
    const kept = previous && previous.status === record.status && !store.unsaved('orders');
    return { record, written: kept ? Promise.resolve(true) : store.update('orders', v => ({ markers: { ...v.markers, [reference]: { account: String(account), ...record } } })) };
  }
  return {
    get,
    sync: (network, account) => Promise.resolve(store.claimOrders(network, String(account))).then(() => store.sync('orders')),
    async reserve(network, account, reference, hash, origin = 'unknown') {
      const { record, written } = mark(network, account, reference, hash, origin, 'pending');
      if (await written === false) throw new Error('This browser could not keep a mark of this order, so nothing was sent. Try again.');
      return record;
    },
    markVerified(network, account, reference, hash) { return mark(network, account, reference, hash, 'unknown', 'verified').written; },
  };
}
