// What the browser keeps of an account that says what it did or whom it paid, locked while the wallet is locked
// (locked-store.mjs, and its key in vault.mjs, storageKeyFrom). Stand-ins only: a storage in memory, a Web Lock that
// queues, Node's WebCrypto.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import { newDevice, openVault, storageKeyFrom, b64, fromB64 } from './vault.mjs';
import { sealLegacy } from './tests/legacy-vault.mjs';
import { createPrivateStore, orderMarkers, peek, placeOf, sentSinceOf, withReceipt, activityFrom, mergeActivity, PLAIN, MAX_ACTIVITY } from './locked-store.mjs';

const source = await readFile(new URL('./vendor/argon2-4.12.0.umd.min.js', import.meta.url), 'utf8');
const umd = { exports: {} }; new Function('module', 'exports', source)(umd, umd.exports);
const { argon2id } = umd.exports;
const NET = 'ab'.repeat(32), NAME = 'alice', PASSWORD = 'violet otters dance beneath moonlight 41';

class Storage {
  m = new Map(); failWrites = null; failRemoves = null;
  get length() { return this.m.size; }
  key(i) { return [...this.m.keys()][i] ?? null; }
  getItem(k) { return this.m.has(k) ? this.m.get(k) : null; }
  setItem(k, v) { if (this.failWrites?.(k)) throw new Error('QuotaExceededError'); this.m.set(k, String(v)); }
  removeItem(k) { if (this.failRemoves?.(k)) return; this.m.delete(k); }
  /// Everything kept, as one text: what someone who reads the storage of a locked wallet sees.
  text() { return [...this.m].map(([k, v]) => `${k}=${v}`).join('\n'); }
}
/// navigator.locks: one holder at a time per name.
function locks() {
  const tails = new Map();
  return { request(name, options, work) { const before = tails.get(name) ?? Promise.resolve(); const run = before.then(() => work()); tails.set(name, run.then(() => {}, () => {})); return run; } };
}
/// A login key, its storage key and its public key.
async function loginKey(name = NAME, networkId = NET) {
  const made = await newDevice(webcrypto, { networkId, name });
  return { publicKey: made.publicKey, storageKey: made.storageKey, secret: made.secret };
}
const HASH = n => n.toString(16).padStart(2, '0').repeat(32).toUpperCase();
const receipt = (n, label, nonce = null) => ({ hash: HASH(n), height: String(100 + n), label, at: 1000 + n, ...(nonce ? { nonce } : {}) });
const open = (store, key, keep = []) => store.open({ networkId: NET, name: NAME, publicKey: key.publicKey, storageKey: key.storageKey, keep });

test('the storage key: from the login key\'s seed, the same at unlock as when the key was made, for one account only, never exported', async () => {
  const made = await newDevice(webcrypto, { networkId: NET, name: NAME });
  assert.equal(made.storageKey.extractable, false);
  assert.deepEqual(made.storageKey.algorithm, { name: 'AES-GCM', length: 256 });
  const binding = { networkId: NET, name: NAME, publicKey: made.publicKey };
  const vault = await sealLegacy({ ...made.secret }, PASSWORD, binding, argon2id, webcrypto);
  assert.equal(Object.keys(vault).sort().join(','), 'binding,ciphertext,iv,kdf,salt,version', 'the vault keeps its format');
  const opened = await openVault(vault, PASSWORD, argon2id, webcrypto);
  const iv = new Uint8Array(12), data = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, made.storageKey, new TextEncoder().encode('kept'));
  assert.equal(new TextDecoder().decode(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, opened.storageKey, data)), 'kept');
  // Another account, another network, or another key: another storage key.
  for (const other of [{ ...binding, name: 'bob' }, { ...binding, networkId: 'cd'.repeat(32) }]) {
    const key = await storageKeyFrom(fromB64(made.secret.pkcs8, 256), other, webcrypto);
    await assert.rejects(webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data));
  }
  // A payment key gives none: it opens nothing kept.
  const spend = await newDevice(webcrypto);
  assert.equal(spend.storageKey, undefined);
  const spendVault = await sealLegacy({ pkcs8: spend.secret.pkcs8 }, PASSWORD, { networkId: NET, name: NAME, publicKey: spend.publicKey }, argon2id, webcrypto, 'spend');
  assert.equal((await openVault(spendVault, PASSWORD, argon2id, webcrypto, 'spend')).storageKey, null);
  await assert.rejects(storageKeyFrom(new Uint8Array(48), binding, webcrypto), /Invalid key encoding/);
});

test('a locked wallet\'s storage shows no action, no name paid and no order; the same key reads them all again', async () => {
  const storage = new Storage(), key = await loginKey(), store = createPrivateStore({ storage, locks: locks(), cryptoImpl: webcrypto });
  assert.deepEqual(await open(store, key), { lost: false, memory: false });
  assert.equal(store.value('activity').since, '0', 'a new store knows everything this browser sent: nothing');
  const markers = orderMarkers(store), reference = 'ef'.repeat(32);
  await Promise.all([
    store.update('activity', kept => withReceipt(kept, receipt(1, 'Send 5 s to @bob', '7'))),
    store.update('names', () => ({ paid: ['bob'] })),
    markers.reserve(NET, '12', reference, HASH(1), 'https://shop.example'),
  ]);
  store.close();
  await store.flushed();
  const kept = storage.text();
  for (const secret of ['Send 5 s', '@bob', '"bob"', HASH(1), HASH(1).toLowerCase(), reference, 'shop.example', '"nonce"']) assert.equal(kept.includes(secret), false, `the storage shows ${secret}`);
  assert.deepEqual(store.value('activity').items, [], 'nothing stays in memory after the lock');
  for (const kind of ['activity', 'names', 'orders']) assert.match(storage.getItem(placeOf(kind, NET, NAME)), /^\{"v":1,"kid":"[0-9a-f]{32}","iv":"[A-Za-z0-9+/=]+","data":"[A-Za-z0-9+/=]+"\}$/);
  await open(store, key);
  assert.deepEqual(store.value('activity'), { since: '0', items: [receipt(1, 'Send 5 s to @bob', '7')] });
  assert.deepEqual(store.value('names'), { paid: ['bob'] });
  assert.deepEqual(markers.get(NET, '12', reference), { hash: HASH(1), origin: 'https://shop.example', status: 'pending', at: store.value('orders').markers[reference].at });
  const seen = await peek({ storage, networkId: NET, name: NAME, publicKey: key.publicKey, storageKey: key.storageKey, cryptoImpl: webcrypto });
  assert.equal(seen.names.paid[0], 'bob');
});

test('each write has a fresh IV, and a record moved to another account, or a wrap to another key, does not open', async () => {
  const storage = new Storage(), key = await loginKey(), store = createPrivateStore({ storage, locks: locks(), cryptoImpl: webcrypto });
  await open(store, key);
  await store.update('names', () => ({ paid: ['bob'] })); const first = JSON.parse(storage.getItem(placeOf('names', NET, NAME))).iv;
  await store.update('names', () => ({ paid: ['bob', 'carol'] })); const second = JSON.parse(storage.getItem(placeOf('names', NET, NAME))).iv;
  assert.notEqual(first, second);
  store.close(); await store.flushed();
  // The records and the wrap of alice copied to the places of mallory, with a wrap for mallory's own key: nothing opens.
  const mallory = await loginKey('mallory'), copy = new Storage();
  const record = JSON.parse(storage.getItem(placeOf('key', NET, NAME)));
  copy.setItem(placeOf('key', NET, 'mallory'), JSON.stringify({ ...record, wraps: { [mallory.publicKey]: record.wraps[key.publicKey] } }));
  for (const kind of ['activity', 'names', 'orders']) if (storage.getItem(placeOf(kind, NET, NAME))) copy.setItem(placeOf(kind, NET, 'mallory'), storage.getItem(placeOf(kind, NET, NAME)));
  const other = createPrivateStore({ storage: copy, locks: locks(), cryptoImpl: webcrypto });
  const opened = await other.open({ networkId: NET, name: 'mallory', publicKey: mallory.publicKey, storageKey: mallory.storageKey });
  assert.equal(opened.lost, true); assert.deepEqual(other.value('names'), { paid: [] }); assert.equal(other.value('activity').since, null);
  // A record of alice's moved to the place of another kind in her own storage does not open either.
  const moved = new Storage(); for (const [k, v] of storage.m) moved.setItem(k, v);
  moved.setItem(placeOf('activity', NET, NAME), storage.getItem(placeOf('names', NET, NAME)));
  const again = createPrivateStore({ storage: moved, locks: locks(), cryptoImpl: webcrypto });
  await open(again, key);
  assert.deepEqual(again.value('activity'), { since: null, items: [] }, 'a damaged activity knows nothing, and says so');
  assert.deepEqual(again.value('names'), { paid: ['bob', 'carol'] });
});

test('plain records of an earlier version are encrypted at the first unlock and removed only once that is written', async () => {
  const storage = new Storage(), key = await loginKey(), plainActivity = `${PLAIN.activity}${NET}:${NAME}`, plainNames = `${PLAIN.names}${NET}:${NAME}`;
  storage.setItem(plainActivity, JSON.stringify([receipt(1, 'Send 1 s to @bob', '3'), receipt(2, 'Account created')]));
  storage.setItem(plainNames, JSON.stringify({ paid: ['dave'] }));
  // The page closes before the encrypted copy is written (here: writing fails): the plain records stay, nothing is lost.
  storage.failWrites = k => k.startsWith('timecurrency.activity.v2:') || k.startsWith('timecurrency.names.v2:');
  const first = createPrivateStore({ storage, locks: locks(), cryptoImpl: webcrypto });
  await open(first, key); first.close(); await first.flushed();
  assert.ok(storage.getItem(plainActivity) && storage.getItem(plainNames));
  // The encrypted copy is written and the page closes before the plain one goes (here: removing does nothing).
  storage.failWrites = null; storage.failRemoves = k => k === plainActivity;
  const second = createPrivateStore({ storage, locks: locks(), cryptoImpl: webcrypto });
  await open(second, key); second.close(); await second.flushed();
  assert.ok(storage.getItem(plainActivity) !== null && storage.getItem(plainNames) === null);
  // The next unlock merges it again, without doubles, and removes it.
  storage.failRemoves = null;
  const third = createPrivateStore({ storage, locks: locks(), cryptoImpl: webcrypto });
  await open(third, key);
  assert.equal(storage.getItem(plainActivity), null);
  assert.deepEqual(third.value('activity'), { since: '0', items: [receipt(1, 'Send 1 s to @bob', '3'), receipt(2, 'Account created')] });
  assert.deepEqual(third.value('names'), { paid: ['dave'] });
  assert.equal(storage.text().includes('@bob'), false);
});

test('the marks of orders kept in the clear by account number are claimed once the account is known; a damaged one still refuses its order', async () => {
  const storage = new Storage(), key = await loginKey(), good = 'aa'.repeat(32), damaged = 'bb'.repeat(32);
  storage.setItem(`${PLAIN.orders}${NET}:12:${good}`, JSON.stringify({ hash: HASH(5), origin: 'https://shop.example', status: 'verified', at: 5 }));
  storage.setItem(`${PLAIN.orders}${NET}:12:${damaged}`, '{not json');
  storage.setItem(`${PLAIN.orders}${NET}:13:${good}`, JSON.stringify({ hash: HASH(6), origin: 'x', status: 'pending', at: 6 }));
  const store = createPrivateStore({ storage, locks: locks(), cryptoImpl: webcrypto }), markers = orderMarkers(store);
  await open(store, key);
  await markers.sync(NET, '12');
  assert.equal(markers.get(NET, '12', good).status, 'verified');
  await assert.rejects(markers.reserve(NET, '12', damaged, HASH(7)), /different signed payment/);
  assert.equal(storage.getItem(`${PLAIN.orders}${NET}:12:${good}`), null);
  assert.ok(storage.getItem(`${PLAIN.orders}${NET}:13:${good}`), 'another account\'s marks are not this one\'s');
  assert.throws(() => markers.markVerified(NET, '12', good, HASH(8)), /different signed payment/);
  assert.throws(() => markers.get(NET, '12', 'not a reference'), /Invalid payment reference/);
});

/// A page of the wallet: its own store on the browser's storage, opened with `key`, or in the page's memory only (null).
async function page(storage, lock, key) {
  const store = createPrivateStore({ storage, locks: lock, cryptoImpl: webcrypto });
  const opened = key ? await open(store, key) : await store.open({ networkId: NET, name: NAME, publicKey: 'aa'.repeat(32), storageKey: null });
  return { store, markers: orderMarkers(store), opened };
}

test('a page that keeps its history in memory only pays a website order: its mark lives in that page, nothing about it is written in the clear, and a normal session afterwards is not held back', async () => {
  // Safe because the chain pays an order once at most (the reference carries the sender's next nonce: locked-store.mjs,
  // orderMarkers), and the SDK takes no quote on a network before that rule (client-v4/orders.test.mjs).
  const storage = new Storage(), lock = locks(), key = await loginKey(), reference = 'a1'.repeat(32);
  const blind = await page(storage, lock, null);
  assert.deepEqual(blind.opened, { lost: false, memory: true });
  assert.equal(blind.markers.get(NET, '12', reference), null);
  assert.equal((await blind.markers.reserve(NET, '12', reference, HASH(1), 'https://shop.example')).status, 'pending', 'the payment is not refused');
  assert.equal(storage.length, 0, 'nothing is written: not the order, not the website');
  // This page still says it paid that order, before another payment of it is signed.
  assert.equal(blind.markers.get(NET, '12', reference).hash, HASH(1));
  await assert.rejects(blind.markers.reserve(NET, '12', reference, HASH(2)), /different signed payment/);
  // A normal session afterwards knows nothing of it, and pays what it is asked to.
  const normal = await page(storage, lock, key);
  assert.equal(normal.markers.get(NET, '12', reference), null);
  assert.equal((await normal.markers.reserve(NET, '12', 'b2'.repeat(32), HASH(3))).status, 'pending');
  assert.equal(storage.getItem(`${PLAIN.orders}${NET}:12:${reference}`), null);
});

test('a session that does not see the store counts no action as signed elsewhere: memory only, and stale', async () => {
  const storage = new Storage(), lock = locks(), old = await loginKey(), recovered = await loginKey();
  const tab = await page(storage, lock, old);
  await tab.store.update('activity', kept => withReceipt(kept, receipt(1, 'Send 1 s to @bob', '8')));
  assert.equal(sentSinceOf(tab.store.value('activity'), '7'), 1);
  // Another tab opens with keys made by a recovery: this one can no longer see what the browser keeps, nor what that tab sends.
  await page(storage, lock, recovered);
  assert.equal(tab.store.value('activity').since, null);
  assert.equal(sentSinceOf(tab.store.value('activity'), '7'), null);
  // A session of the page's memory only, even after the first reading set where its list starts.
  const blind = await page(storage, lock, null);
  await blind.store.update('activity', kept => ({ ...kept, since: '12' }));
  assert.equal(sentSinceOf(blind.store.value('activity'), '12'), null);
});

test('a mark of an order that cannot be written stops the payment before anything is sent', async () => {
  const storage = new Storage(), key = await loginKey(), store = createPrivateStore({ storage, locks: locks(), cryptoImpl: webcrypto });
  await open(store, key);
  storage.failWrites = k => k.startsWith('timecurrency.orders.v2:');
  await assert.rejects(orderMarkers(store).reserve(NET, '12', 'cc'.repeat(32), HASH(1)), /could not keep a mark of this order/);
  // Asked again, the mark is written again, and refused again while the storage refuses it; then kept.
  await assert.rejects(orderMarkers(store).reserve(NET, '12', 'cc'.repeat(32), HASH(1)), /could not keep a mark of this order/);
  storage.failWrites = null;
  assert.equal((await orderMarkers(store).reserve(NET, '12', 'cc'.repeat(32), HASH(1))).status, 'pending');
  assert.ok(storage.getItem(placeOf('orders', NET, NAME)));
});

test('two receipts at once, then the lock at once: both are written, in order, with the keys they were queued with', async () => {
  const storage = new Storage(), key = await loginKey(), store = createPrivateStore({ storage, locks: locks(), cryptoImpl: webcrypto });
  await open(store, key);
  const writes = [store.update('activity', kept => withReceipt(kept, receipt(1, 'Send 1 s to @bob', '1'))), store.update('activity', kept => withReceipt(kept, receipt(2, 'Send 2 s to @carol', '2')))];
  store.close(); // the lock, or the page hiding: the session goes now
  assert.deepEqual(await Promise.all(writes), [true, true]);
  await open(store, key);
  assert.deepEqual(store.value('activity').items.map(item => item.label), ['Send 1 s to @bob', 'Send 2 s to @carol']);
  // A write asked after the lock is not made: there is no session to ask for it.
  store.close(); assert.equal(await store.update('activity', kept => withReceipt(kept, receipt(3, 'late'))), null);
});

test('several tabs of one account: writes merge, and a tab hears what another wrote', async () => {
  const storage = new Storage(), lock = locks(), key = await loginKey();
  const heard = [], a = createPrivateStore({ storage, locks: lock, cryptoImpl: webcrypto }), b = createPrivateStore({ storage, locks: lock, cryptoImpl: webcrypto, onChange: kind => heard.push(kind) });
  await open(a, key); await open(b, key);
  await a.update('activity', kept => withReceipt(kept, receipt(1, 'Send 1 s to @bob', '1')));
  await b.update('activity', kept => withReceipt(kept, receipt(2, 'Send 2 s to @carol', '2')));
  assert.deepEqual(b.value('activity').items.map(item => item.nonce), ['1', '2'], 'b merged what a wrote before its own write');
  await b.update('names', () => ({ paid: ['carol'] }));
  a.storageEvent({ key: placeOf('names', NET, NAME), newValue: storage.getItem(placeOf('names', NET, NAME)) }); await a.flushed();
  assert.deepEqual(a.value('names'), { paid: ['carol'] });
  await a.update('names', kept => ({ paid: [...kept.paid, 'bob'] }));
  b.storageEvent({ key: placeOf('names', NET, NAME), newValue: null }); await b.flushed(); await new Promise(resolve => setTimeout(resolve, 0));
  assert.deepEqual(b.value('names'), { paid: ['carol', 'bob'] }); assert.ok(heard.includes('names') && heard.includes('activity'));
  // One tab's history is never written over by a tab whose store another key replaced: keys made by a recovery.
  const recovered = await loginKey(), c = createPrivateStore({ storage, locks: lock, cryptoImpl: webcrypto });
  assert.equal((await open(c, recovered)).lost, true);
  assert.equal(await a.update('activity', kept => withReceipt(kept, receipt(3, 'stale'))), null);
  assert.deepEqual(c.value('activity'), { since: null, items: [] });
});

test('a new login key made while the account is open opens the same history; keys this browser no longer holds lose their wrap', async () => {
  const storage = new Storage(), old = await loginKey(), next = await loginKey(), store = createPrivateStore({ storage, locks: locks(), cryptoImpl: webcrypto });
  await open(store, old);
  await store.update('activity', kept => withReceipt(kept, receipt(1, 'Send 1 s to @bob', '4')));
  assert.equal(await store.adopt({ networkId: NET, name: NAME, publicKey: next.publicKey, storageKey: next.storageKey }), true);
  assert.equal(await store.adopt({ networkId: NET, name: 'bob', publicKey: next.publicKey, storageKey: next.storageKey }), false, 'never for another account');
  store.close();
  // The new key took the login place (the old one is held nowhere now): it opens everything, and the old wrap goes.
  assert.deepEqual(await open(store, next), { lost: false, memory: false });
  assert.deepEqual(store.value('activity').items.map(item => item.nonce), ['4']);
  assert.deepEqual(Object.keys(JSON.parse(storage.getItem(placeOf('key', NET, NAME))).wraps), [next.publicKey]);
  // While a key is kept aside (a change of keys waiting for the network), its wrap stays.
  const aside = await loginKey(); await store.adopt({ publicKey: aside.publicKey, storageKey: aside.storageKey }); store.close();
  await open(store, next, [aside.publicKey]);
  assert.deepEqual(Object.keys(JSON.parse(storage.getItem(placeOf('key', NET, NAME))).wraps).sort(), [next.publicKey, aside.publicKey].sort());
});

test('keys made by a recovery cannot read the old history: it starts empty, says it knows nothing before, and the alerts count nothing as signed elsewhere', async () => {
  const storage = new Storage(), old = await loginKey(), store = createPrivateStore({ storage, locks: locks(), cryptoImpl: webcrypto });
  await open(store, old);
  await store.update('activity', kept => withReceipt(kept, receipt(1, 'Send 1 s to @bob', '9')));
  store.close(); await store.flushed();
  const recovered = await loginKey();
  assert.deepEqual(await open(store, recovered), { lost: true, memory: false });
  assert.deepEqual(store.value('activity'), { since: null, items: [] });
  assert.equal(storage.text().includes(old.publicKey), false, 'the old wrap went with the old data key');
  // The marker the Alerts panel stored before (nonce 5): with the history unknown, `sent` is null, so no alert about it.
  assert.equal(sentSinceOf(store.value('activity'), '5'), null);
  // app.js sets `since` at the first verified reading (nonce 12). A marker from before stays unknown; one from then on counts.
  await store.update('activity', kept => ({ ...kept, since: '12' }));
  assert.equal(sentSinceOf(store.value('activity'), '5'), null);
  assert.equal(sentSinceOf(store.value('activity'), '12'), 0);
  await store.update('activity', kept => withReceipt(kept, receipt(2, 'Send 2 s to @carol', '13')));
  assert.equal(sentSinceOf(store.value('activity'), '12'), 1);
});

test('a key without a wrap does not throw away what another login key of this browser can still read', async () => {
  const storage = new Storage(), first = await loginKey(), aside = await loginKey(), stranger = await loginKey(), store = createPrivateStore({ storage, locks: locks(), cryptoImpl: webcrypto });
  await open(store, first);
  await store.update('activity', kept => withReceipt(kept, receipt(1, 'Send 1 s to @bob', '2')));
  await store.adopt({ publicKey: aside.publicKey, storageKey: aside.storageKey }); store.close();
  // `aside` is kept aside in this browser (a change of keys waiting for the network): the history stays for it.
  assert.deepEqual(await open(store, stranger, [aside.publicKey]), { lost: true, memory: true });
  assert.deepEqual(store.value('activity'), { since: null, items: [] });
  store.close();
  assert.deepEqual(await open(store, aside), { lost: false, memory: false });
  assert.deepEqual(store.value('activity').items.map(item => item.nonce), ['2']);
});

test('a store that cannot be opened is one of the page\'s memory only, and knows nothing before', async () => {
  const storage = new Storage(), store = createPrivateStore({ storage, locks: locks(), cryptoImpl: webcrypto });
  assert.deepEqual(await store.open({ networkId: NET, name: NAME, publicKey: 'aa'.repeat(32), storageKey: null }), { lost: false, memory: true });
  assert.equal(store.memoryOnly(), true);
  assert.equal(await store.update('names', () => ({ paid: ['bob'] })), null);
  assert.deepEqual(store.value('names'), { paid: ['bob'] }); assert.equal(store.value('activity').since, null);
  assert.equal(storage.length, 0);
});

test('the activity: the newest 40, one entry per action, the lower start of two lists, and what an old plain list was', () => {
  let value = activityFrom([]);
  for (let n = 1; n <= MAX_ACTIVITY + 5; n++) value = withReceipt(value, receipt(n, `a${n}`));
  assert.equal(value.items.length, MAX_ACTIVITY); assert.equal(value.items[0].label, 'a6');
  value = withReceipt(value, { ...receipt(10, 'again'), at: 9999 });
  assert.equal(value.items.at(-1).label, 'again'); assert.equal(value.items.filter(item => item.hash === HASH(10)).length, 1);
  assert.deepEqual(activityFrom([{ hash: 'zz' }, null, receipt(1, 'x')]).items.length, 1);
  assert.equal(mergeActivity({ since: '5', items: [] }, { since: '3', items: [] }).since, '3');
  assert.equal(mergeActivity({ since: null, items: [] }, { since: '3', items: [] }).since, '3');
  assert.equal(activityFrom({ since: 'x', items: [] }).since, null);
  assert.equal(b64(fromB64(b64(new Uint8Array([1, 2, 3])))), 'AQID');
});
