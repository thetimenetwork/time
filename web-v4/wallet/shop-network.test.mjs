// The demo blog's page (web-v4/merchant/app.js) keeps a paid order it could not get confirmed yet in this browser, and
// finishes it later. A test network can be reset under the same addresses, and a new account there can have the number
// of an old one: a payment of the chain that is gone must never be settled for it. Each kept payment therefore carries
// the network it was made on, and only a page of that network finishes it.
//
// It stands here, beside the wallet's tests, because the repository's checks run the tests of web-v4/wallet and not those
// of web-v4/merchant. The page runs as client-v4/own-node.test.mjs runs it: its code in a context of its own, with a
// stand-in for the page and for the blog's server.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const code = await readFile(new URL('../merchant/app.js', import.meta.url), 'utf8');
const OLD = 'a1'.repeat(32), NEW = 'b2'.repeat(32), KEY = 'time-merchant-pending-settlements';
const ticks = async (condition) => { for (let i = 0; i < 400 && !condition(); i++) await new Promise((resolve) => setImmediate(resolve)); };
const payment = (n) => ({ orderId: 'ab'.repeat(31) + String(n).padStart(2, '0'), hash: 'CD'.repeat(31) + String(n).padStart(2, '0') });

/// The page, on a blog of network `networkId` (none: an older blog that names none), signed in as account `account`.
async function page({ storage, networkId, account = '5', settle = () => ({ status: 200 }) }) {
  const elements = new Map(), settles = [], statuses = [];
  const element = (id) => {
    if (!elements.has(id)) { let text = ''; const e = { disabled: false, hidden: false, href: '', value: '', children: [], classList: { toggle() {}, contains: () => false }, listeners: {}, addEventListener(type, fn) { this.listeners[type] = fn; }, replaceChildren(...items) { this.children = items; }, append(...items) { this.children.push(...items); } }; Object.defineProperty(e, 'textContent', { get: () => text, set: (value) => { text = value; if (id === 'status') statuses.push(value); } }); elements.set(id, e); }
    return elements.get(id);
  };
  const answer = (status, body) => ({ ok: status === 200, status, json: async () => body });
  const fetch = async (path, options) => {
    if (path === '/api/config') return answer(200, { walletOrigin: 'https://wallet.example', ...(networkId ? { networkId } : {}) });
    if (path === '/api/session') return answer(200, { accountId: account, name: 'buyer', balance: '1000000', height: '9', csrf: 'token' });
    if (path === '/api/posts') return answer(200, { posts: [], more: false });
    if (path === '/api/order') { const p = payment(90); return answer(200, { orderId: p.orderId, networkId, to: '0', amount: '100000', fee: '1000', expiresAt: 1 }); }
    if (path === '/api/order/settle') { const request = JSON.parse(options.body); settles.push(request); const got = settle(request); return answer(got.status, got.status === 200 ? { ...request, fulfilled: true, height: '42' } : { error: got.error ?? 'Sign in first' }); }
    return answer(404, { error: 'Unknown API route' });
  };
  const localStorage = { getItem: (key) => (storage.has(key) ? storage.get(key) : null), setItem: (key, value) => { storage.set(key, String(value)); }, removeItem: (key) => { storage.delete(key); } };
  const context = vm.createContext({ document: { getElementById: element, createElement: () => element('made') }, fetch, localStorage, console: { warn() {} }, setTimeout: (resolve) => setImmediate(resolve), confirm: () => true, TimeSDK: { requestWallet: async ({ request }) => { await request; return { transactionHash: payment(90).hash }; } } });
  vm.runInContext(code, context);
  await ticks(() => statuses.length > 0 && !/Confirming/.test(statuses.at(-1)));
  return { element, settles, statuses, saved: () => JSON.parse(storage.get(KEY) ?? '[]') };
}

test('a payment kept from a network that was reset is not settled for an account of the same number on the new one; this network\'s is', async () => {
  const at = Date.now(), storage = new Map([[KEY, JSON.stringify([
    { ...payment(1), accountId: '5', savedAt: at, networkId: OLD },
    { ...payment(2), accountId: '5', savedAt: at },
    { ...payment(3), accountId: '5', savedAt: at, networkId: NEW },
  ])]]);
  const shop = await page({ storage, networkId: NEW });
  assert.deepEqual(shop.settles, [payment(3)], 'only the payment of this network is settled');
  // What belongs to another network, or to none, stays as it was, and goes after its seven days as before.
  assert.deepEqual(shop.saved().map((p) => [p.orderId, p.networkId ?? null]), [[payment(1).orderId, OLD], [payment(2).orderId, null]]);
});

test('a payment made now is kept with the network of the blog, and a blog that names no network keeps them as before', async () => {
  const storage = new Map();
  let shop = await page({ storage, networkId: NEW, settle: () => ({ status: 401 }) });
  await shop.element('pay').listeners.click();
  assert.deepEqual(shop.saved().map((p) => [p.orderId, p.accountId, p.networkId]), [[payment(90).orderId, '5', NEW]]);
  // Reopened on the network it was made on: finished.
  shop = await page({ storage, networkId: NEW });
  assert.deepEqual([shop.settles, shop.saved()], [[payment(90)], []]);
  // A blog that names no network (an older server): the payment is kept without one, and finished by such a blog only.
  shop = await page({ storage, settle: () => ({ status: 401 }) });
  await shop.element('pay').listeners.click();
  assert.deepEqual(shop.saved().map((p) => Object.hasOwn(p, 'networkId')), [false]);
  assert.deepEqual((await page({ storage, networkId: NEW })).settles, [], 'not by a blog of a named network');
  assert.deepEqual((await page({ storage })).settles, [payment(90)]);
});
