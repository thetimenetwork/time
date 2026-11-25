// The demo blog on the gateway's second origin: client-v4/blog-store.mjs, its routes in server.mjs and the page
// web-v4/merchant/app.js. The HTTP tests sign in as the fixture's account 0 (@alice), whose key is known; a post of
// another account is written into the store directly. Date.now is the fixture's time, so the server's request limit
// (50 a second) counts every request of one server: each server below answers fewer than 50.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import vm from 'node:vm';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createV4Servers } from './server.mjs';
import { createBlogStore, checkPostText, POST_LIMITS } from './blog-store.mjs';
import { createOrderStore } from './order-store.mjs';
import { createOrderService } from './server-auth.mjs';
import './time-sdk.js';

const fixture = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/proof.json', import.meta.url), 'utf8'));
const NETWORK = fixture.trust.network_id, NOW = fixture.now_ms;
const ALICE = createPrivateKey({ format: 'der', type: 'pkcs8', key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 42)]) });
const ALICE_PUBLIC = createPublicKey(ALICE).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
const block = fixture.proof.light_block;
const rpc = async (endpoint, p = {}) => {
  if (endpoint === '/commit') return { signed_header: block.signed_header };
  if (endpoint === '/validators') return { block_height: p.height, total: '4', validators: p.height === '6' ? block.validators : block.next_validators };
  if (endpoint === '/abci_query') return { response: { height: '5', code: 0, value: Buffer.from(JSON.stringify({ height: '5', root: block.signed_header.header.app_hash.toLowerCase(), entries: fixture.proof.entries, history_proofs: fixture.proof.history_proofs })).toString('base64') } };
  throw Error('Unconfigured test RPC');
};

async function withGateway(directory, work) {
  const original = Date.now; Date.now = () => NOW; let servers;
  try {
    servers = await createV4Servers({ root: fileURLToPath(new URL('../', import.meta.url)), manifest: { networkId: NETWORK, chainId: fixture.trust.chain_id, trust: fixture.trust }, rpc, walletPort: 0, merchantPort: 0, checkpointPath: path.join(directory, 'checkpoint.json'), ordersPath: path.join(directory, 'orders.json'), upgradeCheck: { everyMs: 0 } });
    return await work(servers);
  } finally { await servers?.close(); Date.now = original; }
}
function call(origin, pathname, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(pathname, origin);
    const request = http.request({ hostname: '127.0.0.1', port: u.port, method, path: u.pathname + u.search, headers: { Host: u.host, ...headers } }, response => {
      const chunks = []; response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); let json = null; try { json = JSON.parse(text); } catch {} resolve({ status: response.statusCode, headers: response.headers, text, json }); });
    });
    request.on('error', reject); request.end(body);
  });
}
// A POST as the blog page sends it: its Origin, JSON, the session cookie and the CSRF token. `from: null` sends no Origin.
function send(origin, pathname, value, { session, from = origin, csrf = session?.csrf, cookie = session?.cookie, raw } = {}) {
  return call(origin, pathname, { method: 'POST', body: raw ?? JSON.stringify(value), headers: { 'Content-Type': 'application/json', ...(from ? { Origin: from } : {}), ...(cookie ? { Cookie: cookie } : {}), ...(csrf ? { 'X-CSRF-Token': csrf } : {}) } });
}
async function signIn(servers) {
  const origin = servers.merchantOrigin, challenge = await send(origin, '/api/login/challenge', {});
  assert.equal(challenge.status, 200);
  const account = (await servers.verifiedState({ ids: ['0'] })).state.accounts.find(a => a.id === '0');
  const message = TimeSDK.loginMessage(challenge.json, { account, publicKey: ALICE_PUBLIC });
  const finish = await send(origin, '/api/login/finish', { message, signature: sign(null, TimeSDK.loginBytes(message), ALICE).toString('hex') }, { cookie: challenge.headers['set-cookie'][0].split(';')[0] });
  assert.equal(finish.status, 200, finish.text);
  return { cookie: finish.headers['set-cookie'].find(value => value.includes('_session=')).split(';')[0], csrf: finish.json.csrf };
}
const list = async servers => { const answer = await call(servers.merchantOrigin, '/api/posts'); assert.equal(answer.status, 200, answer.text); return answer.json; };
const temporary = () => mkdtemp(path.join(os.tmpdir(), 'time-v4-blog-'));

test('the text of a post: trimmed, 1 to 500 characters, line breaks but no other control character', () => {
  assert.equal(checkPostText('  hello  \n'), 'hello');
  assert.equal(checkPostText('one\r\ntwo\nthree'), 'one\ntwo\nthree');
  assert.equal(checkPostText('a'.repeat(500)), 'a'.repeat(500));
  assert.equal(checkPostText(' '.repeat(1000) + 'b'.repeat(500) + ' '), 'b'.repeat(500));
  // Characters are code points: 500 emoji are 1000 UTF-16 units and pass.
  assert.equal(checkPostText('\u{1F600}'.repeat(500)).length, 1000);
  assert.equal(checkPostText('<script>alert(1)</script>'), '<script>alert(1)</script>');
  const refused = (value, pattern) => assert.throws(() => checkPostText(value), error => error.httpStatus === 400 && pattern.test(error.message), JSON.stringify(value));
  refused('', /at least one character/); refused(' \n\t ', /at least one character/);
  refused('a'.repeat(501), /at most 500 characters; this one has 501/); refused('\u{1F600}'.repeat(501), /this one has 501/);
  refused('a'.repeat(2001), /at most 500 characters/);
  for (const bad of ['tab\there', 'bell\u0007', 'nul\u0000x', 'cr\ronly', 'esc\u001b[31m', 'del\u007f', 'c1\u0085', 'vt\u000bx']) refused(bad, /control characters/);
  for (const bad of ['‮evil', 'x⁦y', 'x‪y']) refused(bad, /direction/);
  refused('\ud800', /not valid Unicode/); refused(5, /is text/); refused(null, /is text/); refused(['x'], /is text/);
  assert.deepEqual(POST_LIMITS, { maxChars: 500, perAccount: 20, windowMs: 86400000, perHour: 60, keep: 500, keepMs: 7 * 86400000, page: 50, maxRawChars: 2000, maxMarks: 4, maxInvisible: 16 });
});

test('a post paints inside its box: at most 4 combining marks on a letter, at most 16 characters that take no room', async () => {
  const refused = (value, pattern) => assert.throws(() => checkPostText(value), error => error.httpStatus === 400 && pattern.test(error.message), JSON.stringify(value).slice(0, 80));
  // What people write passes: accents, Vietnamese (two marks, decomposed), Hebrew with points, Thai with tone marks,
  // Hindi, emoji with a skin tone, a keycap, a flag and families joined by zero width joiners.
  for (const ok of ['café crème', 'Vie\u0323\u0302t Nam', 'שָׁלוֹם', 'น้ำ ก็่', 'नमस्ते', '\u{1F44B}\u{1F3FD}', '1\uFE0F\u20E3', '\u{1F1EB}\u{1F1F7}', '\u{1F468}\u200D\u{1F469}\u200D\u{1F467}'.repeat(20), 'e' + '\u0301'.repeat(4)])
    assert.equal(checkPostText(ok), ok.trim());
  // Five marks on one letter, and the post made of hundreds (it painted over the page: audit G-8), are refused.
  refused('e' + '\u0301'.repeat(5), /at most 4 accents or other combining marks/);
  refused('Z' + '\u0336\u0353\u0316\u0300\u0301\u0302'.repeat(60) + 'algo', /at most 4 accents/);
  // Up to 16 characters that take no room pass; a seventeenth is refused, however they are mixed.
  assert.equal(checkPostText('a\u200Bb'.repeat(16)), 'a\u200Bb'.repeat(16));
  refused('a\u200Bb'.repeat(17), /at most 16 characters that take no room/);
  refused('x' + ['\u200C', '\u2060', '\uFEFF', '\u00AD', '\u034F', '\u200E', '\u3164', '\u180E', '\u2063'].join('y').repeat(2), /take no room/);
  // A joiner between two emoji is part of the emoji: forty of them are not counted; between letters it is.
  assert.ok(checkPostText('\u{1F469}\u200D\u{1F4BB} '.repeat(40)));
  refused('a\u200Db'.repeat(17), /take no room/);
  // The page cuts what still reaches beyond a post at the post's edges.
  const css = await readFile(new URL('../web-v4/merchant/style.css', import.meta.url), 'utf8');
  assert.match(css, /\n\.post \{[^}]*overflow: hidden;[^}]*contain: paint;[^}]*\}/);
});

test('the store: 20 posts per account in 24 hours whatever is deleted, a week kept and then the newest 500, read back after a restart', async () => {
  const directory = await temporary(), filename = path.join(directory, 'blog.sqlite');
  let time = Date.UTC(2026, 10, 20, 12, 0, 0), store = createBlogStore({ filename, networkId: NETWORK, now: () => time });
  try {
    const mine = [];
    for (let i = 0; i < 20; i++) { mine.push(store.publish({ accountId: '7', name: 'bob', text: `post ${i}` })); time += 1000; }
    assert.deepEqual(mine[0], { id: '1', accountId: '7', name: 'bob', text: 'post 0', createdAt: '2026-11-20T12:00:00.000Z' });
    assert.throws(() => store.publish({ accountId: '7', name: 'bob', text: 'one more' }), error => error.httpStatus === 429 && /20 posts in the last 24 hours/.test(error.message) && /again after 2026-11-21 12:01 UTC/.test(error.message));
    // Deleting a post does not give one back; another account is not affected.
    assert.deepEqual(store.remove({ accountId: '7', id: mine[0].id }), { deleted: '1' });
    assert.throws(() => store.publish({ accountId: '7', name: 'bob', text: 'one more' }), /20 posts/);
    assert.equal(store.publish({ accountId: '8', name: 'carol', text: 'hi' }).accountId, '8');
    // 24 hours after the first publish it leaves the window.
    time = Date.UTC(2026, 10, 21, 12, 0, 0, 1); assert.equal(store.publish({ accountId: '7', name: 'bob', text: 'next day' }).text, 'next day');
    assert.throws(() => store.publish({ accountId: '7', name: 'bob', text: 'and another' }), /20 posts/);
    // Deleting: only the author, only an existing post, only a canonical id.
    assert.throws(() => store.remove({ accountId: '8', id: mine[1].id }), error => error.httpStatus === 403);
    assert.throws(() => store.remove({ accountId: '7', id: '1' }), error => error.httpStatus === 404);
    for (const id of ['0', '01', 'x', 2, '', '1e3', '99999999999999999']) assert.throws(() => store.remove({ accountId: '7', id }), error => error.httpStatus === 400, String(id));
    // Name and account come from the caller (the server's session); a name the chain would not give is stored as none.
    assert.equal(store.publish({ accountId: '9', name: '<b>x</b>', text: 'x' }).name, null);
    assert.throws(() => store.publish({ accountId: 'x', name: 'a', text: 'x' }), /author account/);
    // 26 accounts write 20 posts each, one every 62 seconds (the blog takes 60 an hour from everyone together): none is
    // deleted, since none is a week old.
    const read = () => { const out = []; let at = store.list(); while (true) { out.push(...at.posts); if (!at.more) break; at = store.list({ before: at.posts.at(-1).id }); } return out; };
    const before = read().length;
    for (let account = 100; account < 126; account++) for (let i = 0; i < 20; i++) { time += 62000; store.publish({ accountId: String(account), name: `user${account}`, text: `${account}/${i}` }); }
    let all = read(), page;
    assert.equal(all.length, before + 520, 'a post younger than a week is never deleted to make room'); assert.equal(all[0].text, '125/19');
    assert.equal(store.list().posts.length, 50); assert.equal(store.list({ before: all[0].id }).posts[0].id, all[1].id);
    assert.throws(() => store.list({ before: 'x' }), error => error.httpStatus === 400);
    store.close(); store = createBlogStore({ filename, networkId: NETWORK, now: () => time });
    page = store.list(); assert.deepEqual(page.posts, all.slice(0, 50)); assert.equal(page.more, true);
    // The per-account record is read back too.
    assert.throws(() => store.publish({ accountId: '125', name: 'user125', text: 'after restart' }), /20 posts/);
    // A week after the first of them, the next post leaves the newest 500 and deletes the older ones beyond.
    time = Date.UTC(2026, 10, 28, 12, 30, 0); store.publish({ accountId: '126', name: 'user126', text: 'a week later' });
    all = read();
    assert.equal(all.length, 500); assert.equal(all[0].text, 'a week later'); assert.equal(all[1].text, '125/19'); assert.equal(all.at(-1).text, '101/1');
    store.close(); store = null;
    // A database of another network is refused.
    assert.throws(() => createBlogStore({ filename, networkId: 'cd'.repeat(32) }), /another network/);
  } finally { store?.close(); await rm(directory, { recursive: true, force: true }); }
});

test('everyone together: 60 posts an hour, then a post is refused and nobody else\'s is deleted (audit G-4)', async () => {
  const directory = await temporary(), filename = path.join(directory, 'blog.sqlite');
  let time = Date.UTC(2026, 10, 24, 9, 0, 0); const store = createBlogStore({ filename, networkId: NETWORK, now: () => (time += 1000) });
  try {
    // Thirty people write a post each; then 25 accounts try to write 20 posts each at once (audit proof poc3.mjs, part 2).
    for (let v = 0; v < 30; v++) store.publish({ accountId: String(1000 + v), name: `victim${v}`, text: `a post by someone else ${v}` });
    let refused = 0, published = 0, said = null;
    for (let a = 0; a < 25; a++) for (let p = 0; p < 20; p++) try { store.publish({ accountId: String(a + 1), name: `spam${a}`, text: 'spam' }); published++; } catch (error) { refused++; said ??= error; assert.equal(error.httpStatus, 429); }
    assert.deepEqual([published, refused], [30, 470]);
    assert.match(said.message, /^The blog has taken 60 posts in the last hour from everyone together, the most this demo takes\. You can publish again after 2026-11-24 10:01 UTC\.$/);
    const all = []; let page = store.list(); all.push(...page.posts); while (page.more) { page = store.list({ before: all.at(-1).id }); all.push(...page.posts); }
    assert.equal(all.filter(post => Number(post.accountId) >= 1000).length, 30, 'every post of the thirty is still there');
    // An hour after the first posts, the blog takes posts again.
    time = Date.UTC(2026, 10, 24, 10, 1, 0); assert.equal(store.publish({ accountId: '1000', name: 'victim0', text: 'again' }).text, 'again');
  } finally { store.close(); await rm(directory, { recursive: true, force: true }); }
});

test('the supporter mark: only an order the server settled after verifying its payment', async () => {
  const directory = await temporary(), networkId = 'ab'.repeat(32);
  const repository = createOrderStore({ filename: path.join(directory, 'orders.sqlite'), networkId, recipient: '0' });
  try {
    const state = { protocol_version: '4', network_id: networkId, time_micros: '600000000', genesis: { genesis_time_micros: '0' }, accounts: [{ id: '5', nonce: '7' }], recovery_cases: [], config: {} };
    let order, amount = '1';
    const orders = createOrderService({ repository, networkId, recipient: '0', verifiedState: async () => ({ verified: true, state }), now: () => 1000,
      verifiedReceipt: async hash => ({ verified: true, executionVerified: true, code: 0, networkId, height: '50', hash, action: { kind: 10, from: '5', nonce: '8', payload: { to: '0', amount, reference: order.orderId } } }) });
    order = await orders.issue('5', '100000');
    assert.equal(repository.paidBy('5'), false, 'an order that is not paid');
    await assert.rejects(orders.fulfill('5', order.orderId, 'aa'.repeat(32)), /does not match exact order reference/);
    assert.equal(repository.paidBy('5'), false, 'a payment that does not match the order');
    amount = '100000'; await orders.fulfill('5', order.orderId, 'aa'.repeat(32));
    assert.equal(repository.paidBy('5'), true); assert.equal(repository.paidBy('6'), false); assert.equal(repository.paidBy(5), false);
  } finally { repository.close(); await rm(directory, { recursive: true, force: true }); }
});

test('over HTTP: the list is public; publishing and deleting need a session, the origin and the CSRF token; a post comes back as the same text', async () => {
  const directory = await temporary();
  try {
    // A post of another account (7, @bob), written before the server starts.
    const seed = createBlogStore({ filename: path.join(directory, 'orders.json.blog.sqlite'), networkId: NETWORK, now: () => NOW - 60000 });
    const bob = seed.publish({ accountId: '7', name: 'bob', text: 'Bob was here' }); seed.close();
    let before;
    await withGateway(directory, async servers => {
      const origin = servers.merchantOrigin;
      const empty = await call(origin, '/api/posts');
      assert.equal(empty.status, 200); assert.equal(empty.headers['content-type'], 'application/json; charset=utf-8'); assert.equal(empty.headers['x-content-type-options'], 'nosniff');
      assert.deepEqual(empty.json, { posts: [{ ...bob, supporter: false }], more: false, limits: { maxChars: 500, perAccount: 20, hours: 24, keep: 500 } });
      assert.equal((await call(origin, '/api/posts?limit=5')).status, 400);
      // Without a session, without the origin, from another origin.
      assert.equal((await send(origin, '/api/posts', { text: 'hi' })).status, 401);
      assert.equal((await send(origin, '/api/posts/delete', { id: bob.id })).status, 401);
      assert.match((await send(origin, '/api/posts', { text: 'hi' }, { from: null })).json.error, /origin rejected/);
      const session = await signIn(servers);
      assert.equal((await send(origin, '/api/posts', { text: 'hi' }, { session, from: servers.walletOrigin })).status, 403);
      assert.match((await send(origin, '/api/posts', { text: 'hi' }, { session, from: null })).json.error, /origin rejected/);
      assert.match((await send(origin, '/api/posts', { text: 'hi' }, { session, csrf: 'ab'.repeat(32) })).json.error, /CSRF/);
      assert.equal((await call(origin, '/api/posts', { method: 'POST', headers: { Origin: origin, Cookie: session.cookie, 'X-CSRF-Token': session.csrf, 'Content-Type': 'text/plain' }, body: '{"text":"hi"}' })).status, 400);
      // A post with markup is stored and served as the same text; the author is the session's account.
      const markup = '<script>alert("x")</script>\n<img src=x onerror=alert(1)>';
      const published = await send(origin, '/api/posts', { text: markup }, { session });
      assert.equal(published.status, 200, published.text);
      assert.deepEqual(published.json.post, { id: String(Number(bob.id) + 1), accountId: '0', name: 'alice', text: markup, createdAt: new Date(NOW).toISOString(), supporter: false });
      // Refused texts and bodies.
      for (const [value, pattern] of [[{ text: '' }, /at least one character/], [{ text: ' \n ' }, /at least one character/], [{ text: 'x'.repeat(501) }, /at most 500/], [{ text: 'tab\there' }, /control characters/], [{ text: 'nul\u0000' }, /control characters/], [{ text: '‮evil' }, /direction/], [{ text: 5 }, /is text/], [{ text: 'x', name: 'mallory' }, /one field "text"/], [{ accountId: '7', text: 'x' }, /one field "text"/], [['x'], /one field "text"/]]) {
        const answer = await send(origin, '/api/posts', value, { session });
        assert.equal(answer.status, 400, JSON.stringify(value)); assert.match(answer.json.error, pattern, JSON.stringify(value));
      }
      assert.match((await send(origin, '/api/posts', null, { session, raw: '{"text":"\\ud800"}' })).json.error, /not valid Unicode/);
      const second = await send(origin, '/api/posts', { text: '  two\r\nlines  ' }, { session });
      assert.equal(second.json.post.text, 'two\nlines');
      // Another account's post cannot be deleted; a missing one is said to be missing.
      const refused = await send(origin, '/api/posts/delete', { id: bob.id }, { session });
      assert.equal(refused.status, 403); assert.match(refused.json.error, /Only the person who wrote a post/);
      assert.equal((await send(origin, '/api/posts/delete', { id: '999' }, { session })).status, 404);
      assert.equal((await send(origin, '/api/posts/delete', { id: 'x' }, { session })).status, 400);
      assert.equal((await send(origin, '/api/posts/delete', { id: bob.id, accountId: '7' }, { session })).status, 400);
      // Its own post is deleted.
      assert.deepEqual((await send(origin, '/api/posts/delete', { id: second.json.post.id }, { session })).json, { deleted: second.json.post.id });
      before = await list(servers);
      assert.deepEqual(before.posts.map(post => [post.accountId, post.text]), [['0', markup], ['7', 'Bob was here']]);
    });
    // After a restart the journal is read back.
    await withGateway(directory, async servers => { assert.deepEqual(await list(servers), before); });
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('over HTTP: the supporter mark follows the orders the server settled, never an order that is only issued or a payment it could not verify', async () => {
  const directory = await temporary();
  try {
    await withGateway(directory, async servers => {
      const origin = servers.merchantOrigin, session = await signIn(servers);
      await send(origin, '/api/posts', { text: 'first' }, { session });
      const mark = async () => { const [posts, me] = await Promise.all([list(servers), call(origin, '/api/session', { headers: { Cookie: session.cookie } })]); return [posts.posts[0].supporter, me.json.supporter]; };
      assert.deepEqual(await mark(), [false, false]);
      const order = await send(origin, '/api/order', { item: 'test-purchase' }, { session });
      assert.equal(order.status, 200, order.text); assert.equal(order.json.amount, '100000');
      assert.deepEqual(await mark(), [false, false], 'an issued order is not a payment');
      // This fixture serves no receipt: the payment cannot be verified and the order stays unsettled.
      const settle = await send(origin, '/api/order/settle', { orderId: order.json.orderId, hash: 'AB'.repeat(32) }, { session });
      assert.equal(settle.status, 400); assert.match(settle.json.error, /awaiting canonical finality/);
      assert.deepEqual(await mark(), [false, false], 'a payment the server could not verify');
      // The record the server writes once it verified the payment (server-auth.mjs, fulfill), written here
      // through a second connection to its order database because the fixture has no payment to verify.
      const store = createOrderStore({ filename: path.join(directory, 'orders.json.sqlite'), networkId: NETWORK, recipient: '0' });
      try { store.settle({ ...store.get(order.json.orderId), fulfilled: true, hash: 'AB'.repeat(32), height: '5', confirmedBy: ['light-client'] }); } finally { store.close(); }
      assert.deepEqual(await mark(), [true, true]);
    });
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('over HTTP: an account publishes 20 posts in 24 hours; the 21st is refused with 429 and deleting does not give one back', async () => {
  const directory = await temporary();
  try {
    await withGateway(directory, async servers => {
      const origin = servers.merchantOrigin, session = await signIn(servers);
      let last;
      for (let i = 1; i <= 20; i++) { last = await send(origin, '/api/posts', { text: `post ${i}` }, { session }); assert.equal(last.status, 200, `post ${i}: ${last.text}`); }
      const refused = await send(origin, '/api/posts', { text: 'post 21' }, { session });
      assert.equal(refused.status, 429); assert.match(refused.json.error, /You have published 20 posts in the last 24 hours/);
      assert.equal((await send(origin, '/api/posts/delete', { id: last.json.post.id }, { session })).status, 200);
      assert.equal((await send(origin, '/api/posts', { text: 'post 21' }, { session })).status, 429);
      const page = await list(servers); assert.equal(page.posts.length, 19); assert.equal(page.posts[0].text, 'post 19');
    });
  } finally { await rm(directory, { recursive: true, force: true }); }
});

// The page, run on a stand-in document that records what it creates. Posts reach the page as text only.
function stand() {
  const byId = new Map(), created = [];
  const make = tag => {
    let text = '';
    const node = { tagName: tag, children: [], className: '', hidden: false, disabled: false, href: '', value: '', type: '', dateTime: '', listeners: {}, classes: new Set(),
      classList: { toggle(name, force) { const on = force ?? !node.classes.has(name); if (on) node.classes.add(name); else node.classes.delete(name); return on; } },
      addEventListener(type, listener) { node.listeners[type] = listener; },
      append(...items) { for (const item of items) node.children.push(typeof item === 'string' ? { tagName: '#text', textContent: item } : item); },
      replaceChildren(...items) { node.children = []; node.append(...items); },
      get textContent() { return node.children.length ? node.children.map(child => child.textContent).join('') : text; },
      set textContent(value) { node.children = []; text = String(value); } };
    return node;
  };
  const document = { getElementById: id => { if (!byId.has(id)) byId.set(id, make('#' + id)); return byId.get(id); }, createElement: tag => { const node = make(tag); created.push(node); return node; } };
  return { document, byId: id => document.getElementById(id), created };
}
const ticks = async done => { for (let i = 0; i < 200 && !done(); i++) await new Promise(resolve => setImmediate(resolve)); assert(done(), 'the page did not get there'); };

test('the page: posts and names are shown as text, Delete only on your own posts, the mark only for supporters, the counter counts as the server does', async () => {
  const code = await readFile(new URL('../web-v4/merchant/app.js', import.meta.url), 'utf8'), html = await readFile(new URL('../web-v4/merchant/index.html', import.meta.url), 'utf8');
  assert(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function/.test(code), 'the page code never writes HTML');
  assert(!/<script(?![^>]*\ssrc=)[^>]*>|<style|\sstyle=|\son[a-z]+=|javascript:/i.test(html), 'no inline script, style or handler');
  for (const reference of html.matchAll(/(?:src|href)="([^"]*)"/g)) assert.match(reference[1], /^(\/style\.css|\/app\.js|\/sdk\/time-sdk\.js|\/web-v4\/shared\/network-menu\.js|#)$/);
  for (const words of ['Time blog (demo)', 'Your password stays in your wallet. This website only learns your name.', 'Posts are public', 'may be wiped', 'Test network.', 'without value', 'Sign in with Time']) assert(html.includes(words), words);
  assert(!/Seconds devnet|LOCAL DEVNET|laboratory|\bLAB\b|devnet/i.test(html + code), 'old names');
  const markup = '<img src=x onerror=alert(1)>';
  const posts = [
    { id: '3', accountId: '0', name: 'alice', text: markup, createdAt: '2026-11-20T12:00:00.000Z', supporter: true },
    { id: '2', accountId: '7', name: 'bob', text: 'line one\nline two', createdAt: '2026-11-20T11:00:00.000Z', supporter: false },
  ];
  const page = stand(), requests = [];
  const answer = body => ({ ok: true, status: 200, json: async () => body });
  const fetch = async (url, options) => {
    requests.push({ url, method: options.method, body: options.body, csrf: options.headers['X-CSRF-Token'] });
    if (url === '/api/config') return answer({ walletOrigin: 'https://wallet.example', catalog: { 'test-purchase': '100000' } });
    if (url === '/api/session') return answer({ accountId: '0', name: 'alice', balance: '1500000', height: '9', csrf: 'token', supporter: true });
    if (url === '/api/posts' && options.method === 'GET') return answer({ posts, more: true, limits: { maxChars: 500, perAccount: 20, hours: 24, keep: 500 } });
    if (url === '/api/posts' || url === '/api/posts/delete') return answer({ ok: true });
    return { ok: false, status: 404, json: async () => ({ error: 'Unknown API route' }) };
  };
  const context = vm.createContext({ document: page.document, fetch, localStorage: { getItem: () => null, setItem() {}, removeItem() {} }, console, setTimeout, confirm: () => true, TimeSDK: {} });
  vm.runInContext(code, context);
  await ticks(() => page.byId('posts').children.length === 2 && page.byId('greeting').textContent === 'Hello, @alice');
  assert.equal(page.byId('account-copy').textContent, 'Account 0 · 1.5 seconds');
  assert.equal(page.byId('me-mark').hidden, false); assert.equal(page.byId('pay').textContent, 'Support this blog: 0.1 seconds');
  assert(!page.byId('composer').classes.has('hidden') && page.byId('login').classes.has('hidden'));
  const [mine, theirs] = page.byId('posts').children, part = (item, className) => item.children.find(child => child.className === className);
  const textOf = item => part(item, 'post-text').textContent;
  assert.equal(textOf(mine), markup); assert.equal(textOf(theirs), 'line one\nline two');
  assert(page.created.every(node => ['li', 'p', 'span', 'time', 'button'].includes(node.tagName)), 'only these elements are made');
  assert.deepEqual(part(mine, 'post-head').children.filter(child => child.className === 'mark').map(child => child.textContent), ['supporter']);
  assert.equal(part(theirs, 'post-head').children.filter(child => child.className === 'mark').length, 0);
  assert.equal(part(mine, 'post-head').children[0].textContent, '@alice');
  assert.equal(mine.children.filter(child => child.tagName === 'button').length, 1, 'Delete on my post');
  assert.equal(theirs.children.filter(child => child.tagName === 'button').length, 0, 'no Delete on another account\'s post');
  assert.equal(page.byId('older').hidden, false);
  // The counter: code points of the trimmed text, as the server counts them.
  const typed = value => { page.byId('post-text').value = value; page.byId('post-text').listeners.input(); };
  typed('\u{1F600}'.repeat(500)); assert.equal(page.byId('counter').textContent, '500 / 500'); assert.equal(page.byId('publish').disabled, false);
  typed('x'.repeat(501)); assert.equal(page.byId('counter').textContent, '501 / 500'); assert.equal(page.byId('publish').disabled, true);
  typed('   '); assert.equal(page.byId('publish').disabled, true);
  typed(' hello '); assert.equal(page.byId('counter').textContent, '5 / 500');
  await page.byId('publish').listeners.click();
  assert.deepEqual(requests.find(r => r.url === '/api/posts' && r.method === 'POST'), { url: '/api/posts', method: 'POST', body: JSON.stringify({ text: ' hello ' }), csrf: 'token' });
  assert.equal(page.byId('post-text').value, ''); assert.equal(page.byId('status').textContent, 'Published. Everyone can read it now.');
  await mine.children.find(child => child.tagName === 'button').listeners.click();
  assert.deepEqual(requests.find(r => r.url === '/api/posts/delete'), { url: '/api/posts/delete', method: 'POST', body: JSON.stringify({ id: '3' }), csrf: 'token' });
  await page.byId('older').listeners.click();
  assert(requests.some(r => r.url === '/api/posts?before=2'), 'older posts are asked before the last one shown');
});
