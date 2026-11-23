'use strict';
// The demo blog on the gateway's second origin. A person signs in with the Time wallet, writes and deletes posts,
// and can support the blog with a payment that the server verifies before it marks the supporter. Everything a
// person typed reaches the page through textContent only, never as HTML.
const byId = id => document.getElementById(id);
let config; let session;
async function api(path, payload) {
  const response = await fetch(path, { method: payload === undefined ? 'GET' : 'POST', cache: 'no-store', credentials: 'same-origin', redirect: 'error', headers: payload === undefined ? {} : { 'Content-Type': 'application/json', ...(session?.csrf ? { 'X-CSRF-Token': session.csrf } : {}) }, body: payload === undefined ? undefined : JSON.stringify(payload) });
  const result = await response.json(); if (!response.ok || result.error) throw Object.assign(new Error(result.error || 'App request failed'), { code: result.code, status: response.status }); return result;
}
function status(message) { byId('status').textContent = message; }
function seconds(micros) { const value = BigInt(micros), rest = (value % 1000000n).toString().padStart(6, '0').replace(/0+$/, ''); return `${value / 1000000n}${rest ? '.' + rest : ''}`; }
// A paid order the blog cannot confirm yet (its own full node is behind or down, the payment is
// not yet final for its light client, the blog or the network is busy or unreachable) is asked
// again every few seconds for five minutes. The payer is told not to pay again. Every paid order
// and its transaction stay in a list in this browser, with the account that paid, until the blog
// settles it or answers that this payment cannot settle that order; reopening the page, or signing
// in again as that account, finishes them. The list keeps the 20 newest payments, for 7 days.
// Each payment is kept with the network it was made on (`networkId`, the blog's /api/config), and only a page of that
// network finishes it: a test network can be reset under the same address, and a new account there may have the number
// of an old one, whose payments belong to a chain that is gone. A payment kept before the network was noted is finished
// only by a blog that names no network.
const SETTLE_TRIES = 60, SETTLE_PAUSE_MS = 5000, PENDING = 'time-merchant-pending-settlements', KEEP = 20, KEEP_MS = 7 * 86400000;
const networkOf = () => (typeof config?.networkId === 'string' && /^[0-9a-f]{64}$/.test(config.networkId) ? config.networkId : null);
const thisNetwork = value => (value.networkId ?? null) === networkOf();
// Answers that mean the payment itself is wrong for the order: asking again cannot help.
const wrongPayment = error => error.code === 'OWN_NODE_MISMATCH' || /does not match exact order reference|differs from reserved order nonce|already settled with a different transaction|already used for another order|Unknown payment order|Invalid payment transaction hash/.test(error.message);
function keepPending(list) { try { if (list.length) localStorage.setItem(PENDING, JSON.stringify(list)); else localStorage.removeItem(PENDING); } catch {} }
function pendingList() {
  let list; try { list = JSON.parse(localStorage.getItem(PENDING)); } catch { return []; }
  if (!Array.isArray(list)) return [];
  const valid = list.filter(value => typeof value?.orderId === 'string' && typeof value.hash === 'string' && typeof value.accountId === 'string' && Number.isSafeInteger(value.savedAt) && (value.networkId === undefined || typeof value.networkId === 'string'));
  const fresh = valid.filter(value => Date.now() - value.savedAt < KEEP_MS);
  if (fresh.length < valid.length) { for (const value of valid) if (!fresh.includes(value)) console.warn(`Payment ${value.hash} for order ${value.orderId} was saved more than 7 days ago and is no longer confirmed from this page; give the blog's owner this transaction.`); keepPending(fresh); }
  return fresh;
}
const other = (orderId, hash) => value => value.orderId !== orderId || value.hash !== hash;
function addPending(entry) {
  const list = [...pendingList().filter(other(entry.orderId, entry.hash)), entry];
  while (list.length > KEEP) { const dropped = list.shift(); console.warn(`More than ${KEEP} unconfirmed payments in this browser: payment ${dropped.hash} for order ${dropped.orderId} is no longer confirmed from this page; give the blog's owner this transaction.`); }
  keepPending(list);
}
// One settlement loop per payment: a second request for it (signing in again, say) joins the first.
const loops = new Map(), loopKey = (orderId, hash) => `${orderId}:${hash}`;
function settle(orderId, hash, accountId) {
  const key = loopKey(orderId, hash);
  if (!loops.has(key)) loops.set(key, settling(orderId, hash, accountId).finally(() => loops.delete(key)));
  return loops.get(key);
}
async function settling(orderId, hash, accountId) {
  const paid = typeof hash === 'string' ? ` Payment ${hash}: do not pay again; give the blog's owner this transaction.` : '';
  if (paid && pendingList().every(other(orderId, hash))) addPending({ orderId, hash, accountId, savedAt: Date.now(), ...(networkOf() ? { networkId: networkOf() } : {}) });
  // Another account signed in: its answers say nothing about this payment. Kept for later.
  const elsewhere = () => session?.accountId !== accountId;
  const kept = () => new Error(`Payment ${hash} was made from account ${accountId}: sign in as that account to finish confirming it; do not pay again.`);
  for (let attempt = 1; ; attempt++) {
    if (elsewhere()) throw kept();
    try { const result = await api('/api/order/settle', { orderId, hash }); keepPending(pendingList().filter(other(orderId, hash))); return result; }
    catch (error) {
      // The blog may already know the new account while this page does not: ask before deciding.
      if (/Unknown payment order/.test(error.message)) { try { await refresh(); } catch { throw kept(); } }
      if (elsewhere()) throw kept();
      if (wrongPayment(error)) { keepPending(pendingList().filter(other(orderId, hash))); throw new Error(error.message + paid); }
      // Kept: signing in again resumes the settlement.
      if (error.status === 401) throw new Error(`Sign in again to finish confirming payment ${hash}; do not pay again.`);
      if (attempt >= SETTLE_TRIES) throw new Error(`The blog has not confirmed payment ${hash} yet. Do not pay again for this order: reopen this page later to finish, or give the blog's owner this transaction.`);
      status(`Payment sent (transaction ${hash}). Waiting for the blog to confirm it; do not pay again.`);
      await new Promise(resolve => setTimeout(resolve, SETTLE_PAUSE_MS));
    }
  }
}
function fulfilled(settled) { byId('order-result').textContent = `Order fulfilled at height ${settled.height}. Transaction ${settled.hash}`; }
// Pay stays off while a payment or a resumed settlement is in progress.
let busy = 0;
function payButton() { byId('pay').disabled = !session || busy > 0; }
async function working(task) { busy++; payButton(); try { return await task(); } finally { busy--; payButton(); } }
async function resume() {
  const mine = pendingList().filter(value => session && value.accountId === session.accountId && thisNetwork(value) && !loops.has(loopKey(value.orderId, value.hash))); if (!mine.length) return;
  await working(async () => {
    let failure;
    for (const pending of mine) {
      status(`Confirming your earlier payment ${pending.hash}; do not pay again.`);
      try { fulfilled(await settle(pending.orderId, pending.hash, pending.accountId)); } catch (error) { failure = error; }
    }
    try { await refresh(); status(failure ? failure.message : 'Payment finalized and independently verified by this app.'); loadPosts(); } catch (error) { status(error.message); }
  });
}
async function refresh() {
  const result = await api('/api/session'); session = result.accountId ? result : null;
  byId('connection').textContent = session ? 'Signed in' : 'Signed out';
  byId('greeting').textContent = session ? (session.name ? `Hello, @${session.name}` : `Hello, account ${session.accountId}`) : 'Sign in to write a post';
  byId('me-mark').hidden = session?.supporter !== true;
  byId('account-copy').textContent = session ? `Account ${session.accountId} · ${seconds(session.balance)} seconds` : 'Your password stays in your wallet. This website only learns your name.';
  byId('login').classList.toggle('hidden', !!session);
  for (const id of ['pay', 'logout', 'support-copy', 'composer']) byId(id).classList.toggle('hidden', !session);
  payButton(); composerState(); showPosts();
}

// ---- Posts. The server keeps them; the list is public, writing and deleting need a session.
let posts = null, more = false, limits = null, publishing = false;
const element = (tag, className, text) => { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = String(text); return node; };
const when = iso => { const date = new Date(iso); return Number.isNaN(date.getTime()) ? '' : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }); };
// Characters as the server counts them: Unicode code points of the trimmed text.
const length = text => [...String(text).replace(/\r\n/g, '\n').trim()].length;
function composerState() {
  const count = length(byId('post-text').value || ''), max = limits?.maxChars ?? 500;
  byId('counter').textContent = `${count} / ${max}`;
  byId('counter').classList.toggle('over', count > max);
  byId('publish').disabled = !session || publishing || count === 0 || count > max;
}
function postItem(post) {
  const item = element('li', 'post'), head = element('p', 'post-head'), time = element('time', 'soft', when(post.createdAt));
  time.dateTime = String(post.createdAt);
  head.append(element('span', 'author', post.name ? `@${post.name}` : `Account ${post.accountId}`));
  if (post.supporter === true) head.append(' ', element('span', 'mark', 'supporter'));
  head.append(' ', time);
  item.append(head, element('p', 'post-text', post.text));
  if (session && post.accountId === session.accountId) {
    const button = element('button', 'quiet', 'Delete'); button.type = 'button';
    button.addEventListener('click', () => removePost(post, button)); item.append(button);
  }
  return item;
}
function showPosts() {
  if (!posts) return;
  byId('posts').replaceChildren(...posts.map(postItem));
  byId('posts-note').textContent = posts.length ? '' : 'No posts yet. Sign in and write the first one.';
  byId('posts-note').hidden = posts.length > 0;
  byId('older').hidden = !more;
}
async function loadPosts(older = false) {
  const before = older && posts?.length ? posts.at(-1).id : null;
  try {
    const result = await api('/api/posts' + (before ? `?before=${encodeURIComponent(before)}` : ''));
    if (!Array.isArray(result.posts)) throw new Error('the answer holds no list');
    limits = result.limits ?? limits; posts = before ? [...posts, ...result.posts] : result.posts; more = result.more === true;
    showPosts(); composerState();
  } catch (error) { byId('posts-note').hidden = false; byId('posts-note').textContent = `The posts could not be loaded (${error.message}). Press Refresh to try again.`; }
}
async function removePost(post, button) {
  if (!confirm('Delete this post? This cannot be undone.')) return;
  button.disabled = true; status('Deleting the post…');
  try { await api('/api/posts/delete', { id: post.id }); status('Post deleted.'); await loadPosts(); } catch (error) { button.disabled = false; status(error.message); }
}
byId('post-text').addEventListener('input', composerState);
byId('publish').addEventListener('click', async () => {
  publishing = true; composerState(); status('Publishing…');
  try { await api('/api/posts', { text: byId('post-text').value }); byId('post-text').value = ''; status('Published. Everyone can read it now.'); await loadPosts(); }
  catch (error) { if (error.status === 401) { status('Your sign-in has ended: sign in again to publish. Your text is still in the box.'); await refresh().catch(() => {}); } else status(error.message); }
  finally { publishing = false; composerState(); }
});
byId('reload').addEventListener('click', () => loadPosts());
byId('older').addEventListener('click', () => loadPosts(true));

byId('login').addEventListener('click', async () => {
  byId('login').disabled = true; status('Requesting account approval…');
  try { const request = api('/api/login/challenge', {}).then(challenge => ({ type: 'login', challenge })); const proof = await TimeSDK.requestWallet({ walletOrigin: config.walletOrigin, request }); await api('/api/login/finish', proof); await refresh(); status('Signed in. Your password stayed in your wallet.'); await resume(); } catch (error) { status(error.message); } finally { byId('login').disabled = false; }
});
byId('logout').addEventListener('click', async () => { try { await api('/api/logout', {}); await refresh(); status('Signed out.'); } catch (error) { status(error.message); } });
byId('pay').addEventListener('click', () => working(async () => {
  status('Preparing an exact payment request…'); const accountId = session?.accountId;
  try { let order; const request = api('/api/order', { item: 'test-purchase' }).then(value => { order = value; return { type: 'payment', networkId: order.networkId, to: order.to, amount: order.amount, fee: order.fee, orderId: order.orderId, description: 'Support the Time blog (demo)', expiresAt: order.expiresAt }; }); const result = await TimeSDK.requestWallet({ walletOrigin: config.walletOrigin, request }); fulfilled(await settle(order.orderId, result.transactionHash || result.receipt?.hash, accountId)); await refresh(); status('Payment finalized and independently verified by this app.'); loadPosts(); } catch (error) { status(error.message); }
}));
(async () => {
  loadPosts();
  try {
    config = await api('/api/config'); byId('wallet-link').href = config.walletOrigin;
    // The price is the server's (its catalog); the button says it.
    const price = config.catalog?.['test-purchase']; if (typeof price === 'string' && /^[1-9][0-9]{0,19}$/.test(price)) byId('pay').textContent = `Support this blog: ${seconds(price)} seconds`;
    await refresh(); await resume();
  } catch (error) { status(error.message); }
})();
