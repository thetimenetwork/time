// Website-side login and order verification. No passwords or private signing keys.
import { createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto';
import './time-sdk.js';
import { securityOf, signInRefusal } from './account-security.mjs';
import { createOwnNode, OwnNodeRefusal, OWN_NODE_UNAVAILABLE, OWN_NODE_MISMATCH } from './own-node.mjs';

const sdk = globalThis.TimeSDK;
const keyPrefix = Buffer.from('302a300506032b6570032100', 'hex');
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const fail = message => { throw new Error(message); };
const token = () => randomBytes(32).toString('hex');
function frozen(state, accountId) {
  const cases = state.recovery_cases || []; if (!cases.length) return false;
  const elapsed = BigInt(state.time_micros) - BigInt(state.genesis.genesis_time_micros);
  return cases.some(value => String(value.target) === accountId && value.ready_elapsed_micros != null && BigInt(value.expires_elapsed_micros) >= elapsed);
}

const elapsedOf = state => BigInt(state.time_micros) - BigInt(state.genesis.genesis_time_micros);
// The clock the login rule reads a freeze on: the one of the account security rules (TimeSDK.securityNow). On a
// network whose waits survive a stop that is the chain's time minus the total of its stops, both of which come
// with every verified state; read on the chain's time, a freeze would look over before the chain ends it.
const securityNowOf = state => (state.config === undefined && state.stopped_micros === undefined ? elapsedOf(state) : BigInt(sdk.securityNow(state)));
// What decides a sign-in: the account row and, if the account can have adopted the security
// rules, its security row. Only an account none of whose keys holds both powers can have one;
// for such an account the state is read again with the row (or the proof that there is none).
// A protocol-4 account, which has a key with both powers, costs one read, as before.
async function authority(verifiedState, networkId, accountId, publicKey) {
  const read = async query => {
    const result = await verifiedState(query);
    if (result?.verified !== true || result.state?.network_id !== networkId) fail('Chain authority verification unavailable');
    // A reader that verifies with the installed verifier has already refused a protocol version
    // this build does not implement, with UPGRADE_REQUIRED, and that error passes through here
    // unchanged. A state of a later version from any other reader is refused the same way.
    if (result.state.protocol_version !== undefined) sdk.requireKnownVersion(result.state);
    const account = result.state.accounts.find(value => String(value.id) === accountId);
    return { state: result.state, account: account?.devices.some(device => device.public_key === publicKey) ? account : null };
  };
  const plain = await read({ ids: [accountId] });
  if (!plain.account || plain.account.devices.some(device => device.can_manage && device.can_spend)) return { ...plain, rules: null };
  const full = await read({ ids: [accountId], include_security: true });
  if (!Array.isArray(full.state.security)) fail('Account security state unavailable');
  return { ...full, rules: full.account ? securityOf(full.state, accountId) : null };
}
export function createLoginService({ origin, networkId, verifiedState, now = Date.now, ttlMs = 180000, sessionMs = 3600000 }) {
  if (new URL(origin).origin !== origin || !/^[0-9a-f]{64}$/.test(networkId) || typeof verifiedState !== 'function') fail('Invalid login service configuration');
  const prelogins = new Map(); const sessions = new Map();
  function prune() { const time = now(); for (const [id, value] of prelogins) if (value.challenge.expiresAt <= time) prelogins.delete(id); for (const [id, value] of sessions) if (value.expiresAt <= time) sessions.delete(id); }
  function issue() {
    prune(); if (prelogins.size >= 1000) fail('Too many outstanding login requests');
    const cookie = token(); const issuedAt = now();
    const challenge = { purpose: 'login', origin, networkId, nonce: token(), issuedAt, expiresAt: issuedAt + ttlMs };
    prelogins.set(cookie, { challenge }); return { cookie, challenge };
  }
  async function finish(cookie, proof) {
    prune(); const pending = prelogins.get(cookie); if (!pending) fail('Login challenge expired or already consumed');
    // A challenge is consumed before parsing/verification, including failures.
    prelogins.delete(cookie);
    const message = proof?.message; const challenge = pending.challenge;
    if (!message || Object.keys(message).join(',') !== 'purpose,origin,networkId,accountId,authEpoch,publicKey,nonce,issuedAt,expiresAt') fail('Noncanonical login message');
    for (const field of ['purpose', 'origin', 'networkId', 'nonce', 'issuedAt', 'expiresAt']) if (message[field] !== challenge[field]) fail('Login challenge binding mismatch');
    if (message.purpose !== 'login' || message.origin !== origin || message.networkId !== networkId || message.expiresAt <= now()) fail('Invalid or expired login scope');
    sdk.decimal(message.accountId); sdk.decimal(message.authEpoch); sdk.hexToBytes(message.publicKey, 32); sdk.hexToBytes(proof.signature, 64);
    const { state, account, rules } = await authority(verifiedState, networkId, message.accountId, message.publicKey);
    if (!account || String(account.auth_epoch) !== message.authEpoch) fail('Device authority changed or revoked');
    const refusal = signInRefusal({ account, security: rules, publicKey: message.publicKey, nowElapsedMicros: securityNowOf(state) });
    if (refusal) fail(refusal);
    if (frozen(state, message.accountId)) fail('Account login is frozen by a guardian recovery quorum');
    const publicKey = createPublicKey({ key: Buffer.concat([keyPrefix, Buffer.from(message.publicKey, 'hex')]), format: 'der', type: 'spki' });
    if (!verify(null, sdk.loginBytes(message), publicKey, Buffer.from(proof.signature, 'hex'))) fail('Invalid login signature');
    const id = token(); const session = { accountId: String(account.id), publicKey: message.publicKey, authEpoch: String(account.auth_epoch), name: account.name, csrf: token(), expiresAt: now() + sessionMs };
    sessions.set(id, session); return { cookie: id, session };
  }
  async function current(cookie) {
    prune(); const session = sessions.get(cookie); if (!session) return null;
    const { state, account, rules } = await authority(verifiedState, networkId, session.accountId, session.publicKey);
    if (!account || String(account.auth_epoch) !== session.authEpoch
      || signInRefusal({ account, security: rules, publicKey: session.publicKey, nowElapsedMicros: securityNowOf(state) })
      || frozen(state, session.accountId)) { sessions.delete(cookie); return null; }
    return { session, account, height: String(state.height) };
  }
  function logout(cookie) { sessions.delete(cookie); }
  function checkCsrf(session, csrf) { if (!equal(session.csrf, csrf)) fail('Invalid session CSRF token'); }
  return { issue, finish, current, logout, checkCsrf };
}

// onAlert receives events a person should look at (an own node that contradicts the light
// client); by default they are written to the error log.
export function createOrderService({ networkId, recipient, verifiedReceipt, protocolVersion='4',verifiedState,now = Date.now, initialState, persist, repository, ownNode, onAlert = event => console.error(JSON.stringify(event)) }) {
  if (!repository && typeof persist !== 'function') fail('A durable order persistence callback is required');
  if (typeof onAlert !== 'function') fail('onAlert must be a function');
  if(protocolVersion!=='4'||protocolVersion==='4'&&typeof verifiedState!=='function')fail('V4 orders require a fresh independently verifying account client');
  sdk.decimal(recipient); const orders = new Map(); let queue = Promise.resolve();
  // Optional: the merchant's own full node, a second witness for large orders (own-node.mjs).
  const own = ownNode === undefined ? null : createOwnNode(ownNode);
  if (repository&&initialState?.orders?.length)fail('Import historical orders explicitly before switching merchant stores');
  if (initialState) {
    if (initialState.networkId !== networkId || initialState.recipient !== recipient || !Array.isArray(initialState.orders) || initialState.orders.length > 1000) fail('Invalid persistent merchant order scope');
    const used = new Set();
    for (const order of initialState.orders) {
      // An order records the fee of the network it was issued on: any fee a network can have.
      if (!order || !/^[a-f0-9]{64}$/.test(order.orderId) || orders.has(order.orderId) || order.networkId !== networkId || order.to !== recipient || !sdk.isFee(order.fee) || !Number.isSafeInteger(order.expiresAt) || typeof order.fulfilled !== 'boolean') fail('Invalid persistent merchant order');
      sdk.decimal(order.accountId); sdk.decimal(order.amount); if (BigInt(order.amount) === 0n) fail('Invalid persistent amount');
      if(protocolVersion==='4'){
        sdk.decimal(order.reservedNonce);sdk.decimal(order.expiresElapsedMicros);const quote=sdk.decodeOrderReference(order.orderId);
        if(quote.nonce!==order.reservedNonce||quote.expiresElapsedMicros!==order.expiresElapsedMicros)fail('Persistent order reference differs from its reserved nonce/expiry');
      }
      if (order.fulfilled) { if (!/^[A-F0-9]{64}$/.test(order.hash) || used.has(order.hash)) fail('Invalid/reused persistent receipt'); sdk.decimal(order.height); used.add(order.hash); }
      orders.set(order.orderId, { ...order });
    }
  }
  function locked(operation) { const task = queue.then(operation); queue = task.catch(() => {}); return task; }
  function snapshot(replacement) { const values = [...orders.values()].filter(value => value.orderId !== replacement.orderId); values.push(replacement); return { networkId, recipient, orders: values }; }
  function issue(accountId, amount) { return locked(async () => {
    sdk.decimal(accountId); sdk.decimal(amount); if (BigInt(amount) <= 0n) fail('Payment amount must be positive');
    if (!repository && orders.size >= 1000) fail('Laboratory order limit reached; retain settlement history');
    let reservation={};let orderId=token();let fee;
    if(protocolVersion==='4'){
      const checked=await verifiedState({ids:[accountId]});
      if(checked?.verified!==true||checked.state?.network_id!==networkId||!sdk.sinceFirstVersion(checked.state.protocol_version))fail('Fresh V4 account authority is unavailable');
      // The version in force is the one of the state just verified (`protocolVersion` above is the
      // network's first version and never changes). An order is a promise under rules this build
      // implements: at a later version it issues none and says UPGRADE_REQUIRED, like every
      // program that meets a version it does not know.
      sdk.requireKnownVersion(checked.state);
      // The fee the payer will be charged: the setting of this network, from the state just verified.
      fee=sdk.networkFee(checked.state);
      const account=checked.state.accounts.find(a=>a.id===accountId);if(!account||frozen(checked.state,accountId))fail('Payer account unavailable or frozen');
      const nonce=(BigInt(account.nonce)+1n).toString();sdk.decimal(nonce);
      const expires=(BigInt(checked.state.time_micros)-BigInt(checked.state.genesis.genesis_time_micros)+180000000n).toString();sdk.decimal(expires);
      orderId=sdk.orderReference({nonce,expiresElapsedMicros:expires,randomHex:randomBytes(16).toString('hex')});
      reservation={reservedNonce:nonce,expiresElapsedMicros:expires};
    }
    if (!sdk.isFee(fee)) fail('The network fee is unavailable');
    const order = { orderId, networkId, to: recipient, amount, fee, accountId,...reservation,expiresAt: now() + 180000, fulfilled: false };
    if(repository)await repository.insert(order);else{await persist(snapshot(order));orders.set(order.orderId,order);} return { ...order };
  }); }
  // A payment is checked outside the order queue: the light-client proof and, for a large order,
  // the own node can take seconds, and other orders must not wait for them. Requests for the same
  // order and hash share one check; at most MAX_CHECKS checks run at once, later ones wait their
  // turn. After the own node could not confirm a payment, the same order and hash are refused at
  // once for ownNode.retryAfterMs. Only storing the result is queued, and the order is read again
  // there, so a check that finished late cannot settle an order twice.
  const MAX_CHECKS = 32, checks = new Map(), backoff = new Map(), waiting = []; let running = 0;
  const read = async orderId => repository ? await repository.get(orderId) : orders.get(orderId);
  const usedElsewhere = async (hash, orderId) => repository ? ((await repository.usedHash(hash)) ?? orderId) !== orderId : [...orders.values()].some(value => value.hash === hash && value.orderId !== orderId);
  async function verify(order, hash) {
    if (running >= MAX_CHECKS) await new Promise(resolve => waiting.push(resolve)); else running++;
    try {
      const receipt = await verifiedReceipt(hash);
      if (!receipt?.verified || Number(receipt.code) !== 0 || receipt.networkId !== networkId) fail('Payment is not independently finalized');
      const action = receipt.action;
      if (!action || (action.kind !== 10 && action.kind !== 'merchant_payment') || String(action.from) !== order.accountId || String(action.payload?.to) !== order.to || String(action.payload?.amount) !== order.amount || action.payload?.reference !== order.orderId) fail('Finalized merchant payment does not match exact order reference');
      if(protocolVersion==='4'&&String(action.nonce)!==order.reservedNonce)fail('Finalized merchant payment differs from reserved order nonce');
      // From ownNode.aboveMicros on, the merchant's own full node must also report this payment
      // committed. Its refusal throws here, before the order is settled: it stays unsettled.
      const confirmedBy = ['light-client'];
      if (own?.requiredFor(order.amount)) { await own.confirm({ hash, rawHex: receipt.rawHex, height: String(receipt.height) }); confirmedBy.push('own-node'); }
      return { height: String(receipt.height), confirmedBy };
    } finally { const next = waiting.shift(); if (next) next(); else running--; }
  }
  // The own node contradicted the light client. Reported with the order, the payment and the node,
  // and kept on the order: a later settlement keeps the record too.
  async function noteMismatch(orderId, hash, error) {
    try { onAlert({ event: 'OWN_NODE_MISMATCH', orderId, hash, node: own.endpoint, reason: error.reason }); } catch {}
    try {
      await locked(async () => {
        const order = await read(orderId); if (!order || order.fulfilled) return;
        const noted = { ...order, ownNodeMismatches: [...(order.ownNodeMismatches ?? []).slice(-9), { hash, reason: error.reason, at: now() }] };
        if (repository) { if (typeof repository.note !== 'function') fail('the order store keeps no notes'); await repository.note(noted); } else { await persist(snapshot(noted)); orders.set(orderId, noted); }
      });
    } catch (failure) { try { onAlert({ event: 'OWN_NODE_MISMATCH_NOT_RECORDED', orderId, hash, reason: String(failure?.message ?? failure) }); } catch {} }
  }
  async function fulfill(accountId, orderId, hash) {
    if (typeof hash !== 'string' || !/^[a-f0-9]{64}$/i.test(hash)) fail('Invalid payment transaction hash'); hash = hash.toUpperCase();
    const order = await read(orderId); if (!order || order.accountId !== accountId) fail('Unknown payment order');
    if (order.fulfilled) { if (order.hash !== hash) fail('Order already settled with a different transaction'); return { ...order }; }
    if (await usedElsewhere(hash, orderId)) fail('Transaction already used for another order');
    const key = `${orderId}:${hash}`;
    let check = checks.get(key);
    if (!check) {
      const pause = backoff.get(key); if (pause && performance.now() < pause.until) throw pause.error;
      check = verify(order, hash).catch(async error => {
        if (error instanceof OwnNodeRefusal && error.code === OWN_NODE_UNAVAILABLE && own.retryAfterMs) {
          const time = performance.now(); for (const [k, value] of backoff) if (value.until <= time) backoff.delete(k);
          if (backoff.size >= 4096) backoff.delete(backoff.keys().next().value);
          backoff.set(key, { until: time + own.retryAfterMs, error });
        }
        if (error instanceof OwnNodeRefusal && error.code === OWN_NODE_MISMATCH) await noteMismatch(orderId, hash, error);
        throw error;
      }).finally(() => checks.delete(key));
      checks.set(key, check);
    }
    const { height, confirmedBy } = await check;
    return locked(async () => {
      const current = await read(orderId); if (!current || current.accountId !== accountId) fail('Unknown payment order');
      if (current.fulfilled) { if (current.hash !== hash) fail('Order already settled with a different transaction'); return { ...current }; }
      if (await usedElsewhere(hash, orderId)) fail('Transaction already used for another order');
      const settled = { ...current, fulfilled: true, hash, height, lateReconciliation: now() >= current.expiresAt, confirmedBy: [...confirmedBy] };
      if(repository)await repository.settle(settled);else{await persist(snapshot(settled));orders.set(orderId,settled);} return { ...settled };
    });
  }
  return { issue, fulfill };
}
