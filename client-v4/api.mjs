// The public HTTP API of a Time network: look up blocks, actions and accounts, detect deposits,
// submit signed actions, follow new blocks and payments. JSON under /v1/, usable from any
// language without the JavaScript SDK. It is also the data source of an explorer.
//
// Where each answer comes from, and what it is worth:
//
// - Blocks, actions, activity, payments and totals come from the index (indexer.mjs). The
//   indexer accepts only blocks tied to a header its light client verified, but a caller has no
//   way to see that: to the caller these answers are this server's word. Each says so
//   (`"source": "index", "proven": false`) and carries what the caller needs to check it with
//   the SDK: the action's hash, its block, its bytes and the Merkle proof that ties the bytes to
//   the block's header.
// - The state of an account is read through the SDK's verifying client, with a proof against
//   validator signatures. This server checks the proof and passes it on (`"source":
//   "state_proof"`), so the caller can check it again with its own trust anchor.
// - Submitting passes a signed action to the node. Nothing here holds a key or signs.
//
// What callers can send is small and checked: every path and query parameter has one accepted
// form, unknown parameters are refused (a misspelled filter must not quietly return everything),
// pages are bounded, all SQL is prepared, and no address a caller names is ever fetched.
import http from 'node:http';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { AsyncLocalStorage } from 'node:async_hooks';
import './time-sdk.js';
import { fetchCertifiedView, fetchLightBlock } from './certified-view.mjs';
import { webhookAdapter, checkWebhookURL, withTimeout } from './security-watch-service.mjs';
import { openIndex, createIndexer, paymentEvent, encodeCursor, decodeCursor, plainText, IndexerError, KIND_NAMES, MAX_ACTION_BYTES } from './indexer.mjs';

const SDK = globalThis.TimeSDK;
const MAX_U64 = 18446744073709551615n;
export const MAX_PAGE = 200;
export const DEFAULT_PAGE = 50;
export const MAX_BODY_BYTES = 768 * 1024;
const MAX_URL_LENGTH = 2048;
/// How much of the past a reconnecting stream is sent again before it is told to use the lists:
/// so many blocks, and so many payments read from the index. One request never reads more.
export const REPLAY_BLOCKS = 256, REPLAY_PAYMENTS = 2000;
/// How many actions of an account beyond its proven nonce an account answer looks for in the index.
export const NEWER_ACTIONS = 16;
const STREAM_BUFFER_BYTES = 1024 * 1024;
const OPENAPI = readFileSync(new URL('./api/openapi.json', import.meta.url), 'utf8');

// ------------------------------------------------------------------ the explorer's files
/// The explorer (web-v4/explorer) and the SDK and verifier files it loads: the address each is
/// served under, the file it is, and its type. This list is all there is: a request is answered
/// by looking its path up here, so nothing a caller sends ever names a file.
export const EXPLORER_PREFIX = '/explorer/';
export const EXPLORER_FILES = Object.freeze([
  ['', '../web-v4/explorer/index.html', 'text/html; charset=utf-8'],
  ['index.html', '../web-v4/explorer/index.html', 'text/html; charset=utf-8'],
  ['styles.css', '../web-v4/explorer/styles.css', 'text/css; charset=utf-8'],
  ...['app.js', 'strings.mjs', 'format.mjs', 'route.mjs', 'describe.mjs', 'client.mjs', 'check.mjs', 'dom.mjs', 'views.mjs'].map((name) => [name, `../web-v4/explorer/${name}`, 'text/javascript; charset=utf-8']),
  ...['time-sdk.js', 'proof-verifier.mjs', 'light-client.mjs'].map((name) => [`sdk/${name}`, `./${name}`, 'text/javascript; charset=utf-8']),
  ['web-v4/shared/verifier/timecurrency_verifier_v4.js', '../web-v4/shared/verifier/timecurrency_verifier_v4.js', 'text/javascript; charset=utf-8'],
  ['web-v4/shared/verifier/timecurrency_verifier_v4_bg.wasm', '../web-v4/shared/verifier/timecurrency_verifier_v4_bg.wasm', 'application/wasm'],
  // The menu of the public networks that every page of the project carries (web-v4/shared/network-menu.js).
  ['web-v4/shared/network-menu.js', '../web-v4/shared/network-menu.js', 'text/javascript; charset=utf-8'],
  ['web-v4/shared/network-menu.css', '../web-v4/shared/network-menu.css', 'text/css; charset=utf-8'],
].map(Object.freeze));
/// What the explorer's pages may do, as the wallet gateway says it for the wallet: scripts and
/// styles from this origin only, WebAssembly for the verifier, requests to this origin only.
export const EXPLORER_CSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
/// Reads the files once, at start: no request ever reaches the file system. Each gets a
/// validator (the hash of its bytes), so that a browser that has the file asks only whether it
/// changed.
/// `base` is where this file is (for tests: another place, where files are missing).
export function loadExplorerFiles(base = import.meta.url) {
  return new Map(EXPLORER_FILES.map(([name, location, type]) => {
    let body;
    try { body = readFileSync(new URL(location, base)); } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      // The service itself needs none of these files; an installation without them is a complete one until
      // serve_explorer is turned on. The file is named as the README names it, not by where this machine holds it.
      throw new Error(`serve_explorer is on, but a file of the explorer is not installed with this service: ${location.replace(/^\.\.\//, '').replace(/^\.\//, 'client-v4/')}. The explorer needs web-v4/explorer/, and client-v4/ and web-v4/shared/verifier/ as the service does (deploy/api/README.md, "Running it"): install it, or turn serve_explorer off`);
    }
    return [EXPLORER_PREFIX + name, { type, body, etag: `"${createHash('sha256').update(body).digest('hex').slice(0, 32)}"`,
      // The page and its modules are asked about every time ("not changed" costs no bytes), so
      // that files of two releases never run together. Only the compiled verifier, which the
      // page loads late and which is a megabyte, is kept for a few minutes.
      cache: type === 'application/wasm' ? `max-age=${EXPLORER_MAX_AGE_SECONDS}` : 'no-cache',
      cost: Math.max(EXPLORER_FILE_COST, body.length / EXPLORER_BYTES_PER_TOKEN) }];
  }));
}
/// What a request for a file of the explorer takes from the caller's rate-limit bucket.
/// - A small file, and a "not changed" answer, take a tenth: a page is a dozen files, and loading
///   it must not use up what its reader needs for the API.
/// - A larger file takes more, by its size: the compiled verifier is a megabyte, and costs
///   several requests' worth.
/// - The trust manifest (it reads the database) and a path that names no file take as much as an
///   API request.
export const EXPLORER_FILE_COST = 0.1, EXPLORER_BYTES_PER_TOKEN = 256 * 1024, EXPLORER_MAX_AGE_SECONDS = 300;
/// Where the explorer finds this network's facts for "Run a validator" (the explorer_join setting).
export const EXPLORER_JOIN_PATH = `${EXPLORER_PREFIX}join.json`;
/// An https address with a plain host (lower-case labels, the last one starting with a letter, so that it is
/// never read as a number address) and an optional port; with the join script's path, or nothing after it.
/// The explorer holds a link to such an address to the same rule (web-v4/explorer/format.mjs, outsideAddress).
const JOIN_ADDRESS = /^https:\/\/((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)(?::([1-9][0-9]{0,4}))?(\/join\/join\.sh)?$/;
function joinAddress(value, script) {
  const match = typeof value === 'string' && value.length <= 300 ? JOIN_ADDRESS.exec(value) : null;
  if (!match || match[1].length > 253 || Boolean(match[3]) !== script || (match[2] !== undefined && (Number(match[2]) > 65535 || match[2] === '443'))) return false;
  try { const url = new URL(value); return !url.username && !url.password && (script ? url.href === value : url.origin === value && url.href === `${value}/`); } catch { return false; }
}
const JOIN_PEER = /^[0-9a-f]{40}@(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]):([1-9][0-9]{0,4})$/;
const JOIN_KEYS = ['script_url', 'wallet_url', 'chain_id', 'min_self_bond_micros', 'files', 'peers'], JOIN_FILES = ['node_sha256', 'cometbft_sha256', 'genesis_sha256'];
/// Checks this network's facts for the explorer's "Run a validator" (the explorer_join setting) and returns a
/// frozen copy of them, in a fixed order. `chainId` is the chain id of the trust manifest: the facts must be of
/// the network this service answers for. Throws with a sentence on anything else, and never quotes a value.
export function checkExplorerJoin(value, chainId) {
  const record = (item) => item !== null && typeof item === 'object' && !Array.isArray(item);
  if (!record(value)) throw new Error('explorer_join is an object: script_url, wallet_url, chain_id, min_self_bond_micros, files, peers and, if wanted, pace');
  if (Object.keys(value).some((key) => !JOIN_KEYS.includes(key) && key !== 'pace')) throw new Error('explorer_join takes script_url, wallet_url, chain_id, min_self_bond_micros, files, peers and pace, nothing else');
  if (JOIN_KEYS.some((key) => !Object.hasOwn(value, key))) throw new Error('explorer_join needs script_url, wallet_url, chain_id, min_self_bond_micros, files and peers');
  const { script_url: script, wallet_url: wallet, chain_id: chain, min_self_bond_micros: bond, files, peers, pace } = value;
  if (!joinAddress(script, true)) throw new Error('explorer_join.script_url is the https:// address of the join script: a plain host name in lower case, a port if needed, and the path /join/join.sh, nothing else');
  if (!joinAddress(wallet, false)) throw new Error('explorer_join.wallet_url is the https:// origin of the wallet: a plain host name in lower case and a port if needed, with no path, not even "/"');
  if (typeof chain !== 'string' || !/^[a-z0-9-]{3,64}$/.test(chain)) throw new Error('explorer_join.chain_id is 3 to 64 of a-z, 0-9 and -');
  if (chain !== chainId) throw new Error('explorer_join.chain_id is not the chain id of trust: the facts must be of the network this service answers for');
  if (typeof bond !== 'string' || !/^[1-9][0-9]{0,15}$/.test(bond) || BigInt(bond) > 1000000000000000n) throw new Error('explorer_join.min_self_bond_micros is the smallest bond in microseconds, a decimal string from "1" to "1000000000000000"');
  if (!record(files) || Object.keys(files).length !== JOIN_FILES.length || !JOIN_FILES.every((key) => Object.hasOwn(files, key) && typeof files[key] === 'string' && /^[0-9a-f]{64}$/.test(files[key]))) throw new Error('explorer_join.files holds node_sha256, cometbft_sha256 and genesis_sha256, each 64 of 0-9 and a-f, nothing else');
  if (!Array.isArray(peers) || peers.length < 1 || peers.length > 8 || !peers.every((peer) => { const match = typeof peer === 'string' ? JOIN_PEER.exec(peer) : null; return match !== null && Number(match[1]) <= 65535; }) || new Set(peers).size !== peers.length)
    throw new Error('explorer_join.peers lists 1 to 8 entry nodes, none twice, each as node id (40 of 0-9 and a-f), "@", an IPv4 address and ":port"');
  if (pace !== undefined && (typeof pace !== 'string' || !/^(?:[1-9][0-9]{2}ms|[1-5]s)$/.test(pace))) throw new Error('explorer_join.pace is "100ms" to "999ms", or "1s" to "5s"');
  return Object.freeze({ script_url: script, wallet_url: wallet, chain_id: chain, min_self_bond_micros: bond,
    files: Object.freeze(Object.fromEntries(JOIN_FILES.map((key) => [key, files[key]]))), peers: Object.freeze([...peers]), ...(pace === undefined ? {} : { pace }) });
}
/// How long a proof read for one of the explorer's routes answers further identical requests.
export const STATE_SHARE_MS = 1000;
/// The clock the moments of a security row are on, read from the same verified state as the row. On a network whose
/// waits survive a stop (`waits_survive_stops` in its genesis) the row holds moments on the clock of the waits: the
/// chain's time since genesis less the total of its stops (`stopped_micros`, in the metadata row of every state).
/// Compared with the time of the state they come too early by that total. On any other network the clock is the
/// chain's time, as it always was. Null when the state does not carry what the clock is read from (no genesis time,
/// or a setting in a form the engine does not write), never a guess.
export function securityClockOf(state) {
  try {
    return { waits_survive_stops: SDK.waitsSurviveStops(state), stopped_micros: SDK.stoppedMicros(state), now_elapsed_micros: SDK.securityNow(state) };
  } catch { return null; }
}

// ------------------------------------------------------------------ parameters
/// An answer that is an error: `code` is stable and for programs, `message` is for people.
export class ApiError extends Error {
  constructor(status, code, message, extra = {}) { super(message); this.status = status; this.code = code; this.extra = extra; }
}
const bad = (code, message) => { throw new ApiError(400, code, message); };
/// Each parameter has one accepted spelling; `parse` returns its value or throws.
const PARAMETERS = {
  height: (text) => (/^[1-9][0-9]{0,15}$/.test(text) && Number(text) <= Number.MAX_SAFE_INTEGER ? Number(text) : bad('invalid_height', 'A height is a whole number from 1, without leading zeros')),
  hash: (text) => (/^[0-9A-Fa-f]{64}$/.test(text) ? text.toUpperCase() : bad('invalid_hash', 'A hash is 64 hexadecimal characters')),
  account: (text) => (/^(0|[1-9][0-9]{0,19})$/.test(text) && BigInt(text) < MAX_U64 ? text : bad('invalid_account', 'An account is its number in decimal, without leading zeros')),
  limit: (text) => (/^([1-9][0-9]?|1[0-9]{2}|200)$/.test(text) ? Number(text) : bad('invalid_limit', `limit is a whole number from 1 to ${MAX_PAGE}`)),
  order: (text) => (text === 'asc' || text === 'desc' ? text : bad('invalid_order', 'order is asc or desc')),
  cursor: (text) => decodeCursor(text) ?? bad('invalid_cursor', 'cursor is a next_cursor value of an earlier answer'),
  reference: (text) => (/^[0-9a-f]{64}$/.test(text) ? text : bad('invalid_reference', 'A reference is 64 lower-case hexadecimal characters')),
  /// Where a stream resumes: the id of the last event received, "<height>" or "<height>.<index>".
  position: (text) => {
    const match = /^([1-9][0-9]{0,15})(?:\.(0|[1-9][0-9]{0,5}))?$/.exec(text);
    return match ? { height: Math.min(Number(match[1]), Number.MAX_SAFE_INTEGER), index: match[2] === undefined ? null : Number(match[2]) } : bad('invalid_position', 'after is the id of the last event received');
  },
  direction: (text) => (['in', 'out', 'both'].includes(text) ? text : bad('invalid_direction', 'direction is in, out or both')),
};
/// An account in a path: its number, or its name (2 to 15 of a-z, 0-9 and _). Digits alone are
/// a number, as in the SDK; a leading @ makes any accepted text a name.
function accountOrName(text) {
  if (/^(0|[1-9][0-9]{0,19})$/.test(text) && BigInt(text) < MAX_U64) return { id: text };
  const name = text.startsWith('@') ? text.slice(1) : text;
  if (/^[a-z0-9_]{2,15}$/.test(name)) return { name };
  return bad('invalid_account', 'An account is its number, or its name of 2 to 15 lower-case letters, digits and underscores');
}

// ------------------------------------------------------------------ clients and limits
/// An IP address in one spelling: IPv4 as it is, IPv6 as its eight groups. Null if the text is
/// neither. A port ("203.0.113.9:1234", "[2001:db8::1]:1234"), a zone and the IPv4-in-IPv6 form
/// are removed first, since proxies write all of these.
export function normalIp(address) {
  let text = String(address ?? '').trim();
  const bracketed = /^\[([^\]]+)\](?::\d{1,5})?$/.exec(text);
  if (bracketed) text = bracketed[1];
  else if (/^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$/.test(text)) text = text.slice(0, text.lastIndexOf(':'));
  text = text.split('%')[0];
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(text);
  if (mapped) text = mapped[1];
  if (net.isIPv4(text)) return text;
  if (!net.isIPv6(text) || text.includes('.')) return null;
  const [head, tail] = text.split('::');
  const left = head ? head.split(':') : [], right = tail ? tail.split(':') : [];
  const groups = text.includes('::') ? [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill('0'), ...right] : left;
  return groups.map((group) => parseInt(group, 16).toString(16)).join(':');
}
/// The key a client is limited under: its IPv4 address, or its IPv6 /64 (one subscriber).
export function clientKey(address) {
  const ip = normalIp(address);
  if (ip === null) return 'unknown';
  return ip.includes(':') ? `${ip.split(':').slice(0, 4).join(':')}::/64` : ip;
}
/// Who holds a stream, for counting: the IPv4 address, or the IPv6 /56 of the client's /64.
export function holderKey(client) {
  const match = /^([0-9a-f]+):([0-9a-f]+):([0-9a-f]+):([0-9a-f]+)::\/64$/.exec(client);
  return match ? `${match[1]}:${match[2]}:${match[3]}:${(parseInt(match[4], 16) & 0xff00).toString(16)}::/56` : client;
}
/// A stream is not put out for another reader before it has been open this long.
export const STREAM_MIN_AGE_MS = 5000;
/// A token bucket per client: `burst` requests at once, refilled at `perSecond`. The table is
/// bounded: clients whose bucket is full again are forgotten, then the oldest.
export function createRateLimiter({ perSecond = 20, burst = 60, maxClients = 10000, now = Date.now } = {}) {
  const buckets = new Map();
  return {
    /// Takes `cost` tokens. Returns 0 if allowed, or the seconds to wait.
    take(client, cost = 1) {
      const at = now();
      let bucket = buckets.get(client);
      if (!bucket) {
        if (buckets.size >= maxClients) {
          for (const [key, b] of buckets) if (b.tokens + (Math.max(0, at - b.at) / 1000) * perSecond >= burst) buckets.delete(key);
          for (const key of buckets.keys()) { if (buckets.size < maxClients) break; buckets.delete(key); }
        }
        bucket = { tokens: burst, at };
      } else buckets.delete(client); // re-inserted below, so the table stays in order of last use
      // A clock that was set back must not empty the bucket: the time passed is never negative.
      bucket.tokens = Math.min(burst, bucket.tokens + (Math.max(0, at - bucket.at) / 1000) * perSecond); bucket.at = at;
      buckets.set(client, bucket);
      if (bucket.tokens >= cost) { bucket.tokens -= cost; return 0; }
      return Math.max(1, Math.ceil((cost - bucket.tokens) / perSecond));
    },
    size: () => buckets.size,
  };
}

// ------------------------------------------------------------------ verified state
/// Reads state through the SDK's verifying client, over a CometBFT RPC instead of a wallet
/// gateway: the three gateway routes the client asks for are answered here with the gateway's
/// own functions. The client verifies each answer with its light client and the installed
/// verifier, exactly as a wallet does. Returns the SDK's result and the proof it verified, so a
/// caller of the API can verify it again.
export function createStateReader({ rpc, trust, verifier, storage }) {
  const call = new AsyncLocalStorage();
  const answer = (body) => new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  const fetcher = async (url) => {
    const { pathname, searchParams } = new URL(url);
    if (pathname === '/api/network') return answer({ networkId: trust.network_id, chainId: trust.chain_id, protocolVersion: '4' });
    if (pathname === '/api/light-block') return answer(await fetchLightBlock({ rpc, height: searchParams.get('height') || undefined }));
    if (pathname === '/api/view-proof') {
      const proof = await fetchCertifiedView({ rpc, selection: JSON.parse(searchParams.get('query')) });
      const held = call.getStore();
      if (held) held.proof = proof; // the last one fetched is the one the client verified
      return answer(proof);
    }
    return new Response('{"error":"Unknown route"}', { status: 404, headers: { 'content-type': 'application/json' } });
  };
  // The address is never contacted: every request of this client goes through `fetcher`.
  const client = SDK.createClient({ gateway: 'http://127.0.0.1/', trust, verifier, checkpointStorage: storage, fetcher });
  return async (selection) => {
    const held = {};
    const result = await call.run(held, () => client.getVerifiedState(selection));
    return { ...result, proof: held.proof };
  };
}

// ------------------------------------------------------------------ webhooks
/// The id of a webhook target names its account and its URL, as the watch's does: a queue kept
/// under it can only ever go to that URL for that account.
export function webhookTargetId(account, url) {
  return `webhook-${createHash('sha256').update(JSON.stringify([[String(account)], url])).digest('hex').slice(0, 24)}`;
}
/// Delivers the queued payment events of each target with the watch service's signed webhook
/// (`webhookAdapter`: same headers, same signature, same retry rules). Each target has its own
/// queue in the index file and its own pump, so a dead receiver delays only its own events.
/// - A failure is retried after a pause that doubles from `baseMs` to `maxMs`.
/// - 410 Gone moves the event to the dead letters. Any other refusal keeps it queued.
/// - Delivery is at least once: receivers drop an event id they have seen.
/// - A target is told of payments from the height the chain had when it was first configured
///   (the store keeps it): never of the history before, always of what came after, also when a
///   block is indexed long after it was made. What is left out is counted (`skipped_history`).
function createWebhookDispatcher({ store, webhooks, fetcher, log, baseMs = 2000, maxMs = 300000, maxQueue = 100000, maxDead = 1000, attemptDelayMs }) {
  const stopper = new AbortController();
  const targets = webhooks.map((hook) => ({
    id: webhookTargetId(hook.account, hook.url), account: hook.account,
    adapter: webhookAdapter({ url: hook.url, secret: hook.secret, ...(fetcher ? { fetcher } : {}), ...(attemptDelayMs === undefined ? {} : { baseDelayMs: attemptDelayMs }) }),
    running: null, failing: false, refusing: false, wake: null,
  }));
  const byAccount = new Map();
  for (const target of targets) byAccount.set(target.account, [...(byAccount.get(target.account) || []), target.id]);
  // Queues of targets that are no longer configured go: they must never reach another receiver.
  const configured = new Set(targets.map((t) => t.id));
  for (const id of store.webhooks.list()) if (!configured.has(id)) store.webhooks.forget(id); // configured again later, it is a new target
  for (const id of configured) store.webhooks.register(id);
  for (const id of store.outbox.targets()) if (!configured.has(id)) { const dropped = store.outbox.dropTarget(id); log('warn', 'queue of a webhook that is no longer configured was removed', { events: Number(dropped) }); }

  async function pump(target) {
    let pause = baseMs;
    while (!stopper.signal.aborted) {
      const row = store.outbox.next(target.id);
      if (!row) return;
      try {
        await target.adapter.deliver(JSON.parse(row.body), { first: row.attempts === 0, signal: stopper.signal });
        store.outbox.done(row.seq);
        if (target.failing) log('info', 'a webhook receiver accepts events again', { target: target.id, origin: target.adapter.origin });
        target.failing = false; target.refusing = false; pause = baseMs;
      } catch (error) {
        if (stopper.signal.aborted) return;
        if (error?.permanent) { store.outbox.dead(row.seq); log('error', 'webhook receiver answered 410: event kept in dead letters', { target: target.id, origin: target.adapter.origin, event: row.event_id }); continue; }
        store.outbox.tried(row.seq);
        // The adapter's message names the origin only, never the path or query of the URL.
        if (!target.failing) log('warn', 'webhook delivery failed; it is retried', { target: target.id, origin: target.adapter.origin, event: row.event_id, error: plainText(error?.message, 120) });
        target.failing = true; target.refusing = Boolean(error?.refused);
        await new Promise((resolve) => { const timer = setTimeout(resolve, pause); timer.unref?.(); target.wake = () => { clearTimeout(timer); resolve(); }; stopper.signal.addEventListener('abort', target.wake, { once: true }); });
        pause = Math.min(maxMs, pause * 2);
      }
    }
  }
  const kick = () => {
    for (const target of targets) {
      const dropped = store.outbox.trim(target.id, maxQueue, maxDead);
      if (dropped) log('error', 'webhook queue full: oldest events dropped', { target: target.id, dropped });
      target.running ??= pump(target).catch((error) => log('error', 'webhook pump crashed', { target: target.id, error: plainText(error?.message, 120) })).finally(() => {
        target.running = null;
        // An event queued just as the pump found its queue empty still goes out now.
        if (!stopper.signal.aborted && store.outbox.next(target.id)) kick();
      });
    }
  };
  return {
    targetsOf: (account) => byAccount.get(account) || [],
    kick,
    async stop() { stopper.abort(); await Promise.allSettled(targets.map((t) => t.running)); },
    /// Counts only: no account, no URL.
    status() {
      let queued = 0, dead = 0;
      for (const row of store.outbox.counts()) { if (row.dead) dead += row.count; else queued += row.count; }
      const told = store.webhooks.totals();
      return { targets: targets.length, queued, dead_letters: dead, failing_targets: targets.filter((t) => t.failing).length, refusing_targets: targets.filter((t) => t.refusing).length,
        // Payments left out because their block is older than the target, and targets whose start is not known yet.
        skipped_history: told.skipped, awaiting_start: told.waiting };
    },
    /// Waits until every queue is empty or its pump is pausing (for tests).
    async settled() { for (let i = 0; i < 200 && targets.some((t) => t.running && !t.failing); i++) await new Promise((resolve) => setTimeout(resolve, 10)); },
  };
}

// ------------------------------------------------------------------ the service
const blockView = (row) => ({
  height: String(row.height), hash: row.hash.toUpperCase(), previous_hash: row.previous_hash.toUpperCase(), time: row.time, time_micros: String(row.time_micros),
  proposer: row.proposer, app_hash: row.app_hash, data_hash: row.data_hash, tx_count: row.tx_count, payment_count: row.payment_count, results_checked: row.results_checked === 1,
});

/// Starts the indexer and the HTTP server. Options (see deploy/api/README.md for the config file):
/// - `trust`, `rpc`, `verifier`, `dataFile` (the SQLite file), `startHeight`;
/// - `host`, `port`, `hosts` (extra Host values answered), `corsOrigins` (exact origins, or ['*']);
/// - `rateLimit` { perSecond, burst }, `trustedProxies` (addresses whose X-Forwarded-For is believed);
/// - `webhooks` [{ account, url, secret }];
/// - `maxLagSeconds`, `stateTimeoutMs`, `stateRefreshMs` (how often the state reader's light client is moved on);
/// - `maxStreams`, `maxStreamsPerClient`, `maxStreamSeconds` (a stream is closed after this long and the reader
///   reconnects), `reservedStreamClients` (addresses that always get a stream);
/// - `explorer`: true serves the explorer's pages under /explorer/ (see EXPLORER_FILES);
/// - `explorerJoin`: with `explorer`, this network's facts for the explorer's "Run a validator", served as
///   /explorer/join.json (see checkExplorerJoin); null serves none;
/// - for tests: `readState`, `webhookFetcher`, `webhookTiming` { retryMs, attemptDelayMs }, `now`, `log`, `pollMs`, `autoStart`.
export async function createApiService({
  trust, rpc, verifier, dataFile, startHeight = 1, host = '127.0.0.1', port = 8930, hosts = [], corsOrigins = [], rateLimit = {}, trustedProxies = [],
  webhooks = [], webhookTiming = {}, maxLagSeconds = 120, maxStreams = 100, maxStreamsPerClient = 5, maxStreamSeconds = 900, reservedStreamClients = [],
  stateTimeoutMs = 15000, stateRefreshMs = 3600000, explorer = false, explorerJoin = null, readState, webhookFetcher, now = Date.now, log = () => {}, pollMs = 500, autoStart = true,
}) {
  if (String(trust?.app_version) !== '4' || !/^[0-9a-f]{64}$/.test(trust?.network_id ?? '') || typeof trust?.chain_id !== 'string') throw new Error('trust is the application-4 trust manifest the SDK takes');
  for (const hook of webhooks) { checkWebhookURL(hook.url); PARAMETERS.account(hook.account); }
  if (explorerJoin !== null && explorer !== true) throw new Error('explorer_join is shown by the explorer this service serves: it needs serve_explorer');
  // Checked again here as the setting is checked, and turned into its answer once: the same bytes for every request.
  const joinBody = explorerJoin === null ? null : JSON.stringify(checkExplorerJoin(explorerJoin, trust.chain_id));
  const store = openIndex({ filename: dataFile, networkId: trust.network_id, chainId: trust.chain_id, startHeight });
  const limiter = createRateLimiter({ ...rateLimit, now });
  const proxies = new Set(trustedProxies.map(normalIp).filter(Boolean));
  const reserved = new Set(reservedStreamClients.map(clientKey));
  // A proxy's own address must not be reserved: every request the proxy passes on without naming
  // its client would then count as the reserved one.
  for (const proxy of proxies) if (reserved.has(clientKey(proxy))) throw new Error('An address cannot be both a trusted proxy and a reserved stream client');
  const origins = new Set(corsOrigins);
  // Browsers and curl leave the port out of Host on 80 and 443, so a name is compared without it.
  const hostName = (value) => String(value || '').toLowerCase().replace(/:(?:80|443)$/, '');
  const ownHosts = new Set(hosts.map(hostName));
  const streams = new Set();
  let explorerFiles;
  try { explorerFiles = explorer ? loadExplorerFiles() : null; } catch (error) { store.close(); throw error; }
  let server, indexer, dispatcher, feeMicros = null, noAuction = null, feeAsked = 0, stateReads = 0, heartbeat = null, stateRefresh = null, closing = null;
  const startedAt = now();

  try {
    dispatcher = createWebhookDispatcher({ store, webhooks, fetcher: webhookFetcher, log, ...(webhookTiming.retryMs ? { baseMs: webhookTiming.retryMs } : {}), attemptDelayMs: webhookTiming.attemptDelayMs });
    indexer = createIndexer({ rpc, trust, store, verifier, now, log, pollMs, webhookTargets: dispatcher.targetsOf, onBlock: (event) => { publish(event); dispatcher.kick(); } });
    readState ??= createStateReader({ rpc, trust, verifier, storage: store.checkpointStorage('state') });
  } catch (error) { store.close(); throw error; }

  // ---- what every answer from the index carries
  const indexNote = () => {
    const s = indexer.status();
    return { network_id: store.networkId, chain_id: store.chainId, start_height: String(s.start_height), indexed_height: s.indexed_height === null ? null : String(s.indexed_height), indexed_block_time: s.indexed_block_time, seconds_behind: s.seconds_behind };
  };
  const fromIndex = (body) => ({ source: 'index', proven: false, ...body, index: indexNote() });
  const feeOf = (rule) => (rule === 'none' ? '0' : rule === 'network_fee' ? feeMicros : null);
  const actionView = (row) => ({
    hash: row.hash, height: String(row.height), index: row.idx, time: row.time, kind: row.kind, kind_name: row.kind === null ? null : KIND_NAMES[row.kind] ?? null, opaque: row.opaque === 1,
    sender: row.sender, nonce: row.nonce, recipient: row.recipient, amount: row.amount, reference: row.reference, transfers: row.transfers === 1,
    fee_rule: row.fee_rule, fee_micros: feeOf(row.fee_rule), results_checked: row.results_checked === 1,
    // A completed payment above the limit names the request it completes, if the index could tie
    // the two; if it could not, the action moved a payment the index cannot attribute.
    request_hash: row.request_hash ?? null, request_status: row.request_status ?? null, unattributed: row.kind === 75 && row.opaque !== 1 && row.recipient === null,
    ...(row.role ? { role: row.role } : {}),
  });
  /// A page in chain order. One row more than asked tells whether there are more.
  function page(rows, limit, given, cursorOf) {
    const items = rows.slice(0, limit);
    return { has_more: rows.length > limit, next_cursor: items.length ? cursorOf(items.at(-1)) : given, items };
  }
  const startOf = (order) => (order === 'asc' ? { height: 0, index: 0 } : { height: Number.MAX_SAFE_INTEGER, index: 0 });
  /// A cursor names a place in the chain, and this index starts at `start_height`. A cursor below it comes
  /// from an index that started earlier (this one was rebuilt with a later start, or is another one). What lies
  /// between the cursor and the start is not here, and an answer that simply began at the start would skip it
  /// without a word: a deposit reader would never see those payments. So such a cursor is refused, and the
  /// refusal says where this index starts. `lowest` is the lowest height a cursor may name.
  function cursorWithinIndex(height, lowest = store.startHeight) {
    if (height === undefined || height === null || height >= lowest) return;
    throw new ApiError(409, 'cursor_below_index_start', `This index starts at height ${store.startHeight} and the cursor is at height ${height}. What the chain holds between the two is not in this index: read it from an index that holds those heights, then go on here without a cursor (the list then begins at height ${store.startHeight})`, { body: { index: indexNote() } });
  }

  // ---- verified state
  /// One verified read, bounded in time and in how many run at once.
  async function verifiedState(selection) {
    if (stateReads >= 8) throw new ApiError(503, 'busy', 'Too many state proofs are being read; try again shortly', { retryAfter: 1 });
    stateReads += 1;
    try {
      const result = await withTimeout(readState(selection), stateTimeoutMs, undefined, 'node');
      if (result?.verified !== true || result.state?.network_id !== store.networkId) throw new Error('The state was not verified');
      try { feeMicros = SDK.networkFee(result.state); } catch { /* a state without the setting row: leave the fee unknown */ }
      // Whether the network has a bitcoin auction is a setting of its genesis too.
      if (result.state.config && typeof result.state.config === 'object') noAuction = result.state.config.all_new_time_to_validators === true;
      return result;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      log('warn', 'a verified state read failed', { error: plainText(error?.message, 160) });
      throw new ApiError(503, 'state_unavailable', 'The current state could not be read with a valid proof (the node is behind, unreachable, or the trust anchor has expired); indexed routes still answer', { retryAfter: 5, cause: plainText(error?.message, 400) });
    } finally { stateReads -= 1; }
  }
  /// The same read for the routes many readers ask in the same words (the validators, the proof
  /// of a block, an account's state): requests that arrive while it is under way share it, and
  /// its answer serves further ones for a moment. A proof is as good a second later; a reader
  /// whose light client is already ahead asks again.
  const sharedReads = new Map();
  function sharedState(selection) {
    const key = JSON.stringify(selection), at = now(), held = sharedReads.get(key);
    if (held && (held.result === undefined || (at >= held.at && at - held.at < STATE_SHARE_MS))) return held.reading;
    for (const [other, entry] of sharedReads) if (entry.result !== undefined && !(at >= entry.at && at - entry.at < STATE_SHARE_MS)) sharedReads.delete(other);
    if (sharedReads.size >= 256) return verifiedState(selection);
    const entry = { at, result: undefined, reading: null };
    entry.reading = verifiedState(selection).then((result) => { entry.result = result; entry.at = now(); return result; }, (error) => { if (sharedReads.get(key) === entry) sharedReads.delete(key); throw error; });
    sharedReads.set(key, entry);
    return entry.reading;
  }
  /// The height of the highest verified state seen: the history of blocks is provable up to it.
  let reached = null;
  const noteReach = (state) => {
    const height = /^[1-9][0-9]{0,15}$/.test(String(state?.height ?? '')) ? Number(state.height) : null;
    if (height !== null && (reached === null || height > reached)) reached = height;
  };
  /// What every answer from a state proof carries: where it stands, and the proof this server
  /// checked, so that the caller can check it again.
  const fromState = (result, selection) => {
    const high = store.high();
    return { source: 'state_proof', checked_by: 'this server, with its own trust anchor', state_height: String(result.state.height), state_time_micros: String(result.state.time_micros), indexed_height: high === null ? null : String(high),
      proof: { query: result.requested ?? selection, view_proof: result.proof ?? null, how: 'Verify it yourself: update your light client to view_proof.light_block, then verifyViewProof(view_proof, trust, query) with the installed verifier. SDK: client.getVerifiedState(query).' } };
  };
  /// Material of the node that a caller's own light client verifies: bounded in time and in how
  /// many requests ask the node at once. Nothing of it is this server's word.
  let nodeReads = 0;
  async function fromNode(read) {
    if (nodeReads >= 8) throw new ApiError(503, 'busy', 'Too many requests are asking the node; try again shortly', { retryAfter: 1 });
    nodeReads += 1;
    try { return await withTimeout(read(), stateTimeoutMs, undefined, 'node'); } catch (error) {
      if (error instanceof IndexerError && error.code === 'RPC_REFUSED') throw new ApiError(404, 'not_found', 'The node does not have this block (not made yet, or pruned)');
      throw new ApiError(503, 'node_unavailable', 'The node did not answer', { retryAfter: 5 });
    } finally { nodeReads -= 1; }
  }
  /// The trust manifest the explorer's pages start from: the configured one, moved to the newest
  /// block one of this server's light clients verified, so that it is never older than the
  /// trusting period while the service runs.
  async function explorerTrust() {
    let checkpoint = trust.checkpoint ?? null;
    for (const scope of ['indexer', 'state']) {
      try {
        const saved = JSON.parse(await store.checkpointStorage(scope).getItem(`timecurrency-v4-checkpoint:${trust.network_id}`));
        if (saved?.checkpoint?.height && (!checkpoint || BigInt(saved.checkpoint.height) > BigInt(checkpoint.height))) checkpoint = saved.checkpoint;
      } catch { /* none stored yet */ }
    }
    return { ...trust, ...(checkpoint ? { checkpoint } : {}) };
  }
  /// The fee is a setting of the genesis: one verified state gives it for good.
  function learnFee() {
    if (feeMicros !== null || now() - feeAsked < 10000) return;
    feeAsked = now();
    verifiedState({}).catch(() => {});
  }

  // ---- the event stream
  const frame = (event, id, data) => `event: ${event}\n${id === null ? '' : `id: ${id}\n`}data: ${JSON.stringify(data)}\n\n`;
  function send(stream, text) {
    // A reader that does not keep up is dropped, not buffered without end.
    if (stream.response.writableLength > STREAM_BUFFER_BYTES) { stream.response.destroy(); return false; }
    stream.response.write(text); return true;
  }
  /// Ends a stream on this server's side. The reader reconnects with the id of its last event and
  /// is sent what it missed.
  function endStream(stream, reason) {
    streams.delete(stream);
    if (stream.response.destroyed || stream.response.writableEnded) return;
    send(stream, frame('bye', null, { reason, message: 'Reconnect with Last-Event-ID (or ?after=) to continue where this stream ended' }));
    stream.response.end();
  }
  /// Without an account a stream carries every payment; with one, those to it (direction in,
  /// the default), from it (out), or both.
  const wants = (stream, payment) => !stream.account || (stream.direction !== 'out' && payment.recipient === stream.account) || (stream.direction !== 'in' && payment.sender === stream.account);
  function publish({ block, payments }) {
    if (streams.size === 0) return;
    const frames = payments.map((payment) => ({ payment, text: frame('payment', encodeCursor(block.height, payment.index), payment) }));
    const last = frame('block', String(block.height), { source: 'index', proven: false, ...blockView({ ...block, results_checked: 0 }) });
    for (const stream of [...streams]) {
      let open = true;
      for (const f of frames) if (open && wants(stream, f.payment)) open = send(stream, f.text);
      if (open) send(stream, last);
    }
  }
  /// Sends again what a reconnecting reader missed, from the index. `position` is the id of the
  /// last event it received: a block ("<height>") or a payment ("<height>.<index>").
  /// The work of one request is bounded by what it reads, not by what it sends: at most
  /// REPLAY_BLOCKS block rows and REPLAY_PAYMENTS payment rows, and payments are read through the
  /// index of payments (all, to the account, from it), so actions that would not be sent are
  /// never read. Beyond the bound the reader gets one `gap` event and reads the lists.
  /// Runs without yielding, so no live event can arrive in between.
  function replay(stream, position) {
    const high = store.high();
    // After a block event comes the next block; after a payment, the rest of its block.
    let first = position.index === null ? position.height + 1 : position.height, after = position.index === null ? -1 : position.index;
    // A position below the start of this index: the heights in between are not here. The reader is told so
    // before anything else, and is then sent what this index holds, from its start.
    if (first < store.startHeight) {
      if (!send(stream, frame('gap', null, { from_height: String(first), to_height: String(store.startHeight - 1), message: `This index starts at height ${store.startHeight} and does not hold these heights: read them from an index that does` }))) return;
      first = store.startHeight; after = -1;
    }
    if (high === null || first > high) return;
    const gap = (from) => send(stream, frame('gap', null, { from_height: String(from), to_height: String(high), message: 'Too much was missed to send again: read the lists (blocks, payments) for these heights' }));
    if (high - first >= REPLAY_BLOCKS) { gap(first); return; }
    let budget = REPLAY_PAYMENTS;
    const reader = (direction) => {
      let cursor = { height: first, index: after }, rows = [], at = 0, done = false;
      return {
        /// The next payment of this reader, or null. Reads a page when the last one is used up.
        peek() {
          if (at === rows.length && !done) {
            rows = store.paymentsSpan(direction, stream.account, cursor, high, 250); at = 0;
            budget -= rows.length; done = rows.length < 250;
            if (rows.length) cursor = { height: rows.at(-1).height, index: rows.at(-1).idx };
          }
          return at < rows.length ? rows[at] : null;
        },
        take() { at += 1; },
      };
    };
    const readers = (!stream.account ? ['all'] : stream.direction === 'both' ? ['in', 'out'] : [stream.direction]).map(reader);
    for (const block of store.blocksAfter(first - 1, REPLAY_BLOCKS)) {
      if (block.height > high) break;
      for (;;) {
        // The next payment of this block, from whichever reader has the earlier one.
        let next = null, source = null;
        for (const r of readers) { const row = r.peek(); if (row && row.height === block.height && (next === null || row.idx < next.idx)) { next = row; source = r; } }
        if (budget < 0) { gap(block.height); return; }
        if (next === null) break;
        source.take();
        if (!send(stream, frame('payment', encodeCursor(block.height, next.idx), paymentEvent(next)))) return;
      }
      if (!send(stream, frame('block', String(block.height), { source: 'index', proven: false, ...blockView(block) }))) return;
    }
  }
  /// A place for a new stream of `client`, or a refusal.
  /// - Streams are counted per holder: an IPv4 address, or an IPv6 /56. (Per /64, one subscriber
  ///   with a /56 would be 256 holders.) A holder has at most `maxStreamsPerClient`.
  /// - When every place is taken, a holder with more streams than the one asking gives up its
  ///   oldest, the holder with the most first. A stream is not put out in its first seconds. A
  ///   stream that follows an account is never put out for one that follows none, and goes last
  ///   in any case: whoever only wants a place does not get that of a reader of deposits.
  /// - Reserved clients always get a place and are never put out. This is the only guarantee: a
  ///   service that must not lose its stream is listed there.
  /// A reader that is put out reconnects with the id of its last event and is sent what it missed.
  function admit(client, follows) {
    const holder = holderKey(client), at = now();
    const mine = [...streams].filter((s) => s.holder === holder).length;
    const refuse = () => { throw new ApiError(503, 'too_many_streams', 'Too many event streams are open', { retryAfter: 10 }); };
    if (mine >= maxStreamsPerClient) refuse();
    if (reserved.has(client)) return;
    const open = [...streams].filter((s) => !s.reserved);
    if (open.length < maxStreams) return;
    const counts = new Map();
    for (const s of open) counts.set(s.holder, (counts.get(s.holder) || 0) + 1);
    const candidates = open.filter((s) => counts.get(s.holder) > mine && at - s.opened >= STREAM_MIN_AGE_MS && (follows || !s.account));
    if (candidates.length === 0) refuse();
    // Streams that follow no account go first, also when the one asking follows one.
    const pool = candidates.some((s) => !s.account) ? candidates.filter((s) => !s.account) : candidates;
    const most = Math.max(...pool.map((s) => counts.get(s.holder)));
    endStream(pool.find((s) => counts.get(s.holder) === most), 'evicted');
  }

  // ---- routes
  const ROUTE_HANDLERS = {
    'GET /v1/status': () => {
      learnFee();
      return { status: 200, body: { api: 'v1', service_started_at: new Date(startedAt).toISOString(),
        network: { network_id: store.networkId, chain_id: store.chainId, protocol_version: '4', fee_micros: feeMicros, fee_source: feeMicros === null ? null : 'state_proof' },
        indexer: (({ start_height, indexed_height, tip_height_reported, ...rest }) => ({ start_height: String(start_height), indexed_height: indexed_height === null ? null : String(indexed_height), tip_height_reported: tip_height_reported === null ? null : String(tip_height_reported), ...rest }))(indexer.status()),
        limits: { max_page: MAX_PAGE, default_page: DEFAULT_PAGE, max_body_bytes: MAX_BODY_BYTES },
        notice: 'Answers marked "source": "index" are this server\'s word, not a proof. Verify what matters with the SDK and your own trust anchor.' } };
    },
    'GET /v1/health': () => {
      const s = indexer.status(), reasons = [];
      if (s.fault) reasons.push('indexer_fault');
      if (!s.running) reasons.push('indexer_stopped');
      if (s.indexed_height === null ? now() - startedAt > maxLagSeconds * 1000 : s.seconds_behind > maxLagSeconds) reasons.push('index_behind');
      if (s.consecutive_failures >= 5) reasons.push('indexer_failing');
      return { status: reasons.length ? 503 : 200, body: { ok: reasons.length === 0, reasons, indexed_height: s.indexed_height === null ? null : String(s.indexed_height), seconds_behind: s.seconds_behind,
        blocks_behind_reported: s.blocks_behind_reported, headers_to_verify: s.headers_to_verify, consecutive_failures: s.consecutive_failures, last_error: s.last_error, fault: s.fault,
        streams: streams.size, webhooks: dispatcher.status() } };
    },
    'GET /v1/openapi.json': () => ({ status: 200, raw: OPENAPI }),
    'GET /v1/blocks': ({ query }) => {
      const order = query.order ?? 'desc', limit = query.limit ?? DEFAULT_PAGE;
      // After block h comes block h + 1: a cursor at the block before the start skips nothing.
      cursorWithinIndex(query.cursor, store.startHeight - 1);
      const from = query.cursor ?? (order === 'asc' ? 0 : Number.MAX_SAFE_INTEGER);
      const rows = order === 'asc' ? store.blocksAfter(from, limit + 1) : store.blocksBefore(from, limit + 1);
      const listed = page(rows, limit, query.cursor === undefined ? null : String(query.cursor), (row) => String(row.height));
      return { status: 200, body: fromIndex({ ...listed, items: listed.items.map(blockView), verify: { how: 'Verify a block with a light client of your own: createLightClient(...).updateTo(height) gives the verified header, whose hash must equal `hash`.' } }) };
    },
    'GET /v1/blocks/{height}': ({ params }) => {
      const row = store.block(params.height);
      if (!row) throw new ApiError(404, 'not_found', 'This block is not in the index', { body: { index: indexNote() } });
      return { status: 200, body: fromIndex({ block: blockView(row), verify: { height: String(row.height), block_hash: row.hash.toUpperCase(), how: 'createLightClient(...).updateTo(height) verifies the header against your trust anchor; its block_hash must equal this one.' } }) };
    },
    'GET /v1/blocks/{height}/proof': async ({ params }) => {
      // The state keeps a history of the hashes of its blocks and proves any of them up to its
      // own height. That proof stays when the state drops a block's own rows after fourteen days
      // (`history_pruned_through` counts those rows, not the history), so the age of a block is no
      // obstacle. A proof for this block and the next one, with their two signed headers, is what
      // verifyReceipt takes as the anchor of an action of this block. Two kinds of block cannot be
      // proven here, and each is said as what it is:
      // - one the state does not reach yet (the newest two): 404 `not_in_history`;
      // - on a node that joined the network from a snapshot, one at or below the height it was
      //   restored at, for which it holds no history: 404 `history_not_held`.
      const blocks = [String(params.height), String(params.height + 1)], selection = { blocks };
      const missing = (proven) => new ApiError(404, 'not_in_history', 'The proven state does not reach this block and the next one yet: they are too new. Ask again after two more blocks, or follow the block by its own signed header', { body: proven });
      // A proof asked about a block above the state's height cannot be made at all. So the state
      // is first asked how far it reaches, unless a state already seen reached far enough (it
      // only grows); a block beyond it is answered with the proof of that plain state, which
      // shows its height.
      const held = () => reached !== null && params.height + 1 <= reached;
      if (!held()) {
        const plain = await sharedState({});
        noteReach(plain.state);
        if (!held()) throw missing(fromState(plain, {}));
      }
      let result;
      try { result = await sharedState(selection); } catch (error) {
        // The node refuses a question about history it does not hold, and says so (v5/README.md,
        // "State sync and pruning"). That refusal is this service's own node speaking of itself.
        if (error instanceof ApiError && /holds no block history at or below height/.test(error.extra.cause ?? '')) throw new ApiError(404, 'history_not_held', 'The node of this service holds no history for this block: it joined the network from a snapshot of a later height. A service whose node has the history can prove the block');
        throw error;
      }
      const proven = fromState(result, selection);
      noteReach(result.state);
      const rows = blocks.map((height) => result.state.canonical_blocks?.[height]);
      if (!rows.every((row) => row && typeof row.hash === 'string')) throw missing(proven);
      const signed = await fromNode(() => Promise.all(blocks.map((height) => rpc('/commit', { height }))));
      return { status: 200, body: { ...proven, block: { height: blocks[0], hash: String(rows[0].hash).toUpperCase(), time_micros: String(rows[0].time_micros) }, next_block: { height: blocks[1], hash: String(rows[1].hash).toUpperCase(), time_micros: String(rows[1].time_micros) },
        signed_header: signed[0]?.signed_header ?? null, next_signed_header: signed[1]?.signed_header ?? null,
        verify: { how: 'The two block hashes are proven by proof.view_proof. The signed headers come from the node unchecked: verifyReceipt({ tx, signed_header, next_signed_header, anchor: proof.view_proof }, trust) with the installed verifier checks that they are these two blocks and that the action (tx, in the form GET /v1/actions/{hash} describes) is in the first.' } } };
    },
    'GET /v1/light-blocks/{height}': async ({ params }) => {
      const light = await fromNode(() => fetchLightBlock({ rpc, height: String(params.height) }));
      return { status: 200, body: { source: 'node', proven: false, height: String(params.height), light_block: light,
        verify: { how: 'This is what the node says, unchecked. A light client verifies it: createLightClient({ trust, verifier, fetchBlock }).updateToBlock(light_block), or let fetchBlock return it.' } } };
    },
    'GET /v1/validators': async () => {
      // Whether the state is asked about its upgrade row is not decided here: the SDK's client
      // asks it with every read when the trust data says that the network's nodes report upgrades
      // (`trust.nodes_report_upgrades`), and never otherwise (a node from before the question
      // refuses it). A state that was not asked says nothing about the row, so the answer then
      // has no `upgrade` at all: absence of the field is "not read", never "no plan".
      const selection = { include_pos: true };
      const result = await sharedState(selection), state = result.state;
      return { status: 200, body: { ...fromState(result, selection), protocol_version: state.protocol_version ?? null,
        // `pos` is the staking row of the state as it is: who validates now (active), the sets already announced (scheduled).
        pos: state.pos ?? null,
        ...(Object.hasOwn(state, 'upgrade') ? { upgrade: state.upgrade } : {}) } };
    },
    'GET /v1/accounts/{id}/state': async ({ params }) => {
      const id = params.id, selection = { ids: [id], owners: [id], candidates: [id], include_security: true };
      const result = await sharedState(selection), state = result.state, proven = fromState(result, selection);
      const account = (state.accounts ?? []).find((item) => String(item.id) === id);
      if (!account) throw new ApiError(404, 'account_not_found', 'No such account in the verified state', { body: proven });
      return { status: 200, body: { ...proven, account,
        security: (state.security ?? []).find((row) => String(row.account) === id) ?? null,
        recovery_cases: (state.recovery_cases ?? []).filter((item) => String(item.target) === id),
        stake: state.stake_owners?.[id] ?? null, validator: state.candidates?.[id] ?? null,
        genesis_time_micros: state.genesis?.genesis_time_micros ?? null, security_clock: securityClockOf(state) } };
    },
    'GET /v1/blocks/{height}/actions': ({ params, query }) => {
      if (!store.block(params.height)) throw new ApiError(404, 'not_found', 'This block is not in the index', { body: { index: indexNote() } });
      const limit = query.limit ?? DEFAULT_PAGE;
      if (query.cursor && query.cursor.height !== params.height) bad('invalid_cursor', 'This cursor belongs to another block');
      const rows = store.blockActions(params.height, query.cursor ? query.cursor.index : -1, limit + 1);
      const listed = page(rows, limit, query.cursor?.text ?? null, (row) => encodeCursor(row.height, row.idx));
      return { status: 200, body: fromIndex({ ...listed, items: listed.items.map(actionView), verify: { how: 'Each item is verified by its hash: GET /v1/actions/{hash} gives the proof material.' } }) };
    },
    'GET /v1/actions/{hash}': ({ params }) => {
      const row = store.actionByHash(params.hash);
      if (!row) throw new ApiError(404, 'not_found', 'No action with this hash is in the index: it may be waiting for a block, refused, or above the indexed height', { body: { index: indexNote() } });
      const raw = Buffer.from(row.raw);
      let decoded = null;
      if (row.opaque !== 1) { try { decoded = SDK.decodeAction(new Uint8Array(raw)); } catch { decoded = null; } }
      // The Merkle proof that these bytes are transaction `index` of the block, read from the
      // tree stored with the block. The bytes themselves are in the answer once, as `action.raw`.
      const proof = store.inclusionProof(row.height, row.idx, row.tx_count);
      return { status: 200, body: fromIndex({
        action: { ...actionView(row), public_key: decoded?.publicKey ?? null, auth_epoch: decoded?.authEpoch ?? null, payload: decoded?.payload ?? null, raw: raw.toString('base64'), repeated: row.repeated },
        verify: {
          how: 'Verify the header of this block with your own light client (updateTo(height)). Put the proof in the form of the node\'s own lookup: tx = { hash, height, index, tx: action.raw, proof: { root_hash, data: action.raw, proof: { total, index: String(index), leaf_hash, aunts } } }. Then verifyFastReceipt({ tx, headers: [that header] }, { ...trust, checkpoint }) with the installed verifier. Or ask a wallet gateway through the SDK: client.waitReceipt(hash). Decode the proven bytes yourself with TimeSDK.decodeAction.',
          hash: row.hash, height: String(row.height), block_hash: row.block_hash.toUpperCase(), index: row.idx, total: String(row.tx_count),
          root_hash: proof.root.toString('hex').toUpperCase(), leaf_hash: proof.leaf.toString('base64'), aunts: proof.aunts.map((aunt) => aunt.toString('base64')),
        },
      }) };
    },
    'GET /v1/accounts/{account}': async ({ params }) => {
      const wanted = params.account, selection = wanted.id ? { ids: [wanted.id] } : { names: [wanted.name] };
      const result = await verifiedState(selection), state = result.state;
      const account = state.accounts.find((item) => (wanted.id ? String(item.id) === wanted.id : item.name === wanted.name));
      // `indexed_height` stands next to `state_height` on purpose: what the index does not show is
      // only known to be absent from the chain up to the indexed height, and the state may be ahead.
      const high = store.high();
      const proven = { source: 'state_proof', checked_by: 'this server, with its own trust anchor', state_height: String(state.height), state_time_micros: String(state.time_micros), indexed_height: high === null ? null : String(high),
        proof: { query: result.requested ?? selection, view_proof: result.proof ?? null, how: 'Verify it yourself: update your light client to view_proof.light_block, then verifyViewProof(view_proof, trust, query) with the installed verifier. SDK: client.getVerifiedState(query).' } };
      if (!account) throw new ApiError(404, 'account_not_found', 'No such account in the verified state', { body: proven });
      const totals = store.account(String(account.id));
      // The proven state trails the newest block by one, and the index can be ahead of it. An action this
      // account sent in a block above the height of the proven state is one the proof does not count: whoever
      // takes the proven nonce plus one may then sign for a nonce that is used. Such actions are read from the
      // account's own activity above that height, so what is read is what the account has in the block or two
      // the proof trails by. Every action the account sent counts, also one that carries no nonce (a freeze, a
      // payment or a replacement of the keys approved by several keys, a cancellation): a replacement uses a
      // nonce without carrying one, so a search by "the proven nonce plus one" would miss what came after it.
      // What is said here is the index's word; the proof is not touched by it.
      const id = String(account.id), stateHeight = Number(state.height);
      const sent = (row) => ({ hash: row.hash, height: String(row.height), nonce: row.nonce, kind: row.kind });
      const newer = Number.isSafeInteger(stateHeight) ? store.sentAbove(id, stateHeight, 'asc', NEWER_ACTIONS) : [];
      // The newest of them, also when there are more than the list holds.
      const newest = newer.length < NEWER_ACTIONS ? newer.at(-1) : store.sentAbove(id, stateHeight, 'desc', 1)[0];
      // With none newer: the action that carries the proven nonce, if the index holds it.
      const counted = newest || !/^[1-9][0-9]{0,19}$/.test(String(account.nonce ?? '')) ? null : store.actionBySenderNonce(id, String(account.nonce), '');
      return { status: 200, body: { ...proven, account,
        indexed: fromIndex({
          // `state_is_behind`: the index holds an action this account sent in a block above `state_height`.
          // `newer_actions`: those, oldest first, at most NEWER_ACTIONS. `last_sent`: the newest of them, also
          // when the list does not reach it; with none, the action that carries the proven nonce.
          state_is_behind: newer.length > 0, newer_actions: newer.map(sent), last_sent: newest ? sent(newest) : counted ? sent(counted) : null,
          totals: {
          actions_sent: totals?.actions_sent ?? 0, payments_sent: totals?.payments_sent ?? 0, sent_micros: totals?.sent_micros ?? '0',
          payments_received: totals?.payments_received ?? 0, received_micros: totals?.received_micros ?? '0',
          first_height: totals ? String(totals.first_height) : null, last_height: totals ? String(totals.last_height) : null,
          }, note: 'Totals count what the index holds from its start height: transfers (3), payments to shops (10), payments approved by several keys (73) and completed payments above the daily limit (75) that the index could tie to their request. Rewards, stake movements and completed payments it could not tie change the balance without appearing here.' }) } };
    },
    'GET /v1/accounts/{id}/activity': ({ params, query }) => {
      const order = query.order ?? 'desc', limit = query.limit ?? DEFAULT_PAGE;
      cursorWithinIndex(query.cursor?.height);
      const rows = store.activity(params.id, order, query.cursor ?? startOf(order), limit + 1);
      const listed = page(rows, limit, query.cursor?.text ?? null, (row) => encodeCursor(row.height, row.idx));
      return { status: 200, body: fromIndex({ account: params.id, order, ...listed, items: listed.items.map(actionView), verify: { how: 'Each item is verified by its hash: GET /v1/actions/{hash} gives the proof material.' } }) };
    },
    'GET /v1/accounts/{id}/payments': ({ params, query }) => {
      const order = query.order ?? 'asc', limit = query.limit ?? DEFAULT_PAGE;
      cursorWithinIndex(query.cursor?.height);
      const rows = store.payments(params.id, { reference: query.reference ?? null, sender: query.from ?? null }, order, query.cursor ?? startOf(order), limit + 1);
      const listed = page(rows, limit, query.cursor?.text ?? null, (row) => encodeCursor(row.height, row.idx));
      return { status: 200, body: fromIndex({ account: params.id, order, filters: { reference: query.reference ?? null, from: query.from ?? null }, ...listed, items: listed.items.map(actionView),
        verify: { how: 'Before crediting a deposit, verify its hash: GET /v1/actions/{hash} gives the proof material, and client.waitReceipt(hash) of the SDK checks it against validator signatures. A reference does not name its payer: more than one payment can carry it, so filter by the payer (from) as well and credit each hash once.' } }) };
    },
    'POST /v1/transactions': async ({ body }) => {
      if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).join(',') !== 'tx' || typeof body.tx !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(body.tx)) bad('invalid_body', 'The body is {"tx": "<the signed action in base64>"}');
      const raw = Buffer.from(body.tx, 'base64');
      if (raw.length > MAX_ACTION_BYTES || raw.length < 64 || raw.toString('base64') !== body.tx) bad('invalid_body', 'tx is canonical base64 of one signed action');
      let action;
      // A refusal here judges the request, not the chain: a kind this service's SDK does not know is refused
      // here although a node may take it. The message says so, so that nobody reads "can never be included".
      try { action = SDK.decodeAction(new Uint8Array(raw)); } catch { bad('invalid_action', 'These bytes are not a signed action that the SDK of this service can decode. This says nothing about the chain: a node may still take them'); }
      if (action.networkId !== store.networkId) bad('wrong_network', 'This action is signed for another network');
      const hash = createHash('sha256').update(raw).digest('hex').toUpperCase();
      // These bytes may be in a block already: a withdrawal sent again after a failed answer, say.
      // The node would then refuse them ("incorrect nonce"), which reads like a reason to sign
      // anew. So the index is asked first, and again whenever the node did not take the bytes.
      const included = () => {
        const row = store.actionByHash(hash);
        return row && { status: 200, body: { hash, status: 'already_included', height: String(row.height), index: row.idx, results_checked: row.results_checked === 1, kind: action.kind, sender: action.from, nonce: action.nonce,
          note: 'These bytes are in a block already. Do not sign a replacement: look the hash up (GET /v1/actions/{hash}) and verify it.' } };
      };
      // The nonce of these bytes may be used already, by other bytes: the same payment signed a
      // second time (another key, a signer asked again) has another signature and another hash.
      // The node refuses it like any wrong nonce, which reads like a reason to sign once more.
      // So the index is also asked which action of this account carries the nonce.
      // "The same content" is the same kind and payload. That is the same payment signed twice, or another
      // payment of the same amount to the same recipient: this service cannot tell the two apart, the sender's
      // records can, and the message says so. Either way the answer is the index's word until the sender has
      // verified the action it names.
      const nonceUsed = () => {
        const row = store.actionBySenderNonce(action.from, action.nonce, hash);
        if (!row) return null;
        let same = false;
        try { const other = SDK.decodeAction(new Uint8Array(Buffer.from(row.raw))); same = other.kind === action.kind && JSON.stringify(other.payload) === JSON.stringify(action.payload); } catch { same = false; }
        return new ApiError(409, 'nonce_used', same
          ? 'An action of this account with this nonce and the same content is in a block already, under another signature (see used_by): these bytes can never be included. One hash is one payment: if used_by.hash is not the hash of another payment in your records, this payment is made by it and nothing more is signed for it; if it is, this payment is not made. Verify used_by.hash before you act on either'
          : 'Another action of this account used this nonce (see used_by): these bytes can never be included. Verify used_by.hash before you act on that: until then it is the word of this index',
        { body: { hash, used_by: { ...actionView(row), same_content: same }, index: indexNote() } });
      };
      const before = included();
      if (before) return before;
      // Kinds a network without the bitcoin auction refuses before any other check (40 to 42, 60 to
      // 63), and the one kind that carries no signature (40, the relay of bitcoin headers): it is
      // passed on only when a proof of the network's configuration says the network takes it.
      if ([40, 41, 42, 60, 61, 62].includes(action.kind)) {
        if (noAuction === null && action.kind === 40) await verifiedState({});
        if (noAuction === true) bad('not_on_this_network', 'This network has no bitcoin auction and refuses this kind of action');
        if (noAuction === null && action.kind === 40) throw new ApiError(503, 'state_unavailable', 'The configuration of the network could not be read with a proof; an unsigned relay is not passed on without it', { retryAfter: 5 });
      }
      if (!(await signatureValid(raw, action))) bad('invalid_signature', 'The signature is not one of the key the action names');
      const used = nonceUsed();
      if (used) throw used;
      const hint = 'If these bytes, or the same payment under another signature, were sent before, they may be in a block the index has not reached yet: before signing anything new, look the hash up and find which action used the nonce';
      let result;
      try { result = await rpc('/broadcast_tx_sync', { tx: `0x${raw.toString('hex')}` }); } catch (error) {
        const meanwhile = included();
        if (meanwhile) return meanwhile;
        const usedMeanwhile = nonceUsed();
        if (usedMeanwhile) throw usedMeanwhile;
        if (error instanceof IndexerError && /already exists in cache/i.test(error.rpcMessage || '')) throw new ApiError(409, 'already_submitted', 'The node already has this action; look it up by its hash', { body: { hash, index: indexNote() } });
        log('warn', 'the node did not take a submitted action', { code: error instanceof IndexerError ? error.code : 'INTERNAL' });
        throw new ApiError(502, 'node_unavailable', 'The node did not take the action; it is safe to send the same bytes again', { retryAfter: 2, body: { hash, index: indexNote() } });
      }
      const code = Object.hasOwn(result ?? {}, 'code') ? result.code : 0;
      if (code !== 0) {
        const meanwhile = included();
        if (meanwhile) return meanwhile;
        const usedMeanwhile = nonceUsed();
        if (usedMeanwhile) throw usedMeanwhile;
        throw new ApiError(422, 'rejected', `The node refused the action: ${plainText(result?.log, 200) || 'no reason given'}. ${hint}`, { body: { hash, index: indexNote() } });
      }
      if (typeof result?.hash !== 'string' || result.hash.toUpperCase() !== hash) throw new ApiError(502, 'node_mismatch', 'The node answered for another transaction', { body: { hash, index: indexNote() } });
      return { status: 202, body: { hash, status: 'submitted', kind: action.kind, sender: action.from, nonce: action.nonce,
        note: 'Submitted is not included. Look the hash up (GET /v1/actions/{hash}) until it is in a block, and keep the signed bytes: sending the same bytes again is safe, signing a replacement is not.' } };
    },
    'GET /v1/stream': ({ query, request, response, client }) => {
      const resumeHeader = request.headers['last-event-id'];
      const position = query.after ?? (typeof resumeHeader === 'string' && resumeHeader ? PARAMETERS.position(resumeHeader) : null);
      if (query.direction && !query.account) bad('invalid_direction', 'direction needs an account');
      admit(client, Boolean(query.account));
      response.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'X-Accel-Buffering': 'no' });
      const stream = { response, client, holder: holderKey(client), reserved: reserved.has(client), account: query.account ?? null, direction: query.account ? query.direction ?? 'in' : null, opened: now() };
      response.write(`retry: 3000\n${frame('hello', null, { source: 'index', proven: false, index: indexNote(), account: stream.account, direction: stream.direction })}`);
      if (position) replay(stream, position);
      if (response.destroyed) return { taken: true };
      streams.add(stream);
      response.on('close', () => streams.delete(stream));
      return { taken: true };
    },
  };
  /// The route table: method, path template, what each query parameter must be, and the cost in
  /// rate-limit tokens. The OpenAPI description is checked against it.
  const routes = ROUTES.map((route) => ({ ...route, handler: ROUTE_HANDLERS[`${route.method} ${route.path}`], pattern: new RegExp(`^${route.path.replace(/[.]/g, '\\.').replace(/\{[a-z]+\}/g, '([^/]+)')}$`), names: [...route.path.matchAll(/\{([a-z]+)\}/g)].map((m) => m[1]) }));
  for (const route of routes) if (typeof route.handler !== 'function') throw new Error(`Route without handler: ${route.method} ${route.path}`);

  // ---- HTTP
  const BASE_HEADERS = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY', 'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'" };
  function reply(response, status, body, headers = {}) {
    const text = typeof body === 'string' ? body : JSON.stringify(body);
    response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(text), ...headers });
    response.end(text);
  }
  function failure(response, error) {
    // After a body that was too large the connection is closed: the rest of it is not read.
    // Closing at once would reset the connection before the answer is read, so what is still
    // coming is read and dropped for a moment first.
    if (error.extra.close) response.once('finish', () => { const request = response.req; request?.resume(); setTimeout(() => request?.destroy(), 1000).unref?.(); });
    reply(response, error.status, { error: { code: error.code, message: error.message }, ...(error.extra.body || {}) }, {
      ...(error.extra.retryAfter ? { 'Retry-After': String(error.extra.retryAfter) } : {}), ...(error.extra.allow ? { Allow: error.extra.allow } : {}), ...(error.extra.close ? { Connection: 'close' } : {}) });
  }
  /// Who is asking: the peer, or what trusted proxies say about it. X-Forwarded-For is read from
  /// the right, past the entries that are trusted proxies themselves: the first one that is not
  /// was written by a trusted proxy and is the client. What stands left of it is the client's own
  /// claim and is not read.
  function clientOf(request) {
    const peer = normalIp(request.socket.remoteAddress);
    if (peer === null || !proxies.has(peer)) return clientKey(peer);
    const entries = String(request.headers['x-forwarded-for'] || '').split(',');
    for (let i = entries.length - 1; i >= 0; i--) {
      const ip = normalIp(entries[i]);
      if (ip === null) break; // not an address: nothing left of it can be believed either
      if (!proxies.has(ip)) return clientKey(ip);
    }
    return clientKey(peer);
  }
  /// Whether the signature of a submitted action is one of the key its envelope names.
  /// What this proves: whoever sent the bytes holds a key that signed exactly them. What it does
  /// not: that the key is one of the account's. That is in the account's state, which the node
  /// checks; reading it here with a proof for every submission would cost more than the node's
  /// own refusal. So an action signed by a stranger's key still reaches the node, once per
  /// submission and within the sender's rate limit, and is refused there.
  async function signatureValid(raw, action) {
    const signed = raw.subarray(0, raw.length - 64), signature = raw.subarray(raw.length - 64);
    // The public relay of bitcoin headers is the one action without a signer: no key, no signature.
    // It has exactly one form (wire.rs, `is_public_headers`): anything else of kind 40 is refused here.
    if (action.kind === 40) return action.from === SDK.MAX_U64 && action.nonce === '0' && action.authEpoch === '0' && /^0+$/.test(action.publicKey) && signature.every((byte) => byte === 0);
    try {
      const key = await crypto.subtle.importKey('raw', SDK.hexToBytes(action.publicKey, 32), 'Ed25519', false, ['verify']);
      return await crypto.subtle.verify('Ed25519', key, signature, signed);
    } catch { return false; }
  }
  /// The JSON body of a request, at most MAX_BODY_BYTES. What comes after the limit is not kept.
  async function readBody(request) {
    if (!/^application\/json(?:\s*;|$)/i.test(request.headers['content-type'] || '')) throw new ApiError(415, 'unsupported_media_type', 'Send JSON with Content-Type: application/json');
    const tooLarge = () => new ApiError(413, 'body_too_large', `The body is at most ${MAX_BODY_BYTES} bytes`, { close: true });
    if (Number(request.headers['content-length']) > MAX_BODY_BYTES) throw tooLarge();
    const bytes = await new Promise((resolve, reject) => {
      const chunks = []; let size = 0, over = false;
      request.on('data', (chunk) => {
        if (over) return;
        size += chunk.length;
        if (size > MAX_BODY_BYTES) { over = true; chunks.length = 0; reject(tooLarge()); } else chunks.push(chunk);
      });
      request.on('end', () => { if (!over) resolve(Buffer.concat(chunks)); });
      request.on('error', () => reject(new ApiError(400, 'invalid_body', 'The body could not be read')));
    });
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new ApiError(400, 'invalid_json', 'The body is not valid JSON'); }
  }
  async function handle(request, response) {
    for (const [name, value] of Object.entries(BASE_HEADERS)) response.setHeader(name, value);
    try {
      // Only this server's own names are answered, so a web page cannot reach it under another
      // name (DNS rebinding). A request that names two hosts is refused: this server and a proxy
      // in front of it could each believe another one.
      if (request.rawHeaders.filter((name, i) => i % 2 === 0 && name.toLowerCase() === 'host').length > 1) throw new ApiError(400, 'invalid_request', 'A request names its host once');
      const bound = server.address()?.port, asked = hostName(request.headers.host);
      if (!ownHosts.has(asked) && ![`127.0.0.1:${bound}`, `localhost:${bound}`, `[::1]:${bound}`].map(hostName).includes(asked)) throw new ApiError(421, 'unknown_host', 'This server does not answer under that host name');
      // A browser names the page a request comes from (`Origin`), also for requests of this server's own pages:
      // Chrome sends it with the explorer's module scripts and with every request those scripts make. Before
      // 2026-11-19 such a request was refused like a foreign one, and the explorer served here loaded in no browser.
      // A request is this server's own when its origin is the very address that was asked: under http on this
      // machine, or under https for one of the configured host names (a TLS proxy stands in front). It is not
      // cross-origin and needs neither permission nor permission headers.
      // Cross-origin requests: only from the configured origins, and never with credentials.
      const origin = request.headers.origin;
      const rawHost = String(request.headers.host || '').toLowerCase();
      const own = origin !== undefined && (
        ([`127.0.0.1:${bound}`, `localhost:${bound}`, `[::1]:${bound}`].includes(rawHost) && origin === `http://${rawHost}`)
        || (ownHosts.has(asked) && origin.startsWith('https://') && origin.slice(8).replace(/:443$/, '') === rawHost.replace(/:443$/, '')));
      if (origin !== undefined && !own) {
        if (!origins.has('*') && !origins.has(origin)) throw new ApiError(403, 'origin_not_allowed', 'This origin may not call the API from a browser');
        response.setHeader('Access-Control-Allow-Origin', origins.has('*') ? '*' : origin);
        response.setHeader('Vary', 'Origin');
        // A page on another origin reads how long to wait from Retry-After only if it is exposed.
        response.setHeader('Access-Control-Expose-Headers', 'Retry-After');
      }
      if (request.method === 'OPTIONS' && origin !== undefined) {
        response.writeHead(204, { 'Access-Control-Allow-Methods': 'GET, POST', 'Access-Control-Allow-Headers': 'Content-Type, Last-Event-ID', 'Access-Control-Max-Age': '600' });
        response.end(); return;
      }
      const target = request.url || '';
      if (target.length > MAX_URL_LENGTH) throw new ApiError(414, 'url_too_long', 'The address is too long');
      // The address is a plain path with an optional query. Anything a URL parser would read
      // differently from how it is written is refused: another host ("//name", "http://name"), a
      // fragment (which would hide a filter behind "#"), dot segments, backslashes.
      const invalid = () => new ApiError(400, 'invalid_url', 'The address is a path such as /v1/status, with an optional query');
      if (!target.startsWith('/') || target.startsWith('//') || target.includes('#') || target.includes('\\')) throw invalid();
      let url;
      try { url = new URL(target, 'http://api.invalid'); } catch { throw invalid(); }
      if (url.pathname !== target.split('?')[0]) throw invalid();
      // The explorer's pages, if this service serves them: a fixed table from address to bytes read at
      // start. The path of the request is only ever compared with the keys of that table.
      if (explorerFiles && request.method === 'GET' && (url.pathname === '/explorer' || url.pathname.startsWith(EXPLORER_PREFIX))) {
        // No query, not even an empty one: the address of a file is its path and nothing else.
        const plain = !target.includes('?'), file = plain ? explorerFiles.get(url.pathname) : undefined;
        // "Not changed" is answered when the browser names the validator of the file it has: alone,
        // in a list, or marked weak.
        const known = Boolean(file) && String(request.headers['if-none-match'] ?? '').split(',').map((tag) => tag.trim().replace(/^W\//, '')).some((tag) => tag === file.etag || tag === '*');
        // The request is charged by what answering it costs (see EXPLORER_FILE_COST). This network's join.json is a
        // small answer fixed at start, and is charged as a small file.
        const join = plain && joinBody !== null && url.pathname === EXPLORER_JOIN_PATH;
        const cost = file ? (known ? EXPLORER_FILE_COST : file.cost) : join || (plain && url.pathname === '/explorer') ? EXPLORER_FILE_COST : 1;
        const wait = limiter.take(clientOf(request), cost);
        if (wait) throw new ApiError(429, 'rate_limited', 'Too many requests from this address', { retryAfter: wait });
        if (!plain) throw new ApiError(404, 'unknown_route', 'The files of the explorer take no query');
        const page = { 'Content-Security-Policy': EXPLORER_CSP, 'Cross-Origin-Resource-Policy': 'same-origin' };
        if (url.pathname === '/explorer') { response.writeHead(308, { ...page, Location: EXPLORER_PREFIX, 'Content-Length': 0 }); response.end(); return; }
        // The manifest moves with every block the service verifies: it is never kept by a browser.
        if (url.pathname === `${EXPLORER_PREFIX}trust-manifest.json`) { reply(response, 200, await explorerTrust(), page); return; }
        // This network's facts for "Run a validator", if the operator set them (explorer_join). Not kept by a browser
        // either: a new release of the network changes them. Without the setting it is a file the explorer does not have.
        if (join) { reply(response, 200, joinBody, page); return; }
        if (!file) throw new ApiError(404, 'unknown_route', 'No such file of the explorer');
        const kept = { ...page, 'Cache-Control': file.cache, ETag: file.etag };
        if (known) { response.writeHead(304, kept); response.end(); return; }
        response.writeHead(200, { ...kept, 'Content-Type': file.type, 'Content-Length': file.body.length });
        response.end(file.body); return;
      }
      const matching = routes.map((route) => ({ route, match: route.pattern.exec(url.pathname) })).filter((entry) => entry.match);
      const found = matching.find((entry) => entry.route.method === request.method);
      // Every request counts against its sender, also one for a route that does not exist.
      const client = clientOf(request);
      const wait = limiter.take(client, found?.route.cost ?? 1);
      if (wait) throw new ApiError(429, 'rate_limited', 'Too many requests from this address', { retryAfter: wait });
      if (matching.length === 0) throw new ApiError(404, 'unknown_route', 'No such route; GET /v1/openapi.json describes the API');
      if (!found) throw new ApiError(405, 'method_not_allowed', 'This route does not take that method', { allow: matching.map((entry) => entry.route.method).join(', ') });
      const { route, match } = found;
      // Path and query parameters: each in its one accepted form, nothing unknown, nothing twice.
      const params = {};
      route.names.forEach((name, i) => {
        let text;
        try { text = decodeURIComponent(match[i + 1]); } catch { bad('invalid_path', 'The path is not valid'); }
        params[name] = (name === 'account' ? accountOrName : PARAMETERS[name === 'id' ? 'account' : name])(text);
      });
      const query = {};
      for (const [name, value] of url.searchParams) {
        if (!Object.hasOwn(route.query, name)) bad('unknown_parameter', `This route takes no parameter "${plainText(name, 40)}"; it takes: ${Object.keys(route.query).join(', ') || 'none'}`);
        if (Object.hasOwn(query, name)) bad('repeated_parameter', `The parameter "${name}" is given twice`);
        query[name] = PARAMETERS[route.query[name]](value);
      }
      const body = route.method === 'POST' ? await readBody(request) : undefined;
      const result = await route.handler({ params, query, body, request, response, client });
      if (result.taken) return;
      if (result.raw !== undefined) reply(response, result.status, result.raw);
      else reply(response, result.status, result.body);
    } catch (error) {
      if (response.headersSent) { response.destroy(); return; }
      if (error instanceof ApiError) { failure(response, error); return; }
      // Nothing of an unexpected error reaches the caller; the log gets its text, cut and cleaned.
      log('error', 'request failed', { error: plainText(error?.message, 160) });
      failure(response, new ApiError(500, 'internal', 'The request could not be answered'));
    }
  }
  server = http.createServer((request, response) => { handle(request, response); });
  // A request that is not HTTP, or whose headers are too long or too slow: a short answer, then
  // the connection is closed (after a moment, so that the answer is not lost to a reset).
  server.on('clientError', (error, socket) => {
    if (!socket.writable || socket.bytesWritten > 0) { socket.destroy(); return; }
    const status = error?.code === 'HPE_HEADER_OVERFLOW' ? '431 Request Header Fields Too Large' : error?.code === 'ERR_HTTP_REQUEST_TIMEOUT' ? '408 Request Timeout' : '400 Bad Request';
    socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
    setTimeout(() => socket.destroy(), 1000).unref?.();
  });
  server.requestTimeout = 15000; server.headersTimeout = 5000; server.keepAliveTimeout = 5000; server.maxRequestsPerSocket = 1000; server.maxConnections = 2048;
  const close = () => closing ??= (async () => {
    clearInterval(heartbeat); clearInterval(stateRefresh);
    await indexer.stop();
    await dispatcher.stop();
    for (const stream of streams) stream.response.end();
    if (server.listening) await new Promise((resolve) => { server.close(() => resolve()); server.closeAllConnections?.(); });
    store.close();
  })();
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, () => { server.removeListener('error', reject); resolve(); }); });
  } catch (error) { await close(); throw error; }
  // Comment lines keep idle streams open through proxies. A stream that has been open for the
  // longest time allowed is ended: its reader reconnects, and the place is free for whoever asks.
  const tend = () => { for (const stream of [...streams]) { if (now() - stream.opened > maxStreamSeconds * 1000) endStream(stream, 'lifetime'); else send(stream, ': keep-alive\n\n'); } };
  heartbeat = setInterval(tend, 15000);
  heartbeat.unref?.();
  if (autoStart) {
    indexer.start(); dispatcher.kick(); learnFee();
    // The state reader has a light client of its own, which moves only when a state is read. It is
    // read on a timer, so that a week without account requests does not let its checkpoint expire.
    stateRefresh = setInterval(() => { verifiedState({}).catch(() => {}); }, stateRefreshMs);
    stateRefresh.unref?.();
  }
  const address = server.address();
  return {
    url: `http://${address.family === 'IPv6' ? `[${address.address}]` : address.address}:${address.port}`,
    indexer, store, webhooks: dispatcher, close, tendStreams: tend,
  };
}

/// Every route of the API. `query` names each query parameter and the form it must have (a key
/// of PARAMETERS); `cost` is what a call takes from the caller's rate-limit bucket.
export const ROUTES = Object.freeze([
  { method: 'GET', path: '/v1/status', query: {}, cost: 1 },
  { method: 'GET', path: '/v1/health', query: {}, cost: 1 },
  { method: 'GET', path: '/v1/openapi.json', query: {}, cost: 1 },
  { method: 'GET', path: '/v1/blocks', query: { limit: 'limit', cursor: 'height', order: 'order' }, cost: 1 },
  { method: 'GET', path: '/v1/blocks/{height}', query: {}, cost: 1 },
  { method: 'GET', path: '/v1/blocks/{height}/actions', query: { limit: 'limit', cursor: 'cursor' }, cost: 1 },
  { method: 'GET', path: '/v1/blocks/{height}/proof', query: {}, cost: 5 },
  { method: 'GET', path: '/v1/light-blocks/{height}', query: {}, cost: 5 },
  { method: 'GET', path: '/v1/validators', query: {}, cost: 5 },
  { method: 'GET', path: '/v1/accounts/{id}/state', query: {}, cost: 5 },
  { method: 'GET', path: '/v1/actions/{hash}', query: {}, cost: 5 },
  { method: 'GET', path: '/v1/accounts/{account}', query: {}, cost: 5 },
  { method: 'GET', path: '/v1/accounts/{id}/activity', query: { limit: 'limit', cursor: 'cursor', order: 'order' }, cost: 1 },
  { method: 'GET', path: '/v1/accounts/{id}/payments', query: { limit: 'limit', cursor: 'cursor', order: 'order', reference: 'reference', from: 'account' }, cost: 1 },
  { method: 'POST', path: '/v1/transactions', query: {}, cost: 10 },
  { method: 'GET', path: '/v1/stream', query: { account: 'account', direction: 'direction', after: 'position' }, cost: 10 },
].map(Object.freeze));
