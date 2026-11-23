// The explorer's side of the HTTP API (client-v4/api.mjs): one function per route it reads, and
// the event stream with its reconnection. Every address is built here from values that passed a
// test of format.mjs; a failed request becomes an `ApiFailure` that says what kind of failure it
// was, never a half-read answer.
import { isAccountId, isCursor, isHash, isHeight, isName } from './format.mjs';

/// Why a request gave no answer. `kind`:
/// - 'network': the service could not be reached, or did not answer in time;
/// - 'http': it answered with an error. `status`, and from the body `code` (the API's stable
///   code, if it has the form of one) and `serverMessage` (text of the service: untrusted);
/// - 'invalid': the answer was not what the API describes, or the request was not one this page makes.
/// `retryAfter` is in seconds, for 429 and 503.
export class ApiFailure extends Error {
  constructor(kind, { status = null, code = null, serverMessage = null, retryAfter = null, body = null } = {}) {
    super(`API ${kind}${status ? ` ${status}` : ''}${code ? ` ${code}` : ''}`);
    Object.assign(this, { kind, status, code, serverMessage, retryAfter, body });
  }
}

/// The API origin from the page's one configuration value. Empty: the origin the page came from.
/// Anything that is not a plain http(s) origin is refused, so the value cannot smuggle a path,
/// a user name or another scheme.
export function apiOrigin(value) {
  if (value === undefined || value === null || value === '') return '';
  let url;
  try { url = new URL(value); } catch { throw new Error('The API origin is not an address'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.origin !== value) throw new Error('The API origin is a plain origin such as https://api.example');
  return url.origin;
}

export function createApi({ origin = '', fetcher = globalThis.fetch?.bind(globalThis), timeoutMs = 15000, maxBytes = 8 * 1024 * 1024 } = {}) {
  const invalid = () => new ApiFailure('invalid');
  async function get(path) {
    let response, text;
    try {
      response = await fetcher(origin + path, { method: 'GET', cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(timeoutMs) });
      text = await response.text();
    } catch { throw new ApiFailure('network'); }
    if (text.length > maxBytes) throw invalid();
    let body = null;
    try { body = JSON.parse(text); } catch { body = null; }
    const plain = body !== null && typeof body === 'object' && !Array.isArray(body);
    if (!response.ok) {
      const error = plain && body.error && typeof body.error === 'object' ? body.error : {};
      const wait = Number(response.headers?.get?.('retry-after'));
      throw new ApiFailure('http', {
        status: response.status, body: plain ? body : null,
        code: typeof error.code === 'string' && /^[a-z_]{1,40}$/.test(error.code) ? error.code : null,
        serverMessage: typeof error.message === 'string' ? error.message : null,
        retryAfter: [429, 503].includes(response.status) ? (Number.isInteger(wait) && wait >= 1 && wait <= 3600 ? wait : 5) : null,
      });
    }
    if (!plain) throw invalid();
    return body;
  }
  const height = (value) => { if (!isHeight(value)) throw invalid(); return value; };
  const id = (value) => { if (!isAccountId(value)) throw invalid(); return value; };
  /// `limit` and `cursor` as a query. A cursor is sent back only in the form the API gives it.
  function page({ limit, cursor } = {}) {
    const parts = [];
    if (limit !== undefined) { if (!Number.isInteger(limit) || limit < 1 || limit > 200) throw invalid(); parts.push(`limit=${limit}`); }
    if (cursor !== undefined && cursor !== null) { if (!isCursor(cursor)) throw invalid(); parts.push(`cursor=${cursor}`); }
    return parts.length ? `?${parts.join('&')}` : '';
  }
  return {
    origin,
    status: () => get('/v1/status'),
    blocks: (options) => get(`/v1/blocks${page(options)}`),
    block: (h) => get(`/v1/blocks/${height(h)}`),
    blockActions: (h, options) => get(`/v1/blocks/${height(h)}/actions${page(options)}`),
    blockProof: (h) => get(`/v1/blocks/${height(h)}/proof`),
    lightBlock: (h) => get(`/v1/light-blocks/${height(h)}`),
    action: (hash) => { if (!isHash(hash)) throw invalid(); return get(`/v1/actions/${hash.toUpperCase()}`); },
    /// By number, or by name (sent with "@", so that a name of digits is not read as a number).
    account: ({ id: number, name }) => { if (number !== undefined) return get(`/v1/accounts/${id(number)}`); if (!isName(name)) throw invalid(); return get(`/v1/accounts/@${name}`); },
    accountState: (number) => get(`/v1/accounts/${id(number)}/state`),
    activity: (number, options) => get(`/v1/accounts/${id(number)}/activity${page(options)}`),
    validators: () => get('/v1/validators'),
    /// The address of the event stream, resuming after the event with id `after` if given.
    streamUrl: (after) => `${origin}/v1/stream${typeof after === 'string' && /^[1-9][0-9]{0,15}(?:\.(?:0|[1-9][0-9]{0,5}))?$/.test(after) ? `?after=${after}` : ''}`,
  };
}

/// Follows the event stream and keeps it open.
/// - `open(url)` returns an EventSource (the browser's, or a stand-in in tests).
/// - `listen({ onEvent, onState })` names who is told: `onEvent({ type, data })` gets each `block`,
///   `payment` and `gap` event, parsed; `onState(state)` is told 'connecting', 'live', 'waiting'
///   (a retry is scheduled) or 'idle'.
/// The browser's own reconnection is not used: after any error the source is closed and opened
/// again here, after a pause that grows, from the last event received. That also covers what an
/// EventSource gives up on (a 429 or 503 answer), and the `bye` the server sends when it ends a
/// stream on its side. After a `bye` the stream is reopened at once the first time; a server
/// that keeps ending streams which carried nothing is come back to after a pause that grows too,
/// since every opening costs the reader part of its allowance.
export function createLive({ api, open, timers = globalThis, pauses = [2000, 5000, 15000, 30000, 60000] }) {
  let source = null, timer = null, lastId = null, failures = 0, empty = 0, stopped = true, state = 'idle', onEvent = () => {}, onState = () => {};
  const set = (next) => { if (state !== next) { state = next; onState(next); } };
  const parse = (event) => { try { const data = JSON.parse(event.data); return data && typeof data === 'object' ? data : null; } catch { return null; } };
  function close() { if (source) { try { source.close(); } catch { /* closed already */ } source = null; } }
  function later(ms) {
    close();
    if (stopped) return;
    set('waiting');
    timer = timers.setTimeout(() => { timer = null; connect(); }, ms);
  }
  function connect() {
    if (stopped) return;
    close();
    set('connecting');
    let current;
    try { current = source = open(api.streamUrl(lastId)); } catch { later(pauses[Math.min(failures++, pauses.length - 1)]); return; }
    const mine = (handler) => (event) => { if (source === current && !stopped) handler(event); };
    const remember = (event) => { if (typeof event.lastEventId === 'string' && /^[1-9][0-9]{0,15}(?:\.(?:0|[1-9][0-9]{0,5}))?$/.test(event.lastEventId)) lastId = event.lastEventId; };
    current.addEventListener('hello', mine(() => { failures = 0; set('live'); }));
    for (const type of ['block', 'payment']) current.addEventListener(type, mine((event) => { empty = 0; remember(event); const data = parse(event); if (data) onEvent({ type, data }); }));
    current.addEventListener('gap', mine((event) => { onEvent({ type: 'gap', data: parse(event) ?? {} }); }));
    // The server ended the stream on its side: come back at once, from the last event; later
    // and later if the streams it ends carried no event at all.
    current.addEventListener('bye', mine(() => { empty += 1; later(empty <= 1 ? 500 : pauses[Math.min(empty - 2, pauses.length - 1)]); }));
    current.addEventListener('error', mine(() => later(pauses[Math.min(failures++, pauses.length - 1)])));
  }
  return {
    listen(handlers) { onEvent = handlers.onEvent ?? (() => {}); onState = handlers.onState ?? (() => {}); },
    start() { if (!stopped) return; stopped = false; connect(); },
    stop() { stopped = true; if (timer !== null) { timers.clearTimeout(timer); timer = null; } close(); set('idle'); },
    state: () => state,
  };
}
