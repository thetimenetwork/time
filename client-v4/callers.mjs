// Who is asking, as the wallet's gateway (server.mjs) and the test network's proxy (testnet/proxy.mjs) count it for
// their limits, and the token buckets they count with. Nothing but Node's own modules.
//
// A caller is an IPv4 address, or an IPv6 /64: one subscriber's network is given a /64 at least, and each of its 2^64
// addresses is the same caller (the API counts the same way: clientKey in api.mjs). Around a /64 stands its /48, what
// one site or customer is commonly given: its 65,536 /64s are one network, which shares a larger limit, so that a
// network cannot multiply itself by its /64s. An IPv4 address has no network around it here.
import net from 'node:net';

/// An IP address in one spelling: IPv4 as it is, IPv6 as its eight groups (lower case, no leading zeros). Null if the
/// text is neither. A port ("203.0.113.9:1234", "[2001:db8::1]:1234"), a zone and the IPv4-in-IPv6 form are removed
/// first, since proxies write all of these.
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
/// The key a caller is limited under: its IPv4 address, or its IPv6 /64. 'unknown' for what is not an address: all
/// such requests are one caller.
export function callerKey(address) {
  const ip = normalIp(address);
  if (ip === null) return 'unknown';
  return ip.includes(':') ? `${ip.split(':').slice(0, 4).join(':')}::/64` : ip;
}
/// The network around a caller: the /48 of an IPv6 address; null for an IPv4 address and for what is not an address.
export function networkKey(address) {
  const ip = normalIp(address);
  return ip !== null && ip.includes(':') ? `${ip.split(':').slice(0, 3).join(':')}::/48` : null;
}
/// Whether an address is one of this machine's own (127.0.0.0/8 or ::1).
export function isLoopback(address) {
  const ip = normalIp(address);
  return ip !== null && (ip === '0:0:0:0:0:0:0:1' || /^127\./.test(ip));
}

/// A token bucket per key, all at one rate: `burst` requests at once, refilled at `perSecond`. The table holds at most
/// `max` keys. It is never emptied at once (until 24 November 2026 the test network's proxy cleared its table at 20,000
/// keys, and every caller had its burst back): when a new key comes to a full table, a tenth of the keys are forgotten,
/// those whose buckets are fullest, and among equally full ones those used least recently. A forgotten key starts with
/// a full bucket again, so the fullest are those whose forgetting gives back least; a caller that has used its burst
/// keeps its empty bucket however many new keys come.
export function createBuckets({ perSecond = 20, burst = 60, now = Date.now, max = 20000 } = {}) {
  if (!(perSecond > 0) || !(burst >= 1) || !Number.isSafeInteger(max) || max < 1) throw new Error('A bucket has a positive rate, a burst of at least one, and a table of at least one key');
  const buckets = new Map();
  const level = (b, at) => Math.min(burst, b.tokens + (Math.max(0, at - b.at) / 1000) * perSecond);
  function forget(at) {
    // The table is in the order of use, the least recent first; a stable sort keeps that order among equals.
    const fullest = [...buckets].map(([key, b]) => [level(b, at), key]).sort((x, y) => y[0] - x[0]);
    for (const [, key] of fullest.slice(0, Math.max(1, Math.ceil(max / 10)))) buckets.delete(key);
  }
  // The bucket of a key, refilled to now and moved to the end of the table (the most recently used).
  function bucket(key) {
    const at = now();
    let b = buckets.get(key);
    if (b) buckets.delete(key);
    else { if (buckets.size >= max) forget(at); b = { tokens: burst, at }; }
    b.tokens = level(b, at); b.at = at;
    buckets.set(key, b);
    return b;
  }
  return {
    /// Takes one token; false when the key has none.
    take(key) { const b = bucket(key); if (b.tokens < 1) return false; b.tokens -= 1; return true; },
    /// Whether the key has a token, without taking it.
    can(key) { return bucket(key).tokens >= 1; },
    /// Milliseconds until the key has a token again (0: it has one now).
    wait(key) { const b = bucket(key); return b.tokens >= 1 ? 0 : Math.ceil(((1 - b.tokens) / perSecond) * 1000); },
    size: () => buckets.size,
  };
}
/// The seconds a refusal tells a caller to wait (its Retry-After): whole seconds, from 1 to 30.
export const retrySeconds = (ms) => Math.min(30, Math.max(1, Math.ceil(ms / 1000)));

/// A fair line for work that must run few at a time (the gateway's checks, which its light client does one at a time
/// for both of its origins). `slots` pieces of work run at once; the others wait, at most `size` of them, each for at
/// most `waitMs`. Who asks is { caller, network } (callers.mjs keys) or, for the service's own work, nothing: that runs
/// at once, outside the line.
/// - The line is served fairly, not in the order of arrival: the next place goes to the waiting piece whose network
///   (its /48, or for an IPv4 address the address itself) has the fewest pieces under way (running or waiting), then
///   whose caller has the fewest, then to the one that came first. A caller that asks for one check goes before one
///   that asks for fifty, and one network that asks from many of its /64s goes after everybody else.
/// - When the line is full, a newcomer that ranks before the last of the line takes its place, and the last is refused:
///   when the service is saturated, the caller that asks most is the one refused, not the one that comes next.
/// - One caller may have at most `callerShare` of `size` under way, one network `networkShare`: a share of the line,
///   which honest wallets behind one address do not reach, so that one caller alone cannot fill it.
/// Callers not told apart (`caller` null: a gateway without trusted proxies) are one: the line is then first come,
/// first served, and a newcomer finding it full is refused. A refusal is the error `busy()` makes.
export function createFairLine({ slots = 1, size = 256, callerShare = 1 / 2, networkShare = 3 / 4, waitMs = 8000, busy }) {
  if (!Number.isSafeInteger(slots) || slots < 1 || !Number.isSafeInteger(size) || size < 1 || !(callerShare > 0 && callerShare <= 1) || !(networkShare > 0 && networkShare <= 1) || !(waitMs > 0) || typeof busy !== 'function') throw new Error('A fair line has slots, a size, shares between 0 and 1, a wait and a refusal');
  const underWay = new Map(), waiting = [], seen = { most: 0, mostOfOne: 0, refused: 0 }; let running = 0, arrivals = 0;
  const count = (key) => (key === null ? 0 : underWay.get(key) ?? 0);
  const add = (key, n) => { if (key === null) return; const next = count(key) + n; if (next > 0) underWay.set(key, next); else underWay.delete(key); };
  const rank = (entry) => [count(entry.network), count(entry.caller), entry.order];
  const before = (a, b) => { const x = rank(a), y = rank(b); for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] < y[i]; return false; };
  const leave = (entry) => { add(entry.caller, -1); add(entry.network, -1); };
  const refuse = (entry, reject) => { leave(entry); seen.refused += 1; reject(busy()); };
  function start(entry) {
    running += 1;
    Promise.resolve().then(entry.work).then(entry.resolve, entry.reject).finally(() => {
      running -= 1; leave(entry);
      if (!waiting.length) return;
      let best = 0;
      for (let i = 1; i < waiting.length; i++) if (before(waiting[i], waiting[best])) best = i;
      const [next] = waiting.splice(best, 1);
      clearTimeout(next.timer); start(next);
    });
  }
  return {
    /// Runs `work` (a function) for `who`, after waiting for a place if need be.
    run(who, work) {
      if (!who) return Promise.resolve().then(work);
      return new Promise((resolve, reject) => {
        const caller = who.caller ? `caller|${who.caller}` : null, network = who.caller ? `network|${who.network ?? who.caller}` : null;
        if (caller !== null && (count(caller) >= Math.max(1, Math.floor(size * callerShare)) || count(network) >= Math.max(1, Math.floor(size * networkShare)))) { seen.refused += 1; reject(busy()); return; }
        const entry = { caller, network, order: arrivals++, work, resolve, reject, timer: null };
        add(caller, 1); add(network, 1); seen.mostOfOne = Math.max(seen.mostOfOne, count(caller));
        if (running < slots) { start(entry); seen.most = Math.max(seen.most, waiting.length + running); return; }
        if (waiting.length >= size) {
          let last = 0;
          for (let i = 1; i < waiting.length; i++) if (before(waiting[last], waiting[i])) last = i;
          if (!before(entry, waiting[last])) { refuse(entry, reject); return; }
          const [out] = waiting.splice(last, 1);
          clearTimeout(out.timer); refuse(out, out.reject);
        }
        entry.timer = setTimeout(() => { const at = waiting.indexOf(entry); if (at >= 0) { waiting.splice(at, 1); refuse(entry, reject); } }, waitMs);
        entry.timer.unref?.();
        waiting.push(entry); seen.most = Math.max(seen.most, waiting.length + running);
      });
    },
    /// What the line holds now and has seen: running, waiting, the most at once, the most of one caller, refusals.
    status: () => ({ running, waiting: waiting.length, most: seen.most, mostOfOne: seen.mostOfOne, refused: seen.refused }),
  };
}
