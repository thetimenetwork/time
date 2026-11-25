// A person's own randomness, added to the passwords the wallet makes.
//
// Before the wallet makes a password, the page may ask the person to move a mouse or a finger around (or to press keys)
// until a meter is full, as a phone asks for a finger again and again until it has the whole fingerprint
// (entropy-dialog.mjs). What they did is gathered here: where the pointer was and when, to the finest time the browser
// gives. All of it goes through SHA-512 into 64 bytes, the pool.
//
// MIXED IN, NEVER INSTEAD. A made password is 9 bytes of the browser's own generator (crypto.getRandomValues), as before;
// 9 bytes of the pool are then XORed into them (mixInto). Bytes of a good generator XORed with anything that does not
// depend on them are as random as they were, so nothing gathered here, and nothing a script could put in the pool, can
// make a password weaker or known. If the browser's generator were ever weak, the pool is what the password would still
// have. That is the whole reason for this step; the browser's generator alone is strong.
//
// THE METER IS AN ESTIMATE. Nobody can measure how unpredictable a hand is. The meter credits little: 2 bits for a
// pointer sample that moved at least a few pixels and came a few milliseconds after the last credited one, 1 bit for a
// key pressed (its time only: which key is not kept), and asks for 256 bits, a few seconds of movement. Every sample
// goes into the pool, credited or not. No password's strength is claimed from the meter.
//
// Offline: no network access and no storage in this module. Pool bytes are used once and wiped as they are used; the
// pool is forgotten two minutes after it was gathered, and when the wallet locks.

const DOMAIN = new TextEncoder().encode('TCDEVNET-WALLET-GATHERED-V1\0');
export const GATHER = Object.freeze({ targetBits: 256, pointerBits: 2, keyBits: 1, minPixels: 6, minPointerMs: 4, minKeyMs: 25, maxSamples: 8192, poolBytes: 64, poolMs: 120000, perPassword: 9 });
const FIELDS = 8;

/// What is gathered in one filling of the meter. `pointer({ x, y, t, sx, sy, pressure, kind })`: a pointer sample (page
/// and screen coordinates, the event's time, 0 for a mouse, 1 for a finger, 2 for a pen); `key({ t })`: a key went down.
/// Both return the progress, 0 to 1. `finish()` gives the 64 bytes of what was gathered and wipes the samples.
export function createMeter({ clock = () => globalThis.performance?.now?.() ?? Date.now(), subtle = globalThis.crypto.subtle } = {}) {
  let values = [], bits = 0, last = null, lastKey = -Infinity, done = false;
  const number = value => (Number.isFinite(value) ? value : 0);
  const keep = fields => { if (values.length < GATHER.maxSamples * FIELDS) values.push(...fields.map(number)); };
  const progress = () => Math.min(1, bits / GATHER.targetBits);
  return {
    pointer({ x, y, t, sx = 0, sy = 0, pressure = 0, kind = 0 }) {
      if (done) return progress();
      keep([1 + number(kind), x, y, sx, sy, pressure, t, clock()]);
      const moved = last === null ? Infinity : Math.hypot(number(x) - last.x, number(y) - last.y), waited = last === null ? Infinity : number(t) - last.t;
      if (moved >= GATHER.minPixels && waited >= GATHER.minPointerMs) { bits += GATHER.pointerBits; last = { x: number(x), y: number(y), t: number(t) }; }
      return progress();
    },
    key({ t }) {
      if (done) return progress();
      keep([0, 0, 0, 0, 0, 0, t, clock()]);
      if (number(t) - lastKey >= GATHER.minKeyMs) { bits += GATHER.keyBits; lastKey = number(t); }
      return progress();
    },
    get progress() { return progress(); },
    get full() { return bits >= GATHER.targetBits; },
    get samples() { return values.length / FIELDS; },
    async finish() {
      done = true;
      const data = new Float64Array(values), bytes = new Uint8Array(data.buffer), input = new Uint8Array(DOMAIN.length + bytes.length);
      input.set(DOMAIN); input.set(bytes, DOMAIN.length);
      try { return new Uint8Array(await subtle.digest('SHA-512', input)); } finally { input.fill(0); data.fill(0); values.fill(0); values = []; }
    },
    wipe() { done = true; values.fill(0); values = []; bits = 0; },
  };
}

// ---- the pool --------------------------------------------------------------------------------------------------------
let pool = null, used = 0, born = 0, gatherer = null;
const stale = () => pool !== null && Date.now() - born > GATHER.poolMs;
/// Forgets what was gathered (the wallet locked, or two minutes passed).
export function forgetGathered() { pool?.fill(0); pool = null; used = 0; }
/// How many bytes of the pool are still unused.
export function gathered() { if (stale()) forgetGathered(); return pool === null ? 0 : pool.length - used; }
/// Puts what a person gathered in the pool (64 bytes of a meter's `finish`), in place of what was left of it.
export function stir(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== GATHER.poolBytes) throw new TypeError('What was gathered is 64 bytes.');
  forgetGathered(); pool = new Uint8Array(bytes); born = Date.now();
}
/// XORs unused bytes of the pool into `bytes`, and wipes them in the pool: each is used once. With less left in the pool
/// than `bytes` is long, `bytes` stays as it is: the browser's own randomness alone. Returns how many bytes were mixed in.
export function mixInto(bytes) {
  if (!(bytes instanceof Uint8Array) || gathered() < bytes.length) return 0;
  for (let i = 0; i < bytes.length; i++) { bytes[i] ^= pool[used + i]; pool[used + i] = 0; }
  used += bytes.length;
  if (used >= pool.length) forgetGathered();
  return bytes.length;
}
/// The page's way of asking the person (entropy-dialog.mjs, through app.js): a function that resolves with 64 gathered
/// bytes, or with null when the person went on without, or the page cannot ask; it rejects when the person closed it.
/// Without one (a page that has none, a test), passwords are made of the browser's own randomness alone.
export function setGatherer(ask) { gatherer = typeof ask === 'function' ? ask : null; }
/// Called before `count` passwords are made, and before anything secret is opened or held for them: asks the person,
/// unless the pool still has enough for them. A rejection (the person closed the step) ends the caller's step with
/// nothing made.
export async function readyToMake(count = 1) {
  if (gatherer === null || gathered() >= count * GATHER.perPassword) return;
  const bytes = await gatherer();
  if (bytes) { try { stir(bytes); } finally { bytes.fill(0); } }
}
