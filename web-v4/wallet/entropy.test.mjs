// A person's own randomness (entropy.mjs, entropy-dialog.mjs): what the meter credits, what goes into the pool, that a
// made password is the browser's own random bytes with the pool XORed in and never the pool alone, that pool bytes are
// used once, forgotten after two minutes and on demand, when the person is asked and when not, the dialog from its first
// movement to full, "Go on without this", Escape, a page that cannot draw, and that neither module reaches a network or
// a storage.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash, webcrypto } from 'node:crypto';

const root = new URL('../../', import.meta.url);
const at = name => new URL(`web-v4/wallet/${name}`, root);
const { GATHER, createMeter, stir, mixInto, gathered, forgetGathered, setGatherer, readyToMake } = await import(at('entropy.mjs').href);
const { GATHER_WORDS, FULL, SKIP, gatherDialog } = await import(at('entropy-dialog.mjs').href);
const { makePassword, madeText, madeForm, MADE_PASSWORD } = await import(at('vault.mjs').href);
const { sealedKeys } = await import(at('security-flows.mjs').href);

const argon2id = async ({ password, salt }) => new Uint8Array(createHash('sha256').update(Buffer.from(password)).update(Buffer.from(salt)).digest());
const NET = 'ab'.repeat(32);
/// A hand that moves: sample `i` of a path that never stays within the meter's few pixels, 8 ms apart.
const hand = i => ({ x: 100 + (i * 37) % 400, y: 80 + (i * 53) % 200, sx: 300 + (i * 37) % 400, sy: 280 + (i * 53) % 200, pressure: 0.5, kind: 0, t: 1000 + i * 8 });
const pointerSamples = GATHER.targetBits / GATHER.pointerBits;

test('the meter: a pointer sample that moved and waited is credited 2 bits, one that did not is credited nothing, a key 1 bit; all of them are gathered', async () => {
  let tick = 5000;
  const meter = createMeter({ clock: () => (tick += 0.25), subtle: webcrypto.subtle });
  assert.equal(meter.progress, 0);
  assert.equal(meter.pointer(hand(0)), GATHER.pointerBits / GATHER.targetBits, 'the first sample is credited');
  // The same place again, and a place too near, and a place far enough but too soon: gathered, not credited.
  assert.equal(meter.pointer(hand(0)), GATHER.pointerBits / GATHER.targetBits);
  assert.equal(meter.pointer({ ...hand(0), x: hand(0).x + GATHER.minPixels - 1, t: hand(0).t + 100 }), GATHER.pointerBits / GATHER.targetBits);
  assert.equal(meter.pointer({ ...hand(1), t: hand(0).t + GATHER.minPointerMs - 1 }), GATHER.pointerBits / GATHER.targetBits);
  assert.equal(meter.samples, 4, 'every sample is kept for the pool');
  assert.equal(meter.pointer(hand(1)), 2 * GATHER.pointerBits / GATHER.targetBits);
  // Keys: their time only. One too soon after another is not credited.
  assert.equal(meter.key({ t: 9000 }), (2 * GATHER.pointerBits + GATHER.keyBits) / GATHER.targetBits);
  assert.equal(meter.key({ t: 9000 + GATHER.minKeyMs - 1 }), (2 * GATHER.pointerBits + GATHER.keyBits) / GATHER.targetBits);
  assert.equal(meter.key({ t: 9000 + GATHER.minKeyMs }), (2 * GATHER.pointerBits + 2 * GATHER.keyBits) / GATHER.targetBits);
  assert.equal(meter.full, false);
  // A value that is no number (a browser that gives no pressure) is gathered as zero, and breaks nothing.
  meter.pointer({ x: 1, y: 2, t: 1e6, pressure: undefined, sx: NaN });
  const bytes = await meter.finish();
  assert.ok(bytes instanceof Uint8Array && bytes.length === GATHER.poolBytes && bytes.length === 64);
  assert.equal(meter.samples, 0, 'the samples are wiped once they are hashed');
  assert.equal(meter.pointer(hand(9)), meter.progress, 'nothing is gathered after the end');
});

test('the meter is full after 256 credited bits: 128 pointer samples, or 256 keys; the 64 bytes are the SHA-512 of everything gathered, in order', async () => {
  const fill = async (clockStart, shift = 0) => {
    let tick = clockStart;
    const meter = createMeter({ clock: () => (tick += 1), subtle: webcrypto.subtle });
    for (let i = 0; i < pointerSamples; i++) { assert.equal(meter.full, false, `not full at ${i}`); meter.pointer({ ...hand(i), x: hand(i).x + shift }); }
    assert.equal(meter.full, true); assert.equal(meter.progress, 1);
    return meter.finish();
  };
  const a = await fill(0), again = await fill(0), other = await fill(0, 1), later = await fill(7);
  assert.deepEqual(a, again, 'the same movements at the same times give the same bytes');
  assert.notDeepEqual(a, other, 'one pixel of difference gives other bytes');
  assert.notDeepEqual(a, later, 'the same movements at other times give other bytes');
  assert.ok(new Set(a).size > 20, 'not a constant');
  const keys = createMeter({ subtle: webcrypto.subtle });
  for (let i = 0; i < GATHER.targetBits / GATHER.keyBits; i++) { assert.equal(keys.full, false); keys.key({ t: i * GATHER.minKeyMs }); }
  assert.equal(keys.full, true, 'a person without a pointer fills it with keys');
  // Far more samples than the meter keeps: it stays full and still ends.
  const many = createMeter({ subtle: webcrypto.subtle });
  for (let i = 0; i < GATHER.maxSamples + 50; i++) many.pointer(hand(i));
  assert.equal(many.samples, GATHER.maxSamples);
  assert.equal((await many.finish()).length, 64);
});

test('the pool: 64 bytes, each used once and wiped as it is used; too little left mixes nothing; forgotten on demand and after two minutes', () => {
  forgetGathered();
  assert.equal(gathered(), 0);
  assert.throws(() => stir(new Uint8Array(32)), /64 bytes/);
  assert.throws(() => stir('x'.repeat(64)), /64 bytes/);
  const pool = Uint8Array.from({ length: 64 }, (_, i) => i + 1);
  stir(pool);
  assert.equal(gathered(), 64);
  const first = new Uint8Array(9).fill(0xf0);
  assert.equal(mixInto(first), 9);
  assert.deepEqual([...first], [1, 2, 3, 4, 5, 6, 7, 8, 9].map(v => v ^ 0xf0), 'XORed in');
  assert.equal(gathered(), 55);
  const second = new Uint8Array(9);
  mixInto(second);
  assert.deepEqual([...second], [10, 11, 12, 13, 14, 15, 16, 17, 18], 'the next bytes, never the same ones again');
  assert.deepEqual([...pool].slice(0, 3), [1, 2, 3], 'the caller\'s array is its own: the pool is a copy');
  // 46 bytes are left: five passwords more, then one byte, which is too little and mixes nothing.
  for (let i = 0; i < 5; i++) assert.equal(mixInto(new Uint8Array(9)), 9);
  assert.equal(gathered(), 1);
  const alone = new Uint8Array(9).fill(7);
  assert.equal(mixInto(alone), 0);
  assert.deepEqual([...alone], Array(9).fill(7), 'left as the browser made it');
  assert.equal(mixInto('not bytes'), 0);
  // Forgotten on demand (the wallet locks).
  stir(pool); forgetGathered(); assert.equal(gathered(), 0);
  // Forgotten two minutes after it was gathered.
  const realNow = Date.now;
  try {
    let now = 1_000_000; Date.now = () => now;
    stir(pool); now += GATHER.poolMs; assert.equal(gathered(), 64, 'still there at two minutes');
    now += 1; assert.equal(gathered(), 0, 'gone after');
    assert.equal(mixInto(new Uint8Array(9)), 0);
  } finally { Date.now = realNow; forgetGathered(); }
});

test('a made password is the browser\'s own 9 random bytes with 9 pool bytes XORed in: mixed in, never instead; without a pool, the browser\'s bytes alone', () => {
  forgetGathered();
  const real = globalThis.crypto.getRandomValues;
  const browser = Uint8Array.from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99]);
  try {
    // A browser whose generator gives these bytes (the test's only way to know them).
    globalThis.crypto.getRandomValues = array => { array.set(browser.subarray(0, array.length)); return array; };
    assert.equal(makePassword().text, madeText(browser), 'no pool: the browser\'s bytes');
    const pool = Uint8Array.from({ length: 64 }, (_, i) => 200 - i);
    stir(pool);
    const xored = (offset) => madeText(browser.map((b, i) => b ^ pool[offset + i]));
    assert.equal(makePassword().text, xored(0));
    assert.equal(makePassword().text, xored(9), 'the second password takes the next pool bytes');
    assert.notEqual(xored(0), madeText(pool.subarray(0, 9)), 'never the pool alone');
    // A pool of zeros, which a script could put in: the password is exactly the browser's bytes. Nothing in the pool
    // takes anything away.
    stir(new Uint8Array(64));
    assert.equal(makePassword().text, madeText(browser));
  } finally { globalThis.crypto.getRandomValues = real; forgetGathered(); }
  // With the real generator and one pool put in again and again, as a hostile script could: every password is still
  // different, in the wallet's form, and fresh.
  const seen = new Set();
  for (let i = 0; i < 500; i++) { stir(new Uint8Array(64).fill(0x5a)); const made = makePassword(); assert.equal(madeForm(made.text), made.text); assert.equal(made.fresh, true); seen.add(made.text); }
  assert.equal(seen.size, 500);
  assert.equal(MADE_PASSWORD.bytes, GATHER.perPassword, 'the pool is counted in the bytes of a made password');
  forgetGathered();
});

test('the person is asked before passwords are made, once for what is needed, and not while the pool still has enough; a page that asks nothing changes nothing', async () => {
  forgetGathered(); setGatherer(null);
  await readyToMake(2);
  assert.equal(gathered(), 0, 'no page to ask: the browser\'s randomness alone');
  let asked = 0, answer = () => new Uint8Array(64).fill(3);
  setGatherer(async () => { asked += 1; return answer(); });
  try {
    await readyToMake(2);
    assert.deepEqual([asked, gathered()], [1, 64]);
    makePassword(); makePassword();
    await readyToMake(2);
    assert.equal(asked, 1, '46 bytes are left: enough for two more');
    for (let i = 0; i < 4; i++) makePassword();
    assert.equal(gathered(), 10);
    await readyToMake(1); assert.equal(asked, 1, 'enough for one');
    await readyToMake(2); assert.equal(asked, 2, 'not enough for two: asked again, and the pool is new');
    assert.equal(gathered(), 64);
    // "Go on without this": nothing is put in the pool, and what was left of it stays as it was.
    forgetGathered(); answer = () => null;
    await readyToMake(1);
    assert.deepEqual([asked, gathered()], [3, 0]);
    // The person closed the step: the caller's step ends.
    answer = () => { throw Object.assign(new Error(GATHER_WORDS.closed), { notGathered: true }); };
    await assert.rejects(readyToMake(1), error => error.notGathered === true && error.message === GATHER_WORDS.closed);
    // What a page hands over is wiped once it is in the pool.
    const handed = new Uint8Array(64).fill(9); answer = () => handed;
    await readyToMake(1);
    assert.deepEqual([...handed], Array(64).fill(0));
  } finally { setGatherer(null); forgetGathered(); }
});

test('new keys under passwords the wallet makes ask the person first, before any key is made; keys locked to the device ask nothing; a closed step makes nothing', async () => {
  forgetGathered();
  let asked = 0, close = false;
  const made = [];
  const cryptoImpl = { getRandomValues: array => webcrypto.getRandomValues(array), subtle: { ...webcrypto.subtle, generateKey: (...args) => { made.push(asked); return webcrypto.subtle.generateKey(...args); }, exportKey: (...args) => webcrypto.subtle.exportKey(...args), importKey: (...args) => webcrypto.subtle.importKey(...args), sign: (...args) => webcrypto.subtle.sign(...args), digest: (...args) => webcrypto.subtle.digest(...args), deriveBits: (...args) => webcrypto.subtle.deriveBits(...args), deriveKey: (...args) => webcrypto.subtle.deriveKey(...args), encrypt: (...args) => webcrypto.subtle.encrypt(...args), decrypt: (...args) => webcrypto.subtle.decrypt(...args) } };
  setGatherer(async () => { asked += 1; if (close) throw Object.assign(new Error(GATHER_WORDS.closed), { notGathered: true }); return new Uint8Array(64).fill(1); });
  try {
    const keys = await sealedKeys({ wanted: [{ intent: 'signin' }, { intent: 'spend' }], networkId: NET, name: 'alice', argon2id, cryptoImpl });
    assert.equal(asked, 1, 'asked once for both passwords');
    assert.ok(made.length >= 2 && made.every(count => count === 1), 'every key was made after the person was asked');
    assert.deepEqual(keys.map(key => madeForm(key.made) === key.made), [true, true]);
    assert.equal(gathered(), 64 - 18, 'both passwords took their bytes of the pool');
    // Locked to the device: the passwords are the person's own, and nothing is asked.
    forgetGathered(); made.length = 0;
    const locked = await sealedKeys({ wanted: [{ intent: 'signin', password: 'a password chosen for the device lock 1' }, { intent: 'spend', password: 'another password chosen for the lock 2' }], networkId: NET, name: 'alice', argon2id, cryptoImpl,
      lock: async list => ({ credential: 'A'.repeat(22), secrets: list.map(() => webcrypto.getRandomValues(new Uint8Array(32))) }) });
    assert.equal(asked, 1, 'not asked again');
    assert.deepEqual(locked.map(key => key.made ?? null), [null, null]);
    // The person closes the step: no key is made at all.
    close = true; made.length = 0;
    await assert.rejects(sealedKeys({ wanted: [{ intent: 'signin' }, { intent: 'spend' }], networkId: NET, name: 'alice', argon2id, cryptoImpl }), error => error.notGathered === true);
    assert.deepEqual(made, [], 'nothing was made');
  } finally { setGatherer(null); forgetGathered(); }
});

// ---- the dialog, on a stand-in page ------------------------------------------------------------------------------------
class El {
  constructor(id) { Object.assign(this, { id, textContent: '', value: 0, disabled: false, open: false, returnValue: '', listeners: {}, focused: 0 }); }
  addEventListener(type, fn, options) { (this.listeners[type] ??= []).push({ fn, once: options?.once === true }); }
  emit(type, event = {}) { const list = this.listeners[type] ?? []; this.listeners[type] = list.filter(item => !item.once); for (const item of list) item.fn(event); }
  showModal() { this.open = true; }
  close(value) { if (!this.open) return; this.open = false; if (value !== undefined) this.returnValue = value; this.emit('close'); }
  focus() { this.focused += 1; }
}
function page({ canvas = true } = {}) {
  const els = new Map(), drawn = [], $ = id => { if (!els.has(id)) els.set(id, new El(id)); return els.get(id); };
  const pad = $('gather-pad');
  Object.assign(pad, { width: 640, height: 260, getBoundingClientRect: () => ({ left: 20, top: 100, width: 320, height: 130 }) });
  if (canvas) pad.getContext = () => ({ beginPath() {}, arc(x, y) { drawn.push([x, y]); }, fill() {}, clearRect() { drawn.length = 0; drawn.cleared = (drawn.cleared ?? 0) + 1; } });
  const gather = gatherDialog($, { style: () => ({ color: 'rgb(1, 2, 3)' }) });
  const move = (i, extra = {}) => $('gather-dialog').emit('pointermove', { clientX: hand(i).x, clientY: hand(i).y, screenX: hand(i).sx, screenY: hand(i).sy, pressure: 0.5, pointerType: 'mouse', timeStamp: hand(i).t, ...extra });
  return { $, gather, move, drawn };
}
const settle = () => new Promise(resolve => setTimeout(resolve, 20));

test('the dialog: its words, the meter from nothing to full as a person moves, said in steps of ten, the trail drawn in the box, and closed by itself with 64 bytes', async () => {
  const { $, gather, move, drawn } = page();
  assert.deepEqual(['gather-title', 'gather-why', 'gather-skip', 'gather-skip-note'].map(id => $(id).textContent), [GATHER_WORDS.title, GATHER_WORDS.why, GATHER_WORDS.skip, GATHER_WORDS.skipNote]);
  assert.match(GATHER_WORDS.why, /^Move your mouse or your finger around inside the box.*press keys too.*on top of this device's own randomness\. Nothing of it leaves this page\.$/);
  const result = gather();
  assert.deepEqual([$('gather-dialog').open, $('gather-progress').value, $('gather-said').textContent, $('gather-skip').disabled, $('gather-title').focused], [true, 0, GATHER_WORDS.start, false, 1]);
  const said = new Set();
  for (let i = 0; i < pointerSamples - 1; i++) { move(i); said.add($('gather-said').textContent); assert.equal($('gather-dialog').open, true, `still open at ${i}`); }
  assert.equal($('gather-progress').value, 99);
  assert.ok(said.has(GATHER_WORDS.percent(50)) && said.has(GATHER_WORDS.percent(90)) && said.size <= 11, [...said].join(' | '));
  // Inside the box (20..340 by 100..230 on the page) a movement is drawn, scaled to the canvas; outside it is not.
  assert.ok(drawn.length > 10 && drawn.every(([x, y]) => x >= 0 && x <= 640 && y >= 0 && y <= 260));
  const before = drawn.length;
  $('gather-dialog').emit('pointermove', { clientX: 900, clientY: 900, screenX: 1, screenY: 1, pressure: 0, pointerType: 'mouse', timeStamp: 5 });
  assert.equal(drawn.length, before, 'a movement outside the box is gathered, not drawn');
  move(pointerSamples - 1);
  assert.deepEqual([$('gather-said').textContent, $('gather-skip').disabled], [GATHER_WORDS.full, true]);
  const bytes = await result;
  assert.ok(bytes instanceof Uint8Array && bytes.length === 64 && new Set(bytes).size > 20);
  assert.deepEqual([$('gather-dialog').open, $('gather-dialog').returnValue, drawn.length], [false, '', 0], 'closed by itself, and the trail is wiped');
  // A movement after it closed does nothing.
  move(3); assert.equal($('gather-progress').value, 100);
  // The next time starts from nothing, and gives other bytes for other movements.
  const next = gather();
  assert.deepEqual([$('gather-progress').value, $('gather-said').textContent, $('gather-skip').disabled], [0, GATHER_WORDS.start, false]);
  for (let i = 0; i < pointerSamples; i++) move(i + 1000, { pointerType: 'touch' });
  assert.notDeepEqual(await next, bytes);
});

test('the dialog: the samples a browser merged into one event are gathered too, a finger is told from a mouse, and keys alone fill it', async () => {
  const one = page(), two = page(), three = page();
  const run = async (p, extra) => { const r = p.gather(); for (let i = 0; i < pointerSamples; i++) p.move(i, extra(i)); return r; };
  const plain = await run(one, () => ({}));
  const merged = await run(two, i => ({ getCoalescedEvents: () => [{ clientX: hand(i).x - 1, clientY: hand(i).y - 1, screenX: 0, screenY: 0, pressure: 0.5, pointerType: 'mouse', timeStamp: hand(i).t - 2 }, {}] }));
  const finger = await run(three, () => ({ pointerType: 'touch' }));
  assert.notDeepEqual(plain, merged); assert.notDeepEqual(plain, finger);
  const { $, gather } = page();
  const byKeys = gather();
  for (let i = 0; i < 256; i++) $('gather-dialog').emit('keydown', { key: 'a', timeStamp: i * GATHER.minKeyMs });
  assert.equal((await byKeys).length, 64);
});

test('the dialog: "Go on without this" goes on with nothing gathered; Escape, a back gesture or the wallet locking end the step; a page that cannot draw asks nothing', async () => {
  const { $, gather, move } = page();
  // "Go on without this": the button of the dialog's form closes it with its value.
  let result = gather(); for (let i = 0; i < 30; i++) move(i);
  $('gather-dialog').close(SKIP);
  assert.equal(await result, null);
  // Escape (the dialog's cancel event), with the meter half full.
  result = gather(); for (let i = 0; i < 60; i++) move(i);
  $('gather-dialog').emit('cancel');
  await assert.rejects(result, error => error.notGathered === true && error.message === GATHER_WORDS.closed);
  assert.equal($('gather-dialog').open, false);
  // An Escape key that reaches the dialog as a key is not counted as a key pressed.
  result = gather();
  $('gather-dialog').emit('keydown', { key: 'Escape', timeStamp: 50 });
  assert.equal($('gather-progress').value, 0);
  // The wallet locks (app.js closes the dialog with no value).
  $('gather-dialog').close('');
  await assert.rejects(result, error => error.notGathered === true);
  // Locked at the very moment the meter filled: what was gathered is not handed on.
  result = gather(); for (let i = 0; i < pointerSamples; i++) move(i);
  $('gather-dialog').close('');
  await assert.rejects(result, error => error.notGathered === true);
  await settle();
  assert.equal($('gather-dialog').open, false, 'and the dialog is not closed a second time as full');
  // A page that cannot draw the box: nothing is asked, nothing is shown.
  const bare = page({ canvas: false });
  assert.equal(await bare.gather(), null);
  assert.equal(bare.$('gather-dialog').open, false);
  // While the dialog is open, a second request asks nothing more.
  const open = gather();
  assert.equal(await gather(), null);
  $('gather-dialog').close(SKIP); await open;
  assert.equal(FULL, 'full');
});

test('offline: neither module reaches a network, a storage, another window or another script; the page has the dialog, with no style or script of its own', async () => {
  for (const name of ['entropy.mjs', 'entropy-dialog.mjs']) {
    const code = (await readFile(at(name), 'utf8')).replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    for (const word of ['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'sendBeacon', 'localStorage', 'sessionStorage', 'indexedDB', 'postMessage', 'BroadcastChannel', 'navigator', 'document.cookie', 'import(', 'Worker', 'eval(', 'Math.random']) assert.equal(code.includes(word), false, `${name} uses ${word}`);
    assert.deepEqual([...code.matchAll(/^import .* from '([^']+)';$/gm)].map(found => found[1]), name === 'entropy.mjs' ? [] : ['./entropy.mjs'], `${name} imports`);
  }
  const html = await readFile(at('index.html'), 'utf8');
  const dialog = /<dialog id="gather-dialog"[\s\S]*?<\/dialog>/.exec(html)?.[0] ?? '';
  for (const id of ['gather-form', 'gather-title', 'gather-why', 'gather-pad', 'gather-progress', 'gather-said', 'gather-skip', 'gather-skip-note']) assert.ok(dialog.includes(`id="${id}"`), id);
  assert.match(dialog, /<form id="gather-form" method="dialog">/);
  assert.match(dialog, /<button id="gather-skip" class="secondary" value="skip">/);
  assert.match(dialog, /<canvas id="gather-pad" width="640" height="260" aria-hidden="true"><\/canvas>/);
  assert.equal(/\sstyle=|\son[a-z]+=|<script/.test(dialog), false);
  assert.match(await readFile(at('styles.css'), 'utf8'), /#gather-pad \{[^}]*touch-action: none;[^}]*\}/, 'a finger moves in the box without scrolling the page');
  // The page asks through app.js, and forgets what was gathered when the wallet locks.
  const app = await readFile(at('app.js'), 'utf8');
  assert.match(app, /setGatherer\(gatherDialog\(\$\)\);/);
  assert.match(app, /if \(\$\('gather-dialog'\)\.open\) \$\('gather-dialog'\)\.close\(''\);\r?\n\s*forgetGathered\(\);/);
});
