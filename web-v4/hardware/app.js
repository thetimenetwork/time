// The hardware page: three drawings of the watch (to turn, to pay with, to open) and the demonstration's buttons.
// Nothing is fetched and nothing is stored. The page's text stands without this script; the drawings are extra.
// Under the page's Content-Security-Policy: no inline style or script, only textContent and properties.
import { render, pickAt } from './engine.js';
import { buildWatch, MARKS, FACE_UNIT, clockOf, newDemo, act, facesOf, storyOf, secondsText, FEE_MS } from './watch.js';

const $ = (id) => document.getElementById(id);
const calm = matchMedia('(prefers-reduced-motion: reduce)');
const dark = matchMedia('(prefers-color-scheme: dark)');
const hex = (value) => { const m = /^#([0-9a-f]{6})$/i.exec(String(value).trim()); return m ? [0, 2, 4].map((i) => parseInt(m[1].slice(i, i + 2), 16)) : null; };
const readPalette = () => { const style = getComputedStyle(document.documentElement); return { page: hex(style.getPropertyValue('--page')) ?? [255, 255, 255], ink: hex(style.getPropertyValue('--ink')) ?? [34, 34, 34] }; };
const ease = (t) => (t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2);
const scenes = [];
let palette = readPalette();

/// A value that moves to a new one in `ms`, or at once for a reader who asked for less motion.
function glide(from, to, ms, each, done) {
  if (calm.matches || ms <= 0) { each(to); done?.(); return () => {}; }
  let stopped = false; const start = performance.now();
  const tick = (now) => {
    if (stopped) return;
    const t = Math.min(1, (now - start) / ms); each(from + (to - from) * ease(t));
    if (t < 1) requestAnimationFrame(tick); else done?.();
  };
  requestAnimationFrame(tick);
  return () => { stopped = true; };
}

/// One canvas: it draws its objects when asked, turns under a finger or the arrow keys, and says what was pressed.
class Scene {
  constructor(canvas, { yaw, pitch, minPitch = 0.02, maxPitch = 3.05, layout, objects }) {
    Object.assign(this, { canvas, yaw, pitch, minPitch, maxPitch, layout, objects, hits: [], selected: null, marks: [], seen: true, frame: 0, width: 0, height: 0, drag: null });
    this.ctx = canvas.getContext('2d');
    if (!this.ctx) return;
    scenes.push(this);
    new ResizeObserver(() => this.fit()).observe(canvas);
    new IntersectionObserver((entries) => { this.seen = entries.some((entry) => entry.isIntersecting); if (this.seen) this.ask(); }).observe(canvas);
    canvas.addEventListener('pointerdown', (event) => this.down(event));
    canvas.addEventListener('pointermove', (event) => this.move(event));
    for (const kind of ['pointerup', 'pointercancel']) canvas.addEventListener(kind, (event) => this.up(event, kind === 'pointercancel'));
    canvas.addEventListener('keydown', (event) => {
      const step = { ArrowLeft: [-0.2, 0], ArrowRight: [0.2, 0], ArrowUp: [0, 0.15], ArrowDown: [0, -0.15] }[event.key];
      if (!step) return;
      event.preventDefault(); this.turn(step[0], step[1]);
    });
    this.fit();
  }
  fit() {
    const ratio = Math.min(globalThis.devicePixelRatio || 1, 2.5), width = this.canvas.clientWidth, height = this.canvas.clientHeight;
    if (!width || !height) return;
    Object.assign(this, { ratio, width, height });
    this.canvas.width = Math.round(width * ratio); this.canvas.height = Math.round(height * ratio);
    this.draw();
  }
  ask() { if (!this.frame && this.ctx) this.frame = requestAnimationFrame(() => { this.frame = 0; this.draw(); }); }
  draw() {
    if (!this.ctx || !this.width || !this.seen) return;
    const view = { width: this.width, height: this.height, yaw: this.yaw, pitch: this.pitch, ...this.layout(this.width, this.height, this) };
    this.hits = render(this.ctx, { view, objects: this.objects, palette, ratio: this.ratio, selected: this.selected, marks: this.marks });
  }
  turn(dyaw, dpitch) {
    this.yaw += dyaw; this.pitch = Math.max(this.minPitch, Math.min(this.maxPitch, this.pitch + dpitch));
    this.onTurn?.(); this.ask();
  }
  at(event) { const box = this.canvas.getBoundingClientRect(); return [event.clientX - box.left, event.clientY - box.top]; }
  down(event) {
    if (event.button > 0) return;
    const [x, y] = this.at(event), pick = pickAt(this.hits, x, y);
    this.drag = { x, y, pick, moved: false, taken: this.onPress?.(pick, event) === true, touch: event.pointerType === 'touch' };
    this.canvas.setPointerCapture?.(event.pointerId);
  }
  move(event) {
    const drag = this.drag; if (!drag) return;
    const [x, y] = this.at(event), dx = x - drag.x, dy = y - drag.y;
    if (drag.taken) { this.onDrag?.(x, y, drag); return; }
    if (!drag.moved && Math.hypot(dx, dy) < 5) return;
    drag.moved = true; drag.x = x; drag.y = y;
    // A finger on a phone turns it sideways only: up and down belong to the page.
    this.turn(dx * 0.011, drag.touch ? 0 : -dy * 0.011);
  }
  up(event, cancelled) {
    const drag = this.drag; if (!drag) return;
    this.drag = null;
    if (drag.taken) { this.onRelease?.(drag, cancelled); return; }
    if (!drag.moved && !cancelled) this.onTap?.(drag.pick);
  }
}

// ---- The watch at the top: it shows the time and turns ----

const VIEWS = { angle: [-0.5, 0.95], front: [0, 0.03], side: [-1.25, 1.42], back: [0.45, 2.55] };
function hero() {
  const canvas = $('hero-scene'); if (!canvas) return null;
  const watch = { key: 'watch', parts: buildWatch(), pose: {}, open: 0, state: { face: { screen: 'time', clock: clockOf(new Date()), balance: 842_000 } } };
  const scene = new Scene(canvas, { yaw: VIEWS.angle[0], pitch: VIEWS.angle[1], objects: [watch], layout: (w, h) => { const zoom = Math.min(w / 78, h / 72); return { cx: w / 2, cy: h / 2 + zoom * 1.5, zoom }; } });
  const buttons = [...document.querySelectorAll('[data-view]')], press = (name) => { for (const b of buttons) b.setAttribute('aria-pressed', String(b.dataset.view === name)); };
  let stop = () => {};
  scene.onTurn = () => press(null);
  for (const button of buttons) button.addEventListener('click', () => {
    const [yaw, pitch] = VIEWS[button.dataset.view] ?? VIEWS.angle, fromYaw = scene.yaw, fromPitch = scene.pitch;
    stop(); stop = glide(0, 1, 520, (t) => { scene.yaw = fromYaw + (yaw - fromYaw) * t; scene.pitch = fromPitch + (pitch - fromPitch) * t; scene.ask(); });
    press(button.dataset.view);
  });
  return { scene, tick(clock) { watch.state.face.clock = clock; scene.ask(); } };
}

// ---- The open watch: its parts, numbered as in the list ----

function inside() {
  const canvas = $('inside-scene'), toggle = $('open-toggle'); if (!canvas || !toggle) return null;
  const watch = { key: 'watch', parts: buildWatch({ strap: 'none' }), pose: {}, open: 0, state: { face: { screen: 'time', clock: clockOf(new Date()), balance: 842_000 } } };
  const scene = new Scene(canvas, {
    yaw: -0.55, pitch: 1.2, minPitch: 0.6, maxPitch: 2.1, objects: [watch],
    layout: (w, h) => { const shut = Math.min(w / 62, h / 62), apart = Math.min((w - 150) / 50, h / 116), zoom = shut + (apart - shut) * watch.open; return { cx: w / 2, cy: h / 2 + zoom * (2 + 2 * watch.open), zoom }; },
  });
  const names = [...document.querySelectorAll('#parts [data-group]')];
  let open = false, stop = () => {};
  const choose = (group, from) => {
    scene.selected = scene.selected === group ? null : group;
    for (const name of names) { const on = name.dataset.group === scene.selected; name.setAttribute('aria-pressed', String(on)); name.closest('li').classList.toggle('chosen', on); }
    if (from === 'drawing' && scene.selected) names.find((name) => name.dataset.group === scene.selected)?.closest('li').scrollIntoView({ block: 'nearest', behavior: calm.matches ? 'auto' : 'smooth' });
    scene.ask();
  };
  const set = (value) => {
    open = value; toggle.setAttribute('aria-pressed', String(open)); toggle.textContent = open ? 'Close the watch' : 'Open the watch';
    if (!open) scene.marks = [];
    stop(); stop = glide(watch.open, open ? 1 : 0, 900, (t) => { watch.open = t; scene.ask(); }, () => { scene.marks = open ? MARKS.map((mark) => ({ ...mark, object: 'watch' })) : []; scene.ask(); });
  };
  toggle.addEventListener('click', () => set(!open));
  for (const name of names) name.addEventListener('click', () => { if (!open) set(true); choose(name.dataset.group, 'list'); });
  scene.onTap = (pick) => { if (!open) { set(true); return; } if (pick?.group && pick.group !== 'board') choose(pick.group, 'drawing'); };
  return { scene, tick(clock) { watch.state.face.clock = clock; scene.ask(); } };
}

// ---- Two watches and a payment ----

const APART = 26, TOGETHER = 22, HOLD_MS = 700;
function demo() {
  const canvas = $('demo-scene'); if (!canvas) return null;
  let state = newDemo(), clock = clockOf(new Date()), gap = APART, busy = false, hold = 0, pin, turn = 0, holding = null, settleTimer = 0, pinTimer = 0;
  const you = { key: 'you', parts: buildWatch(), pose: { x: -gap, turn: 0.1 }, open: 0, state: {} }, other = { key: 'other', parts: buildWatch(), pose: { x: gap, turn: -0.1 }, open: 0, state: {} };
  const scene = new Scene(canvas, { yaw: 0, pitch: 0.6, minPitch: 0.1, maxPitch: 1.35, objects: [you, other], layout: (w, h) => ({ cx: w / 2, cy: h / 2 + 2, zoom: Math.min(w / 104, h / 92) }) });
  const groups = { idle: $('controls-idle'), amount: $('controls-amount'), review: $('controls-review'), blocked: $('controls-blocked'), done: $('controls-done') };
  const note = (text) => { $('demo-note').textContent = text; $('demo-note').hidden = !text; };

  function show() {
    const faces = facesOf(state, { clock, hold, pin, turn });
    you.state.face = faces.you; other.state.face = faces.other; you.pose.x = -gap; other.pose.x = gap;
    scene.ask();
  }
  function sync() {
    const step = state.step === 'sending' ? 'review' : state.step;
    for (const [name, element] of Object.entries(groups)) element.hidden = name !== step;
    for (const button of document.querySelectorAll('#demo button')) button.disabled = busy || state.step === 'sending';
    $('demo-story').textContent = storyOf(state);
    $('demo-amount').textContent = secondsText(state.amount);
    for (const button of document.querySelectorAll('[data-unit]')) button.setAttribute('aria-pressed', String(Number(button.dataset.unit) === state.unit));
    $('review-to').textContent = `@${state.other.name}`; $('review-amount').textContent = secondsText(state.amount); $('review-fee').textContent = secondsText(FEE_MS); $('review-total').textContent = secondsText(state.amount + FEE_MS);
    $('review-carrier').textContent = state.you.online ? 'your watch, through your phone' : `@${state.other.name}'s watch`;
    $('you-online').checked = state.you.online; $('other-online').checked = state.other.online;
    $('you-online').disabled = $('other-online').disabled = busy || state.step === 'sending';
    $('demo-give').textContent = 'Give seconds';
    note(state.note);
    show();
  }
  const run = (kind, value) => { if (busy) return; state = act(state, kind, value); sync(); };

  // The watches come together, exchange what they need, and part.
  function touch() {
    if (busy || state.step !== 'amount') return;
    if (state.amount <= 0) { run('touch'); return; }
    busy = true; sync();
    glide(APART, TOGETHER, 420, (value) => { gap = value; show(); }, () => {
      state = act(state, 'touch'); show();
      setTimeout(() => glide(TOGETHER, APART, 420, (value) => { gap = value; show(); }, () => { busy = false; sync(); }), calm.matches ? 0 : 380);
    });
  }
  function approve() {
    clearInterval(pinTimer); holding = null; hold = 0; pin = undefined;
    if (state.step !== 'review') return;
    state = act(state, 'approve'); sync();
    const started = performance.now(), spin = (now) => { if (state.step !== 'sending') return; turn = ((now - started) / 1000) % 1; show(); if (!calm.matches) requestAnimationFrame(spin); };
    requestAnimationFrame(spin);
    // The wait stands for the network's answer: here it is a timer, and the page says so.
    settleTimer = setTimeout(() => { state = act(state, 'settle'); sync(); }, 1400 + Math.random() * 700);
  }
  // A finger on the sensor: the ring on the watch closes in HOLD_MS; lifted before, nothing is sent.
  function startHold() {
    if (busy || state.step !== 'review' || holding || pin !== undefined) return;
    const started = performance.now(); holding = {}; note('');
    const tick = (now) => {
      if (!holding) return;
      hold = Math.min(1, (now - started) / HOLD_MS); show();
      if (hold >= 1) approve(); else requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }
  function endHold() {
    if (!holding) return;
    holding = null; hold = 0; show();
    if (state.step === 'review') note('Lifted too early. Nothing was sent. Keep the finger down until the ring closes.');
  }
  function typePin() {
    if (busy || state.step !== 'review' || holding || pin !== undefined) return;
    pin = 0; note('The demonstration types a PIN for you.'); show();
    pinTimer = setInterval(() => { pin += 1; show(); if (pin >= 4) { clearInterval(pinTimer); setTimeout(approve, 260); } }, 260);
  }
  function leave(kind) { clearInterval(pinTimer); clearTimeout(settleTimer); holding = null; hold = 0; pin = undefined; run(kind); }

  $('demo-give').addEventListener('click', () => run('give'));
  $('demo-minus').addEventListener('click', () => run('minus'));
  $('demo-plus').addEventListener('click', () => run('plus'));
  for (const button of document.querySelectorAll('[data-unit]')) button.addEventListener('click', () => run('unit', Number(button.dataset.unit)));
  $('demo-touch').addEventListener('click', touch);
  for (const button of document.querySelectorAll('#demo [data-act="cancel"]')) button.addEventListener('click', () => leave('cancel'));
  $('demo-again').addEventListener('click', () => leave('again'));
  $('demo-pin').addEventListener('click', typePin);
  const holdButton = $('demo-hold');
  holdButton.addEventListener('pointerdown', (event) => { if (event.button > 0) return; holdButton.setPointerCapture?.(event.pointerId); startHold(); });
  for (const kind of ['pointerup', 'pointercancel', 'lostpointercapture']) holdButton.addEventListener(kind, endHold);
  holdButton.addEventListener('contextmenu', (event) => event.preventDefault());
  // From the keyboard the key is held down, as the finger is.
  holdButton.addEventListener('keydown', (event) => { if ((event.key === ' ' || event.key === 'Enter') && !event.repeat) { event.preventDefault(); startHold(); } });
  holdButton.addEventListener('keyup', (event) => { if (event.key === ' ' || event.key === 'Enter') endHold(); });
  holdButton.addEventListener('blur', endHold);
  $('you-online').addEventListener('change', (event) => run('online', { who: 'you', on: event.target.checked }));
  $('other-online').addEventListener('change', (event) => run('online', { who: 'other', on: event.target.checked }));

  // On your own watch: the halves of the glass are minus and plus, a finger around the edge turns the amount, and a
  // finger on the pad approves. Everything else turns the drawing.
  const onFace = (pick) => (pick?.object === 'you' && pick.on && (pick.id === 'glass' || pick.id === 'display') ? { x: pick.on.x / (pick.id === 'glass' ? FACE_UNIT : 1), y: pick.on.y / (pick.id === 'glass' ? FACE_UNIT : 1) } : null);
  scene.onPress = (pick) => {
    if (busy) return false;
    if (pick?.object === 'you' && pick.id === 'pad' && state.step === 'review') { startHold(); return true; }
    const face = onFace(pick);
    return Boolean(face && state.step === 'amount');
  };
  scene.onDrag = (x, y, drag) => {
    const start = onFace(drag.pick); if (!start || state.step !== 'amount') return;
    const { a, b, c, d, e, f } = drag.pick.cap.matrix, det = a * d - b * c, k = drag.pick.id === 'glass' ? FACE_UNIT : 1;
    const now = { x: (d * (x - e) - c * (y - f)) / det / k, y: (a * (y - f) - b * (x - e)) / det / k };
    drag.angle ??= Math.atan2(start.y, start.x); drag.far ??= Math.hypot(start.x, start.y) > 55;
    if (!drag.far) { if (Math.hypot(now.x - start.x, now.y - start.y) > 12) drag.slid = true; return; }
    let delta = Math.atan2(now.y, now.x) - drag.angle;
    if (delta > Math.PI) delta -= 2 * Math.PI; else if (delta < -Math.PI) delta += 2 * Math.PI;
    const steps = Math.trunc(delta / 0.2);
    if (steps) { drag.angle += steps * 0.2; drag.turned = true; run('turn', steps); }
  };
  scene.onRelease = (drag) => {
    if (holding) { endHold(); return; }
    const face = onFace(drag.pick);
    if (face && !drag.turned && !drag.slid && state.step === 'amount') run(face.x < 0 ? 'minus' : 'plus');
  };
  scene.onTap = (pick) => { if (pick?.object === 'you' && (state.step === 'idle' || state.step === 'done') && onFace(pick)) run('give'); };
  sync();
  return { scene, tick(now) { clock = now; if (state.step === 'idle' || state.step === 'amount' || state.step === 'blocked') show(); } };
}

const parts = [hero(), demo(), inside()].filter(Boolean);
setInterval(() => { if (document.hidden) return; const clock = clockOf(new Date()); for (const part of parts) part.tick(clock); }, 1000);
dark.addEventListener('change', () => { palette = readPalette(); for (const scene of scenes) scene.ask(); });
