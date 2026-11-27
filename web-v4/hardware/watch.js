// The Time Watch as a model: its parts in millimetres, what its screen shows, and the payment of the demonstration.
// A design draft: no such watch has been built. Nothing here reaches a network or holds a key.
// Everything in this file runs under Node too (client-v4/hardware-page.test.mjs).
import { prism, circle, roundRect, band } from './engine.js';

/// The groups of parts, in the order of the list on the page (index.html, #parts): the number of a group is its
/// place here plus one.
export const GROUPS = Object.freeze(['glass', 'display', 'antenna', 'case', 'finger', 'processor', 'secure', 'radio', 'power']);
export const CASE_RADIUS = 21, FACE_RADIUS = 16.4, FACE_UNIT = FACE_RADIUS / 100;

const TAU = Math.PI * 2;
const mirror = (points, sx, sy) => points.map(([u, v]) => [u * sx, v * sy]);

/// The parts of one watch. z is up through the glass, y towards twelve o'clock, x towards three. `strap`: 'none' leaves
/// the strap off, for the open watch, where it would hide the parts under the case.
export function buildWatch({ strap = 'long' } = {}) {
  const strapLine = [[22.6, 4.6], [27, 4.2], [32, 2.6], [37, -0.4], [41.5, -4.8], [45, -10.2], [47.2, -16.4], [48, -23]];
  const lug = [[10.8, 17.6], [13.8, 15.4], [13.8, 24.2], [12.9, 25.6], [11.6, 25.6], [10.8, 24.6]];
  const chip = (id, group, w, h, x, y, tall) => prism({ id, group, outline: roundRect(w, h, 0.3, x, y, 2), from: 5.6, to: 5.6 + tall, tone: 0.78, layer: 3, inner: true, lift: [0, 0, -20], top: (p) => p.begin().circle(x - w / 2 + 0.8, y + h / 2 - 0.8, 0.28).fill(0.25) });
  return [
    prism({ id: 'back', group: 'power', outline: circle(19.6, 56), from: -1.2, to: 0, tone: 0.07, smooth: true, layer: 0, lift: [0, 0, -44], bottom: drawBack }),
    prism({ id: 'battery', group: 'power', outline: roundRect(25, 21, 5), from: 1.2, to: 4.6, tone: 0.1, layer: 1, inner: true, lift: [0, 0, -32], top: drawBattery }),
    prism({ id: 'board', group: 'board', outline: circle(17.6, 48), from: 4.8, to: 5.6, tone: 0.13, smooth: true, layer: 2, inner: true, lift: [0, 0, -20], top: drawBoard }),
    chip('processor', 'processor', 6.4, 6.4, -6, 4.5, 0.9),
    chip('secure-1', 'secure', 3.2, 3.2, -11, -4.5, 0.7),
    chip('secure-2', 'secure', 3.2, 3.2, -5, -7, 0.7),
    chip('bluetooth', 'radio', 5.6, 5.6, 8.5, 6, 0.9),
    chip('nfc', 'radio', 4, 4, 9.5, -4, 0.8),
    chip('motion', 'power', 2, 2, 3, 13, 0.6),
    prism({ id: 'motor', group: 'power', outline: circle(3.4, 20, 2, -12), from: 5.6, to: 7.2, tone: 0.3, smooth: true, layer: 3, inner: true, lift: [0, 0, -20] }),
    prism({ id: 'barrel', group: 'case', outline: circle(CASE_RADIUS, 72), holes: [circle(18.6, 72)], from: 0, to: 9.6, tone: 0.07, smooth: true, layer: 4 }),
    ...[[1, 1], [-1, 1], [-1, -1], [1, -1]].map(([sx, sy], i) => prism({ id: `lug-${i}`, group: 'case', outline: mirror(lug, sx, sy), from: 1.6, to: 7.4, tone: 0.07 })),
    ...(strap === 'none' ? [] : [strapLine, mirror(strapLine, -1, 1)].map((line, i) => prism({ id: i ? 'strap-6' : 'strap-12', group: 'case', axis: 'x', outline: band(line, 2.4), from: -10, to: 10, tone: 0.84 }))),
    prism({ id: 'pad', group: 'finger', axis: 'x', outline: roundRect(9, 4.4, 2.2, 0, 4.9, 6), from: 20.55, to: 22.2, tone: 0.16, smooth: true, lift: [10, 0, 0], top: drawPad }),
    prism({ id: 'coil', group: 'antenna', outline: circle(18.2, 56), holes: [circle(16.7, 56)], from: 8.2, to: 8.4, tone: 0.2, smooth: true, layer: 5, inner: true, lift: [0, 0, 22], top: drawCoil }),
    prism({ id: 'display', group: 'display', outline: circle(FACE_RADIUS, 56), from: 7.4, to: 8.6, tone: 0, smooth: true, layer: 6, lift: [0, 0, 32], unit: FACE_UNIT, top: drawFace }),
    prism({ id: 'glass', group: 'glass', outline: circle(18.6, 64), from: 8.6, to: 10, tone: 0.03, alpha: 0.1, smooth: true, layer: 7, lift: [0, 0, 44], top: drawGlass }),
  ];
}

/// Where the numbered dots of the open watch stand. `c`: a point on the axis of the part; `r`: how far from it the
/// dot sits, towards the left (`side` -1) or the right (1) of the screen however the watch is turned; `lift`: the
/// part's own; `dx`, `dy`: the way the number leans away from its dot, in pixels.
export const MARKS = Object.freeze([
  { group: 'glass', c: [0, 0, 10], r: 18.6, side: -1, lift: [0, 0, 44], dx: -40, dy: -8 },
  { group: 'display', c: [0, 0, 8.6], r: FACE_RADIUS, side: 1, lift: [0, 0, 32], dx: 40, dy: -8 },
  { group: 'antenna', c: [0, 0, 8.4], r: 18.2, side: -1, lift: [0, 0, 22], dx: -40, dy: -8 },
  { group: 'case', c: [0, 0, 6], r: CASE_RADIUS, side: -1, lift: [0, 0, 0], dx: -36, dy: -4 },
  { group: 'finger', c: [22.2, 0, 4.9], r: 0, side: 1, lift: [10, 0, 0], dx: 34, dy: -20 },
  { group: 'processor', c: [-6, 4.5, 6.5], r: 0, side: -1, lift: [0, 0, -20], dx: -84, dy: -6 },
  { group: 'secure', c: [-11, -4.5, 6.3], r: 0, side: -1, lift: [0, 0, -20], dx: -62, dy: 30 },
  { group: 'radio', c: [8.5, 6, 6.5], r: 0, side: 1, lift: [0, 0, -20], dx: 84, dy: -6 },
  { group: 'power', c: [0, 0, 3], r: 12.5, side: 1, lift: [0, 0, -32], dx: 58, dy: 8 },
].map((mark) => Object.freeze({ ...mark, n: GROUPS.indexOf(mark.group) + 1 })));

// ---- What is drawn on the parts ----

function drawGlass(p) {
  // The dark border printed under the glass, which hides the antenna and the edge of the screen.
  p.begin().circle(0, 0, 18.6).circle(0, 0, 16.5).fill(0.9, 0.9, 'evenodd');
}
function drawCoil(p) {
  for (const r of [17.1, 17.5, 17.9]) p.begin().circle(0, 0, r).stroke(0.8, 1);
}
function drawBoard(p) {
  // The one narrow link between the two sides of the board: left of the dashes the secure side, right the radios.
  p.begin().move(1.6, -15.5).line(1.6, 9).stroke(1.2, 1, [4, 4]);
  p.begin().move(-2.8, -4.5).line(5.7, -6).stroke(1, 0.75);
  p.begin().move(-9.4, 4.5).line(-14.2, 4.5).line(-14.2, -1).move(-9.4, -2.9).line(-9.4, 1.2).move(-5, -5.4).line(-5, 1.2).stroke(1, 0.6);
  p.begin().move(8.5, 3.1).line(8.5, -1.9).move(11.5, 6).line(15, 6).stroke(1, 0.6);
}
function drawBattery(p) {
  p.begin().move(-8, 0).line(-5, 0).move(-6.5, -1.5).line(-6.5, 1.5).move(5, 0).line(8, 0).stroke(1.2, 0.8);
}
function drawBack(p) {
  p.begin().circle(0, 0, 15).stroke(1, 0.5);
  p.begin().rect(-3.2, -2.2, 6.4, 4.4, 1.4).stroke(1.2, 1);
  p.begin().circle(-2.6, 9, 1.1).circle(2.6, 9, 1.1).fill(0.85);
}
function drawPad(p) {
  for (const r of [0.7, 1.4, 2.1]) p.begin().arc(0, -4.3, r, Math.PI * 1.1, Math.PI * 1.9).stroke(1, 0.9);
  p.begin().move(-0.0, -5.6).line(0, -4.9).stroke(1, 0.9);
}

/// The time written as a seconds amount of the watch: milliseconds below a second, else seconds with up to three decimals.
export function secondsText(ms) {
  if (!Number.isSafeInteger(ms) || ms < 0) return '?';
  if (ms < 1000) return `${ms} ms`;
  const whole = Math.floor(ms / 1000), part = ms % 1000;
  return `${String(whole).replace(/\B(?=(\d{3})+(?!\d))/g, ',')}${part ? '.' + String(part).padStart(3, '0').replace(/0+$/, '') : ''} s`;
}
const two = (n) => String(n).padStart(2, '0');
const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'], MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
/// What the clock face needs of a moment, in the reader's own time zone.
export function clockOf(date) {
  return { time: `${two(date.getHours())}:${two(date.getMinutes())}`, date: `${DAYS[date.getDay()]} ${date.getDate()} ${MONTHS[date.getMonth()]}`, second: date.getSeconds() };
}

/// The screen of the watch. `face`: { screen, clock, balance, amount, step, limit, to, from, fee, total, hold, pin, turn }.
/// Units: the screen is a circle of radius 100, y down.
export function drawFace(p, state, info) {
  const face = state.face ?? { screen: 'time' }, z = info.zoom, ring = (part, tone = 1) => {
    p.begin().circle(0, 0, 90).stroke(3 * z, 0.14);
    if (part > 0) p.begin().arc(0, 0, 90, -Math.PI / 2, -Math.PI / 2 + TAU * Math.min(1, part)).stroke(3.4 * z, tone);
  };
  const clock = face.clock ?? { time: '10:09', date: '', second: 0 };
  switch (face.screen) {
    case 'amount':
      ring(face.limit > 0 ? face.amount / face.limit : 0);
      p.text('Give', 0, -50, 16, { tone: 0.62 }).text(secondsText(face.amount), 0, -10, 38, { weight: 800 });
      p.text(`step ${secondsText(face.step)}`, 0, 24, 14, { tone: 0.62 }).text('then touch', 0, 56, 14, { tone: 0.62 });
      p.text('−', -68, -10, 34, { weight: 500 }).text('+', 68, -10, 34, { weight: 500 });
      break;
    case 'review':
      ring(face.hold ?? 0);
      p.text(`To @${face.to}`, 0, -54, 18, { weight: 800 }).text(secondsText(face.amount), 0, -20, 34, { weight: 800 });
      p.text(`Fee ${secondsText(face.fee)}`, 0, 10, 14, { tone: 0.62 }).text(`Total ${secondsText(face.total)}`, 0, 30, 15, { weight: 700 });
      p.text('Final once sent', 0, 56, 12.5, { tone: 0.62 });
      break;
    case 'pin':
      ring(0);
      p.text('PIN', 0, -36, 20, { weight: 800 });
      for (let i = 0; i < 4; i += 1) { p.begin().circle(-36 + i * 24, 4, 7); if (i < (face.pin ?? 0)) p.fill(1); p.stroke(1.4, 1); }
      p.text(`To @${face.to}  ${secondsText(face.amount)}`, 0, 44, 13, { tone: 0.62 });
      break;
    case 'sending': {
      p.begin().circle(0, 0, 90).stroke(3 * z, 0.14);
      const a = (face.turn ?? 0) * TAU;
      p.begin().arc(0, 0, 90, a, a + 1.3).stroke(3.4 * z, 1);
      p.text('Sending', 0, -12, 22, { weight: 800 }).text(secondsText(face.amount), 0, 18, 17, { tone: 0.62 });
      break;
    }
    case 'done':
      ring(1);
      p.begin().move(-16, -42).line(-4, -30).line(18, -54).stroke(3 * z, 1);
      p.text(`Sent ${secondsText(face.amount)}`, 0, 0, 22, { weight: 800 }).text(`to @${face.to}`, 0, 28, 16, { tone: 0.62 }).text(`${secondsText(face.balance)} left`, 0, 54, 13, { tone: 0.62 });
      break;
    case 'incoming':
      ring(0);
      p.text(`@${face.from}`, 0, -46, 18, { weight: 800 }).text('is paying you', 0, -22, 14, { tone: 0.62 }).text(secondsText(face.amount), 0, 12, 34, { weight: 800 });
      p.text(face.wait ? 'waiting' : 'nothing to do', 0, 50, 13, { tone: 0.62 });
      break;
    case 'received':
      ring(1);
      p.text(`+${secondsText(face.amount)}`, 0, -16, 34, { weight: 800 }).text(`from @${face.from}`, 0, 18, 16, { tone: 0.62 }).text(`${secondsText(face.balance)} now`, 0, 48, 13, { tone: 0.62 });
      break;
    case 'notice':
      ring(0);
      p.text(face.title ?? '', 0, -24, 18, { weight: 800 }).text(face.line ?? '', 0, 6, 13.5, { tone: 0.62 }).text(face.more ?? '', 0, 28, 13.5, { tone: 0.62 });
      break;
    default:
      ring(clock.second / 60);
      if (clock.date) p.text(clock.date, 0, -50, 15, { tone: 0.62 });
      p.text(clock.time, 0, -6, 52, { weight: 800 });
      if (Number.isSafeInteger(face.balance)) p.text(secondsText(face.balance), 0, 44, 17, { weight: 700 });
  }
}

// ---- The payment of the demonstration ----

export const FEE_MS = 1, DAILY_LIMIT_MS = 600_000, STEPS_MS = Object.freeze([1, 1000, 60_000]);

/// Two watches with example names and amounts. `you` pays `other`.
export function newDemo() {
  return { step: 'idle', amount: 90_000, unit: 1, you: { name: 'sam', balance: 842_000, online: false, spent: 0 }, other: { name: 'anna', balance: 318_000, online: true }, carrier: null, note: '' };
}
/// The most the paying watch may give now: what the account holds less the fee, and what is left of the day's limit.
export function mostOf(demo) {
  return Math.max(0, Math.min(demo.you.balance - FEE_MS, DAILY_LIMIT_MS - demo.you.spent));
}
/// The demonstration after one act. Acts: give, plus, minus, unit (value), turn (value: steps), touch, approve, settle,
/// cancel, again, online (who, value). An act that does not belong to the step changes nothing.
export function act(demo, kind, value) {
  const next = { ...demo, you: { ...demo.you }, other: { ...demo.other }, note: '' }, most = mostOf(demo), step = STEPS_MS[demo.unit];
  const clamp = (amount) => Math.max(0, Math.min(most, amount));
  switch (kind) {
    case 'online':
      if (demo.step === 'sending') return demo;
      next[value.who === 'other' ? 'other' : 'you'].online = value.on === true;
      if (demo.step === 'blocked') next.step = 'amount';
      return next;
    case 'give': if (demo.step !== 'idle' && demo.step !== 'done') return demo; next.step = 'amount'; next.carrier = null; next.amount = clamp(demo.amount || 90_000); return next;
    case 'plus': case 'minus': case 'turn': {
      if (demo.step !== 'amount') return demo;
      const steps = kind === 'turn' ? Math.trunc(value) : kind === 'plus' ? 1 : -1, amount = clamp(demo.amount + steps * step);
      if (amount === demo.amount && steps > 0) next.note = most === demo.you.balance - FEE_MS ? 'That is all the watch holds, less the fee.' : 'That is the most this watch may give today.';
      next.amount = amount; return next;
    }
    case 'unit': if (demo.step !== 'amount' || ![0, 1, 2].includes(value)) return demo; next.unit = value; return next;
    case 'touch':
      if (demo.step !== 'amount') return demo;
      if (demo.amount <= 0) { next.note = 'Set an amount first.'; return next; }
      next.step = demo.you.online || demo.other.online ? 'review' : 'blocked';
      return next;
    case 'approve': if (demo.step !== 'review') return demo; next.step = 'sending'; return next;
    case 'settle':
      if (demo.step !== 'sending') return demo;
      next.you.balance -= demo.amount + FEE_MS; next.you.spent += demo.amount; next.other.balance += demo.amount;
      next.carrier = demo.you.online ? 'you' : 'other'; next.step = 'done';
      return next;
    case 'cancel': if (demo.step === 'sending' || demo.step === 'idle' || demo.step === 'done') return demo; next.step = demo.step === 'amount' ? 'idle' : 'amount'; return next;
    case 'again': next.step = 'idle'; next.carrier = null; return next;
    default: return demo;
  }
}
/// What each watch shows at a step. `extra`: { hold, pin, turn, clock } of the moment.
export function facesOf(demo, extra = {}) {
  const { you, other, amount } = demo, clock = extra.clock, common = { amount, fee: FEE_MS, total: amount + FEE_MS, to: other.name, from: you.name };
  const rest = (who) => ({ screen: 'time', clock, balance: who.balance });
  switch (demo.step) {
    case 'amount': return { you: { screen: 'amount', ...common, step: STEPS_MS[demo.unit], limit: mostOf(demo) }, other: rest(other) };
    case 'review': return { you: extra.pin !== undefined ? { screen: 'pin', ...common, pin: extra.pin } : { screen: 'review', ...common, hold: extra.hold ?? 0 }, other: { screen: 'incoming', ...common, wait: false } };
    case 'sending': return { you: { screen: 'sending', ...common, turn: extra.turn ?? 0 }, other: { screen: 'incoming', ...common, wait: true } };
    case 'done': return { you: { screen: 'done', ...common, balance: you.balance }, other: { screen: 'received', ...common, balance: other.balance } };
    case 'blocked': return { you: { screen: 'notice', title: 'Both offline', line: 'One of the two must', more: 'reach the network' }, other: rest(other) };
    default: return { you: rest(you), other: rest(other) };
  }
}
/// The sentence under the watches: what is happening, and who carries the payment to the network.
export function storyOf(demo) {
  const { you, other } = demo, amount = secondsText(demo.amount);
  switch (demo.step) {
    case 'amount': return `Set the amount: tap the left or the right half of your watch, or turn a finger around its edge. Then bring the watches together.`;
    case 'review': return `The watches have met. Yours shows who receives, the amount, the fee and the total. Nothing is sent until your finger rests on the sensor.`;
    case 'sending': return you.online ? `Your watch signed the payment and is sending it through its phone.` : `Your watch signed the payment and handed it to @${other.name}'s watch by touch. Hers is carrying it to the network.`;
    case 'done': return `${amount} went from @${you.name} to @${other.name}, and 1 ms of fee. ${demo.carrier === 'you' ? 'Your watch sent it itself.' : `Your watch was offline the whole time: @${other.name}'s watch carried the signed payment to the network.`} It cannot be taken back.`;
    case 'blocked': return `Both watches are offline, so nobody can carry the payment to the network. In this design one of the two must have a connection. Paying with both offline is planned for small amounts only, in a later version.`;
    default: return `Your watch is offline and holds ${secondsText(you.balance)}. @${other.name}'s watch has a connection through her phone.`;
  }
}
