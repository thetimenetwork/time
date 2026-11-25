// The step in which a person adds their own randomness before the wallet makes passwords (entropy.mjs says what is done
// with it, and why it can only add): a dialog of its own (#gather-dialog in index.html) with a box to move a mouse or a
// finger around in, and a meter that fills as they do, the way a phone asks for a finger until it has the whole
// fingerprint. Keys pressed count too, for a person who uses no pointer. When the meter is full the dialog closes by
// itself and the step goes on.
//
// "Go on without this" goes on with the browser's own randomness alone, which is what every password was made of before
// this step existed: nobody is kept out of the wallet by a hand, a device or a screen reader that gives no movement.
// Closed any other way (Escape, a phone's back gesture, the wallet locking), the step ends and nothing is made.
//
// No network access and no storage here. What is drawn in the box is where the pointer went, and is wiped when the
// dialog closes. Where the page cannot draw the box (no canvas), nothing is asked.
import { createMeter } from './entropy.mjs';

export const GATHER_WORDS = Object.freeze({
  title: 'Add your own randomness',
  why: 'Move your mouse or your finger around inside the box, any way you like, until it is full. You can press keys too. The wallet mixes what you do into the passwords it makes, on top of this device\'s own randomness. Nothing of it leaves this page.',
  start: 'Not started yet.',
  percent: n => `${n}% full. Keep going.`,
  full: 'Full. The wallet goes on.',
  skip: 'Go on without this',
  skipNote: 'The wallet then uses this device\'s own randomness alone, which is strong too.',
  closed: 'Nothing was made: the box was closed before it was full. Start again.',
});
/// The values the dialog closes with: full, and "Go on without this" (index.html, #gather-skip).
export const FULL = 'full', SKIP = 'skip';

/// The dialog of the page whose elements `$` gives. Returns gather(): shows the dialog and resolves with the 64 bytes of
/// what the person gathered once the meter is full, or with null on "Go on without this" (and at once, where the page
/// cannot draw the box); it rejects with GATHER_WORDS.closed (an Error with `notGathered`) when it closed any other way.
export function gatherDialog($, { style = element => globalThis.getComputedStyle?.(element) } = {}) {
  const dialog = $('gather-dialog'), pad = $('gather-pad');
  let meter = null, bytes = null, said = -1, finishing = false;
  const kinds = { mouse: 0, touch: 1, pen: 2 };
  const context = () => { try { return pad.getContext('2d'); } catch { return null; } };
  function draw(x, y) {
    const paint = context(), box = pad.getBoundingClientRect?.();
    if (!paint || !box || !(box.width > 0) || !(box.height > 0)) return;
    const px = (x - box.left) * pad.width / box.width, py = (y - box.top) * pad.height / box.height;
    if (px < 0 || py < 0 || px > pad.width || py > pad.height) return;
    paint.fillStyle = style(pad)?.color || 'currentColor';
    paint.beginPath(); paint.arc(px, py, 3, 0, 2 * Math.PI); paint.fill();
  }
  const clear = () => { const paint = context(); paint?.clearRect?.(0, 0, pad.width, pad.height); };
  function show(progress) {
    const percent = Math.floor(progress * 100);
    $('gather-progress').value = percent;
    // Said in steps of ten, so that a screen reader is not told at every movement.
    const step = Math.floor(percent / 10);
    if (step !== said) { said = step; $('gather-said').textContent = percent === 0 ? GATHER_WORDS.start : GATHER_WORDS.percent(step * 10); }
  }
  async function took(progress) {
    show(progress);
    if (!meter?.full || finishing) return;
    finishing = true;
    $('gather-said').textContent = GATHER_WORDS.full; $('gather-skip').disabled = true;
    const mine = meter, gathered = await mine.finish();
    // The dialog closed meanwhile (the wallet locked): what was gathered is not used.
    if (meter !== mine || !dialog.open) { gathered.fill(0); return; }
    bytes = gathered; dialog.close(FULL);
  }
  const sample = event => ({ x: event.clientX, y: event.clientY, sx: event.screenX, sy: event.screenY, pressure: event.pressure, t: event.timeStamp, kind: kinds[event.pointerType] ?? 0 });
  function moved(event) {
    if (!meter || finishing) return;
    // The samples the browser merged into this event are gathered too; the meter credits the event once.
    let earlier = [];
    try { earlier = event.getCoalescedEvents?.() ?? []; } catch { earlier = []; }
    for (const one of earlier.slice(0, -1)) meter.pointer(sample(one));
    draw(event.clientX, event.clientY);
    took(meter.pointer(sample(event)));
  }
  dialog.addEventListener('pointermove', moved);
  dialog.addEventListener('pointerdown', moved);
  dialog.addEventListener('keydown', event => { if (meter && !finishing && event.key !== 'Escape') took(meter.key({ t: event.timeStamp })); });
  // Escape, or a phone's back gesture, asks the dialog to close: it does, as not gathered.
  dialog.addEventListener('cancel', () => { if (dialog.open) dialog.close(''); });
  $('gather-title').textContent = GATHER_WORDS.title; $('gather-why').textContent = GATHER_WORDS.why;
  $('gather-skip').textContent = GATHER_WORDS.skip; $('gather-skip-note').textContent = GATHER_WORDS.skipNote;

  return function gather() {
    // A page that cannot draw the box, or show a dialog, asks nothing: the browser's own randomness alone, as before.
    if (typeof pad.getContext !== 'function' || typeof dialog.showModal !== 'function' || context() === null || dialog.open) return Promise.resolve(null);
    meter = createMeter(); bytes = null; said = -1; finishing = false;
    clear(); show(0); $('gather-skip').disabled = false;
    dialog.returnValue = ''; dialog.showModal(); $('gather-title').focus?.();
    return new Promise((resolve, reject) => dialog.addEventListener('close', () => {
      const how = dialog.returnValue, got = bytes;
      meter?.wipe(); meter = null; bytes = null; finishing = false; clear();
      dialog.returnValue = '';
      if (how === FULL && got) resolve(got);
      else { got?.fill(0); if (how === SKIP) resolve(null); else reject(Object.assign(new Error(GATHER_WORDS.closed), { notGathered: true })); }
    }, { once: true }));
  };
}
