// Review of the browser-check changes (commit 16d3e5d): the review before signing (app.js, `review`).
// The test of app.test.mjs checks the focus with a regular expression over the source text; it still passes when
// the line that moves the focus is commented out or never reached. Here `reviewGate` and `review` are taken out of
// app.js as they are written there and run with a stand-in page that records what was opened and focused, in order.
// These tests pass on 16d3e5d; they fail if the focus is not moved to the title right after the dialog opens.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { NAME_ACKNOWLEDGE } from './names.mjs';

const source = await readFile(new URL('./app.js', import.meta.url), 'utf8');
const start = source.indexOf('function reviewGate()'), end = source.indexOf('async function run(action)');
assert.ok(start > 0 && end > start, 'app.js holds reviewGate and review right before run');

function page() {
  const log = [], dom = new Map();
  let active = null;
  class El {
    constructor(id) { Object.assign(this, { id, textContent: '', hidden: false, checked: false, disabled: false, open: false, returnValue: '', children: [], listeners: {} }); }
    addEventListener(type, fn, options) { (this.listeners[type] ??= []).push({ fn, once: options?.once === true }); }
    replaceChildren(...c) { this.children = c; } append(...c) { this.children.push(...c); }
    showModal() { log.push(`showModal:${this.id}`); this.open = true; active = 'review-confirm'; /* what Chrome did: the first control */ }
    focus() { log.push(`focus:${this.id}`); active = this.id; }
    fire(type) { const list = this.listeners[type] || []; this.listeners[type] = list.filter((item) => !item.once); for (const item of list) item.fn({}); }
  }
  const $ = (id) => { if (!dom.has(id)) dom.set(id, new El(id)); return dom.get(id); };
  $('review-ack-wrap').hidden = true;
  const textNode = (tag, text, className) => { const el = new El(tag); el.textContent = text; if (className) el.className = className; return el; };
  const document = { createElement: (tag) => new El(tag) };
  const assertion = (value, message) => { if (!value) throw new Error(message); };
  // NAME_ACKNOWLEDGE: the sentence app.js takes from names.mjs for the box of a review that warns about a name.
  const review = new Function('$', 'assert', 'textNode', 'document', 'busy', 'NAME_ACKNOWLEDGE', `${source.slice(start, end)}; return review;`)($, assertion, textNode, document, false, NAME_ACKNOWLEDGE);
  return { $, log, review, active: () => active };
}

test('a review opens with the focus on its title, after the dialog has opened, with or without a box to tick', async () => {
  for (const acknowledge of ['', 'I have read this.']) {
    const { $, log, review, active } = page();
    const answer = review('Send test seconds', [['Amount', '1 second']], 'Confirm & sign', { acknowledge });
    assert.deepEqual(log, ['showModal:review-dialog', 'focus:review-title'], `opened and focused in this order (acknowledge: ${JSON.stringify(acknowledge)})`);
    assert.equal(active(), 'review-title', 'the focus is not left on the button that confirms');
    // Changed after the review: the button is also disabled for the review's first moments (app.js, REVIEW_ARM_MS),
    // against the second click of a double click. After that it waits for the tick only when a tick is asked for.
    assert.equal($('review-confirm').disabled, true, 'the button cannot be pressed the moment the review opens');
    await new Promise((resolve) => setTimeout(resolve, 760));
    assert.equal($('review-confirm').disabled, acknowledge !== '', 'once armed, the button waits for the tick only when a tick is asked for');
    $('review-dialog').returnValue = 'cancel'; $('review-dialog').open = false; $('review-dialog').fire('close');
    assert.equal(await answer, false);
  }
});

test('a review asked for while one is open is refused, and a close without the asked tick is a cancel', async () => {
  const { $, review } = page();
  const first = review('First', [['A', 'b']], 'Sign', { acknowledge: 'Ticked on purpose.' });
  assert.throws(() => review('Second', [['C', 'd']]), /Another review is already open/);
  assert.equal($('review-title').textContent, 'First', 'the open review still shows what it was opened for');
  $('review-dialog').returnValue = 'confirm'; $('review-dialog').open = false; $('review-dialog').fire('close');
  assert.equal(await first, false, 'confirmed without the tick');
});

// Added with the warnings about the names typed for guardians (recovery.mjs): a review can carry warnings of its own.
test('a review that carries warnings about names shows each above its fields, with the names set apart, and always asks for a tick', async () => {
  const b0b = ['@b0b', ' looks like ', '@bob', ', another guardian in this list. Check every letter.'], d4na = ['@d4na', ' looks like ', '@dana', ', your own name. Check every letter.'];
  const close = ($, button) => { $('review-dialog').returnValue = button; $('review-dialog').open = false; $('review-dialog').fire('close'); };
  const { $, review } = page();
  // Without a sentence of the caller's, the box asks with the sentence of a payment's name.
  const first = review('Set guardian recovery policy', [['Guardians', '@bob, @d4na, @b0b']], 'Set recovery policy', { warnings: [d4na, b0b] });
  assert.deepEqual($('review-body').children.map((item) => [item.id, item.className ?? '']), [['p', 'warning name-check'], ['p', 'warning name-check'], ['dl', '']], 'the warnings stand above the fields');
  assert.deepEqual($('review-body').children[1].children.map((piece) => [piece.id, piece.textContent]), [['code', '@b0b'], ['span', ' looks like '], ['code', '@bob'], ['span', ', another guardian in this list. Check every letter.']]);
  assert.deepEqual([$('review-ack-wrap').hidden, $('review-ack-text').textContent, $('review-ack').checked], [false, 'I checked the name, letter by letter.', false]);
  await new Promise((resolve) => setTimeout(resolve, 760));
  assert.equal($('review-confirm').disabled, true, 'armed, and still waiting for the tick');
  close($, 'confirm');
  assert.equal(await first, false, 'confirmed without the tick');
  // With the caller's sentence, that sentence is asked; ticked and armed, the review confirms.
  const second = review('Set guardian recovery policy', [['Guardians', '@bob, @b0b']], 'Set recovery policy', { warnings: [b0b], acknowledge: 'I checked the guardian names, letter by letter.' });
  assert.deepEqual([$('review-ack-text').textContent, $('review-body').children.length], ['I checked the guardian names, letter by letter.', 2]);
  $('review-ack').checked = true; $('review-ack').fire('change');
  await new Promise((resolve) => setTimeout(resolve, 760));
  close($, 'confirm');
  assert.equal(await second, true);
  // No warnings, or something that is no list of them: the review is as it always was, with no box.
  for (const warnings of [[], undefined, null, 'text']) {
    const plain = review('Send test seconds', [['Amount', '1 second']], 'Confirm & sign', warnings === undefined ? {} : { warnings });
    assert.deepEqual([$('review-ack-wrap').hidden, $('review-body').children.map((item) => item.id)], [true, ['dl']], JSON.stringify(warnings));
    close($, 'cancel'); assert.equal(await plain, false);
  }
});

// Added with the fix for the reviewer's concern about clicks: a review cannot be confirmed in its first moments.
test('a review closed as confirmed in its first moments counts as cancelled; the same close a moment later confirms', async () => {
  const early = page();
  const first = early.review('Send test seconds', [['Amount', '1 second']]);
  early.$('review-dialog').returnValue = 'confirm'; early.$('review-dialog').open = false; early.$('review-dialog').fire('close');
  assert.equal(await first, false, 'confirmed 0 ms after it opened');
  // The next review of the same page is armed by its own clock, not by the one before.
  const second = early.review('Send test seconds', [['Amount', '1 second']]);
  assert.equal(early.$('review-confirm').disabled, true);
  await new Promise((resolve) => setTimeout(resolve, 760));
  assert.equal(early.$('review-confirm').disabled, false);
  early.$('review-dialog').returnValue = 'confirm'; early.$('review-dialog').open = false; early.$('review-dialog').fire('close');
  assert.equal(await second, true, 'confirmed after it was armed');
  // A review that was closed leaves no timer that arms the next one early.
  const third = early.review('Send test seconds', [['Amount', '1 second']]);
  early.$('review-dialog').returnValue = 'cancel'; early.$('review-dialog').open = false; early.$('review-dialog').fire('close');
  assert.equal(await third, false);
  const fourth = early.review('Send test seconds', [['Amount', '1 second']]);
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(early.$('review-confirm').disabled, true, 'the timer of the review before did not arm this one');
  early.$('review-dialog').returnValue = 'confirm'; early.$('review-dialog').open = false; early.$('review-dialog').fire('close');
  assert.equal(await fourth, false, 'confirmed 300 ms after it opened');
});
