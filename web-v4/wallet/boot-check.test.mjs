// The page that never starts (boot-check.js): run in a stand-in window, and held to its place in the page. When a script
// or the stylesheet does not load, or the page has not started 20 seconds after its document was read, the wallet says
// so with a button that reloads it; once app.js has started, the check stands down.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('./boot-check.js', import.meta.url), 'utf8');
const page = await readFile(new URL('./index.html', import.meta.url), 'utf8');
const app = await readFile(new URL('./app.js', import.meta.url), 'utf8');
const MESSAGE = 'The wallet could not load. Check your connection and reload this page. Nothing was changed.';

/// A window with the elements the check uses, its timers in our hands, and the check run in it.
function load({ readyState = 'loading' } = {}) {
  const listeners = { window: {}, document: {} }, timers = [], reloads = [];
  const on = where => (type, fn, options) => (listeners[where][type] ??= []).push({ fn, once: options?.once === true, capture: options === true });
  const box = { hidden: true }, button = { listeners: {}, addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn); } };
  const classes = new Set();
  const document = { readyState, addEventListener: on('document'), getElementById: id => (id === 'boot-failed' ? box : id === 'boot-reload' ? button : null), body: { classList: { add: name => classes.add(name) } } };
  const window = { addEventListener: on('window') };
  const fire = (where, type, event = {}) => { const list = listeners[where][type] || []; listeners[where][type] = list.filter(item => !item.once); for (const item of list) item.fn(event); };
  const context = vm.createContext({ window, document, location: { reload: () => reloads.push(1) }, setTimeout: (fn, ms) => { timers.push({ fn, ms, cleared: false }); return timers.length; }, clearTimeout: id => { if (timers[id - 1]) timers[id - 1].cleared = true; } });
  vm.runInContext(source, context);
  return { listeners, timers, reloads, box, button, classes, fire, document,
    ready() { document.readyState = 'interactive'; fire('document', 'DOMContentLoaded'); },
    elapse() { for (const timer of timers.filter(t => !t.cleared && !t.ran)) { timer.ran = true; timer.fn(); } },
  };
}

test('a script or the stylesheet that does not load: the message and its button, once the document is read', () => {
  for (const target of [{ tagName: 'SCRIPT' }, { tagName: 'LINK', rel: 'stylesheet' }]) {
    const w = load();
    assert.equal(w.listeners.window.error[0].capture, true, 'caught on its way down: an element\'s error does not bubble');
    w.fire('window', 'error', { target });
    assert.equal(w.box.hidden, true, 'not before the message is in the document');
    w.ready();
    assert.deepEqual([w.box.hidden, w.classes.has('boot-failed')], [false, true]);
    w.button.listeners.click[0]();
    assert.equal(w.reloads.length, 1, 'the button reloads the page');
  }
  // Read already: at once.
  const w = load({ readyState: 'interactive' });
  w.fire('window', 'error', { target: { tagName: 'SCRIPT' } });
  assert.equal(w.box.hidden, false);
});

test('what is not a script or the stylesheet is not looked at: an image, an icon, an error of the page\'s own code', () => {
  const w = load(); w.ready();
  for (const target of [{ tagName: 'IMG' }, { tagName: 'LINK', rel: 'icon' }, { tagName: 'LINK', rel: 'manifest' }, null, {}]) w.fire('window', 'error', { target });
  assert.equal(w.box.hidden, true);
});

test('not started 20 seconds after the document was read: the message; started before that: never', () => {
  const late = load(); late.ready();
  assert.deepEqual(late.timers.map(t => t.ms), [20000]);
  late.elapse();
  assert.equal(late.box.hidden, false);
  const fine = load(); fine.ready();
  fine.fire('document', 'time-wallet:started');
  assert.equal(fine.timers[0].cleared, true);
  fine.elapse();
  fine.fire('window', 'error', { target: { tagName: 'SCRIPT' } });
  assert.equal(fine.box.hidden, true, 'after the start the page answers for itself');
  // Started before the document was read (a cached page): no timer at all.
  const quick = load(); quick.fire('document', 'time-wallet:started'); quick.ready();
  assert.equal(quick.timers.length, 0);
});

test('the check is the first script of the page, before the stylesheet; its message is in the page; app.js says when it starts', () => {
  const head = page.slice(page.indexOf('<head>'), page.indexOf('</head>'));
  const first = head.indexOf('<script'), sheet = head.indexOf('<link rel="stylesheet"');
  assert.ok(first > 0 && first < sheet, 'first, and before the stylesheet');
  assert.equal(head.slice(first, head.indexOf('</script>', first) + 9), '<script src="/boot-check.js"></script>', 'a file, not deferred: the policy allows no inline script');
  assert.ok(page.includes(`<section id="boot-failed" class="card boot-failed" role="alert" hidden><p>${MESSAGE}</p><div class="button-row"><button id="boot-reload" type="button">Reload</button></div></section>`));
  assert.ok(!/<script(?![^>]*\ssrc=)[^>]*>/.test(page), 'no inline script');
  assert.ok(app.includes("document.dispatchEvent?.(new Event('time-wallet:started'));"));
  // It sends nothing and keeps nothing.
  assert.ok(!/fetch|XMLHttpRequest|localStorage|sessionStorage|innerHTML|eval|Function\(/.test(source));
});
