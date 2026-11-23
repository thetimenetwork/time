// Review helper: the fake page of views.test.mjs, exported, so that review tests drive the same page code.
import assert from 'node:assert/strict';

export class Text { constructor(text) { this.text = String(text); } get textContent() { return this.text; } }
export class El {
  constructor(tag, id = '') { Object.assign(this, { tagName: tag, id, children: [], attributes: {}, listeners: {}, className: '', hidden: false, value: '', parent: null }); }
  set textContent(value) { this.children = [new Text(value)]; }
  get textContent() { return this.children.map((child) => child.textContent).join(''); }
  set innerHTML(_) { throw new Error('innerHTML must never be used'); }
  append(...nodes) { for (const node of nodes) { assert(node instanceof El || node instanceof Text, 'only elements and text nodes are appended'); this.children.push(node); } }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  removeAttribute(name) { delete this.attributes[name]; }
  getAttribute(name) { return this.attributes[name] ?? null; }
  addEventListener(type, listener) { (this.listeners[type] ??= []).push(listener); }
  focus() { this.ownerPage.focused = this; }
  fire(type, event = {}) { for (const listener of this.listeners[type] ?? []) listener({ preventDefault() {}, ...event }); }
}
export function page(hash = '#/') {
  const byId = new Map(), state = { focused: null }, listeners = {};
  const make = (tag, id) => { const element = new El(tag, id); element.ownerPage = state; return element; };
  const document = { title: '', getElementById: (id) => { if (!byId.has(id)) byId.set(id, make('div', id)); return byId.get(id); }, createElement: (tag) => make(tag), createTextNode: (text) => new Text(text) };
  const window = { location: { hash }, addEventListener: (type, listener) => { (listeners[type] ??= []).push(listener); } };
  return { document, window, state, $: document.getElementById, go: (next) => { window.location.hash = next; for (const listener of listeners.hashchange ?? []) listener(); } };
}
export const all = (node, out = []) => { if (node instanceof El) { out.push(node); for (const child of node.children) all(child, out); } return out; };
const INLINE = new Set(['span', 'a', 'code', 'strong', 'bdi']);
const flow = (node) => (node instanceof Text ? node.text : (INLINE.has(node.tagName) ? '' : ' ') + node.children.map(flow).join('') + (INLINE.has(node.tagName) ? '' : ' '));
export const textOf = (node) => flow(node).replace(/\s+/g, ' ').trim();
export const within = (root, className) => all(root).filter((element) => element.className.split(' ').includes(className));
export const buttons = (root, label) => all(root).filter((element) => element.tagName === 'button' && element.textContent === label);
export function fakeTimers() {
  const timers = { timeouts: [], intervals: [], setTimeout: (fn, ms) => { const entry = { fn, ms, cleared: false }; timers.timeouts.push(entry); return entry; }, clearTimeout: (entry) => { if (entry) entry.cleared = true; },
    setInterval: (fn, ms) => { const entry = { fn, ms, cleared: false }; timers.intervals.push(entry); return entry; }, clearInterval: (entry) => { if (entry) entry.cleared = true; } };
  return timers;
}
