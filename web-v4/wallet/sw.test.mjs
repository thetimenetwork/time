// The wallet's service worker (sw.js): it shows fixed words on a push and opens only the wallet when they are tapped.
// It must not be able to change what the wallet page loads: no fetch handler, no cache, no import, no other address.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('./sw.js', import.meta.url), 'utf8');
/// The code without its comments: what the browser runs.
const code = source.replace(/\/\*[\s\S]*?\*\//g, '').split('\n').map((line) => line.replace(/(^|[^:'"])\/\/.*$/, '$1')).join('\n');

test('the worker has no fetch handler, keeps no cache, imports nothing and names no address', () => {
  const listeners = [...code.matchAll(/addEventListener\(\s*'([a-z]+)'/g)].map((m) => m[1]);
  assert.deepEqual(listeners, ['install', 'activate', 'push', 'notificationclick']);
  for (const forbidden of [/\bfetch\b/, /\bonfetch\b/, /importScripts/, /\bimport\b/, /\bcaches\b/, /\bCache\b/, /indexedDB/, /localStorage/, /sessionStorage/, /https?:/, /\beval\b/, /new Function/, /postMessage/, /navigate\(/])
    assert.ok(!forbidden.test(code), `sw.js must not hold ${forbidden}`);
  // It opens one address: its own scope.
  assert.deepEqual([...code.matchAll(/openWindow\(([^)]*)\)/g)].map((m) => m[1]), ['scope']);
  assert.match(code, /const scope = self\.registration\.scope;/);
  // The words are fixed here; nothing of the push is read.
  assert.ok(!/event\.data|\.json\(\)|\.text\(\)/.test(code));
  assert.match(code, /const TITLE = 'Time';/);
  assert.match(code, /const BODY = 'Open your wallet to check your account\.';/);
});

/// Runs the worker in a stand-in of its global scope.
function load({ windows = [], scope = 'https://wallet.example/' } = {}) {
  const handlers = {}, shown = [], opened = [], focused = [];
  const self = {
    addEventListener: (type, fn) => { handlers[type] = fn; },
    skipWaiting: () => {},
    registration: { scope, showNotification: async (title, options) => { shown.push({ title, options }); } },
    clients: { claim: async () => {}, matchAll: async () => windows.map((w) => ({ ...w, focus: async () => { focused.push(w.url); return w; } })), openWindow: async (url) => { opened.push(url); } },
  };
  new Function('self', source)(self);
  const fire = async (type, event) => { let waiting = null; await handlers[type]({ ...event, waitUntil: (p) => { waiting = p; } }); await waiting; };
  return { handlers, shown, opened, focused, fire };
}

test('a push shows one notification with fixed words, whatever it carries; several pushes are one (the same tag)', async () => {
  const worker = load();
  let read = false;
  const data = new Proxy({}, { get: () => { read = true; return () => '<b>Your account was emptied, click here</b> https://evil.example'; } });
  await worker.fire('push', { data });
  await worker.fire('push', { data: null });
  assert.equal(read, false, 'the payload is never read');
  assert.deepEqual(worker.shown, [
    { title: 'Time', options: { body: 'Open your wallet to check your account.', tag: 'time-account-alert', renotify: true } },
    { title: 'Time', options: { body: 'Open your wallet to check your account.', tag: 'time-account-alert', renotify: true } },
  ]);
});

test('a tap closes the notification and brings the wallet forward, or opens it at the worker\'s scope, never anywhere else', async () => {
  let closed = 0;
  const notification = { close: () => { closed += 1; }, data: { url: 'https://evil.example/' } };
  const open = load({ windows: [{ url: 'https://other.example/page' }, { url: 'https://wallet.example/#receive' }] });
  await open.fire('notificationclick', { notification });
  assert.deepEqual([closed, open.focused, open.opened], [1, ['https://wallet.example/#receive'], []]);
  const none = load({ windows: [{ url: 'https://other.example/' }, { url: 'https://wallet.example.evil.example/' }] });
  await none.fire('notificationclick', { notification });
  assert.deepEqual([none.focused, none.opened], [[], ['https://wallet.example/']]);
  // Under a path, the scope is that path.
  const nested = load({ scope: 'https://wallet.example/wallet/', windows: [{ url: 'https://wallet.example/' }] });
  await nested.fire('notificationclick', { notification });
  assert.deepEqual([nested.focused, nested.opened], [[], ['https://wallet.example/wallet/']]);
});
