import test from 'node:test';
import assert from 'node:assert/strict';
import { managerOrigin, openManager } from './manager-client.mjs';
import { holdVaultField, takeWalletField, clearVaultFields, installVaultFields } from './manager-fields.mjs';
import { keysView } from './actions.mjs';

const wallet = 'https://wallet.testnet.thetimenetwork.org', vault = 'https://vault.testnet.thetimenetwork.org';
function fixture() {
  const messages = [], listeners = new Map(), timers = new Map();
  const popup = { closed: false, close() { this.closed = true; }, postMessage(data, origin) { messages.push([structuredClone(data), origin]); } };
  const win = {
    crypto, location: { origin: wallet },
    open(url, name) { assert.equal(url, vault + '/'); assert.equal(name, '_blank'); return popup; },
    addEventListener: (type, fn) => listeners.set(type, fn), removeEventListener: type => listeners.delete(type),
    setTimeout: fn => (timers.set('timeout', fn), 1), clearTimeout: () => timers.delete('timeout'),
    setInterval: fn => (timers.set('poll', fn), 2), clearInterval: () => timers.delete('poll')
  };
  const deliver = (data, origin = vault, source = popup) => listeners.get('message')?.({ data, origin, source });
  return { win, popup, timers, messages, deliver };
}
const ready = { v: 1, type: 'time:vault-ready' };
const account = { name: 'lina', networkId: 'bc'.repeat(32) };
test('managed account help explains where the keys live and how to recover after device loss', () => {
  const view = keysView({ name: account.name, managed: true, protectedAccount: true, limit: '600 seconds', recoveryKind: 'words' });
  assert.match(view.lede, /encrypted in this browser/);
  assert.match(view.note, /update that entry/);
  assert.deepEqual(view.cards.map(c => c.id), ['login', 'payment', 'phrase']);
  assert.match(JSON.stringify(view.cards), /paper recovery words/);
});
test('only paired wallet origins have a vault', () => {
  assert.equal(managerOrigin(wallet), vault);
  assert.equal(managerOrigin('http://localhost:8780'), 'http://localhost:8786');
  assert.equal(managerOrigin('http://127.0.0.1:8780'), null);
  for (const origin of [vault, wallet + '.invalid', wallet.replace('https:', 'http:'), 'http://localhost:8781']) assert.equal(managerOrigin(origin), null);
});
test('blocked or refused popup gives browser settings guidance without showing a browser error', () => {
  for (const open of [() => null, () => { throw new DOMException('Internal popup diagnostic', 'SecurityError'); }]) {
    const f = fixture();
    f.win.open = open;
    assert.throws(() => openManager(f.win), { message: 'Allow pop-ups for this wallet in your browser, then open Time Vault again.' });
    assert.equal(f.timers.size, 0);
  }
});
test('a field request accepts only the paired popup and its matching response, once', async () => {
  const f = fixture(), handle = openManager(f.win), result = handle.get({ ...account, role: 'spend' });
  f.deliver(ready, wallet); f.deliver(ready, vault, {});
  assert.equal(f.messages.length, 0);
  f.deliver(ready); f.deliver(ready); assert.equal(f.messages.length, 1);
  const [[request, target]] = f.messages;
  assert.equal(target, vault); assert.equal(request.role, 'spend'); assert.equal(request.name, account.name);
  const reply = { type: 'time:vault-result', v: 1, id: request.id, ok: true, value: 'only the requested password' };
  f.deliver({ ...reply, id: 'stale' }); f.deliver(reply, wallet); f.deliver(reply, vault, {});
  assert.equal(f.popup.closed, false);
  f.deliver(reply);
  assert.equal(await result, reply.value); assert.equal(f.popup.closed, true); assert.equal(f.timers.size, 0);
});
test('distinguish a save which never left the wallet from a lost acknowledgement', async () => {
  for (const sent of [false, true]) {
    const f = fixture(), handle = openManager(f.win);
    if (sent) f.deliver(ready);
    const promise = handle.save({ ...account, secrets: { signin: 's', spend: 'p', recover: 'r' } });
    f.timers.get('timeout')();
    await assert.rejects(promise, e => Boolean(e.unsaved) === !sent);
    assert.equal(f.popup.closed, true);
  }
});
test('confirmed pre-write cancellation allows staged enrollment to be rolled back', async () => {
  const f = fixture(), handle = openManager(f.win);
  f.deliver(ready);
  const promise = handle.save({ ...account, secrets: { signin: 's', spend: 'p', recover: 'r' } });
  const [request, target] = f.messages[0];
  assert.equal(target, vault); assert.equal(request.secrets.recover, 'r');
  f.deliver({ v: 1, type: 'time:vault-result', id: request.id, ok: false, reason: 'cancelled', error: 'Private browser diagnostic.', unsaved: true });
  await assert.rejects(promise, { unsaved: true, message: 'The vault request was cancelled. Open Time Vault again to continue.' });
});
test('legacy or unrecognized vault replies keep the save status and hide the supplied error text', async () => {
  for (const [reason, unsaved] of [[undefined, true], [undefined, false], ['constructor', false]]) {
    const f = fixture(), handle = openManager(f.win);
    f.deliver(ready);
    const promise = handle.save({ ...account, secrets: { signin: 's', spend: 'p', recover: 'r' } });
    const [request] = f.messages[0];
    f.deliver({ v: 1, type: 'time:vault-result', id: request.id, ok: false, reason, unsaved, error: 'Private browser diagnostic.' });
    await assert.rejects(promise, error => Boolean(error.unsaved) === unsaved && error.message === 'Time Vault could not finish. Open it again from the wallet and check your account.');
  }
});
test('vault credentials stay out of the DOM, are consumed once, and expire on a context change', () => {
  const field = { value: '' };
  holdVaultField(field, 'one action only', () => true);
  assert.notEqual(field.value, 'one action only'); assert.equal(takeWalletField(field), 'one action only');
  assert.equal(takeWalletField(field), '');
  holdVaultField(field, 'old account', () => false);
  assert.throws(() => takeWalletField(field)); assert.equal(field.value, '');
  holdVaultField(field, 'old', () => true); field.value = 'typed instead';
  assert.equal(takeWalletField(field), 'typed instead');
  holdVaultField(field, 'old', () => true); clearVaultFields(); assert.equal(takeWalletField(field), '');
});
test('payment, login and lost-device forms request only their own roles and preserve manual entry', async () => {
  const inputs = new Map(), requests = [];
  function element() {
    const listeners = new Map();
    return { value: '', addEventListener: (t,f) => listeners.set(t,f), dispatchEvent: e => listeners.get(e.type)?.(e),
      click: () => listeners.get('click')(), after(button) { this.button = button; }, getClientRects: () => [1] };
  }
  const doc = { getElementById(id) { if (!inputs.has(id)) inputs.set(id, element()); return inputs.get(id); }, createElement: element };
  installVaultFields({ doc, context: () => account, notice() {}, startManager: () => ({
    get: async request => { requests.push(request); return 'value for ' + request.role; }, close() {}
  }) });
  for (const [id, role] of [['approval-payment','spend'], ['backup-export-password','signin'], ['lost-phrase','recover'], ['freeze-secret','recover']]) {
    const field = inputs.get(id); await field.button.click();
    assert.deepEqual(requests.at(-1), { ...account, role });
    assert.equal(takeWalletField(field), 'value for ' + role);
  }
  assert.equal(inputs.has('replace-login-new'), false);
});
