import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { openStore } from '../store.mjs';
import { validateSubscription } from '../push.mjs';

const net = 'a'.repeat(64);
function fixtures(filename = ':memory:') {
  const store = openStore(filename, net);
  for (const [id, name] of [
    ['1', 'alice'],
    ['2', 'bob'],
    ['3', 'cleo'],
    ['4', 'dan'],
  ]) {
    store.enroll({ id, name, publicKey: 'public ' + id, attestation: { id } });
  }
  return store;
}
test('a room survives restart with stable membership, paged history, a read cursor, and idempotent delivery', (t) => {
  const directory = mkdtempSync(path.join(tmpdir(), 'time-chat-store-'));
  const filename = path.join(directory, 'chat.sqlite');
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  let store = fixtures(filename);
  try {
    const group = store.createChat('1', ['3', '2']);
    assert.equal(store.createChat('2', ['1', '3']).id, group.id);
    for (let n = 0; n < 52; n++)
      store.append(group.id, '1', 'id' + n, 'encrypted' + n);
    assert.equal(store.list('2')[0].unread, 52);
    const recent = store.history(group.id, '2');
    assert.equal(recent.messages.length, 50);
    assert.equal(recent.hasMore, true);
    assert.equal(
      store.history(group.id, '2', recent.messages[0].seq).messages.length,
      2
    );
    assert.equal(
      store.append(group.id, '1', 'id51', 'encrypted51').inserted,
      false
    );
    assert.throws(() => store.append(group.id, '1', 'id51', 'different'));
    assert.throws(() => store.history(group.id, '4'));
    assert.throws(() => store.append(group.id, '4', 'id52', 'encrypted52'));
    store.markRead(group.id, '2', recent.messages.at(-1).seq);
    store.close();
    store = openStore(filename, net);
    assert.equal(store.list('2')[0].unread, 0);
    assert.equal(
      store.history(group.id, '2').messages.at(-1).ciphertext,
      'encrypted51'
    );
    assert.throws(
      () => openStore(filename, 'b'.repeat(64)),
      /another Time network/
    );
  } finally {
    store.close();
  }
});
test('immutable enrollment, exact directory and blocking, including shared groups', (t) => {
  const store = fixtures();
  t.after(() => store.close());
  assert.deepEqual(store.contact('ali'), []);
  assert.equal(store.contact('@alice')[0].id, '1');
  assert.throws(
    () =>
      store.enroll({
        id: '1',
        name: 'alice',
        publicKey: 'changed',
        attestation: {},
      }),
    /different chat key/
  );
  const group = store.createChat('1', ['2', '3']);
  store.block('1', '2', true);
  assert.deepEqual(
    store.blocks('1').map((u) => u.id),
    ['2']
  );
  assert.deepEqual(store.list('1'), []);
  assert.deepEqual(store.list('2'), []);
  assert.throws(() => store.createChat('2', ['1']));
  assert.throws(() => store.append(group.id, '2', 'a', 'b'));
  assert.deepEqual(
    store.visibleParticipants(group.id).map((u) => u.id),
    ['3']
  );
  store.block('1', '2', false);
  assert.equal(store.list('1')[0].id, group.id);
});
test('push subscriptions use a browser service and belong to one account', (t) => {
  const store = fixtures();
  t.after(() => store.close());
  const sub = {
    endpoint: 'https://fcm.googleapis.com/fcm/send/example',
    keys: {
      auth: Buffer.alloc(16).toString('base64url'),
      p256dh: Buffer.concat([Buffer.from([4]), Buffer.alloc(64)]).toString(
        'base64url'
      ),
    },
  };
  assert.deepEqual(validateSubscription(sub), sub);
  assert.throws(() =>
    validateSubscription({ ...sub, endpoint: 'http://localhost/push' })
  );
  assert.throws(() =>
    validateSubscription({ ...sub, endpoint: 'https://example.com/push' })
  );
  store.subscribe('1', sub);
  assert.throws(() => store.subscribe('2', sub));
  store.unsubscribe('2', sub.endpoint);
  assert.equal(store.subscriptions('1').length, 1);
  store.unsubscribe('1', sub.endpoint);
  assert.deepEqual(store.subscriptions('1'), []);
});
