import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { createMessage, encrypt, generateKey } from 'openpgp';
import { createChatServer, loginRateAddress } from '../server.mjs';
import { openStore } from '../store.mjs';
import { validateSubscription } from '../push.mjs';

const net = 'a'.repeat(64);
test('low disk space pauses new messages and rooms while preserving history and retries', t => {
  const directory = mkdtempSync(path.join(tmpdir(), 'time-chat-disk-'));
  const filename = path.join(directory, 'chat.sqlite');
  let freeBytes = 128n * 1024n * 1024n;
  const store = openStore(filename, net, { volumeStats: () => ({ bavail: freeBytes, bsize: 1n }) });
  t.after(() => { store.close(); rmSync(directory, { recursive: true, force: true }); });
  for (const id of ['1', '2', '3']) store.enroll({ id, name: 'account' + id, publicKey: 'public ' + id, attestation: {} });
  const room = store.createChat('1', ['2']);
  const sent = store.append(room.id, '1', 'first', 'ciphertext');
  freeBytes = 1024n;
  assert.equal(store.createChat('2', ['1']).id, room.id);
  assert.deepEqual(store.append(room.id, '1', 'first', 'ciphertext'), { seq: sent.seq, inserted: false });
  const nearFull = e => e.status === 503;
  assert.throws(() => store.append(room.id, '1', 'second', 'ciphertext'), nearFull);
  assert.throws(() => store.createChat('1', ['3']), nearFull);
  assert.equal(store.history(room.id, '2').messages.length, 1);
  freeBytes = 128n * 1024n * 1024n;
  assert.equal(store.append(room.id, '1', 'second', 'ciphertext').inserted, true);
  assert.ok(store.createChat('1', ['3']).id);
});

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
    assert.equal(store.list('2').chats[0].unread, 52);
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
    assert.equal(store.list('2').chats[0].unread, 0);
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
  assert.equal(store.block('1', '2', true), true);
  assert.equal(store.block('1', '2', true), false);
  assert.deepEqual(
    store.blocks('1').map((u) => u.id),
    ['2']
  );
  assert.deepEqual(store.list('1').chats, []);
  assert.deepEqual(store.list('2').chats, []);
  assert.throws(() => store.createChat('2', ['1']));
  assert.throws(() => store.append(group.id, '2', 'a', 'b'));
  assert.deepEqual(
    store.visibleParticipants(group.id).map((u) => u.id),
    ['3']
  );
  store.block('1', '2', false);
  assert.equal(store.list('1').chats[0].id, group.id);
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

test('a rolling envelope allowance counts persisted bytes per sender and preserves idempotent delivery', t => {
  const directory = mkdtempSync(path.join(tmpdir(),'time-chat-volume-'));
  const filename = path.join(directory,'messages.sqlite');
  let store = fixtures(filename);
  t.after(() => { store.close(); rmSync(directory,{recursive:true,force:true}); });
  const room = store.createChat('1',['2']).id;
  const sent = store.append(room,'1','receipt','saved');
  store.db.prepare('INSERT INTO messages(room,senderId,messageId,ciphertext,createdAt) VALUES(?,?,?,zeroblob(?),?)')
    .run(room,'1','volume',8 * 1024 * 1024,Date.now());
  store.close();
  store = openStore(filename,net);
  assert.deepEqual(store.append(room,'1','receipt','saved'), {seq:sent.seq,inserted:false});
  assert.throws(() => store.append(room,'1','next','envelope'), {status:429});
  assert.equal(store.append(room,'2','from-another','envelope').inserted,true);
  store.db.prepare('UPDATE messages SET createdAt=0 WHERE messageId=?').run('volume');
  assert.equal(store.append(room,'1','next','envelope').inserted,true);
});

test('new-room allowance belongs to the creator and permits reopening existing rooms', t => {
  const store = fixtures();
  t.after(() => store.close());
  for (let n = 10; n < 110; n++) {
    const id = String(n);
    store.enroll({id, name:'user'+id, publicKey:'fixture '+id, attestation:{}});
    store.createChat('1',[id]);
  }
  assert.ok(store.createChat('1',['10']).id);
  assert.throws(() => store.createChat('1',['2']), {status:429});
  const first = store.list('1');
  assert.equal(first.chats.length,24);
  assert.ok(first.nextCursor);
  assert.ok(store.createChat('10',['2']).id);
  store.db.prepare('UPDATE room_creations SET createdAt=0 WHERE creator=?').run('1');
  assert.ok(store.createChat('1',['2']).id);
});

test('inbox cursors traverse equal timestamps and byte-limited rosters, excluding blocked rooms', t => {
  const store = fixtures();
  t.after(() => store.close());
  const roster = [], expected = [];
  for (let i = 10; i < 36; i++) {
    const id = String(i);
    store.enroll({id,name:'user'+id,publicKey:'a'.repeat(16_384),attestation:{}});
    if (i < 24) roster.push(id);
    else {
      const room = store.createChat('1',[...roster,id]);
      if (i !== 24) expected.push(room.id);
    }
  }
  store.db.exec('UPDATE rooms SET updatedAt=100');
  store.block('1','24',true);
  const found = [];
  let cursor = null;
  do {
    const page = store.list('1',cursor);
    assert.ok(Buffer.byteLength(JSON.stringify(page)) <= 1024 * 1024);
    assert.ok(page.chats.length && page.chats.length < 12);
    found.push(...page.chats.map(chat=>chat.id));
    cursor = page.nextCursor;
  } while (cursor);
  assert.deepEqual(found,expected.sort());
  assert.throws(() => store.list('1',''), {status:400});
  assert.throws(() => store.list('1','9007199254740992.'+expected[0]), {status:400});
});

test('byte-limited history pages retain each maximum-size envelope', t => {
  const store = fixtures();
  t.after(() => store.close());
  const { id } = store.createChat('1',['2']);
  const ciphertext = 'x'.repeat(128 * 1024);
  for (let n=0; n<10; n++) store.append(id,'1',String(n),ciphertext);
  const newest = store.history(id,'2');
  assert.equal(newest.hasMore,true);
  assert.ok(Buffer.byteLength(JSON.stringify(newest)) <= 1024 * 1024);
  const older = store.history(id,'2',newest.messages[0].seq);
  assert.equal(older.hasMore,false);
  const all = [...older.messages,...newest.messages];
  assert.deepEqual(all.map(row=>row.messageId),Array.from({length:10},(_,i)=>String(i)));
  assert.ok(all.every(row=>row.ciphertext===ciphertext));
});

test('hosted approvals use host-bound cookies and the relay accepts ordinary encrypted envelopes', async t => {
  const store = fixtures();
  const origin = 'https://chat.example', hosts = [];
  const session = 'fixture-session';
  let signedIn = true;
  const auth = { networkId:net, issue:()=>({token:'fixture-pre',challenge:{}}),
    sessionAccount:token=>signedIn && token === session ? '1' : null,
    logout:()=>{ signedIn = false; },
    current:async token=>signedIn && token === session ? {accountId:'1',name:'alice',expiresAt:Date.now()+60_000} : null };
  const relay = createChatServer({auth,store,origin,hosts});
  relay.listen(0,'127.0.0.1');
  await once(relay,'listening');
  const host = '127.0.0.1:' + relay.address().port;
  hosts.push(host);
  t.after(async () => { await new Promise(resolve=>relay.close(resolve)); store.close(); });
  const base = 'http://' + host;
  const post = (route, value, extra={}) => fetch(base + route, {method:'POST',
    headers:{'content-type':'application/json',origin,...extra},body:JSON.stringify(value)});
  const start = await post('/api/login/challenge',{});
  assert.equal(start.status,200);
  assert.match(start.headers.get('set-cookie'),/^__Host-time_chat_pre=.*; Path=\/; HttpOnly; SameSite=Strict; Max-Age=180; Secure$/);
  const cookie = '__Host-time_chat_session=' + session;
  const { csrf } = await (await fetch(base+'/api/me',{headers:{cookie}})).json();
  assert.ok(csrf);
  const before = await fetch(base+'/api/me',{headers:{cookie:'time_chat_session='+session}});
  assert.deepEqual(await before.json(),{user:null});
  const room = store.createChat('1',['2']).id;
  const { publicKey } = await generateKey({type:'curve25519',format:'object',config:{v6Keys:true}});
  const message = await createMessage({text:'fixture text'});
  const ciphertext = await encrypt({message,encryptionKeys:publicKey,config:{aeadProtect:true}});
  const endpoint = '/api/chats/'+room+'/messages', headers = {cookie,'x-csrf-token':csrf};
  const info = await fetch(base+'/api/chats/'+room,{headers:{cookie}});
  assert.equal((await info.json()).chat.id,room);
  const outside = store.createChat('2',['3']).id;
  assert.equal((await fetch(base+'/api/chats/'+outside,{headers:{cookie}})).status,404);
  assert.equal((await post('/api/login/challenge',{publicKey:publicKey.armor()},headers)).status,200);
  assert.equal((await post(endpoint,{messageId:crypto.randomUUID(),ciphertext},headers)).status,200);
  assert.equal((await post(endpoint,{messageId:crypto.randomUUID(),ciphertext:message.armor()},headers)).status,400);
  const response = await fetch(base+'/api/events',{headers:{cookie},signal:AbortSignal.timeout(3000)});
  const events = response.body.getReader();
  assert.equal(new TextDecoder().decode((await events.read()).value),': connected\n\n');
  assert.equal((await post('/api/logout',{},headers)).status,200);
  assert.equal((await events.read()).done,true);
});

test('only an explicitly trusted local proxy supplies the directly connected address', () => {
  const forwarded = '192.0.2.7, 2001:db8::a';
  assert.equal(loginRateAddress('127.0.0.1',forwarded,false),'127.0.0.1');
  assert.equal(loginRateAddress('192.0.2.33',forwarded,true),'192.0.2.33');
  assert.equal(loginRateAddress('127.0.0.1',forwarded,true),'2001:db8::a');
  assert.equal(loginRateAddress('::1','not-an-ip',true),'::1');
});
