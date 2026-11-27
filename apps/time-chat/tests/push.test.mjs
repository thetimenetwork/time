import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { openPush } from '../push.mjs';

const browserKeys = {
  auth: Buffer.alloc(16).toString('base64url'),
  p256dh: Buffer.concat([Buffer.from([4]), Buffer.alloc(64)]).toString('base64url'),
};

test('push service sends an empty wakeup and prunes expired subscriptions', async t => {
  const dir = await mkdtemp(path.join(tmpdir(),'time-chat-push-'));
  t.after(()=>rm(dir,{recursive:true,force:true}));
  const sent = [], removed = [];
  const service = await openPush(dir,async (subscription,payload,options)=>{
    sent.push({subscription,payload,options});
    if(subscription.endpoint.endsWith('/expired')) throw Object.assign(new Error('Gone'),{statusCode:410});
  });
  await service.notify({
    subscriptions:()=>['current','expired'].map(path=>({endpoint:'https://fcm.googleapis.com/'+path, keys:browserKeys})),
    unsubscribe:(id,endpoint)=>removed.push({id,endpoint})
  },'9');
  assert.equal(sent.length,2);
  for (const delivery of sent) {
    assert.equal(delivery.payload,undefined);
    assert.equal(delivery.options.topic,'time-chat');
  }
  assert.deepEqual(removed,[{id:'9',endpoint:'https://fcm.googleapis.com/expired'}]);
  assert.equal(service.publicKey,(await openPush(dir)).publicKey);
});

test('each endpoint gets one pending wakeup and stored destinations are checked again', async t => {
  const dir = await mkdtemp(path.join(tmpdir(),'time-chat-push-'));
  t.after(() => rm(dir,{recursive:true,force:true}));
  const destinations = [];
  const completion = Promise.withResolvers();
  const service = await openPush(dir, async (sub, payload, options) => {
    destinations.push(sub.endpoint);
    assert.equal(options.agent.maxTotalSockets, 16);
    await completion.promise;
  });
  const valid = {endpoint:'https://fcm.googleapis.com/current', keys:browserKeys};
  const store = { subscriptions: () => [valid, { ...valid, endpoint:'https://example.com/unused' }] };
  const first = service.notify(store,'9');
  await service.notify(store,'9');
  assert.deepEqual(destinations,[valid.endpoint]);
  completion.resolve();
  await first;
  await service.notify(store,'9');
  assert.deepEqual(destinations,[valid.endpoint, valid.endpoint]);
});

test('the service worker shows fixed text and opens its own app', async () => {
  const handlers={}, shown=[], opened=[];
  const self={
    addEventListener:(type,fn)=>{handlers[type]=fn;},
    registration:{showNotification:(...args)=>shown.push(args)},
    location:{origin:'https://chat.example'},
    clients:{matchAll:async()=>[],openWindow:async url=>opened.push(url)}
  };
  vm.runInNewContext(await readFile(new URL('../public/sw.js',import.meta.url),'utf8'),{self,URL});
  let pending;
  handlers.push({data:{text:()=> 'private sender and contents'},waitUntil:task=>{pending=task;}});
  await pending;
  assert.equal(shown[0][0],'Time Chat');
  assert.equal(shown[0][1].body,'Open Time Chat to check for new messages.');
  assert.ok(!JSON.stringify(shown).includes('private sender'));
  handlers.notificationclick({notification:{close(){}},waitUntil:task=>{pending=task;}});
  await pending;
  assert.deepEqual(opened,['/']);
});
