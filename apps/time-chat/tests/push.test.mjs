import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { openPush } from '../push.mjs';

test('push service sends an empty wakeup and prunes expired subscriptions', async t => {
  const dir = await mkdtemp(path.join(tmpdir(),'time-chat-push-'));
  t.after(()=>rm(dir,{recursive:true,force:true}));
  const sent = [], removed = [];
  const service = await openPush(dir,async (subscription,payload,options)=>{
    sent.push({subscription,payload,options});
    if(subscription.endpoint.endsWith('/expired')) throw Object.assign(new Error('Gone'),{statusCode:410});
  });
  await service.notify({
    subscriptions:()=>[{endpoint:'https://fcm.googleapis.com/current'},{endpoint:'https://fcm.googleapis.com/expired'}],
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
