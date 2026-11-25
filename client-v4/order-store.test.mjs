import test from 'node:test';import assert from 'node:assert/strict';import {mkdtemp,rm} from 'node:fs/promises';import os from 'node:os';import path from 'node:path';import {createOrderStore} from './order-store.mjs';import {createOrderService} from './server-auth.mjs';
test('indexed SQLite orders exceed old laboratory cap, survive restart and enforce settlement uniqueness',async()=>{
 const directory=await mkdtemp(path.join(os.tmpdir(),'time-v4-orders-')),filename=path.join(directory,'orders.sqlite'),networkId='aa'.repeat(32),state={protocol_version:'4',network_id:networkId,time_micros:'1000',genesis:{genesis_time_micros:'0'},accounts:[{id:'5',nonce:'7'}],recovery_cases:[],config:{}};let repository;
 // One order from each of 1100 accounts (one account may have only 3 waiting for their payment at once: audit G-3).
 const verifiedState=async query=>({verified:true,state:{...state,accounts:[{id:query.ids[0],nonce:'7'}]}});
 try{repository=createOrderStore({filename,networkId,recipient:'0'});const service=createOrderService({networkId,recipient:'0',repository,verifiedState,verifiedReceipt:async()=>{throw Error('unused');}});let order;
  for(let i=0;i<1100;i++)order=await service.issue(String(1000+i),'1000');assert.equal(order.accountId,'2099');assert(order);repository.close();repository=createOrderStore({filename,networkId,recipient:'0'});assert.deepEqual(repository.get(order.orderId),order);
  const hash='BB'.repeat(32),settled={...order,fulfilled:true,hash,height:'5'};repository.settle(settled);assert.equal(repository.usedHash(hash),order.orderId);assert.throws(()=>repository.settle(settled),/race/);
  const next=await createOrderService({networkId,recipient:'0',repository,verifiedState,verifiedReceipt:async()=>{throw Error('unused');}}).issue('5','1000');assert.throws(()=>repository.settle({...next,fulfilled:true,hash,height:'5'}),/UNIQUE/);
  assert.throws(()=>createOrderStore({filename,networkId:'cc'.repeat(32),recipient:'0'}),/another network/);
 }finally{repository?.close();await rm(directory,{recursive:true,force:true});}
});

// Audit G-3: one signed-in account made 588 orders in 12 seconds, all kept for ever (proof poc1.mjs, part C).
test('one account: its open order back for the same amount and nonce, at most 3 waiting at once, unpaid ones deleted a day after they expired',async()=>{
 const directory=await mkdtemp(path.join(os.tmpdir(),'time-v4-orders-')),filename=path.join(directory,'orders.sqlite'),networkId='aa'.repeat(32);let repository,nonce=7,chainMicros=1000,clock=1_000_000;
 const verifiedState=async query=>({verified:true,state:{protocol_version:'4',network_id:networkId,time_micros:String(chainMicros),genesis:{genesis_time_micros:'0'},accounts:[{id:query.ids[0],nonce:String(nonce)}],recovery_cases:[],config:{}}});
 const rows=()=>{const db=new (process.getBuiltinModule('node:sqlite').DatabaseSync)(filename,{readOnly:true});try{return Number(db.prepare('SELECT COUNT(*) n FROM orders').get().n);}finally{db.close();}};
 try{
  repository=createOrderStore({filename,networkId,recipient:'0'});
  const service=createOrderService({networkId,recipient:'0',repository,verifiedState,now:()=>clock,verifiedReceipt:async()=>{throw Error('unused');}});
  // Asked again for the same item while the first still reserves the next nonce: the same order.
  const first=await service.issue('5','1000');
  assert.deepEqual(await service.issue('5','1000'),first);
  for(let i=0;i<20;i++)assert.equal((await service.issue('5','1000')).orderId,first.orderId);
  // Another amount, and the same amount once the account has acted (its nonce moved): new orders, up to three open.
  const second=await service.issue('5','2000');nonce=8;const third=await service.issue('5','1000');
  assert.equal(new Set([first.orderId,second.orderId,third.orderId]).size,3);assert.equal(third.reservedNonce,'9');
  await assert.rejects(service.issue('5','3000'),error=>error.httpStatus===429&&error.message==='This account has 3 orders waiting for their payment, the most at once. Pay one of them, or ask again once they have expired, three minutes after they were made.');
  // Another account is not held by the first.
  assert.equal((await service.issue('6','1000')).accountId,'6');
  // Less than a minute before its expiry an order is not given back: a new one, once the others have expired.
  clock+=150_000;chainMicros+=150_000_000;
  await assert.rejects(service.issue('5','1000'),/3 orders waiting/);
  clock+=31_000;chainMicros+=31_000_000;
  const fourth=await service.issue('5','1000');assert.notEqual(fourth.orderId,third.orderId);
  // A settled order stays for ever; one nobody paid is deleted a day after it expired.
  const hash='CC'.repeat(32);repository.settle({...second,fulfilled:true,hash,height:'5'});
  assert.equal(rows(),5);
  clock+=86_400_000+179_000;chainMicros+=86_579_000_000;
  const fifth=await service.issue('7','1000');
  assert.equal(rows(),3,'the settled order, the order of the day before that has not expired a day ago, and the new one');
  assert.deepEqual([repository.get(second.orderId)?.fulfilled,repository.get(first.orderId),repository.get(fifth.orderId)?.accountId],[true,null,'7']);
  // An order is named by its reference only: anything else is no order, and is not asked of the store.
  for(const orderId of [{a:1},['x'],'x',42,'AA'.repeat(32)])await assert.rejects(service.fulfill('5',orderId,'dd'.repeat(32)),/Unknown payment order/,JSON.stringify(orderId));
 }finally{repository?.close();await rm(directory,{recursive:true,force:true});}
});
