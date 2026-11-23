import test from 'node:test';import assert from 'node:assert/strict';import {mkdtemp,rm} from 'node:fs/promises';import os from 'node:os';import path from 'node:path';import {createOrderStore} from './order-store.mjs';import {createOrderService} from './server-auth.mjs';
test('indexed SQLite orders exceed old laboratory cap, survive restart and enforce settlement uniqueness',async()=>{
 const directory=await mkdtemp(path.join(os.tmpdir(),'time-v4-orders-')),filename=path.join(directory,'orders.sqlite'),networkId='aa'.repeat(32),state={protocol_version:'4',network_id:networkId,time_micros:'1000',genesis:{genesis_time_micros:'0'},accounts:[{id:'5',nonce:'7'}],recovery_cases:[],config:{}};let repository;
 try{repository=createOrderStore({filename,networkId,recipient:'0'});const service=createOrderService({networkId,recipient:'0',repository,verifiedState:async()=>({verified:true,state}),verifiedReceipt:async()=>{throw Error('unused');}});let order;
  for(let i=0;i<1100;i++)order=await service.issue('5','1000');assert(order);repository.close();repository=createOrderStore({filename,networkId,recipient:'0'});assert.deepEqual(repository.get(order.orderId),order);
  const hash='BB'.repeat(32),settled={...order,fulfilled:true,hash,height:'5'};repository.settle(settled);assert.equal(repository.usedHash(hash),order.orderId);assert.throws(()=>repository.settle(settled),/race/);
  const next=await createOrderService({networkId,recipient:'0',repository,verifiedState:async()=>({verified:true,state}),verifiedReceipt:async()=>{throw Error('unused');}}).issue('5','1000');assert.throws(()=>repository.settle({...next,fulfilled:true,hash,height:'5'}),/UNIQUE/);
  assert.throws(()=>createOrderStore({filename,networkId:'cc'.repeat(32),recipient:'0'}),/another network/);
 }finally{repository?.close();await rm(directory,{recursive:true,force:true});}
});
