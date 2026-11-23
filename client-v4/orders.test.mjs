import test from 'node:test';
import assert from 'node:assert/strict';
import './time-sdk.js';
import {createOrderService} from './server-auth.mjs';
const sdk=globalThis.TimeSDK,networkId='ab'.repeat(32);
const state={protocol_version:'4',network_id:networkId,time_micros:'600000000',genesis:{genesis_time_micros:'0'},accounts:[{id:'5',nonce:'7'}],recovery_cases:[],config:{}};
test('V4 order reference is nonceBE8 + expiryBE8 + random16 with exact u64 precision',()=>{
  const nonce=BigInt('0x0102030405060708').toString(),expiry=BigInt('0x08090a0b0c0d0e0f').toString(),randomHex='f0'.repeat(16);
  const ref=sdk.orderReference({nonce,expiresElapsedMicros:expiry,randomHex});
  assert.equal(ref,'010203040506070808090a0b0c0d0e0f'+'f0'.repeat(16));
  assert.deepEqual(sdk.decodeOrderReference(ref),{nonce,expiresElapsedMicros:expiry,randomHex});
  assert.throws(()=>sdk.orderReference({nonce:'18446744073709551616',expiresElapsedMicros:'1'}),/canonical/);
});
test('V4 wallet preflight rejects consumed nonce, expired quote and overly long quote',()=>{
  const ref=sdk.orderReference({nonce:'8',expiresElapsedMicros:'780000000'});
  assert.equal(sdk.checkMerchantQuote(ref,'8',state).nonce,'8');
  assert.throws(()=>sdk.checkMerchantQuote(ref,'9',state),/another nonce/);
  assert.throws(()=>sdk.checkMerchantQuote(ref,'8',{...state,time_micros:'780000001'}),/expired/);
  assert.throws(()=>sdk.checkMerchantQuote(sdk.orderReference({nonce:'8',expiresElapsedMicros:'87000000001'}),'8',state),/protocol limit/);
  assert.throws(()=>sdk.checkMerchantQuote(ref,'8',{...state,protocol_version:'2'}),/version 4/);
});
test('merchant V4 quote comes from fresh verified payer nonce and consensus elapsed time',async()=>{
  const queries=[],snapshots=[];
  const orders=createOrderService({networkId,recipient:'0',protocolVersion:'4',verifiedState:async q=>{queries.push(q);return {verified:true,state};},verifiedReceipt:async()=>{throw Error('not needed');},persist:async s=>snapshots.push(s),now:()=>1000});
  const order=await orders.issue('5','10000');
  assert.deepEqual(queries,[{ids:['5']}]);assert.equal(order.reservedNonce,'8');assert.equal(order.expiresElapsedMicros,'780000000');assert.equal(order.expiresAt,181000);
  assert.equal(sdk.decodeOrderReference(order.orderId).nonce,'8');assert.equal(snapshots[0].orders[0].orderId,order.orderId);
  const later=createOrderService({networkId,recipient:'0',protocolVersion:'4',verifiedState:async()=>({verified:true,state:{...state,accounts:[{id:'5',nonce:'8'}]}}),verifiedReceipt:async()=>{},persist:async()=>{}});
  assert.equal((await later.issue('5','10000')).reservedNonce,'9');
});
test('V4 exact order settlement binds action nonce and still allows late reconciliation',async()=>{
  let order,nonce='8',time=1000;const snapshots=[];
  const config={networkId,recipient:'0',protocolVersion:'4',verifiedState:async()=>({verified:true,state}),persist:async s=>snapshots.push(s),now:()=>time,verifiedReceipt:async hash=>({verified:true,executionVerified:true,code:0,networkId,height:'50',hash,action:{kind:10,from:'5',nonce,payload:{to:'0',amount:'10000',reference:order.orderId}}})};
  const orders=createOrderService(config);order=await orders.issue('5','10000');nonce='9';
  await assert.rejects(orders.fulfill('5',order.orderId,'aa'.repeat(32)),/reserved order nonce/);
  nonce='8';time=200000;const settled=await orders.fulfill('5',order.orderId,'aa'.repeat(32));
  assert.equal(settled.fulfilled,true);assert.equal(settled.lateReconciliation,true);
  const resumed=createOrderService({...config,initialState:snapshots.at(-1)});
  assert.equal((await resumed.fulfill('5',order.orderId,'aa'.repeat(32))).fulfilled,true);
  const corrupted=structuredClone(snapshots.at(-1));corrupted.orders[0].reservedNonce='9';
  assert.throws(()=>createOrderService({...config,initialState:corrupted}),/reserved nonce\/expiry/);
});
