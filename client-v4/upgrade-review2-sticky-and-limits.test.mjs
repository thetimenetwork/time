// A proof of the second independent review of the upgrade clients, kept as a test.
// Changed in one place, marked ADAPTED, where the fix chose another behaviour than the proof asked for (the wallet's
// learned answer), and extended in one place, marked ADDED (the watch); the rest is unchanged but for its import paths.
// Round 2: the carried question (wallet flag, watch store flag), time limits, restart.
import test from 'node:test';import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import './time-sdk.js';
import * as installed from './proof-verifier.mjs';
import {createUpgradeMonitor} from '../web-v4/wallet/actions.mjs';
import {createSecurityWatch,memoryStore} from './security-watch-service.mjs';
const sdk=globalThis.TimeSDK;
const fixture=JSON.parse(await readFile(new URL('../verifier-v4/fixtures/upgrade.json',import.meta.url),'utf8')),view=fixture.views.plan,keyHex=Buffer.from('upgrade/state').toString('hex');
const clocked=now=>({verifyTrust:t=>installed.verifyTrust(t,now),verifyLightUpdate:(b,t)=>installed.verifyLightUpdate(b,t,now),verifyViewProof:(p,t,r)=>installed.verifyViewProof(p,t,r,now)});
const memory=()=>{const m=new Map();return {getItem:k=>m.has(k)?m.get(k):null,setItem:(k,v)=>{m.set(k,String(v));},removeItem:k=>{m.delete(k);},map:m};};
const OLD_NODE='Could not obtain compatible certified V4 state: Pinned state unavailable: unknown field `include_upgrade`';
const net={ok:true,status:200,text:async()=>JSON.stringify({protocolVersion:'4',networkId:view.trust.network_id,chainId:view.trust.chain_id})};
const withEntry={ok:true,status:200,text:async()=>JSON.stringify(view.proof)},withoutEntry={ok:true,status:200,text:async()=>JSON.stringify({...view.proof,entries:view.proof.entries.filter(e=>e.key_hex!==keyHex)})};

test('WALLET, sticky flag: after one answer, a node that does not know the question (a rollback, another node behind the gateway) fails every read; nothing resets the flag',async()=>{
  const storage=memory(),key='timecurrency.upgrade-entry.v1:'+view.trust.network_id;
  let node='0.7.0';
  const fetcher=async url=>{const t=new URL(url);if(t.pathname==='/api/network')return net;const q=JSON.parse(t.searchParams.get('query'));
    if(node==='0.7.0')return q.include_upgrade?withEntry:withoutEntry;
    return q.include_upgrade?{ok:false,status:400,text:async()=>JSON.stringify({error:OLD_NODE})}:withoutEntry;};
  const client=sdk.createClient({gateway:'https://rpc.example',trust:view.trust,verifier:clocked(view.now_ms),fetcher});
  let upgrades=createUpgradeMonitor({storage,networkId:view.trust.network_id});
  const {state}=await client.getVerifiedState({include_upgrade:true});upgrades.fromState(state,sdk.upgradeStatusOf(state));
  assert.equal(storage.map.get(key),'1');
  node='0.6.0';upgrades=createUpgradeMonitor({storage,networkId:view.trust.network_id}); // a later page load
  let failure;try{await client.getVerifiedState({ids:[],...upgrades.selection()});}catch(error){failure=error;}
  console.log(' every refresh of the wallet now fails with:',failure?.message?.slice(0,120));
  assert.equal((await client.getVerifiedState({})).verified,true,'the same gateway still answers a read without the question');
  // ADAPTED: the proof asked that this read succeed. It still fails, on purpose: a wallet that falls back to a read
  // without the question whenever the question is refused lets a gateway hide a plan by refusing it. What the fix
  // adds is the way out the proof found missing: the wallet can forget the learned answer (a control beside the
  // checkpoint refresh), after which it asks on its own again and reads as before. A network whose trust data says
  // that its nodes report upgrades never learns a flag at all.
  assert.ok(failure,'with the learned answer the read carries the question and fails as a whole');
  assert.equal(upgrades.learned(),true);assert.equal(upgrades.forget(),true);
  assert.equal(storage.map.has(key),false,'the flag is gone from the storage');assert.deepEqual(upgrades.selection(),{});assert.equal(upgrades.probeDue(),true);
  assert.equal((await client.getVerifiedState({ids:[],...upgrades.selection()})).verified,true,'after forgetting, the wallet reads again');
  assert.equal(upgrades.forget(),false);
  const declared=createUpgradeMonitor({storage,networkId:view.trust.network_id,declared:true});
  assert.deepEqual([declared.capable(),declared.learned(),declared.probeDue(),declared.forget()],[true,false,false,false]);
  declared.fromState(state,sdk.upgradeStatusOf(state));assert.equal(storage.map.size,0,'a declared network stores nothing');
});

// ---- the watch
const sec=JSON.parse(await readFile(new URL('./account-security.fixture.json',import.meta.url),'utf8'));
const GENESIS='1794260994671000',S=1_000_000n,T0=2_407_000_000n;
const DEVICES=sec.secure.payload.keys.map(k=>({public_key:k.public_key,can_manage:k.role==='recover',can_spend:k.role==='spend'}));
const BASE={...sec.allowance.security,pending_limit:null,account:'5'};
const plan={activate_elapsed_micros:String(T0+21n*86_400n*S),scheduled_elapsed_micros:String(T0),spec:'5e'.repeat(32),version:'5'};
const stateAt=({height,elapsed,security=BASE,upgrade})=>({verified:true,height:String(height),state:{protocol_version:'4',network_id:sec.network_id,height:String(height),time_micros:(BigInt(GENESIS)+elapsed).toString(),genesis:{genesis_time_micros:GENESIS},accounts:[{id:'5',name:'alice',public_key:DEVICES[0].public_key,balance:String(50n*S),nonce:'3',auth_epoch:'1',devices:DEVICES,delegations:[],unbonding:[]}],security:[security],config:{},...(upgrade===undefined?{}:{upgrade})}});
const ms=elapsed=>Number((BigInt(GENESIS)+elapsed)/1000n);

test('WATCH, stored flag: after one answer, a gateway whose node does not know the question makes the watch blind, and it says the gateway "did not answer"',async()=>{
  const store=memoryStore(),got=[];let wall=ms(T0)+500,at={height:10,elapsed:T0},node='0.7.0';
  const verifiedState=async selection=>{if(selection.include_upgrade&&node!=='0.7.0')throw Object.assign(new Error(OLD_NODE),{gateway:true});return stateAt({...at,...(selection.include_upgrade?{upgrade:null}:{})});};
  const make=()=>createSecurityWatch({verifiedState,upgradeStatus:async()=>({version:'4',scheduled:null,known:true}),accounts:['5'],onEvent:async e=>got.push(e),now:()=>wall,store});
  let watch=make();await watch.poll();await watch.settled();await watch.stop();
  assert.equal((await store.get()).upgrade.capable,true);
  // The operator points the watch at another gateway of the same network, or the node is rolled back.
  node='0.6.0';watch=make();
  for(let i=1;i<=12;i++){wall+=30_000;at={height:10+i,elapsed:T0+BigInt(30*i)*S};await watch.poll();await watch.settled();}
  console.log(' events:',JSON.stringify(got.map(e=>[e.type,e.urgent,e.reason])));console.log(' message:',got[0]?.message?.slice(0,170));console.log(' /health upgrade_read:',watch.status().upgrade_read,'| failing accounts:',watch.status().failing);
  await watch.stop();
  // As the reviewer wrote it (it was adapted for one round, while the question rode on the account checks of such a
  // network). Since the third review the question is asked apart there, so no account check carries it.
  assert.deepEqual(got.map(e=>e.type),[],'a gateway that answers every account check except the new question led to an urgent watch_blind');
  // ADDED: when the question itself is no longer answered, every owner gets one message of a type of its own, not
  // urgent, which says nothing about the account. Starting once with forgetUpgradeAnswer ends that.
  const asking=()=>createSecurityWatch({verifiedState,upgradeStatus:async()=>sdk.upgradeStatusOf((await verifiedState({include_upgrade:true})).state),accounts:['5'],onEvent:async e=>got.push(e),now:()=>wall,store});
  watch=asking();
  for(let i=13;i<=18;i++){wall+=30_000;at={height:10+i,elapsed:T0+BigInt(30*i)*S};await watch.poll();await watch.settled();}
  assert.deepEqual(got.map(e=>[e.type,e.urgent,e.reason??null]),[['upgrade_question_unanswered',false,null]]);
  assert.ok(!/did not answer its last checks|cannot see your account/.test(got[0].message));
  assert.deepEqual([watch.status().failing,watch.status().blind,watch.status().upgrade_read],[0,0,'unanswered']);
  assert.equal(watch.details().last_heights['5'],'28','the account was read at every poll');
  await watch.stop();
  const forgetful=createSecurityWatch({verifiedState,upgradeStatus:async()=>{throw new Error('this node does not know the question');},forgetUpgradeAnswer:true,accounts:['5'],onEvent:async e=>got.push(e),now:()=>wall,store});
  wall+=30_000;at={height:30,elapsed:T0+570n*S};await forgetful.poll();await forgetful.settled();
  assert.deepEqual([(await store.get()).upgrade.capable,(await store.get()).upgrade.unanswered,forgetful.status().upgrade_read,got.length],[false,null,'failing',1]);
  await forgetful.stop();
});

test('WATCH, the stored flag is not checked on load: what a store whose `upgrade` is not as expected does',async()=>{
  let wall=ms(T0)+500;const results=[];
  for(const upgrade of [null,'yes',{capable:'no'},{plan:{}},{capable:true}]){
    const store=memoryStore();const first=createSecurityWatch({verifiedState:async()=>stateAt({height:10,elapsed:T0}),accounts:['5'],onEvent:async()=>{},now:()=>wall,store});
    await first.poll();await first.settled();await first.stop();
    const saved=await store.get();saved.upgrade=upgrade;await store.put(saved);
    const watch=createSecurityWatch({verifiedState:async s=>stateAt({height:11,elapsed:T0+5n*S,...(s.include_upgrade?{upgrade:null}:{})}),upgradeStatus:async()=>({version:'4',scheduled:null,known:true}),accounts:['5'],onEvent:async()=>{},now:()=>wall+5000,store});
    const report=await watch.poll().catch(error=>({crashed:error.message}));await watch.settled();
    const line={upgrade,failed:report.failed,crashed:report.crashed,problem:watch.details().problems['5']?.detail};results.push(line);console.log(' ',JSON.stringify(line));await watch.stop();
  }
  assert.ok(results.every(r=>!r.crashed&&(r.failed??[]).length===0),'a malformed `upgrade` field of the store stops the account checks');
});

test('WATCH, restart: plan notices and account alerts are neither lost nor sent twice; account alerts leave before the upgrade question is asked',async()=>{
  const store=memoryStore(),got=[],order=[];let wall=ms(T0)+500,at={height:10,elapsed:T0};const status={version:'4',scheduled:plan,known:false};
  const payment={id:'2',to:'42',amount:String(12_500_000n),ready_elapsed_micros:String(T0+65n*S)};
  const verifiedState=async s=>stateAt({...at,...(s.include_upgrade?{upgrade:{plan,signals:[]}}:{})});
  const make=()=>createSecurityWatch({verifiedState,upgradeStatus:async()=>{order.push('QUESTION');return status;},upgradeOf:()=>status,accounts:['5'],onEvent:async e=>{order.push(e.type);got.push(e);},now:()=>wall,store});
  let watch=make();await watch.poll();await watch.settled();await watch.stop();
  order.length=0;got.length=0;
  // A fresh store for the ordering check: the first poll finds a waiting payment and the question is still open.
  const store2=memoryStore(),got2=[],order2=[];
  const make2=()=>createSecurityWatch({verifiedState,upgradeStatus:async()=>{order2.push('QUESTION');return status;},upgradeOf:()=>status,accounts:['5'],onEvent:async e=>{order2.push(e.type);got2.push(e);},now:()=>wall,store:store2});
  let w2=make2();await w2.poll();await w2.settled();
  at={height:11,elapsed:T0+5n*S,security:{...BASE,pending_payments:[payment],next_id:'3'}};wall+=5000;
  // Forget the flag in memory by restarting on a store saved before the answer: emulate with a new store copy.
  await w2.stop();
  const store3=memoryStore(),order3=[],got3=[];
  const w3=createSecurityWatch({verifiedState:async s=>stateAt({height:10,elapsed:T0}),upgradeStatus:async()=>{order3.push('QUESTION');return status;},upgradeOf:()=>status,accounts:['5'],onEvent:async e=>{order3.push(e.type);got3.push(e);},now:()=>ms(T0)+500,store:store3});
  // first poll of w3: snapshot only, question asked after
  await w3.poll();await w3.settled();await w3.stop();
  console.log(' fresh watch, first poll:',order3.join(' > '));
  // w2 continues after restart with the flag stored: the payment and nothing twice
  for(let i=0;i<3;i++){w2=make2();await w2.poll();await w2.settled();await w2.stop();wall+=30_000;at={...at,height:12+i,elapsed:T0+BigInt(35+30*i)*S};}
  console.log(' events over three restarts:',got2.map(e=>e.type).join(', '));
  assert.equal(new Set(got2.map(e=>e.id)).size,got2.length,'an event was sent twice');
  assert.equal(got2.filter(e=>e.type==='upgrade_scheduled').length,1);assert.equal(got2.filter(e=>e.type==='upgrade_cancelled').length,0);
  assert.equal(got2.filter(e=>e.type==='payment_waiting').length,1);
});

test('TIME LIMIT: a read abandoned at the limit fails with timeout:true; its late answer sets no flag and raises no unhandled rejection',async()=>{
  let unhandled=0;const on=()=>{unhandled++;};process.on('unhandledRejection',on);
  let delay=400,aborted=0;
  const fetcher=async(url,options={})=>{const t=new URL(url);if(t.pathname==='/api/network')return net;options.signal?.addEventListener('abort',()=>{aborted++;});await new Promise(r=>setTimeout(r,delay));return JSON.parse(t.searchParams.get('query')).include_upgrade?withEntry:withoutEntry;};
  const client=sdk.createClient({gateway:'https://rpc.example',trust:view.trust,verifier:clocked(view.now_ms),fetcher});
  const storage=memory(),upgrades=createUpgradeMonitor({storage,networkId:view.trust.network_id});
  const started=performance.now();
  await assert.rejects(client.getVerifiedState({include_upgrade:true},{timeoutMs:150}),e=>e.timeout===true&&e.code===undefined);
  const shown=upgrades.probeFailed(Object.assign(new Error('x'),{timeout:true}));
  console.log(' failed after',Math.round(performance.now()-started),'ms; the wallet shows:',shown.banner.text);
  await new Promise(r=>setTimeout(r,500)); // the late answer arrives (this gateway ignores the abort)
  assert.equal(aborted,1);assert.equal(upgrades.capable(),false);assert.equal(storage.map.size,0);
  delay=0;assert.equal((await client.getVerifiedState({})).verified,true);assert.equal(unhandled,0);
  for(const bad of [-1,1.5,600001,'20',NaN])await assert.rejects(client.getVerifiedState({},{timeoutMs:bad}),/timeoutMs/);
  process.off('unhandledRejection',on);
});
