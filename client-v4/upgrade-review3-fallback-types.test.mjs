// A proof of the third independent review of the upgrade clients, kept as a test.
// Unchanged but for its import paths, with one test added at the end, marked ADDED. The reviewer's test passes as
// written. Since the fix the watch asks the question apart and tells of it with two event types of its own
// (upgrade_question_unanswered, upgrade_question_answered), so the reviewer's gateway, which acts on requests that
// carry the question, meets none (its `upgradeStatus` always answers). The added test runs the same sequence with the
// question going through that gateway.
// Round 3: the fallback reuses the event types watch_blind / watch_restored for the upgrade question.
// (1) The real, urgent blindness is NOT suppressed while the question is unanswered (holds).
// (2) A watch_restored (reason upgrade_question) can reach the owner while the account is still
//     unseen: a receiver that goes by the type alone would take the watch for restored.
import test from 'node:test';import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import './time-sdk.js';
import {createSecurityWatch,memoryStore} from './security-watch-service.mjs';
const sec=JSON.parse(await readFile(new URL('./account-security.fixture.json',import.meta.url),'utf8'));
const GENESIS='1794260994671000',S=1_000_000n,T0=2_407_000_000n;
const DEVICES=sec.secure.payload.keys.map(k=>({public_key:k.public_key,can_manage:k.role==='recover',can_spend:k.role==='spend'}));
const BASE={...sec.allowance.security,pending_limit:null,account:'5'};
const stateAt=({height,elapsed,upgrade})=>({verified:true,height:String(height),state:{protocol_version:'4',network_id:sec.network_id,height:String(height),time_micros:(BigInt(GENESIS)+elapsed).toString(),genesis:{genesis_time_micros:GENESIS},accounts:[{id:'5',name:'alice',public_key:DEVICES[0].public_key,balance:String(50n*S),nonce:'3',auth_epoch:'1',devices:DEVICES,delegations:[],unbonding:[]}],security:[BASE],config:{},...(upgrade===undefined?{}:{upgrade})}});
const ms=elapsed=>Number((BigInt(GENESIS)+elapsed)/1000n);
const refuse=()=>{throw Object.assign(new Error('refused'),{gateway:true});};

test('the urgent blindness still goes out while the question is unanswered; and a watch_restored arrives while the account is unseen',async()=>{
  const got=[];let wall=ms(T0)+500,at={height:10,elapsed:T0},mode='honest',carriedSeen=0;
  const verifiedState=async s=>{
    if(mode==='honest')return stateAt({...at,...(s.include_upgrade?{upgrade:null}:{})});
    if(mode==='question refused')return s.include_upgrade?refuse():stateAt(at);
    // 'dark': nothing is answered, except one single request that carries the question.
    if(s.include_upgrade&&carriedSeen++===0)return stateAt({...at,upgrade:null});
    return refuse();
  };
  const watch=createSecurityWatch({verifiedState,upgradeStatus:async()=>({version:'4',scheduled:null,known:true}),accounts:['5'],onEvent:async e=>got.push({type:e.type,urgent:e.urgent,reason:e.reason??null}),now:()=>wall,store:memoryStore()});
  const step=async()=>{wall+=30_000;at={height:at.height+1,elapsed:at.elapsed+30n*S};await watch.poll();await watch.settled();};
  await watch.poll();await watch.settled();await step();
  mode='question refused';await step();await step();
  const frozen={...at};mode='dark';
  for(let i=0;i<14;i++){wall+=30_000;await watch.poll();await watch.settled();} // the chain view does not move: nothing verified
  at=frozen;
  console.log(' events in order:');for(const e of got)console.log('  ',JSON.stringify(e));
  console.log(' at the end: blind accounts',watch.status().blind,'| failing',watch.status().failing,'| upgrade_read',watch.status().upgrade_read);
  await watch.stop();
  const urgentBlind=got.findIndex(e=>e.type==='watch_blind'&&e.urgent),restored=got.findIndex(e=>e.type==='watch_restored');
  assert.ok(urgentBlind>=0,'the urgent watch_blind was suppressed');
  assert.ok(restored<0||got[restored].reason!=='upgrade_question'||got.slice(restored).some(e=>e.type==='watch_blind'&&e.urgent)||restored<urgentBlind,'a watch_restored (upgrade_question) is the last word to the owner while the account is unseen');
});

// ---- ADDED: the same sequence, with the question asked through the same gateway
test('ADDED: the urgent blindness goes out, and what is said about the question never has the type watch_blind or watch_restored',async()=>{
  const got=[];let wall=ms(T0)+500,at={height:10,elapsed:T0},mode='honest',carriedSeen=0;
  const verifiedState=async s=>{
    if(mode==='honest')return stateAt({...at,...(s.include_upgrade?{upgrade:null}:{})});
    if(mode==='question refused')return s.include_upgrade?refuse():stateAt(at);
    // 'dark': no account check is answered; the question is answered once, or ('dark, question answered') always.
    if(s.include_upgrade&&(mode==='dark, question answered'||carriedSeen++===0))return stateAt({...at,upgrade:null});
    return refuse();
  };
  const upgradeStatus=async()=>globalThis.TimeSDK.upgradeStatusOf((await verifiedState({include_upgrade:true})).state);
  const watch=createSecurityWatch({verifiedState,upgradeStatus,accounts:['5'],onEvent:async e=>got.push({type:e.type,urgent:e.urgent,reason:e.reason??null}),now:()=>wall,store:memoryStore()});
  const step=async()=>{wall+=30_000;at={height:at.height+1,elapsed:at.elapsed+30n*S};await watch.poll();await watch.settled();};
  await watch.poll();await watch.settled();await step();
  mode='question refused';await step();await step();
  assert.deepEqual(got,[{type:'upgrade_question_unanswered',urgent:false,reason:null}]);
  mode='dark';
  for(let i=0;i<14;i++){wall+=30_000;await watch.poll();await watch.settled();} // the chain view does not move: nothing verified
  // The account stays unseen while the gateway answers the question again, several times in a row.
  mode='dark, question answered';
  for(let i=0;i<4;i++){wall+=30_000;await watch.poll();await watch.settled();}
  console.log(' events in order:');for(const e of got)console.log('  ',JSON.stringify(e));
  console.log(' at the end: blind accounts',watch.status().blind,'| failing',watch.status().failing,'| upgrade_read',watch.status().upgrade_read);
  const status=watch.status();await watch.stop();
  assert.deepEqual(got,[{type:'upgrade_question_unanswered',urgent:false,reason:null},{type:'watch_blind',urgent:true,reason:'unreachable'},{type:'upgrade_question_answered',urgent:false,reason:null}]);
  // A receiver that goes by the type alone: the last word about the watch is "blind", and nothing says "restored".
  assert.equal(got.filter(e=>e.type.startsWith('watch_')).at(-1).type,'watch_blind');
  assert.ok(got.every(e=>e.type!=='watch_restored'));
  assert.deepEqual([status.blind,status.failing,status.upgrade_read],[1,1,'ok']);
});
