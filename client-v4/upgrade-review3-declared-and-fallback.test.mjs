// A proof of the third independent review of the upgrade clients, kept as a test.
// Unchanged but for its import paths, with two tests added at the end, marked ADDED. All six of the reviewer's tests
// pass as written. Its two FALLBACK tests failed at the reviewed commit (40 messages in 10 minutes; an urgent alert
// held for the whole gateway time limit). They pass now because, on a network whose trust data does not declare that
// its nodes report upgrades, the watch no longer puts the question into an account check at all: it asks it apart,
// after each poll. Their gateway acts on requests that carry the question and their `upgradeStatus` always answers, so
// since the fix it meets no such request. The added tests aim the same two attacks at the question where it is asked now.
// Round 3: the trust field `nodes_report_upgrades`, the declared path in the SDK, the wallet's
// monitor and the watch, and the watch's fallback on a network that does not declare it.
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
const declared={...view.trust,nodes_report_upgrades:true};
const net={ok:true,status:200,text:async()=>JSON.stringify({protocolVersion:'4',networkId:view.trust.network_id,chainId:view.trust.chain_id,trust:{...view.trust,nodes_report_upgrades:false}})};
const withEntry={ok:true,status:200,text:async()=>JSON.stringify(view.proof)},withoutEntry={ok:true,status:200,text:async()=>JSON.stringify({...view.proof,entries:view.proof.entries.filter(e=>e.key_hex!==keyHex)})};
const OLD='Could not obtain compatible certified V4 state: Pinned state unavailable: unknown field `include_upgrade`';
const client=(trust,answer,asked=[])=>sdk.createClient({gateway:'https://rpc.example',trust,verifier:clocked(view.now_ms),fetcher:async url=>{const t=new URL(url);if(t.pathname==='/api/network')return net;const q=JSON.parse(t.searchParams.get('query'));asked.push(q);return answer(q);}});

test('declared: the question is on every read from the first one, a caller cannot switch it off, and the plan shows at once',async()=>{
  const asked=[],c=client(declared,q=>q.include_upgrade?withEntry:withoutEntry,asked);
  assert.equal(c.nodesReportUpgrades,true);
  const first=await c.getVerifiedState({});
  const upgrades=createUpgradeMonitor({storage:memory(),networkId:view.trust.network_id,declared:c.nodesReportUpgrades===true});
  const shown=upgrades.fromState(first.state,sdk.upgradeStatusOf(first.state));
  console.log(' first read shows:',shown.banner.text.slice(0,110));
  assert.equal(shown.banner.urgent,true);assert.match(shown.banner.text,/scheduled to move to version 5/);
  await c.getVerifiedState({include_upgrade:false});await c.account('alice');await c.getUpgradeStatus();await c.getVerifiedState({names:['alice'],include_upgrade:false});
  assert.deepEqual(asked.map(q=>q.include_upgrade),[true,true,true,true,true]);
  assert.equal(upgrades.probeDue(),false);assert.deepEqual(upgrades.selection(),{include_upgrade:true});assert.equal(upgrades.learned(),false);assert.equal(upgrades.forget(),false);
  // The gateway's own /api/network carries a trust object that says false: nothing reads it.
  assert.equal((await c.getNetwork()).trust.nodes_report_upgrades,false);assert.equal(c.nodesReportUpgrades,true);
});

test('declared: the quiet words, a left-out entry and a held question all fail the read itself (no healthy wallet without the answer)',async()=>{
  for(const [label,answer,expected] of [
    ['refuses with the old node\'s words',q=>q.include_upgrade?{ok:false,status:400,text:async()=>JSON.stringify({error:OLD})}:withoutEntry,/unknown field/],
    ['leaves the entry out',()=>withoutEntry,/missing requested proof for 757067726164652f7374617465/],
    ['answers "Invalid proof selection"',q=>q.include_upgrade?{ok:false,status:400,text:async()=>JSON.stringify({error:'Invalid proof selection'})}:withoutEntry,/Invalid proof selection/],
  ]){
    const asked=[],c=client(declared,answer,asked);
    for(const read of [()=>c.getVerifiedState({}),()=>c.getVerifiedState({include_upgrade:false}),()=>c.account('alice')])await assert.rejects(read(),expected,label);
    assert.ok(asked.every(q=>q.include_upgrade===true),label);
    const storage=memory(),upgrades=createUpgradeMonitor({storage,networkId:view.trust.network_id,declared:true});
    assert.equal(upgrades.probeDue(),false);assert.equal(storage.map.size,0);
  }
  // Held: every read hangs; with a time limit it fails. Nothing verifies meanwhile.
  const c=client(declared,q=>q.include_upgrade?new Promise(()=>{}):withoutEntry);
  let outcome='pending';c.getVerifiedState({}).then(()=>{outcome='answered';},()=>{outcome='failed';});
  await assert.rejects(c.getVerifiedState({},{timeoutMs:200}),e=>e.timeout===true);
  assert.equal(outcome,'pending');
});

test('the trust field takes true, false or nothing; and a trust without it on the same chain verifies all the same',async()=>{
  for(const bad of ['true',1,0,null,{},[]])assert.throws(()=>client({...view.trust,nodes_report_upgrades:bad},()=>withEntry),/nodes_report_upgrades is true or false/,JSON.stringify(bad));
  for(const trust of [view.trust,{...view.trust,nodes_report_upgrades:false}]){const asked=[],c=client(trust,q=>q.include_upgrade?withEntry:withoutEntry,asked);assert.equal(c.nodesReportUpgrades,false);assert.equal((await c.getVerifiedState({})).verified,true);assert.equal(Object.hasOwn(asked[0],'include_upgrade'),false);}
  // Nothing else in the trust object or on the chain depends on the field: dropping it is not detected.
  const {nodes_report_upgrades:_,...stripped}=declared;
  assert.equal((await client(stripped,q=>q.include_upgrade?withEntry:withoutEntry).getVerifiedState({})).verified,true);
});

// ---- the watch
const sec=JSON.parse(await readFile(new URL('./account-security.fixture.json',import.meta.url),'utf8'));
const GENESIS='1794260994671000',S=1_000_000n,T0=2_407_000_000n;
const DEVICES=sec.secure.payload.keys.map(k=>({public_key:k.public_key,can_manage:k.role==='recover',can_spend:k.role==='spend'}));
const BASE={...sec.allowance.security,pending_limit:null,account:'5'};
const plan={activate_elapsed_micros:String(T0+21n*86_400n*S),scheduled_elapsed_micros:String(T0),spec:'5e'.repeat(32),version:'5'};
const payment={id:'2',to:'42',amount:String(12_500_000n),ready_elapsed_micros:String(T0+65n*S)};
const stateAt=({height,elapsed,security=BASE,upgrade})=>({verified:true,height:String(height),state:{protocol_version:'4',network_id:sec.network_id,height:String(height),time_micros:(BigInt(GENESIS)+elapsed).toString(),genesis:{genesis_time_micros:GENESIS},accounts:[{id:'5',name:'alice',public_key:DEVICES[0].public_key,balance:String(50n*S),nonce:'3',auth_epoch:'1',devices:DEVICES,delegations:[],unbonding:[]}],security:[security],config:{},...(upgrade===undefined?{}:{upgrade})}});
const ms=elapsed=>Number((BigInt(GENESIS)+elapsed)/1000n);
const refusal=()=>Object.assign(new Error(OLD),{gateway:true});

test('declared watch: the plan and an urgent alert come with the first polls; a held or refused question is an unreachable gateway, never a quiet watch',async()=>{
  const got=[];let wall=ms(T0)+500,at={height:10,elapsed:T0},mode='honest';const selections=[];
  const verifiedState=async s=>{selections.push(s);if(mode==='refuse'&&s.include_upgrade)throw refusal();if(mode==='leave out')return stateAt(at);return stateAt({...at,...(s.include_upgrade?{upgrade:{plan,signals:[]}}:{})});};
  const watch=createSecurityWatch({verifiedState,upgradeDeclared:true,upgradeStatus:async()=>{throw new Error('never called on a declared network');},accounts:['5'],onEvent:async e=>got.push({type:e.type,urgent:e.urgent,reason:e.reason}),now:()=>wall});
  await watch.poll();await watch.settled();
  at={height:11,elapsed:T0+5n*S,security:{...BASE,pending_payments:[payment],next_id:'3'}};wall+=5000;await watch.poll();await watch.settled();
  console.log(' honest gateway:',JSON.stringify(got));
  assert.ok(selections.every(s=>s.include_upgrade===true));
  assert.deepEqual(got.map(e=>e.type),['upgrade_scheduled','watch_outdated','payment_waiting']);
  for(const lie of ['refuse','leave out']){
    mode=lie;const before=got.length;
    for(let i=1;i<=12;i++){wall+=30_000;at={...at,height:at.height+1,elapsed:at.elapsed+30n*S};await watch.poll();await watch.settled();}
    console.log(` gateway that ${lie}s the question:`,JSON.stringify(got.slice(before)),'| health:',watch.status().upgrade_read);
    assert.deepEqual(got.slice(before).map(e=>[e.type,e.urgent]),[['watch_blind',true]],lie);
    mode='honest';wall+=30_000;at={...at,height:at.height+1,elapsed:at.elapsed+30n*S};await watch.poll();await watch.settled();
  }
  await watch.stop();
});

test('FALLBACK (undeclared, learned): a gateway that answers every other question-carrying request flips the watch at every poll',async()=>{
  const got=[];let wall=ms(T0)+500,at={height:10,elapsed:T0},attack=false,carried=0;
  // The attack: requests that carry the question are refused and answered in turn. The watch sends
  // them in this order: account check (refused), then, after the poll, its retry of the question (answered).
  const verifiedState=async s=>{if(s.include_upgrade&&attack&&(carried++%2===0))throw refusal();return stateAt({...at,...(s.include_upgrade?{upgrade:null}:{})});};
  const watch=createSecurityWatch({verifiedState,upgradeStatus:async()=>({version:'4',scheduled:null,known:true}),accounts:['5'],onEvent:async e=>got.push({type:e.type,urgent:e.urgent,reason:e.reason}),now:()=>wall,store:memoryStore()});
  await watch.poll();await watch.settled();           // learns that the node answers
  wall+=30_000;at={height:11,elapsed:T0+30n*S};await watch.poll();await watch.settled();assert.deepEqual(got,[]);
  attack=true;const polls=20;
  for(let i=0;i<polls;i++){wall+=30_000;at={height:12+i,elapsed:T0+BigInt(60+30*i)*S};await watch.poll();await watch.settled();}
  const count=type=>got.filter(e=>e.type===type&&e.reason==='upgrade_question').length;
  console.log(` after ${polls} polls (10 minutes at the default 30 s): watch_blind(upgrade_question) x${count('watch_blind')}, watch_restored(upgrade_question) x${count('watch_restored')}, other events: ${got.filter(e=>e.reason!=='upgrade_question').length}`);
  await watch.stop();
  assert.ok(got.length<=2,`one owner got ${got.length} messages about a question that was never really gone`);
});

test('FALLBACK: the same gateway, holding instead of refusing, delays the first batch\'s urgent alert by the gateway timeout at every poll',async()=>{
  const got=[];let wall=ms(T0)+500,at={height:10,elapsed:T0},attack=false,carried=0,started=0;
  const verifiedState=s=>{if(s.include_upgrade&&attack&&(carried++%2===0))return new Promise(()=>{});return Promise.resolve(stateAt({...at,...(s.include_upgrade?{upgrade:null}:{})}));};
  const watch=createSecurityWatch({verifiedState,upgradeStatus:async()=>({version:'4',scheduled:null,known:true}),accounts:['5'],onEvent:async e=>got.push({type:e.type,urgent:e.urgent,afterMs:Math.round(performance.now()-started)}),now:()=>wall,store:memoryStore(),batchTimeoutMs:1500});
  await watch.poll();await watch.settled();attack=true;
  wall+=5000;at={height:11,elapsed:T0+5n*S,security:{...BASE,pending_payments:[payment],next_id:'3'}};started=performance.now();await watch.poll();await watch.settled();
  const urgent=got.find(e=>e.type==='payment_waiting');console.log(' urgent payment_waiting left after',urgent.afterMs,'ms (batchTimeoutMs 1500 here; gateway_timeout_seconds, default 30 s, in the watch process)');
  await watch.stop();
  assert.ok(urgent.afterMs<500,`the urgent alert waited ${urgent.afterMs} ms for the held question`);
});

// ---- ADDED: the same two attacks, aimed at the question where the watch now asks it (apart, through the same gateway)
const through=verifiedState=>async()=>sdk.upgradeStatusOf((await verifiedState({include_upgrade:true})).state);

test('FALLBACK, ADDED: every other question refused where the watch now asks it: one message in 10 minutes, not urgent, of a type of its own',async()=>{
  const got=[],selections=[];let wall=ms(T0)+500,at={height:10,elapsed:T0},attack=false,carried=0;
  const verifiedState=async s=>{selections.push(s);if(s.include_upgrade&&attack&&(carried++%2===0))throw refusal();return stateAt({...at,...(s.include_upgrade?{upgrade:null}:{})});};
  const watch=createSecurityWatch({verifiedState,upgradeStatus:through(verifiedState),accounts:['5'],onEvent:async e=>got.push({type:e.type,urgent:e.urgent,reason:e.reason}),now:()=>wall,store:memoryStore()});
  await watch.poll();await watch.settled();           // learns that the node answers
  wall+=30_000;at={height:11,elapsed:T0+30n*S};await watch.poll();await watch.settled();assert.deepEqual(got,[]);
  attack=true;const polls=20;
  for(let i=0;i<polls;i++){wall+=30_000;at={height:12+i,elapsed:T0+BigInt(60+30*i)*S};await watch.poll();await watch.settled();}
  console.log(` after ${polls} polls: ${JSON.stringify(got)} | health: ${watch.status().upgrade_read} | failing accounts: ${watch.status().failing}`);
  await watch.stop();
  assert.ok(got.length<=2,`one owner got ${got.length} messages about a question that was never really gone`);
  assert.deepEqual(got.map(e=>[e.type,e.urgent]),[['upgrade_question_unanswered',false]]);
  assert.equal(carried,polls,'the question was asked once after every poll, and refused every other time');
  assert.ok(selections.filter(s=>s.ids).every(s=>!Object.hasOwn(s,'include_upgrade')),'an account check carried the question');
  assert.equal(watch.status().failing,0);
});

test('FALLBACK, ADDED: the question held where the watch now asks it: the urgent alert leaves at once, at every poll',async()=>{
  const got=[];let wall=ms(T0)+500,at={height:10,elapsed:T0},attack=false,started=0;
  const verifiedState=s=>{if(s.include_upgrade&&attack)return new Promise(()=>{});return Promise.resolve(stateAt({...at,...(s.include_upgrade?{upgrade:null}:{})}));};
  const watch=createSecurityWatch({verifiedState,upgradeStatus:through(verifiedState),accounts:['5'],onEvent:async e=>got.push({type:e.type,urgent:e.urgent,id:e.id,afterMs:Math.round(performance.now()-started)}),now:()=>wall,store:memoryStore(),batchTimeoutMs:700});
  await watch.poll();await watch.settled();attack=true;
  const second={id:'3',to:'43',amount:String(1_000_000n),ready_elapsed_micros:String(T0+95n*S)};
  // Two polls, each with a new waiting payment, while every question is held to the time limit.
  wall+=5000;at={height:11,elapsed:T0+5n*S,security:{...BASE,pending_payments:[payment],next_id:'3'}};started=performance.now();await watch.poll();await watch.settled();
  wall+=30_000;at={height:12,elapsed:T0+35n*S,security:{...BASE,pending_payments:[payment,second],next_id:'4'}};started=performance.now();await watch.poll();await watch.settled();
  const urgent=got.filter(e=>e.type==='payment_waiting');console.log(' urgent payment_waiting left after',urgent.map(e=>e.afterMs).join(' ms and '),'ms (batchTimeoutMs 700 here)');
  await watch.stop();
  assert.equal(urgent.length,2);
  for(const e of urgent)assert.ok(e.afterMs<300,`the urgent alert waited ${e.afterMs} ms for the held question`);
  // The held question itself is told once, without urgency, after its own time limit.
  assert.deepEqual(got.filter(e=>e.type!=='payment_waiting').map(e=>[e.type,e.urgent]),[['upgrade_question_unanswered',false]]);
});
