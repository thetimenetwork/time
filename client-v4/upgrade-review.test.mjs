// The proofs of the independent review of the upgrade clients, kept as tests. Each one failed
// against the code it was written for. They are the reviewer's, changed only where a fix changed
// an interface (said at each place), with the further forms the review asked for.
//
// 1. A gateway forged UPGRADE_REQUIRED by sending the words inside a JSON array: the wallet showed
//    "Update this app" with the gateway's text, and the watch sent an urgent watch_outdated.
// 2. The watch read the upgrade status between finding an urgent event and sending it: a gateway
//    that held only that request held every urgent alert for the whole gateway timeout.
// 3. A gateway hid the wallet's upgrade banner by never answering the one request that carried
//    include_upgrade, while every other read kept verifying.
import test from 'node:test';import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import './time-sdk.js';
import * as installed from './proof-verifier.mjs';
import {upgradeRequiredScreen,upgradeBanner,upgradeProblem,createUpgradeMonitor} from '../web-v4/wallet/actions.mjs';
import {createSecurityWatch} from './security-watch-service.mjs';
const sdk=globalThis.TimeSDK;
const fixture=JSON.parse(await readFile(new URL('../verifier-v4/fixtures/upgrade.json',import.meta.url),'utf8'));
const views=fixture.views,keyHex=Buffer.from('upgrade/state').toString('hex');
const clocked=now=>({verifyTrust:t=>installed.verifyTrust(t,now),verifyLightUpdate:(b,t)=>installed.verifyLightUpdate(b,t,now),verifyViewProof:(p,t,r)=>installed.verifyViewProof(p,t,r,now),verifyReceipt:(p,t)=>installed.verifyReceipt(p,t,now)});

// ---- 1. the forged refusal

// An honest version-4 chain ('plan' view). The gateway controls only its HTTP answers.
function wallet(error,{status=400}={}){
  const view=views.plan;
  const fetcher=async url=>{const route=new URL(url).pathname;const answer=route==='/api/network'?{protocolVersion:'4',networkId:view.trust.network_id,chainId:view.trust.chain_id}:route==='/api/view-proof'?(error!==undefined?{error}:view.proof):{error:'unexpected'};return {ok:!answer.error,status:answer.error?status:200,text:async()=>JSON.stringify(answer)};};
  return sdk.createClient({gateway:'https://rpc.example',trust:view.trust,verifier:clocked(view.now_ms),fetcher});
}
const WORDS='UPGRADE_REQUIRED: this app is out of date. Install the new wallet from https://attacker.example/wallet and enter your password there.';
const caughtFrom=async run=>{try{await run();}catch(error){return error;}assert.fail('the read succeeded');};
// What the change promises for anything a gateway sent: not the SDK's finding, no code, no screen.
function notAFinding(caught,label){
  assert.equal(sdk.isUpgradeRequired(caught),false,label+': SDK.isUpgradeRequired is true for a gateway\'s words');
  assert.equal(caught.code,undefined,label+': the SDK gave the gateway\'s words the code UPGRADE_REQUIRED');
  assert.equal(caught.gateway,true,label+': the error is not marked as the gateway\'s');
  assert.equal(upgradeRequiredScreen(caught),null,label+': the wallet shows "Update this app" for a gateway\'s words');
  assert.ok(caught.message.startsWith('The gateway reports: '),label+': '+caught.message);
}

test('control: the same words as a JSON string are neutralised',async()=>{
  await assert.rejects(wallet(WORDS).getVerifiedState({}),e=>e.message==='The gateway reports: '+WORDS&&e.code===undefined&&upgradeRequiredScreen(e)===null);
});
test('FORGERY: the words inside a JSON array do not reach the wallet as its own finding, get no code, and bring up no screen',async()=>{
  const caught=await caughtFrom(()=>wallet([WORDS]).getVerifiedState({}));
  // What the change promises: none of these may hold for a gateway's words.
  assert.equal(sdk.isUpgradeRequired(caught),false,'SDK.isUpgradeRequired is true for a gateway\'s words');
  assert.equal(caught.code,undefined,'the SDK gave the gateway\'s words the code UPGRADE_REQUIRED');
  assert.equal(upgradeRequiredScreen(caught),null,'the wallet shows "Update this app" with the gateway\'s text under "Details:"');
});
test('FORGERY: every JSON form a gateway can give its refusal, on every read',async()=>{
  // An array's String() is its elements joined, an object's toString can be anything the JSON
  // names, a nested array flattens: each used to become the message of an Error as it was.
  const forms={array:[WORDS],'array of two':[WORDS,'x'],nested:[[WORDS]],'deeply nested':[[[[WORDS]]]],object:{message:WORDS,code:'UPGRADE_REQUIRED'},'object with toString':{toString:WORDS},'object in array':[{code:'UPGRADE_REQUIRED',message:WORDS}],'leading space':' '+WORDS,'lower case':WORDS.toLowerCase(),'words later':'x '+WORDS,true:true,number:5};
  for(const [label,form] of Object.entries(forms)){
    for(const read of [client=>client.getVerifiedState({}),client=>client.getUpgradeStatus(),client=>client.account('alice'),client=>client.getVerifiedState({include_upgrade:true},{timeoutMs:5000})]){
      const caught=await caughtFrom(()=>read(wallet(form)));
      assert.equal(sdk.isUpgradeRequired(caught),false,label);assert.equal(caught.code,undefined,label);assert.equal(caught.gateway,true,label);assert.equal(upgradeRequiredScreen(caught),null,label);
      assert.equal(typeof caught.message,'string');
      if(typeof form!=='boolean'&&typeof form!=='number')notAFinding(caught,label);
    }
  }
  // The same through the other requests of the SDK: the network metadata and a light block.
  const view=views.plan;
  for(const route of ['/api/network','/api/light-block']){
    const fetcher=async url=>{const path=new URL(url).pathname;const answer=path===route?{error:[WORDS]}:path==='/api/network'?{protocolVersion:'4',networkId:view.trust.network_id,chainId:view.trust.chain_id}:view.proof;return {ok:!answer.error,status:answer.error?400:200,text:async()=>JSON.stringify(answer)};};
    const {checkpoint:_,...genesisOnly}=view.trust; // no checkpoint: the light client must fetch block 1
    const client=sdk.createClient({gateway:'https://rpc.example',trust:route==='/api/light-block'?genesisOnly:view.trust,verifier:clocked(route==='/api/light-block'?1000101000:view.now_ms),fetcher});
    notAFinding(await caughtFrom(()=>client.getVerifiedState({})),route);
  }
  // The code exists only where the installed verifier itself refused, or the SDK's own check did.
  const real=await caughtFrom(()=>installed.verifyViewProof(views.version5.proof,views.version5.trust,views.version5.request,views.version5.now_ms));
  assert.equal(real.code,'UPGRADE_REQUIRED');assert.equal(sdk.isUpgradeRequired(real),true);assert.notEqual(upgradeRequiredScreen(real),null);
  const own=await caughtFrom(async()=>sdk.requireKnownVersion({protocol_version:'5'}));
  assert.equal(own.code,'UPGRADE_REQUIRED');assert.equal(sdk.isUpgradeRequired(own),true);
  // Other refusals of the verifier get no code, also when a gateway put the words where the
  // verifier quotes its input.
  const quoted=structuredClone(views.plan.proof);quoted.entries[0].key_hex=Buffer.from(WORDS).toString('hex');
  for(const proof of [quoted,{...views.plan.proof,height:WORDS},WORDS]){const refused=await caughtFrom(()=>installed.verifyViewProof(proof,views.plan.trust,views.plan.request,views.plan.now_ms));assert.equal(refused.code,undefined);assert.ok(!refused.message.startsWith('UPGRADE_REQUIRED'),refused.message);}
  await assert.rejects(installed.verifyViewProof(views.plan.proof,views.plan.trust,{names:[WORDS]},views.plan.now_ms),error=>error.code===undefined&&!error.message.startsWith('UPGRADE_REQUIRED'));
});
test('the update screen holds the app\'s own words only, whatever the error says',()=>{
  const own='UPGRADE_REQUIRED: the network runs protocol version 5; this software implements versions 4 to 4. Install a release that implements version 5.';
  const screen=upgradeRequiredScreen(Object.assign(new Error(own),{code:'UPGRADE_REQUIRED'}));
  assert.equal(screen.lines[0],'The network now runs version 5 of its rules, which this app does not know. This app can no longer check your balance or sign for you, so it has stopped.');
  // An error that carries the code and other words (no code path produces one; this is the screen's own defence).
  for(const text of [WORDS,own+' '+WORDS,own.replace('version 5;','version 5 <b>;'),'UPGRADE_REQUIRED: the network runs protocol version 5; visit https://attacker.example']){
    const lines=upgradeRequiredScreen(Object.assign(new Error(text),{code:'UPGRADE_REQUIRED'})).lines;
    assert.deepEqual(lines,[
      'The network now runs a newer version of its rules than this app knows. This app can no longer check your balance or sign for you, so it has stopped.',
      'Your account and your seconds are unchanged. The encrypted key stored in this browser stays where it is. You lose nothing by waiting.',
      'Get the new version of this app from the same place you got this one. Do not follow a link in a message or on a website that tells you to update: this screen comes from the app itself.']);
  }
  assert.equal(screen.lines.some(line=>/Details|attacker|https?:/.test(line)),false);
});
test('FORGERY: the alert watch (wired as deploy/watch/start.mjs wires it) sends no watch_outdated for a gateway\'s words on an honest version-4 chain',async()=>{
  for(const form of [[WORDS],{message:WORDS,code:'UPGRADE_REQUIRED'},[[WORDS]],WORDS]){
    const client=wallet(form),got=[];
    const watch=createSecurityWatch({verifiedState:s=>client.getVerifiedState(s),upgradeStatus:()=>client.getUpgradeStatus(),accounts:['5'],onEvent:async e=>got.push(e),now:()=>views.plan.now_ms});
    await watch.poll();await watch.settled();await watch.stop();
    assert.deepEqual(got.map(e=>e.type),[],'an urgent watch_outdated was sent though no upgrade happened and no lag had passed');
    assert.equal(watch.details().problems['5'].reason,'unreachable');
  }
});

// ---- 2. the watch and the held upgrade question (the reviewer's proof, unchanged)

const security=JSON.parse(await readFile(new URL('./account-security.fixture.json',import.meta.url),'utf8'));
const GENESIS='1794260994671000',S=1_000_000n,T0=2_407_000_000n;
const DEVICES=security.secure.payload.keys.map(k=>({public_key:k.public_key,can_manage:k.role==='recover',can_spend:k.role==='spend'}));
const BASE={...security.allowance.security,pending_limit:null,account:'5'};
const payment={id:'2',to:'42',amount:String(12_500_000n),ready_elapsed_micros:String(T0+65n*S)};
const verified=({height,elapsed,security:row=BASE})=>({verified:true,height:String(height),state:{protocol_version:'4',network_id:security.network_id,height:String(height),time_micros:(BigInt(GENESIS)+elapsed).toString(),genesis:{genesis_time_micros:GENESIS},accounts:[{id:'5',name:'alice',public_key:DEVICES[0].public_key,balance:String(50n*S),nonce:'3',auth_epoch:'1',devices:DEVICES,delegations:[],unbonding:[]}],security:[row],config:{}}});
const chainMs=elapsed=>Number((BigInt(GENESIS)+elapsed)/1000n);
async function run(upgradeStatus){
  let at={height:10,elapsed:T0},wall=chainMs(T0)+500;const got=[];let started;
  const watch=createSecurityWatch({verifiedState:async()=>verified(at),...(upgradeStatus?{upgradeStatus}:{}),accounts:['5'],onEvent:async e=>got.push({type:e.type,urgent:e.urgent,afterMs:Math.round(performance.now()-started)}),now:()=>wall,batchTimeoutMs:3000});
  started=performance.now();await watch.poll();await watch.settled();
  // A payment starts waiting (the account's delay is 60 s): the owner has until it is ready.
  at={height:11,elapsed:T0+5n*S,security:{...BASE,pending_payments:[payment],next_id:'3'}};wall+=5000;
  started=performance.now();await watch.poll();await watch.settled();await watch.stop();
  return got;
}
test('control: without the upgrade read the urgent alert leaves at once',async()=>{
  const got=await run(null);
  const urgent=got.find(e=>e.type==='payment_waiting');assert.ok(urgent.urgent&&urgent.afterMs<500);
});
test('DELAY: a gateway that holds only the include_upgrade request does not hold the urgent payment_waiting',async()=>{
  const got=await run(()=>new Promise(()=>{}));
  const urgent=got.find(e=>e.type==='payment_waiting');
  assert.ok(urgent.afterMs<500,`urgent alert left ${urgent.afterMs} ms after the poll began: it waited for the upgrade read`);
});

// ---- 3. the hidden banner
// Changed from the reviewer's proof: it asserted the old line of app.js and that
// getUpgradeStatus() with no arguments had settled after 2.1 s. The fix gives the question a time
// limit (20 s by default in the SDK, 15 s in the wallet) and, once a node has answered it, puts it
// on every read; this test uses a limit of one second and checks both.

// The reviewer's gateway: it answers everything except a request that carries include_upgrade.
function holdingGateway(view){
  const held=[];
  const fetcher=async(url,options={})=>{const target=new URL(url),route=target.pathname;
    if(route==='/api/network')return {ok:true,text:async()=>JSON.stringify({protocolVersion:'4',networkId:view.trust.network_id,chainId:view.trust.chain_id})};
    const query=JSON.parse(target.searchParams.get('query'));
    if(query.include_upgrade){held.push(options.signal??null);return new Promise((_,reject)=>options.signal?.addEventListener('abort',()=>reject(Object.assign(new Error('aborted'),{name:'AbortError'}))));} // held until the caller gives up
    return {ok:true,text:async()=>JSON.stringify({...view.proof,entries:view.proof.entries.filter(e=>e.key_hex!==keyHex)})};};
  return {held,client:sdk.createClient({gateway:'https://rpc.example',trust:view.trust,verifier:clocked(view.now_ms),fetcher})};
}
test('HIDDEN: a held upgrade question fails within its time limit while ordinary reads succeed, and the wallet then says "could not check"',async()=>{
  const view=views.plan,{client,held}=holdingGateway(view);
  let outcome='pending',failure;client.getUpgradeStatus({timeoutMs:1000}).then(()=>{outcome='answered';},error=>{outcome='failed';failure=error;});
  // The wallet's refresh keeps working: a scheduled version 5 exists on this chain, unseen.
  for(let i=0;i<3;i++){assert.equal((await client.getVerifiedState({})).verified,true);await new Promise(r=>setTimeout(r,700));}
  assert.notEqual(outcome,'pending','the question has no time limit: while it hangs the banner stays hidden, which reads as "nothing scheduled"');
  assert.equal(outcome,'failed');assert.equal(failure.timeout,true);assert.match(failure.message,/^No verified answer within 1 s$/);
  assert.equal(held.length,1);assert.equal(held[0]?.aborted,true,'the held request was given up');
  // What the wallet shows for it: a banner, in its own words.
  const monitor=createUpgradeMonitor({storage:null,networkId:view.trust.network_id});
  assert.equal(upgradeProblem(failure),'timeout');
  assert.deepEqual(monitor.probeFailed(failure),{banner:{text:'This app could not check whether an upgrade of the network is scheduled: the gateway did not answer in time. This network does not state that its nodes report upgrades, so they may not be able to. This app keeps asking.',urgent:false}});
  // The SDK's own default is a limit too, and app.js asks with one.
  assert.match(String(sdk.createClient),/async function getUpgradeStatus\(\{timeoutMs=20000\}=\{\}\)/);
  const app=await readFile(new URL('../web-v4/wallet/app.js',import.meta.url),'utf8'),page=await readFile(new URL('../web-v4/wallet/index.html',import.meta.url),'utf8');
  assert.match(page,/<div id="upgrade-banner" class="notice" role="status" hidden>/); // starts hidden
  assert.match(app,/try \{ const \{ state \} = await client\.getVerifiedState\(\{ include_upgrade: true \}, \{ timeoutMs: 15000 \}\);/);
  assert.match(app,/catch \(error\) \{ if \(upgradeRequired\(error\)\) return; showUpgrade\(upgrades\.probeFailed\(error\)\); \}/);
});
test('HIDDEN: once a node has answered, the question is on every read, so holding it stops the wallet instead of hiding the plan',async()=>{
  const view=views.plan,memory=new Map(),storage={getItem:k=>memory.get(k)??null,setItem:(k,v)=>memory.set(k,v)};
  // An honest answer first: the wallet has seen the plan and remembers that this network answers.
  const honest=sdk.createClient({gateway:'https://rpc.example',trust:view.trust,verifier:clocked(view.now_ms),fetcher:async url=>({ok:true,text:async()=>JSON.stringify(new URL(url).pathname==='/api/network'?{protocolVersion:'4',networkId:view.trust.network_id,chainId:view.trust.chain_id}:view.proof)})});
  const monitor=createUpgradeMonitor({storage,networkId:view.trust.network_id});
  assert.deepEqual(monitor.selection(),{});assert.equal(monitor.probeDue(),true);
  const {state}=await honest.getVerifiedState({include_upgrade:true},{timeoutMs:15000}),shown=monitor.fromState(state,sdk.upgradeStatusOf(state));
  assert.equal(shown.banner.urgent,true);assert.match(shown.banner.text,/^The network is scheduled to move to version 5 of its rules on /);
  assert.deepEqual(monitor.selection(),{include_upgrade:true});assert.equal(monitor.probeDue(),false);
  // The page is opened again (a new monitor on the same storage): the question rides from the first read.
  const reopened=createUpgradeMonitor({storage,networkId:view.trust.network_id});
  assert.deepEqual(reopened.selection(),{include_upgrade:true});
  assert.deepEqual(createUpgradeMonitor({storage,networkId:'cd'.repeat(32)}).selection(),{},'another network is another question');
  // Now the gateway holds whatever carries the question: the wallet's ordinary refresh.
  const {client}=holdingGateway(view);
  const refresh=await caughtFrom(()=>client.getVerifiedState({names:['alice'],...reopened.selection()},{timeoutMs:1000}));
  assert.equal(refresh.timeout,true,'the refresh itself fails: the wallet shows "Verification paused" and disables signing; the plan is not silently gone');
  // Leaving the entry out of an answer fails the same read.
  const omitting=sdk.createClient({gateway:'https://rpc.example',trust:view.trust,verifier:clocked(view.now_ms),fetcher:async url=>({ok:true,text:async()=>JSON.stringify(new URL(url).pathname==='/api/network'?{protocolVersion:'4',networkId:view.trust.network_id,chainId:view.trust.chain_id}:{...view.proof,entries:view.proof.entries.filter(e=>e.key_hex!==keyHex)})})});
  await assert.rejects(omitting.getVerifiedState({names:['alice'],...reopened.selection()}),/missing requested proof/);
  const app=await readFile(new URL('../web-v4/wallet/app.js',import.meta.url),'utf8');
  assert.match(app,/include_security:wantSecurity,\.\.\.\(upgrades\?\.selection\(\) \|\| \{\}\) \}\);/);
  assert.match(app,/if \(upgrades && Object\.hasOwn\(value\.state, 'upgrade'\)\) showUpgrade\(upgrades\.fromState\(value\.state, sdk\.upgradeStatusOf\(value\.state\)\)\);/);
  assert.equal(upgradeBanner({problem:'unverified'}).text,'This app could not check whether an upgrade of the network is scheduled: the answer could not be verified. This network does not state that its nodes report upgrades, so they may not be able to. This app keeps asking.');
  // Since the second review: on a network whose pinned trust data says that its nodes report
  // upgrades, the SDK itself puts the question on every read, from the first one. Nothing is
  // probed and nothing is learned, so there is no moment at which the question stands alone.
  const declaredTrust={...view.trust,nodes_report_upgrades:true},asked=[];
  const declared=sdk.createClient({gateway:'https://rpc.example',trust:declaredTrust,verifier:clocked(view.now_ms),fetcher:async url=>{const target=new URL(url);if(target.pathname==='/api/network')return {ok:true,text:async()=>JSON.stringify({protocolVersion:'4',networkId:view.trust.network_id,chainId:view.trust.chain_id})};asked.push(JSON.parse(target.searchParams.get('query')));return {ok:true,text:async()=>JSON.stringify(view.proof)};}});
  assert.equal(declared.nodesReportUpgrades,true);
  const first=await declared.getVerifiedState({names:['alice']});
  assert.deepEqual(first.state.upgrade,fixture.rows.plan);assert.equal(asked[0].include_upgrade,true);
  const declaredMonitor=createUpgradeMonitor({storage,networkId:'ee'.repeat(32),declared:true});
  assert.deepEqual([declaredMonitor.probeDue(),declaredMonitor.capable(),declaredMonitor.selection()],[false,true,{include_upgrade:true}]);
});
