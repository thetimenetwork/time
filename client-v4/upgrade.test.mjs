// A change of the protocol version on a running network, as the SDK, the gateway and the order
// and login servers see it (docs/design/upgrade-mechanism.md, sections 3.5 and 8).
//
// - The trust anchor and the gateway's /api/network keep naming the network's first version, 4.
// - The version in force is the one of a verified state: a certified header and the state proven
//   under it. A gateway's report decides nothing.
// - A scheduled upgrade is read from the proven row `upgrade/state`: `include_upgrade`,
//   `state.upgrade`, `getUpgradeStatus()`. A view that leaves the entry out is refused, never
//   read as "no plan".
// - Software that meets a version it does not implement fails with `UPGRADE_REQUIRED:`.
//
// verifier-v4/fixtures/upgrade.json holds signed blocks and proven rows made by hand from section
// 3.2 of the design (verifier-v4/src/upgrade_tests.rs writes it). The rows the engine itself
// writes are checked in upgrade-engine-fixture.test.mjs.
import test from 'node:test';import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {readFile,mkdtemp,rm} from 'node:fs/promises';import os from 'node:os';import path from 'node:path';import {fileURLToPath} from 'node:url';
import './time-sdk.js';
import * as installed from './proof-verifier.mjs';
import {createOrderService,createLoginService} from './server-auth.mjs';
import {createV4Servers} from './server.mjs';

const sdk=globalThis.TimeSDK;
const fixture=JSON.parse(await readFile(new URL('../verifier-v4/fixtures/upgrade.json',import.meta.url),'utf8'));
const views=fixture.views,keyHex=Buffer.from('upgrade/state').toString('hex');
// The refusal, word for word, as the verifier and the SDK raise it. (A regular expression given to
// assert.rejects is matched against "Error: ...", so the message is compared by a function.)
const REQUIRED_TEXT='UPGRADE_REQUIRED: the network runs protocol version 5; this software implements versions 4 to 4. Install a release that implements version 5.';
const REQUIRED=error=>{assert.equal(error.message,REQUIRED_TEXT);assert.ok(error.message.startsWith('UPGRADE_REQUIRED:'));return true;};
const without=(proof,key)=>({...proof,entries:proof.entries.filter(entry=>entry.key_hex!==key)});
const check=(name,{proof=views[name].proof,request=views[name].request}={})=>installed.verifyViewProof(proof,views[name].trust,request,views[name].now_ms);

test('this build implements versions 4 to 4, and the first version of a network is 4',()=>{
  assert.equal(sdk.FIRST_VERSION,'4');assert.deepEqual(sdk.KNOWN_VERSIONS,['4']);assert.ok(Object.isFrozen(sdk.KNOWN_VERSIONS));
  assert.equal(sdk.knowsVersion('4'),true);
  for(const other of ['5','3','04',4,undefined,null,''])assert.equal(sdk.knowsVersion(other),false,String(other));
  for(const later of ['4','5','6','40','18446744073709551615'])assert.equal(sdk.sinceFirstVersion(later),true,later);
  for(const not of ['3','0','04',' 4','4 ','4.0','18446744073709551616',4,5,null,undefined,'',['4']])assert.equal(sdk.sinceFirstVersion(not),false,String(not));
  assert.equal(sdk.requireKnownVersion({protocol_version:'4'}),'4');
  assert.throws(()=>sdk.requireKnownVersion({protocol_version:'5'}),error=>error.message===REQUIRED_TEXT&&error.code==='UPGRADE_REQUIRED');
  for(const bad of [{protocol_version:'3'},{protocol_version:4},{},null,undefined])assert.throws(()=>sdk.requireKnownVersion(bad),error=>/no protocol version of this network/.test(error.message)&&error.code===undefined);
  // The refusal is known by its code, which only the verifier's wrapper and requireKnownVersion
  // set. The words alone are never enough: a gateway can send any words.
  assert.equal(sdk.isUpgradeRequired(Object.assign(new Error('UPGRADE_REQUIRED: x'),{code:'UPGRADE_REQUIRED'})),true);
  for(const other of [new Error('UPGRADE_REQUIRED: x'),new Error('The gateway reports: UPGRADE_REQUIRED: x'),Object.assign(new Error('The gateway reports: UPGRADE_REQUIRED: x'),{code:'UPGRADE_REQUIRED'}),Object.assign(new Error('STALE_STATE: y'),{code:'UPGRADE_REQUIRED'}),new Error('STALE_STATE: y'),'UPGRADE_REQUIRED: z',{code:'UPGRADE_REQUIRED'},null])assert.equal(sdk.isUpgradeRequired(other),false);
  // Each implemented version with the hash of its specification. A plan is known only under
  // exactly the specification this build implements; version 4 is never the subject of a plan.
  assert.deepEqual(sdk.IMPLEMENTED,[{version:'4',spec:null}]);assert.ok(Object.isFrozen(sdk.IMPLEMENTED)&&Object.isFrozen(sdk.IMPLEMENTED[0]));
  for(const plan of [{version:'5',spec:'5e'.repeat(32)},{version:'4',spec:'5e'.repeat(32)},{version:'4',spec:null},{version:'4'},{},null,undefined])assert.equal(sdk.knowsPlan(plan),false,JSON.stringify(plan));
});

// ---- the installed verifier (the compiled copy every client loads)

test('the installed verifier proves the upgrade row present or absent, and refuses a view that leaves it out',async()=>{
  assert.equal(fixture.key_hex,keyHex);
  const absent=await check('absent');
  assert.equal(Object.hasOwn(absent.state,'upgrade'),true);assert.equal(absent.state.upgrade,null);assert.equal(absent.state.protocol_version,'4');
  assert.deepEqual((await check('signals')).state.upgrade,fixture.rows.signals);
  assert.deepEqual((await check('plan')).state.upgrade,fixture.rows.plan);
  // Not asked for: the state says nothing about upgrades.
  for(const name of ['absent','plan']){const {include_upgrade:_,...request}=views[name].request;assert.equal(Object.hasOwn((await check(name,{request})).state,'upgrade'),false,name);}
  // Asked for, with no entry for the key in the proof: refused, whether the row exists or not.
  for(const name of ['absent','signals','plan'])await assert.rejects(check(name,{proof:without(views[name].proof,keyHex)}),/missing requested proof for 757067726164652f7374617465/,name);
  // A row in a form this build cannot read is refused, though the validators certified it.
  await assert.rejects(check('malformed'),/invalid upgrade plan/);
  // "Absent" for a row that exists, or the proof of absence of another state.
  const lied=structuredClone(views.plan.proof);lied.entries.find(entry=>entry.key_hex===keyHex).value_b64=null;
  await assert.rejects(check('plan',{proof:lied}),/invalid key\/value proof/);
  const transplanted=structuredClone(views.plan.proof);Object.assign(transplanted.entries.find(entry=>entry.key_hex===keyHex),views.absent.proof.entries.find(entry=>entry.key_hex===keyHex));
  await assert.rejects(check('plan',{proof:transplanted}),/invalid key\/value proof/);
});

test('the installed verifier takes the version from the certified header: a later one is UPGRADE_REQUIRED, a state that disagrees is refused',async()=>{
  await assert.rejects(check('version5'),REQUIRED);
  const {include_upgrade:_,...plain}=views.version5.request;await assert.rejects(check('version5',{request:plain}),REQUIRED);
  // The state names version 5 under a header of version 4: no upgrade happened, the proof is wrong.
  await assert.rejects(check('mismatch'),error=>error.message==='state/header version or height mismatch');
  // A gateway cannot produce UPGRADE_REQUIRED by writing a version into a header.
  const forged=structuredClone(views.plan.proof);forged.light_block.signed_header.header.version.app='5';
  await assert.rejects(check('plan',{proof:forged}),error=>/^CHECKPOINT_MISMATCH/.test(error.message));
  // A receipt whose fresh anchor is of a later version is not judged.
  const r=fixture.receipt_version5;await assert.rejects(installed.verifyReceipt(r.receipt,r.trust,r.now_ms),REQUIRED);
});

// ---- the SDK with the installed verifier, against a gateway that serves one of the views

// The fixtures are dated 1970: the installed verifier is given their clock.
const clocked=now=>({
  verifyTrust:trust=>installed.verifyTrust(trust,now),
  verifyLightUpdate:(block,trust)=>installed.verifyLightUpdate(block,trust,now),
  verifyViewProof:(proof,trust,request)=>installed.verifyViewProof(proof,trust,request,now),
  verifyReceipt:(proof,trust)=>installed.verifyReceipt(proof,trust,now),
});
function wallet(name,{proof=views[name].proof,network={},refuse,trust=views[name].trust}={}){
  const view=views[name],asked=[];
  const fetcher=async url=>{
    const target=new URL(url),route=target.pathname;let answer;
    if(route==='/api/network')answer={protocolVersion:'4',networkId:view.trust.network_id,chainId:view.trust.chain_id,...network};
    else if(route==='/api/view-proof'){const query=JSON.parse(target.searchParams.get('query'));asked.push(query);answer=refuse?{error:refuse}:proof;}
    else answer={error:'unexpected request '+route};
    return {ok:!answer.error,status:answer.error?400:200,text:async()=>JSON.stringify(answer)};
  };
  return {client:sdk.createClient({gateway:'https://rpc.example',trust,verifier:clocked(view.now_ms),fetcher}),asked};
}

test('getUpgradeStatus() reads a proven plan, a proven absence, and entries without a plan',async()=>{
  for(const name of ['absent','signals']){
    const {client,asked}=wallet(name);
    assert.deepEqual(await client.getUpgradeStatus(),{version:'4',scheduled:null,known:true},name);
    assert.equal(asked.at(-1).include_upgrade,true);
  }
  const {client,asked}=wallet('plan'),status=await client.getUpgradeStatus();
  assert.deepEqual(status,{version:'4',scheduled:fixture.rows.plan.plan,known:false});
  assert.deepEqual(Object.keys(status.scheduled).sort(),['activate_elapsed_micros','scheduled_elapsed_micros','spec','version']);
  assert.equal(status.scheduled.version,'5');
  // The state itself, asked with the flag.
  const {state,requested}=await client.getVerifiedState({include_upgrade:true});
  assert.deepEqual(state.upgrade,fixture.rows.plan);assert.equal(requested.include_upgrade,true);
  // Like include_security, the flag is left out when false: a node that predates it refuses it.
  await client.getVerifiedState({});await client.getVerifiedState({include_upgrade:false});
  assert.deepEqual(asked.map(query=>Object.hasOwn(query,'include_upgrade')),[true,true,false,false]);
  await assert.rejects(client.getVerifiedState({include_upgrade:'yes'}),/Proof flags must be booleans/);
});

test('a gateway that leaves the upgrade entry out, or cannot prove it, is never read as "no plan"',async()=>{
  for(const name of ['absent','plan']){
    const {client}=wallet(name,{proof:without(views[name].proof,keyHex)});
    await assert.rejects(client.getUpgradeStatus(),/missing requested proof/,name);
    // The rest of that view still verifies: only the question about upgrades has no answer.
    assert.equal((await client.getVerifiedState({})).verified,true);
  }
  // A gateway (or node) that refuses the question.
  await assert.rejects(wallet('plan',{refuse:'Pinned state unavailable: unknown field include_upgrade'}).client.getUpgradeStatus(),/unknown field include_upgrade/);
  await assert.rejects(wallet('malformed').client.getUpgradeStatus(),/invalid upgrade plan/);
});

test('a network whose pinned trust data says that its nodes report upgrades: the SDK asks with every read, from the first one',async()=>{
  // The statement is one optional field of the trust object: true, false or absent, nothing else.
  assert.deepEqual([sdk.nodesReportUpgrades({nodes_report_upgrades:true}),sdk.nodesReportUpgrades({nodes_report_upgrades:false}),sdk.nodesReportUpgrades(views.plan.trust)],[true,false,false]);
  for(const said of ['true',1,0,null,{},[]]){
    assert.throws(()=>sdk.nodesReportUpgrades({nodes_report_upgrades:said}),/trust\.nodes_report_upgrades is true or false/,JSON.stringify(said));
    assert.throws(()=>wallet('plan',{trust:{...views.plan.trust,nodes_report_upgrades:said}}),/trust\.nodes_report_upgrades is true or false/,JSON.stringify(said));
  }
  // A trust object without it, or with false: nothing changes (the fixtures above are such networks).
  assert.equal(wallet('plan').client.nodesReportUpgrades,false);
  assert.equal(wallet('plan',{trust:{...views.plan.trust,nodes_report_upgrades:false}}).client.nodesReportUpgrades,false);
  // With it: the installed verifier accepts the trust object, and the very first read asks.
  const trust={...views.plan.trust,nodes_report_upgrades:true};
  assert.deepEqual(await installed.verifyTrust(trust,views.plan.now_ms),await installed.verifyTrust(views.plan.trust,views.plan.now_ms));
  assert.equal((await installed.verifyTrust(trust,views.plan.now_ms)).ready,true);
  const {client,asked}=wallet('plan',{trust});
  assert.equal(client.nodesReportUpgrades,true);
  const first=await client.getVerifiedState({names:['alice']});
  assert.deepEqual(first.state.upgrade,fixture.rows.plan);assert.equal(first.requested.include_upgrade,true);
  // A read that asks for nothing, and one that says it does not want the entry, ask all the same.
  await client.getVerifiedState({});await client.getVerifiedState({include_upgrade:false});
  assert.deepEqual(await client.getUpgradeStatus(),{version:'4',scheduled:fixture.rows.plan.plan,known:false});
  assert.deepEqual(asked.map(query=>query.include_upgrade),[true,true,true,true]);
  // So a gateway cannot single the question out. Left out, refused or unprovable, the read itself
  // fails: there is no read without the question to fall back to.
  await assert.rejects(wallet('plan',{trust,proof:without(views.plan.proof,keyHex)}).client.getVerifiedState({names:['alice']}),/missing requested proof/);
  await assert.rejects(wallet('absent',{trust:{...views.absent.trust,nodes_report_upgrades:true},proof:without(views.absent.proof,keyHex)}).client.getVerifiedState({}),/missing requested proof/);
  for(const refusal of ['Pinned state unavailable: unknown field `include_upgrade`','Invalid proof selection','anything']){
    const refused=wallet('plan',{trust,refuse:refusal});
    await assert.rejects(refused.client.getVerifiedState({names:['alice']}),error=>error.gateway===true&&error.code===undefined);
    assert.deepEqual(refused.asked.map(query=>query.include_upgrade),[true],'one request, with the question; no second one without it');
  }
});

test('a gateway that reports a false version changes nothing: the verified state decides',async()=>{
  // Whatever the chain runs, /api/network names the first version; anything else is refused.
  for(const protocolVersion of ['5','3',4,undefined,null])await assert.rejects(wallet('plan',{network:{protocolVersion}}).client.getNetwork(),/Unsupported V4 metadata/,String(protocolVersion));
  // The gateway says 4 (as it always will) while the certified header says 5.
  for(const read of [client=>client.getVerifiedState({}),client=>client.getUpgradeStatus(),client=>client.account('alice')]){
    const {client}=wallet('version5');assert.equal((await client.getNetwork()).protocolVersion,'4');
    await assert.rejects(read(client),error=>error.message===REQUIRED_TEXT&&error.code==='UPGRADE_REQUIRED');
  }
  // A state of version 5 under a header of version 4.
  await assert.rejects(wallet('mismatch').client.getVerifiedState({}),error=>/state\/header version/.test(error.message)&&error.code===undefined);
  // UPGRADE_REQUIRED is this client's own finding, never a gateway's words: a wallet shows
  // "update this app" for it.
  for(const words of ['UPGRADE_REQUIRED: install the release at https://attacker.example',' upgrade_required: x']){
    const {client}=wallet('plan',{refuse:words});
    await assert.rejects(client.getVerifiedState({}),error=>error.message==='The gateway reports: '+words&&error.code===undefined&&!sdk.isUpgradeRequired(error));
  }
});

// ---- the SDK with a verifier of another generation

function mocked(state){
  const block={signed_header:{header:{height:'1'}}},networkId='ab'.repeat(32),trust={app_version:'4',network_id:networkId,chain_id:'time-devnet-v4-test'};
  const verifier={verifyTrust:async()=>({}),verifyLightUpdate:async candidate=>({verified:true,status:'VERIFIED',checkpoint:{height:candidate.signed_header.header.height,block_hash:'cd'.repeat(32),block:candidate}}),verifyViewProof:async()=>({verified:true,completeAccountSet:false,state:{network_id:networkId,height:'5',accounts:[],config:{},...state}})};
  const posted=[],fetcher=async(url,options={})=>{const route=new URL(url).pathname;if(options.method==='POST')posted.push(route);const answer=route==='/api/network'?{protocolVersion:'4',networkId,chainId:trust.chain_id}:route==='/api/view-proof'?{light_block:block}:{error:'unexpected request'};return {ok:!answer.error,text:async()=>JSON.stringify(answer)};};
  return {client:sdk.createClient({gateway:'https://rpc.example',trust,verifier,fetcher}),networkId,posted};
}

test('the SDK itself implements versions 4 to 4, whatever verifier it is given',async()=>{
  // A verifier that implements version 5 under an SDK that does not.
  await assert.rejects(mocked({protocol_version:'5',upgrade:null}).client.getVerifiedState({}),error=>error.message===REQUIRED_TEXT&&error.code==='UPGRADE_REQUIRED');
  await assert.rejects(mocked({protocol_version:'3'}).client.getVerifiedState({}),/no protocol version of this network/);
  // A verifier that predates the flag and ignores it has proven nothing about upgrades.
  await assert.rejects(mocked({protocol_version:'4'}).client.getUpgradeStatus(),/lacks the upgrade entry that was asked for/);
  assert.deepEqual(await mocked({protocol_version:'4',upgrade:null}).client.getUpgradeStatus(),{version:'4',scheduled:null,known:true});
});

test('upgradeStatusOf reads only a state that carries the proven entry',()=>{
  const plan=fixture.rows.plan.plan,state={protocol_version:'4',upgrade:null};
  assert.deepEqual(sdk.upgradeStatusOf(state),{version:'4',scheduled:null,known:true});
  assert.deepEqual(sdk.upgradeStatusOf({...state,upgrade:fixture.rows.signals}),{version:'4',scheduled:null,known:true});
  assert.deepEqual(sdk.upgradeStatusOf({...state,upgrade:fixture.rows.plan}),{version:'4',scheduled:plan,known:false});
  // No entry is not "no plan".
  assert.throws(()=>sdk.upgradeStatusOf({protocol_version:'4'}),/verified without the upgrade entry/);
  assert.throws(()=>sdk.upgradeStatusOf({protocol_version:'4',upgrade:undefined}),/Unsupported upgrade row/);
  assert.throws(()=>sdk.upgradeStatusOf({protocol_version:'5',upgrade:null}),REQUIRED);
  for(const none of [undefined,null,'state'])assert.throws(()=>sdk.upgradeStatusOf(none),/verified state/);
  for(const upgrade of [[],'none',{},{signals:{}},{signals:[],plan:null},{signals:[],plan:{...plan,version:'4'}},{signals:[],plan:{...plan,version:'6'}},{signals:[],plan:{...plan,version:5}},{signals:[],plan:{...plan,spec:plan.spec.toUpperCase()}},{signals:[],plan:{...plan,height:'1'}},{signals:[],plan,extra:1},{signals:[],plan:{version:'5'}}])assert.throws(()=>sdk.upgradeStatusOf({...state,upgrade}),undefined,JSON.stringify(upgrade));
});

test('merchant payments are checked against the verified state at version 4 and at every later one',async()=>{
  const state={protocol_version:'4',time_micros:'600000000',genesis:{genesis_time_micros:'0'}},reference=sdk.orderReference({nonce:'8',expiresElapsedMicros:'780000000'});
  // "4 or later": the rule came with version 4 and holds from then on.
  for(const version of ['4','5','17'])assert.equal(sdk.checkMerchantQuote(reference,'8',{...state,protocol_version:version}).nonce,'8',version);
  for(const version of ['4','5'])assert.throws(()=>sdk.checkMerchantQuote(reference,'9',{...state,protocol_version:version}),/another nonce/);
  for(const version of ['3','0',4,undefined,null,'04'])assert.throws(()=>sdk.checkMerchantQuote(reference,'8',{...state,protocol_version:version}),/version 4 or later/,String(version));
  // submit(): a payment whose quote reserved another nonce is refused before it is sent, on the
  // word of the verified state (the gateway's report of the version is not consulted).
  const pair=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']),publicKey=sdk.bytesToHex(new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey)));
  const account={id:'5',nonce:'7',auth_epoch:'0',devices:[{public_key:publicKey,can_manage:true,can_spend:true}]};
  const signed=nonce=>network=>sdk.signAction({networkId:network,kind:'merchant_payment',from:'5',nonce,authEpoch:'0',publicKey,payload:{to:'0',amount:'1000',reference}},pair.privateKey);
  const stale=mocked({...state,accounts:[account]});
  await assert.rejects(async()=>stale.client.submit(await signed('9')(stale.networkId),{wait:false}),/another nonce/);
  assert.deepEqual(stale.posted,[]);
  // perform(): a state of a version before the network's first is refused outright (the check
  // used to be skipped for it, without a word).
  const old=mocked({...state,protocol_version:'3',accounts:[account],recovery_cases:[]});
  await assert.rejects(old.client.perform({kind:'merchant_payment',account,publicKey,privateKey:pair.privateKey,payload:{to:'0',amount:'1000',reference}}),/no protocol version of this network/);
  assert.deepEqual(old.posted,[]);
});

// ---- order issuance and logins

const networkId='ab'.repeat(32);
const orderState={protocol_version:'4',network_id:networkId,time_micros:'600000000',genesis:{genesis_time_micros:'0'},accounts:[{id:'5',nonce:'7'}],recovery_cases:[],config:{}};
const orders=verifiedState=>createOrderService({networkId,recipient:'0',verifiedState,verifiedReceipt:async()=>{throw Error('not needed');},persist:async()=>{}});

test('an order is issued at a version this build implements, and refused with UPGRADE_REQUIRED at a later one',async()=>{
  assert.equal((await orders(async()=>({verified:true,state:orderState})).issue('5','10000')).reservedNonce,'8');
  // A reader that returns a state of version 5.
  await assert.rejects(orders(async()=>({verified:true,state:{...orderState,protocol_version:'5'}})).issue('5','10000'),error=>error.message===REQUIRED_TEXT&&error.code==='UPGRADE_REQUIRED');
  // The verifier's own refusal is passed on unchanged.
  const refusal=new Error('UPGRADE_REQUIRED: the network runs protocol version 5; this software implements versions 4 to 4. Install a release that implements version 5.');
  await assert.rejects(orders(async()=>{throw refusal;}).issue('5','10000'),error=>error===refusal);
  // No version, or one before the network's first: unavailable, as before.
  for(const version of ['3',undefined,4,'04'])await assert.rejects(orders(async()=>({verified:true,state:{...orderState,protocol_version:version}})).issue('5','10000'),/Fresh V4 account authority is unavailable/,String(version));
  // The service's own protocolVersion is the network's first version and takes no other value.
  assert.throws(()=>createOrderService({networkId,recipient:'0',protocolVersion:'5',verifiedState:async()=>({}),verifiedReceipt:async()=>({}),persist:async()=>{}}),/V4 orders require/);
});

test('a login is refused with UPGRADE_REQUIRED once the network runs a version this build does not implement',async()=>{
  const pair=generateKeyPairSync('ed25519'),key=pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex'),authority={id:'123',name:'alice',auth_epoch:'0',devices:[{public_key:key,can_manage:true,can_spend:true}]};
  let answer;
  const service=createLoginService({origin:'https://merchant.example',networkId,verifiedState:async()=>answer()});
  const state=version=>({verified:true,state:{...(version===undefined?{}:{protocol_version:version}),network_id:networkId,height:'9',genesis:{genesis_time_micros:'0'},time_micros:'100',accounts:[authority],recovery_cases:[]}});
  const login=()=>{const issued=service.issue(),message=sdk.loginMessage(issued.challenge,{account:authority,publicKey:key});return service.finish(issued.cookie,{message,signature:sign(null,sdk.loginBytes(message),pair.privateKey).toString('hex')});};
  answer=()=>state('4');const session=await login();assert.equal((await service.current(session.cookie)).account.name,'alice');
  // The verifier's refusal, unchanged: at sign-in and for a session that was open at the activation.
  const refusal=new Error('UPGRADE_REQUIRED: the network runs protocol version 5; this software implements versions 4 to 4. Install a release that implements version 5.');
  answer=()=>{throw refusal;};
  await assert.rejects(login(),error=>error===refusal);await assert.rejects(service.current(session.cookie),error=>error===refusal);
  // A reader that returns a state of version 5.
  answer=()=>state('5');
  await assert.rejects(login(),REQUIRED);await assert.rejects(service.current(session.cookie),REQUIRED);
  // Back at a version this build implements (a newer build would be), the session is still there.
  answer=()=>state('4');assert.equal((await service.current(session.cookie)).account.name,'alice');
});

// ---- the gateway and shop server with the installed verifier

async function server(name,run,{refuseFlag=false,notices=[],trust=views[name].trust}={}){
  const view=views[name],directory=await mkdtemp(path.join(os.tmpdir(),'time-v4-upgrade-')),originalNow=Date.now;Date.now=()=>view.now_ms;
  const block=view.proof.light_block,selections=[];
  const rpc=async(endpoint,p={})=>{
    if(endpoint==='/commit')return {signed_header:block.signed_header};
    if(endpoint==='/validators')return {block_height:p.height,total:'4',validators:p.height==='6'?block.validators:block.next_validators};
    if(endpoint==='/abci_query'){
      const selection=JSON.parse(Buffer.from(p.data.slice(2),'hex').toString());selections.push(selection);
      if(refuseFlag&&selection.include_upgrade)return {response:{code:1,log:'unknown field `include_upgrade`'}};
      // A node answers with the entry only when it is asked for.
      const entries=selection.include_upgrade?view.proof.entries:view.proof.entries.filter(entry=>entry.key_hex!==keyHex);
      return {response:{height:'5',code:0,value:Buffer.from(JSON.stringify({height:'5',history_proofs:view.proof.history_proofs,root:block.signed_header.header.app_hash.toLowerCase(),entries})).toString('base64')}};
    }
    throw Error('Unconfigured test RPC');
  };
  let servers;
  try{
    servers=await createV4Servers({root:fileURLToPath(new URL('../',import.meta.url)),manifest:{networkId:view.trust.network_id,chainId:view.trust.chain_id,trust},rpc,walletPort:0,merchantPort:0,checkpointPath:path.join(directory,'checkpoint.json'),ordersPath:path.join(directory,'orders.json'),onUpgradeNotice:event=>notices.push(event)});
    await run(servers,{notices,selections,directory});
  }finally{Date.now=originalNow;await servers?.close();await rm(directory,{recursive:true,force:true});}
}

test('the gateway passes include_upgrade on, and a wallet behind it reads the plan with its own verifier',async()=>{
  await server('plan',async(servers,{selections})=>{
    const client=sdk.createClient({gateway:servers.walletOrigin,trust:views.plan.trust});
    assert.deepEqual(await client.getUpgradeStatus(),{version:'4',scheduled:fixture.rows.plan.plan,known:false});
    assert.equal(selections.at(-1).include_upgrade,true);
    // /api/network names the first version, whatever is scheduled.
    assert.equal((await (await fetch(servers.walletOrigin+'/api/network')).json()).protocolVersion,'4');
    // Reads that do not ask are as before.
    assert.equal((await client.getVerifiedState({names:['alice']})).state.accounts[0].name,'alice');
    assert.equal(Object.hasOwn(selections.at(-1),'include_upgrade'),false);
    assert.equal((await fetch(servers.walletOrigin+'/api/view-proof?query='+encodeURIComponent('{"include_upgrade":"yes"}'))).status,400);
  });
  await server('absent',async servers=>{
    assert.deepEqual(await sdk.createClient({gateway:servers.walletOrigin,trust:views.absent.trust}).getUpgradeStatus(),{version:'4',scheduled:null,known:true});
  });
});

test('on a network whose trust data says so, the server asks with every state it verifies, and hands the same trust data to the wallet',async()=>{
  const trust={...views.plan.trust,nodes_report_upgrades:true};
  await server('plan',async(servers,{selections})=>{
    // Every state verified for a login or an order carries the question, from the first one.
    const checked=await servers.verifiedState({names:['alice']});
    assert.deepEqual(checked.state.upgrade,fixture.rows.plan);assert.equal(selections.at(-1).include_upgrade,true);
    await servers.verifiedState({ids:['0']});await servers.verifiedState();
    assert.ok(selections.length>=3&&selections.every(selection=>selection.include_upgrade===true),'a state was verified without the question');
    const order=await createOrderService({networkId:trust.network_id,recipient:'0',verifiedState:servers.verifiedState,verifiedReceipt:async()=>{throw Error('not needed');},persist:async()=>{}}).issue('0','100000');
    assert.equal(order.reservedNonce,'1');
    // The wallet gets its trust data from its own origin, with the statement in it, and so asks
    // with its first read too.
    const installedTrust=await (await fetch(servers.walletOrigin+'/trust-manifest.json')).json();
    assert.equal(installedTrust.nodes_report_upgrades,true);
    const client=sdk.createClient({gateway:servers.walletOrigin,trust:installedTrust});
    assert.equal(client.nodesReportUpgrades,true);selections.length=0;
    assert.deepEqual((await client.getVerifiedState({names:['alice']})).state.upgrade,fixture.rows.plan);
    assert.ok(selections.length>0&&selections.every(selection=>selection.include_upgrade===true));
  },{trust});
  // A node that refuses the question, on a network that says its nodes answer it: no state is
  // verified at all. Nothing falls back to a read without the question.
  await server('plan',async(servers,{selections})=>{
    await assert.rejects(servers.verifiedState({names:['alice']}),/Could not obtain compatible certified V4 state/);
    assert.ok(selections.every(selection=>selection.include_upgrade===true));
    const shop=createOrderService({networkId:trust.network_id,recipient:'0',verifiedState:servers.verifiedState,verifiedReceipt:async()=>{throw Error('not needed');},persist:async()=>{}});
    await assert.rejects(shop.issue('0','100000'),/Could not obtain compatible certified V4 state/);
  },{trust,refuseFlag:true});
  for(const said of ['true',1,null])await assert.rejects(createV4Servers({root:'.',manifest:{networkId:trust.network_id,chainId:trust.chain_id,trust:{...trust,nodes_report_upgrades:said}},rpc:async()=>{throw Error('unused');},checkpointPath:'unused',ordersPath:'unused'}),/trust\.nodes_report_upgrades is true or false/);
});

test('the order and login server warns while a plan it does not implement is scheduled',async()=>{
  await server('plan',async(servers,{notices})=>{
    const status=await servers.checkUpgrade();assert.equal(status.known,false);assert.equal(status.scheduled.version,'5');
    assert.equal(notices.length,1);const [notice]=notices,plan=fixture.rows.plan.plan;
    assert.deepEqual([notice.event,notice.level,notice.version,notice.spec,notice.activate_elapsed_micros,notice.implemented],['UPGRADE_SCHEDULED_NOT_IMPLEMENTED','warn','5',plan.spec,plan.activate_elapsed_micros,['4']]);
    // The start as a date: genesis (1,000,001 s after 1970) plus 3,024,000 s.
    assert.equal(notice.activates_utc,new Date((1000001+3024000)*1000).toISOString());
    assert.match(notice.message,/scheduled protocol version 5 .* refuses every login and every order with UPGRADE_REQUIRED\. Install a release that implements version 5 before then\./);
    // Said again at every check while the plan stands, and orders are still issued meanwhile.
    await servers.checkUpgrade();assert.equal(notices.length,2);
    const order=await createOrderService({networkId:views.plan.trust.network_id,recipient:'0',verifiedState:servers.verifiedState,verifiedReceipt:async()=>{throw Error('not needed');},persist:async()=>{}}).issue('0','100000');
    assert.equal(order.reservedNonce,'1');
  });
  // Nothing scheduled, or signals without a plan: nothing is said.
  for(const name of ['absent','signals'])await server(name,async(servers,{notices})=>{assert.equal((await servers.checkUpgrade()).scheduled,null);assert.deepEqual(notices,[]);});
});

test('after the activation the server says UPGRADE_REQUIRED: in its log, to orders and to logins',async()=>{
  await server('version5',async(servers,{notices,directory})=>{
    await assert.rejects(servers.checkUpgrade(),REQUIRED);
    assert.deepEqual(notices.map(notice=>[notice.event,notice.level]),[['UPGRADE_REQUIRED','error']]);assert.equal(notices[0].message,REQUIRED_TEXT);
    await assert.rejects(servers.verifiedState({ids:['0']}),REQUIRED);
    const shop=createOrderService({networkId:views.version5.trust.network_id,recipient:'0',verifiedState:servers.verifiedState,verifiedReceipt:async()=>{throw Error('not needed');},persist:async()=>{}});
    await assert.rejects(shop.issue('0','100000'),REQUIRED);
    // Over HTTP the shop page gets the same words.
    const answer=await fetch(servers.walletOrigin+'/api/notifications?account=0');assert.equal(answer.status,400);assert.equal((await answer.json()).error,REQUIRED_TEXT);
    // The server's own checkpoint did advance to the block of version 5, and its stored record
    // still names the first version.
    const stored=JSON.parse(await readFile(path.join(directory,'checkpoint.json'),'utf8'));
    assert.equal(stored.appVersion,'4');assert.equal(stored.checkpoint.block.signed_header.header.version.app,'5');
  });
});

test('a node that cannot answer the question is reported once, not taken for "nothing scheduled"',async()=>{
  await server('plan',async(servers,{notices})=>{
    for(let i=0;i<3;i++)await assert.rejects(servers.checkUpgrade(),/Could not obtain compatible certified V4 state/);
    assert.equal(notices.length,1);assert.deepEqual([notices[0].event,notices[0].level],['UPGRADE_STATUS_UNAVAILABLE','warn']);assert.match(notices[0].reason,/include_upgrade/);
    // Everything else works as before against such a node.
    assert.equal((await servers.verifiedState({names:['alice']})).verified,true);
  },{refuseFlag:true});
  for(const bad of [{upgradeCheck:{everyMs:-1}},{upgradeCheck:{firstMs:1.5}},{upgradeCheck:{now:1}},{upgradeCheck:null},{onUpgradeNotice:'log'}])await assert.rejects(createV4Servers({root:'.',manifest:{networkId:views.plan.trust.network_id,chainId:views.plan.trust.chain_id,trust:views.plan.trust},rpc:async()=>{throw Error('unused');},checkpointPath:'unused',ordersPath:'unused',...bad}),/upgradeCheck/);
});
