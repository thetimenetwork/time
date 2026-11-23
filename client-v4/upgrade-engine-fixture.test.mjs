// The engine's own proven `upgrade/state` rows (absent, entries only, with a scheduled plan, the
// activating block, after the activation), verified end to end through the installed verifier
// and the SDK.
//
// - verifier-v4/fixtures/upgrade-state.fixture.json is the engine's file, copied unchanged
//   (v5/tests/upgrade_node.rs writes it): for five heights of a laboratory chain, the answer of
//   `/v4/state` to `{"include_upgrade":true}` and its root, the application hash of that height.
//   The engine tests run without CometBFT, so it holds no signed header.
// - verifier-v4/fixtures/upgrade-engine.json holds the same answers, each under a header signed
//   by test validators that carries exactly that application hash, the version the engine names
//   for the next block and the chain's own times (verifier-v4/src/upgrade_tests.rs writes it,
//   V4_EXPORT_UPGRADE_FIXTURE=1). The entries, the Merkle proofs, the metadata and the rows are
//   the engine's; only the signatures are stand-ins.
// TIME_UPGRADE_ENGINE_FIXTURE names another file of the second form.
import test from 'node:test';import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import './time-sdk.js';
import * as installed from './proof-verifier.mjs';

const sdk=globalThis.TimeSDK,keyHex=Buffer.from('upgrade/state').toString('hex');
const wrapped=JSON.parse(await readFile(process.env.TIME_UPGRADE_ENGINE_FIXTURE||new URL('../verifier-v4/fixtures/upgrade-engine.json',import.meta.url),'utf8'));
const engineBytes=await readFile(new URL('../verifier-v4/fixtures/upgrade-state.fixture.json',import.meta.url)),engine=JSON.parse(engineBytes);
const cases=Object.entries(wrapped.cases);

test('the wrapped cases are the engine\'s answers, entry for entry',()=>{
  if(!process.env.TIME_UPGRADE_ENGINE_FIXTURE)assert.equal(wrapped.source_sha256,createHash('sha256').update(engineBytes).digest('hex'),'regenerate verifier-v4/fixtures/upgrade-engine.json from the engine fixture');
  assert.equal(engine.state_key_hex,keyHex);assert.equal(engine.state_key_utf8,'upgrade/state');
  assert.deepEqual(cases.map(([name])=>name).sort(),engine.cases.map(item=>item.name).sort());
  for(const item of engine.cases){
    const mine=wrapped.cases[item.name];
    assert.deepEqual(mine.proof.entries,item.response.entries,item.name);assert.equal(mine.proof.height,item.response.height);
    assert.equal(mine.proof.light_block.signed_header.header.app_hash.toLowerCase(),item.app_hash,item.name);
    assert.equal(mine.proof.light_block.signed_header.header.version.app,item.next_block_version,item.name);
    assert.equal(mine.proof.light_block.signed_header.header.height,String(BigInt(item.height)+1n),item.name);
    assert.deepEqual(mine.upgrade,item.upgrade_state,item.name);assert.deepEqual(mine.request,item.request);
    // The engine's stored bytes are the canonical JSON of the row (section 3.2).
    if(item.upgrade_state!==null)assert.equal(item.upgrade_state_utf8,JSON.stringify(item.upgrade_state),item.name);
  }
  // The forms the design names are all there.
  assert.deepEqual(engine.cases.map(item=>[item.name,item.protocol_version,item.upgrade_state===null?'absent':item.upgrade_state.plan?'plan':'signals']),[['absent','4','absent'],['entries_only','4','signals'],['scheduled','4','plan'],['activated','5','absent'],['after_activation','5','absent']]);
});

test('every row of the engine verifies through the installed verifier',async()=>{
  for(const [name,item] of cases){
    const version=item.proof.light_block.signed_header.header.version.app;
    if(version!=='4'){
      // From the activating block on the certified header carries version 5.
      await assert.rejects(installed.verifyViewProof(item.proof,item.trust,item.request,item.now_ms),error=>error.message==='UPGRADE_REQUIRED: the network runs protocol version 5; this software implements versions 4 to 4. Install a release that implements version 5.',name);
      continue;
    }
    const checked=await installed.verifyViewProof(item.proof,item.trust,item.request,item.now_ms);
    assert.equal(checked.verified,true,name);assert.equal(checked.state.protocol_version,'4');
    assert.equal(Object.hasOwn(checked.state,'upgrade'),true,name);assert.deepEqual(checked.state.upgrade,item.upgrade,name);
    // Without the entry the engine's own proof is refused, never read as "no plan".
    await assert.rejects(installed.verifyViewProof({...item.proof,entries:item.proof.entries.filter(entry=>entry.key_hex!==keyHex)},item.trust,item.request,item.now_ms),/missing requested proof for 757067726164652f7374617465/,name);
    // Not asked for, the state says nothing about upgrades.
    assert.equal(Object.hasOwn((await installed.verifyViewProof(item.proof,item.trust,{},item.now_ms)).state,'upgrade'),false,name);
  }
});

test('the SDK reads the engine\'s rows: getUpgradeStatus() before, during and after a scheduled upgrade',async()=>{
  const client=item=>{
    const clocked={verifyTrust:trust=>installed.verifyTrust(trust,item.now_ms),verifyLightUpdate:(block,trust)=>installed.verifyLightUpdate(block,trust,item.now_ms),verifyViewProof:(proof,trust,request)=>installed.verifyViewProof(proof,trust,request,item.now_ms)};
    const fetcher=async url=>{const route=new URL(url).pathname,answer=route==='/api/network'?{protocolVersion:'4',networkId:item.trust.network_id,chainId:item.trust.chain_id}:route==='/api/view-proof'?item.proof:{error:'unexpected request'};return {ok:!answer.error,text:async()=>JSON.stringify(answer)};};
    return sdk.createClient({gateway:'https://rpc.example',trust:item.trust,verifier:clocked,fetcher});
  };
  const c=wrapped.cases;
  assert.deepEqual(await client(c.absent).getUpgradeStatus(),{version:'4',scheduled:null,known:true});
  assert.deepEqual(await client(c.entries_only).getUpgradeStatus(),{version:'4',scheduled:null,known:true});
  // The plan the engine scheduled, as the wallet's banner reads it. Release 1 implements 4 only.
  const status=await client(c.scheduled).getUpgradeStatus();
  assert.deepEqual(status,{version:'4',scheduled:engine.cases.find(item=>item.name==='scheduled').upgrade_state.plan,known:false});
  assert.deepEqual([status.scheduled.version,status.scheduled.spec,status.scheduled.activate_elapsed_micros],[engine.plan.version,engine.plan.spec,engine.plan.activate_elapsed_micros]);
  // The gateway still reports the first version; the certified header decides.
  for(const name of ['activated','after_activation']){
    const wallet=client(c[name]);assert.equal((await wallet.getNetwork()).protocolVersion,'4');
    for(const read of [()=>wallet.getUpgradeStatus(),()=>wallet.getVerifiedState({})])await assert.rejects(read(),error=>error.code==='UPGRADE_REQUIRED'&&error.message.startsWith('UPGRADE_REQUIRED: the network runs protocol version 5;'),name);
  }
});
