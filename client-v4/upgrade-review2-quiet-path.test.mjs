// A proof of the second independent review of the upgrade clients, kept as a test.
// Unchanged but for its import paths and one added check. Its three QUIET tests failed at the reviewed commit: the
// wallet read a gateway's words to choose what it showed. Now it reads no error text: on a network whose trust data
// does not say that its nodes report upgrades, any failed probe is the same standing "could not check" line; on a
// network that says so there is no probe at all (web-v4/wallet/upgrade.test.mjs).
// Round 2, finding A: for a wallet that never had an answer, a gateway chooses what the wallet shows
// about upgrades by its words. Saying what an old node says ("unknown field `include_upgrade`")
// gives no banner at all, on a chain where version 5 is scheduled.
import test from 'node:test';import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import './time-sdk.js';
import * as installed from './proof-verifier.mjs';
import {createUpgradeMonitor,upgradeProblem} from '../web-v4/wallet/actions.mjs';
const sdk=globalThis.TimeSDK;
const fixture=JSON.parse(await readFile(new URL('../verifier-v4/fixtures/upgrade.json',import.meta.url),'utf8')),view=fixture.views.plan,keyHex=Buffer.from('upgrade/state').toString('hex');
const clocked=now=>({verifyTrust:t=>installed.verifyTrust(t,now),verifyLightUpdate:(b,t)=>installed.verifyLightUpdate(b,t,now),verifyViewProof:(p,t,r)=>installed.verifyViewProof(p,t,r,now)});
const memory=()=>{const m=new Map();return {getItem:k=>m.has(k)?m.get(k):null,setItem:(k,v)=>{m.set(k,String(v));},size:()=>m.size};};
// The chain has a scheduled version 5 (fixture view 'plan'). The gateway serves every ordinary read
// honestly and answers the one question about upgrades with `words`.
const gateway=words=>async url=>{const target=new URL(url),route=target.pathname;
  if(route==='/api/network')return {ok:true,status:200,text:async()=>JSON.stringify({protocolVersion:'4',networkId:view.trust.network_id,chainId:view.trust.chain_id})};
  const query=JSON.parse(target.searchParams.get('query'));
  if(query.include_upgrade)return {ok:false,status:400,text:async()=>JSON.stringify({error:words})};
  return {ok:true,status:200,text:async()=>JSON.stringify({...view.proof,entries:view.proof.entries.filter(e=>e.key_hex!==keyHex)})};};
// What app.js checkUpgrade() does, without the page.
async function checkUpgrade(client,upgrades){
  if(!upgrades.probeDue())return 'not asked';upgrades.probeStarted();
  try{const {state}=await client.getVerifiedState({include_upgrade:true},{timeoutMs:15000});return upgrades.fromState(state,sdk.upgradeStatusOf(state));}
  catch(error){return upgrades.probeFailed(error);}
}
for(const words of ['Could not obtain compatible certified V4 state: Pinned state unavailable: unknown field `include_upgrade`, expected one of `names`, `ids`','Invalid proof selection','unknown field include_upgrade']){
  test(`QUIET: the gateway says "${words.slice(0,40)}..." and the wallet shows no banner though version 5 is scheduled`,async()=>{
    let clock=1_000_000;const storage=memory(),upgrades=createUpgradeMonitor({storage,networkId:view.trust.network_id,now:()=>clock});
    const client=sdk.createClient({gateway:'https://rpc.example',trust:view.trust,verifier:clocked(view.now_ms),fetcher:gateway(words)});
    assert.equal((await client.getVerifiedState({})).verified,true); // the wallet looks healthy
    const first=await checkUpgrade(client,upgrades);
    clock+=60_000;const minuteLater=await checkUpgrade(client,upgrades);
    clock+=300_000;const second=await checkUpgrade(client,upgrades);
    console.log(' first probe  :',JSON.stringify(first));console.log(' 1 min later  :',JSON.stringify(minuteLater));console.log(' 6 min later  :',JSON.stringify(second),'| remembered:',storage.size(),'| capable:',upgrades.capable());
    // The promise of the change: no answer is never shown as "nothing is scheduled"; the wallet says "could not check".
    assert.notEqual(first.banner,null,'no banner: only a one-time note that blames the network\'s nodes');
    // Added: the line stands at every later look too, and it is the same line whatever the gateway said.
    assert.deepEqual([minuteLater.banner?.text,second.banner?.text],[first.banner.text,first.banner.text]);assert.equal(first.banner.urgent,false);
    assert.equal(first.banner.text.includes('include_upgrade')||first.banner.text.includes('Invalid proof'),false,'the gateway\'s words are on the screen');
  });
}
test('control: any other refusal, or silence, is a "could not check" banner in the app\'s own words',async()=>{
  for(const [words,expected] of [['no such thing','the answer could not be verified'],['{}','the answer could not be verified']]){
    const upgrades=createUpgradeMonitor({storage:memory(),networkId:view.trust.network_id}),client=sdk.createClient({gateway:'https://rpc.example',trust:view.trust,verifier:clocked(view.now_ms),fetcher:gateway(words)});
    const shown=await checkUpgrade(client,upgrades);assert.ok(shown.banner.text.includes(expected),JSON.stringify(shown));
  }
  assert.equal(upgradeProblem(Object.assign(new Error('x'),{timeout:true})),'timeout');
});
