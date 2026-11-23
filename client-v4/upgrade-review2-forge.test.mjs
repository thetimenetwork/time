// A proof of the second independent review of the upgrade clients, kept as a test.
// Unchanged but for its import paths. Every case here held at the reviewed commit and still does.
// Round 2, attack: any other way for a gateway to give an error the code UPGRADE_REQUIRED.
// Every case here is expected to HOLD (the attack fails).
import test from 'node:test';import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import './time-sdk.js';
import * as installed from './proof-verifier.mjs';
import {upgradeRequiredScreen} from '../web-v4/wallet/actions.mjs';
import {createSecurityWatch} from './security-watch-service.mjs';
const sdk=globalThis.TimeSDK;
const fixture=JSON.parse(await readFile(new URL('../verifier-v4/fixtures/upgrade.json',import.meta.url),'utf8')),view=fixture.views.plan;
const clocked=now=>({verifyTrust:t=>installed.verifyTrust(t,now),verifyLightUpdate:(b,t)=>installed.verifyLightUpdate(b,t,now),verifyViewProof:(p,t,r)=>installed.verifyViewProof(p,t,r,now),verifyReceipt:(p,t)=>installed.verifyReceipt(p,t,now),verifyFastReceipt:(p,t)=>installed.verifyFastReceipt(p,t,now)});
const W='UPGRADE_REQUIRED: the network runs protocol version 9; this software implements versions 4 to 4. Install a release that implements version 9.';
// Raw answer texts, so that keys such as __proto__ arrive exactly as a gateway would send them.
const good=JSON.stringify(view.proof);
const answers={
  'error object with code and message':JSON.stringify({error:{code:'UPGRADE_REQUIRED',message:W}}),
  'error string plus a top-level code':JSON.stringify({error:W,code:'UPGRADE_REQUIRED'}),
  'array':JSON.stringify({error:[W]}),'nested array':JSON.stringify({error:[[[W]]]}),
  'object with toString/message/name':JSON.stringify({error:{toString:W,message:W,name:'Error',code:'UPGRADE_REQUIRED',stack:W}}),
  'number':JSON.stringify({error:1}),'true':JSON.stringify({error:true}),
  '__proto__ at the top':`{"__proto__":{"code":"UPGRADE_REQUIRED","message":${JSON.stringify(W)}},"error":${JSON.stringify(W)}}`,
  '__proto__ inside the error':`{"error":{"__proto__":{"code":"UPGRADE_REQUIRED"},"message":${JSON.stringify(W)}}}`,
  'constructor.prototype':`{"error":{"constructor":{"prototype":{"code":"UPGRADE_REQUIRED"}}},"constructor":{"prototype":{"code":"UPGRADE_REQUIRED"}}}`,
  'a good proof with a code and an empty error beside it':good.replace(/^\{/,'{"code":"UPGRADE_REQUIRED","error":"",'),
  'a good proof whose light block names version 9':good.replace('"version":{"app":"4"','"version":{"app":"9"'),
  'a bare JSON string':JSON.stringify(W),'a bare array':JSON.stringify([W]),'null':'null','not JSON':W,
};
const client=(raw,ok)=>sdk.createClient({gateway:'https://rpc.example',trust:view.trust,verifier:clocked(view.now_ms),fetcher:async url=>{const route=new URL(url).pathname;
  if(route==='/api/network')return {ok:true,status:200,text:async()=>JSON.stringify({protocolVersion:'4',networkId:view.trust.network_id,chainId:view.trust.chain_id})};
  return {ok,status:ok?200:400,text:async()=>raw};}});
const never=(error,label)=>{
  assert.notEqual(error?.code,'UPGRADE_REQUIRED',label+': the error carries the code');
  assert.equal(sdk.isUpgradeRequired(error),false,label);assert.equal(upgradeRequiredScreen(error),null,label);
  assert.equal(({}).code,undefined,label+': Object.prototype was changed');assert.equal(Object.hasOwn(Error.prototype,'code'),false);
};
test('no gateway answer gives the code: views, receipts, the watch',async()=>{
  for(const [label,raw] of Object.entries(answers))for(const ok of [false,true]){
    const c=client(raw,ok);let caught;
    for(const read of [()=>c.getVerifiedState({}),()=>c.getUpgradeStatus({timeoutMs:2000}),()=>c.waitReceipt('ab'.repeat(32),{timeoutMs:50}),()=>c.exportReceiptEvidence('ab'.repeat(32))]){
      try{await read();caught=null;}catch(error){caught=error;}
      if(caught)never(caught,`${label} (ok ${ok})`);
    }
    const got=[];const watch=createSecurityWatch({verifiedState:s=>c.getVerifiedState(s),upgradeStatus:()=>c.getUpgradeStatus({timeoutMs:2000}),accounts:['5'],onEvent:async e=>got.push(e),now:()=>view.now_ms,batchTimeoutMs:3000});
    await watch.poll();await watch.settled();await watch.stop();
    assert.deepEqual(got.filter(e=>e.type==='watch_outdated'),[],label+': the watch sent watch_outdated');
  }
});
test('the only two sources: the compiled verifier on a certified header, and the SDK on a verified state',async()=>{
  const v5=fixture.views.version5;
  await assert.rejects(installed.verifyViewProof(v5.proof,v5.trust,v5.request,v5.now_ms),e=>e.code==='UPGRADE_REQUIRED'&&sdk.isUpgradeRequired(e)&&upgradeRequiredScreen(e).lines[0].startsWith('The network now runs version 5 of its rules'));
  // The number on the screen: only from the exact sentence, and only with the code.
  assert.equal(upgradeRequiredScreen(Object.assign(new Error(W+' Get it at https://attacker.example'),{code:'UPGRADE_REQUIRED'})).lines.join(' ').includes('attacker'),false);
  assert.equal(upgradeRequiredScreen(new Error(W)),null);
  // A thrown non-string from the wasm boundary, or an Error whose text has the words, gets no code.
  for(const bad of [[v5.proof,'not json',v5.request],[null,v5.trust,v5.request],[{...v5.proof,x:W},v5.trust,v5.request]])await assert.rejects(installed.verifyViewProof(bad[0],bad[1],bad[2],v5.now_ms),e=>e.code===undefined);
});
