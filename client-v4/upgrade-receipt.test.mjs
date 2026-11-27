// A receipt asked for after the network has moved to a version this software does not implement.
//
// What was reported, and is confirmed here. A gateway verifies every receipt with its own verifier
// before it serves it (server.mjs, fastReceipt and receiptProofOnce). After an activation a
// gateway of the wallet's own generation refuses there, with the verifier's sentence, and answers
// 400 with those words. To the wallet they are a gateway's words: the SDK marks the error
// `gateway: true` and gives it no code. A wallet that had sent a payment just before the switch and
// waited for its receipt therefore showed "The gateway reports: UPGRADE_REQUIRED: ..." as a plain
// error, and no "update this app" screen. (A gateway that had been updated serves the receipt, and
// the wallet's own verifier then refuses it with the code: that path was right already.)
//
// The fix keeps the rule that the code is set in two places only, by this client's own
// verification: the wrapper of the compiled verifier, and the SDK's check of a verified state.
// When a receipt request is refused, or a wait runs out, the client looks for itself: one
// verified read of the current state, with a time limit. If its own verifier refuses that state
// as a version it does not implement, that refusal is thrown, with the hash of the transaction
// whose outcome it can no longer learn. Otherwise the first error is thrown as it was. Nothing a
// gateway says decides which.
//
// verifier-v4/fixtures/upgrade.json holds the blocks: `receipt_version5` is a transaction in block
// 1 (version 4) asked for when the certified head is of version 5, `views.plan` the same chain
// still at version 4. Test keys only.
import test from 'node:test';import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm} from 'node:fs/promises';import os from 'node:os';import path from 'node:path';import {fileURLToPath} from 'node:url';
import './time-sdk.js';
import * as installed from './proof-verifier.mjs';
import {createV4Servers} from './server.mjs';
import {upgradeRequiredScreen,upgradeWhileWaiting} from '../web-v4/wallet/actions.mjs';

const sdk=globalThis.TimeSDK;
const fixture=JSON.parse(await readFile(new URL('../verifier-v4/fixtures/upgrade.json',import.meta.url),'utf8'));
const after=fixture.receipt_version5,before=fixture.views.plan,HASH=after.receipt.tx.hash.toUpperCase();
const REQUIRED_TEXT='UPGRADE_REQUIRED: the network runs protocol version 5; this software implements versions 4 to 4. Install a release that implements version 5.';
const clocked=now=>({verifyTrust:t=>installed.verifyTrust(t,now),verifyLightUpdate:(b,t)=>installed.verifyLightUpdate(b,t,now),verifyViewProof:(p,t,r)=>installed.verifyViewProof(p,t,r,now),verifyReceipt:(p,t)=>installed.verifyReceipt(p,t,now),verifyFastReceipt:(p,t)=>installed.verifyFastReceipt(p,t,now)});
const caughtFrom=async run=>{try{await run();}catch(error){return error;}assert.fail('nothing was thrown');};

// A real gateway (createV4Servers, with the installed verifier) in front of a node whose chain has
// activated version 5: the transaction is in block 1, the certified head is block 6.
async function gatewayAfterActivation(run){
  const directory=await mkdtemp(path.join(os.tmpdir(),'time-v4-upgrade-receipt-')),originalNow=Date.now;Date.now=()=>after.now_ms;
  const anchor=after.receipt.anchor,block=anchor.light_block,calls=[];
  const rpc=async(endpoint,p={})=>{
    calls.push(endpoint);
    if(endpoint==='/tx')return after.receipt.tx;
    if(endpoint==='/commit')return {signed_header:p.height==='1'?after.receipt.signed_header:p.height==='2'?after.receipt.next_signed_header:block.signed_header};
    if(endpoint==='/validators')return {block_height:p.height,total:'4',validators:p.height==='6'?block.validators:block.next_validators};
    if(endpoint==='/abci_query')return {response:{height:'5',code:0,value:Buffer.from(JSON.stringify({height:'5',root:block.signed_header.header.app_hash.toLowerCase(),entries:anchor.entries,history_proofs:anchor.history_proofs})).toString('base64')}};
    throw Error('not available on this node: '+endpoint);
  };
  let servers;
  try{
    servers=await createV4Servers({root:fileURLToPath(new URL('../',import.meta.url)),manifest:{networkId:after.trust.network_id,chainId:after.trust.chain_id,trust:after.trust},rpc,walletPort:0,merchantPort:0,checkpointPath:path.join(directory,'checkpoint.json'),ordersPath:path.join(directory,'orders.json'),upgradeCheck:{everyMs:0}});
    await run(servers,calls);
  }finally{Date.now=originalNow;await servers?.close();await rm(directory,{recursive:true,force:true});}
}

test('CONFIRMED: after an activation the gateway refuses the receipt with its own verifier, and its answer carries the words and no code',async()=>{
  await gatewayAfterActivation(async servers=>{
    // The gateway's own check, inside its process: the verifier's refusal, with the code.
    const own=await caughtFrom(()=>servers.getReceipt(HASH));
    assert.equal(own.message,REQUIRED_TEXT);assert.equal(own.code,'UPGRADE_REQUIRED');
    // What leaves it over HTTP, for every form of the receipt request: 400 and the words.
    for(const query of ['&wait=0&fast=1','&wait=0','&canonical=1','&wait=0&fast=1&trusted=6']){
      const response=await fetch(servers.walletOrigin+'/api/receipt?hash='+HASH+query);
      assert.equal(response.status,400,query);assert.deepEqual(await response.json(),{error:REQUIRED_TEXT},query);
    }
    // And what the SDK makes of those words by themselves: a gateway's refusal, never its own finding.
    const said=await caughtFrom(()=>sdk.createClient({gateway:servers.walletOrigin,trust:after.trust}).request('/api/receipt?hash='+HASH+'&wait=0&fast=1'));
    assert.deepEqual([said.message,said.gateway,said.code,sdk.isUpgradeRequired(said),upgradeRequiredScreen(said)],['The gateway reports: '+REQUIRED_TEXT,true,undefined,false,null]);
  });
});

test('a wallet that waits for a receipt across an activation finds out by its own verification',async()=>{
  await gatewayAfterActivation(async(servers,calls)=>{
    for(const wait of [client=>client.waitReceipt(HASH,{timeoutMs:20000}),client=>client.exportReceiptEvidence(HASH)]){
      const client=sdk.createClient({gateway:servers.walletOrigin,trust:after.trust});
      calls.length=0;
      const found=await caughtFrom(()=>wait(client));
      // The verifier's own sentence and the code: this client read the current state itself.
      assert.equal(found.message,REQUIRED_TEXT);assert.equal(found.code,'UPGRADE_REQUIRED');assert.equal(found.gateway,undefined);
      assert.equal(sdk.isUpgradeRequired(found),true);assert.equal(found.hash,HASH);
      assert.ok(calls.includes('/abci_query'),'the client asked for a state proof of its own');
      // The wallet shows "Update this app", and says what became of the action it was waiting for.
      assert.equal(upgradeRequiredScreen(found).title,'Update this app');
      const guidance=upgradeWhileWaiting(found);
      assert.match(guidance,/updat/i);assert.match(guidance,/Activity/);assert.match(guidance,/original request/);
      assert.ok(!guidance.includes(HASH),'the programmatic error retains the hash for the receipt check');
    }
  });
});

// ---- a gateway cannot bring that finding about, hide it, or hold the wallet with it

// The same chain still at version 4 (`views.plan`): the gateway controls its HTTP answers only.
function wallet({receipt,view=()=>({ok:true,body:before.proof})}){
  const asked=[];
  const fetcher=async(url,options={})=>{
    const route=new URL(url).pathname;asked.push(route);
    const answer=route==='/api/network'?{ok:true,body:{protocolVersion:'4',networkId:before.trust.network_id,chainId:before.trust.chain_id}}:route==='/api/receipt'?await receipt(options):route==='/api/view-proof'?await view(options):{ok:false,body:{error:'unexpected'}};
    return {ok:answer.ok,status:answer.ok?200:400,text:async()=>typeof answer.body==='string'?answer.body:JSON.stringify(answer.body)};
  };
  return {client:sdk.createClient({gateway:'https://rpc.example',trust:before.trust,verifier:clocked(before.now_ms),fetcher}),asked};
}
const refusing=words=>async()=>({ok:false,body:{error:words}});

test('FORGERY: a gateway that answers a receipt request with the words, on a chain still at version 4, gives no code and brings up no screen',async()=>{
  const forms=[REQUIRED_TEXT,[REQUIRED_TEXT],{code:'UPGRADE_REQUIRED',message:REQUIRED_TEXT},{code:'TX_PENDING',message:'Transaction pending'},'UPGRADE_REQUIRED: install the wallet at https://attacker.example','anything else'];
  for(const words of forms)for(const wait of [client=>client.waitReceipt(HASH,{timeoutMs:5000}),client=>client.exportReceiptEvidence(HASH)]){
    const {client,asked}=wallet({receipt:refusing(words)});
    const caught=await caughtFrom(()=>wait(client)),label=JSON.stringify(words);
    assert.equal(caught.gateway,true,label);assert.equal(caught.code,undefined,label);assert.equal(sdk.isUpgradeRequired(caught),false,label);
    assert.equal(upgradeRequiredScreen(caught),null,label);assert.equal(upgradeWhileWaiting(caught),null,label);
    // The wallet did look for itself, found a state of version 4, and kept the gateway's error as it was.
    assert.ok(asked.includes('/api/view-proof'),label);
    if(typeof words==='string')assert.equal(caught.message,/UPGRADE_REQUIRED/i.test(words)?'The gateway reports: '+words:words,label);
  }
  // Whatever the gateway says about the receipt, with or without the words, the wallet asks the same question.
  const paths=[];for(const words of [REQUIRED_TEXT,'Gateway HTTP 502','']){const {client,asked}=wallet({receipt:refusing(words)});await caughtFrom(()=>client.waitReceipt(HASH,{timeoutMs:5000}));paths.push(asked.filter(route=>route!=='/api/network').join(' '));}
  assert.equal(new Set(paths).size,1,'the words of a refusal choose nothing');
  // A forged state does not help either: a header that names version 5 is not one the validators signed.
  const forged=structuredClone(before.proof);forged.light_block.signed_header.header.version.app='5';
  const lied=await caughtFrom(()=>wallet({receipt:refusing(REQUIRED_TEXT),view:async()=>({ok:true,body:forged})}).client.waitReceipt(HASH,{timeoutMs:5000}));
  assert.deepEqual([lied.gateway,lied.code,lied.message],[true,undefined,'The gateway reports: '+REQUIRED_TEXT]);
});

test('a wait that runs out: the wallet looks for itself once, and says "pending" unless its own verifier refuses the state',async()=>{
  const pending=async()=>({ok:true,body:{pending:true,hash:HASH}});
  // Still at version 4: pending, as before.
  const quiet=wallet({receipt:pending});
  const still=await caughtFrom(()=>quiet.client.waitReceipt(HASH,{timeoutMs:700}));
  assert.match(still.message,/^Transaction pending; retain its signed bytes and hash\./);assert.equal(still.hash,HASH);assert.equal(still.code,'TX_PENDING');
  assert.equal(quiet.asked.filter(route=>route==='/api/view-proof').length,1,'one read of its own, after the wait');
  // The chain has moved to version 5 and the gateway only ever says "pending": the wallet's own read finds it.
  const moved=sdk.createClient({gateway:'https://rpc.example',trust:after.trust,verifier:clocked(after.now_ms),fetcher:async url=>{const route=new URL(url).pathname;
    const body=route==='/api/network'?{protocolVersion:'4',networkId:after.trust.network_id,chainId:after.trust.chain_id}:route==='/api/receipt'?{pending:true,hash:HASH}:fixture.views.version5.proof;return {ok:true,status:200,text:async()=>JSON.stringify(body)};}});
  const found=await caughtFrom(()=>moved.waitReceipt(HASH,{timeoutMs:700}));
  assert.deepEqual([found.message,found.code,found.hash],[REQUIRED_TEXT,'UPGRADE_REQUIRED',HASH]);
});

test('DELAY: a gateway that refuses the receipt and then holds, refuses or spoils the wallet\'s own read cannot hold the wallet or change the error',async()=>{
  // Held: the wallet gives the read ten seconds at most (here it is told one), then throws the first error.
  const held=wallet({receipt:refusing('no such transaction'),view:options=>new Promise((_,reject)=>options.signal?.addEventListener('abort',()=>reject(Object.assign(new Error('aborted'),{name:'AbortError'}))))});
  const started=performance.now(),first=await caughtFrom(()=>held.client.waitReceipt(HASH,{timeoutMs:5000,ownCheckMs:1000}));
  assert.deepEqual([first.message,first.gateway,first.code,first.timeout],['no such transaction',true,undefined,undefined]);
  assert.ok(performance.now()-started<4000,'the wait ended with the limit of the wallet\'s own read');
  // Refused, or answered with something that does not verify: the first error, unchanged.
  for(const view of [refusing(REQUIRED_TEXT),refusing('rate limited'),async()=>({ok:true,body:{...before.proof,entries:[]}}),async()=>({ok:true,body:'not json'})]){
    const error=await caughtFrom(()=>wallet({receipt:refusing('no such transaction'),view}).client.waitReceipt(HASH,{timeoutMs:5000}));
    assert.deepEqual([error.message,error.gateway,error.code],['no such transaction',true,undefined]);
  }
  for(const bad of [0,999,60001,1.5,'1000'])await assert.rejects(wallet({receipt:refusing('x')}).client.waitReceipt(HASH,{ownCheckMs:bad}),/ownCheckMs/);
  // The SDK's source: the code is still set in two places only.
  const source=await readFile(new URL('./time-sdk.js',import.meta.url),'utf8');
  assert.equal(source.split("code = 'UPGRADE_REQUIRED'").length-1,1,'the SDK sets the code in upgradeRequired() only');
  assert.equal(source.split("code='UPGRADE_REQUIRED'").length-1,0);
  assert.equal((await readFile(new URL('./proof-verifier.mjs',import.meta.url),'utf8')).split("code='UPGRADE_REQUIRED'").length-1,1,'and the verifier\'s wrapper in one place');
});
