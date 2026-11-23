// A payment is proven to the wallet as soon as its own block is final: gateway, SDK and
// the installed WASM verifier together, against real signed blocks.
import test from 'node:test';import assert from 'node:assert/strict';import {createHash} from 'node:crypto';
import {readFile,mkdtemp,rm} from 'node:fs/promises';import os from 'node:os';import path from 'node:path';import {fileURLToPath} from 'node:url';
import {createV4Servers} from './server.mjs';import './time-sdk.js';
const fixture=JSON.parse(await readFile(new URL('../verifier-v4/fixtures/fast-receipt.json',import.meta.url),'utf8'));
// Block 2 holds two signed transfers, block 4 a third one.
const raw=(height,index)=>Buffer.from(fixture.txs[height][index],'base64');
const hashOf=bytes=>createHash('sha256').update(bytes).digest('hex').toUpperCase();
const FIRST=raw('2',0),SECOND=raw('2',1),LATER=raw('4',0),NEVER=Buffer.from('never sent');

// A node at height `tip` without a transaction index: only blocks, commits and validators.
async function lab(run){
  const directory=await mkdtemp(path.join(os.tmpdir(),'time-v4-fast-receipt-')),originalNow=Date.now;
  const state={tip:3,clock:fixture.now_ms,calls:[]};Date.now=()=>state.clock;
  const block=h=>{const b=fixture.blocks[Number(h)-1];if(!b||Number(h)>state.tip)throw Error('height is not available');return b;};
  const rpc=async(endpoint,p={})=>{
    state.calls.push(endpoint);
    if(endpoint==='/status'){state.clock+=50;return {sync_info:{latest_block_height:String(state.tip)}};}
    if(endpoint==='/block')return {block:{header:block(p.height).signed_header.header,data:{txs:fixture.txs[p.height]}}};
    if(endpoint==='/header')return {header:block(p.height).signed_header.header};
    if(endpoint==='/commit')return {signed_header:block(p.height??state.tip).signed_header};
    if(endpoint==='/validators'){const h=Number(p.height);if(h>state.tip+1)throw Error('height is not available');return {block_height:p.height,total:'4',validators:h<=fixture.blocks.length?fixture.blocks[h-1].validators:fixture.blocks.at(-1).next_validators};}
    throw Error('not available on this node: '+endpoint);
  };
  let servers;
  try{
    servers=await createV4Servers({root:fileURLToPath(new URL('../',import.meta.url)),manifest:{networkId:fixture.trust.network_id,chainId:fixture.trust.chain_id,trust:fixture.trust},rpc,walletPort:0,merchantPort:0,checkpointPath:path.join(directory,'checkpoint.json'),ordersPath:path.join(directory,'orders.json')});
    await run({servers,state});
  }finally{Date.now=originalNow;await servers?.close();await rm(directory,{recursive:true,force:true});}
}

test('a wallet verifies a payment from the block that contains it, without a later block',async()=>{
  await lab(async({servers,state})=>{
    const wallet=TimeSDK.createClient({gateway:servers.walletOrigin,trust:fixture.trust});
    // Block 2 holds the payment; the node is at height 3.
    const second=await wallet.waitReceipt(hashOf(SECOND),{timeoutMs:20000});
    assert.equal(second.verified,true);assert.equal(second.executionVerified,true);
    assert.equal(second.verificationMode,'finalized-block-inclusion');assert.equal(second.height,'2');
    assert.equal(second.hash.toUpperCase(),hashOf(SECOND));assert.deepEqual(Buffer.from(second.rawHex,'hex'),SECOND);
    assert.equal(second.action.kind,3);assert.equal(second.action.from,'7');assert.equal(second.action.nonce,'2');assert.deepEqual(second.action.payload,{to:'1',amount:'5'});
    // No transaction index and no canonical-history anchor were needed.
    assert(!state.calls.includes('/abci_query'));
    // A payment in the newest block, proven while the wallet's checkpoint is older.
    state.tip=4;
    const later=await wallet.waitReceipt(hashOf(LATER),{timeoutMs:20000});
    assert.equal(later.height,'4');assert.equal(later.trustedHeight,'4');assert.equal(later.verificationMode,'finalized-block-inclusion');
    // An older payment, proven by the chain of block hashes up to the wallet's checkpoint.
    const first=await wallet.waitReceipt(hashOf(FIRST),{timeoutMs:20000});
    assert.equal(first.height,'2');assert.equal(first.trustedHeight,'4');assert.equal(first.action.nonce,'1');
    // A second wallet with no checkpoint at all reaches the same result by itself.
    const fresh=TimeSDK.createClient({gateway:servers.walletOrigin,trust:fixture.trust});
    assert.equal((await fresh.waitReceipt(hashOf(LATER),{timeoutMs:20000})).height,'4');
  });
});

test('a transaction that is in no block stays pending and nothing is reported as verified',async()=>{
  await lab(async({servers})=>{
    const wallet=TimeSDK.createClient({gateway:servers.walletOrigin,trust:fixture.trust});
    await assert.rejects(wallet.waitReceipt(hashOf(NEVER),{timeoutMs:1500}),/Transaction pending/);
    const answer=await (await fetch(servers.walletOrigin+'/api/receipt?hash='+hashOf(NEVER)+'&wait=200')).json();
    assert.deepEqual(answer,{pending:true,hash:hashOf(NEVER)});
    for(const bad of ['&wait=9000','&wait=-1','&wait=1e3','&trusted=0','&trusted=x','&canonical=yes','&fast=true'])assert.equal((await fetch(servers.walletOrigin+'/api/receipt?hash='+hashOf(LATER)+bad)).status,400,bad);
  });
});

test('the wallet rejects a gateway answer that proves something else',async()=>{
  await lab(async({servers})=>{
    const honest=await (await fetch(servers.walletOrigin+'/api/receipt?hash='+hashOf(SECOND)+'&wait=3000&fast=1')).json();
    assert.equal(honest.fast,true);
    const other=await (await fetch(servers.walletOrigin+'/api/receipt?hash='+hashOf(FIRST)+'&wait=3000&fast=1')).json();
    // The untouched answer is accepted: the rejections below are caused by the changes alone.
    const pass=async(url,options)=>String(url).includes('/api/receipt')?new Response(JSON.stringify(honest),{status:200,headers:{'content-type':'application/json'}}):fetch(url,options);
    assert.equal((await TimeSDK.createClient({gateway:servers.walletOrigin,trust:fixture.trust,fetcher:pass}).waitReceipt(hashOf(SECOND),{timeoutMs:3000})).verified,true);
    const forgeries={
      'another transaction of the same block':()=>other,
      'changed transaction bytes':()=>({...honest,tx:{...honest.tx,tx:FIRST.toString('base64')}}),
      'changed Merkle path':()=>({...honest,tx:{...honest.tx,proof:{...honest.tx.proof,proof:{...honest.tx.proof.proof,aunts:[Buffer.alloc(32,7).toString('base64')]}}}}),
      'header that is not the checkpoint':()=>({...honest,headers:[{...honest.headers[0],app_hash:'11'.repeat(32).toUpperCase()}]}),
      'missing checkpoint block':()=>({fast:true,tx:honest.tx,headers:honest.headers}),
      'checkpoint signed by too few validators':()=>{const forged=structuredClone(honest);forged.light_block.signed_header.commit.signatures=forged.light_block.signed_header.commit.signatures.map((s,i)=>i<2?s:{block_id_flag:1,validator_address:'',timestamp:'0001-01-01T00:00:00Z',signature:null});return forged;},
    };
    for(const [name,forge] of Object.entries(forgeries)){
      const fetcher=async(url,options)=>String(url).includes('/api/receipt')?new Response(JSON.stringify(forge()),{status:200,headers:{'content-type':'application/json'}}):fetch(url,options);
      const wallet=TimeSDK.createClient({gateway:servers.walletOrigin,trust:fixture.trust,fetcher});
      await assert.rejects(wallet.waitReceipt(hashOf(SECOND),{timeoutMs:3000}),error=>!/Transaction pending/.test(error.message),name);
    }
  });
});

test('older wallets and durable exports never receive the one-block form',async()=>{
  await lab(async({servers})=>{
    // Bring the block into the gateway's memory through a wallet that understands the new form.
    const wallet=TimeSDK.createClient({gateway:servers.walletOrigin,trust:fixture.trust});
    assert.equal((await wallet.waitReceipt(hashOf(SECOND),{timeoutMs:20000})).verificationMode,'finalized-block-inclusion');
    // A caller that does not ask for it (an older SDK) is never handed a proof it cannot check.
    // This node serves no state queries, so the canonical form is not available here: the answer
    // is an error or "pending", never the one-block form.
    for(const query of ['','&canonical=1','&canonical=1&fast=1']){
      const response=await fetch(servers.walletOrigin+'/api/receipt?hash='+hashOf(SECOND)+query),answer=await response.json();
      assert.notEqual(answer.fast,true,query);
    }
    // A gateway cannot pass the one-block form off as a durable public receipt.
    const fast=await (await fetch(servers.walletOrigin+'/api/receipt?hash='+hashOf(SECOND)+'&fast=1')).json();
    assert.equal(fast.fast,true);
    const fetcher=async(url,options)=>String(url).includes('/api/receipt')?new Response(JSON.stringify(fast),{status:200,headers:{'content-type':'application/json'}}):fetch(url,options);
    const downgraded=TimeSDK.createClient({gateway:servers.walletOrigin,trust:fixture.trust,fetcher});
    await assert.rejects(downgraded.exportReceiptEvidence(hashOf(SECOND)),/canonical history is required/);
  });
});

test('the gateway frees the blocks it kept once nobody is waiting, and proofs match for every position',async()=>{
  // Proofs built from the cached tree levels verify for each transaction of a block
  // (two transactions in block 2, one in block 4), also when asked repeatedly.
  await lab(async({servers,state})=>{
    state.tip=4;
    const wallet=TimeSDK.createClient({gateway:servers.walletOrigin,trust:fixture.trust});
    for(let round=0;round<2;round++)for(const tx of [FIRST,SECOND,LATER]){
      const receipt=await wallet.waitReceipt(hashOf(tx),{timeoutMs:20000});
      assert.equal(receipt.verified,true);assert.deepEqual(Buffer.from(receipt.rawHex,'hex'),tx);
    }
  });
});
