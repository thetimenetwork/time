// A large order settles only when, besides the light client, the merchant's own full node
// (reached directly, never through the gateway) reports the same payment committed: the same
// bytes and hash, at the height of the light-client receipt, result code 0, and the block after
// it accepted. Any other answer, or none, leaves the order unsettled; a later attempt settles it
// once the node agrees. Below `aboveMicros`, and without the option, nothing changes.
import test from 'node:test';import assert from 'node:assert/strict';import http from 'node:http';import {createHash} from 'node:crypto';
import {readFile,mkdtemp,rm} from 'node:fs/promises';import os from 'node:os';import path from 'node:path';import {fileURLToPath} from 'node:url';import vm from 'node:vm';
import './time-sdk.js';
import {createOrderService} from './server-auth.mjs';
import {createOrderStore} from './order-store.mjs';
import {createV4Servers,errorBody} from './server.mjs';
import {createOwnNode,ownNodeOptions,OwnNodeRefusal,OWN_NODE_UNAVAILABLE,OWN_NODE_MISMATCH} from './own-node.mjs';

const networkId='ab'.repeat(32),CHAIN='time-devnet-v4-own-node-test',HEIGHT=42;
const state={protocol_version:'4',network_id:networkId,time_micros:'600000000',genesis:{genesis_time_micros:'0'},accounts:[{id:'5',nonce:'7'}],recovery_cases:[],config:{}};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex').toUpperCase();

// The merchant's full node (CometBFT with the time-node-v5 application) as its RPC answers:
// blocks with their transactions and results, a transaction index that can be off, a tip.
// `tamper` changes an answer the way another node would answer (another chain, another result),
// or holds it back.
function fullNode({tip=HEIGHT+2,indexed=true,network=CHAIN}={}){
  const node={tip,indexed,network,blocks:new Map(),calls:[],tamper:(method,answer)=>answer};
  node.include=(height,bytes,code=0)=>{const block=node.blocks.get(height)??{txs:[],codes:[]};block.txs.push(Buffer.from(bytes).toString('base64'));block.codes.push(code);node.blocks.set(height,block);};
  const block=height=>{if(height>node.tip)throw Error(`height ${height} must be less than or equal to the current blockchain height ${node.tip}`);return node.blocks.get(height)??{txs:[],codes:[]};};
  const result=code=>({code,data:null,log:code?'refused':'',info:'',gas_wanted:'0',gas_used:'0',events:[],codespace:''});
  const answer=(method,p)=>{
    if(method==='/status')return {node_info:{network:node.network,version:'0.38.17'},sync_info:{latest_block_height:String(node.tip),catching_up:false}};
    if(method==='/tx'){
      if(!node.indexed)throw Error('transaction indexing is disabled');
      const hash=String(p.hash).replace(/^0x/,'').toUpperCase();
      for(const [height,b] of node.blocks){if(height>node.tip)continue;const i=b.txs.findIndex(tx=>sha(Buffer.from(tx,'base64'))===hash);if(i>=0)return {hash,height:String(height),index:i,tx_result:result(b.codes[i]),tx:b.txs[i]};}
      throw Error(`tx (${hash}) not found`);
    }
    if(method==='/block'){const h=Number(p.height),b=block(h);return {block_id:{hash:'CD'.repeat(32)},block:{header:{chain_id:node.network,height:String(h)},data:{txs:b.txs}}};}
    if(method==='/block_results'){const h=Number(p.height),b=block(h);return {height:String(h),txs_results:b.codes.map(result),finalize_block_events:[],validator_updates:[],app_hash:''};}
    throw Error(`method ${method} not served`);
  };
  node.rpc=async(method,p={})=>{node.calls.push(method+(Object.keys(p).length?'?'+new URLSearchParams(p):''));return node.tamper(method,structuredClone(answer(method,p)));};
  return node;
}

// A shop whose light client proved each payment in block HEIGHT. The gateway's verifiedReceipt
// is faked here (server.test.mjs and fast-receipt.test.mjs cover the real one); it never sees
// the own node, and the own node never sees it. Its own node is on CHAIN and, unless a test says
// otherwise, an order is checked again at once after the node could not confirm it.
function shop({ownNode,repository,receipt}={}){
  const snapshots=[],proven=new Map(),alerts=[];let receipts=0,paidBefore=0;
  // Each order is made after the one before was paid: the payer's nonce has moved on (the shop gives an account its open
  // order back while that order still reserves the next nonce). The shop takes more open orders of one account than the
  // forty of the test of 32 checks; it takes 3 unless told (server-auth.mjs).
  const service=createOrderService({networkId,recipient:'0',verifiedState:async()=>({verified:true,state:{...state,accounts:[{id:'5',nonce:String(7+paidBefore++)}]}}),now:()=>1000,onAlert:event=>alerts.push(event),maxOpenPerAccount:64,
    ...(repository?{repository}:{persist:async s=>snapshots.push(structuredClone(s))}),
    verifiedReceipt:async hash=>{receipts++;await receipt?.(hash);const p=proven.get(hash);if(!p)throw Error('Payment is awaiting canonical finality');return {verified:true,executionVerified:true,code:0,networkId,height:p.height,hash,rawHex:p.raw.toString('hex'),action:p.action};},
    ...(ownNode===undefined?{}:{ownNode:ownNode&&typeof ownNode==='object'?{chainId:CHAIN,retryAfterMs:0,...ownNode}:ownNode})});
  // The payer pays the order and the light client proves it; returns the bytes and their hash.
  function pay(order,height=String(HEIGHT)){
    const raw=Buffer.from(`signed merchant payment ${order.orderId}`),hash=sha(raw);
    proven.set(hash,{raw,height,action:{kind:10,from:order.accountId,nonce:order.reservedNonce,payload:{to:order.to,amount:order.amount,reference:order.orderId}}});
    return {raw,hash};
  }
  const stored=orderId=>repository?repository.get(orderId):snapshots.at(-1).orders.find(o=>o.orderId===orderId);
  return {service,pay,stored,alerts,receipts:()=>receipts};
}
async function refused(s,order,hash,code,pattern,name=''){
  await assert.rejects(s.service.fulfill('5',order.orderId,hash),error=>{assert.equal(error.code,code,`${name}: ${error.message}`);assert.match(error.message,pattern,name);return true;});
  assert.equal(s.stored(order.orderId).fulfilled,false,name);assert.equal(s.stored(order.orderId).hash,undefined,name);
}
const settles=async(s,order,hash,name='')=>assert.deepEqual((await s.service.fulfill('5',order.orderId,hash)).confirmedBy,['light-client','own-node'],name);

test('a large order settles once the own node agrees, from its transaction index',async()=>{
  const node=fullNode(),s=shop({ownNode:{rpc:node.rpc,aboveMicros:'1000000',chainId:CHAIN}});
  const order=await s.service.issue('5','2500000'),{raw,hash}=s.pay(order);
  node.include(HEIGHT,Buffer.from('another payment in the same block'));node.include(HEIGHT,raw);
  const settled=await s.service.fulfill('5',order.orderId,hash.toLowerCase());
  assert.equal(settled.fulfilled,true);assert.equal(settled.hash,hash);assert.equal(settled.height,'42');
  assert.deepEqual(settled.confirmedBy,['light-client','own-node']);assert.deepEqual(s.stored(order.orderId),settled);
  assert.deepEqual(node.calls,['/status',`/tx?hash=0x${hash}`]);
  // Settled is settled: a repeated request asks neither the light client nor the node again.
  const receipts=s.receipts();
  assert.deepEqual(await s.service.fulfill('5',order.orderId,hash),settled);assert.equal(node.calls.length,2);assert.equal(s.receipts(),receipts);
  // What the check reports when used on its own.
  assert.deepEqual(await createOwnNode({chainId:CHAIN,rpc:node.rpc}).confirm({hash,rawHex:raw.toString('hex'),height:'42'}),{path:'tx-index',height:'42',nodeHeight:'44'});
});

test('without an index, or before the node has indexed the payment, the block and its results are read',async()=>{
  for(const indexed of [false,true]){
    const node=fullNode({indexed}),s=shop({ownNode:{rpc:node.rpc}});
    const order=await s.service.issue('5','2500000'),{raw,hash}=s.pay(order);
    node.include(HEIGHT,Buffer.from('another payment'));node.include(HEIGHT,raw);node.include(HEIGHT+1,Buffer.from('a later payment'));
    // A node that keeps an index but has not indexed this transaction yet answers "not found".
    if(indexed)node.tamper=(method,answer)=>{if(method==='/tx')throw Error(`tx (${hash}) not found`);return answer;};
    await settles(s,order,hash,`indexed ${indexed}`);
    // The block at the height the light-client receipt names, not one found by searching.
    assert.deepEqual(node.calls,['/status',`/tx?hash=0x${hash}`,'/block?height=42','/block_results?height=42']);
    assert.deepEqual(await createOwnNode({chainId:CHAIN,rpc:node.rpc}).confirm({hash,rawHex:raw.toString('hex'),height:'42'}),{path:'block',height:'42',nodeHeight:'44'});
  }
});

test('while the own node is behind, a large order stays unsettled; it settles once the node has accepted the next block',async()=>{
  const node=fullNode({tip:HEIGHT-1}),s=shop({ownNode:{rpc:node.rpc}});
  const order=await s.service.issue('5','2500000'),{raw,hash}=s.pay(order);
  node.include(HEIGHT,raw);
  await refused(s,order,hash,OWN_NODE_UNAVAILABLE,/at height 41 and has not yet accepted block 43/);
  // In the payment's block but not past it: the header that commits to that block's results
  // is not yet checked against the node's own execution.
  node.tip=HEIGHT;
  await refused(s,order,hash,OWN_NODE_UNAVAILABLE,/at height 42 and has not yet accepted block 43/);
  node.tip=HEIGHT+1;
  await settles(s,order,hash);
});

test('refused while the own node does not know the transaction; settled once it does',async()=>{
  const node=fullNode(),s=shop({ownNode:{rpc:node.rpc}});
  const order=await s.service.issue('5','2500000'),{raw,hash}=s.pay(order);
  node.include(HEIGHT,Buffer.from('another payment'));
  // Not in its index, not in its block 42: the light client was shown another block 42 than
  // the one this node executed.
  await refused(s,order,hash,OWN_NODE_MISMATCH,/block 42 does not contain the transaction/);
  // A node that has neither an index nor that block any more cannot confirm either.
  node.indexed=false;node.tamper=(method,answer)=>{if(method==='/block')throw Error('height 42 is not available, lowest height is 100');return answer;};
  await refused(s,order,hash,OWN_NODE_UNAVAILABLE,/neither indexed the transaction \(transaction indexing is disabled\) nor kept block 42 \(height 42 is not available/);
  node.indexed=true;node.tamper=(method,answer)=>answer;node.include(HEIGHT,raw);
  await settles(s,order,hash);
});

test('refused when the own node reports a failure code, another height or other bytes; settled once it agrees',async()=>{
  const noIndex=()=>{throw Error('transaction indexing is disabled');};
  const cases={
    'failure code in the index':[{'/tx':a=>({...a,tx_result:{...a.tx_result,code:7,log:'insufficient balance'}})},/result code 7/],
    // A code that is present must be a number: text or null is not a success (a missing one is 0).
    'code given as text':[{'/tx':a=>({...a,tx_result:{...a.tx_result,code:'0'}})},/result code "0"/],
    'code null':[{'/tx':a=>({...a,tx_result:{...a.tx_result,code:null}})},/result code null/],
    'code null in the block results':[{'/tx':noIndex,'/block_results':a=>({...a,txs_results:a.txs_results.map(r=>({...r,code:null}))})},/result code null/],
    'failure code in the block results':[{'/tx':noIndex,'/block_results':a=>({...a,txs_results:a.txs_results.map(r=>({...r,code:7}))})},/result code 7/],
    'another height in the index':[{'/tx':a=>({...a,height:'41'})},/at height 41, the light client at 42/],
    'other bytes in the index':[{'/tx':a=>({...a,tx:Buffer.from('other bytes').toString('base64')})},/other transaction bytes/],
    'another hash in the index':[{'/tx':a=>({...a,hash:'EE'.repeat(32)})},/other transaction bytes/],
  };
  for(const [name,[changes,pattern]] of Object.entries(cases)){
    const node=fullNode(),s=shop({ownNode:{rpc:node.rpc}});
    const order=await s.service.issue('5','2500000'),{raw,hash}=s.pay(order);
    node.include(HEIGHT,raw);node.tamper=(method,answer)=>changes[method]?changes[method](answer):answer;
    await refused(s,order,hash,OWN_NODE_MISMATCH,pattern,name);
    // A contradiction from the index is final for this attempt: no other source is tried.
    if(!changes['/block_results'])assert(!node.calls.some(call=>call.startsWith('/block')),name);
    node.tamper=(method,answer)=>answer;
    await settles(s,order,hash,name);
  }
});

test('refused when the own node does not answer in time or cannot be reached; settled once it answers',async()=>{
  const node=fullNode(),s=shop({ownNode:{rpc:node.rpc,timeoutMs:200}});
  const order=await s.service.issue('5','2500000'),{raw,hash}=s.pay(order);
  node.include(HEIGHT,raw);
  for(const silent of ['/status','/tx','/block','/block_results']){
    node.indexed=silent==='/status'||silent==='/tx';
    node.tamper=(method,answer)=>method===silent?new Promise(()=>{}):answer;
    const started=performance.now();
    await refused(s,order,hash,OWN_NODE_UNAVAILABLE,/no answer within 200 ms/,silent);
    assert(performance.now()-started<2000,silent);
  }
  node.indexed=true;
  node.tamper=()=>{throw Object.assign(Error('connect ECONNREFUSED 127.0.0.1:26757'),{code:'ECONNREFUSED'});};
  await refused(s,order,hash,OWN_NODE_UNAVAILABLE,/no status from the node: connect ECONNREFUSED/);
  node.tamper=()=>'not an answer';
  await refused(s,order,hash,OWN_NODE_UNAVAILABLE,/unexpected \/status answer/);
  node.tamper=(method,answer)=>answer;
  await settles(s,order,hash);
});

test('refused when the own node follows another network',async()=>{
  const node=fullNode({network:'time-devnet-v4-elsewhere'}),s=shop({ownNode:{rpc:node.rpc,chainId:CHAIN}});
  const order=await s.service.issue('5','2500000'),{raw,hash}=s.pay(order);
  node.include(HEIGHT,raw);
  await refused(s,order,hash,OWN_NODE_MISMATCH,/network "time-devnet-v4-elsewhere", the trust manifest names time-devnet-v4-own-node-test/);
  node.network=CHAIN;
  await settles(s,order,hash);
});

test('below aboveMicros an order settles on the light client alone; the own node is asked only after the light client',async()=>{
  const node=fullNode(),s=shop({ownNode:{rpc:node.rpc,aboveMicros:'1000000'}});
  node.tamper=()=>{throw Error('connect ECONNREFUSED 127.0.0.1:26757');};
  const small=await s.service.issue('5','999999'),paid=s.pay(small);
  const settled=await s.service.fulfill('5',small.orderId,paid.hash);
  assert.equal(settled.fulfilled,true);assert.deepEqual(settled.confirmedBy,['light-client']);assert.deepEqual(node.calls,[]);
  // From the threshold itself on, the node is required.
  const large=await s.service.issue('5','1000000'),second=s.pay(large);
  await refused(s,large,second.hash,OWN_NODE_UNAVAILABLE,/ECONNREFUSED/);
  node.tamper=(method,answer)=>answer;node.include(HEIGHT,second.raw);
  await settles(s,large,second.hash);
  // A payment the light client has not proven is refused before the node is asked: the node
  // never replaces the light client, even where it would agree.
  const unproven=await s.service.issue('5','2500000'),bytes=Buffer.from('a payment no light client has seen');node.include(HEIGHT,bytes);node.calls.length=0;
  await assert.rejects(s.service.fulfill('5',unproven.orderId,sha(bytes)),/canonical finality/);assert.deepEqual(node.calls,[]);
  // The default threshold is 0: every order.
  assert.equal(createOwnNode({chainId:CHAIN,rpc:node.rpc}).aboveMicros,'0');assert.equal(createOwnNode({chainId:CHAIN,rpc:node.rpc}).requiredFor('1'),true);
  assert.equal(createOwnNode({chainId:CHAIN,rpc:node.rpc,aboveMicros:2500000}).requiredFor('2499999'),false);
});

test('without ownNode a settlement is what it was, and records that the light client confirmed it',async()=>{
  const s=shop();
  const order=await s.service.issue('5','2500000'),{hash}=s.pay(order);
  const settled=await s.service.fulfill('5',order.orderId,hash);
  assert.deepEqual(settled,{...order,fulfilled:true,hash,height:'42',lateReconciliation:false,confirmedBy:['light-client']});
  assert.deepEqual(s.stored(order.orderId),settled);
});

// The node's CometBFT JSON-RPC over HTTP, which `ownNode.url` reaches.
async function serve(node){
  const seen=[],modes={};
  const server=http.createServer(async(request,response)=>{
    const url=new URL(request.url,'http://127.0.0.1');seen.push(`${request.method} ${url.pathname}${url.search}`);
    if(modes.silent)return;
    if(modes.redirect){response.writeHead(302,{location:'http://127.0.0.1:9/status'});response.end();return;}
    let body;
    try{body={jsonrpc:'2.0',id:-1,result:await node.rpc(url.pathname,Object.fromEntries(url.searchParams))};}
    catch(error){body={jsonrpc:'2.0',id:-1,error:{code:-32603,message:'Internal error',data:error.message}};}
    response.writeHead(body.error?500:200,{'content-type':'application/json'});response.end(JSON.stringify(body));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  return {seen,modes,url:`http://127.0.0.1:${server.address().port}/`,close:()=>new Promise(resolve=>{server.closeAllConnections();server.close(resolve);})};
}

test('ownNode.url: the node is asked directly over HTTP, read-only, without redirects, within the timeout',async()=>{
  const node=fullNode(),web=await serve(node);let closed;
  try{
    const s=shop({ownNode:{url:web.url,timeoutMs:500}});
    const order=await s.service.issue('5','2500000'),{raw,hash}=s.pay(order);node.include(HEIGHT,raw);
    await settles(s,order,hash);
    assert.deepEqual(web.seen,['GET /status',`GET /tx?hash=0x${hash}`]);
    // Without an index the node's JSON-RPC error is read, and its block is asked for.
    node.indexed=false;web.seen.length=0;
    const second=await s.service.issue('5','2500000'),paid=s.pay(second);node.include(HEIGHT,paid.raw);
    await settles(s,second,paid.hash);
    assert.deepEqual(web.seen,['GET /status',`GET /tx?hash=0x${paid.hash}`,'GET /block?height=42','GET /block_results?height=42']);
    // A node that keeps silent, or sends the request elsewhere, confirms nothing.
    const third=await s.service.issue('5','2500000'),late=s.pay(third);node.include(HEIGHT,late.raw);
    web.modes.silent=true;
    await refused(s,third,late.hash,OWN_NODE_UNAVAILABLE,/no answer within 500 ms/);
    web.modes.silent=false;web.modes.redirect=true;web.seen.length=0;
    await refused(s,third,late.hash,OWN_NODE_UNAVAILABLE,/no status from the node: unreachable \(unexpected redirect\)$/);
    assert.deepEqual(web.seen,['GET /status']);
    web.modes.redirect=false;
    await settles(s,third,late.hash);
  }finally{closed=web.url;await web.close();}
  // The node has stopped: a kept-alive connection is reset, a new one refused. Linux reports the closed
  // kept-alive connection as UND_ERR_SOCKET (seen on the first Linux run of this suite), Windows as ECONNRESET.
  const s=shop({ownNode:{url:closed}});
  const order=await s.service.issue('5','2500000'),{hash}=s.pay(order);
  await refused(s,order,hash,OWN_NODE_UNAVAILABLE,/no status from the node: unreachable \((ECONNRESET|ECONNREFUSED|UND_ERR_SOCKET)\)$/);
  // A port nothing listens on.
  const port=await new Promise(resolve=>{const probe=http.createServer().listen(0,'127.0.0.1',()=>{const free=probe.address().port;probe.close(()=>resolve(free));});});
  const nowhere=shop({ownNode:{url:`http://127.0.0.1:${port}/`}});
  const other=await nowhere.service.issue('5','2500000'),paid=nowhere.pay(other);
  await refused(nowhere,other,paid.hash,OWN_NODE_UNAVAILABLE,/no status from the node: unreachable \(ECONNREFUSED\)$/);
});

test('with the SQLite order store, a refused settlement leaves the order unsettled and a later one settles it',async()=>{
  const directory=await mkdtemp(path.join(os.tmpdir(),'time-v4-own-node-store-'));let repository;
  try{
    repository=createOrderStore({filename:path.join(directory,'orders.sqlite'),networkId,recipient:'0'});
    const node=fullNode(),s=shop({ownNode:{rpc:node.rpc},repository});
    const order=await s.service.issue('5','2500000'),{raw,hash}=s.pay(order);
    await refused(s,order,hash,OWN_NODE_MISMATCH,/does not contain the transaction/);
    assert.equal(repository.usedHash(hash),null);
    // The contradiction is kept on the stored order; a note can change nothing else of it.
    const noted=repository.get(order.orderId);
    assert.deepEqual(noted.ownNodeMismatches,[{hash,reason:"the node's block 42 does not contain the transaction",at:1000}]);
    assert.throws(()=>repository.note({...noted,amount:'1'}),/only the record of own-node mismatches/);
    assert.throws(()=>repository.note({...noted,ownNodeMismatches:undefined}),/records own-node mismatches/);
    node.include(HEIGHT,raw);
    const settled=await s.service.fulfill('5',order.orderId,hash);
    assert.deepEqual(settled.confirmedBy,['light-client','own-node']);assert.deepEqual(repository.get(order.orderId),settled);assert.equal(repository.usedHash(hash),order.orderId);
    assert.deepEqual(settled.ownNodeMismatches,noted.ownNodeMismatches);
    assert.throws(()=>repository.note({...settled,fulfilled:false}),/race or settled order|only the record/);
  }finally{repository?.close();await rm(directory,{recursive:true,force:true});}
});

test('configuration: one of url or rpc, the chain id, an amount, bounded times; createV4Servers never uses the gateway as the own node',async()=>{
  const rpc=async()=>({}),ok={rpc,chainId:CHAIN};
  assert.deepEqual({...ownNodeOptions(ok)},{rpc,endpoint:'rpc function',chainId:CHAIN,aboveMicros:'0',timeoutMs:5000,retryAfterMs:2000});
  assert.equal(ownNodeOptions({url:'http://127.0.0.1:26757',chainId:CHAIN,aboveMicros:2500000,timeoutMs:100,retryAfterMs:0}).aboveMicros,'2500000');
  assert.equal(ownNodeOptions({url:'https://node.shop.example/rpc',chainId:CHAIN,aboveMicros:'18446744073709551615'}).endpoint,'https://node.shop.example/rpc/');
  const config={networkId,recipient:'0',verifiedState:async()=>({}),verifiedReceipt:async()=>({}),persist:async()=>{}};
  for(const [bad,pattern] of [[null,/ownNode must be an object/],[[],/ownNode must be an object/],['http://127.0.0.1:26757/',/ownNode must be an object/],
    [{chainId:CHAIN},/exactly one of url/],[{url:'http://127.0.0.1:26757/',rpc,chainId:CHAIN},/exactly one of url/],[{rpc:'http://127.0.0.1:26757/',chainId:CHAIN},/ownNode\.rpc/],
    [{url:'ftp://127.0.0.1/',chainId:CHAIN},/ownNode\.url/],[{url:'http://user:secret@127.0.0.1:26757/',chainId:CHAIN},/ownNode\.url/],[{url:'http://127.0.0.1:26757/?x=1',chainId:CHAIN},/ownNode\.url/],[{url:'not an address',chainId:CHAIN},/ownNode\.url/],
    // The network is required when the order service is set up directly.
    [{rpc},/ownNode\.chainId/],[{url:'http://127.0.0.1:26757/'},/ownNode\.chainId/],[{...ok,chainId:''},/ownNode\.chainId/],[{...ok,chainId:'two words'},/ownNode\.chainId/],[{...ok,chainId:7},/ownNode\.chainId/],
    [{...ok,aboveMicros:'01'},/aboveMicros/],[{...ok,aboveMicros:-1},/aboveMicros/],[{...ok,aboveMicros:'1.5'},/aboveMicros/],[{...ok,aboveMicros:'18446744073709551616'},/aboveMicros/],[{...ok,aboveMicros:null},/aboveMicros/],
    [{...ok,timeoutMs:99},/timeoutMs/],[{...ok,timeoutMs:60001},/timeoutMs/],[{...ok,timeoutMs:'5000'},/timeoutMs/],
    [{...ok,retryAfterMs:-1},/retryAfterMs/],[{...ok,retryAfterMs:60001},/retryAfterMs/],[{...ok,retryAfterMs:'0'},/retryAfterMs/],[{...ok,gateway:true},/takes url or rpc/]])
    assert.throws(()=>createOrderService({...config,ownNode:bad}),pattern,JSON.stringify(bad)??String(bad));
  assert.throws(()=>createOrderService({...config,ownNode:ok,onAlert:'console'}),/onAlert/);
  const fixture=JSON.parse(await readFile(new URL('../verifier-v4/fixtures/proof.json',import.meta.url),'utf8'));
  const directory=await mkdtemp(path.join(os.tmpdir(),'time-v4-own-node-gateway-')),originalNow=Date.now;Date.now=()=>fixture.now_ms;
  const gateway=async()=>{throw Error('Unconfigured RPC');};
  const base={root:fileURLToPath(new URL('../',import.meta.url)),manifest:{networkId:fixture.trust.network_id,chainId:fixture.trust.chain_id,trust:fixture.trust},rpc:gateway,walletPort:0,merchantPort:0,checkpointPath:path.join(directory,'checkpoint.json'),ordersPath:path.join(directory,'orders.json')};
  let servers;
  try{
    await assert.rejects(createV4Servers({...base,ownNode:{rpc:gateway}}),/directly, not through the gateway rpc/);
    await assert.rejects(createV4Servers({...base,ownNode:{url:'http://127.0.0.1:26757/',chainId:'time-devnet-v4-elsewhere'}}),/differs from the pinned manifest/);
    await assert.rejects(createV4Servers({...base,ownNode:{url:'ftp://127.0.0.1/'}}),/ownNode\.url/);
    await assert.rejects(createV4Servers({...base,ownNode:null}),/ownNode/);
    // A node that is down does not keep the gateway from starting: only large orders wait for it.
    servers=await createV4Servers({...base,ownNode:{url:'http://127.0.0.1:9/',aboveMicros:'1000000'}});
    assert.equal((await fetch(servers.merchantOrigin+'/api/config')).status,200);
  }finally{Date.now=originalNow;await servers?.close();await rm(directory,{recursive:true,force:true});}
});

const ticks=async(until,limit=500)=>{for(let i=0;i<limit&&!until();i++)await new Promise(resolve=>setImmediate(resolve));};

test('checks run outside the order queue: other orders do not wait, one check per payment, at most 32 at a time',async()=>{
  let open;const gate=new Promise(resolve=>{open=resolve;});let asked=0;
  const node=fullNode(),s=shop({ownNode:{rpc:async(method,p)=>{if(method==='/status'){asked++;await gate;}return node.rpc(method,p);}}});
  const paid=[];
  for(let i=0;i<40;i++){const order=await s.service.issue('5','2500000'),payment=s.pay(order);node.include(HEIGHT,payment.raw);paid.push({order,...payment});}
  // Forty paid large orders whose node does not answer yet, and the first one asked twice.
  const settling=paid.map(({order,hash})=>s.service.fulfill('5',order.orderId,hash));
  const again=s.service.fulfill('5',paid[0].order.orderId,paid[0].hash);
  await ticks(()=>asked>=32);await ticks(()=>false,50);
  assert.equal(asked,32);assert.equal(s.receipts(),32,'eight checks wait for a free place; the repeated request joins the running check');
  // Meanwhile the shop takes new orders without waiting for the node.
  const started=performance.now();
  const other=await s.service.issue('5','1000');
  assert(other.orderId&&performance.now()-started<1000);
  open();
  const results=await Promise.all(settling);
  assert(results.every(result=>result.fulfilled&&result.confirmedBy.join()==='light-client,own-node'));
  assert.deepEqual(await again,results[0]);assert.equal(s.receipts(),40);assert.equal(asked,40);
});

test('after the own node could not confirm a payment, that order is refused at once for retryAfterMs, without a new proof',async()=>{
  const node=fullNode({tip:HEIGHT}),s=shop({ownNode:{rpc:node.rpc,retryAfterMs:400}});
  const order=await s.service.issue('5','2500000'),{raw,hash}=s.pay(order);node.include(HEIGHT,raw);
  await refused(s,order,hash,OWN_NODE_UNAVAILABLE,/has not yet accepted block 43/);
  const receipts=s.receipts(),calls=node.calls.length;node.tip=HEIGHT+1;
  await refused(s,order,hash,OWN_NODE_UNAVAILABLE,/has not yet accepted block 43/);
  assert.equal(s.receipts(),receipts);assert.equal(node.calls.length,calls);
  // Other orders are not held back.
  const other=await s.service.issue('5','2500000'),payment=s.pay(other);node.include(HEIGHT,payment.raw);
  await settles(s,other,payment.hash);
  await new Promise(resolve=>setTimeout(resolve,450));
  await settles(s,order,hash);
});

test('an own node that contradicts the light client is reported and kept on the order, also after a later settlement',async()=>{
  const node=fullNode(),s=shop({ownNode:{rpc:node.rpc}});
  const order=await s.service.issue('5','2500000'),{raw,hash}=s.pay(order);node.include(HEIGHT,raw);
  node.tamper=(method,answer)=>method==='/tx'?{...answer,height:'41'}:answer;
  let refusal;await s.service.fulfill('5',order.orderId,hash).catch(error=>{refusal=error;});
  assert(refusal instanceof OwnNodeRefusal);assert.equal(refusal.code,OWN_NODE_MISMATCH);
  const reason='the node has the transaction at height 41, the light client at 42';
  assert.deepEqual(s.alerts,[{event:'OWN_NODE_MISMATCH',orderId:order.orderId,hash,node:'rpc function',reason}]);
  assert.deepEqual(s.stored(order.orderId).ownNodeMismatches,[{hash,reason,at:1000}]);assert.equal(s.stored(order.orderId).fulfilled,false);
  node.tamper=(method,answer)=>answer;
  const settled=await s.service.fulfill('5',order.orderId,hash);
  assert.deepEqual(settled.confirmedBy,['light-client','own-node']);assert.deepEqual(settled.ownNodeMismatches,[{hash,reason,at:1000}]);
  assert.deepEqual(s.stored(order.orderId),settled);assert.equal(s.alerts.length,1);
  // A node reached over HTTP is named by its address.
  assert.equal(createOwnNode({chainId:CHAIN,url:'http://127.0.0.1:26757'}).endpoint,'http://127.0.0.1:26757/');
  // The HTTP answer to a refused settlement carries the code and the fixed first half of the refusal: the reason can name
  // the node, its words and its address, and goes to the gateway's log instead (server.mjs, publicError). Other refusals
  // answer as before, except an error of the system, whose words name addresses and paths.
  assert.deepEqual(errorBody(refusal),{error:'Own node contradicts the light-client receipt; the order stays unsettled',code:OWN_NODE_MISMATCH});
  assert.deepEqual(errorBody(new OwnNodeRefusal(OWN_NODE_UNAVAILABLE,'no answer within 5000 ms')),{error:'Own node has not confirmed the payment; the order stays unsettled, retry later',code:OWN_NODE_UNAVAILABLE});
  assert.deepEqual(errorBody(new Error('Unknown item')),{error:'Unknown item'});
  assert.deepEqual(errorBody(Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:26757'),{code:'ECONNREFUSED'})),{error:'The gateway could not complete the request'});
});

// web-v4/merchant/app.js in a page with this backend. Each payment gets its own order and
// transaction; the answer to the nth settlement request comes from `settle(n, request)`: an HTTP
// answer, {network:true} for a failed connection, or {page:status} for a proxy page that is not JSON.
let payments=0;
const paymentOf=n=>({orderId:'ab'.repeat(31)+n.toString(16).padStart(2,'0'),hash:'CD'.repeat(31)+n.toString(16).padStart(2,'0').toUpperCase()});
// The signed-in account is `account.id`; the shop answers "Unknown payment order" to a settlement
// request for an order of another account, as server-auth.mjs does.
async function merchantPage({settle,storage=new Map(),account={id:'5'}}){
  const code=await readFile(new URL('../web-v4/merchant/app.js',import.meta.url),'utf8');
  const elements=new Map(),statuses=[],settles=[],payDisabled=[],warnings=[],owners=new Map();let current;
  const element=id=>{
    if(!elements.has(id)){let text='';const e={disabled:false,href:'',classList:{toggle(){}},listeners:{},addEventListener(type,listener){this.listeners[type]=listener;}};
      Object.defineProperty(e,'textContent',{get:()=>text,set:value=>{text=value;if(id==='status')statuses.push(value);}});elements.set(id,e);}
    return elements.get(id);
  };
  const answer=(status,body)=>({ok:status===200,status,json:async()=>body});
  const fetch=async(path,options)=>{
    if(path==='/api/config')return answer(200,{walletOrigin:'https://wallet.example'});
    if(path==='/api/session')return answer(200,{accountId:account.id,name:'buyer'+account.id,balance:'1000000',height:'9',csrf:'token'});
    if(path==='/api/login/challenge'||path==='/api/login/finish')return answer(200,{});
    if(path==='/api/order'){current=paymentOf(++payments);owners.set(current.orderId,account.id);return answer(200,{orderId:current.orderId,networkId,to:'0',amount:'2500000',fee:'1000',expiresAt:1});}
    if(path==='/api/order/settle'){
      const request=JSON.parse(options.body);settles.push(request);payDisabled.push(element('pay').disabled);
      if(owners.has(request.orderId)&&owners.get(request.orderId)!==account.id)return answer(400,{error:'Unknown payment order'});
      const next=settle(settles.length,request);
      if(next.network)throw new TypeError('Failed to fetch');
      if(next.page)return {ok:false,status:next.page,json:async()=>{throw new SyntaxError('Unexpected token < in JSON');}};
      return answer(next.status,next.body);
    }
    return answer(404,{error:'Unknown API route'});
  };
  const localStorage={getItem:key=>storage.has(key)?storage.get(key):null,setItem:(key,value)=>{storage.set(key,String(value));},removeItem:key=>{storage.delete(key);}};
  const context=vm.createContext({document:{getElementById:element},fetch,localStorage,console:{warn:message=>warnings.push(message)},setTimeout:resolve=>setImmediate(resolve),TimeSDK:{requestWallet:async({request})=>{await request;return {transactionHash:current?.hash};}}});
  vm.runInContext(code,context);
  await ticks(()=>statuses.length>0&&!/Confirming/.test(statuses.at(-1))||elements.get('wallet-link')?.href&&!storage.size);
  const saved=()=>JSON.parse(storage.get('time-merchant-pending-settlements')??'[]');
  return {element,statuses,settles,storage,payDisabled,warnings,owners,saved,pending:()=>saved().map(({savedAt,...entry})=>entry)};
}

test('the shop page asks again while the payment cannot be confirmed, tells the buyer not to pay again, and resumes when reopened',async()=>{
  const finalized='Payment finalized and independently verified by this app.';
  const unavailable={status:400,body:{error:'Own node has not confirmed the payment; the order stays unsettled, retry later: the node is at height 41',code:OWN_NODE_UNAVAILABLE}};
  const done=request=>({status:200,body:{...request,fulfilled:true,height:'42',confirmedBy:['light-client','own-node']}});
  // Confirmed at the third request.
  let page=await merchantPage({settle:(n,request)=>n<3?unavailable:done(request)});
  await page.element('pay').listeners.click();
  let paid=paymentOf(payments);
  assert.equal(page.settles.length,3);assert(page.payDisabled.every(Boolean),'no second payment while the first is being confirmed');
  // The page is the demo blog now: its words say "the blog" where they said "the shop" (the only change to this test).
  assert(page.statuses.includes(`Payment sent (transaction ${paid.hash}). Waiting for the blog to confirm it; do not pay again.`));
  assert.equal(page.element('order-result').textContent,`Order fulfilled at height 42. Transaction ${paid.hash}`);
  assert.equal(page.statuses.at(-1),finalized);assert.equal(page.storage.size,0);
  // A failed connection, the shop's rate limit, a proxy error page and a gateway failure are asked again too.
  const failures=[{network:true},{status:429,body:{error:'Local request limit reached'}},{page:502},{status:400,body:{error:'Could not obtain compatible certified V4 state: Private RPC HTTP failure'}}];
  page=await merchantPage({settle:(n,request)=>failures[n-1]??done(request)});
  await page.element('pay').listeners.click();
  assert.equal(page.settles.length,5);assert.equal(page.statuses.at(-1),finalized);assert.equal(page.storage.size,0);
  // Not confirmed while the page is open: it stops after sixty requests and keeps the payment.
  // A second payment in the meantime is kept next to the first, not in its place.
  const storage=new Map();
  page=await merchantPage({settle:n=>n%2?unavailable:failures[n%4],storage});
  await page.element('pay').listeners.click();
  const first=paymentOf(payments);
  assert.equal(page.settles.length,60);assert.equal(page.element('pay').disabled,false);
  assert.equal(page.statuses.at(-1),`The blog has not confirmed payment ${first.hash} yet. Do not pay again for this order: reopen this page later to finish, or give the blog's owner this transaction.`);
  assert.deepEqual(page.pending(),[{...first,accountId:'5'}]);
  await page.element('pay').listeners.click();
  const second=paymentOf(payments);
  assert.equal(page.settles.length,120);assert.deepEqual(page.pending(),[{...first,accountId:'5'},{...second,accountId:'5'}]);
  // Reopened later, the page finishes both settlements by itself.
  page=await merchantPage({settle:(n,request)=>done(request),storage});
  await ticks(()=>page.statuses.at(-1)===finalized);
  assert.deepEqual(page.settles,[first,second]);assert.equal(storage.size,0);
  assert.equal(page.element('order-result').textContent,`Order fulfilled at height 42. Transaction ${second.hash}`);
  // A lost session stops the requests but keeps the payment; the page finishes it when reopened.
  page=await merchantPage({settle:()=>({status:401,body:{error:'Sign in first'}}),storage});
  await page.element('pay').listeners.click();
  paid=paymentOf(payments);
  assert.equal(page.settles.length,1);assert.equal(page.statuses.at(-1),`Sign in again to finish confirming payment ${paid.hash}; do not pay again.`);
  assert.deepEqual(page.pending(),[{...paid,accountId:'5'}]);
  page=await merchantPage({settle:(n,request)=>done(request),storage});
  await ticks(()=>page.statuses.at(-1)===finalized);
  assert.deepEqual(page.settles,[paid]);assert.equal(storage.size,0);
  // Answers that mean the payment is wrong for the order are not asked again, and nothing is kept.
  for(const error of [{error:'Own node contradicts the light-client receipt; the order stays unsettled: x',code:OWN_NODE_MISMATCH},{error:'Finalized merchant payment differs from reserved order nonce'},{error:'Finalized merchant payment does not match exact order reference'}]){
    page=await merchantPage({settle:()=>({status:400,body:error}),storage});
    await page.element('pay').listeners.click();
    paid=paymentOf(payments);
    assert.equal(page.settles.length,1,error.error);assert.equal(storage.size,0,error.error);
    assert.equal(page.statuses.at(-1),`${error.error} Payment ${paid.hash}: do not pay again; give the blog's owner this transaction.`);
  }
});

test('the shop page keeps a payment through an account switch, runs one loop per payment, and keeps at most 20 payments for 7 days',async()=>{
  const finalized='Payment finalized and independently verified by this app.',key='time-merchant-pending-settlements';
  const unavailable={status:400,body:{error:'Own node has not confirmed the payment; the order stays unsettled, retry later: no answer within 5000 ms',code:OWN_NODE_UNAVAILABLE}};
  const done=request=>({status:200,body:{...request,fulfilled:true,height:'42',confirmedBy:['light-client','own-node']}});
  // "Not independently finalized" is asked again.
  let page=await merchantPage({settle:(n,request)=>n===1?{status:400,body:{error:'Payment is not independently finalized'}}:done(request)});
  await page.element('pay').listeners.click();
  assert.equal(page.settles.length,2);assert.equal(page.statuses.at(-1),finalized);assert.equal(page.storage.size,0);

  // Another account signs in while the payment of account 5 is being confirmed. The shop then
  // answers "Unknown payment order" (even before this page has seen the new session): the payment
  // is kept, not dropped, and finished once account 5 signs in again.
  const account={id:'5'},storage=new Map();let answer=()=>unavailable;
  page=await merchantPage({settle:(n,request)=>answer(request),storage,account});
  const paying=page.element('pay').listeners.click();
  await ticks(()=>page.settles.length>=3);
  account.id='6';await page.element('login').listeners.click();await paying;
  const first=paymentOf(payments);
  assert.deepEqual(page.pending(),[{...first,accountId:'5'}]);
  assert(page.statuses.includes(`Payment ${first.hash} was made from account 5: sign in as that account to finish confirming it; do not pay again.`));
  // Account 6 does not resume it.
  const asked=page.settles.length;await page.element('login').listeners.click();assert.equal(page.settles.length,asked);
  answer=done;account.id='5';await page.element('login').listeners.click();
  assert.equal(page.statuses.at(-1),finalized);assert.deepEqual(page.settles.at(-1),first);assert.equal(storage.size,0);

  // One loop per payment, and Pay stays off while any settlement runs: a payment C is being
  // confirmed when signing in again resumes an earlier payment A; C is not asked twice, and
  // finishing C does not turn Pay back on while A is still being confirmed.
  page=await merchantPage({settle:(n,request)=>answer(request),storage:new Map()});
  answer=()=>unavailable;await page.element('pay').listeners.click();
  const A=paymentOf(payments);let countA=0,countC=0;
  answer=request=>request.hash===A.hash?(++countA<30?unavailable:done(request)):(++countC<10?unavailable:done(request));
  const payingC=page.element('pay').listeners.click();
  await ticks(()=>countC>=2);
  page.payDisabled.length=0;
  await page.element('login').listeners.click();await payingC;
  assert.equal(countC,10);assert.equal(countA,30);
  assert(page.payDisabled.every(Boolean),'Pay stays off while a settlement runs');
  assert.equal(page.element('pay').disabled,false);assert.deepEqual(page.pending(),[]);

  // At most 20 payments, for 7 days: an expired one is dropped when the page opens, the oldest
  // when a 21st is added, each with a warning.
  const saved=new Map(),now=Date.now(),kept=[...Array(20)].map((_,i)=>({...paymentOf(230+i),accountId:'5',savedAt:now-1000*(20-i)})),expired={...paymentOf(255),accountId:'5',savedAt:now-8*86400000};
  saved.set(key,JSON.stringify([expired,...kept]));
  page=await merchantPage({settle:()=>({status:401,body:{error:'Sign in first'}}),storage:saved});
  await ticks(()=>page.settles.length>=20&&page.element('pay').disabled===false);
  assert.equal(page.settles.length,20);assert.equal(page.saved().length,20);
  assert.match(page.warnings[0],new RegExp(`Payment ${expired.hash} .* more than 7 days ago`));
  await page.element('pay').listeners.click();
  const newest=paymentOf(payments);
  assert.deepEqual(page.pending(),[...kept.slice(1),{...newest,accountId:'5'}].map(({savedAt,...entry})=>entry));
  assert.match(page.warnings[1],new RegExp(`More than 20 unconfirmed payments .* payment ${kept[0].hash} `));assert.equal(page.warnings.length,2);
});
