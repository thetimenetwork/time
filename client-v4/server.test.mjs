import test from 'node:test';import assert from 'node:assert/strict';import {readFile,mkdtemp,rm} from 'node:fs/promises';import os from 'node:os';import path from 'node:path';import {fileURLToPath} from 'node:url';
import {createV4Servers,checkCatalog,priceOf} from './server.mjs';import './time-sdk.js';
const fixture=JSON.parse(await readFile(new URL('../verifier-v4/fixtures/proof.json',import.meta.url),'utf8'));
test('public HTTP pins certified H-1, independently verifies actual WASM, and confines installed code',async()=>{
 const directory=await mkdtemp(path.join(os.tmpdir(),'time-v4-http-')),calls=[],originalNow=Date.now;Date.now=()=>fixture.now_ms;
 const block=fixture.proof.light_block,root=fileURLToPath(new URL('../',import.meta.url));
 const rpc=async(endpoint,p={})=>{calls.push({endpoint,p});if(endpoint==='/commit')return {signed_header:block.signed_header};if(endpoint==='/validators')return {block_height:p.height,total:'4',validators:p.height==='6'?block.validators:block.next_validators};if(endpoint==='/abci_query'){assert.equal(p.height,'5');assert.equal(p.path,'"/v4/state"');return {response:{height:'5',code:0,value:Buffer.from(JSON.stringify({height:'5',history_proofs:fixture.proof.history_proofs,root:block.signed_header.header.app_hash.toLowerCase(),entries:fixture.proof.entries})).toString('base64')}};}throw Error('Unconfigured test RPC');};
 let servers;try{
  servers=await createV4Servers({root,manifest:{networkId:fixture.trust.network_id,chainId:fixture.trust.chain_id,trust:fixture.trust},rpc,walletPort:0,merchantPort:0,checkpointPath:path.join(directory,'checkpoint.json'),ordersPath:path.join(directory,'orders.json')});
  const c=TimeSDK.createClient({gateway:servers.walletOrigin,trust:fixture.trust}),v=await c.getVerifiedState(fixture.request);assert.equal(v.verified,true);assert.equal(v.height,'5');
  assert(calls.some(x=>x.endpoint==='/validators'&&x.p.height==='7'));assert(calls.filter(x=>x.endpoint==='/abci_query').every(x=>x.p.height==='5'));
  for(const asset of ['/','/approve','/sdk/time-sdk.js','/sdk/proof-verifier.js','/sdk/light-client.mjs','/sdk/account-security.mjs','/web-v4/shared/verifier/timecurrency_verifier_v4.js','/web-v4/shared/verifier/timecurrency_verifier_v4_bg.wasm','/trust-manifest.json'])assert.equal((await fetch(servers.walletOrigin+asset)).status,200,asset);
  for(const route of ['/sdk/server.mjs','/sdk/server-auth.mjs','/sdk/order-store.mjs','/wallet/wallet.test.mjs','/web-v4/shared/../../../client-v4/server.mjs','/%5c../client-v4/server.mjs','/%00'])assert.equal((await fetch(servers.walletOrigin+route)).status,404,route);
  const before=calls.length;assert.equal((await fetch(servers.walletOrigin+'/api/view-proof?query='+encodeURIComponent('{"names":"alice"}'))).status,400);assert.equal(calls.length,before);
  assert.equal((await fetch(servers.walletOrigin+'/api/submit',{method:'POST',headers:{Origin:'https://attacker.example','Content-Type':'application/json'},body:'{}'})).status,403);assert.equal(calls.length,before);
 }finally{Date.now=originalNow;if(servers)await servers.close();await rm(directory,{recursive:true,force:true});}
});

test('a valid proof for another transaction cannot poison the durable requested-hash archive',async()=>{
 const directory=await mkdtemp(path.join(os.tmpdir(),'time-v4-receipt-http-')),originalNow=Date.now;Date.now=()=>fixture.now_ms;let servers;
 const b=fixture.proof.light_block;
 const rpc=async(endpoint,p={})=>{
  if(endpoint==='/tx')return fixture.receipt.tx;
  if(endpoint==='/commit')return {signed_header:p.height==='1'?fixture.receipt.signed_header:p.height==='2'?fixture.receipt.next_signed_header:b.signed_header};
  if(endpoint==='/validators')return {block_height:p.height,total:'4',validators:p.height==='6'?b.validators:b.next_validators};
  if(endpoint==='/abci_query')return {response:{height:'5',code:0,value:Buffer.from(JSON.stringify({height:'5',root:b.signed_header.header.app_hash.toLowerCase(),entries:fixture.proof.entries,history_proofs:fixture.proof.history_proofs})).toString('base64')}};
  throw Error('Unconfigured RPC');
 };
 try{servers=await createV4Servers({root:fileURLToPath(new URL('../',import.meta.url)),manifest:{networkId:fixture.trust.network_id,chainId:fixture.trust.chain_id,trust:fixture.trust},rpc,walletPort:0,merchantPort:0,checkpointPath:path.join(directory,'checkpoint.json'),ordersPath:path.join(directory,'orders.json')});
  await assert.rejects(servers.getReceipt('00'.repeat(32)),/requested transaction/);
  const proof=await servers.getReceipt(fixture.receipt.tx.hash);assert.equal(proof.tx.hash,fixture.receipt.tx.hash);
 }finally{Date.now=originalNow;await servers?.close();await rm(directory,{recursive:true,force:true});}
});

test('the shop sets the price: the order route reads an item name, never an amount from the browser',async()=>{
 const catalog=checkCatalog({'test-purchase':'100000','poster-a3':'2500000'});
 assert.equal(priceOf(catalog,'test-purchase'),'100000');assert.equal(priceOf(catalog,'poster-a3'),'2500000');
 for(const item of [undefined,null,'','unknown','__proto__','constructor','toString',100000,{amount:'1'},['test-purchase']])assert.throws(()=>priceOf(catalog,item),/Unknown item/,String(item));
 assert.throws(()=>{catalog['test-purchase']='1';},TypeError);
 for(const bad of [undefined,null,[],{},{'Test':'1'},{'a b':'1'},{'x':1},{'x':'0'},{'x':'01'},{'x':'-1'},{'x':'1.5'},{'x':'18446744073709551616'},{'x':'99999999999999999999'}])assert.throws(()=>checkCatalog(bad),/[Cc]atalog/,JSON.stringify(bad));
 const directory=await mkdtemp(path.join(os.tmpdir(),'time-v4-catalog-')),originalNow=Date.now;Date.now=()=>fixture.now_ms;let servers;
 const base={root:fileURLToPath(new URL('../',import.meta.url)),manifest:{networkId:fixture.trust.network_id,chainId:fixture.trust.chain_id,trust:fixture.trust},rpc:async()=>{throw Error('Unconfigured RPC');},walletPort:0,merchantPort:0,checkpointPath:path.join(directory,'checkpoint.json'),ordersPath:path.join(directory,'orders.json')};
 try{
  await assert.rejects(createV4Servers({...base,catalog:{'x':'0'}}),/Catalog/);
  servers=await createV4Servers({...base,catalog:{'poster-a3':'2500000'}});
  const config=await (await fetch(servers.merchantOrigin+'/api/config')).json();assert.deepEqual(config.catalog,{'poster-a3':'2500000'});
  // Without a session the route answers 401 whatever the body says.
  assert.equal((await fetch(servers.merchantOrigin+'/api/order',{method:'POST',headers:{Origin:servers.merchantOrigin,'Content-Type':'application/json'},body:JSON.stringify({amount:'1',item:'poster-a3'})})).status,401);
 }finally{Date.now=originalNow;await servers?.close();await rm(directory,{recursive:true,force:true});}
});
