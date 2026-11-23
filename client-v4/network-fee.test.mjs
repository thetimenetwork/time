// The action fee is a setting of the network (genesis field `fee_micros`, 1 to 999; left out
// for the protocol-4 fee of 1000). Wallets, the gateway, shops and the campaign harness take it
// from the network: from verified state where there is one, never from a constant.
import test from 'node:test';import assert from 'node:assert/strict';import {createHash} from 'node:crypto';
import {readFile,mkdtemp,rm} from 'node:fs/promises';import os from 'node:os';import path from 'node:path';import {fileURLToPath} from 'node:url';
import './time-sdk.js';
import {createOrderService} from './server-auth.mjs';
import {createV4Servers} from './server.mjs';
import {buildGenesis} from '../campaign/lib/genesis.mjs';

const sdk=globalThis.TimeSDK,networkId='ab'.repeat(32);
const trust={app_version:'4',network_id:networkId,chain_id:'time-devnet-v4-test'};

test('a fee is a canonical decimal from 1 to 1000, and verified state says which one a network has',()=>{
  assert.equal(sdk.PROTOCOL_FEE_MICROS,'1000');
  for(const good of ['1','2','10','999','1000'])assert.equal(sdk.isFee(good),true,good);
  for(const bad of ['0','1001','2000','10000','01','010','+1','-1',' 1','1 ','1.0','1e2','0x10','','ten','１０',0,1,10,1000,10n,null,undefined,true,['10'],{fee:'10'}])assert.equal(sdk.isFee(bad),false,String(bad));
  // A network that keeps the protocol-4 fee leaves the field out of its genesis.
  assert.equal(sdk.networkFee({config:{}}),'1000');
  assert.equal(sdk.networkFee({config:{registration:{fee_micros:'10000'}}}),'1000','the registration charge is another setting');
  // The setting is read from the configuration of a verified state, never assumed without one.
  for(const config of [undefined,null,'config',['fee_micros']])assert.throws(()=>sdk.networkFee({config}),/network configuration/,String(config));
  for(const fee of ['1','10','999'])assert.equal(sdk.networkFee({config:{fee_micros:fee}}),fee);
  // What no node accepts in a genesis is not a fee here either: the protocol-4 fee written out,
  // zero, more than 1000, another spelling, another type.
  for(const bad of ['1000','0','1001','010','10 ',10,null,true,['10']])assert.throws(()=>sdk.networkFee({config:{fee_micros:bad}}),/network fee/,String(bad));
  for(const none of [undefined,null,'state',7])assert.throws(()=>sdk.networkFee(none),/verified state/);
});

// A wallet client whose gateway reports `reported` and whose verifier returns a state with the
// setting `written` (undefined: the genesis has no such field).
function client(reported,written){
  const block={signed_header:{header:{height:'1'}}};
  const verifier={
    verifyTrust:async()=>({}),
    verifyLightUpdate:async candidate=>({verified:true,status:'VERIFIED',checkpoint:{height:candidate.signed_header.header.height,block_hash:'cd'.repeat(32),block:candidate}}),
    verifyViewProof:async()=>({verified:true,completeAccountSet:false,state:{network_id:networkId,height:'5',accounts:[],config:written===undefined?{}:{fee_micros:written}}}),
  };
  const fetcher=async url=>{
    const route=new URL(url).pathname;
    const answer=route==='/api/network'?{protocolVersion:'4',networkId,chainId:trust.chain_id,...(reported===undefined?{}:{feeMicros:reported})}:route==='/api/view-proof'?{light_block:block}:{error:'unexpected request'};
    return {ok:true,text:async()=>JSON.stringify(answer)};
  };
  return sdk.createClient({gateway:'https://rpc.example',trust,verifier,fetcher});
}

test('the SDK gives no fee on the word of a gateway, and refuses a report that no network could have',async()=>{
  for(const fee of [undefined,'1','10','999','1000'])assert.equal((await client(fee).getNetwork()).feeMicros,undefined,String(fee));
  for(const bad of ['0','1001','010','10.0',10,1000,null])await assert.rejects(client(bad).getNetwork(),/Unsupported V4 metadata/,String(bad));
});

test('once the wallet has verified a state, the fee is the one in that state, whatever the gateway reported',async()=>{
  // The gateway did not know yet (it reports the protocol-4 fee), reported another network's
  // fee, or was right: verified state decides.
  for(const [reported,written,fee] of [['1000','10','10'],['10',undefined,'1000'],['500','1','1'],['10','10','10'],['1000',undefined,'1000']]){
    const wallet=client(reported,written),network=await wallet.getNetwork();
    assert.equal(network.feeMicros,undefined);
    await wallet.getVerifiedState({});
    assert.equal(network.feeMicros,fee,`reported ${reported}, state says ${written}`);
    assert.equal((await wallet.getNetwork()).feeMicros,fee);
  }
  // A state whose setting no node would have accepted is not used at all.
  for(const bad of ['1000','0','1001','010',10,null])await assert.rejects(client('1000',bad).getVerifiedState({}),/network fee/,String(bad));
});

test('an order carries the fee of the network it is issued on',async()=>{
  const state=fee=>({protocol_version:'4',network_id:networkId,time_micros:'600000000',genesis:{genesis_time_micros:'0'},accounts:[{id:'5',nonce:'7'}],recovery_cases:[],config:fee===undefined?{}:{fee_micros:fee}});
  const snapshots=[];
  const config=fee=>({networkId,recipient:'0',protocolVersion:'4',verifiedState:async()=>({verified:true,state:state(fee)}),verifiedReceipt:async()=>{throw Error('not needed');},persist:async s=>snapshots.push(s),now:()=>1000});
  assert.equal((await createOrderService(config('10')).issue('5','10000')).fee,'10');
  assert.equal(snapshots.at(-1).orders[0].fee,'10');
  assert.equal((await createOrderService(config('1')).issue('5','10000')).fee,'1');
  assert.equal((await createOrderService(config('999')).issue('5','10000')).fee,'999');
  // A network without the setting: the protocol-4 fee, as before.
  assert.equal((await createOrderService(config(undefined)).issue('5','10000')).fee,'1000');
  // No order is issued on a fee no network can have.
  for(const bad of ['1000','0','1001','010',10,null]){const before=snapshots.length;await assert.rejects(createOrderService(config(bad)).issue('5','10000'),/network fee/,String(bad));assert.equal(snapshots.length,before);}
  // Stored orders are read back with the fee they were issued at; a fee no network can have is refused.
  const saved=snapshots[0];assert.equal(saved.orders[0].fee,'10');
  createOrderService({...config('10'),initialState:saved});
  for(const bad of ['0','1001','010',10,undefined]){const corrupted=structuredClone(saved);corrupted.orders[0].fee=bad;assert.throws(()=>createOrderService({...config('10'),initialState:corrupted}),/Invalid persistent merchant order/,String(bad));}
});

test('the campaign genesis writes the fee where the node writes it: directly after the share of the fees',()=>{
  const identities=Array.from({length:4},(_,i)=>({address:String(i).repeat(40),pub_key:{type:'tendermint/PubKeyEd25519',value:Buffer.alloc(32,i+1).toString('base64')}}));
  const consensusParams={block:{max_bytes:'1',max_gas:'-1'},evidence:{max_age_num_blocks:'1',max_age_duration:'1',max_bytes:'1'},validator:{pub_key_types:['ed25519']},version:{app:'0'},abci:{}};
  const build=options=>buildGenesis({identities,consensusParams,now:1_800_000_000_000,...options});
  // What follows the last protocol-4 field in the bytes the network id is the hash of.
  const tail=g=>JSON.stringify(g.manifest.genesis).split('"trusting_period_seconds":"604800"')[1];
  for(const [options,expected] of [
    [{},'}'],
    [{feeMicros:1000},'}'],
    [{feeMicros:10},',"fee_micros":"10"}'],
    [{feeMicros:1},',"fee_micros":"1"}'],
    [{feesToValidatorsPpm:1_000_000},',"fees_to_validators_ppm":"1000000"}'],
    [{feesToValidatorsPpm:1_000_000,feeMicros:10},',"fees_to_validators_ppm":"1000000","fee_micros":"10"}'],
    [{feeMicros:999,feesToValidatorsPpm:5},',"fees_to_validators_ppm":"5","fee_micros":"999"}'],
  ]){
    const g=build(options);
    assert.equal(tail(g),expected,JSON.stringify(options));
    assert.equal(g.networkId,createHash('sha256').update('TCDEVNET-NETWORK-V4\0').update(JSON.stringify(g.manifest.genesis)).digest('hex'));
    assert.deepEqual(g.genesis.app_state,g.manifest.genesis);
    // What the load generator reads from the manifest, and what the SDK reads from state.
    assert.equal(g.manifest.genesis.fee_micros??'1000',String(options.feeMicros??1000));
    assert.equal(sdk.networkFee({config:g.manifest.genesis}),String(options.feeMicros??1000));
  }
  for(const bad of [0,1001,-1,10.5,NaN,'10','1000',null,true])assert.throws(()=>build({feeMicros:bad}),/feeMicros/,String(bad));
});

// The gateway with the installed WASM verifier, against signed blocks and state proofs.
async function gateway(fixture,run){
  const directory=await mkdtemp(path.join(os.tmpdir(),'time-v4-fee-')),originalNow=Date.now;Date.now=()=>fixture.now_ms;
  const block=fixture.proof.light_block;
  const rpc=async(endpoint,p={})=>{
    if(endpoint==='/commit')return {signed_header:block.signed_header};
    if(endpoint==='/validators')return {block_height:p.height,total:'4',validators:p.height==='6'?block.validators:block.next_validators};
    if(endpoint==='/abci_query')return {response:{height:'5',code:0,value:Buffer.from(JSON.stringify({height:'5',history_proofs:fixture.proof.history_proofs,root:block.signed_header.header.app_hash.toLowerCase(),entries:fixture.proof.entries})).toString('base64')}};
    throw Error('Unconfigured test RPC');
  };
  let servers;
  try{
    servers=await createV4Servers({root:fileURLToPath(new URL('../',import.meta.url)),manifest:{networkId:fixture.trust.network_id,chainId:fixture.trust.chain_id,trust:fixture.trust},rpc,walletPort:0,merchantPort:0,checkpointPath:path.join(directory,'checkpoint.json'),ordersPath:path.join(directory,'orders.json')});
    await run(servers);
  }finally{Date.now=originalNow;await servers?.close();await rm(directory,{recursive:true,force:true});}
}
const reportedFee=async servers=>(await (await fetch(servers.walletOrigin+'/api/network')).json()).feeMicros;

// verifier-v4/fixtures/proof-fee.json is the public proof fixture of the verifier with
// `"fee_micros":"10"` in the configuration of the metadata row, signed like the original
// (regenerate: V4_EXPORT_FEE_FIXTURE=1 cargo test --manifest-path verifier-v4/Cargo.toml).
test('a network with a fee of 10: the installed verifier, the gateway, the wallet and an order all say 10',async()=>{
  const fixture=JSON.parse(await readFile(new URL('../verifier-v4/fixtures/proof-fee.json',import.meta.url),'utf8'));
  await gateway(fixture,async servers=>{
    // Before it has verified any state the gateway reports no fee.
    assert.equal(await reportedFee(servers),undefined);
    const checked=await servers.verifiedState(fixture.request);
    assert.equal(checked.verified,true);assert.equal(checked.state.config.fee_micros,'10');
    assert.equal(await reportedFee(servers),'10');
    // The wallet takes no fee from that report, only from a state it verified itself.
    const wallet=sdk.createClient({gateway:servers.walletOrigin,trust:fixture.trust});
    assert.equal((await wallet.getNetwork()).feeMicros,undefined);
    const seen=await wallet.getVerifiedState(fixture.request);
    assert.equal(seen.state.config.fee_micros,'10');assert.equal((await wallet.getNetwork()).feeMicros,'10');
    // A shop on this gateway asks the payer for the fee of the network.
    const order=await createOrderService({networkId:fixture.trust.network_id,recipient:'0',verifiedState:servers.verifiedState,verifiedReceipt:async()=>{throw Error('not needed');},persist:async()=>{}}).issue('0','100000');
    assert.equal(order.fee,'10');
  });
});

test('a network without the setting: gateway and wallet agree on the protocol-4 fee once they have verified a state',async()=>{
  const fixture=JSON.parse(await readFile(new URL('../verifier-v4/fixtures/proof.json',import.meta.url),'utf8'));
  await gateway(fixture,async servers=>{
    assert.equal(await reportedFee(servers),undefined);
    const checked=await servers.verifiedState(fixture.request);
    assert.equal(checked.state.config.fee_micros,undefined);
    assert.equal(await reportedFee(servers),'1000');
    const wallet=sdk.createClient({gateway:servers.walletOrigin,trust:fixture.trust});
    await wallet.getVerifiedState(fixture.request);
    assert.equal((await wallet.getNetwork()).feeMicros,'1000');
  });
});
