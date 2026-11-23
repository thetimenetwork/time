// Integration tests operate only on the launcher-owned development processes.
// Test account and signer keys are read in memory; evidence contains no secrets.
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {createPrivateKey,sign} from 'node:crypto';
import path from 'node:path';
import net from 'node:net';
import '../client-v4/time-sdk.js';
import * as verifier from '../client-v4/proof-verifier.mjs';

const SDK=globalThis.TimeSDK;
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const assert=(ok,text)=>{if(!ok)throw Error(text);};
const be64=n=>{const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(n));return b;};
export async function runV4NetworkProbe({root,options,nodes,launch,stop,rpc,wait,servers,runtime}){
  const start=new Date().toISOString(),checks=[];
  const record=(name,detail)=>{checks.push({name,passed:true,detail});console.log('V4 network probe: '+name);};
  const client=SDK.createClient({gateway:servers.walletOrigin,trust:runtime.trust,verifier});
  const keys=JSON.parse(await readFile(path.join(options.lab,'operator-auth.json'),'utf8'));
  const state=async query=>(await client.getVerifiedState(query)).state;
  const privateKey=async id=>crypto.subtle.importKey('pkcs8',Buffer.from(keys[id].privateKeyPkcs8,'base64'),'Ed25519',false,['sign']);
  const perform=async(id,kind,payload)=>client.perform({kind,account:{id:String(id)},publicKey:keys[id].publicKey,privateKey:await privateKey(id),payload});
  async function reject(name,operation){let error;try{await operation();}catch(e){error=e;}assert(error,name+' unexpectedly succeeded');record(name,{rejection:String(error.message).slice(0,180)});}
  let first=await state({ids:['0','1','2','3','4','5','6'],include_pos:true,include_bitcoin:true,include_policy:true});
  assert(first.protocol_version==='4'&&first.pos.profile==='laboratory'&&first.bitcoin.meta.config.network==='regtest','wrong integration test network');
  record('independent WASM verifies zero-premine network and exact supply counters',{height:first.height,elapsed:(BigInt(first.time_micros)-BigInt(first.genesis.genesis_time_micros)).toString(),accounts:first.account_count});
  const initialActive=first.pos.active.map(v=>String(v.owner));
  assert(initialActive.length===4,'this rehearsal requires four initial validators');
  await reject('synthetic unpaid earning weights are rejected',()=>perform(0,4,{epoch:first.auction_epoch,weight:'999999'}));
  // Bootstrap rewards fund these four real self bonds. The next three receive
  // their funds through actual Core payments and native receipt verification.
  for(let id=0;id<4;id++){
    const s=await wait('bootstrap rewards fund operator '+id,async()=>{const s=await state({ids:[String(id)],candidates:[String(id)]});return BigInt(s.accounts[0].balance)>=1_001_000n?s:false;},60000);
    if(BigInt(s.candidates[id].self_bond)<1_000_000n){assert(BigInt(s.accounts[0].balance)>=1_001_000n,'wait for bootstrap rewards before the rehearsal');await perform(id,18,{amount:'1000000'});}
  }
  record('four bootstrap operators escrow real minted self collateral',{minimumMicros:'1000000'});
  const snapshot=await state({include_bitcoin:true,include_policy:true});
  const period=BigInt(snapshot.config.auction.epoch_seconds)*1_000_000n;
  const target=((BigInt(snapshot.time_micros)-BigInt(snapshot.genesis.genesis_time_micros))/period+8n).toString();
  const receipts=[];
  for(let id=4;id<7;id++){
    const fixture=await client.request('/api/regtest-bid',{method:'POST',body:JSON.stringify({account:String(id),epoch:target})});
    const current=await state({include_bitcoin:true});
    const newHeaders=fixture.headersHex.slice(Number(current.bitcoin.meta.best_height));
    for(let at=0;at<newHeaders.length;at+=256){
      const body=SDK.buildAction({kind:40,from:SDK.MAX_U64,nonce:'0',authEpoch:'0',networkId:runtime.networkId,publicKey:'00'.repeat(32),payload:{headers:newHeaders.slice(at,at+256)}});
      await client.submit(SDK.concat(body,new Uint8Array(64)));
    }
    const payload={epoch:target,policy_revision:String(snapshot.receiving_policy.revision),receipt:{network:fixture.receipt.network,block_hash:fixture.receipt.block_hash,transaction_hex:fixture.transactionHex,vout:fixture.receipt.vout,expected_sats:String(fixture.receipt.expected_sats),merkle_proof_hex:fixture.proofHex}};
    await perform(id,41,payload);receipts.push({id,payload,txid:fixture.txid});
  }
  record('three real Core bids finalize after twelve confirmations',{epoch:target,beneficiaries:receipts.map(r=>String(r.id)),txids:receipts.map(r=>r.txid),confirmations:12});
  await reject('permanent BTC outpoint replay is rejected',()=>perform(4,41,receipts[0].payload));
  await reject('another beneficiary cannot use a copied Bitcoin receipt',()=>perform(5,41,receipts[0].payload));
  await wait('target Bitcoin earning epoch closes',async()=>{const s=await state({ids:['4','5','6'],epochs:[target]});return s.earning_epochs[target]?.closed?s:false;},150000);
  for(let id=4;id<7;id++){await perform(id,42,{epoch:target});}
  const paid=await state({ids:['4','5','6'],epochs:[target],include_bitcoin:true});
  const pot=paid.earning_epochs[target],expected=BigInt(pot.pot)/3n;
  assert(pot.claims==='3'&&BigInt(pot.paid)===expected*3n,'pro-rata auction settlement mismatch');
  assert(paid.accounts.every(a=>BigInt(a.balance)===expected),'fresh recipients did not get exact pro-rata earnings');
  record('zero-balance claim, exact pro-rata payout and dust settlement',{pot:pot.pot,eachMicros:expected.toString(),paid:pot.paid,reserve:paid.auction_reserve_total});
  await reject('earning cannot be claimed twice',()=>perform(4,42,{epoch:target}));
  for(let id=4;id<7;id++){
    const validator=JSON.parse(await readFile(path.join(nodes[id].home,'config','priv_validator_key.json'),'utf8'));
    const consensusKey=Buffer.from(validator.pub_key.value,'base64').toString('hex');
    const seed=Buffer.from(validator.priv_key.value,'base64').subarray(0,32);
    const secret=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});
    const commission=Buffer.alloc(2);commission.writeUInt16BE(1000);
    const proof=sign(null,Buffer.concat([Buffer.from('TIME-POS-REGISTER-V1\0'),Buffer.from(runtime.networkId,'hex'),be64(id),Buffer.from(consensusKey,'hex'),commission]),secret).toString('hex');
    await perform(id,17,{commission_bps:1000,consensus_key:consensusKey,proof});
  }
  const handoff=await wait('seven funded validators complete actual H+2 handoff',async()=>{const s=await state({include_pos:true});return s.pos.bootstrap_ended&&s.pos.active.length===7&&!s.pos.safety_hold?s:false;},180000);
  const actual=await rpc('/validators',{height:handoff.height,per_page:'100'});
  const actualKeys=actual.validators.map(v=>Buffer.from(v.pub_key.value,'base64').toString('hex')).sort();
  assert(JSON.stringify(actualKeys)===JSON.stringify(handoff.pos.active.map(v=>v.consensus_key).sort()),'Comet roster differs from authenticated active PoS roster');
  record('actual seven-key funded handoff and dynamic light client agree',{height:handoff.height,bootstrapEnded:handoff.pos.bootstrap_ended,validators:handoff.pos.active.map(v=>({owner:v.owner,power:v.power}))});
  const transfer=await perform(4,3,{to:'6',amount:'10000'});
  assert(transfer.executionVerified&&transfer.action.kind===3,'native payment receipt was not independently verified');
  record('earned seconds transfer with canonical anchored receipt',{hash:transfer.hash,height:transfer.height});
  const statuses=indices=>Promise.all(indices.map(i=>rpc('/status',{},i)));
  const minimum=values=>values.reduce((m,v)=>BigInt(v.sync_info.latest_block_height)<m?BigInt(v.sync_info.latest_block_height):m,BigInt(values[0].sync_info.latest_block_height));
  const advance=async(indices,before,label)=>wait(label,async()=>{const v=await statuses(indices);return minimum(v)>=before+2n?v:false;});
  const agree=async indices=>{const h=minimum(await statuses(indices));const blocks=await Promise.all(indices.map(i=>rpc('/block',{height:String(h)},i)));assert(blocks.every(b=>b.block_id.hash===blocks[0].block_id.hash&&b.block.header.app_hash===blocks[0].block.header.app_hash),'finalized network disagreement');return {height:String(h),blockHash:blocks[0].block_id.hash,appHash:blocks[0].block.header.app_hash};};
  const halt=async h=>{h.expectedStop=true;await stop(h);};
  const startComet=i=>{const n=nodes[i];n.consensus=launch(options.comet,['start','--home',n.home,'--log_level','error'],'comet'+i+'-resumed',path.join(n.home,'consensus.log'));};
  // Select unavailable authority by actual power, not a convenient node count.
  const ordered=[...handoff.pos.active].sort((a,b)=>BigInt(a.power)>BigInt(b.power)?-1:1);
  const total=ordered.reduce((s,v)=>s+BigInt(v.power),0n),unavailable=[];let stoppedPower=0n;
  for(const v of [...ordered].reverse()){if((stoppedPower+BigInt(v.power))*3n>=total)break;unavailable.push(Number(v.owner));stoppedPower+=BigInt(v.power);}
  assert(unavailable.length>0,'cannot construct minority outage');
  let live=Array.from({length:7},(_,i)=>i).filter(i=>!unavailable.includes(i));const before=minimum(await statuses(live));
  for(const i of unavailable)await halt(nodes[i].consensus);
  await advance(live,before,'more than two thirds actual power progresses');record('minority power outage permits finality',{stoppedPower:String(stoppedPower),totalPower:String(total),agreement:await agree(live)});
  for(const v of ordered){if(unavailable.includes(Number(v.owner)))continue;unavailable.push(Number(v.owner));stoppedPower+=BigInt(v.power);await halt(nodes[Number(v.owner)].consensus);if(stoppedPower*3n>=total)break;}
  live=Array.from({length:7},(_,i)=>i).filter(i=>!unavailable.includes(i));await sleep(3500);const halted=(await statuses(live)).map(v=>v.sync_info.latest_block_height);await sleep(6500);const later=(await statuses(live)).map(v=>v.sync_info.latest_block_height);
  assert(JSON.stringify(halted)===JSON.stringify(later),'less than supermajority continued finalizing');record('at least one third unavailable power halts finality',{stoppedPower:String(stoppedPower),totalPower:String(total),before:halted,after:later,observationSeconds:6.5});
  for(const i of unavailable)startComet(i);await advance(Array.from({length:7},(_,i)=>i),BigInt(later[0]),'restored voting quorum catches up');record('restored signers and all seven databases converge',await agree(Array.from({length:7},(_,i)=>i)));
  await halt(nodes[6].consensus);await halt(nodes[6].application);const node=nodes[6];
  node.application=launch(options.app,['--devnet','--db',path.join(node.home,'data','application.redb'),'--listen',`127.0.0.1:${node.ports.app.port}`],'app6-reopened',path.join(node.home,'application.log'));
  await wait('reopened Rust application listens',()=>new Promise(resolve=>{const socket=net.connect(node.ports.app.port,'127.0.0.1');socket.setTimeout(500);socket.once('connect',()=>{socket.destroy();resolve(true);});socket.once('error',()=>resolve(false));socket.once('timeout',()=>{socket.destroy();resolve(false);});}));
  startComet(6);const baseline=minimum(await statuses([0,1,2,3,4,5]));await advance([0,1,2,3,4,5,6],baseline,'reopened native database catches up');record('native state and consensus signer restart preserve roots',await agree([0,1,2,3,4,5,6]));
  await client.waitReceipt(transfer.hash);record('pre-outage payment receipt reanchors after restart',{hash:transfer.hash});
  const final=await state({include_pos:true,include_bitcoin:true,include_policy:true});
  const report={status:'PASS_LOCAL_V4_FUNDED_HANDOFF_AND_FAULTS',rewardVersion:1,startedAt:start,finishedAt:new Date().toISOString(),networkId:runtime.networkId,binaries:runtime.binaries,sourceHashes:runtime.sourceHashes,checks,final:{height:final.height,bank:final.bank,liquid:final.liquid_total,posEscrow:final.pos_assets_total,auctionReserve:final.auction_reserve_total,elapsedMicros:(BigInt(final.time_micros)-BigInt(final.genesis.genesis_time_micros)).toString()},publicLaunchAllowed:false,scope:'Seven processes on one computer and private Bitcoin Core regtest. Real native transitions/proofs/H+2 changes; no independent operators, WAN capacity, hardware custody, physical power-loss or external audit claim.'};
  const directory=path.join(root,'results-v4');await mkdir(directory,{recursive:true});const file=path.join(directory,'network-'+start.replace(/[:.]/g,'-')+'.json');await writeFile(file,JSON.stringify(report,null,2)+'\n',{flag:'wx'});console.log('V4 network probe PASS: '+file);return report;
}
