// Independent review of the SDK's part of the upgrade signal (branch upgrade-signal, commit 35f080e).
//
// Tests named "REVIEW ...: FINDING" state a property the SDK must have and are expected to FAIL on
// the code under review. Tests named "REVIEW ...: held" are attacks that did not get through; they
// pass, and are kept so that they keep passing.
//
// The engine's rules are ported here from the Rust source by hand, independently of the SDK's
// code: `Tally::holds` and `signal_counts` (v5/src/upgrade.rs, v5/src/engine.rs),
// `security::frozen_at` (v5/src/security.rs), `decode_signal` and `wire::decode`.
import test from 'node:test';import assert from 'node:assert/strict';
import './time-sdk.js';

const sdk=globalThis.TimeSDK;
const NETWORK='ab'.repeat(32),KEY='11'.repeat(32),GENESIS='1700000000000000',MAX=18446744073709551615n;
const DAY=86400000000n,NOW=100n*DAY;

// ------------------------------------------------------------------ the engine's count, ported
/// `security::frozen_at`: only an account none of whose keys holds both powers has a row; a freeze
/// still running, or a replacement of the keys that has not expired (`settle` drops it when
/// `expires < now`).
function engineFrozen(account,row,now){
  if(account.devices.some(device=>device.can_manage&&device.can_spend)||!row)return false;
  const waiting=row.pending_root&&!(BigInt(row.pending_root.expires_elapsed_micros)<now);
  return now<BigInt(row.frozen_until_elapsed_micros)||Boolean(waiting);
}
/// `Overlay::signal_counts`.
function engineCounts(world,owner){
  const candidate=world.candidates[owner];if(!candidate)return false;
  if(candidate.jailed||candidate.archived)return false;
  const account=world.accounts.find(item=>item.id===owner);
  if(world.recovery.some(item=>item.target===owner&&item.ready_elapsed_micros!==null))return false;
  return !engineFrozen(account,world.security.find(item=>item.account===owner),world.now);
}
/// `Tally::holds`, with the rosters and the jailed set as `upgrade_step` builds them.
function engineHolds(world,proposal,[numerator,denominator]){
  const rosters=[world.active,...world.scheduled],jailed=new Set(rosters.flat().filter(item=>world.candidates[item.owner].jailed).map(item=>item.owner));
  for(const roster of rosters){
    let total=0n,support=0n;
    for(const item of roster){
      if(jailed.has(item.owner))continue;
      total+=BigInt(item.power);
      const entry=world.signals.find(signal=>signal.owner===item.owner);
      if(!entry||entry.version===undefined||entry.version!==proposal.version||entry.spec!==proposal.spec||entry.activate_elapsed_micros!==proposal.activate_elapsed_micros)continue;
      if(engineCounts(world,item.owner))support+=BigInt(item.power);
    }
    if(total===0n||support*denominator<total*numerator)return false;
  }
  return rosters.length>0;
}
/// The verified state of a world, as the verifier returns it for a selection that names every account.
function stateOf(world,{accounts=world.accounts,candidates=world.candidates,security=world.security}={}){
  return {protocol_version:'4',network_id:NETWORK,height:'500',time_micros:(BigInt(GENESIS)+world.now).toString(),genesis:{genesis_time_micros:GENESIS},config:{},accounts,recovery_cases:world.recovery,security,candidates,
    upgrade:world.signals.length||world.plan?{...(world.plan?{plan:world.plan}:{}),signals:world.signals}:null,
    pos:{profile:'production',candidate_ids:Object.keys(world.candidates),active:world.active,scheduled:world.scheduled.map((validators,index)=>({announced_height:String(499+index),effective_height:String(501+index),validators})),safety_hold:world.hold}};
}
const securedDevices=[{public_key:'21'.repeat(32),can_manage:false,can_spend:false},{public_key:'22'.repeat(32),can_manage:false,can_spend:true},{public_key:'23'.repeat(32),can_manage:true,can_spend:false}];
const securityRow=(id,more={})=>({account:id,version:'1',policy:{threshold:'2',daily_limit_micros:'60000000',delay_seconds:'172800',freeze_seconds:'172800'},allowance_micros:'60000000',allowance_elapsed_micros:'0',frozen_until_elapsed_micros:'0',freezes:'0',pending_limit:null,pending_payments:[],next_id:'1',pending_root:null,...more});
const PLANS=[{version:'5',spec:'5e'.repeat(32),activate_elapsed_micros:(NOW+30n*DAY).toString()},{version:'5',spec:'7a'.repeat(32),activate_elapsed_micros:(NOW+30n*DAY).toString()},{version:'5',spec:'5e'.repeat(32),activate_elapsed_micros:(NOW+31n*DAY).toString()}];
/// A small deterministic generator, so that a failure can be repeated.
function random(seed){let state=seed>>>0;return max=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state%max;};}
function world(seed){
  const pick=random(seed),count=1+pick(9),owners=Array.from({length:count+pick(3)},(_,index)=>String(index*3+1));
  const power=()=>[1n,2n,3n,1000n,999n,1001n,MAX/400n,BigInt(1+pick(100000))][pick(8)].toString();
  const set=members=>members.map(owner=>({owner,consensus_key:KEY,power:power()}));
  const active=set(owners.slice(0,count)),scheduled=Array.from({length:pick(3)},()=>set(owners.filter(()=>pick(4)>0))).filter(list=>list.length);
  const inSets=new Set([...active,...scheduled.flat()].map(item=>item.owner));
  const candidates={},accounts=[],security=[],recovery=[],signals=[];
  for(const owner of owners){
    const kind=pick(10);
    candidates[owner]={owner,consensus_key:KEY,jailed:inSets.has(owner)&&pick(7)===0,archived:false,self_bond:'86400000000'};
    accounts.push({id:owner,name:'owner_'+owner,public_key:KEY,balance:'5000000',nonce:'3',auth_epoch:'0',devices:kind<6?[{public_key:KEY,can_manage:true,can_spend:true}]:securedDevices});
    if(kind===6)security.push(securityRow(owner));
    if(kind===7)security.push(securityRow(owner,{frozen_until_elapsed_micros:(NOW+BigInt(pick(3))-1n).toString()}));
    if(kind===8)security.push(securityRow(owner,{pending_root:{devices:[],policy:{},ready_elapsed_micros:'1',expires_elapsed_micros:(NOW+BigInt(pick(3))-1n).toString()}}));
    if(kind===5||kind===9)recovery.push({target:owner,ready_elapsed_micros:pick(2)?'5':null,expires_elapsed_micros:(NOW+DAY).toString()});
    const choice=pick(6);
    if(choice<4)signals.push({...(choice<3?{activate_elapsed_micros:PLANS[choice].activate_elapsed_micros,spec:PLANS[choice].spec,version:PLANS[choice].version}:{}),changed_elapsed_micros:'0',owner});
  }
  // `pos::Summary::safety_hold` after every block: a jailed validator in the set in force or in an announced one.
  const hold=[...inSets].some(owner=>candidates[owner].jailed);
  return {now:NOW,active,scheduled,candidates,accounts,security,recovery,signals,plan:null,hold};
}

test('REVIEW held: with every fact proven, the SDK\'s tally of each plan is the engine\'s, for 4000 generated validator sets',()=>{
  let compared=0,scheduled=0,kept=0;
  for(let seed=1;seed<=4000;seed++){
    const made=world(seed),state=stateOf(made),ids=made.accounts.map(item=>item.id);
    const status=sdk.signalStatusOf(state,{facts:sdk.signalFactsOf(state,ids)});
    for(const plan of status.plans){
      const proposal={version:plan.version,spec:plan.spec,activate_elapsed_micros:plan.activate_elapsed_micros};
      const expected=[engineHolds(made,proposal,[4n,5n]),engineHolds(made,proposal,[3n,4n])];
      assert.deepEqual([plan.tally.schedule,plan.tally.keep,plan.tally.exact],[...expected,true],`seed ${seed}: ${JSON.stringify(plan.tally)}`);
      compared+=1;scheduled+=Number(expected[0]);kept+=Number(expected[1]);
    }
  }
  // The generator reaches both answers often enough to mean something.
  assert.ok(compared>4000&&scheduled>100&&kept>scheduled&&kept<compared,`${compared} tallies, ${scheduled} at four fifths, ${kept} at three quarters`);
});

test('REVIEW FINDING: a tally that is not exact can be BELOW the engine\'s, and the SDK says a plan loses its three quarters when the network keeps it',()=>{
  // time-sdk.js on `exact`: "such a signal is then counted, so the share shown can be higher than the engine's".
  // client-v4/README.md: "Such a signal is counted, so the share can be higher than the network's, and it is said."
  // During a validator safety hold the SDK cannot tell who is jailed until it has read the candidate rows.
  // Until then it keeps every validator in the total, a jailed one that does not support the plan included.
  // The engine leaves that validator out of the total: its share is higher than the SDK's.
  const owners=['1','2','3','4','5'],plan=PLANS[0];
  const made={now:NOW,active:owners.map(owner=>({owner,consensus_key:KEY,power:'1000'})),scheduled:[],hold:true,recovery:[],security:[],
    candidates:Object.fromEntries(owners.map(owner=>[owner,{owner,consensus_key:KEY,jailed:owner==='5',archived:false,self_bond:'86400000000'}])),
    accounts:owners.map(owner=>({id:owner,name:'owner_'+owner,public_key:KEY,balance:'5000000',nonce:'3',auth_epoch:'0',devices:[{public_key:KEY,can_manage:true,can_spend:true}]})),
    signals:['1','2','3'].map(owner=>({activate_elapsed_micros:plan.activate_elapsed_micros,changed_elapsed_micros:'0',owner,spec:plan.spec,version:plan.version})),
    plan:{...plan,scheduled_elapsed_micros:'5'}};
  // The engine: validator 5 is jailed and left out; 3000 of 4000 is three quarters; the plan stays.
  assert.equal(engineHolds(made,plan,[3n,4n]),true,'control: the engine keeps the plan');
  // The SDK after its first proof alone (the gateway refused the further ones): the candidate rows of the others are not read.
  const first=stateOf(made,{candidates:{1:made.candidates['1']}}),partial=sdk.signalStatusOf(first,{account:'1',facts:sdk.signalFactsOf(first,['1']),complete:false});
  const tally=partial.plans[0].tally;
  assert.deepEqual([tally.exact,tally.lowest],[false,{support:'3000',total:'5000'}],'control: the SDK says its tally is not exact, and counts 3000 of 5000');
  // With every row read it agrees with the engine.
  const full=stateOf(made),complete=sdk.signalStatusOf(full,{account:'1',facts:sdk.signalFactsOf(full,owners)}).plans[0].tally;
  assert.deepEqual([complete.exact,complete.lowest,complete.keep],[true,{support:'3000',total:'4000'},true],'control: with every candidate row read the SDK counts as the engine does');
  // What the inexact tally says: below three quarters. The wallet turns `keep: false` of a scheduled plan into
  // "the next block cancels it unless support returns" (upgrade-signal.mjs, statusLines).
  // ADAPTED: this line asserted `tally.keep === true` for the inexact tally. A tally that could not read who is
  // jailed cannot know that either: 3000 of 5000 is what it counted. The corrected behaviour is that an inexact
  // tally states neither threshold (`keep` and `schedule` are null), so that nothing can be announced from it.
  assert.deepEqual([tally.keep,tally.schedule],[null,null],'an inexact tally says keep: false for a plan the engine keeps: "can be higher than the engine\'s" is not the only direction in which it is wrong');
});

// ------------------------------------------------------------------ the bytes, against the engine's parser
/// `wire::decode` and `decode_signal`: the payload of a kind-80 action is `{}` or the three fields in
/// their one order, the numbers as canonical decimal u64 strings, the hash as 64 lowercase
/// hexadecimal characters; `proposal.payload() == payload` leaves no other bytes.
function engineTakes(bytes){
  let text;try{text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);}catch{return false;}
  if(text==='{}')return true;
  const found=/^\{"activate_elapsed_micros":"(0|[1-9][0-9]*)","spec":"[0-9a-f]{64}","version":"(0|[1-9][0-9]*)"\}$/.exec(text);
  return Boolean(found)&&BigInt(found[1])<=MAX&&BigInt(found[2])<=MAX;
}
function envelope(kind,body){
  const u64=value=>{const bytes=Buffer.alloc(8);bytes.writeBigUInt64BE(BigInt(value));return bytes;},length=Buffer.alloc(4);length.writeUInt32BE(body.length);
  return new Uint8Array(Buffer.concat([Buffer.from('TCDEVNET-ACTION-V1\0'),Buffer.from(NETWORK,'hex'),Buffer.from([kind]),u64(3),u64(7),u64(2),Buffer.from(KEY,'hex'),length,Buffer.from(body),Buffer.alloc(64)]));
}
const sdkTakes=bytes=>{try{sdk.decodeAction(envelope(80,bytes));return true;}catch{return false;}};

test('REVIEW held: decodeAction takes exactly the kind-80 payloads the engine\'s parser takes, over 40000 altered payloads',()=>{
  const spec='5e'.repeat(32),good=`{"activate_elapsed_micros":"1814400000000","spec":"${spec}","version":"5"}`;
  const seeds=[good,'{}',good.replace('1814400000000','18446744073709551615'),good.replace('"5"','"18446744073709551615"'),good.replace('1814400000000','0'),good.replace('"version":"5"','"version":"0"')];
  const pieces=['',' ','\n','\t','\r','0','1','9','+','-','.','e','E','5','a','f','A','F','g','"','\\','\\u0035','\\"','{','}',',',':','null','true','[]','{}','"spec"','"version":"5",','18446744073709551616','18446744073709551615','\u00a0','\ufeff','\u200b','５','é','\0'];
  const pick=random(20261118);let agree=0,taken=0;
  const check=text=>{const bytes=Buffer.from(text,'utf8'),expected=engineTakes(bytes);assert.equal(sdkTakes(bytes),expected,JSON.stringify(text));agree+=1;taken+=Number(expected);};
  for(const text of seeds)check(text);
  for(let round=0;round<40000;round++){
    let text=seeds[pick(seeds.length)];
    for(let edits=1+pick(3);edits>0;edits--){
      const at=pick(text.length+1),kind=pick(4),piece=pieces[pick(pieces.length)];
      text=kind===0?text.slice(0,at)+piece+text.slice(at):kind===1?text.slice(0,at)+text.slice(at+1+pick(3)):kind===2?text.slice(0,at)+piece+text.slice(at+1):text.slice(0,at)+text.slice(at,at+1+pick(20))+text.slice(at);
    }
    check(text);
  }
  // Bytes that are not text at all, a byte-order mark before a valid payload, and a payload cut short.
  for(const bytes of [Buffer.from([0xff,0xfe]),Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),Buffer.from('{}')]),Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),Buffer.from(good)]),Buffer.from(good).subarray(0,good.length-1),Buffer.from(good+'\0'),Buffer.from([0x7b,0x7d,0x00])])assert.equal(sdkTakes(bytes),engineTakes(bytes),bytes.toString('hex'));
  assert.ok(agree>40000&&taken>50,`${agree} payloads compared, ${taken} of them valid`);
});

test('REVIEW held: whatever is handed to buildAction for kind 80, it throws or writes bytes the engine\'s parser takes, and they are what was handed in',()=>{
  const spec='5e'.repeat(32),base={networkId:NETWORK,kind:80,from:'3',nonce:'7',authEpoch:'2',publicKey:KEY};
  const values=['5','0','05','+5',' 5','5 ','5\n','-0','1e3','0x5','5.0','18446744073709551615','18446744073709551616','9007199254740993','',5,-0,0,5n,9007199254740993,1e21,NaN,Infinity,null,undefined,true,['5'],{toString:()=>'5'},new String('5'),Symbol.iterator,spec,spec.toUpperCase(),spec+'\n',' '+spec,spec.slice(1),spec+'0','0x'+spec.slice(2)];
  let built=0,refused=0;
  const attempt=payload=>{
    let bytes;try{bytes=sdk.buildAction({...base,payload});}catch{refused+=1;return;}
    const body=Buffer.from(bytes.slice(19+32+1+24+32+4));
    assert.equal(engineTakes(body),true,body.toString());
    // What was signed is what was handed in, value for value.
    const text=body.toString();if(text!=='{}')assert.equal(text,`{"activate_elapsed_micros":"${payload.activate_elapsed_micros}","spec":"${payload.spec}","version":"${payload.version}"}`);
    else assert.equal(Object.keys(payload).length,0);
    built+=1;
  };
  for(const version of values)for(const start of values)for(const hash of [spec,...values.slice(-8)])attempt({activate_elapsed_micros:start,spec:hash,version});
  // Other shapes: extra, missing and inherited keys, accessors, other prototypes, and JSON text.
  class Plan{constructor(){Object.assign(this,{activate_elapsed_micros:'9',spec,version:'5'});}}
  const inherited=Object.create({activate_elapsed_micros:'9',spec,version:'5'}),hidden=Object.defineProperty({activate_elapsed_micros:'9',spec},'version',{value:'5',enumerable:false});
  let reads=0;const shifting={activate_elapsed_micros:'9',version:'5',get spec(){reads+=1;return reads>2?'7a'.repeat(32):spec;}};
  for(const payload of [new Plan(),inherited,hidden,Object.assign(Object.create(null),{activate_elapsed_micros:'9',spec,version:'5'}),new Map(),new Map([['version','5']]),[],[['version','5']],'{}','',null,undefined,0,()=>({}),{withdraw:true},{version:'5'},{activate_elapsed_micros:'9',spec,version:'5',extra:undefined},JSON.parse('{"__proto__":{"version":"5"}}'),new Proxy({},{ownKeys:()=>[]})])attempt(payload);
  // An accessor that answers differently the third time it is read: the bytes hold a hash that was never checked.
  // (Only whoever builds the object can do this, and they could pass that hash openly: recorded, not a finding.)
  let slipped=null;try{slipped=Buffer.from(sdk.buildAction({...base,payload:shifting}).slice(112)).toString();}catch{slipped=null;}
  assert.ok(slipped===null||engineTakes(Buffer.from(slipped)),'even then the bytes are a valid signal');
  assert.ok(built>=3&&refused>1000,`${built} built, ${refused} refused`);
});

// ------------------------------------------------------------------ the receipt wait and the wallet's own read
function receiptClient({receipt,view,state=()=>({protocol_version:'4',network_id:NETWORK,height:'9',time_micros:'1700000600000000',genesis:{genesis_time_micros:GENESIS},config:{}})}){
  const trust={app_version:'4',network_id:NETWORK,chain_id:'time-devnet-v4-test'},asked=[];
  const verifier={verifyTrust:async()=>({}),verifyLightUpdate:async block=>({verified:true,status:'VERIFIED',checkpoint:{height:block.signed_header.header.height,block_hash:'cd'.repeat(32),block}}),
    verifyViewProof:async()=>({verified:true,completeAccountSet:false,state:await state()}),verifyReceipt:async()=>{throw new Error('no receipt is verified in these tests');}};
  const fetcher=async(url,options={})=>{
    const route=new URL(url).pathname;asked.push(route+new URL(url).search);
    const answer=route==='/api/network'?{body:{protocolVersion:'4',networkId:NETWORK,chainId:trust.chain_id}}:route==='/api/light-block'?{body:{signed_header:{header:{height:new URL(url).searchParams.get('height')||'9'}}}}:route==='/api/receipt'?await receipt(options):route==='/api/view-proof'?await (view?view(options):{body:{light_block:{signed_header:{header:{height:'9'}}}}}):{error:'unexpected'};
    return {ok:!answer.error,status:answer.error?400:200,text:async()=>JSON.stringify(answer.error?{error:answer.error}:answer.body)};
  };
  return {client:sdk.createClient({gateway:'https://rpc.example',trust,verifier,fetcher}),asked};
}
const HASH='AB'.repeat(32),caught=async run=>{try{await run();}catch(error){return error;}assert.fail('nothing was thrown');};
const holding=options=>new Promise((_,reject)=>options.signal?.addEventListener('abort',()=>reject(Object.assign(new Error('aborted'),{name:'AbortError'}))));

test('REVIEW held: the wallet\'s own read after a receipt failure names no transaction to anybody, and a gateway cannot stretch the wait beyond the two limits',async()=>{
  // The read asks for no account, no key and no hash: the same request for every transaction.
  const quiet=receiptClient({receipt:async()=>({error:'no such transaction'})});
  await caught(()=>quiet.client.waitReceipt(HASH,{timeoutMs:3000,ownCheckMs:1000}));
  const views=quiet.asked.filter(route=>route.startsWith('/api/view-proof')).map(route=>decodeURIComponent(route));
  assert.equal(views.length,1);assert.equal(views[0].includes(HASH)||views[0].toUpperCase().includes(HASH),false);
  assert.equal(quiet.asked.filter(route=>!route.startsWith('/api/receipt')).some(route=>route.toUpperCase().includes(HASH)),false,'no other request names the transaction');
  assert.equal((await quiet.client.getVerifiedState({})).height,'9','control: this stand-in gateway serves a state the client verifies');
  assert.deepEqual(JSON.parse(views[0].split('query=')[1]),{names:[],ids:[],public_keys:[],owners:[],candidates:[],epochs:[],blocks:[],include_pos:false,include_bitcoin:false,include_policy:false});
  // Pending for the whole wait, then the own read held: the wait plus the limit of the own read, and "pending".
  const slow=receiptClient({receipt:async()=>({body:{pending:true}}),view:holding});
  const started=performance.now(),error=await caught(()=>slow.client.waitReceipt(HASH,{timeoutMs:1200,ownCheckMs:1000}));
  assert.match(error.message,/^Transaction pending; retain its signed bytes and hash\./);assert.deepEqual([error.hash,error.code,error.gateway],[HASH,undefined,undefined]);
  assert.ok(performance.now()-started<4500,'bounded by timeoutMs + ownCheckMs');
  // A gateway that holds the receipt request itself is treated as pending and asked again, never for longer than the wait.
  const stuck=receiptClient({receipt:holding});
  const begun=performance.now(),late=await caught(()=>stuck.client.waitReceipt(HASH,{timeoutMs:1000,ownCheckMs:1000}));
  assert.match(late.message,/^Transaction pending/);assert.ok(performance.now()-begun<15000);
});

test('REVIEW held: only the client\'s own check of a verified state turns a receipt failure into UPGRADE_REQUIRED; nothing a gateway puts into an answer does',async()=>{
  const words='UPGRADE_REQUIRED: the network runs protocol version 5; this software implements versions 4 to 4. Install a release that implements version 5.';
  // Every part of an answer a gateway controls, with the words and a "code" in it.
  const answers=[{error:words},{error:{code:'UPGRADE_REQUIRED',message:words}},{error:[{code:'UPGRADE_REQUIRED'}]},{body:{code:'UPGRADE_REQUIRED',message:words,error:words}},{body:{pending:false,code:'UPGRADE_REQUIRED',anchor:{light_block:{signed_header:{header:{height:'9'}}}}}},{body:null},{body:'UPGRADE_REQUIRED'},{body:[]},{body:{pending:true,code:'UPGRADE_REQUIRED',message:words}}];
  for(const answer of answers)for(const viewAnswer of [undefined,{error:words},{body:{code:'UPGRADE_REQUIRED',message:words}},{body:{light_block:{signed_header:{header:{height:'9'}}},code:'UPGRADE_REQUIRED'}}]){
    const {client}=receiptClient({receipt:async()=>answer,view:viewAnswer?async()=>viewAnswer:undefined});
    for(const run of [()=>client.waitReceipt(HASH,{timeoutMs:700,ownCheckMs:1000}),()=>client.exportReceiptEvidence(HASH)]){
      const error=await caught(run);
      assert.equal(sdk.isUpgradeRequired(error),false,JSON.stringify([answer,viewAnswer,error.message]));assert.equal(error.code,undefined,JSON.stringify([answer,viewAnswer]));
    }
  }
  // The one way: the state this client verified names a version it does not implement.
  const moved=receiptClient({receipt:async()=>({error:'no such transaction'}),state:()=>({protocol_version:'5',network_id:NETWORK,height:'9',time_micros:'1700000600000000',genesis:{genesis_time_micros:GENESIS},config:{}})});
  const found=await caught(()=>moved.client.waitReceipt(HASH,{timeoutMs:700,ownCheckMs:1000}));
  assert.deepEqual([sdk.isUpgradeRequired(found),found.hash,found.gateway],[true,HASH,undefined]);
  // And a later read of the same client throws a finding of its own, without the hash of that transaction.
  const later=await caught(()=>moved.client.getVerifiedState({}));
  assert.deepEqual([sdk.isUpgradeRequired(later),later.hash],[true,undefined]);
});
