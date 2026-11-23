// A validator's upgrade signal (action kind 80) as the SDK builds, signs and reads it, and the
// proven status a caller acts on before it sends one (docs/design/upgrade-mechanism.md, sections
// 3.1, 5.1 and 5.2; the rules are v5/src/upgrade.rs and spec/protocol-4.md, section 6).
//
// - The bytes are compared with signed actions the engine itself wrote and accepted:
//   v5/tests/fixtures/upgrade-state.fixture.json holds one that supports a plan and one that
//   withdraws, each with the seed of the test key that signed it.
// - The rows of `upgrade/state` in the first status test are the engine's too, verified through
//   the installed verifier (verifier-v4/fixtures/upgrade-engine.json). That fixture was asked for
//   the upgrade row only and holds no staking rows: the validator sets used with it are written
//   here by hand (four equal validators, as that chain had). Every other state in this file is
//   written by hand in the form the verifier returns.
import test from 'node:test';import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';import {existsSync,readFileSync} from 'node:fs';import {readFile} from 'node:fs/promises';
import './time-sdk.js';
import * as installed from './proof-verifier.mjs';

const sdk=globalThis.TimeSDK;
const engine=JSON.parse(await readFile(new URL('../v5/tests/fixtures/upgrade-state.fixture.json',import.meta.url),'utf8'));
const wrapped=JSON.parse(await readFile(new URL('../verifier-v4/fixtures/upgrade-engine.json',import.meta.url),'utf8'));
const SPEC='5e'.repeat(32),OTHER='7a'.repeat(32),NETWORK='ab'.repeat(32),KEY='11'.repeat(32);
const DAY=86400000000n,GENESIS='1700000000000000';
// An Ed25519 signing key from its 32-byte seed.
const keyOf=seedHex=>crypto.subtle.importKey('pkcs8',sdk.concat(sdk.hexToBytes('302e020100300506032b657004220420'),sdk.hexToBytes(seedHex,32)),{name:'Ed25519'},false,['sign']);
// An action envelope around any payload text, as a node would receive it.
function envelope(kind,text,{from='3',nonce='7',authEpoch='2'}={}){
  const u64=value=>{const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(value));return b;},body=Buffer.from(text),length=Buffer.alloc(4);length.writeUInt32BE(body.length);
  return new Uint8Array(Buffer.concat([Buffer.from('TCDEVNET-ACTION-V1\0'),Buffer.from(NETWORK,'hex'),Buffer.from([kind]),u64(from),u64(nonce),u64(authEpoch),Buffer.from(KEY,'hex'),length,body,Buffer.alloc(64)]));
}

// ---- the bytes

test('the SDK signs the two signals the engine accepted, byte for byte',async()=>{
  assert.equal(sdk.KINDS.upgrade_signal,80);assert.equal(engine.actions.kind,80);
  for(const [name,payload] of [['support',{activate_elapsed_micros:engine.plan.activate_elapsed_micros,spec:engine.plan.spec,version:engine.plan.version}],['withdraw',{}]]){
    const vector=engine.actions[name],bytes=sdk.hexToBytes(vector.action_hex);
    // Read back: the fields of the envelope and the payload.
    const action=sdk.decodeAction(bytes);
    assert.deepEqual([action.kind,action.from,action.networkId,action.payload],[80,vector.from,engine.network_id,payload],name);
    assert.equal(bytes[51],80,'the kind is the byte at offset 51');
    assert.equal(new TextDecoder().decode(sdk.canonicalPayload(80,payload)),vector.payload_utf8,name);
    // Built and signed again with the same key: Ed25519 signatures are deterministic, so every byte is the engine's.
    const fields={networkId:engine.network_id,kind:'upgrade_signal',from:action.from,nonce:action.nonce,authEpoch:action.authEpoch,publicKey:action.publicKey,payload};
    assert.equal(sdk.bytesToHex(await sdk.signAction(fields,await keyOf(vector.signer_seed_hex))),vector.action_hex,name);
    assert.equal(sdk.bytesToHex(sdk.buildAction({...fields,kind:80})),vector.action_hex.slice(0,-128),name);
  }
  // The helpers give the same two payloads.
  assert.deepEqual(sdk.signalSupport({version:'5',spec:engine.plan.spec,activateElapsedMicros:'421000000'}),sdk.decodeAction(sdk.hexToBytes(engine.actions.support.action_hex)).payload);
  assert.deepEqual(sdk.signalWithdrawal(),{});
  assert.equal(new TextDecoder().decode(sdk.canonicalPayload(80,sdk.signalSupport({version:'5',spec:SPEC,activateElapsedMicros:'1814400000000'}))),`{"activate_elapsed_micros":"1814400000000","spec":"${SPEC}","version":"5"}`);
});

test('anything but the two forms is refused before it is signed',async()=>{
  const good={activate_elapsed_micros:'9',spec:SPEC,version:'5'},base={networkId:NETWORK,kind:80,from:'3',nonce:'7',authEpoch:'2',publicKey:KEY};
  const key=(await crypto.subtle.generateKey('Ed25519',true,['sign','verify'])).privateKey;
  class Plan{constructor(){Object.assign(this,good);}}
  const bad=[
    {...good,extra:'1'},{activate_elapsed_micros:'9',spec:SPEC},{spec:SPEC,version:'5'},{version:'5'},{withdraw:true},{'':''},
    {...good,version:5},{...good,version:'05'},{...good,version:'5 '},{...good,version:'+5'},{...good,version:'5.0'},{...good,version:''},{...good,version:'18446744073709551616'},{...good,version:null},{...good,version:['5']},
    {...good,activate_elapsed_micros:9},{...good,activate_elapsed_micros:'09'},{...good,activate_elapsed_micros:'-9'},{...good,activate_elapsed_micros:'1e3'},{...good,activate_elapsed_micros:'18446744073709551616'},
    {...good,spec:SPEC.toUpperCase()},{...good,spec:SPEC.slice(2)},{...good,spec:SPEC+'5e'},{...good,spec:'0x'+SPEC.slice(2)},{...good,spec:' '+SPEC.slice(1)},{...good,spec:'zz'.repeat(32)},{...good,spec:null},{...good,spec:sdk.hexToBytes(SPEC)},
    null,undefined,'{}','',[],[good],0,true,new Plan(),Object.create(good),Object.assign(Object.create(null),good),new Map(Object.entries(good)),
  ];
  for(const payload of bad){
    const label=JSON.stringify(payload)??String(payload);
    assert.throws(()=>sdk.canonicalPayload(80,payload),label);assert.throws(()=>sdk.buildAction({...base,payload}),label);
    await assert.rejects(sdk.signAction({...base,payload},key),label);
  }
  for(const plan of [{version:'5',spec:SPEC},{version:5,spec:SPEC,activateElapsedMicros:'9'},{version:'5',spec:SPEC.toUpperCase(),activateElapsedMicros:'9'},{version:'5',spec:SPEC,activateElapsedMicros:'09'},{}])assert.throws(()=>sdk.signalSupport(plan),JSON.stringify(plan));
  // The largest values the form allows are taken: whether a plan may be signalled is a rule, judged elsewhere.
  assert.equal(new TextDecoder().decode(sdk.canonicalPayload(80,{activate_elapsed_micros:'18446744073709551615',spec:'0'.repeat(64),version:'0'})),`{"activate_elapsed_micros":"18446744073709551615","spec":"${'0'.repeat(64)}","version":"0"}`);
  // Read back, the same: an envelope whose payload is not one of the two byte strings is not a signal.
  const plan=`{"activate_elapsed_micros":"9","spec":"${SPEC}","version":"5"}`;
  assert.deepEqual(sdk.decodeAction(envelope(80,plan)).payload,good);assert.deepEqual(sdk.decodeAction(envelope(80,'{}')).payload,{});
  for(const text of ['{ }','{} ',' {}','{}\n','null','[]','""','0',`{"spec":"${SPEC}","activate_elapsed_micros":"9","version":"5"}`,plan.replace('":"9"','": "9"'),plan+' ',plan.replace('"version":"5"','"version":"5","version":"5"'),plan.replace('"version":"5"','"version":"\\u0035"'),
    plan.replace('"version":"5"','"version":5'),plan.replace('"version":"5"','"version":"05"'),plan.replace(SPEC,SPEC.toUpperCase()),plan.replace('}',',"more":"1"}'),plan.replace('{','{"__proto__":{},'),'{"__proto__":{}}','{"constructor":{}}'])
    assert.throws(()=>sdk.decodeAction(envelope(80,text)),text);
  // Kind 81 is reserved for an emergency release: the SDK neither builds nor reads it.
  assert.throws(()=>sdk.buildAction({...base,kind:81,payload:{spec:SPEC,version:'5'}}),/Unknown action/);
  assert.throws(()=>sdk.decodeAction(envelope(81,`{"spec":"${SPEC}","version":"5"}`)),/Unknown action/);
  assert.equal(Object.values(sdk.KINDS).includes(81),false);
});

test('the numbers are the engine\'s and the specification\'s',t=>{
  const micros=seconds=>(BigInt(seconds)*1000000n).toString();
  assert.deepEqual(sdk.SIGNAL_RULES,{production:{noticeMicros:micros(21*86400),farthestMicros:micros(120*86400),intervalMicros:micros(600),lateMicros:micros(3600)},laboratory:{noticeMicros:micros(120),farthestMicros:micros(3600),intervalMicros:micros(1),lateMicros:micros(60)}});
  assert.ok(Object.isFrozen(sdk.SIGNAL_RULES)&&Object.isFrozen(sdk.SIGNAL_RULES.production)&&Object.isFrozen(sdk.SIGNAL_SHARES.schedule));
  assert.deepEqual([sdk.SIGNAL_SHARES.schedule,sdk.SIGNAL_SHARES.keep,sdk.SIGNAL_ADMISSION_MARGIN_MICROS],[['4','5'],['3','4'],micros(30)]);
  // The table of the specification, whose hash names version 4.
  const spec=readFileSync(new URL('../spec/protocol-4.md',import.meta.url),'utf8');
  for(const row of ['| Support needed to schedule | at least 4/5 | same |','| Support needed to stay scheduled | at least 3/4 | same |','| Notice | 21 days | 120 seconds |','| Farthest start | 120 days | 1 hour |','| Interval between two changes of one candidate | 10 minutes | 1 second |','| Longest a plan may wait after its start time | 1 hour | 60 seconds |'])assert.ok(spec.includes(row),row);
  assert.ok(spec.includes('- `{"activate_elapsed_micros":"D","spec":"H","version":"D"}`: support this plan.')&&spec.includes('- `{}`: withdraw.'));
  // The engine's own source, where this copy of the repository holds it.
  const file=name=>{const location=new URL('../v5/src/'+name,import.meta.url);return existsSync(location)?readFileSync(location,'utf8'):null;};
  const upgrade=file('upgrade.rs'),engineSource=file('engine.rs');
  if(!upgrade||!engineSource)return t.skip('this copy of the repository holds no engine source');
  const flat=text=>text?.replace(/\s+/g,' ');
  const production=flat(/pos::Profile::Production => Self \{([^}]*)\}/.exec(upgrade)?.[1]),laboratory=flat(/pos::Profile::Laboratory => Self \{([^}]*)\}/.exec(upgrade)?.[1]);
  for(const part of ['notice: 21 * pos::DAY,','farthest: 120 * pos::DAY,','interval: 600 * pos::SECOND,','late: 3600 * pos::SECOND,'])assert.ok(production.includes(part),part);
  for(const part of ['notice: 120 * pos::SECOND,','farthest: 3600 * pos::SECOND,','interval: pos::SECOND,','late: 60 * pos::SECOND,'])assert.ok(laboratory.includes(part),part);
  for(const line of ['pub const SIGNAL: u8 = 80;','pub const SCHEDULE: (u128, u128) = (4, 5);','pub const KEEP: (u128, u128) = (3, 4);','pub const MAX_ENTRIES: usize = pos::MAX_CANDIDATES;'])assert.ok(upgrade.includes(line),line);
  assert.ok(engineSource.includes('pub const ADMISSION_MARGIN_MICROS: u64 = 30 * ledger::MICROS_PER_SECOND;'));
  assert.ok(readFileSync(new URL('../pos/src/lib.rs',import.meta.url),'utf8').includes('pub const MAX_CANDIDATES: usize = 256;'));
});

// ---- the status

const validator=(owner,power='1000')=>({owner:String(owner),consensus_key:KEY,power:String(power)});
const equal=(count,power='1000')=>Array.from({length:count},(_,owner)=>validator(owner,power));
const supports=(owner,plan,changed='0')=>({activate_elapsed_micros:plan.activate_elapsed_micros,changed_elapsed_micros:String(changed),owner:String(owner),spec:plan.spec,version:plan.version});
const withdrawn=(owner,changed='0')=>({changed_elapsed_micros:String(changed),owner:String(owner)});
const account=(id,more={})=>({id:String(id),name:'owner_'+id,public_key:KEY,balance:'5000000',nonce:'3',auth_epoch:'0',devices:[{public_key:KEY,can_manage:true,can_spend:true}],...more});
const candidate=(owner,more={})=>({owner:String(owner),consensus_key:KEY,jailed:false,archived:false,self_bond:'86400000000',...more});
const securedDevices=[{public_key:'21'.repeat(32),can_manage:false,can_spend:false},{public_key:'22'.repeat(32),can_manage:false,can_spend:true},{public_key:'23'.repeat(32),can_manage:true,can_spend:false},{public_key:'24'.repeat(32),can_manage:true,can_spend:false}];
const securityRow=(id,more={})=>({account:String(id),version:'1',policy:{threshold:'2',daily_limit_micros:'60000000',delay_seconds:'172800',freeze_seconds:'172800'},allowance_micros:'60000000',allowance_elapsed_micros:'0',frozen_until_elapsed_micros:'0',freezes:'0',pending_limit:null,pending_payments:[],next_id:'1',pending_root:null,...more});
const NOW=100n*DAY,PLAN={version:'5',spec:SPEC,activate_elapsed_micros:(NOW+30n*DAY).toString()};
// A verified state in the form the verifier returns it.
function chain({now=NOW,version='4',height='500',active=equal(5),scheduled=[],hold=false,profile='production',signals,plan,accounts=[account(0)],candidates={0:candidate(0)},security=[],recovery=[],upgrade}={}){
  const row=upgrade!==undefined?upgrade:signals||plan?{...(plan?{plan}:{}),signals:signals||[]}:null;
  return {protocol_version:version,network_id:NETWORK,height,time_micros:(BigInt(GENESIS)+now).toString(),genesis:{genesis_time_micros:GENESIS},config:{},accounts,recovery_cases:recovery,security,candidates,upgrade:row,
    pos:{profile,candidate_ids:active.map(item=>item.owner),active,scheduled:scheduled.map((validators,index)=>({announced_height:String(Number(height)-1+index),effective_height:String(Number(height)+1+index),validators})),safety_hold:hold}};
}
const status=(options,ask={account:'0'})=>sdk.signalStatusOf(chain(options),ask);
const planOf=(result,plan=PLAN)=>result.plans.find(item=>sdk.samePlan(item,plan));

test('the status is read from the rows the engine wrote: signals without a plan, then the scheduled plan',async()=>{
  // The engine's chain: four validators of equal power, owners 0 to 3 (v5/tests/upgrade_node.rs).
  const read=async name=>{
    const item=wrapped.cases[name],checked=await installed.verifyViewProof(item.proof,item.trust,item.request,item.now_ms);
    return {...checked.state,config:checked.state.config??{},accounts:[account(2)],candidates:{2:candidate(2)},recovery_cases:[],security:[],pos:{profile:'laboratory',candidate_ids:['0','1','2','3'],active:equal(4),scheduled:[],safety_hold:false}};
  };
  // Two validators support the plan, a third has withdrawn.
  const entries=sdk.signalStatusOf(await read('entries_only'),{account:'2'}),plan=engine.plan;
  assert.deepEqual([entries.version,entries.nextVersion,entries.scheduled,entries.profile,entries.entries],['4','5',null,'laboratory',3]);
  assert.deepEqual(entries.rules,{...sdk.SIGNAL_RULES.laboratory,admissionMarginMicros:'30000000'});
  assert.deepEqual(entries.validators.map(item=>[item.owner,item.power,item.signal?.withdrawn===true?'withdrawn':item.signal?.spec??null]),[['0','1000',plan.spec],['1','1000',plan.spec],['2','1000','withdrawn'],['3','1000',null]]);
  assert.equal(entries.plans.length,1);
  assert.deepEqual([entries.plans[0].version,entries.plans[0].spec,entries.plans[0].activate_elapsed_micros,entries.plans[0].scheduled,entries.plans[0].supporters],[plan.version,plan.spec,plan.activate_elapsed_micros,false,['0','1']]);
  assert.deepEqual(entries.plans[0].tally,{rosters:[{support:'2000',total:'4000'}],lowest:{support:'2000',total:'4000'},schedule:null,keep:null,exact:false});
  // The account that withdrew: its entry, and when it may signal again (one second in this profile).
  assert.deepEqual(entries.account.entry,{withdrawn:true,changed_elapsed_micros:'123000000'});
  assert.deepEqual([entries.account.ownsValidator,entries.account.supports,entries.account.mayChangeFromElapsedMicros,entries.account.mayChangeNow,entries.nowElapsedMicros],[true,null,'124000000',false,'123000000']);
  // Two blocks later all four support it and the engine has scheduled it.
  const scheduled=sdk.signalStatusOf(await read('scheduled'),{account:'2'});
  assert.deepEqual(scheduled.scheduled,engine.cases.find(item=>item.name==='scheduled').upgrade_state.plan);
  // The state holds the account that was asked for only: the tally is not exact and states neither threshold.
  assert.deepEqual([scheduled.plans.length,scheduled.plans[0].scheduled,scheduled.plans[0].supporters,scheduled.plans[0].tally.lowest,scheduled.plans[0].tally.exact,scheduled.plans[0].tally.schedule,scheduled.plans[0].tally.keep],[1,true,['0','1','2','3'],{support:'4000',total:'4000'},false,null,null]);
  assert.deepEqual(scheduled.account.supports,{version:plan.version,spec:plan.spec,activate_elapsed_micros:plan.activate_elapsed_micros});
  // Nobody has signalled: no plan, no entry, and the account may signal.
  const absent=sdk.signalStatusOf(await read('absent'),{account:'2'});
  assert.deepEqual([absent.plans,absent.entries,absent.account.entry,absent.account.mayChangeNow],[[],0,null,true]);
  // After the activation this build does not read the state at all.
  await assert.rejects(read('activated'),error=>error.code==='UPGRADE_REQUIRED');
});

test('the tally is the engine\'s: four fifths to schedule, three quarters to keep, the lowest of the validator sets',()=>{
  const all=(owners,more={})=>status({signals:owners.map(owner=>supports(owner,PLAN)),accounts:equal(5).map(item=>account(item.owner)),...more},{account:'0',facts:undefined});
  // Every owner account is in the state (protocol-4 accounts, never frozen): the tally is exact.
  const full=owners=>{const state=chain({signals:owners.map(owner=>supports(owner,PLAN)),accounts:equal(5).map(item=>account(item.owner))});return planOf(sdk.signalStatusOf(state,{account:'0',facts:sdk.signalFactsOf(state,['0','1','2','3','4'])})).tally;};
  assert.deepEqual(full([0,1,2,3]),{rosters:[{support:'4000',total:'5000'}],lowest:{support:'4000',total:'5000'},schedule:true,keep:true,exact:true});
  assert.deepEqual(full([0,1,2]),{rosters:[{support:'3000',total:'5000'}],lowest:{support:'3000',total:'5000'},schedule:false,keep:false,exact:true});
  assert.equal(all([0,1,2,3]).plans[0].tally.schedule,true);
  // Exactly at the two boundaries, and one unit of power under each.
  const powers=(list,owners)=>planOf(status({active:list.map((power,owner)=>validator(owner,power)),signals:owners.map(owner=>supports(owner,PLAN))})).tally;
  assert.deepEqual([powers([4,1],[0]).schedule,powers([3999,1001],[0]).schedule,powers([3999,1001],[0]).keep],[true,false,true]);
  assert.deepEqual([powers([3,1],[0]).keep,powers([2999,1001],[0]).keep,powers([2999,1001],[0]).schedule],[true,false,false]);
  // Powers near the largest a 64-bit number holds are compared without rounding.
  const huge=18446744073709551615n;
  assert.deepEqual([powers([huge,huge/4n],[0]).schedule,powers([huge-4n,huge/4n+1n],[0]).schedule],[true,false]);
  // The set in force and each announced set: the lowest share counts.
  const sets=status({signals:[0,1,2,3].map(owner=>supports(owner,PLAN)),scheduled:[[...equal(5),validator(5,2000)],[...equal(4),validator(5,1000)]]});
  assert.deepEqual(planOf(sets).tally,{rosters:[{support:'4000',total:'5000'},{support:'4000',total:'7000'},{support:'4000',total:'5000'}],lowest:{support:'4000',total:'7000'},schedule:null,keep:null,exact:false});
  assert.deepEqual(sets.rosters,[{effectiveHeight:null,validators:5,total:'5000'},{effectiveHeight:'501',validators:6,total:'7000'},{effectiveHeight:'502',validators:5,total:'5000'}]);
  // A validator that is only in an announced set is listed, with no power in the set in force.
  assert.deepEqual(sets.validators.find(item=>item.owner==='5'),{owner:'5',power:'0',inForce:false,signal:null,jailed:false,counts:null,stopped:null});
  // Two plans: each has its own supporters; the scheduled one stands first.
  const second={version:'5',spec:OTHER,activate_elapsed_micros:PLAN.activate_elapsed_micros};
  const two=status({accounts:equal(5).map(item=>account(item.owner)),plan:{...second,scheduled_elapsed_micros:'5'},signals:[supports(0,PLAN),supports(1,second),supports(2,second),supports(3,second),supports(4,second)]});
  assert.deepEqual(two.plans.map(item=>[item.spec,item.scheduled,item.supporters,item.tally.keep]),[[OTHER,true,['1','2','3','4'],true],[SPEC,false,['0'],false]]);
  // The same version and hash at another start time is another plan.
  const later={...PLAN,activate_elapsed_micros:(BigInt(PLAN.activate_elapsed_micros)+1n).toString()};
  assert.deepEqual(status({signals:[supports(0,PLAN),supports(1,later)]}).plans.map(item=>item.supporters),[['0'],['1']]);
  // A signal of an account that is not a validator of any set is not counted and names no plan here.
  assert.deepEqual(status({signals:[supports(77,second)]}).plans,[]);
});

test('a jailed validator is in neither sum; a frozen or recovering owner is in the total only; what is not proven is said',()=>{
  const signals=[0,1,2,3].map(owner=>supports(owner,PLAN));
  const judged=(more,ids=['0','1','2','3','4'])=>{const state=chain({signals,accounts:equal(5).map(item=>account(item.owner)),...more});return sdk.signalStatusOf(state,{account:'0',facts:sdk.signalFactsOf(state,ids)});};
  // The design's example: five equal validators, four supporters, one supporter jailed: three of the four that remain.
  const rows=Object.fromEntries(equal(5).map(item=>[item.owner,candidate(item.owner,{jailed:item.owner==='3'})]));
  const jailed=judged({hold:true,candidates:rows});
  assert.deepEqual(planOf(jailed).tally,{rosters:[{support:'3000',total:'4000'}],lowest:{support:'3000',total:'4000'},schedule:false,keep:true,exact:true});
  assert.deepEqual(jailed.validators.find(item=>item.owner==='3').jailed,true);assert.equal(jailed.hold,true);
  // During a hold, without the candidate rows, it is not known who is jailed: counted, and said.
  const unread=judged({hold:true});
  assert.deepEqual([planOf(unread).tally.lowest,planOf(unread).tally.exact,unread.validators.find(item=>item.owner==='3').jailed],[{support:'4000',total:'5000'},false,null]);
  // An inexact tally states neither threshold: the unread jailed validator may be a supporter (the engine's share
  // is then 3000 of 4000, below four fifths) or not (4000 of 4000). `schedule` and `keep` are null, not true or false.
  assert.deepEqual([planOf(unread).tally.schedule,planOf(unread).tally.keep],[null,null]);
  // One unread row is enough, also when it is the row of a validator that does not support the plan: here every
  // row but that of validator 4 was read, and validator 4 has not signalled. Jailed, it would leave the total.
  const rest=judged({hold:true,candidates:Object.fromEntries(['0','1','2','3'].map(owner=>[owner,candidate(owner)]))});
  assert.deepEqual([rest.validators.find(item=>item.owner==='4').jailed,planOf(rest).tally],[null,{rosters:[{support:'4000',total:'5000'}],lowest:{support:'4000',total:'5000'},schedule:null,keep:null,exact:false}]);
  // Without a hold no validator of these sets is jailed.
  assert.deepEqual([planOf(judged({})).tally.exact,judged({}).validators.every(item=>item.jailed===false)],[true,true]);
  // A secured owner whose account is frozen: its validator stays in the total, its signal does not count.
  const secured=id=>account(id,{devices:securedDevices});
  const frozen=judged({accounts:[account(0),secured(1),account(2),account(3),account(4)],security:[securityRow(1,{frozen_until_elapsed_micros:(NOW+1n).toString()})]});
  assert.deepEqual(planOf(frozen).tally,{rosters:[{support:'3000',total:'5000'}],lowest:{support:'3000',total:'5000'},schedule:false,keep:false,exact:true});
  assert.deepEqual([frozen.validators[1].counts,frozen.validators[1].stopped,frozen.validators[0].counts],[false,'frozen',true]);
  // The freeze has ended by time alone: it counts again. A replacement of the keys that waits freezes too.
  assert.equal(planOf(judged({accounts:[account(0),secured(1),account(2),account(3),account(4)],security:[securityRow(1,{frozen_until_elapsed_micros:NOW.toString()})]})).tally.schedule,true);
  const waiting=root=>planOf(judged({accounts:[account(0),secured(1),account(2),account(3),account(4)],security:[securityRow(1,{pending_root:root})]})).tally.lowest.support;
  assert.deepEqual([waiting({devices:[],policy:{},ready_elapsed_micros:'1',expires_elapsed_micros:NOW.toString()}),waiting({devices:[],policy:{},ready_elapsed_micros:'1',expires_elapsed_micros:(NOW-1n).toString()})],['3000','4000']);
  // A guardian recovery of a protocol-4 owner that has its approvals.
  const recovering=judged({recovery:[{target:'2',ready_elapsed_micros:'5',expires_elapsed_micros:(NOW+DAY).toString()},{target:'3',ready_elapsed_micros:null,expires_elapsed_micros:(NOW+DAY).toString()}]});
  assert.deepEqual([planOf(recovering).tally.lowest,recovering.validators[2].stopped,recovering.validators[3].stopped],[{support:'3000',total:'5000'},'recovery',null]);
  // An owner whose candidate is archived, or gone.
  assert.equal(planOf(judged({candidates:{0:candidate(0),1:candidate(1,{archived:true})}})).tally.lowest.support,'3000');
  assert.equal(planOf(judged({candidates:{0:candidate(0),1:null}})).tally.lowest.support,'3000');
  // A secured owner whose security row was not asked for: its absence proves nothing. Counted, and said.
  const unproven=judged({accounts:[account(0),secured(1),account(2),account(3),account(4)],security:[]},['0']);
  assert.deepEqual([planOf(unproven).tally.lowest.support,planOf(unproven).tally.exact,unproven.validators[1].counts],['4000',false,null]);
  // An owner whose account is not in the state at all.
  const absent=status({signals});
  assert.deepEqual([planOf(absent).tally.exact,absent.validators.map(item=>item.counts)],[false,[true,null,null,null,null]]);
});

test('the account: whether it owns a validator, what it supports, when it may change, and why its signal does not count',()=>{
  const interval=600000000n,changed=NOW-interval+1n;
  const own=options=>status(options).account;
  assert.deepEqual(own({}),{id:'0',name:'owner_0',ownsValidator:true,candidate:'live',jailed:false,inRoster:true,power:'1000',entry:null,supports:null,mayChangeFromElapsedMicros:null,mayChangeNow:true,stopped:null,frozenUntilElapsedMicros:null,secured:false,signers:[KEY],balance:'5000000',nonce:'3',authEpoch:'0'});
  // No candidate, an archived one, a jailed one, a candidate outside every validator set.
  assert.deepEqual([own({candidates:{0:null}}).ownsValidator,own({candidates:{0:null}}).candidate,own({candidates:{0:candidate(0,{archived:true})}}).ownsValidator,own({candidates:{0:candidate(0,{jailed:true})}}).jailed],[false,'none',false,true]);
  assert.deepEqual([own({active:[validator(1),validator(2)]}).inRoster,own({active:[validator(1),validator(2)]}).power,own({active:[validator(1),validator(2)]}).ownsValidator],[false,'0',true]);
  // One change per interval: ten minutes in production.
  const early=own({signals:[supports(0,PLAN,changed)]});
  assert.deepEqual([early.supports,early.mayChangeFromElapsedMicros,early.mayChangeNow],[PLAN,(NOW+1n).toString(),false]);
  assert.equal(own({signals:[supports(0,PLAN,changed-1n)]}).mayChangeNow,true);
  assert.deepEqual(own({signals:[withdrawn(0,changed)]}).entry,{withdrawn:true,changed_elapsed_micros:changed.toString()});
  assert.equal(own({signals:[withdrawn(0,changed)]}).mayChangeNow,false);
  // A full table takes no new entry.
  const crowd=Array.from({length:256},(_,index)=>withdrawn(index+10,NOW));
  assert.deepEqual([own({signals:crowd}).mayChangeNow,own({signals:crowd.slice(1)}).mayChangeNow],[false,true]);
  // A secured account: its spend keys sign; frozen until a time, or while a replacement waits.
  const secured={accounts:[account(0,{devices:securedDevices})]};
  assert.deepEqual([own({...secured,security:[securityRow(0)]}).secured,own({...secured,security:[securityRow(0)]}).signers,own({...secured,security:[securityRow(0)]}).stopped],[true,['22'.repeat(32)],null]);
  const frozen=own({...secured,security:[securityRow(0,{frozen_until_elapsed_micros:(NOW+DAY).toString()})]});
  assert.deepEqual([frozen.stopped,frozen.frozenUntilElapsedMicros],['frozen',(NOW+DAY).toString()]);
  assert.equal(own({recovery:[{target:'0',ready_elapsed_micros:'9',expires_elapsed_micros:(NOW+DAY).toString()}]}).stopped,'recovery');
  // What the state must prove, or there is no status.
  assert.throws(()=>status({accounts:[]}),/does not prove this account/);
  assert.throws(()=>status({candidates:{}}),/does not prove this account/);
  assert.throws(()=>sdk.signalStatusOf({...chain(secured),security:undefined},{account:'0'}),/whether this account is frozen/);
  assert.throws(()=>sdk.signalStatusOf({...chain(),pos:undefined},{account:'0'}),/include_pos/);
  const {upgrade:_,...unasked}=chain();assert.throws(()=>sdk.signalStatusOf(unasked,{account:'0'}),/verified without the upgrade entry/);
  assert.throws(()=>status({version:'5'}),error=>error.code==='UPGRADE_REQUIRED');
  for(const signals of [[supports(1,PLAN),supports(0,PLAN)],[supports(0,PLAN),supports(0,PLAN)],[{...supports(0,PLAN),version:'6'}],[{...supports(0,PLAN),spec:SPEC.toUpperCase()}],[{owner:'0'}],[{...withdrawn(0),more:'1'}],[null]])assert.throws(()=>status({signals}),undefined,JSON.stringify(signals));
  // Without an account it is the public part only.
  assert.equal(sdk.signalStatusOf(chain()).account,null);
});

test('a signal is judged as the engine judges it, before anything is signed',()=>{
  const notice=21n*DAY,margin=30000000n,farthest=120n*DAY;
  const judge=(options,intent)=>sdk.judgeSignal(status(options),intent);
  const plan=(start,more={})=>({version:'5',spec:SPEC,activateElapsedMicros:start.toString(),...more});
  // A new plan: from the notice and the admission margin to the farthest start, as of the proven block.
  const ok=judge({},plan(NOW+30n*DAY));
  assert.deepEqual(ok,{ok:true,kind:'support',payload:{activate_elapsed_micros:(NOW+30n*DAY).toString(),spec:SPEC,version:'5'},plan:{version:'5',spec:SPEC,activate_elapsed_micros:(NOW+30n*DAY).toString()},joins:false,tight:false});
  const window={earliestElapsedMicros:(NOW+notice+margin).toString(),latestElapsedMicros:(NOW+farthest).toString()};
  assert.deepEqual(judge({},plan(NOW+notice+margin-1n)),{ok:false,refusal:'start_too_soon',...window});
  assert.deepEqual([judge({},plan(NOW+notice+margin)).ok,judge({},plan(NOW+notice+margin)).tight,judge({},plan(NOW+notice+margin+600000000n)).tight],[true,true,false]);
  assert.deepEqual(judge({},plan(NOW+farthest+1n)),{ok:false,refusal:'start_too_far',...window});
  assert.equal(judge({},plan(NOW+farthest)).ok,true);
  assert.equal(judge({},plan(0n)).refusal,'start_too_soon');
  // The scheduled plan may be joined however near its start is; any other plan near it may not.
  const near={version:'5',spec:SPEC,activate_elapsed_micros:(NOW+DAY).toString()},scheduled={plan:{...near,scheduled_elapsed_micros:'1'},signals:[1,2,3,4].map(owner=>supports(owner,near))};
  assert.deepEqual([judge(scheduled,plan(NOW+DAY)).ok,judge(scheduled,plan(NOW+DAY)).joins,judge(scheduled,plan(NOW+DAY,{spec:OTHER})).refusal,judge(scheduled,plan(NOW+DAY+1n)).refusal],[true,true,'start_too_soon','start_too_soon']);
  // The version after the one in force, and no other.
  for(const version of ['4','6','0','18446744073709551615'])assert.deepEqual(judge({},plan(NOW+30n*DAY,{version})),{ok:false,refusal:'version',current:'4',next:'5'});
  // It must change something.
  assert.equal(judge({signals:[supports(0,PLAN,0)]},plan(BigInt(PLAN.activate_elapsed_micros))).refusal,'no_change');
  assert.equal(judge({signals:[supports(0,PLAN,0)]},plan(BigInt(PLAN.activate_elapsed_micros),{spec:OTHER})).ok,true);
  assert.equal(judge({},{withdraw:true}).refusal,'no_change');assert.equal(judge({signals:[withdrawn(0,0)]},{withdraw:true}).refusal,'no_change');
  assert.deepEqual(judge({signals:[supports(0,PLAN,0)]},{withdraw:true}),{ok:true,kind:'withdraw',payload:{},plan:null,joins:false,tight:false});
  // At most one change per interval.
  const recent=NOW-600000000n+1n;
  assert.deepEqual(judge({signals:[supports(0,PLAN,recent)]},{withdraw:true}),{ok:false,refusal:'interval',fromElapsedMicros:(NOW+1n).toString()});
  assert.deepEqual(judge({signals:[withdrawn(0,recent)]},plan(NOW+30n*DAY)),{ok:false,refusal:'interval',fromElapsedMicros:(NOW+1n).toString()});
  assert.equal(judge({signals:Array.from({length:256},(_,index)=>withdrawn(index+10,NOW))},plan(NOW+30n*DAY)).refusal,'table_full');
  // Who may signal at all, and what stops an account.
  assert.equal(judge({candidates:{0:null}},plan(NOW+30n*DAY)).refusal,'not_owner');
  assert.equal(judge({candidates:{0:candidate(0,{archived:true})}},{withdraw:true}).refusal,'not_owner');
  assert.equal(judge({candidates:{0:candidate(0,{jailed:true})}},plan(NOW+30n*DAY)).ok,true,'a jailed candidate may signal; it is left out of the count');
  assert.equal(judge({active:[validator(1),validator(2)]},plan(NOW+30n*DAY)).ok,true,'a candidate need not be in the validator set');
  assert.equal(judge({hold:true},plan(NOW+30n*DAY)).ok,true,'signals pass a validator safety hold');
  assert.equal(judge({recovery:[{target:'0',ready_elapsed_micros:'9',expires_elapsed_micros:(NOW+DAY).toString()}]},plan(NOW+30n*DAY)).refusal,'recovery');
  const secured={accounts:[account(0,{devices:securedDevices})]};
  assert.equal(judge({...secured,security:[securityRow(0,{frozen_until_elapsed_micros:(NOW+DAY).toString()})],signals:[supports(0,PLAN,0)]},{withdraw:true}).refusal,'frozen');
  assert.equal(judge({accounts:[account(0,{balance:'999'})]},plan(NOW+30n*DAY)).refusal,'fee');
  assert.equal(judge({accounts:[account(0,{balance:'1000'})]},plan(NOW+30n*DAY)).ok,true);
  // Malformed values are not judged: they are refused as they would be when built.
  for(const intent of [plan(NOW+30n*DAY,{spec:SPEC.toUpperCase()}),{version:'5',spec:SPEC},{withdraw:true,version:'5'},{withdraw:false},{},null])assert.throws(()=>judge({},intent),undefined,JSON.stringify(intent));
  assert.throws(()=>sdk.judgeSignal(sdk.signalStatusOf(chain()),{withdraw:true}),/status read for the signalling account/);
});

// ---- the client

// A client whose verifier answers each selection with the state `stateFor` gives for it.
function reader(stateFor){
  const trust={app_version:'4',network_id:NETWORK,chain_id:'time-devnet-v4-test'},asked=[],posted=[];
  const verifier={verifyTrust:async()=>({}),verifyLightUpdate:async block=>({verified:true,status:'VERIFIED',checkpoint:{height:block.signed_header.header.height,block_hash:'cd'.repeat(32),block}}),
    verifyViewProof:async(_proof,_trust,query)=>{asked.push(query);return {verified:true,completeAccountSet:false,state:await stateFor(query,asked.length)};}};
  const fetcher=async(url,options={})=>{const route=new URL(url).pathname;if(options.method==='POST')posted.push(JSON.parse(options.body));
    const answer=route==='/api/network'?{protocolVersion:'4',networkId:NETWORK,chainId:trust.chain_id}:route==='/api/view-proof'?{light_block:{signed_header:{header:{height:'1'}}}}:route==='/api/submit'?{hash:createHash('sha256').update(Buffer.from(posted.at(-1).tx,'base64')).digest('hex').toUpperCase()}:{error:'unexpected request'};return {ok:!answer.error,text:async()=>JSON.stringify(answer)};};
  return {client:sdk.createClient({gateway:'https://rpc.example',trust,verifier,fetcher}),asked,posted};
}
// Twenty validators that all support the plan: more owner accounts than one proof holds.
const twenty=equal(20),everyone=twenty.map(item=>supports(item.owner,PLAN));
const answering=(more={},each=()=>({}))=>(query,count)=>{
  const ids=query.ids||[];
  return chain({active:twenty,signals:everyone,height:String(500+count),now:NOW+BigInt(count)*1000000n,accounts:ids.map(id=>account(id)),candidates:Object.fromEntries((query.candidates||[]).map(id=>[id,candidate(id)])),...more,...each(query,count)});
};

test('getSignalStatus() reads the status with proofs: one proof for the sets, the signals and the account, further ones for the other owners',async()=>{
  const {client,asked}=reader(answering());
  const result=await client.getSignalStatus('0');
  // The first read; then the nineteen other supporters, eight accounts to a proof.
  assert.deepEqual(asked[0],{names:[],ids:['0'],public_keys:[],owners:[],candidates:['0'],epochs:[],blocks:[],include_pos:true,include_bitcoin:false,include_policy:false,include_security:true,include_upgrade:true});
  assert.deepEqual(asked.slice(1).map(query=>[query.ids.length,query.candidates.length,query.include_security,query.include_pos]),[[8,0,true,false],[8,0,true,false],[3,0,true,false]]);
  assert.deepEqual(asked.slice(1).flatMap(query=>query.ids),twenty.slice(1).map(item=>item.owner));
  assert.deepEqual([result.complete,result.heights,result.height,planOf(result).tally],[true,{first:'501',last:'504'},'501',{rosters:[{support:'20000',total:'20000'}],lowest:{support:'20000',total:'20000'},schedule:true,keep:true,exact:true}]);
  assert.equal(result.validators.every(item=>item.counts===true),true);assert.equal(result.account.id,'0');
  // An owner found frozen in a later proof is taken out of the support.
  const frozen=reader(answering({},query=>query.ids?.includes('9')?{accounts:query.ids.map(id=>account(id,id==='9'?{devices:securedDevices}:{})),security:[securityRow(9,{frozen_until_elapsed_micros:(NOW+DAY).toString()})]}:{}));
  const second=await frozen.client.getSignalStatus('0');
  assert.deepEqual([planOf(second).tally.lowest,planOf(second).tally.exact,second.validators[9].stopped],[{support:'19000',total:'20000'},true,'frozen']);
  // During a hold the candidate rows are read as well, sixteen to a proof, and a jailed validator leaves both sums.
  const held=reader(answering({hold:true},query=>({candidates:Object.fromEntries((query.candidates||[]).map(id=>[id,candidate(id,{jailed:id==='4'})]))})));
  const third=await held.client.getSignalStatus('0');
  assert.deepEqual(held.asked.slice(1).map(query=>[query.ids.length,query.candidates.length]),[[8,16],[8,3],[3,0]]);
  assert.deepEqual([planOf(third).tally.lowest,planOf(third).tally.exact,third.validators[4].jailed,third.hold],[{support:'19000',total:'19000'},true,true,true]);
  // Nothing to complete: one read.
  const alone=reader(answering({active:equal(5),signals:[]}));
  assert.deepEqual([(await alone.client.getSignalStatus('0')).complete,alone.asked.length],[true,1]);
});

test('getSignalStatus() says what it could not read, and never guesses',async()=>{
  // Asked not to read further, or allowed fewer reads than needed: the first proof alone, and said.
  for(const options of [{complete:false},{maxReads:0},{maxReads:2}]){
    const {client,asked}=reader(answering()),result=await client.getSignalStatus('0',options);
    assert.deepEqual([result.complete,planOf(result).tally.exact,planOf(result).tally.lowest,asked.length],[false,false,{support:'20000',total:'20000'},1+(options.maxReads??0)],JSON.stringify(options));
  }
  // A further read that fails leaves the facts out; the status of the first proof stands.
  const failing=reader((query,count)=>{if(count===3)throw new Error('missing requested proof');return answering()(query,count);});
  const partial=await failing.client.getSignalStatus('0');
  assert.deepEqual([partial.complete,planOf(partial).tally.exact,partial.validators.filter(item=>item.counts===true).length,partial.heights],[false,false,9,{first:'501',last:'502'}]);
  // Without the first proof there is no status.
  await assert.rejects(reader(()=>{throw new Error('invalid key/value proof');}).client.getSignalStatus('0'),/invalid key\/value proof/);
  // A state of a version this build does not implement is this client's own finding, in any of the reads.
  for(const at of [1,2]){
    const upgraded=reader((query,count)=>count===at?chain({version:'5'}):answering()(query,count));
    await assert.rejects(upgraded.client.getSignalStatus('0'),error=>sdk.isUpgradeRequired(error));
  }
  // The account must be in the proof with its candidate row, or proven to have none.
  await assert.rejects(reader(()=>chain({accounts:[]})).client.getSignalStatus('0'),/does not prove this account/);
  assert.equal((await reader(()=>chain({candidates:{0:null}})).client.getSignalStatus('0')).account.ownsValidator,false);
  for(const bad of [{timeoutMs:999},{timeoutMs:600001},{maxReads:-1},{maxReads:65},{timeoutMs:'30000'}])await assert.rejects(reader(answering()).client.getSignalStatus('0',bad),/timeoutMs is from/);
  await assert.rejects(reader(answering()).client.getSignalStatus('01'),/canonical u64/);
});

test('a signed signal is submitted like any other action',async()=>{
  const pair=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']),publicKey=sdk.bytesToHex(new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey)));
  const owner=account(0,{devices:[{public_key:publicKey,can_manage:true,can_spend:true}]});
  const {client,posted}=reader(()=>chain({accounts:[owner]}));
  const judged=sdk.judgeSignal(await client.getSignalStatus('0'),{version:'5',spec:SPEC,activateElapsedMicros:PLAN.activate_elapsed_micros});
  const tx=await sdk.signAction({networkId:NETWORK,kind:'upgrade_signal',from:'0',nonce:'4',authEpoch:'0',publicKey,payload:judged.payload},pair.privateKey);
  assert.deepEqual(await client.submit(tx,{wait:false}),{hash:await sdk.transactionHash(tx),pending:true});
  const sent=sdk.decodeAction(sdk.fromBase64(posted.at(-1).tx));
  assert.deepEqual([sent.kind,sent.from,sent.nonce,sent.payload],[80,'0','4',{activate_elapsed_micros:PLAN.activate_elapsed_micros,spec:SPEC,version:'5'}]);
});

test('the status carries the rule of the waits and the total of the stops of its state: what dates the end of a freeze',()=>{
  // Without the rule: the two clocks are one, and a stored moment is a date as it is.
  assert.deepEqual(status({}).waits,{rule:false,stoppedMicros:'0'});
  // With it: the stops of the state, which a frozen owner's moment is on (`frozenUntilElapsedMicros`, a moment of the
  // clock of the waits) and which securityDeadline adds to make it a date.
  const HOUR=3600000000n,stopped=6n*HOUR,until=NOW-stopped+HOUR;
  const state={...chain({accounts:[account(0,{devices:securedDevices})],security:[securityRow(0,{frozen_until_elapsed_micros:until.toString(),freezes:'1'})]}),config:{waits_survive_stops:true},stopped_micros:stopped.toString()};
  const read=sdk.signalStatusOf(state,{account:'0'});
  assert.deepEqual([read.waits,read.account.stopped,read.account.frozenUntilElapsedMicros],[{rule:true,stoppedMicros:stopped.toString()},'frozen',until.toString()]);
  const due=sdk.securityDeadline(state,read.account.frozenUntilElapsedMicros);
  assert.deepEqual([due.earliest,due.elapsedMicros],[true,(until+stopped).toString()]);
  // A state that carries stops without the rule is not one the engine writes: no status is made of it.
  assert.throws(()=>sdk.signalStatusOf({...chain(),stopped_micros:'1'},{account:'0'}),/belongs to a network whose waits survive a stop/);
});
