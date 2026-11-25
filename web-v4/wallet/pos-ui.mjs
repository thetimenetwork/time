import {minSelfBond} from './security-flows.mjs';
const $=id=>document.getElementById(id);
const node=(tag,text)=>{const el=document.createElement(tag);el.textContent=text;return el;};
/// What the Validator operator panel says of a pasted text it cannot take.
export const NOT_A_REGISTRATION='This is not a registration text for this account on this network. Run the script with this account\'s number and paste what it prints.';
export function createPosUI(c){
 function row(title,detail,label,run){const el=node('div','');el.className='row';const copy=node('div','');copy.append(node('strong',title),node('small',detail));el.append(copy);if(label){const b=node('button',label);b.type='button';b.className='secondary';b.dataset.chainAction='true';b.addEventListener('click',()=>c.run(run));el.append(b);}return el;}
 // `payment`: the field of the payment password of a protected account on the screen the action came from. Such an account
 // is told before the review what the action does to its daily limit, or why it cannot be signed now (c.limitLines:
 // security-ui.mjs, stakeLimit; null for an account with one key, whose review is as it was).
 async function action(kind,payload,title,fields,payment){const check=c.capture();try{const limit=await c.limitLines?.(kind,payload);check();if(!await c.review(title,limit?[...fields,...limit]:fields))return;check();c.setBusy(true);await c.sendSigned(kind,payload,title,{payment});check();await c.refresh();c.notice(title+' finalized and verified.');}finally{const field=payment&&$(payment);if(field)field.value='';}}
 function render(account,state){
  const own=state.stake_owners?.[account.id],candidate=state.candidates?.[account.id],pos=state.pos;
  $('operator').replaceChildren();for(const id of [...(pos?.candidate_ids||[])].sort((a,b)=>Number(pos.active.some(v=>v.owner===b))-Number(pos.active.some(v=>v.owner===a)))){const option=node('option',`Validator ${id}${pos.active.some(v=>v.owner===id)?' · active':''}`);option.value=id;$('operator').append(option);}
  $('pos-status').textContent=`${pos?.active?.length||0} active validators · ${pos?.bootstrap_ended?'funded validator handoff complete':'genesis bootstrap still present'} · ${pos?.safety_hold?'selection safety hold':'selection running'}. Unbonding remains slashable for 14 days.`;
  $('delegations').replaceChildren();let bonded=candidate?BigInt(candidate.self_bond):0n,unpriced=0;
  for(const position of own?.positions||[]){const pool=state.candidates?.[position.candidate];const value=pool&&BigInt(pool.pool_shares)?BigInt(position.shares)*BigInt(pool.pool_assets)/BigInt(pool.pool_shares):null;if(value!==null)bonded+=value;else unpriced++;
   $('delegations').append(row(`Validator ${position.candidate}`,`${position.shares} shares${value===null?' · load candidate to price':` · ${c.seconds(value)} seconds`}`,'Unbond all',async()=>{
    const fresh=await c.verifiedState({candidates:[position.candidate]}),pool=fresh.candidates[position.candidate];if(!pool)throw Error('Candidate unavailable');const amount=BigInt(position.shares)*BigInt(pool.pool_assets)/BigInt(pool.pool_shares);
    await action('undelegate',{operator:position.candidate,shares:position.shares,min_amount:amount.toString()},'Unbond delegation',[['Validator',position.candidate],['Shares',position.shares],['Exposure','Voting power must decrease at H+2. Withdrawal is available only after the full 14-day slash window.']],'stake-payment');
   }));
  }
  $('bonded').textContent=c.seconds(bonded)+' s'+(unpriced?` + ${unpriced} unpriced positions`:'');$('home-staked').textContent=$('bonded').textContent;$('unbonding').replaceChildren();$('validator-exits').replaceChildren();
  for(const exit of own?.exits||[]){const pool=state.candidates?.[exit.candidate],active=pos.active.some(v=>v.owner===exit.candidate)||pos.scheduled.some(s=>s.validators.some(v=>v.owner===exit.candidate)),block=state.canonical_blocks?.[exit.release_height],absolute=state.release_times?.[exit.release_height]??block?.time_micros;
   let end=absolute?BigInt(absolute)-BigInt(state.genesis.genesis_time_micros):null;if(end!==null&&exit.kind==='self_bond'&&pool&&BigInt(pool.last_active_end)>end)end=BigInt(pool.last_active_end);
   const unlock=end===null?null:end+1209600000000n,elapsed=BigInt(state.time_micros)-BigInt(state.genesis.genesis_time_micros),ready=unlock!==null&&elapsed>=unlock&&(exit.kind!=='self_bond'||!active);
   const detail=exit.kind==='self_bond'&&active?'Self-exit remains exposed while active or scheduled. The 14-day window starts after actual removal.':unlock===null?`Awaiting authenticated H${exit.release_height} removal time`:`${ready?'Ready':'Unlocks'} at ${new Date(Number((BigInt(state.genesis.genesis_time_micros)+unlock)/1000n)).toISOString()}`;
   const withdraw=payment=>()=>action('withdraw_stake',{entry:exit.id},'Withdraw mature stake',[['Exit',exit.id],['Policy','Full exposure end plus 14 days; current ledger rechecks maturity.']],payment);
   $('unbonding').append(row(`Exit ${exit.id} · ${exit.kind}`,detail,ready?'Withdraw':null,withdraw('stake-payment')));
   // The validator's own bond on its way out is listed where the validator is run too.
   if(exit.kind==='self_bond')$('validator-exits').append(row(`Bond taken out · exit ${exit.id}`,detail,ready?'Withdraw':null,withdraw('validator-payment')));
  }
  $('validator-summary').textContent=candidate?`Validator key ${candidate.consensus_key} · your bond ${c.seconds(candidate.self_bond)} s · ${candidate.archived?'retired; what is still owed can be taken out':candidate.jailed?'removed for signing twice':pos?.active?.some(v=>v.owner===account.id)?'in the set':BigInt(candidate.self_bond)===0n?'no bond, so not in the set':'in line for the set'}`:'This account has no validator. Run the join script on your server first: it prints the registration text to paste here.';
 }
 $('validator-register-form').addEventListener('submit',event=>{event.preventDefault();c.run(async()=>{
  // A text that is too long, is not JSON, or is not bound to this account and this network gets one plain answer.
  const unfit=()=>Error(NOT_A_REGISTRATION);
  const text=$('validator-enrollment').value;if(text.length>4096)throw unfit();let e;try{e=JSON.parse(text);}catch{throw unfit();}const account=c.ownAccount(),network=c.network();
  if(!e||typeof e!=='object'||Object.keys(e).sort().join(',')!=='commission_bps,consensus_key,networkId,owner,proof'||e.networkId!==network.networkId||e.owner!==account.id||!Number.isInteger(e.commission_bps)||e.commission_bps<0||e.commission_bps>2000||!/^[0-9a-f]{64}$/.test(e.consensus_key)||!/^[0-9a-f]{128}$/.test(e.proof))throw unfit();
  // The bond is the network's least one, by the staking profile of a verified state (security-flows.mjs, minSelfBond); a
  // network whose least bond this wallet does not know gets no review (web audit of November 2026, W-7).
  const bond=minSelfBond(await c.verifiedState());
  await action('register_validator',{commission_bps:e.commission_bps,consensus_key:e.consensus_key,proof:e.proof},'Register my validator',[['Validator key',e.consensus_key],['Commission',`${e.commission_bps/100}%`],['Bond',`${c.seconds(bond)} seconds, the network's least bond, taken from your balance now. It is lost if the validator signs two different blocks at one height.`]],'validator-payment');$('validator-enrollment').value='';
 });});
 // One listener: one click asks for one review.
 $('validator-retire').addEventListener('click',()=>c.run(()=>action('retire_validator',{},'Retire my validator',[['What happens','Only a validator that has left the set and holds nothing any more can be retired. Its key cannot be used again.']],'validator-payment')));
 $('self-bond-form').addEventListener('submit',event=>{event.preventDefault();c.run(async()=>{const state=await c.verifiedState(),own=c.ownAccount(),candidate=state.candidates?.[own.id];if(!candidate||candidate.archived||candidate.jailed)throw Error('This account has no validator that can take more bond: it has none, or it was removed or retired.');return action('self_bond',{amount:c.parseSeconds($('self-bond-amount').value)},'Add to my validator\'s bond',[['Amount',$('self-bond-amount').value+' seconds'],['Risk','The bond can be lost if the validator signs twice. Taking it out takes 14 days.']],'validator-payment');})});
 $('self-unbond-form').addEventListener('submit',event=>{event.preventDefault();c.run(()=>{const amount=c.parseSeconds($('self-unbond-amount').value);return action('self_unbond',{amount,min_amount:amount},'Take out of my validator\'s bond',[['Amount',c.seconds(amount)+' seconds'],['What happens','With less than the minimum left the validator leaves the set two blocks later. The seconds come back 14 days after it has left.']],'validator-payment');})});
 return {render};
}
