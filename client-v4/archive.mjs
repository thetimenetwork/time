// Public evidence only. Durable files preserve availability, never replace
// current canonical proofs or an independently authenticated trust checkpoint.
import {mkdir,open,readFile,rename} from 'node:fs/promises';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
export async function createArchive({directory,networkId}){
 if(!directory||!/^[0-9a-f]{64}$/.test(networkId))throw Error('Durable V4 archive directory and network are required');
 await mkdir(directory,{recursive:true,mode:0o700});let queue=Promise.resolve();
 const serial=fn=>{const r=queue.then(fn);queue=r.catch(()=>{});return r;};
 function file(prefix,key){if(!/^[0-9a-f]{64}$/.test(key)&&!/^(0|[1-9][0-9]*)$/.test(key))throw Error('Invalid archive key');return path.join(directory,prefix+'-'+key+'.json');}
 async function read(location){try{const raw=await readFile(location,'utf8');if(raw.length>2*1024*1024)throw Error('Archive file limit');const row=JSON.parse(raw);if(row.networkId!==networkId||row.digest!==digest(row.value))throw Error('Archive corruption or foreign network');return row.value;}catch(e){if(e.code==='ENOENT')return null;throw e;}}
 async function write(location,value){const text=JSON.stringify({networkId,value,digest:digest(value)});if(text.length>2*1024*1024)throw Error('Archive record limit');const tmp=location+'.'+randomBytes(8).toString('hex')+'.tmp',f=await open(tmp,'wx',0o600);try{await f.writeFile(text);await f.sync();}finally{await f.close();}await rename(tmp,location);}
 return Object.freeze({
  getReceipt:hash=>read(file('receipt',hash.toLowerCase())),
  putReceipt:(hash,evidence)=>serial(async()=>{const location=file('receipt',hash.toLowerCase()),existing=await read(location);if(existing&&(existing.tx.tx!==evidence.tx.tx||digest(existing.signed_header.header)!==digest(evidence.signed_header.header)||digest(existing.next_signed_header.header)!==digest(evidence.next_signed_header.header)))throw Error('Conflicting receipt archive evidence');if(!existing)await write(location,evidence);}),
  observeAccount:(account,state)=>serial(async()=>{
   const location=file('inbox',account.id),old=await read(location)||{accountId:account.id,last:null,items:[]};
   const cases=(state.recovery_cases||[]).filter(c=>c.target===account.id),snapshot={authEpoch:account.auth_epoch,devices:account.devices.map(d=>d.public_key),recovery:cases.map(c=>({id:c.recovery_id,approvals:c.approvals.length,ready:c.ready_elapsed_micros})),policy:account.recovery_version||'0'};
   const changes=[];if(cases.some(c=>c.ready_elapsed_micros!==null))changes.push('RECOVERY_QUORUM_SPENDING_FROZEN');else if(cases.length)changes.push('RECOVERY_APPROVAL_PENDING');
   if(old.last&&old.last.authEpoch!==snapshot.authEpoch)changes.push('DEVICE_AUTHORITY_CHANGED');if(old.last&&old.last.policy!==snapshot.policy)changes.push('RECOVERY_POLICY_CHANGED');
   if(digest(old.last)!==digest(snapshot)){for(const type of changes)old.items.push({id:digest({height:state.height,type,snapshot}),type,height:state.height,timeMicros:state.time_micros,read:false});old.items=old.items.slice(-128);old.last=snapshot;await write(location,old);}
   return {accountId:account.id,items:old.items,observedHeight:state.height,notice:'Alerts are collected when this account is queried. Verify the attached current state before acting.'};
  }),
 });
}
