// Portable encrypted envelope only. Passwords/plaintext signing keys never leave
// this module; the caller provides the independently verifying chain client.
import {validateVaultRecord,openVault,forgetSecret} from './vault.mjs';
export const BACKUP_FORMAT='timecurrency-encrypted-vault';
export const MAX_BACKUP_BYTES=16*1024;
export const storedVaultKey=binding=>'timecurrency.vault.v1:'+binding.networkId+':'+binding.name;
function fail(message){throw new Error(message);}
function rejectDuplicateKeys(text){
  const stack=[];
  for(const [token] of text.matchAll(/"(?:\\[\s\S]|[^"\\])*"|[{}\[\]:,]/g)){
    if(token==='{')stack.push({object:true,keys:new Set(),key:true});
    else if(token==='[')stack.push({object:false});
    else if(token==='}'||token===']')stack.pop();
    else if(token===':'&&stack.at(-1)?.object)stack.at(-1).key=false;
    else if(token===','&&stack.at(-1)?.object)stack.at(-1).key=true;
    else if(token.startsWith('"')&&stack.at(-1)?.object&&stack.at(-1).key){
      const key=JSON.parse(token),object=stack.at(-1);
      if(object.keys.has(key))fail('Encrypted backup contains duplicate JSON fields');object.keys.add(key);
    }
  }
}
export function parseEncryptedBackup(text){
  if(typeof text!=='string'||new TextEncoder().encode(text).byteLength>MAX_BACKUP_BYTES)fail('Encrypted backup exceeds the supported size');
  let backup;try{backup=JSON.parse(text);}catch{fail('Choose a valid encrypted backup JSON file');}
  rejectDuplicateKeys(text);
  if(!backup||Object.keys(backup).sort().join(',')!=='format,vault,version'||backup.format!==BACKUP_FORMAT||backup.version!==1)fail('Unsupported encrypted backup format');
  return validateVaultRecord(backup.vault);
}
async function assertFreshAuthority(binding,networkId,client,check){
  if(binding.networkId!==networkId)fail('Backup belongs to another network');
  const result=await client.getVerifiedState({names:[binding.name]});check();
  if(result?.verified!==true||result.state?.network_id!==networkId)fail('Fresh independently verified account authority is required');
  const account=result.state.accounts.find(a=>a.name===binding.name);
  if(!account||!account.devices?.some(d=>d.public_key===binding.publicKey))fail('Backup device is no longer approved for this account');
  return account;
}
export async function createEncryptedBackup({record,password,expectedBinding,networkId,client,argon2id,check=()=>{}}){
  record=validateVaultRecord(record);check();
  if(record.binding.networkId!==networkId)fail('Backup belongs to another network');
  if(!expectedBinding||['networkId','name','publicKey'].some(key=>record.binding[key]!==expectedBinding[key]))fail('Stored vault differs from the unlocked device');
  let opened;
  try{
    opened=await openVault(record,password,argon2id);check();
    await assertFreshAuthority(record.binding,networkId,client,check);check();
    return JSON.stringify({format:BACKUP_FORMAT,version:1,vault:record},null,2)+'\n';
  }finally{if(opened){forgetSecret(opened.secret);opened.privateKey=null;}}
}
export async function importEncryptedBackup({text,password,networkId,client,argon2id,storage,locks,check=()=>{}}){
  const record=parseEncryptedBackup(text);check();
  if(record.binding.networkId!==networkId)fail('Backup belongs to another network');
  if(typeof locks?.request!=='function')fail('Web Locks are required to restore a vault safely');
  const binding=record.binding,key=storedVaultKey(binding);
  return locks.request('timecurrency:vault:'+networkId+':'+binding.name,{mode:'exclusive'},async()=>{
    check();if(storage.getItem(key)!==null)fail('A vault already exists here for this account. Import never overwrites it.');
    let opened;
    try{
      opened=await openVault(record,password,argon2id);check();
      const account=await assertFreshAuthority(binding,networkId,client,check);check();
      if(storage.getItem(key)!==null)fail('A vault was created while restoring. It was not overwritten.');
      storage.setItem(key,JSON.stringify(record));
      return {binding:{...binding},accountId:String(account.id)};
    }finally{if(opened){forgetSecret(opened.secret);opened.privateKey=null;}}
  });
}
