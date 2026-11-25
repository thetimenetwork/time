// Portable encrypted envelope only. Passwords/plaintext signing keys never leave
// this module; the caller provides the independently verifying chain client.
import {validateVaultRecord,openVault,forgetSecret,vaultDevice,vaultUnder,vaultMade,vaultIntent,sealVault,makePassword} from './vault.mjs';
import {readyToMake} from './entropy.mjs';
export const BACKUP_FORMAT='timecurrency-encrypted-vault';
// The rule (vault.mjs, RULE): a file leaves the device, so it is made only of a record whose password the wallet made.
// A record under a password a person chose (kept from before the rule) makes no file; a file made of one before still
// restores, and opens with its password.
export const BACKUP_MADE_ONLY='This browser makes a backup file only of a key whose password the wallet made: a file of a key under a password you chose could be guessed on another computer. Let the wallet make your passwords, under Keys, first.';
export const BACKUP_UNDER='This key is kept under another key of this browser and never travels in a file.';
// A file made before the rule holds a record of a password a person chose. Restoring it does not write that record as it
// is (every record the wallet writes follows the rule): the same key is sealed again under a password the wallet makes,
// shown (`show`) before it is kept. The file itself keeps opening with its old password.
export const BACKUP_CHOSEN_RESTORE='This backup file is locked with a password you chose. The wallet keeps its key only under a password it makes for it, which it shows first.';
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
  const record=validateVaultRecord(backup.vault);
  // A key locked to a device (vault version 3, device-lock.mjs) never travels in a file: a file opens with a password alone.
  if(vaultDevice(record))fail('This backup holds a key locked to a device. A backup file cannot carry one: it would open with a password alone.');
  if(vaultUnder(record))fail(BACKUP_UNDER);
  return record;
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
  if(vaultUnder(record))fail(BACKUP_UNDER);
  if(vaultDevice(record))fail('This key is locked to this device. A backup file cannot carry one: it would open with a password alone.');
  if(!vaultMade(record))fail(BACKUP_MADE_ONLY);
  if(record.binding.networkId!==networkId)fail('Backup belongs to another network');
  if(!expectedBinding||['networkId','name','publicKey'].some(key=>record.binding[key]!==expectedBinding[key]))fail('Stored vault differs from the unlocked device');
  let opened;
  try{
    opened=await openVault(record,password,argon2id);check();
    await assertFreshAuthority(record.binding,networkId,client,check);check();
    return JSON.stringify({format:BACKUP_FORMAT,version:1,vault:record},null,2)+'\n';
  }finally{if(opened){forgetSecret(opened.secret);opened.privateKey=null;}}
}
/// `show(password)`: awaited with the password the wallet made for the key of a file of a chosen password, before that key
/// is kept (BACKUP_CHOSEN_RESTORE); without it such a file is refused. It is called once the new record opened with that
/// password, the key opened from the file was wiped and the Web Lock let go (review of 24 November 2026, finding 4); the
/// record is written under the lock again, and only if no vault of the account was written meanwhile. Returns the
/// binding, the account, and `made` (that password, or null when the file's record was of a password the wallet made, and
/// is kept as it is).
export async function importEncryptedBackup({text,password,networkId,client,argon2id,storage,locks,check=()=>{},show=null,cryptoImpl=globalThis.crypto}){
  const record=parseEncryptedBackup(text);check();
  if(record.binding.networkId!==networkId)fail('Backup belongs to another network');
  if(typeof locks?.request!=='function')fail('Web Locks are required to restore a vault safely');
  // Only a login key (or the key of an account with one key) travels in a file: said before anything else.
  validateVaultRecord(record,['device','signin']);
  if(!vaultMade(record)&&typeof show!=='function')fail(BACKUP_CHOSEN_RESTORE);
  const binding=record.binding,key=storedVaultKey(binding),lockName='timecurrency:vault:'+networkId+':'+binding.name;
  // A file of a chosen password gets a password the wallet makes: the person may add their own randomness first
  // (entropy.mjs), before the lock is taken and the file's key is opened.
  if(!vaultMade(record)){await readyToMake(1);check();}
  const sealed=await locks.request(lockName,{mode:'exclusive'},async()=>{
    check();if(storage.getItem(key)!==null)fail('A vault already exists here for this account. Import never overwrites it.');
    let opened;
    try{
      opened=await openVault(record,password,argon2id);check();
      const account=await assertFreshAuthority(binding,networkId,client,check);check();
      // A record of a password the wallet made is kept as it is, at once.
      if(vaultMade(record)){
        if(storage.getItem(key)!==null)fail('A vault was created while restoring. It was not overwritten.');
        storage.setItem(key,JSON.stringify(record));
        return {done:{binding:{...binding},accountId:String(account.id),made:null}};
      }
      // The rule: the key of a file of a chosen password is sealed again, the same key, under a password the wallet makes,
      // and the new record must open with it before it is shown.
      const fresh=makePassword(),intent=vaultIntent(record);
      const kept=await sealVault(intent==='device'?{...opened.secret}:{pkcs8:opened.secret.pkcs8},fresh,binding,argon2id,cryptoImpl,intent);check();
      const proof=await openVault(kept,fresh.text,argon2id,cryptoImpl,intent);forgetSecret(proof.secret);proof.privateKey=null;check();
      return {kept,made:fresh.text,accountId:String(account.id)};
    }finally{if(opened){forgetSecret(opened.secret);opened.privateKey=null;}}
  });
  if(sealed.done)return sealed.done;
  await show(sealed.made);check();
  return locks.request(lockName,{mode:'exclusive'},async()=>{
    check();if(storage.getItem(key)!==null)fail('A vault was created while restoring. It was not overwritten.');
    storage.setItem(key,JSON.stringify(sealed.kept));
    return {binding:{...binding},accountId:sealed.accountId,made:sealed.made};
  });
}
