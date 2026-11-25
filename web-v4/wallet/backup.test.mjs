import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {newDevice,sealVault,openVault,makePassword,sealUnder,vaultMade} from './vault.mjs';
import {sealLegacy} from './tests/legacy-vault.mjs';
import {createEncryptedBackup,parseEncryptedBackup,importEncryptedBackup,storedVaultKey,BACKUP_MADE_ONLY,BACKUP_CHOSEN_RESTORE} from './vault-backup.mjs';
const source=await readFile(new URL('./vendor/argon2-4.12.0.umd.min.js',import.meta.url),'utf8'),module={exports:{}};
new Function('module','exports',source)(module,module.exports);const {argon2id}=module.exports;
// The backup file is made only from a record whose password the wallet made (vault.mjs, RULE): this one.
const networkId='ab'.repeat(32),made=makePassword(),password=made.text;
const device=await newDevice(),binding={networkId,name:'alice',publicKey:device.publicKey};
const record=await sealVault({...device.secret,intent:'device'},made,binding,argon2id);
let active=true;
const client={getVerifiedState:async query=>{assert.deepEqual(query,{names:['alice']});return {verified:true,state:{network_id:networkId,accounts:[{id:'123',name:'alice',devices:active?[{public_key:device.publicKey}]:[]}]}};}};
const create=overrides=>createEncryptedBackup({record,password,expectedBinding:binding,networkId,client,argon2id,...overrides});
class Storage{
  entries=new Map();getItem(key){return this.entries.has(key)?this.entries.get(key):null;}setItem(key,value){this.entries.set(key,value);}
}
class Locks{
  tail=Promise.resolve();names=[];
  request(name,options,fn){assert.deepEqual(options,{mode:'exclusive'});this.names.push(name);const task=this.tail.then(fn);this.tail=task.catch(()=>{});return task;}
}
const restore=(text,overrides={})=>importEncryptedBackup({text,password,networkId,client,argon2id,storage:new Storage(),locks:new Locks(),...overrides});
let text;
test('portable backup contains only the authenticated encrypted envelope and restores the same key',async()=>{
  text=await create();assert.ok(!text.includes(password));assert.ok(!text.includes(device.secret.pkcs8));assert.ok(!text.includes('pkcs8'));
  const storage=new Storage(),locks=new Locks(),result=await restore(text,{storage,locks});
  assert.deepEqual(result,{binding,accountId:'123',made:null});assert.equal(Object.keys(result).join(','),'binding,accountId,made');
  const saved=JSON.parse(storage.getItem(storedVaultKey(binding)));assert.deepEqual(saved,record);
  const opened=await openVault(saved,password,argon2id);assert.equal(opened.privateKey.extractable,false);assert.equal(opened.binding.publicKey,device.publicKey);
  assert.equal(locks.names[0],'timecurrency:vault:'+networkId+':alice');
});
test('backup import rejects wrong password, ciphertext tamper and revoked device without storage writes',async()=>{
  const storage=new Storage();await assert.rejects(restore(text,{password:makePassword().text,storage}),/Could not unlock/);
  // A text that cannot be a password the wallet made is told so, before anything is derived.
  await assert.rejects(restore(text,{password:password+'wrong',storage}),/one the wallet made/);
  const altered=JSON.parse(text);altered.vault.ciphertext=(altered.vault.ciphertext[0]==='A'?'B':'A')+altered.vault.ciphertext.slice(1);
  await assert.rejects(restore(JSON.stringify(altered),{storage}),/Could not unlock/);
  active=false;try{await assert.rejects(restore(text,{storage}),/no longer approved/);await assert.rejects(create(),/no longer approved/);}finally{active=true;}
  assert.equal(storage.entries.size,0);
});
test('foreign network, unsupported versions, unknown fields and untrusted KDF costs fail before Argon2',async()=>{
  let calls=0;const argon=async()=>{calls++;throw Error('must not derive');};
  await assert.rejects(restore(text,{networkId:'cd'.repeat(32),argon2id:argon}),/another network/);
  for(const mutate of [b=>b.version=2,b=>b.unknown=true,b=>b.vault.kdf.memoryKiB=1,b=>b.vault.kdf.unknown=1,b=>b.vault.plaintextKey='forbidden']){
    const altered=JSON.parse(text);mutate(altered);await assert.rejects(restore(JSON.stringify(altered),{argon2id:argon}));
  }
  assert.equal(calls,0);assert.throws(()=>parseEncryptedBackup('x'.repeat(16385)),/size/);
  assert.throws(()=>parseEncryptedBackup(text.replace('"version": 1','"version": 1,"version":1')),/duplicate/);
  assert.throws(()=>parseEncryptedBackup(text.replace('"version": 1','"version": 1,"\\u0076ersion":1')),/duplicate/);
});
test('a key locked to a device (vault version 3) never travels in a backup file: refused before any derivation',async()=>{
  let calls=0;const argon=async(...a)=>{calls++;return argon2id(...a);};
  const login=await newDevice(),bound={networkId,name:'alice',publicKey:login.publicKey};
  const locked=await sealVault({pkcs8:login.secret.pkcs8},made,bound,argon2id,globalThis.crypto,'signin',{credential:'A'.repeat(22),secret:new Uint8Array(32).fill(7)});
  assert.equal(locked.version,3);
  const file=JSON.stringify({format:'timecurrency-encrypted-vault',version:1,vault:locked});
  assert.throws(()=>parseEncryptedBackup(file),/locked to a device\. A backup file cannot carry one: it would open with a password alone\./);
  const storage=new Storage();await assert.rejects(restore(file,{storage,argon2id:argon}),/locked to a device/);
  assert.equal(calls,0);assert.equal(storage.entries.size,0);
});
test('the rule: a file is made only from a record whose password the wallet made; a file made before from a chosen password still restores and opens; a key kept under another key never travels',async()=>{
  assert.equal(vaultMade(record),true);
  // A record under a password a person chose, kept from before the rule: no file is made of it, before anything is derived.
  let calls=0;const counting=async(...a)=>{calls++;return argon2id(...a);};
  const chosen='violet otters dance beneath moonlight 41',legacy=await sealLegacy({...device.secret,intent:'device'},chosen,binding,argon2id);
  await assert.rejects(create({record:legacy,password:chosen,argon2id:counting}),error=>error.message===BACKUP_MADE_ONLY);
  assert.equal(calls,0);
  // A file of such a record, made before the rule, still opens with its password; the browser keeps its key only under a
  // password the wallet makes, shown before it is kept (the record of the file is not written as it is).
  const old=JSON.stringify({format:'timecurrency-encrypted-vault',version:1,vault:legacy},null,2)+'\n',storage=new Storage();
  await assert.rejects(restore(old,{password:chosen,storage}),error=>error.message===BACKUP_CHOSEN_RESTORE);
  assert.equal(storage.entries.size,0);
  let shown=null,keptWhenShown=null;
  const restored=await restore(old,{password:chosen,storage,show:async made=>{shown=made;keptWhenShown=storage.entries.size;}});
  assert.deepEqual([restored.binding.publicKey,restored.made,keptWhenShown],[device.publicKey,shown,0]);
  const kept=JSON.parse(storage.getItem(storedVaultKey(binding)));
  assert.deepEqual([kept.version,kept.password,kept.binding.publicKey],[1,'made',device.publicKey]);
  const reopened=await openVault(kept,shown,argon2id);
  assert.deepEqual([reopened.binding.publicKey,reopened.secret.intent],[device.publicKey,'device']);
  await assert.rejects(openVault(kept,chosen,argon2id),error=>error.madeForm===true,'the chosen password does not open what this browser keeps');
  // The registration key of a sign-up, kept under the login key (vault version 4): never in a file, refused before anything.
  const login=await newDevice(),under=await sealUnder({...device.secret,intent:'device'},binding,{publicKey:login.publicKey,pkcs8:login.secret.pkcs8});
  const file=JSON.stringify({format:'timecurrency-encrypted-vault',version:1,vault:under});
  assert.throws(()=>parseEncryptedBackup(file),/kept under another key/);
  await assert.rejects(create({record:under}),/kept under another key/);
});
test('the password made for the key of a file of a chosen password is shown with no lock held, once the new record opened with it; a vault written meanwhile is never overwritten',async()=>{
  const chosen='violet otters dance beneath moonlight 41',legacy=await sealLegacy({...device.secret,intent:'device'},chosen,binding,argon2id);
  const old=JSON.stringify({format:'timecurrency-encrypted-vault',version:1,vault:legacy},null,2)+'\n';
  let held=0;const locks={request:async(name,options,fn)=>{held++;try{return await fn();}finally{held--;}}};
  const storage=new Storage();let heldWhenShown=null,shown=null;
  const restored=await restore(old,{password:chosen,storage,locks,show:async made=>{heldWhenShown=held;shown=made;}});
  assert.deepEqual([heldWhenShown,restored.made,storage.entries.size],[0,shown,1],'shown with no lock held, then kept');
  // Written by another tab while the password is shown: kept as it is; the password shown opens nothing kept.
  const racing=new Storage();
  await assert.rejects(restore(old,{password:chosen,storage:racing,locks,show:async()=>{racing.setItem(storedVaultKey(binding),'written meanwhile');}}),/not overwritten/);
  assert.equal(racing.getItem(storedVaultKey(binding)),'written meanwhile');
  // The dialog closed without "I have it" (made-dialog.mjs): nothing is kept.
  const closed=new Storage();
  await assert.rejects(restore(old,{password:chosen,storage:closed,locks,show:async()=>{throw new Error('Nothing was kept.');}}),/Nothing was kept/);
  assert.equal(closed.entries.size,0);
});
test('portable JSON field order is irrelevant while KDF values and AAD stay exact',async()=>{
  const other=JSON.parse(text);other.vault.kdf=Object.fromEntries(Object.entries(other.vault.kdf).reverse());other.vault.binding=Object.fromEntries(Object.entries(other.vault.binding).reverse());
  const result=await restore(JSON.stringify(other));assert.equal(result.binding.publicKey,device.publicKey);
  const changed=JSON.parse(text);changed.vault.binding.name='bob';await assert.rejects(restore(JSON.stringify(changed)),/Could not unlock/);
});
test('existing vault is never overwritten, even with the identical backup and password',async()=>{
  const storage=new Storage();storage.setItem(storedVaultKey(binding),'existing bytes');let calls=0;
  await assert.rejects(restore(text,{storage,argon2id:async()=>{calls++;}}),/never overwrites/);
  assert.equal(storage.getItem(storedVaultKey(binding)),'existing bytes');assert.equal(calls,0);
});
test('late vault creation or a failed fresh-proof/generation check cannot overwrite storage',async()=>{
  const storage=new Storage();
  const racingClient={getVerifiedState:async query=>{storage.setItem(storedVaultKey(binding),'concurrent bytes');return client.getVerifiedState(query);}};
  await assert.rejects(restore(text,{storage,client:racingClient}),/not overwritten/);assert.equal(storage.getItem(storedVaultKey(binding)),'concurrent bytes');
  const empty=new Storage();let checks=0;
  await assert.rejects(restore(text,{storage:empty,check:()=>{if(++checks>=3)throw Error('Locked generation');}}),/Locked generation/);assert.equal(empty.entries.size,0);
  await assert.rejects(restore(text,{storage:empty,client:{getVerifiedState:async()=>({verified:false})}}),/independently verified/);assert.equal(empty.entries.size,0);
});
test('two simultaneous imports serialize and only one creates a vault',async()=>{
  const storage=new Storage(),locks=new Locks();const results=await Promise.allSettled([restore(text,{storage,locks}),restore(text,{storage,locks})]);
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal(results.filter(r=>r.status==='rejected').length,1);assert.deepEqual(JSON.parse(storage.getItem(storedVaultKey(binding))),record);
});
test('backup export requires the unlocked binding and rejects corrupted stored ciphertext',async()=>{
  await assert.rejects(create({expectedBinding:{...binding,publicKey:'cd'.repeat(32)}}),/unlocked device/);
  const bad=structuredClone(record);bad.ciphertext=(bad.ciphertext[0]==='A'?'B':'A')+bad.ciphertext.slice(1);
  await assert.rejects(create({record:bad}),/Could not unlock/);
});
