import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {newDevice,sealVault,openVault} from './vault.mjs';
import {createEncryptedBackup,parseEncryptedBackup,importEncryptedBackup,storedVaultKey} from './vault-backup.mjs';
const source=await readFile(new URL('./vendor/argon2-4.12.0.umd.min.js',import.meta.url),'utf8'),module={exports:{}};
new Function('module','exports',source)(module,module.exports);const {argon2id}=module.exports;
const networkId='ab'.repeat(32),password='violet otters dance beneath moonlight 41';
const device=await newDevice(),binding={networkId,name:'alice',publicKey:device.publicKey};
const record=await sealVault({...device.secret,intent:'device'},password,binding,argon2id);
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
  assert.deepEqual(result,{binding,accountId:'123'});assert.equal(Object.keys(result).join(','),'binding,accountId');
  const saved=JSON.parse(storage.getItem(storedVaultKey(binding)));assert.deepEqual(saved,record);
  const opened=await openVault(saved,password,argon2id);assert.equal(opened.privateKey.extractable,false);assert.equal(opened.binding.publicKey,device.publicKey);
  assert.equal(locks.names[0],'timecurrency:vault:'+networkId+':alice');
});
test('backup import rejects wrong password, ciphertext tamper and revoked device without storage writes',async()=>{
  const storage=new Storage();await assert.rejects(restore(text,{password:password+'wrong',storage}),/Could not unlock/);
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
