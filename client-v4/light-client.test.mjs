import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createLightClient} from './light-client.mjs';
import * as verifier from './proof-verifier.mjs';
const fixture=JSON.parse(await readFile(new URL('../verifier-v4/fixtures/dynamic.json',import.meta.url)));
class Storage{map=new Map();getItem(k){return this.map.get(k)??null;}setItem(k,v){this.map.set(k,v);}}
const blocks=new Map(fixture.blocks.map(b=>[b.signed_header.header.height,b]));
function make({storage=new Storage(),now=()=>fixture.now_ms,fetchBlock=async h=>blocks.get(h),...rest}={}){
  return createLightClient({trust:fixture.trust,verifier,storage,now,fetchBlock,...rest});
}
test('actual WASM bisects a disjoint new committee and persists H+2 authority',async()=>{
  const fetched=[],storage=new Storage(),client=make({storage,fetchBlock:async h=>{fetched.push(h);return structuredClone(blocks.get(h));}});
  const checkpoint=await client.updateTo('3');assert.equal(checkpoint.height,'3');assert.deepEqual(fetched,['3','1','2']);
  const stored=JSON.parse([...storage.map.values()][0]);assert.equal(stored.checkpoint.block_hash,checkpoint.block_hash);
  const resumed=make({storage});assert.equal((await resumed.updateTo('3')).block_hash,checkpoint.block_hash);
});
test('a missing intermediate cannot turn NEEDS_BISECTION into trust',async()=>{
  const client=make({fetchBlock:async h=>{if(h==='2')throw Error('intermediate withheld');return structuredClone(blocks.get(h));}});
  await assert.rejects(client.updateTo('3'),/withheld/);assert.equal(client.getCheckpoint().height,'1');
});
test('the highest checkpoint is preserved after an RPC rollback or forged next set',async()=>{
  const client=make();await client.updateTo('3');await assert.rejects(client.updateTo('2'),/HEADER_ROLLBACK/);assert.equal(client.getCheckpoint().height,'3');
  const bad=structuredClone(blocks.get('3'));bad.next_validators=structuredClone(blocks.get('1').validators);
  await assert.rejects(client.updateToBlock(bad),/verification|validator|hash/);assert.equal(client.getCheckpoint().height,'3');
});
test('expired trust rejects before contacting any RPC and cannot auto-refresh',async()=>{
  let requests=0;const client=make({now:()=>fixture.refresh_now_ms,fetchBlock:async()=>{requests++;return blocks.get('3');}});
  await assert.rejects(client.updateTo('3'),/CHECKPOINT_REFRESH_REQUIRED/);assert.equal(requests,0);assert.equal(client.getCheckpoint(),null);
});
test('external refresh requires a separate full expected hash and makes no RPC calls',async()=>{
  let requests=0;const client=make({now:()=>fixture.refresh_now_ms,fetchBlock:async()=>{requests++;throw Error('must not fetch');}}),fresh=fixture.external_checkpoint;
  await assert.rejects(client.importTrustedCheckpoint(fresh,'00'.repeat(32)),/INDEPENDENT_CHECKPOINT_HASH_REQUIRED/);
  assert.equal((await client.importTrustedCheckpoint(fresh,fresh.block_hash)).height,'4');assert.equal(requests,0);assert.equal((await client.ready()).ready,true);
});
test('external refresh still cannot erase a higher stored checkpoint',async()=>{
  const storage=new Storage(),first=make({storage});await first.updateTo('3');
  const lower=JSON.parse(JSON.stringify(fixture.trust));const result=await verifier.verifyLightUpdate(blocks.get('1'),lower,fixture.now_ms);
  const resumed=make({storage});await assert.rejects(resumed.importTrustedCheckpoint(result.checkpoint,result.checkpoint.block_hash),/ROLLBACK/);
  assert.equal(resumed.getCheckpoint().height,'3');
});
test('concurrent updates serialize and never publish an unverified candidate',async()=>{
  const client=make();const [a,b]=await Promise.all([client.updateTo('2'),client.updateTo('3')]);assert.equal(a.height,'2');assert.equal(b.height,'3');
  assert.equal(client.getCheckpoint().height,'3');
});
test('bounded bisection saves verified progress and storage errors block the operation',async()=>{
  const client=make({maxSteps:1});await assert.rejects(client.updateTo('3'),/LIGHT_UPDATE_BUDGET/);assert.equal(client.getCheckpoint().height,'1');
  const broken={getItem:()=>null,setItem:()=>{throw Error('disk full');}},failed=make({storage:broken});
  await assert.rejects(failed.updateTo('1'),/disk full/);assert.equal(failed.getCheckpoint().height,'1');
});
test('a pasted checkpoint cannot replace a trust anchor that is still valid',async()=>{
  // A correctly signed block with its matching hash: everything the import form checks.
  const source=make();const signed=await source.updateTo('3');
  // A wallet whose genesis pin is still valid must reach that block by verification, not by paste.
  const fresh=make();await assert.rejects(fresh.importTrustedCheckpoint(signed,signed.block_hash),/CURRENT_TRUST_STILL_VALID/);assert.equal(fresh.getCheckpoint(),null);
  // The same holds once it has a checkpoint of its own.
  const synced=make();await synced.updateTo('1');await assert.rejects(synced.importTrustedCheckpoint(signed,signed.block_hash),/CURRENT_TRUST_STILL_VALID/);assert.equal(synced.getCheckpoint().height,'1');
  assert.equal((await synced.updateTo('3')).block_hash,signed.block_hash);
});
test('an idle client re-reads the shared store before accepting a pasted checkpoint',async()=>{
  // Two tabs share one store. The first has been idle since before the genesis pin
  // expired; the second has stored a valid newer checkpoint in the meantime.
  const storage=new Storage();let time=fixture.now_ms;
  const idle=make({storage,now:()=>time});await idle.ready();assert.equal(idle.getCheckpoint(),null);
  time=fixture.refresh_now_ms;
  const active=make({storage,now:()=>time}),anchor=fixture.external_checkpoint;
  assert.equal((await active.importTrustedCheckpoint(anchor,anchor.block_hash)).height,'4');
  // Pasting anything into the idle tab now meets the stored anchor, not an empty one.
  const pasted=structuredClone(anchor);
  await assert.rejects(idle.importTrustedCheckpoint(pasted,pasted.block_hash),/CURRENT_TRUST_STILL_VALID/);
  assert.equal(JSON.parse([...storage.map.values()][0]).checkpoint.block_hash,anchor.block_hash);
  assert.equal(idle.getCheckpoint().block_hash,anchor.block_hash);
});
// A change of the protocol version (docs/design/upgrade-mechanism.md, section 8). The blocks are
// those of verifier-v4/fixtures/upgrade.json: heights 1 and 2 of version 4, 3 and 4 of version 5,
// 5 of version 6, and `lower`, a block 5 that claims version 4 again.
const upgrade=JSON.parse(await readFile(new URL('../verifier-v4/fixtures/upgrade.json',import.meta.url)));
await import('./time-sdk.js');
test('a stored checkpoint survives headers of a higher version, and the stored record keeps the first version',async()=>{
  const light=upgrade.light,blocks=new Map(light.blocks.map(block=>[block.signed_header.header.height,block]));
  assert.deepEqual(light.blocks.map(block=>block.signed_header.header.version.app),['4','4','5','5','6']);
  class Storage{map=new Map();getItem(k){return this.map.get(k)??null;}setItem(k,v){this.map.set(k,v);}}
  const storage=new Storage(),make=()=>createLightClient({trust:light.trust,verifier,storage,now:()=>light.now_ms,fetchBlock:async height=>structuredClone(blocks.get(height))});
  // Before the activation.
  const before=make();assert.equal((await before.updateTo('2')).height,'2');
  const stored=()=>JSON.parse([...storage.map.values()][0]);
  assert.equal(stored().appVersion,'4');assert.equal(stored().checkpoint.height,'2');
  // After it, the same wallet opened again: the checkpoint loads and advances to blocks of
  // versions this build does not implement, one by one and skipping.
  const after=make();assert.equal((await after.ready()).height,'2');
  assert.equal((await after.updateTo('3')).height,'3');assert.equal((await after.updateTo('5')).height,'5');
  assert.equal(stored().appVersion,'4','the stored value names the first version: changing it would make every wallet discard its checkpoint');
  assert.equal(stored().checkpoint.block.signed_header.header.version.app,'6');
  // Opened once more on the checkpoint of version 6.
  const again=make();assert.equal((await again.ready()).height,'5');assert.equal(again.getTrust().app_version,'4');
  // A header that goes back to a lower version is refused, and the checkpoint stays.
  const back=createLightClient({trust:light.trust,verifier,storage:new Storage(),now:()=>light.now_ms,fetchBlock:async height=>structuredClone(blocks.get(height))});
  assert.equal((await back.updateTo('4')).height,'4');
  await assert.rejects(back.updateToBlock(structuredClone(light.lower)),/lower than the trusted checkpoint/);assert.equal(back.getCheckpoint().height,'4');
  // The anchor itself is never reissued for a later version.
  assert.throws(()=>createLightClient({trust:{...light.trust,app_version:'5'},verifier,fetchBlock:async()=>null}),/independent V4 manifest/);
  assert.throws(()=>globalThis.TimeSDK.createClient({gateway:'https://rpc.example',trust:{...light.trust,app_version:'5'}}),/application-4 trust manifest/);
});
