// Capture public fixtures from an explicitly selected loopback rehearsal.
// No signing keys, vaults, passwords or Bitcoin Core credentials are read.
import {mkdir,writeFile} from 'node:fs/promises';import path from 'node:path';
import {createLightClient} from './light-client.mjs';import * as verifier from './proof-verifier.mjs';
const gateway=process.argv[2]||'http://127.0.0.1:8907',destination=path.resolve(process.argv[3]||'verifier-v4/fixtures'),receiptHash=process.argv[4];
if(new URL(gateway).hostname!=='127.0.0.1')throw Error('Public fixture capture accepts only literal loopback');
async function request(route){const response=await fetch(gateway+route,{cache:'no-store',redirect:'error'}),value=await response.json();if(!response.ok||value.error)throw Error(value.error||'HTTP '+response.status);return value;}
const trust=await request('/trust-manifest.json'),light=createLightClient({trust,fetchBlock:height=>request('/api/light-block'+(height?'?height='+height:'')),verifier});
const selection={public_keys:['ff'.repeat(32)],ids:['0'],names:['fixture_absent'],include_pos:true,include_bitcoin:true,include_policy:true};
const proof=await request('/api/view-proof?query='+encodeURIComponent(JSON.stringify(selection)));await light.updateToBlock(proof.light_block);let now=Date.now();await verifier.verifyViewProof(proof,light.getTrust(),selection,now);
await mkdir(destination,{recursive:true});await writeFile(path.join(destination,'live-view.json'),JSON.stringify({proof,trust:light.getTrust(),request:selection,now_ms:now,pinSource:'Locally installed rehearsal manifest; same-machine evidence, not independent operators.'},null,2));
if(receiptHash){const receipt=await request('/api/receipt?hash='+receiptHash);if(receipt.pending)throw Error('Receipt not yet canonically anchored');await light.updateToBlock(receipt.anchor.light_block);now=Date.now();await verifier.verifyReceipt(receipt,light.getTrust(),now);await writeFile(path.join(destination,'live-receipt.json'),JSON.stringify({proof:receipt,trust:light.getTrust(),now_ms:now},null,2));}
console.log(JSON.stringify({verified:true,stateHeight:proof.height,checkpointHeight:light.getCheckpoint().height,capturedReceipt:Boolean(receiptHash)}));
