// Offline operator action: the expected hash must come from an independently
// authenticated channel. This tool never contacts an RPC or discovers a pin.
import {readFile,open,rename} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {createLightClient} from './light-client.mjs';import * as verifier from './proof-verifier.mjs';
export async function refreshCheckpoint({manifest,checkpoint,expectedHash,output,now=Date.now}){
 if(!output)throw Error('Explicit checkpoint storage output is required');
 const trust=manifest.trust||manifest;
 const storage={getItem:async()=>{try{return await readFile(output,'utf8');}catch(e){if(e.code==='ENOENT')return null;throw e;}},setItem:async(_,text)=>{const f=await open(output+'.refresh.tmp','wx',0o600);try{await f.writeFile(text);await f.sync();}finally{await f.close();}await rename(output+'.refresh.tmp',output);}};
 const client=createLightClient({trust,storage,verifier,now,fetchBlock:async()=>{throw Error('Offline checkpoint refresh must never query RPC');}});
 return client.importTrustedCheckpoint(checkpoint,expectedHash);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const option=name=>{const i=process.argv.indexOf(name);if(i<0||!process.argv[i+1])throw Error('Required '+name);return process.argv[i+1];};
 try{const manifest=JSON.parse(await readFile(option('--manifest'),'utf8')),file=JSON.parse(await readFile(option('--checkpoint'),'utf8'));const checked=await refreshCheckpoint({manifest,checkpoint:file.checkpoint||file,expectedHash:option('--independent-hash'),output:option('--output')});console.log(JSON.stringify({verified:true,height:checked.height,blockHash:checked.block_hash,networkId:(manifest.trust||manifest).network_id}));}catch(e){console.error(String(e.message));process.exitCode=1;}
}
