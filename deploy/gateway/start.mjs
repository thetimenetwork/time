#!/usr/bin/env node
// Independent gateway process. No validator, sponsor or Bitcoin signing keys.
import{readFile,mkdir,open,unlink}from'node:fs/promises';import{createHash}from'node:crypto';import path from'node:path';import{fileURLToPath}from'node:url';
import{createV4Servers}from'../../client-v4/server.mjs';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
// Optional own_node: the merchant's own full node, which must also report a payment committed
// before an order from above_micros on settles (client-v4/own-node.mjs). A literal-loopback
// origin like native_rpc_url (a tunnel for another machine), and never native_rpc_url itself:
// the light client checks what that endpoint serves, the own-node check must not depend on it.
function validateOwnNode(own,nativeRpcUrl){
 if(!own||typeof own!=='object'||Array.isArray(own)||Object.keys(own).some(k=>!['rpc_url','above_micros','timeout_ms'].includes(k)))throw Error('own_node takes rpc_url, above_micros and timeout_ms');
 let url=null;try{url=new URL(own.rpc_url);}catch{}
 if(typeof own.rpc_url!=='string'||url?.protocol!=='http:'||url.hostname!=='127.0.0.1'||!url.port||Number(url.port)===0||url.origin+'/'!==url.href||url.href!==own.rpc_url)throw Error('own_node.rpc_url must be an explicit literal-loopback HTTP origin');
 if(own.rpc_url===nativeRpcUrl)throw Error('own_node.rpc_url must reach your own full node directly, not the native RPC the light client checks');
 if(own.above_micros!==undefined&&(typeof own.above_micros!=='string'||!/^(?:0|[1-9][0-9]{0,19})$/.test(own.above_micros)||BigInt(own.above_micros)>18446744073709551615n))throw Error('own_node.above_micros must be a canonical decimal amount of microseconds');
 if(own.timeout_ms!==undefined&&(!Number.isInteger(own.timeout_ms)||own.timeout_ms<100||own.timeout_ms>60000))throw Error('own_node.timeout_ms must be an integer from 100 to 60000');
}
export function ownNodeOption(settings){const own=settings.own_node;return own===undefined?undefined:{url:own.rpc_url,...(own.above_micros===undefined?{}:{aboveMicros:own.above_micros}),...(own.timeout_ms===undefined?{}:{timeoutMs:own.timeout_ms})};}
export function validateSettings(settings){
 const keys=['manifest_file','manifest_sha256','native_rpc_url','data_directory','recipient','wallet_port','merchant_port','public_origins','own_node','registration_service'];if(!settings||Object.keys(settings).some(k=>!keys.includes(k)))throw Error('Unsupported gateway setting; signing callbacks are forbidden');
 if(!path.isAbsolute(settings.manifest_file??'')||!/^[a-f0-9]{64}$/.test(settings.manifest_sha256??''))throw Error('Independently pinned manifest path/hash required');
 const rpc=new URL(settings.native_rpc_url);if(rpc.protocol!=='http:'||rpc.hostname!=='127.0.0.1'||!rpc.port||Number(rpc.port)===0||rpc.origin+'/'!==rpc.href||rpc.href!==settings.native_rpc_url)throw Error('Native RPC must be an explicit literal-loopback HTTP origin');
 if(!path.isAbsolute(settings.data_directory??'')||path.resolve(settings.data_directory)!==settings.data_directory)throw Error('Explicit canonical durable gateway data directory required');
 if(typeof settings.recipient!=='string'||! /^(?:0|[1-9][0-9]{0,19})$/.test(settings.recipient)||BigInt(settings.recipient)>=18446744073709551615n)throw Error('Canonical merchant recipient required');
 for(const name of ['wallet_port','merchant_port'])if(!Number.isInteger(settings[name])||settings[name]<1024||settings[name]>65535)throw Error('Fixed nonprivileged loopback port required');if(settings.wallet_port===settings.merchant_port)throw Error('Wallet and merchant listeners must differ');
 if(!settings.public_origins||Object.keys(settings.public_origins).sort().join(',')!=='merchant,wallet')throw Error('Explicit wallet and merchant HTTPS origins required');for(const origin of Object.values(settings.public_origins)){const url=new URL(origin);if(url.protocol!=='https:'||url.origin!==origin||url.username||url.password)throw Error('Canonical HTTPS origins required');}if(settings.public_origins.wallet===settings.public_origins.merchant)throw Error('Wallet and merchant origins must differ');
 if(settings.own_node!==undefined)validateOwnNode(settings.own_node,settings.native_rpc_url);
 // Optional: the origin of a service that sponsors the registration of a new account (a test network's faucet).
 // The gateway holds no key for it and never calls it; the wallet page is told where it is and may connect there.
 if(settings.registration_service!==undefined){let url=null;try{url=new URL(settings.registration_service);}catch{}if(typeof settings.registration_service!=='string'||!/^https:\/\/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?::[1-9][0-9]{0,4})?$/.test(settings.registration_service)||!url||url.protocol!=='https:'||url.origin!==settings.registration_service||url.username||url.password)throw Error('registration_service must be a canonical HTTPS origin');if(Object.values(settings.public_origins).includes(settings.registration_service))throw Error('registration_service must not be the wallet or the merchant origin');}
 return settings;
}
export function rpcAdapter(origin,fetchImpl=fetch){const allowed=new Set(['/commit','/validators','/abci_query','/tx','/broadcast_tx_sync','/status','/block','/header']);return async(method,parameters={})=>{if(!allowed.has(method))throw Error('RPC method not allowed by gateway adapter');const url=new URL(method,origin);for(const[key,value]of Object.entries(parameters)){if(typeof value!=='string')throw Error('Canonical RPC string parameter required');url.searchParams.set(key,value);}const response=await fetchImpl(url,{redirect:'error',signal:AbortSignal.timeout(10000)});if(!response.ok)throw Error('Private RPC HTTP failure');let size=0;const chunks=[];for await(const chunk of response.body){size+=chunk.length;if(size>8*1024*1024)throw Error('Private RPC response exceeds bound');chunks.push(chunk);}const result=JSON.parse(Buffer.concat(chunks).toString());if(result.error||!result.result)throw Error('Private RPC rejected request');return result.result;};}
export async function claimDirectory(directory){await mkdir(directory,{recursive:true,mode:0o700});const file=path.join(directory,'gateway-process.lock');let handle;try{handle=await open(file,'wx',0o600);}catch(error){if(error.code==='EEXIST')throw Error('Gateway data directory already claimed; stop the former process and verify the checkpoint before removing its lock');throw error;}await handle.writeFile(JSON.stringify({pid:process.pid,scope:'single-host-gateway-state'}));let released=false;return async()=>{if(released)return;await handle.close();await unlink(file);released=true;};}
// What the process prints once it serves: the ready line, and a warning when the pinned manifest's trust data does
// not say that the network's nodes report upgrades (trust.nodes_report_upgrades). Without that statement the states
// this server verifies do not carry the question about scheduled upgrades, and the wallets it serves ask it apart
// from their reads: the weaker way, which must not be chosen silently.
export function startReport(server){
 const declared=server.nodesReportUpgrades===true;
 return {ready:{status:'PRIVATE_HTTPS_PROXY_UPSTREAMS_READY',wallet:server.walletListenOrigin,merchant:server.merchantListenOrigin,public_funds_allowed:false,signing_callbacks:false,nodes_report_upgrades:declared},
  warning:declared?null:{event:'UPGRADE_REPORTS_NOT_DECLARED',level:'warn',message:"The pinned manifest does not say that this network's nodes report upgrades (trust.nodes_report_upgrades is not true). The states this server verifies do not carry the question about scheduled upgrades, and wallets that install this trust data ask it apart from their reads, where a gateway can leave it unanswered. If the nodes are time-node-v5 0.7.0 or later, pin a manifest whose trust data says so."}};
}
export async function start(settings){
 validateSettings(settings);if(process.version!=='v26.13.0')throw Error('This candidate requires tested Node26.13.0');
 const bytes=await readFile(settings.manifest_file);if(hash(bytes)!==settings.manifest_sha256)throw Error('Independently pinned manifest hash mismatch');const manifest=JSON.parse(bytes);
 if(String(manifest.trust?.app_version)!=='4'||manifest.trust.chain_id?.startsWith('time-devnet-v4-')!==true||manifest.networkId!==manifest.trust.network_id)throw Error('Pinned protocol4 private devnet manifest required');
 const release=await claimDirectory(settings.data_directory);let server;
 try{
  server=await createV4Servers({root:fileURLToPath(new URL('../../',import.meta.url)),manifest,rpc:rpcAdapter(settings.native_rpc_url),walletPort:settings.wallet_port,merchantPort:settings.merchant_port,recipient:settings.recipient,checkpointPath:path.join(settings.data_directory,'checkpoint.json'),ordersPath:path.join(settings.data_directory,'orders.json'),archivePath:path.join(settings.data_directory,'archive'),publicOrigins:settings.public_origins,ownNode:ownNodeOption(settings),...(settings.registration_service?{registrationService:settings.registration_service}:{})});
  if(server.walletListenOrigin!==`http://127.0.0.1:${settings.wallet_port}`||server.merchantListenOrigin!==`http://127.0.0.1:${settings.merchant_port}`)throw Error('A requested fixed proxy upstream was unavailable; refused fallback ports');
  await server.verifiedState({});let closing;
  return {...server,close:()=>closing??=(async()=>{await server.close();await release();})()};
 }catch(error){await server?.close();await release();throw error;}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){(async()=>{if(process.argv.length!==3)throw Error('Usage: node deploy/gateway/start.mjs SETTINGS_JSON');const server=await start(JSON.parse(await readFile(process.argv[2],'utf8'))),report=startReport(server);console.log(JSON.stringify(report.ready));if(report.warning)console.error(JSON.stringify(report.warning));let closing=false;const close=async()=>{if(closing)return;closing=true;await server.close();};process.once('SIGTERM',close);process.once('SIGINT',close);})().catch(error=>{console.error(error.message);process.exitCode=1;});}
