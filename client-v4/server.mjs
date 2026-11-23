import http from 'node:http';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { readFile, writeFile, rename, open } from 'node:fs/promises';
import { createLoginService, createOrderService } from './server-auth.mjs';
import { fetchCertifiedView,fetchLightBlock } from './certified-view.mjs';
import './time-sdk.js';
import {createLightClient} from './light-client.mjs';
import * as installedVerifier from './proof-verifier.mjs';
import {createArchive} from './archive.mjs';
import {createOrderStore} from './order-store.mjs';
import {createBlogStore} from './blog-store.mjs';
import {ownNodeOptions,OWN_NODE_UNAVAILABLE,OWN_NODE_MISMATCH} from './own-node.mjs';

const SDK = globalThis.TimeSDK;
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.wasm': 'application/wasm', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml' };
const cookie = (request, name) => (request.headers.cookie || '').split(';').map(part => part.trim()).find(part => part.startsWith(name + '='))?.slice(name.length + 1) || '';
function cookieHeader(name,value,maxAge,secure){return `${name}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure?'; Secure':''}`;}
function requireOrigin(request, origin) { if (request.headers.origin !== origin) throw new Error('Request origin rejected'); }
function json(response, status, body, headers = {}) { response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers }); response.end(JSON.stringify(body)); }
async function body(request) {
  if (!/^application\/json(?:;|$)/i.test(request.headers['content-type'] || '')) throw new Error('Expected JSON content type');
  let size = 0; const chunks = [];
  for await (const chunk of request) { size += chunk.length; if (size > 768*1024) throw new Error('Request body exceeds 768 KiB'); chunks.push(chunk); }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

// The shop's price list: item name -> price in whole microseconds. The buyer's page names an
// item; the amount always comes from this list, never from the browser.
export function checkCatalog(catalog) {
  if (!catalog || typeof catalog !== 'object' || Array.isArray(catalog) || !Object.keys(catalog).length) throw Error('A catalog of item prices is required');
  for (const [item, amount] of Object.entries(catalog)) if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(item) || typeof amount !== 'string' || !/^[1-9][0-9]{0,18}$/.test(amount) || BigInt(amount) > 18446744073709551615n) throw Error('Catalog entries are item names with a price in whole microseconds');
  return Object.freeze({ ...catalog });
}
export function priceOf(catalog, item) {
  if (typeof item !== 'string' || !Object.hasOwn(catalog, item)) throw Error('Unknown item');
  return catalog[item];
}
// The answer to a refused request. An own-node refusal also carries its code, so the shop page
// can tell "retry later" (OWN_NODE_UNAVAILABLE) from "do not ship" (OWN_NODE_MISMATCH).
export function errorBody(error) {
  return { error: String(error?.message).slice(0, 240), ...(error?.code === OWN_NODE_UNAVAILABLE || error?.code === OWN_NODE_MISMATCH ? { code: error.code } : {}) };
}
export async function createV4Servers({ root, manifest, rpc, walletPort = 8907, merchantPort = 8908, recipient = '0', catalog = { 'test-purchase': '100000' }, checkpointPath, ordersPath, archivePath, onRegtestBid, onSponsorRegistration, registrationService, publicOrigins, onPorts, ownNode, upgradeCheck = {}, onUpgradeNotice = event => (event.level === 'error' ? console.error : console.warn)(JSON.stringify(event)) }) {
  // `registrationService`: the origin of a service that sponsors the registration of a new account, such as the
  // faucet of a test network (deploy/faucet/README.md, "Sponsored registrations"). The gateway holds no key for it
  // and never calls it: it only tells the wallet page where it is and lets that page connect there. HTTPS, or
  // plain HTTP on this machine's loopback address for tests.
  if(registrationService!==undefined){
    let u=null;try{u=new URL(registrationService);}catch{}
    // The value goes into the wallet page's Content-Security-Policy as written. A URL parser takes more than a
    // policy may hold: `https://*` (every https host), `https://*.example`, and a `;` or `,` in the name, which
    // would end the directive or the policy. So the name is checked letter by letter: labels of letters, digits
    // and hyphens, an optional port, nothing else.
    const plain=typeof registrationService==='string'&&(/^https:\/\/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?::[1-9][0-9]{0,4})?$/.test(registrationService)||/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(registrationService));
    if(!plain||!u||u.origin!==registrationService||u.username||u.password)throw Error('The registration service must be a canonical HTTPS origin');
  }
  if(publicOrigins!==undefined){
    if(!publicOrigins||typeof publicOrigins!=='object'||Object.keys(publicOrigins).sort().join(',')!=='merchant,wallet')throw Error('Explicit wallet and merchant public HTTPS origins are required');
    for(const role of ['wallet','merchant']){const value=publicOrigins[role],u=new URL(value);if(typeof value!=='string'||u.protocol!=='https:'||u.origin!==value||u.username||u.password)throw Error('Public origins must be canonical HTTPS origins');}
    if(publicOrigins.wallet===publicOrigins.merchant)throw Error('Wallet and merchant public origins must be distinct');
    publicOrigins={...publicOrigins};
  }
  catalog=checkCatalog(catalog);
  // When this server looks for a scheduled change of the protocol version (see checkUpgrade):
  // first `firstMs` after start, then every `everyMs`; everyMs 0 never looks by itself.
  if(!upgradeCheck||typeof upgradeCheck!=='object'||Array.isArray(upgradeCheck)||Object.keys(upgradeCheck).some(k=>!['firstMs','everyMs'].includes(k))||typeof onUpgradeNotice!=='function')throw Error('upgradeCheck takes firstMs and everyMs; onUpgradeNotice is a function');
  upgradeCheck={firstMs:60000,everyMs:600000,...upgradeCheck};
  for(const name of ['firstMs','everyMs'])if(!Number.isSafeInteger(upgradeCheck[name])||upgradeCheck[name]<0||upgradeCheck[name]>86400000)throw Error('upgradeCheck.'+name+' is a number of milliseconds from 0 to 86400000');
  const setCookie=(name,value,maxAge)=>cookieHeader(name,value,maxAge,Boolean(publicOrigins));
  const listeners={};
  const protocolVersion=String(manifest.trust?.app_version??'');
  if(protocolVersion!=='4')throw new Error('Unsupported independently pinned application version');
  // Whether this network's nodes answer the question about scheduled upgrades: from the pinned
  // trust data (`trust.nodes_report_upgrades`), never from what a node or gateway says. If they
  // do, every state this server verifies for a login or an order is asked with the question, so
  // the answer cannot be held or left out while the rest is served.
  const reportsUpgrades=SDK.nodesReportUpgrades(manifest.trust);
  // Optional second witness for large orders: the merchant's own full node (own-node.mjs), on
  // the network of the pinned manifest. It is reached directly, never through `rpc`: the light
  // client checks what `rpc` serves, but the own-node check must not depend on it.
  // The identity test below is a sanity check: a function that wraps `rpc` cannot be recognized.
  if(ownNode!==undefined){
    if(!ownNode||typeof ownNode!=='object'||Array.isArray(ownNode))throw Error('ownNode must be an object such as {url, aboveMicros}');
    if(ownNode.rpc!==undefined&&ownNode.rpc===rpc)throw Error('ownNode must reach your own full node directly, not through the gateway rpc');
    if(ownNode.chainId!==undefined&&ownNode.chainId!==manifest.trust.chain_id)throw Error('ownNode.chainId differs from the pinned manifest');
    ownNode={...ownNode,chainId:manifest.trust.chain_id};ownNodeOptions(ownNode);
  }
  const cookiePrefix=publicOrigins?'__Host-':'';const preloginCookie=`${cookiePrefix}time${protocolVersion}_${manifest.networkId}_prelogin`,sessionCookie=`${cookiePrefix}time${protocolVersion}_${manifest.networkId}_session`;
  let walletOrigin; let merchantOrigin; let network; 
  if(!checkpointPath||!ordersPath)throw Error("V4 requires durable checkpoint and order paths");
  const archive=await createArchive({directory:archivePath||checkpointPath+".archive",networkId:manifest.networkId});
  let checkpointWrites=Promise.resolve();
  const storage=checkpointPath?{
    getItem:async()=>{try{return await readFile(checkpointPath,'utf8');}catch(e){if(e.code==='ENOENT')return null;throw e;}},
    setItem:async(_,serialized)=>{checkpointWrites=checkpointWrites.catch(()=>{}).then(async()=>{const file=await open(checkpointPath+'.tmp','w',0o600);try{await file.writeFile(serialized);await file.sync();}finally{await file.close();}await rename(checkpointPath+'.tmp',checkpointPath);});await checkpointWrites;},
  }:undefined;
  const light=createLightClient({trust:manifest.trust,verifier:installedVerifier,storage,fetchBlock:height=>fetchLightBlock({rpc,height})});
  async function getStateProof(query={}){
    // Native and verifier independently enforce exact fields, counts and types.
    const arrays=['names','ids','public_keys','owners','candidates','epochs','blocks'],flags=['include_pos','include_bitcoin','include_policy','include_security','include_upgrade'];
    if(!query||typeof query!=='object'||Array.isArray(query)||Object.keys(query).some(k=>!arrays.includes(k)&&!flags.includes(k))||JSON.stringify(query).length>4096)throw Error('Invalid proof selection');
    for(const f of arrays)if(query[f]!==undefined&&(!Array.isArray(query[f])||query[f].length>({names:8,ids:8,public_keys:8,owners:16,candidates:16,epochs:8,blocks:16}[f])))throw Error('Proof selection exceeds limit');
    if((query.names?.length||0)+(query.ids?.length||0)+(query.public_keys?.length||0)>16)throw Error('Proof selection exceeds limit');
    for(const f of flags)if(query[f]!==undefined&&typeof query[f]!=='boolean')throw Error('Invalid proof flag');
    for(const n of query.names||[])if(typeof n!=='string'||!/^[a-z0-9_]{2,15}$/.test(n))throw Error('Invalid name');for(const k of query.public_keys||[])SDK.hexToBytes(k,32);for(const f of ['ids','owners','candidates','epochs','blocks'])for(const n of query[f]||[])SDK.decimal(n);if(query.blocks?.includes('0'))throw Error('Canonical history heights start at one');
    return fetchCertifiedView({rpc,selection:query});
  }
  async function verifyProof(proof,query){
    await light.ready();await light.updateToBlock(proof.light_block);
    return installedVerifier.verifyViewProof(proof,light.getTrust(),query);
  }
  // The action fee is a setting of the network's genesis (`fee_micros`, left out for the
  // protocol-4 fee) and never changes. /api/network reports it once this gateway has verified a
  // state, which carries the setting, and leaves it out until then (a gateway may start
  // serving before it has verified one, and a node that serves blocks only gives none).
  // Wallets do not depend on this report: the SDK takes the fee from the state it verifies
  // itself.
  let feeMicros;
  async function verifiedState(query={}){
    if(reportsUpgrades)query={...query,include_upgrade:true};
    let last;for(let attempt=0;attempt<4;attempt++)try{
      await light.ready();const proof=await getStateProof(query),checked=await verifyProof(proof,query);
      if(checked.verified!==true||checked.state.network_id!==manifest.networkId)throw Error('Independent V4 state verification failed');
      if(query.include_upgrade&&!Object.hasOwn(checked.state,'upgrade'))throw Error('The verified state lacks the upgrade entry that was asked for');
      feeMicros=SDK.networkFee(checked.state);return checked;
    }catch(error){last=error;if(!/ROLLBACK|CHECKPOINT_MISMATCH|LIGHT_UPDATE_BUDGET/.test(error.message))throw error;}throw last;
  }
  // ---- A coming change of the protocol version.
  // This server implements the protocol versions SDK.KNOWN_VERSIONS. Once the network runs a
  // later one, every login and every order fails with UPGRADE_REQUIRED (the verifier refuses the
  // state). So that this does not come as a surprise, the server reads the proven row
  // `upgrade/state` (never the node's own report) and warns while the validators have scheduled
  // a version it does not implement: first a minute after start, then every ten minutes.
  // Notices go to onUpgradeNotice (by default one JSON line on the error log):
  // - UPGRADE_SCHEDULED_NOT_IMPLEMENTED: install a release that implements the version before
  //   `activates_utc`;
  // - UPGRADE_REQUIRED: the network already runs a version this server does not implement;
  // - UPGRADE_STATUS_UNAVAILABLE: the plan could not be read (a node that predates the
  //   `include_upgrade` selection, or one that does not answer). Said once per reason: silence
  //   would look like "nothing is scheduled".
  const utcOf=micros=>{const ms=micros/1000n;return ms>8640000000000000n?'a time beyond the calendar':new Date(Number(ms)).toISOString();};
  let upgradeTimer,upgradeUnavailable='';
  const notify=event=>{try{onUpgradeNotice(event);}catch{}};
  async function checkUpgrade(){
    try{
      const checked=await verifiedState({include_upgrade:true}),status=SDK.upgradeStatusOf(checked.state);upgradeUnavailable='';
      if(status.scheduled&&!status.known){
        const plan=status.scheduled,starts=utcOf(BigInt(checked.state.genesis.genesis_time_micros)+BigInt(plan.activate_elapsed_micros));
        notify({event:'UPGRADE_SCHEDULED_NOT_IMPLEMENTED',level:'warn',version:plan.version,spec:plan.spec,activates_utc:starts,activate_elapsed_micros:plan.activate_elapsed_micros,implemented:[...SDK.KNOWN_VERSIONS],message:`The network has scheduled protocol version ${plan.version} (spec ${plan.spec}) for ${starts}. This server implements version ${SDK.KNOWN_VERSIONS.join(', ')}: from that time on it refuses every login and every order with UPGRADE_REQUIRED. Install a release that implements version ${plan.version} before then.`});
      }
      return status;
    }catch(error){
      if(SDK.isUpgradeRequired(error))notify({event:'UPGRADE_REQUIRED',level:'error',message:error.message});
      else{const reason=String(error?.message).slice(0,240);if(reason!==upgradeUnavailable){upgradeUnavailable=reason;notify({event:'UPGRADE_STATUS_UNAVAILABLE',level:'warn',reason,message:'This server could not read whether a change of the protocol version is scheduled. It will not warn before one until it can.'});}}
      throw error;
    }
  }
  function scheduleUpgradeCheck(ms){
    if(closed||!upgradeCheck.everyMs)return;
    upgradeTimer=setTimeout(async()=>{await checkUpgrade().catch(()=>{});scheduleUpgradeCheck(upgradeCheck.everyMs);},ms);upgradeTimer.unref?.();
  }
  // ---- Receipts that need only the transaction's own block to be final.
  // A watcher indexes the transactions of each new block while someone waits for a
  // receipt. The block's header is then tied by block hashes to a checkpoint this
  // gateway's light client verified, and the transaction to that header by a Merkle
  // proof built here. Nothing in the answer is trusted by the wallet: it repeats the
  // same verification with its own light client.
  // The watcher keeps the newest blocks in memory, bounded by count and by size, and
  // frees them when nobody has waited for a while.
  const FAST_HEADERS=16,RECENT_BLOCKS=64,RECENT_MIN=4,RECENT_BYTES=96*1024*1024,ZERO=Buffer.from([0]),ONE=Buffer.from([1]);
  const sha=bytes=>createHash('sha256').update(bytes).digest();
  // Background timers never keep the process alive, and stop when the gateway closes.
  const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms).unref?.());let closed=false;
  const recent=new Map();const watchers=new Set();let knownHeight=0n,scannedHeight=0n,recentBytes=0,watch=null;
  // Merkle tree of a block's transactions as CometBFT hashes it (RFC 6962): pairs are
  // hashed level by level and an odd last node moves up unchanged. Built once per
  // block, when a proof is first asked for.
  function levelsOf(block){
    if(!block.levels){
      const levels=[block.leaves];
      while(levels.at(-1).length>1){
        const below=levels.at(-1),above=[];
        for(let i=0;i+1<below.length;i+=2)above.push(sha(Buffer.concat([ONE,below[i],below[i+1]])));
        if(below.length%2)above.push(below.at(-1));
        levels.push(above);
      }
      block.levels=levels;
    }
    return block.levels;
  }
  function merkle(block,index){
    const levels=levelsOf(block),aunts=[];
    for(let depth=0,i=index;depth<levels.length-1;depth++,i>>=1){
      const level=levels[depth];
      // An odd last node has no sibling on this level.
      if(i===level.length-1&&level.length%2)continue;
      aunts.push(level[i^1]);
    }
    return {root:levels.at(-1)[0],aunts};
  }
  async function scan(height){
    const result=await rpc('/block',{height:height.toString()}),txs=result?.block?.data?.txs||[];
    if(String(result?.block?.header?.height)!==height.toString()||!Array.isArray(txs)||txs.length>20000)throw Error('Unexpected block answer');
    const index=new Map(),leaves=[];let bytes=0;
    txs.forEach((encoded,i)=>{const digest=sha(Buffer.from(encoded,'base64'));index.set(digest.toString('hex'),i);leaves.push(sha(Buffer.concat([ZERO,digest])));bytes+=encoded.length+200;});
    recent.set(height,{header:result.block.header,txs,index,leaves,bytes});recentBytes+=bytes;
    for(const [old,block] of recent){
      if(recent.size<=RECENT_MIN||recent.size<=RECENT_BLOCKS&&recentBytes<=RECENT_BYTES)break;
      recent.delete(old);recentBytes-=block.bytes;
    }
  }
  function startWatch(){
    if(watch)return;
    watch=(async()=>{
      // Keeps going for a few seconds after the last waiter, so a wallet that asks
      // right after sending still finds its block in memory.
      for(let idle=0;!closed&&(watchers.size||idle<200);idle=watchers.size?0:idle+1){
        try{
          const tip=BigInt((await rpc('/status')).sync_info.latest_block_height);
          if(scannedHeight===0n||tip>scannedHeight+BigInt(RECENT_BLOCKS))scannedHeight=tip>3n?tip-3n:0n;
          while(scannedHeight<tip){await scan(scannedHeight+1n);scannedHeight+=1n;}
          knownHeight=tip;
        }catch{}
        for(const waiter of [...watchers])if(knownHeight>waiter.above)waiter.done();
        await pause(25);
      }
      watch=null;recent.clear();recentBytes=0;scannedHeight=0n;
    })();
  }
  // Resolves at the next block after `above`, or at `until`, whichever comes first.
  const nextHeight=(above,until)=>new Promise(resolve=>{
    const waiter={above,done:()=>{clearTimeout(timer);watchers.delete(waiter);resolve();}};
    const timer=setTimeout(waiter.done,Math.max(0,until-Date.now()));
    watchers.add(waiter);startWatch();
  });
  function recentTx(hash){
    const key=hash.toLowerCase();
    for(const [height,block] of recent){
      const i=block.index.get(key);if(i===undefined)continue;
      const proof=merkle(block,i),raw=block.txs[i];
      return {hash:hash.toUpperCase(),height:height.toString(),index:i,tx:raw,proof:{root_hash:proof.root.toString('hex').toUpperCase(),data:raw,proof:{total:String(block.leaves.length),index:String(i),leaf_hash:block.leaves[i].toString('base64'),aunts:proof.aunts.map(a=>a.toString('base64'))}}};
    }
    return null;
  }
  // After a wallet was shown a payment in its block, the durable receipt (anchored in
  // canonical history, two blocks later) is fetched and archived in the background, so
  // the same receipt can still be served long after the block left memory, with or
  // without a transaction index on the node.
  const archiving=new Set();
  function archiveLater(hash){
    const key=hash.toUpperCase();if(archiving.has(key)||archiving.size>=256)return;archiving.add(key);
    (async()=>{for(const delay of [2000,6000,20000]){await pause(delay);if(closed)break;try{const proof=await getReceipt(key,{canonical:true});if(!proof.pending)break;}catch{}}archiving.delete(key);})();
  }
  // Returns null when the block is not final yet for this gateway, or too far below
  // its checkpoint for a short header chain (the canonical receipt then applies).
  async function fastReceipt(hash,tx,trustedHeight){
    await light.ready();
    const height=BigInt(tx.height),want=trustedHeight!==undefined&&trustedHeight>height?trustedHeight:height;
    let trust=light.getTrust();
    if(!trust.checkpoint||BigInt(trust.checkpoint.height)<want){
      // On success the checkpoint is exactly the verified block at `want`. On failure
      // (not served yet, or another request moved the checkpoint further) re-read it.
      try{trust={...trust,checkpoint:await light.updateTo(want.toString())};}catch{trust=light.getTrust();}
    }
    const checkpoint=trust.checkpoint;if(!checkpoint||BigInt(checkpoint.height)<height)return null;
    // A proof that ends below the asking wallet's own checkpoint is of no use to it.
    if(trustedHeight!==undefined&&BigInt(checkpoint.height)<trustedHeight)return null;
    const top=BigInt(checkpoint.height);if(top-height>=BigInt(FAST_HEADERS))return null;
    const headers=[];for(let h=height;h<top;h++)headers.push(recent.get(h)?.header||(await rpc('/header',{height:h.toString()})).header);
    headers.push(checkpoint.block.signed_header.header);
    const checked=await installedVerifier.verifyFastReceipt({tx,headers},trust);
    if(checked.verified!==true||checked.executionVerified!==true||checked.txHash.toLowerCase()!==hash.toLowerCase())throw Error('Receipt proof does not match the requested transaction');
    archiveLater(hash);
    return {fast:true,tx,headers,light_block:checkpoint.block};
  }
  // options.canonical: only the durable receipt anchored in canonical history (the default
  // for callers that do not ask for the one-block form).
  // options.trustedHeight: the asking wallet's checkpoint height, so the header chain ends at or above it.
  async function getReceipt(hash,options={}){
    let last;for(let attempt=0;attempt<4;attempt++)try{return await receiptProofOnce(hash,options);}catch(error){last=error;if(!/ROLLBACK|CHECKPOINT_MISMATCH|LIGHT_UPDATE_BUDGET/.test(error.message))throw error;}throw last;
  }
  // Answers as soon as the receipt exists, or with {pending:true} after waitMs.
  async function awaitReceipt(hash,waitMs,options){
    const until=Date.now()+waitMs;
    for(;;){
      const above=knownHeight,proof=await getReceipt(hash,options);
      if(!proof.pending||Date.now()>=until)return proof;
      await nextHeight(above,until);
    }
  }
  async function receiptProofOnce(hash,{canonical=false,trustedHeight}={}) {
    if (!/^[A-Fa-f0-9]{64}$/.test(hash)) throw new Error('Invalid transaction hash');
    // Any failure of the one-block form falls through to the canonical one or to "pending".
    if(!canonical){const seen=recentTx(hash);if(seen){const fast=await fastReceipt(hash,seen,trustedHeight).catch(()=>null);if(fast)return fast;}}
    // The transaction comes from the node's index if it keeps one, else from the blocks
    // this gateway has in memory, else from the archive of receipts it served before.
    let tx; let saved;try { tx = await rpc('/tx', { hash: '0x' + hash.toUpperCase(), prove: 'true' }); } catch { tx=recentTx(hash);if(!tx){saved=await archive.getReceipt(hash);if(!saved)return {pending:true,hash:hash.toUpperCase()};tx=saved.tx;} }
    if(!canonical&&!saved){const fast=await fastReceipt(hash,{hash:tx.hash,height:tx.height,index:tx.index,tx:tx.tx,proof:tx.proof},trustedHeight).catch(()=>null);if(fast)return fast;}
    let signed; let next;
    if(saved){signed={signed_header:saved.signed_header};next={signed_header:saved.next_signed_header};}else try { [signed, next] = await Promise.all([rpc('/commit', { height: tx.height }), rpc('/commit', { height: (BigInt(tx.height) + 1n).toString() })]); } catch { return { pending: true, hash: hash.toUpperCase() }; }
    const blocks=[tx.height,(BigInt(tx.height)+1n).toString()];
    const anchor=await getStateProof({blocks});
    if(BigInt(anchor.height)<BigInt(blocks[1]))return {pending:true,hash:hash.toUpperCase()};
    const proof={tx,signed_header:signed.signed_header,next_signed_header:next.signed_header,anchor};
    await light.ready();await light.updateToBlock(anchor.light_block);const bound=await installedVerifier.verifyReceipt(proof,light.getTrust());if(bound.txHash.toLowerCase()!==hash.toLowerCase())throw Error('Receipt proof does not match the requested transaction');
    const evidence={tx:{hash:tx.hash,height:tx.height,index:tx.index,tx:tx.tx,proof:tx.proof},signed_header:signed.signed_header,next_signed_header:next.signed_header};
    await archive.putReceipt(hash,evidence);return proof;
  }
  async function verifiedReceipt(hash){
    await light.ready();let last;
    for(let attempt=0;attempt<4;attempt++)try{
      const proof=await getReceipt(hash,{canonical:true});if(proof.pending)throw Error('Payment is awaiting canonical finality');
      await light.updateToBlock(proof.anchor.light_block);const checked=await installedVerifier.verifyReceipt(proof,light.getTrust());
      const raw=Buffer.from(checked.rawHex,'hex'),action=SDK.decodeAction(raw),computed=await SDK.transactionHash(raw);
      if(checked.verified!==true||checked.executionVerified!==true||checked.txHash.toUpperCase()!==computed||computed!==hash.toUpperCase()||action.networkId!==manifest.networkId)throw Error('Receipt verification failed');
      return {...checked,hash:computed,action,networkId:action.networkId,code:0};
    }catch(error){last=error;if(!/ROLLBACK|CHECKPOINT_MISMATCH/.test(error.message))throw error;}throw last;
  }
  let login; let orders;let orderRepository;let blog;let regtestBusy=false;const regtestLast=new Map();let sponsorQueue=Promise.resolve();const sponsorLast=new Map();
  async function chainRoute(request, response, url) {
    if (request.method === 'GET' && url.pathname === '/api/light-block') { await light.ready(); json(response,200,await fetchLightBlock({rpc,height:url.searchParams.get('height')||undefined}));return true; }
    if (request.method === 'GET' && url.pathname === '/api/network') { json(response, 200, { ...network, ...(feeMicros === undefined ? {} : { feeMicros }) }); return true; }
    if (request.method === 'GET' && url.pathname === '/api/view-proof') { const text = url.searchParams.get('query') || '{}'; if (text.length > 4096) throw new Error('Proof selection exceeds limit'); json(response, 200, await getStateProof(JSON.parse(text))); return true; }
    if(request.method==='GET'&&url.pathname==='/api/notifications'){const id=url.searchParams.get('account');SDK.decimal(id);const checked=await verifiedState({ids:[id]});const account=checked.state.accounts.find(a=>a.id===id);if(!account)throw Error('Unknown account');json(response,200,{...(await archive.observeAccount(account,checked.state)),proof:await getStateProof({ids:[id]})});return true;}
    if(request.method==='GET'&&url.pathname==='/api/archive/receipt'){json(response,200,await getReceipt(url.searchParams.get('hash')||'',{canonical:true}));return true;}
    if (request.method === 'GET' && url.pathname === '/api/receipt') {
      // fast=1: the caller can verify the one-block form. Without it the answer is the
      // canonical receipt, as before, so older wallets keep working.
      const wait=url.searchParams.get('wait')??'0',trusted=url.searchParams.get('trusted'),canonical=url.searchParams.get('canonical'),fast=url.searchParams.get('fast');
      if(!/^(0|[1-9][0-9]{0,3})$/.test(wait)||Number(wait)>8000||trusted!==null&&!/^[1-9][0-9]{0,18}$/.test(trusted)||canonical!==null&&canonical!=='1'||fast!==null&&fast!=='1')throw new Error('Invalid receipt request');
      json(response, 200, await awaitReceipt(url.searchParams.get('hash') || '',Number(wait),{canonical:canonical==='1'||fast!=='1',trustedHeight:trusted===null?undefined:BigInt(trusted)})); return true;
    }
    if(request.method==='POST'&&url.pathname==='/api/sponsor-registration'){
      requireOrigin(request,walletOrigin);if(typeof onSponsorRegistration!=='function'||network.sponsorAccount===undefined)throw Error('A funded registration sponsor is not configured');
      const p=await body(request);if(Object.keys(p).sort().join(',')!=='commitment,expires_elapsed_micros,proof,public_key')throw Error('Invalid sponsorship request');SDK.hexToBytes(p.public_key,32);SDK.hexToBytes(p.commitment,32);SDK.hexToBytes(p.proof,64);SDK.decimal(p.expires_elapsed_micros);
      const key=await crypto.subtle.importKey('raw',SDK.hexToBytes(p.public_key,32),'Ed25519',false,['verify']);
      if(!await crypto.subtle.verify('Ed25519',key,SDK.hexToBytes(p.proof,64),SDK.sponsorConsentBytes({networkId:manifest.networkId,sponsorAccount:network.sponsorAccount,publicKey:p.public_key,commitment:p.commitment,expiresElapsedMicros:p.expires_elapsed_micros})))throw Error('New device sponsorship consent is invalid');
      const operation=sponsorQueue.then(async()=>{
        const checked=await verifiedState({public_keys:[p.public_key],ids:[network.sponsorAccount]}),state=checked.state,elapsed=BigInt(state.time_micros)-BigInt(state.genesis.genesis_time_micros),expiry=BigInt(p.expires_elapsed_micros);
        if(expiry<=elapsed||expiry>elapsed+BigInt(state.config.registration.max_lifetime_micros))throw Error('Registration consent expiry is outside the freshly proved lifetime window');
        const current=state.name_commits?.find(c=>c.public_key===p.public_key&&BigInt(c.expires_elapsed_micros)>=elapsed);
        if(current){if(current.commitment!==p.commitment)throw Error('Another active commitment already exists for this device');return {alreadyCommitted:true};}
        const now=Date.now();for(const [pk,time]of sponsorLast)if(now-time>60000)sponsorLast.delete(pk);if(sponsorLast.size>=32||now-(sponsorLast.get(p.public_key)||0)<10000)throw Error('Local registration sponsor rate limit; retry later');sponsorLast.set(p.public_key,now);
        const result=await onSponsorRegistration(p);if(!result||!/^[a-f0-9]{64}$/i.test(result.hash||''))throw Error('Sponsor did not return a transaction hash');
        const receipt=await verifiedReceipt(result.hash),a=receipt.action;
        if(a.kind!==44||a.from!==network.sponsorAccount||a.payload.public_key!==p.public_key||a.payload.commitment!==p.commitment||a.payload.expires_elapsed_micros!==p.expires_elapsed_micros)throw Error('Sponsor receipt differs from approved registration consent');
        return {hash:receipt.hash};
      });sponsorQueue=operation.catch(()=>{});json(response,200,await operation);return true;
    }
    if(request.method==='POST'&&url.pathname==='/api/regtest-bid'){
      requireOrigin(request,walletOrigin);if(typeof onRegtestBid!=='function'||manifest.trust.app_version!=='4')throw Error('Bitcoin regtest earning is unavailable');
      const p=await body(request);if(Object.keys(p).sort().join(',')!=='account,epoch')throw Error('Invalid regtest bid request');SDK.decimal(p.account);SDK.decimal(p.epoch);
      const checked=await verifiedState({ids:[p.account],include_bitcoin:true,include_policy:true});
      if(checked.state.treasury.paused)throw Error('Treasury receiving is paused');if(checked.state.treasury.pending)throw Error('Treasury rotation is pending; wait for activation or cancellation before funding');
      if(!checked.state.accounts.some(a=>a.id===p.account)||checked.state.config.bitcoin.network!=='regtest')throw Error('Regtest account/network mismatch');
      const cfg=checked.state.config.auction,elapsed=BigInt(checked.state.time_micros)-BigInt(checked.state.genesis.genesis_time_micros),current=elapsed/(BigInt(cfg.epoch_seconds)*1000000n),target=BigInt(p.epoch);
      if(target<current+BigInt(cfg.bid_lead_epochs)||target>current+BigInt(cfg.max_future_epochs))throw Error('Earning target must be within the freshly proved future auction window');
      const now=Date.now();for(const [id,time]of regtestLast)if(now-time>60000)regtestLast.delete(id);
      if(regtestBusy||now-(regtestLast.get(p.account)||0)<30000||regtestLast.size>=128)throw Error('Regtest fixture rate limit; retry later');
      regtestBusy=true;regtestLast.set(p.account,now);try{json(response,200,await onRegtestBid({account:p.account,epoch:p.epoch}));}finally{regtestBusy=false;}return true;
    }
    if (request.method === 'POST' && url.pathname === '/api/submit') {
      requireOrigin(request, walletOrigin); const payload = await body(request);
      if (Object.keys(payload).join(',') !== 'tx' || typeof payload.tx !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(payload.tx)) throw new Error('Invalid signed transaction');
      const raw = Buffer.from(payload.tx, 'base64'); if (raw.length > 512*1024+512 || raw.length < 64 || raw.toString('base64') !== payload.tx) throw new Error('Invalid transaction encoding');
      const result = await rpc('/broadcast_tx_sync', { tx: '0x' + raw.toString('hex') });
      if (Number(result.code || 0)) throw new Error(result.log || 'Transaction rejected by CheckTx');
      json(response, 200, { hash: result.hash, pending: true }); return true;
    }
    return false;
  }
  async function merchantRoute(request, response, url) {
    if (request.method === 'GET' && url.pathname === '/api/config') { json(response, 200, { walletOrigin, networkId: manifest.networkId, recipient, catalog, publicLaunchAllowed: false }); return true; }
    if (request.method === 'POST' && url.pathname === '/api/login/challenge') {
      requireOrigin(request, merchantOrigin); await body(request); const issued = login.issue();
      json(response, 200, issued.challenge, { 'Set-Cookie': setCookie(preloginCookie, issued.cookie, 180) }); return true;
    }
    if (request.method === 'POST' && url.pathname === '/api/login/finish') {
      requireOrigin(request, merchantOrigin); const result = await login.finish(cookie(request, preloginCookie), await body(request));
      json(response, 200, { accountId: result.session.accountId, name: result.session.name, csrf: result.session.csrf }, { 'Set-Cookie': [setCookie(preloginCookie, '', 0), setCookie(sessionCookie, result.cookie, 3600)] }); return true;
    }
    if (request.method === 'GET' && url.pathname === '/api/session') { const current = await login.current(cookie(request, sessionCookie)); json(response, 200, current ? { accountId: current.session.accountId, name: current.account.name, balance: current.account.balance, height: current.height, csrf: current.session.csrf, supporter: orderRepository.paidBy(current.session.accountId) } : { signedIn: false }); return true; }
    // The demo blog (web-v4/merchant, posts in blog-store.mjs). Reading is public; publishing and deleting
    // need a session and pass the same checks as an order, below.
    if (request.method === 'GET' && url.pathname === '/api/posts') {
      const before = url.searchParams.get('before');
      if ([...url.searchParams.keys()].some(key => key !== 'before')) throw new Error('Invalid posts request');
      const page = blog.list(before === null ? {} : { before }), mark = supporterMark();
      json(response, 200, { posts: page.posts.map(mark), more: page.more, limits: blogLimits() }); return true;
    }
    if (request.method === 'POST' && ['/api/logout', '/api/order', '/api/order/settle', '/api/posts', '/api/posts/delete'].includes(url.pathname)) {
      requireOrigin(request, merchantOrigin); const current = await login.current(cookie(request, sessionCookie)); if (!current) { json(response, 401, { error: 'Sign in first' }); return true; }
      login.checkCsrf(current.session, request.headers['x-csrf-token']); const payload = await body(request);
      if (url.pathname === '/api/logout') { login.logout(cookie(request, sessionCookie)); json(response, 200, { ok: true }, { 'Set-Cookie': setCookie(sessionCookie, '', 0) }); }
      else if (url.pathname === '/api/order') json(response, 200, await orders.issue(current.session.accountId, priceOf(catalog, payload.item)));
      else if (url.pathname === '/api/order/settle') json(response, 200, await orders.fulfill(current.session.accountId, payload.orderId, payload.hash));
      else {
        const only = key => { if (!payload || typeof payload !== 'object' || Array.isArray(payload) || Object.keys(payload).join(',') !== key) throw new Error(`Expected a JSON object with the one field "${key}"`); };
        // A refusal of the blog store carries its HTTP status: 429 for the limit per account, 403 and 404 for a delete.
        try {
          // The author is the account of the verified session, with the name the chain gives it.
          if (url.pathname === '/api/posts') { only('text'); json(response, 200, { post: supporterMark()(blog.publish({ accountId: current.session.accountId, name: current.account.name, text: payload.text })) }); }
          else { only('id'); json(response, 200, blog.remove({ accountId: current.session.accountId, id: payload.id })); }
        } catch (error) { if (!error?.httpStatus) throw error; json(response, error.httpStatus, errorBody(error)); }
      }
      return true;
    }
    return false;
  }
  // The blog's "supporter" mark: an account with an order this server settled, which it does only after it
  // verified the payment (server-auth.mjs, fulfill). Asked once per account for a list.
  function supporterMark() { const known = new Map(); return post => { if (!known.has(post.accountId)) known.set(post.accountId, orderRepository.paidBy(post.accountId)); return { ...post, supporter: known.get(post.accountId) }; }; }
  const blogLimits = () => ({ maxChars: blog.limits.maxChars, perAccount: blog.limits.perAccount, hours: blog.limits.windowMs / 3600000, keep: blog.limits.keep });
  async function serveStatic(response, url, role) {
    let pathname = decodeURIComponent(url.pathname); let location; let allowedBase;
    if (pathname.includes('\\') || pathname.includes('\0')) { json(response, 404, { error: 'Not found' }); return; }
    if (role === 'wallet' && pathname.startsWith('/wallet/')) pathname = pathname.slice('/wallet'.length);
    if(pathname==='/trust-manifest.json'&&role==='wallet'){json(response,200,manifest.trust);return;}
    if (pathname === '/sdk/proof-verifier.js') { allowedBase = path.join(root, 'client-v4'); location = path.join(allowedBase, 'proof-verifier.mjs'); }
    else if (pathname === '/sdk/time-sdk.js') { allowedBase = path.join(root, 'client-v4'); location = path.join(allowedBase, 'time-sdk.js'); }
    else if (pathname==='/sdk/light-client.mjs') {allowedBase=path.join(root,'client-v4');location=path.join(allowedBase,'light-client.mjs');}
    else if (pathname==='/sdk/account-security.mjs') {allowedBase=path.join(root,'client-v4');location=path.join(allowedBase,'account-security.mjs');}
    else if (pathname.startsWith('/sdk/')) { json(response, 404, { error: 'Not found' }); return; }
    else if (pathname.startsWith('/web-v4/shared/')) { allowedBase = path.join(root, 'web-v4', 'shared'); location = path.resolve(root, '.' + pathname); }
    else { if (pathname === '/' || pathname === '/approve') pathname = '/index.html'; allowedBase = path.join(root, 'web-v4', role); location = path.resolve(allowedBase, '.' + pathname); }
    if (!location.startsWith(allowedBase + path.sep) || !MIME[path.extname(location)] || path.extname(location) === '.json' && allowedBase !== path.join(root, 'web-v4', 'shared')) { json(response, 404, { error: 'Not found' }); return; }
    // Server modules and their security tests are never exposed as browser assets.
    if (location.includes(path.sep + 'tests' + path.sep) || location.endsWith('.test.mjs')) { json(response, 404, { error: 'Not found' }); return; }
    try { const content = await readFile(location); response.writeHead(200, { 'Content-Type': MIME[path.extname(location)] }); response.end(content); } catch (error) { if (error.code !== 'ENOENT') throw error; json(response, 404, { error: 'Not found' }); }
  }
  const servers = [];
  async function start(role, preferred) {
    const rates = new Map(); let origin;
    const server = http.createServer(async (request, response) => {
      response.setHeader('Cache-Control', 'no-store'); response.setHeader('X-Content-Type-Options', 'nosniff'); response.setHeader('Referrer-Policy', 'no-referrer'); response.setHeader('X-Frame-Options', 'DENY'); response.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
      // The wallet page may connect to its own origin and, when one is configured, to the registration service.
      response.setHeader('Content-Security-Policy', `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'${role === 'wallet' && registrationService ? ' ' + registrationService : ''}; img-src 'self' data:; font-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`);
      try {
        if (request.headers.host !== new URL(origin).host || request.socket.remoteAddress !== '127.0.0.1') { json(response, 403, { error: 'Loopback host rejected' }); return; }
        if (!['GET', 'POST'].includes(request.method)) { json(response, 405, { error: 'Method not allowed' }); return; }
        if (request.headers.origin && request.headers.origin !== origin) { json(response, 403, { error: 'Cross-origin request rejected' }); return; }
        const second = Math.floor(Date.now() / 1000); const count = (rates.get(second) || 0) + 1; rates.clear(); rates.set(second, count); if (count > 50) { json(response, 429, { error: 'Local request limit reached' }); return; }
        const url = new URL(request.url, origin);
        if (role === 'wallet' && await chainRoute(request, response, url)) return;
        if (role === 'merchant' && await merchantRoute(request, response, url)) return;
        if (url.pathname.startsWith('/api/')) { json(response, 404, { error: 'Unknown API route' }); return; }
        if (request.method !== 'GET') { json(response, 405, { error: 'Method not allowed' }); return; }
        await serveStatic(response, url, role);
      } catch (error) { if (!response.headersSent) json(response, 400, errorBody(error)); else response.destroy(); }
    });
    server.requestTimeout = 10000; server.headersTimeout = 5000; server.maxRequestsPerSocket = 100;
    async function listen(port) { await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); }); }); }
    try { await listen(preferred); } catch (error) { if (error.code !== 'EADDRINUSE'||publicOrigins) throw error; await listen(0); }
    listeners[role]=`http://127.0.0.1:${server.address().port}`;origin=publicOrigins?.[role]||listeners[role];servers.push(server);return origin;
  }
  const close=async()=>{closed=true;clearTimeout(upgradeTimer);for(const waiter of [...watchers])waiter.done();await Promise.all(servers.map(server=>new Promise(resolve=>{server.close(resolve);server.closeAllConnections();})));orderRepository?.close();orderRepository=undefined;blog?.close();blog=undefined;};
  try {
    walletOrigin = await start('wallet', walletPort); merchantOrigin = await start('merchant', merchantPort);
    network = { ...manifest, ...(typeof onSponsorRegistration==='function'?{sponsorAccount:String(manifest.sponsorAccount??'0')}:{ }),...(registrationService?{registrationService}:{}),walletOrigin, merchantOrigin, protocolVersion, mode: 'local-devnet', publicLaunchAllowed: false, transport:publicOrigins?'explicit-https-proxy':'literal-loopback',trustModel:'Dynamic voting-power light client with independently installed genesis/checkpoint. Private development network, not independent production operators.' };
    login = createLoginService({ origin: merchantOrigin, networkId: manifest.networkId, verifiedState });
    let initialOrders;
    if (ordersPath) { try { initialOrders = JSON.parse(await readFile(ordersPath, 'utf8')); } catch (error) { if (error.code !== 'ENOENT') throw error; } }
    orderRepository=createOrderStore({filename:ordersPath+'.sqlite',networkId:manifest.networkId,recipient});
    // The demo blog's posts, beside the orders: the path is derived from ordersPath as the orders database's is.
    blog=createBlogStore({filename:ordersPath+'.blog.sqlite',networkId:manifest.networkId});
    orders = createOrderService({ repository:orderRepository,networkId: manifest.networkId, protocolVersion,verifiedState,recipient, verifiedReceipt, ownNode, initialState: initialOrders, persist: ordersPath ? async snapshot => {
      const file = await open(ordersPath + '.tmp', 'w', 0o600);
      try { await file.writeFile(JSON.stringify(snapshot)); await file.sync(); } finally { await file.close(); }
      await rename(ordersPath + '.tmp', ordersPath);
    } : async () => { throw new Error('Durable order storage is not configured'); } });
    await onPorts?.({ walletOrigin, merchantOrigin,walletListenOrigin:listeners.wallet,merchantListenOrigin:listeners.merchant });
    scheduleUpgradeCheck(upgradeCheck.firstMs);
    return { walletOrigin, merchantOrigin,walletListenOrigin:listeners.wallet,merchantListenOrigin:listeners.merchant, nodesReportUpgrades:reportsUpgrades, getStateProof, verifiedState, verifiedView: verifiedState, getReceipt, verifiedReceipt, checkUpgrade, close };
  } catch (error) { await close(); throw error; }
}
