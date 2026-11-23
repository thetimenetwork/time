#!/usr/bin/env node
import{spawn}from'node:child_process';import{readFile,writeFile,mkdir,open,lstat,unlink,link,readdir,rename}from'node:fs/promises';import path from'node:path';import{fileURLToPath}from'node:url';import{randomUUID}from'node:crypto';
import{json,sha256,hex32,signed,validateRelease,exactU64,imagePin,releaseEngine,ENGINES}from'./lib.mjs';
const scalar=value=>JSON.stringify(value);
// Every key an operator settings file may hold. Anything else is refused by the guard, before
// anything starts: a mistyped optional setting (stop_after_height in a coordinated stop, say)
// must not pass as if it were not there.
export const SETTINGS_KEYS=Object.freeze(['release_manifest','release_id','genesis_file','genesis_sha256','chain_id','validator_public_key_hex','signer_identity','signer_lease_file','trust_file','sentry_peers','snapshot_seconds','clock_tolerance_seconds','state_sync_snapshot_blocks','state_sync_snapshots_kept','state_sync_max_mib','keep_blocks','stop_after_height']);
export function checkSettingsKeys(settings){
 if(!settings||typeof settings!=='object'||Array.isArray(settings))throw new Error('Operator settings are a JSON object');
 const unknown=Object.keys(settings).filter(key=>!SETTINGS_KEYS.includes(key));
 if(unknown.length)throw new Error('Unknown operator setting'+(unknown.length>1?'s':'')+': '+unknown.map(key=>JSON.stringify(key.slice(0,64))).join(', ')+'. Check the spelling; the settings are '+SETTINGS_KEYS.join(', '));
 return settings;
}
// `now` is for tests. Without it the lease is judged against the clock as it reads AFTER the files were read
// and hashed, not as it read when the guard was called: a guard that takes long must not answer "valid" for
// a lease that ended while it worked.
export async function guard(settings,now){
 checkSettingsKeys(settings);
 const manifest=validateRelease(await json(settings.release_manifest));if(settings.release_id!==manifest.release_id)throw new Error('Pinned release identity mismatch');const engine=releaseEngine(manifest);appCommand(engine,settings);hex32(settings.genesis_sha256);hex32(settings.validator_public_key_hex);
 const bytes=await readFile(settings.genesis_file);if(sha256(bytes)!==settings.genesis_sha256)throw new Error('Genesis hash mismatch');const genesis=JSON.parse(bytes);
 if(!/^time-devnet-v4-[A-Za-z0-9_-]+$/.test(settings.chain_id??'')||genesis.chain_id!==settings.chain_id||genesis.app_state?.ledger?.chain_id!==settings.chain_id||genesis.app_state?.bitcoin?.mainnet_receipts_enabled!==false)throw new Error('Pinned nonmonetary v4 genesis required');
 if(!genesis.app_state.validators.some(v=>v.consensus_key===settings.validator_public_key_hex))throw new Error('Operator consensus key absent from genesis');
 if(!Array.isArray(settings.sentry_peers)||settings.sentry_peers.length<2||settings.sentry_peers.length>16||new Set(settings.sentry_peers.map(p=>p.split('@')[0])).size!==settings.sentry_peers.length||!settings.sentry_peers.every(p=>/^[0-9a-f]{40}@[a-zA-Z0-9.:-]+:[0-9]{1,5}$/.test(p)&&Number(p.split(':').at(-1))>0&&Number(p.split(':').at(-1))<=65535))throw new Error('Two to sixteen distinct pinned sentry peers required');
 const trust=await json(settings.trust_file),lease=await json(settings.signer_lease_file);const result=signed(lease,trust,{kind:'signer_lease',release_id:settings.release_id,genesis_sha256:settings.genesis_sha256,chain_id:settings.chain_id,validator_public_key_hex:settings.validator_public_key_hex,signer_identity:settings.signer_identity,engine:engine==='v4'?undefined:engine},now??Date.now());
 if(result.payload.enforcement!=='EVERY_SIGNATURE'||typeof result.payload.fence_domain!=='string'||!result.payload.fence_domain||typeof result.payload.lease_id!=='string'||!result.payload.lease_id)throw new Error('Per-signature fencing enforcement attestation required');exactU64(result.payload.fence_token);
 if(Date.parse(result.payload.expires_utc)-Date.parse(result.payload.issued_utc)>300000)throw new Error('Signer lease lifetime must not exceed five minutes');return{manifest,genesis,genesis_bytes:bytes,lease:result.payload,engine};
}
// The engine comes from the pinned release. v4 output is byte-identical to the pre-v5 kit.
// CometBFT 0.38 prunes blocks only when the application returns a retain_height;
// time-node-v5 returns 0 unless keep_blocks is set, and then never asks for a block
// after its oldest snapshot to go, so the blocks it replays after a snapshot stay.
// discard_abci_responses = false is load-bearing for upgrades: after a crash between
// the application's commit of a block and CometBFT's own, the restart handshake replays
// the stored FinalizeBlock answer of that block. At the block that activates a new
// protocol version that answer carries the new version; without it CometBFT would build
// the next header with the old one. Never set it to true.
// CometBFT 0.38.26 (`cometbft start`, node.DefaultNewNode) loads or GENERATES a file validator key at every start,
// before it sees priv_validator_laddr, and panics when it cannot write that file. The v4 paths below are on the
// read-only /operator mount, so a v4 CometBFT panics at start (a finding of the kit rehearsal; v4 output stays
// byte-identical). The v5 configuration names a path on the validator container's tmpfs instead: CometBFT writes a
// random key there that is in no genesis, is never used (the remote signer on priv_validator_laddr replaces it) and
// is gone when the container ends. It is never on /operator or on a volume.
export const V5_UNUSED_PRIVVAL=Object.freeze({key:'/tmp/cometbft-0.38-unused-generated-priv-validator-key.json',state:'/tmp/cometbft-0.38-unused-generated-priv-validator-state.json'});
// double_sign_check_height = 100: before CometBFT 0.38 joins consensus it looks for a signature of its own key in the
// last 100 blocks and panics if it finds one (consensus/state.go, checkDoubleSigningRisk), so that one key never runs
// on two machines. `resume` (a resume order the launcher found applicable, below) turns that look off for the one start
// that order is for: after a stop of the whole chain every validator signed the last blocks, no block comes, and with
// the look on no validator could start again.
export const DOUBLE_SIGN_CHECK_HEIGHT=100;
export function cometConfig(settings,engine='v4',resume=null){if(!Object.hasOwn(ENGINES,engine))throw new Error('Unsupported release engine');const config=`# Managed private v4 devnet configuration. No file-validator fallback.\nproxy_app = "tcp://127.0.0.1:26658"\nmoniker = "time-v4-validator"\ndb_backend = "goleveldb"\ndb_dir = "data"\ngenesis_file = "/data/comet/config/genesis.json"\npriv_validator_laddr = "tcp://127.0.0.1:26659"\npriv_validator_key_file = "/operator/FILE_VALIDATOR_IS_FORBIDDEN"\npriv_validator_state_file = "/operator/FILE_VALIDATOR_STATE_IS_FORBIDDEN"\nnode_key_file = "/operator/node-identity.json"\n[rpc]\nladdr = "tcp://127.0.0.1:26657"\nunsafe = false\ncors_allowed_origins = []\n[p2p]\nladdr = "tcp://0.0.0.0:26656"\npersistent_peers = ${scalar(settings.sentry_peers.join(','))}\nprivate_peer_ids = ${scalar(settings.sentry_peers.map(p=>p.split('@')[0]).join(','))}\npex = false\naddr_book_strict = true\nallow_duplicate_ip = false\n[consensus]\ncreate_empty_blocks = true\ncreate_empty_blocks_interval = "1s"\ntimeout_commit = "1s"\ndouble_sign_check_height = 100\n[instrumentation]\nprometheus = true\nprometheus_listen_addr = "127.0.0.1:26660"\nnamespace = "cometbft"\n`;if(engine==='v4'){if(resume)throw new Error('A resume order applies only to v5 releases');return config;}const line='double_sign_check_height = '+DOUBLE_SIGN_CHECK_HEIGHT+'\n';if(!config.includes(line))throw new Error('The configuration has no double_sign_check_height line');return config.replace(line,resume?'# ONE START ONLY: resume order '+resume.order_id+' for height '+resume.height+' and root '+resume.root+' ('+RESUME_FILE+'). The chain stood\n# and every validator signed its last blocks; the look for them is off for this start, and the next start writes\n# '+line.trim()+' again (deploy/README.md, "A chain that stood").\ndouble_sign_check_height = 0\n':line).replace('# Managed private v4 devnet configuration.','# Managed private v5 devnet configuration (time-node-v5, protocol 4).').replace('priv_validator_key_file = "/operator/FILE_VALIDATOR_IS_FORBIDDEN"\npriv_validator_state_file = "/operator/FILE_VALIDATOR_STATE_IS_FORBIDDEN"\n','# CometBFT 0.38 writes a file validator key at every start even with a remote signer. It goes to the container\'s\n# tmpfs: a random key in no genesis, never used for signing (priv_validator_laddr replaces it), gone at exit.\npriv_validator_key_file = '+scalar(V5_UNUSED_PRIVVAL.key)+'\npriv_validator_state_file = '+scalar(V5_UNUSED_PRIVVAL.state)+'\n')+'[mempool]\n# time-node-v5 relies on re-check: after every block it reports which pending transactions are still valid.\nrecheck = true\n[storage]\n# Keep ABCI responses: the restart handshake replays the last block from them. A protocol upgrade depends on it:\n# the answer of the activating block carries the new version. Never set this to true.\ndiscard_abci_responses = false\n# Block pruning is decided by time-node-v5 alone: it returns retain_height 0 (keep every block) unless the\n# operator set keep_blocks, and never releases a block after its oldest snapshot. No other pruning.\n';}
async function fetchJson(url){const response=await fetch(url,{signal:AbortSignal.timeout(5000)});if(!response.ok)throw new Error('Local consensus HTTP status '+response.status);const chunks=[];let length=0;for await(const chunk of response.body){length+=chunk.length;if(length>2*1024*1024)throw new Error('Local diagnostic response byte bound');chunks.push(chunk);}const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(body.error)throw new Error('Local consensus RPC rejected query');return body.result;}
export function checkHealth(settings,status,app,now=Date.now(),engine='v4'){
 const observed=Date.parse(status.sync_info.latest_block_time);if(status.node_info.network!==settings.chain_id||status.sync_info.catching_up!==false||BigInt(status.sync_info.latest_block_height)<=0n||!Number.isFinite(observed)||Math.abs(now-observed)>30000)throw new Error('Consensus head stale, wrong chain or catching up');
 // v4 reports no engine field; v5 reports engine "v5". Either must match the pinned release.
 if(!Object.hasOwn(ENGINES,engine)||(engine==='v4'?app.engine!==undefined:app.engine!==engine))throw new Error('Application engine does not match the pinned release');
 if(app.app_version!=='4'||app.mode!=='devnet'||app.public_launch_allowed!==false||app.maintenance?.pressure!==false)throw new Error('Application protocol/mode/GC pressure not ready');
 return{status:'READY_PRIVATE_DEVNET',height:status.sync_info.latest_block_height,root:app.root,...(engine==='v4'?{}:{engine,snapshot_height:app.maintenance.snapshot_height??null,...upgradeHealth(app)}),operational_diagnostic_only:true,authenticated:false,public_funds_allowed:false};
}
// What the node's own /status says about a change of the protocol version (its `upgrade` field,
// time-node-v5 0.7.0): the scheduled version, whether this program implements it, and a
// coordinated stop height. Read from the application, never from CometBFT's
// node_info.protocol_version.app, which is the value at start and goes stale.
// A node that reports no such field gives no upgrade keys. A field in another form is refused.
export function upgradeHealth(app){
 const upgrade=app?.upgrade;if(upgrade===undefined)return{};
 const bad=()=>{throw new Error('Application upgrade status has an unexpected form');};
 if(!upgrade||typeof upgrade!=='object'||Array.isArray(upgrade)||!Array.isArray(upgrade.implemented)||!upgrade.implemented.length)bad();
 for(const item of upgrade.implemented)if(!item||typeof item.version!=='string'||!/^[1-9][0-9]{0,19}$/.test(item.version)||typeof item.spec!=='string'||!/^[a-f0-9]{64}$/.test(item.spec))bad();
 const plan=upgrade.scheduled??null;if(plan!==null&&(typeof plan!=='object'||typeof plan.version!=='string'||!/^[1-9][0-9]{0,19}$/.test(plan.version)||typeof plan.activate_elapsed_micros!=='string'||!/^(?:0|[1-9][0-9]{0,19})$/.test(plan.activate_elapsed_micros)))bad();
 const ready=upgrade.implements_scheduled??null;if(![null,true,false].includes(ready))bad();
 const stop=upgrade.stop_after_height??null;if(stop!==null&&(typeof stop!=='string'||!/^[1-9][0-9]{0,19}$/.test(stop)))bad();
 return{upgrade:{implemented_versions:upgrade.implemented.map(item=>item.version),scheduled_version:plan?.version??null,scheduled_activate_elapsed_micros:plan?.activate_elapsed_micros??null,implements_scheduled:ready,stop_after_height:stop}};
}
// What the monitor holds after a probe that failed: not ready, with the error, and with what
// the node last said about an upgrade. A node that stops for an upgrade it does not implement
// (exit code 4) fails every probe from then on; without this, time_upgrade_not_implemented
// would fall back to 0 at the very moment it matters.
export function failedSample(previous,error,observedUtc){
 const kept=previous?.upgrade?{upgrade:previous.upgrade,upgrade_observed_utc:previous.upgrade_observed_utc??previous.observed_utc??null}:{};
 return{ready:false,observed_utc:observedUtc,error:String(error?.message??error),public_funds_allowed:false,...kept};
}
// Prometheus text of the monitor. The first two metrics are unchanged. The upgrade metrics are 0
// while nothing is known: only the node's own report of a scheduled version it does not
// implement sets time_upgrade_not_implemented, and it keeps its last known value while the
// node cannot be probed (failedSample).
export function metricsText(latest){
 const upgrade=latest?.upgrade??null;
 return'# HELP time_private_devnet_ready Local unauthenticated operational health\n# TYPE time_private_devnet_ready gauge\ntime_private_devnet_ready '+Number(latest.ready)+'\n# TYPE time_bitcoin_earning_paused gauge\ntime_bitcoin_earning_paused '+Number(latest.bitcoin_earning_paused??true)+'\n'
  +'# HELP time_upgrade_scheduled A change of the protocol version is scheduled on the chain\n# TYPE time_upgrade_scheduled gauge\ntime_upgrade_scheduled '+Number(Boolean(upgrade?.scheduled_version))+'\n'
  +'# HELP time_upgrade_not_implemented The scheduled protocol version is one this node does not implement: it stops at the activation unless a newer release is installed\n# TYPE time_upgrade_not_implemented gauge\ntime_upgrade_not_implemented '+Number(upgrade?.implements_scheduled===false)+'\n'
  +'# HELP time_stop_after_height_set The node was started with a coordinated stop height\n# TYPE time_stop_after_height_set gauge\ntime_stop_after_height_set '+Number(Boolean(upgrade?.stop_after_height))+'\n';
}
export async function probe(settings){const{engine}=await guard(settings);const status=await fetchJson('http://127.0.0.1:26657/status'),query=await fetchJson('http://127.0.0.1:26657/abci_query?path=%22%2Fstatus%22');if(Number(query.response.code)!==0)throw new Error('Application status rejected');const health=checkHealth(settings,status,JSON.parse(Buffer.from(query.response.value,'base64').toString('utf8')),Date.now(),engine);const data=Buffer.from(JSON.stringify({include_bitcoin:true})).toString('hex');const result=await fetchJson('http://127.0.0.1:26657/abci_query?path=%22%2Fv4%2Fstate%22&data=0x'+data);if(Number(result.response.code)!==0)throw new Error('Bitcoin health query rejected');const entries=JSON.parse(Buffer.from(result.response.value,'base64').toString()).entries;const decode=key=>JSON.parse(Buffer.from(entries.find(e=>e.key_hex===Buffer.from(key).toString('hex')).value_b64,'base64').toString());const meta=decode('meta'),bitcoin=decode('bitcoin/meta').meta;const supply=exactU64(meta.bank)+exactU64(meta.liquid_total)+exactU64(meta.pos_assets_total)+exactU64(meta.auction_reserve_total);const elapsed=BigInt(meta.time_micros)-BigInt(meta.genesis.genesis_time_micros);if(supply!==elapsed)throw new Error('Operational metadata supply identity failed');return{...health,supply_micros:supply.toString(),bitcoin_best_height:bitcoin.best_height,bitcoin_earning_paused:bitcoin.halted!==null,bitcoin_halt:bitcoin.halted,full_supply_recount:'NOT_PERFORMED_BY_HTTP_PROBE'};}
// Application process for the pinned engine. ABCI stays on loopback 26658 in the
// shared validator namespace. v5 state lives in the ledger volume:
// /data/ledger/v5-state.v5state/ (snapshots) and /data/ledger/v5-state.history/.
// The v5 name avoids v4's /data/ledger/state.history archive.
export const V5_DB='/data/ledger/v5-state';
const bounded=(settings,name,low,high)=>{const value=settings[name];if(value===undefined)return undefined;if(!Number.isSafeInteger(value)||value<low||value>high)throw new Error(name+' must be an integer from '+low+' to '+high);return String(value);};
// A setting that is 0 (off) or an integer from low to high, as the node's own flags are.
const zeroOr=(settings,name,low,high)=>{const value=settings[name];if(value===undefined)return undefined;if(value!==0&&(!Number.isSafeInteger(value)||value<low||value>high))throw new Error(name+' must be 0 or an integer from '+low+' to '+high);return String(value);};
// Optional settings of a v5 node, each passed as its flag only when present. Ranges are the node's
// own (v5/src/main.rs): a value the node would refuse is refused here, by the guard, before start.
// - state_sync_snapshot_blocks (0, or 10 to 1,000,000): a snapshot for joining peers every N blocks.
// - state_sync_snapshots_kept (1 to 10): how many of them stay; needs the setting above, not 0.
// - state_sync_max_mib (4 to 400,000): the largest snapshot this node restores.
// - keep_blocks (0, or 2,000,000 to 10^12): blocks CometBFT keeps; 0 keeps all.
// - stop_after_height (1 or more): the coordinated stop of an emergency. After the commit of that
//   block the node saves, prints STOPPED AS ASKED and exits with code 4.
export const V5_SETTINGS=Object.freeze(['snapshot_seconds','clock_tolerance_seconds','state_sync_snapshot_blocks','state_sync_snapshots_kept','state_sync_max_mib','keep_blocks','stop_after_height']);
export function appCommand(engine,settings={}){
 if(engine==='v4'){for(const name of V5_SETTINGS)if(settings[name]!==undefined)throw new Error(name+' applies only to v5 releases');return['time-node-v4',['--devnet','--db','/data/ledger/state.redb','--listen','127.0.0.1:26658']];}
 if(engine!=='v5')throw new Error('Unsupported release engine');const args=['--devnet','--db',V5_DB,'--listen','127.0.0.1:26658'];
 // time-node-v5 0.6.0 caps the clock tolerance at 60 s: CometBFT's consensus.block_time_tolerance
 // defaults to 60 s, so a larger value would have no effect.
 const snapshot=bounded(settings,'snapshot_seconds',5,86400),clock=bounded(settings,'clock_tolerance_seconds',1,60);
 if(snapshot!==undefined)args.push('--snapshot-seconds',snapshot);
 if(clock!==undefined)args.push('--clock-tolerance-seconds',clock);
 const syncBlocks=zeroOr(settings,'state_sync_snapshot_blocks',10,1000000),syncKept=bounded(settings,'state_sync_snapshots_kept',1,10),syncMax=bounded(settings,'state_sync_max_mib',4,400000),keep=zeroOr(settings,'keep_blocks',2000000,1000000000000),stopAfter=bounded(settings,'stop_after_height',1,Number.MAX_SAFE_INTEGER);
 if(syncKept!==undefined&&(syncBlocks===undefined||syncBlocks==='0'))throw new Error('state_sync_snapshots_kept needs state_sync_snapshot_blocks (not 0)');
 if(syncBlocks!==undefined)args.push('--state-sync-snapshot-blocks',syncBlocks);
 if(syncKept!==undefined)args.push('--state-sync-snapshots-kept',syncKept);
 if(syncMax!==undefined)args.push('--state-sync-max-mib',syncMax);
 if(keep!==undefined)args.push('--keep-blocks',keep);
 if(stopAfter!==undefined)args.push('--stop-after-height',stopAfter);
 // No --stay-after-disconnect: when CometBFT goes away the node saves a snapshot and exits 3.
 return['time-node-v5',args];
}
// Volumes are bound to one engine and one network. A v5 launcher writes
// network-binding.json {schema_version,engine,genesis_sha256,chain_id} into the
// ledger and consensus volumes on first start; both engines refuse a binding or
// state of anything else. v4 writes no binding, so v4 volumes stay as they were.
export const BINDING_FILE='network-binding.json';
// compose.v5.yaml mounts the ledger volume read-only here in the validator
// container, so the consensus launcher can see what the application holds.
export const LEDGER_VIEW='/data/ledger-view';
const FRESH='start this release in a new Compose project: fresh ledger AND consensus volumes';
const ENGINE_STATE=Object.freeze({v4:['state.redb','state.history'],v5:['v5-state.v5state','v5-state.history']});
async function present(file){try{await lstat(file);return true;}catch(error){if(error.code==='ENOENT')return false;throw error;}}
export function networkBinding(engine,settings){if(!Object.hasOwn(ENGINES,engine))throw new Error('Unsupported release engine');hex32(settings.genesis_sha256);if(typeof settings.chain_id!=='string'||!settings.chain_id)throw new Error('Pinned chain ID required');return{schema_version:1,engine,genesis_sha256:settings.genesis_sha256,chain_id:settings.chain_id};}
async function readBinding(directory){
 const file=path.join(directory,BINDING_FILE);if(!await present(file))return null;let value;
 try{value=await json(file);if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!=='chain_id,engine,genesis_sha256,schema_version'||value.schema_version!==1||!Object.hasOwn(ENGINES,value.engine)||!/^[a-f0-9]{64}$/.test(value.genesis_sha256)||typeof value.chain_id!=='string'||!value.chain_id)throw new Error('unexpected fields or values');}
 catch(error){throw new Error('Unreadable volume network binding '+file+' ('+error.message+'). Bindings are created atomically, so this file was damaged or written by something else. Confirm out of band which engine, chain and genesis this volume belongs to; if it is this network, remove the file and start again, otherwise '+FRESH);}
 return value;
}
// v5 state that CometBFT can replay onto: at least one snapshot file. A marker or
// an empty state directory is not enough (the node creates the directory at open).
async function hasEngineState(engine,ledger){if(engine==='v4')return present(path.join(ledger,'state.redb'));let entries;try{entries=await readdir(path.join(ledger,'v5-state.v5state'));}catch(error){if(error.code==='ENOENT')return false;throw error;}return entries.some(name=>/^state-[0-9]{20}\.snap$/.test(name));}
// Refuses a ledger volume that holds the other engine's state, in both directions.
export async function checkLedgerVolume(engine,directory='/data/ledger'){if(!Object.hasOwn(ENGINES,engine))throw new Error('Unsupported release engine');const other=engine==='v5'?'v4':'v5';for(const name of ENGINE_STATE[other])if(await present(path.join(directory,name)))throw new Error('Ledger volume holds '+other+' state ('+name+'); '+FRESH);return true;}
// ledger/comet: the volume paths this process can see (null when not mounted).
export async function checkVolumes(engine,settings,{ledger=null,comet=null}={}){
 const expected=networkBinding(engine,settings),found={};
 for(const[name,directory]of Object.entries({ledger,comet})){if(!directory)continue;const binding=await readBinding(directory);if(binding&&JSON.stringify(Object.keys(expected).map(k=>binding[k]))!==JSON.stringify(Object.values(expected)))throw new Error('The '+name+' volume is bound to engine '+binding.engine+' on chain '+binding.chain_id+' (genesis '+binding.genesis_sha256+'); '+FRESH);found[name]=binding;}
 if(ledger)await checkLedgerVolume(engine,ledger);
 if(comet&&await present(path.join(comet,'data','blockstore.db'))){
  if(engine!=='v4'&&!found.comet)throw new Error('The consensus volume holds blocks but no '+engine+' network binding; '+FRESH);
  // Whatever the ledger's marker says: without a snapshot the node would replay from height 0.
  if(ledger&&!await hasEngineState(engine,ledger))throw new Error('The consensus volume holds blocks but the ledger volume has no binding or state for '+engine+' (no saved snapshot). Restore the ledger from the coordinated checkpoint, or '+FRESH);
 }
 return expected;
}
// Atomic create that never overwrites: write and fsync a private temporary file,
// then link() it to the final name. A reader sees no file or the whole file.
export async function bindVolume(directory,binding){
 const file=path.join(directory,BINDING_FILE);if(await present(file))return false;
 const temporary=path.join(directory,'.'+BINDING_FILE+'.'+process.pid+'.'+randomUUID()+'.tmp');const handle=await open(temporary,'wx',0o600);
 try{await handle.writeFile(JSON.stringify(binding)+'\n');await handle.sync();}finally{await handle.close();}
 try{await link(temporary,file);}catch(error){if(error.code==='EEXIST')return false;throw error;}finally{await unlink(temporary);}
 if(process.platform!=='win32'){const dir=await open(directory,'r');try{await dir.sync();}finally{await dir.close();}}
 return true;
}
// Writes the CometBFT home from the bytes the guard verified, never by re-reading
// the genesis file, so Comet runs exactly the genesis the bindings record.
// The configuration is written at every start, so a start that a resume order turned the double-sign look off for is
// followed by starts with the look on, without anyone having to change anything.
export async function prepareCometHome(home,settings,engine,genesisBytes,resume=null){
 if(!Buffer.isBuffer(genesisBytes)||sha256(genesisBytes)!==settings.genesis_sha256)throw new Error('Genesis bytes differ from the pinned hash');
 await mkdir(path.join(home,'config'),{recursive:true,mode:0o700});await mkdir(path.join(home,'data'),{recursive:true,mode:0o700});
 await writeFile(path.join(home,'config','config.toml'),cometConfig(settings,engine,resume),{mode:0o600});await writeFile(path.join(home,'config','genesis.json'),genesisBytes,{mode:0o600});
}
// ---- A chain that stood (docs/emergency-fix.md; deploy/README.md, "A chain that stood").
// After a coordinated stop (stop_after_height, STOPPED AS ASKED), a stop in the middle of a block (FAILED ON A DECIDED
// BLOCK) or an upgrade that more than a third did not install in time, every validator signed the last blocks and no
// new block comes. With double_sign_check_height = 100 no validator could start again. The operator therefore writes a
// RESUME ORDER, once, with the height and the state root the validators agreed on:
//   node deploy/operator.mjs resume-order SETTINGS HEIGHT:ROOT       (on the host; it writes resume.json beside SETTINGS)
// At the next start of the stack the order is judged by both launchers, from the files alone:
// - It applies only while the node's saved state (its newest snapshot in the ledger volume) is at or below HEIGHT. A node
//   past it, or with no state at all, ignores it: an order left behind never changes a later start.
// - Where it applies it must name this chain, genesis, consensus key and release, and the settings must not stop the
//   node at or below HEIGHT; otherwise the start is refused.
// - The node launcher passes --expect-root HEIGHT:ROOT: the node goes on only on the agreed state, and refuses to start
//   (exit code 1, nothing changed) on any other.
// - The consensus launcher turns double_sign_check_height off for ONE start per order: it marks the order used in the
//   consensus volume before CometBFT starts, and every later start writes the look back. It does so only after a node
//   that ended by itself at a height (exit code 4) or on a failure (exit code 1), and whose state has not moved since:
//   the node launcher records each end of the node in the ledger volume (`noteExit`), and keeps such an end until the
//   saved state moves past it, so that a start CometBFT refused at the standstill does not wipe it. After a clean stop
//   (0), a lost CometBFT or an ended lease (3), or a kill, with nothing of the kind before, it refuses the start. In
//   ordinary operation a validator never ends that way, so an order cannot be used to skip the wait of 100 blocks after
//   a restart.
// - The lease guard runs as at every start: no lease, no start.
export const RESUME_FILE='/operator/resume.json',RESUME_KIND='time-v5-resume-order',RESUME_USED='resume-orders-used',LAST_EXIT_FILE='node-last-exit.json';
// The node's own form of --expect-root (v5/src/main.rs, height_and_root): a height of at least 1 without sign or leading
// zero, at most 2^63 - 1, a colon, and 64 lowercase hexadecimal characters.
export function heightAndRoot(text){
 const form='HEIGHT:ROOT needs a block height (at least 1) and the 64 lowercase hexadecimal characters of a state root, as the node takes them for --expect-root';
 const found=typeof text==='string'?/^([1-9][0-9]{0,18}):([0-9a-f]{64})$/.exec(text):null;if(!found||BigInt(found[1])>9223372036854775807n)throw new Error(form);
 return{height:found[1],root:found[2]};
}
export function resumeOrder(settings,text,{now=Date.now(),id=randomUUID().replace(/-/g,'')}={}){
 const{height,root}=heightAndRoot(text);hex32(settings.genesis_sha256);hex32(settings.validator_public_key_hex);hex32(settings.release_id,'release identity');
 if(typeof settings.chain_id!=='string'||!/^time-devnet-v4-[A-Za-z0-9_-]+$/.test(settings.chain_id))throw new Error('Pinned chain ID required');
 if(settings.stop_after_height!==undefined&&BigInt(settings.stop_after_height)<=BigInt(height))throw new Error('These settings carry stop_after_height '+settings.stop_after_height+', at or below '+height+': remove it from the settings first. A node that goes on from a height does not stop at or before it.');
 return{schema_version:1,kind:RESUME_KIND,order_id:id,chain_id:settings.chain_id,genesis_sha256:settings.genesis_sha256,validator_public_key_hex:settings.validator_public_key_hex,release_id:settings.release_id,height,root,written_utc:new Date(now).toISOString()};
}
// The fields of an order, checked; and, where it applies, that it is for these settings.
export function checkResumeOrder(order,settings){
 const keys='chain_id,genesis_sha256,height,kind,order_id,release_id,root,schema_version,validator_public_key_hex,written_utc';
 if(!order||typeof order!=='object'||Array.isArray(order)||Object.keys(order).sort().join(',')!==keys||order.schema_version!==1||order.kind!==RESUME_KIND||typeof order.order_id!=='string'||!/^[0-9a-f]{32}$/.test(order.order_id)||!Number.isFinite(Date.parse(order.written_utc)))throw new Error('The resume order '+RESUME_FILE+' is not one this kit writes. Remove it, and write it again with: node deploy/operator.mjs resume-order SETTINGS HEIGHT:ROOT');
 heightAndRoot(order.height+':'+order.root);
 for(const name of ['chain_id','genesis_sha256','validator_public_key_hex','release_id'])if(order[name]!==settings[name])throw new Error('The resume order '+order.order_id+' was written for another '+name.replace(/_/g,' ')+' than these settings pin. Write it again after the settings are final (the release to start, without stop_after_height).');
 if(settings.stop_after_height!==undefined&&BigInt(settings.stop_after_height)<=BigInt(order.height))throw new Error('These settings carry stop_after_height '+settings.stop_after_height+', at or below the height '+order.height+' of the resume order: remove it from the settings.');
 return order;
}
// The height of the newest snapshot the node saved in the ledger volume, or null: where its state stands at a start.
export async function savedHeight(ledger){let names;try{names=await readdir(path.join(ledger,'v5-state.v5state'));}catch(error){if(error.code==='ENOENT')return null;throw error;}const heights=names.map(name=>/^state-([0-9]{20})\.snap$/.exec(name)?.[1]).filter(Boolean).map(BigInt);return heights.length?heights.reduce((a,b)=>(a>b?a:b)):null;}
// How the node's runs ended, as the node launcher records it in the ledger volume (`noteExit`).
export async function lastExit(ledger){try{return await json(path.join(ledger,LAST_EXIT_FILE));}catch(error){if(error.code==='ENOENT')return null;throw error;}}
export async function recordExit(ledger,record){const file=path.join(ledger,LAST_EXIT_FILE),temporary=file+'.'+process.pid+'.tmp';await writeFile(temporary,JSON.stringify(record)+'\n',{mode:0o600});await rename(temporary,file);}
// An end by itself at a height (4) or on a failure (1) is where a chain that stood leaves a node.
export const standstillEnd=(record)=>Boolean(record&&record.asked===false&&[1,4].includes(record.code)&&typeof record.saved_height==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(record.saved_height));
// Records how a run of the node ended, with the height of the state it saved (`end`: {code, asked}). Such an end is kept
// while the saved state has not moved past it: a later run that went nowhere (a start CometBFT refused, a signer that
// answered late) does not wipe it. Any end after the state moved replaces it.
export async function noteExit(ledger,end,{now=Date.now()}={}){
 const saved=await savedHeight(ledger),before=await lastExit(ledger).catch(()=>null);
 if(standstillEnd(before)&&saved!==null&&saved<=BigInt(before.saved_height))return before;
 const record={code:end.code,asked:end.asked,saved_height:saved===null?null:saved.toString(),ended_utc:new Date(now).toISOString(),...(end.release_id?{release_id:end.release_id}:{}),...(end.expect_root?{expect_root:end.expect_root}:{})};
 await recordExit(ledger,record);return record;
}
// What a launcher does with the resume order of this start. `kind` is 'app' or 'comet'; `ledger` is the ledger volume
// as this launcher sees it, `comet` the consensus volume (consensus launcher only), `file` the order. Returns
// {applies:false, why} or {applies:true, order, expectRoot, doubleSignCheckOff, why}, or throws to refuse the start.
export async function resumeDecision(kind,settings,{ledger,comet=null,file=RESUME_FILE}){
 let order;try{order=await json(file);}catch(error){if(error.code==='ENOENT')return{applies:false,why:'no resume order'};throw new Error('The resume order '+file+' cannot be read ('+error.message+'). Remove it, and write it again with: node deploy/operator.mjs resume-order SETTINGS HEIGHT:ROOT');}
 if(!order||typeof order!=='object'||typeof order.height!=='string'||!/^[1-9][0-9]{0,18}$/.test(order.height))checkResumeOrder(order,settings);
 const saved=await savedHeight(ledger);
 if(saved===null||saved>BigInt(order.height))return{applies:false,why:'the resume order '+String(order.order_id)+' is for height '+order.height+(saved===null?', and this node holds no saved state':', and this node\'s state is at height '+saved+', past it')+': it does not apply, and this start runs as any other. resume.json may be removed.'};
 checkResumeOrder(order,settings);
 const expectRoot=order.height+':'+order.root;
 if(kind!=='comet')return{applies:true,order,expectRoot,doubleSignCheckOff:false,why:'resume order '+order.order_id+': --expect-root '+expectRoot};
 const used=path.join(comet,RESUME_USED,order.order_id+'.json');
 if(await present(used))return{applies:true,order,expectRoot,doubleSignCheckOff:false,why:'resume order '+order.order_id+' was used by an earlier start: double_sign_check_height stays '+DOUBLE_SIGN_CHECK_HEIGHT+'. A start that must again go on from a chain that stood needs a new order.'};
 const ended=await lastExit(ledger);
 if(!standstillEnd(ended)||saved>BigInt(ended.saved_height))throw new Error('The resume order '+order.order_id+' is for a validator whose node ended by itself at the height the chain stood at (exit code 4: STOPPED AS ASKED, AT A SWITCH or FOR UPGRADE) or failed there (exit code 1: FAILED ON A DECIDED BLOCK). This node\'s last run '+(ended?'ended with exit code '+ended.code+(ended.asked?' when it was asked to stop':'')+(standstillEnd(ended)?', and its state has moved since':''):'left no record')+'. Nothing was started. If the chain really stands and this node runs at '+order.height+' or was stopped by hand, set stop_after_height to '+order.height+' and start the stack once: the node stops at once (STOPPED AS ASKED); then remove stop_after_height and start again. Otherwise wait until the chain is '+DOUBLE_SIGN_CHECK_HEIGHT+' blocks past this validator\'s last signature and start without an order.');
 return{applies:true,order,expectRoot,doubleSignCheckOff:true,usedFile:used,why:'resume order '+order.order_id+': double_sign_check_height = 0 for this one start, after a node that ended with exit code '+ended.code};
}
// Marks the order used before CometBFT starts: exclusive creation, so two starts can never both turn the look off.
export async function markResumeUsed(decision,startedUtc){await mkdir(path.dirname(decision.usedFile),{recursive:true,mode:0o700});const handle=await open(decision.usedFile,'wx',0o600);try{await handle.writeFile(JSON.stringify({order_id:decision.order.order_id,height:decision.order.height,root:decision.order.root,started_utc:startedUtc})+'\n');await handle.sync();}finally{await handle.close();}}
// How a finished child is reported. Policy: nothing restarts automatically (compose restart "no").
// Exit code 4 of time-node-v5: it stopped at a height on purpose, with its state saved. The
// node's own first line says which of three causes it was; the launcher cannot read that line
// (the node writes straight to the container log), so the message names all three and what to
// do for each. `settings` only adds which is likely.
export function childOutcome(kind,engine,code,settings={},resume=null){
 if(code===0)return{exitCode:0};
 // A start under a resume order that the node refused: its state is not the agreed one, or it is past that height.
 if(kind==='app'&&engine==='v5'&&code===1&&resume)throw new Error('Node child process failed: time-node-v5 exited with code 1 on a start with --expect-root '+resume+' (the resume order in '+RESUME_FILE+'). If its log says "The node did not start: --expect-root", this node does not hold the state the validators agreed on, or is past that height; nothing was changed. Do not start this validator: tell the coordinators, and read docs/emergency-fix.md. Otherwise read the node log for the cause.');
 if(kind==='app'&&engine==='v5'&&code===4){const asked=settings?.stop_after_height!==undefined;const error=new Error('time-node-v5 exited with code 4: it stopped at a height on purpose and its state is saved and valid. Delete nothing; nothing restarts automatically. The first line the node printed says why. '
  +'STOPPED FOR UPGRADE: the chain now runs a protocol version this release does not implement. Install the release that implements it (the line names the version and the height), pin its release_id in the settings, obtain signer leases for that release, and start the whole stack on the same volumes. '
  +'STOPPED AS ASKED: the height in stop_after_height was reached'+(asked?' (these settings carry stop_after_height '+settings.stop_after_height+')':'')+'. Follow the agreed procedure; before a start that should run on, remove stop_after_height from the settings, since a node whose head is above that height refuses to start. '
  +'STOPPED AT A SWITCH: a decided block carries an emergency switch, or should, and this release did not execute it; its state stays at the height before. The second line says which of three causes it was. '
  +'(1) A decided block carries an emergency switch to a version this release does not implement: Install the fix release named by the coordinators and start it on the same volumes; CometBFT hands it that block again. '
  +'(2) This is a fix release, and the decided block at its switch height is not its switch block: the chain did not stop where this release expects. '
  +'(3) This is a fix release, and the state is already past its switch height under the old version. '
  +'In cases 2 and 3 start the release the state was made by, and wait for a fix release built for the height the chain stopped at (docs/emergency-fix.md). '
  +'If the whole chain stands, starting again needs a resume order with the agreed height and root (node deploy/operator.mjs resume-order SETTINGS HEIGHT:ROOT; deploy/README.md, "A chain that stood").');error.exitCode=4;throw error;}
 if(kind==='app'&&engine==='v5'&&code===3){const error=new Error('time-node-v5 exited with code 3: CometBFT disconnected and the node saved a final snapshot. Nothing restarts automatically. Find out why the validator (comet) container stopped and check the signer lease, then start the whole stack again; CometBFT replays the blocks after the snapshot.');error.exitCode=3;throw error;}
 // A node whose head is already above stop_after_height refuses to start, with code 1.
 if(kind==='app'&&engine==='v5'&&code===1&&settings?.stop_after_height!==undefined)throw new Error('Node child process failed: time-node-v5 exited with code 1, and these settings carry stop_after_height '+settings.stop_after_height+'. A node whose state is already above that height refuses to start (its log says so). If the coordinated stop is over, remove stop_after_height from the settings and start again; otherwise read the node log for the cause.');
 throw new Error('Node child process failed');
}
// What ends a child once its signer lease is no longer valid (docs/design/signer-lease-controller.md, 10.2 and 14).
// The rule: the child may run until the expiry of the last lease that verified, and must be dead a bounded
// time after it.
// The signer container is not under this guard: it signs for whoever listens on 127.0.0.1:26659, which is
// CometBFT. So a lease reaches the signer only through the end of the CometBFT process, made certain here.
// - `check()` is guard(): it resolves with the lease it verified, or rejects.
// - A lease that verifies gives the child two deadlines, and the child is stopped at whichever comes first:
//   its expires_utc on the wall clock, looked at every GUARD_PERIOD_MS and once when the watch is created;
//   and its remaining life at the moment it first verified, counted from then by a timer, which runs on the
//   monotonic clock. So a wall clock that is set BACK after a lease verified does not lengthen that lease.
//   (A clock that was already wrong when the lease first verified is not seen.)
// - A newer lease is one with a later expires_utc. A slow check that verified a lease which has ended by the
//   time it returns moves nothing, and a lease verified a second time keeps its first deadline.
// - No interval is ever measured between two wall-clock readings. A wall clock stepped forward, or a
//   launcher that did not run for a while, stops nothing unless a deadline has in fact been reached.
// - A check that REFUSES what it read (a lease that is expired, dated in the future, for another key, from an
//   authority that is no longer pinned, ...) stops the child at once, as before. A check that cannot read (an
//   error of the file system: it names the system call that failed) or never returns is not a refusal: the
//   child runs on until a deadline and no longer.
// - Stopping is SIGTERM through onFailure, called once. With hardKill (the consensus child) SIGKILL follows
//   GUARD_KILL_MS later if the child still runs; that timer is armed before onFailure is called. CometBFT
//   recovers from a kill through its write-ahead log. The node is never killed, so that it can finish its
//   snapshot.
// - run() verifies the lease again immediately before it starts the child and hands that lease to the watch.
// The bound: CometBFT has been sent SIGKILL at most GUARD_PERIOD_MS + GUARD_KILL_MS = 15 s after the host's
// wall clock reached the expiry of the last lease that verified, whatever the checks did, and no later than
// GUARD_KILL_MS after that lease's remaining life, as it was when it first verified, has passed.
// `now` (the wall clock), `every` and `after` are for tests.
export const GUARD_PERIOD_MS=5000,GUARD_KILL_MS=10000;
export function leaseWatch({check,child,hardKill,onFailure,validUntilMs=Number.POSITIVE_INFINITY,now=Date.now,every=setInterval,after=setTimeout}){
 let stopped=false,validUntil=Number.POSITIVE_INFINITY;
 const stop=error=>{if(stopped)return;stopped=true;if(hardKill)after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');},GUARD_KILL_MS)?.unref?.();try{onFailure(error);}catch{/* the kill is armed; nothing a callback throws may take the launcher down before it fires */}};
 const ended=()=>new Error('The last signer lease that verified ended at '+new Date(validUntil).toISOString()+' and no newer one has verified');
 // Only an error of the file system (it carries the system call it failed in) means "could not read".
 const unreadable=error=>typeof error?.code==='string'&&typeof error?.syscall==='string';
 // A newer lease: its expiry on the wall clock, and a timer for its remaining life as it is now.
 const accept=expires=>{if(!(validUntil===Number.POSITIVE_INFINITY||expires>validUntil))return;validUntil=expires;const left=expires-now();if(left<=0)return stop(ended());after(()=>{if(validUntil===expires)stop(ended());},left)?.unref?.();};
 const verified=result=>{const expires=Date.parse(result?.lease?.expires_utc);if(!Number.isFinite(expires))throw new Error('The lease check named no expiry');accept(expires);};
 if(validUntilMs!==Number.POSITIVE_INFINITY)accept(validUntilMs);
 return every(()=>{
  if(now()>=validUntil)stop(ended());
  Promise.resolve().then(check).then(verified).catch(error=>{if(!unreadable(error))stop(error);});
 },GUARD_PERIOD_MS);
}
// A stop asked of the launcher (SIGTERM from Compose or systemd) is passed to the child as SIGTERM. With hardKill (the
// v5 consensus child) SIGKILL follows GUARD_KILL_MS later if the child still runs. Found by the kit rehearsal: a
// CometBFT 0.38.26 whose remote signer has gone does not end on SIGTERM (it keeps waiting for the signer), Compose then
// kills the whole container after its stop_grace_period (30 s), the launcher dies with it before it removes its
// process lock, and every later start is refused ("Existing process fence"). Ended by the launcher itself, CometBFT
// stops, the launcher sees it stop and removes the lock. CometBFT recovers from SIGKILL through its write-ahead log,
// as after the lease guard's kill (leaseWatch). The node is never killed: it must be able to finish its snapshot.
export function stopChild(child,{hardKill=false,after=setTimeout}={}){
 if(!child||child.exitCode!==null||child.signalCode!==null)return false;
 child.kill('SIGTERM');
 if(hardKill&&!child.kitKillArmed){child.kitKillArmed=true;after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');},GUARD_KILL_MS)?.unref?.();}
 return true;
}
async function run(kind,settings){
 // Signals are handled from the first instruction. A stop before the child exists
 // ends the launch cleanly; after spawn it is forwarded to the child (v5: final snapshot).
 let child,stopping=false,hardStop=false;const stop=()=>{stopping=true;stopChild(child,{hardKill:hardStop});};process.on('SIGTERM',stop);process.on('SIGINT',stop);
 try{
  for(const name of ['TIME_IMAGE','REMOTE_SIGNER_IMAGE'])if(!imagePin(process.env[name]))throw new Error('Runtime image digest pin missing: '+name);const{engine,genesis_bytes}=await guard(settings);if(!['app','comet'].includes(kind))throw new Error('Unknown process kind');hardStop=kind==='comet'&&engine==='v5';if(stopping)return;
  const directory=kind==='app'?'/data/ledger':'/data/comet';await mkdir(directory,{recursive:true,mode:0o700});const lock=path.join(directory,'operator-process.lock');let handle;try{handle=await open(lock,'wx',0o600);}catch{throw new Error('Existing process fence: verify old instance and signer lease revoked before removing the lock');}await handle.writeFile(JSON.stringify({pid:process.pid,release_id:settings.release_id}));
  try{
   if(kind==='comet'&&engine==='v5'&&!await present(LEDGER_VIEW))throw new Error('A v5 validator needs the ledger volume read-only at '+LEDGER_VIEW+': run deploy/compose.v5.yaml (project time-v5-private-devnet), not the v4 compose file');
   const binding=await checkVolumes(engine,settings,kind==='app'?{ledger:directory}:{comet:directory,ledger:engine==='v5'?LEDGER_VIEW:null});if(engine==='v5')await bindVolume(directory,binding);
   // A chain that stood: what the resume order of this start, if any, changes (resumeDecision above).
   const resume=engine==='v5'?await resumeDecision(kind,settings,kind==='app'?{ledger:directory}:{ledger:LEDGER_VIEW,comet:directory}):{applies:false,why:'no resume order'};
   if(resume.applies||resume.why!=='no resume order')console.error((resume.applies?'RESUME: ':'Resume order: ')+resume.why);
   if(kind==='comet'){if(resume.doubleSignCheckOff)await markResumeUsed(resume,new Date().toISOString());await prepareCometHome('/data/comet',settings,engine,genesis_bytes,resume.doubleSignCheckOff?resume.order:null);const node=await lstat('/operator/node-identity.json');if(!node.isFile()||node.isSymbolicLink())throw new Error('Pinned operator P2P node key required');}
   if(stopping)return;
   const[executable,args]=kind==='app'?appCommand(engine,settings):['cometbft',['start','--home','/data/comet']];if(kind==='app'&&resume.applies)args.push('--expect-root',resume.expectRoot);const{lease:startLease}=await guard(settings);if(stopping)return;child=spawn(executable,args,{stdio:'inherit'});let guardFailure;
   const timer=leaseWatch({check:()=>guard(settings),child,hardKill:kind==='comet',validUntilMs:Date.parse(startLease.expires_utc),onFailure:error=>{guardFailure=error;stop();}});
   try{const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',resolve);});if(kind==='app'&&engine==='v5')await noteExit(directory,{code,asked:stopping||Boolean(guardFailure),release_id:settings.release_id,...(resume.applies?{expect_root:resume.expectRoot}:{})}).catch(error=>console.error('The end of the node could not be recorded: '+error.message));if(guardFailure)throw guardFailure;childOutcome(kind,engine,code,settings,resume.applies?resume.expectRoot:null);}finally{clearInterval(timer);}
  }finally{if(child&&child.exitCode===null)child.kill('SIGTERM');await handle.close();await unlink(lock);}
 }finally{process.removeListener('SIGTERM',stop);process.removeListener('SIGINT',stop);}
}
// Writes the resume order beside the settings file (on the host: OPERATOR_CONFIG, which the containers see as /operator).
// It reads the settings' own values only, so it runs on the host, where the settings' file paths are those of the
// containers. It never replaces an order: remove the old one first, on purpose.
export async function writeResumeOrder(settingsFile,text,{now=Date.now()}={}){
 const settings=checkSettingsKeys(await json(settingsFile)),order=resumeOrder(settings,text,{now}),file=path.join(path.dirname(path.resolve(settingsFile)),path.basename(RESUME_FILE));
 const handle=await open(file,'wx',0o644).catch(error=>{throw new Error(error.code==='EEXIST'?file+' exists already. An order is used by one start: remove the old one on purpose, then write the new one.':error.message);});
 try{await handle.writeFile(JSON.stringify(order,null,2)+'\n');await handle.sync();}finally{await handle.close();}
 return{file,order};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){(async()=>{const[action,kindOrFile,settingsFile]=process.argv.slice(2);if(action==='help'){console.log('Devnet only: run app|comet SETTINGS.json; probe SETTINGS.json; resume-order SETTINGS.json HEIGHT:ROOT (on the host, for a chain that stood). All runs require a live externally signed per-signature fenced signer lease. The pinned release selects the engine (time-node-v4 or time-node-v5); a v5 app that loses CometBFT exits 3 after saving a snapshot, and one that stops at a height on purpose (a protocol upgrade this release does not implement, stop_after_height, an emergency switch) exits 4.');return;}if(action==='probe')console.log(JSON.stringify(await probe(await json(kindOrFile))));else if(action==='guard'){await guard(await json(kindOrFile));console.log('Operator guard accepted a private devnet lease');}else if(action==='run')await run(kindOrFile,await json(settingsFile));
 else if(action==='resume-order'){const{file,order}=await writeResumeOrder(kindOrFile,settingsFile);console.log('Wrote '+file+': resume order '+order.order_id+' for height '+order.height+' and root '+order.root+', release '+order.release_id+'.\nAt the next start of the stack the node goes on only on that state (--expect-root '+order.height+':'+order.root+'), and CometBFT starts once without double_sign_check_height, only if this node\'s saved state is at or below '+order.height+' and its last run ended by itself (exit code 4 or 1). Every later start has the check on again; the file may then be removed.\nNever write an order on a machine that is not the one validator this key belongs to.');}
 else throw new Error('Unsupported operator action');})().catch(e=>{console.error(e.message);process.exitCode=e.exitCode??1;});}
