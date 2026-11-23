// Full offline recount of each owned node, with a separate BigInt supply check.
import {spawn} from 'node:child_process';
import {readFile,writeFile,mkdir,access} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url)),args=process.argv.slice(2);
if(args.length!==2||args[0]!=='--lab')throw Error('Usage: node production/tools/audit-v4-lab.mjs --lab production/.local/LAB (stop the lab first)');
const lab=path.resolve(args[1]),relative=path.relative(path.join(root,'.local'),lab);
if(!relative||relative.startsWith('..')||path.isAbsolute(relative))throw Error('Audit must target a named private lab inside production/.local');
try{await access(path.join(lab,'.running.lock'));throw Error('Stop this lab before auditing its databases');}catch(e){if(e.code!=='ENOENT')throw e;}
const manifest=JSON.parse(await readFile(path.join(lab,'network-manifest.json'),'utf8'));if(manifest.protocolVersion!=='4'||manifest.publicLaunchAllowed!==false||manifest.genesis?.history_version!==1||manifest.genesis?.reward_version!==1)throw Error('Expected explicit history/reward-version-one development network');
const executable=path.join(root,'v4/target/debug/time-node-v4'+(process.platform==='win32'?'.exe':''));
const digest=async file=>createHash('sha256').update(await readFile(file)).digest('hex');
const binary=await digest(executable),startedAt=new Date().toISOString(),nodes=[];
for(let i=0;i<7;i++){
  const database=path.join(lab,'node'+i,'data/application.redb');
  const child=spawn(executable,['--devnet','--audit','--db',database],{windowsHide:true,stdio:['ignore','pipe','pipe']});
  let stdout='',stderr='';child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>{if(stderr.length<65536)stderr+=b;});
  const exitCode=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',resolve);});
  if(exitCode!==0)throw Error('Native audit failed for node'+i+': '+stderr.slice(-1000));
  const result=JSON.parse(stdout);if(result.status!=='PASS_OFFLINE_AUTHENTICATED_RECOUNT'||result.network_id!==manifest.networkId||result.history_archive_verified!==true)throw Error('Audit evidence scope mismatch for node'+i);
  const sum=BigInt(result.bank)+BigInt(result.liquid)+BigInt(result.pos_escrow)+BigInt(result.auction_reserve);
  if(sum!==BigInt(result.elapsed_micros))throw Error('Independent BigInt supply recount failed');
  nodes.push({node:i,...result,independentSupplySum:sum.toString()});console.log('Node'+i+' full audit and archive PASS at H'+result.height);
}
if(await digest(executable)!==binary)throw Error('Native binary changed during audit');
for(const n of nodes){const same=nodes.filter(other=>other.height===n.height);if(same.some(other=>other.root!==n.root))throw Error('Same-height audited roots diverge');}
const directory=path.join(root,'results-v4');await mkdir(directory,{recursive:true});const file=path.join(directory,'offline-audit-'+startedAt.replace(/[:.]/g,'-')+'.json');
await writeFile(file,JSON.stringify({status:'PASS_SEVEN_OFFLINE_TREES_ARCHIVES_AND_SUPPLY',rewardVersion:1,startedAt,finishedAt:new Date().toISOString(),networkId:manifest.networkId,binarySha256:binary,nodes,publicLaunchAllowed:false,scope:'Whole-tree authentication, module/index/claim/Bitcoin/auction recounts, complete history archive replay and independent BigInt supply equality. Audited committed heads may differ by in-flight shutdown height; equal-height roots must agree. This is local evidence, not an external audit or replacement for a fresh quorum certificate.'},null,2)+'\n',{flag:'wx'});
console.log('Saved '+file);
