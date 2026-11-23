// Snapshot one RustSec database revision, then audit all candidate lockfiles.
// Network failure or a changed lockfile is not a passing security scan.
import {spawn} from 'node:child_process';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
const executable=path.join(root,'.tools/security/bin/cargo-audit'+(process.platform==='win32'?'.exe':''));
const database=path.join(root,'.tools/rustsec-advisory-db');
const files=['v4/Cargo.lock','verifier-v4/Cargo.lock','history/Cargo.lock','registration/Cargo.lock','pos/Cargo.lock','bitcoin-bridge/Cargo.lock','treasury/Cargo.lock','ops-v4/helper/Cargo.lock','bench-v4/Cargo.lock'];
const digest=async file=>createHash('sha256').update(await readFile(file)).digest('hex');
const directory=path.join(root,'results-v4/dependencies-'+new Date().toISOString().replace(/[:.]/g,'-'));
await mkdir(directory,{recursive:true});const startedAt=new Date().toISOString(),reports=[];
for(let i=0;i<files.length;i++){
  const file=files[i],before=await digest(path.join(root,file));
  const args=['audit','--db',database,'--file',path.join(root,file),'--json',...(i?['--no-fetch']:[])];
  const child=spawn(executable,args,{cwd:root,windowsHide:true,stdio:['ignore','pipe','pipe'],env:{...process.env,CARGO_HOME:path.join(root,'.tools/cargo')}});
  let stdout='',stderr='';child.stdout.on('data',b=>{stdout+=b;if(stdout.length>16*1024*1024)child.kill();});child.stderr.on('data',b=>{if(stderr.length<65536)stderr+=b;});
  const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',resolve);});
  const output=file.replaceAll('/','-')+'.json';await writeFile(path.join(directory,output),stdout);await writeFile(path.join(directory,output+'.stderr.txt'),stderr);
  let audit;try{audit=JSON.parse(stdout);}catch{throw Error('Dependency scan did not produce valid JSON: '+file);}
  const after=await digest(path.join(root,file));if(before!==after)throw Error('Lockfile changed during dependency scan: '+file);
  const findings=(audit.vulnerabilities?.list||[]).map(v=>({id:v.advisory.id,package:v.package.name,version:v.package.version,title:v.advisory.title,patched:v.versions?.patched}));
  const warnings=Object.fromEntries(Object.entries(audit.warnings||{}).map(([name,values])=>[name,values.map(v=>({id:v.advisory?.id,package:v.package?.name,version:v.package?.version,title:v.advisory?.title}))]));
  reports.push({lockfile:file,sha256:before,exitCode:code,database:audit.database,findings,warnings,evidence:output});
  console.log(file+': '+findings.length+' vulnerabilities; '+Object.values(warnings).reduce((n,v)=>n+v.length,0)+' warnings');
}
const status=reports.some(r=>r.exitCode!==0||r.findings.length)?'DEPENDENCY_FINDINGS':reports.some(r=>Object.values(r.warnings).some(v=>v.length))?'DEPENDENCY_WARNINGS_REQUIRE_REVIEW':'PASS_CURRENT_RUSTSEC_DATABASE';
await writeFile(path.join(directory,'report.json'),JSON.stringify({status,startedAt,finishedAt:new Date().toISOString(),tool:{name:'cargo-audit',version:'0.22.2',sha256:await digest(executable)},reports,publicLaunchAllowed:false,scope:'Published RustSec advisories and registry yanks for exact recorded lockfiles. This is not a code audit, proof of exploit absence, or scan of Bitcoin Core/Go/browser binaries.'},null,2)+'\n');
console.log(status+': '+directory);if(status==='DEPENDENCY_FINDINGS')process.exitCode=1;
