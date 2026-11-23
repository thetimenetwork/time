#!/usr/bin/env node
import {spawn} from 'node:child_process';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=fileURLToPath(new URL('../',import.meta.url));
const binary=path.resolve(root,process.argv[2]||'.tools/bin/cometbft.exe');
await mkdir(path.join(root,'results'),{recursive:true});
const run=await new Promise((resolve,reject)=>{
  const child=spawn('go',['run','golang.org/x/vuln/cmd/govulncheck@v1.9.0','-mode=binary','-json',binary],{cwd:root,windowsHide:true,stdio:['ignore','pipe','pipe']});
  let stdout='',stderr='';child.stdout.on('data',data=>{stdout+=data;});child.stderr.on('data',data=>{stderr+=data;});child.once('error',reject);child.once('close',code=>resolve({stdout,stderr,code}));
});
await writeFile(path.join(root,'results/comet-govulncheck.raw.json'),run.stdout);
function documents(text) {
  const result=[];let start=-1,depth=0,quoted=false,escaped=false;
  for(let i=0;i<text.length;i++) {
    const c=text[i];if(quoted){if(escaped)escaped=false;else if(c==='\\')escaped=true;else if(c==='"')quoted=false;continue;}
    if(c==='"')quoted=true;else if(c==='{'){if(depth++===0)start=i;}else if(c==='}'&&--depth===0){result.push(JSON.parse(text.slice(start,i+1)));start=-1;}
  }
  if(depth!==0||quoted)throw new Error('Incomplete govulncheck JSON');return result;
}
const messages=documents(run.stdout);const config=messages.find(item=>item.config)?.config;const sbom=messages.find(item=>item.SBOM)?.SBOM;
if(run.code!==0||!config||!sbom)throw new Error('govulncheck incomplete: '+run.stderr.slice(0,1000));
const advisories=new Map(messages.filter(item=>item.osv).map(item=>[item.osv.id,item.osv]));
const grouped=new Map();
for(const item of messages.filter(item=>item.finding)) {
  const f=item.finding;let entry=grouped.get(f.osv);if(!entry){const advisory=advisories.get(f.osv);entry={id:f.osv,summary:advisory?.summary,url:advisory?.database_specific?.url,aliases:advisory?.aliases,matched_symbols:0,modules:[],fixed_versions:[]};grouped.set(f.osv,entry);}
  entry.matched_symbols++;for(const frame of f.trace||[])if(frame.module&&!entry.modules.includes(frame.module))entry.modules.push(frame.module);
  if(f.fixed_version&&!entry.fixed_versions.includes(f.fixed_version))entry.fixed_versions.push(f.fixed_version);
}
const report={recordedAt:new Date().toISOString(),publicLaunchAllowed:false,binarySha256:createHash('sha256').update(await readFile(binary)).digest('hex'),scanner:config,sbom,unversionedModules:sbom.modules.filter(module=>!module.version||module.version==='(devel)'),status:grouped.size?'KNOWN_BINARY_SYMBOL_MATCHES':'NO_KNOWN_BINARY_SYMBOL_MATCHES',findings:[...grouped.values()],limitations:['Binary symbol presence is not application reachability or an exploitation proof.','Custom build main module is unversioned in Go build metadata; its source pin and upstream advisories need separate review (consensus/BUILD.md).','Known Go vulnerability database only; no unknown vulnerabilities, first-party Rust/JS or configuration assessment.','Loopback development isolation does not resolve public-deployment dependency advisories.']};
await writeFile(path.join(root,'results/comet-dependency-audit.json'),JSON.stringify(report,null,2));
console.log(JSON.stringify({status:report.status,advisories:grouped.size,findings:report.findings.map(({id,modules,fixed_versions})=>({id,modules,fixed_versions}))},null,2));
process.exitCode=grouped.size?1:0;
