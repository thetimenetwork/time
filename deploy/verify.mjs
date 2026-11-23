#!/usr/bin/env node
import {spawn} from 'node:child_process';
import {writeFile,mkdir,readFile,lstat} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomUUID} from 'node:crypto';
import {json,sha256} from './lib.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
// One suite per engine. A v5 release context carries both test files, so v5 runs
// the 27 v4 kit tests plus the v5 tests (52 before the upgrade mechanism, 58 with
// its six, 63 with the five of the kit rehearsal). tools/release-v5.test.mjs checks these counts against the test() calls
// in the files.
export const SUITES=Object.freeze({
 v4:Object.freeze({packager:'../tools/release-v4.mjs',compose:'deploy/compose.yaml',files:['tools/release-v4.test.mjs'],tests:27,sources:file=>file.path.startsWith('deploy/')||/^tools\/release-v4(?:\.test)?\.mjs$/.test(file.path)}),
 v5:Object.freeze({packager:'../tools/release-v5.mjs',compose:'deploy/compose.v5.yaml',files:['tools/release-v4.test.mjs','tools/release-v5.test.mjs'],tests:27+63,sources:file=>file.path.startsWith('deploy/')||file.path.startsWith('tools/')})
});
const counted=(output,label,count)=>new RegExp('\\b'+label+' '+count+'\\b').test(output);
async function capture(executable,args,env=process.env){return new Promise((resolve,reject)=>{let stdout='',stderr='';const child=spawn(executable,args,{cwd:root,env,windowsHide:true,stdio:['ignore','pipe','pipe']});for(const [stream,name]of [[child.stdout,'stdout'],[child.stderr,'stderr']])stream.on('data',chunk=>{if(name==='stdout')stdout+=chunk;else stderr+=chunk;if(stdout.length+stderr.length>8*1024*1024){child.kill();reject(new Error('Verification output bound exceeded'));}});child.on('error',reject);child.on('exit',code=>resolve({code,stdout,stderr}));});}
async function main(){
  let args=process.argv.slice(2),engine='v4';if(args[0]==='--engine'){engine=args[1];args=args.slice(2);}if(!Object.hasOwn(SUITES,engine)||args.length>1)throw new Error('Usage: verify.mjs [--engine v4|v5] [NEW deploy/results/REPORT.json]');const suite=SUITES[engine],{createRelease}=await import(suite.packager);
  const out=path.resolve(args[0]??path.join(root,'deploy/results/operator-'+randomUUID()+'.json'));if(!out.startsWith(path.join(root,'deploy/results')+path.sep)||!out.endsWith('.json'))throw new Error('Choose NEW deploy/results/*.json report path');try{await lstat(out);throw new Error('Existing evidence preserved');}catch(e){if(e.code!=='ENOENT')throw e;}await mkdir(path.dirname(out),{recursive:true});
  const pins=await json(path.join(root,'deploy/images.verified.json')),directory=path.join(root,'releases','operator-check-'+randomUUID());const manifest=await createRelease({root,out:directory,imagePins:pins});
  const sourceFiles=manifest.source_files.filter(suite.sources);
  const windows=await capture(process.execPath,['--test',...suite.files]);await writeFile(out+'.host.log',windows.stdout+windows.stderr,{flag:'wx'});
  const docker=await capture('docker',['version','--format','{{json .Server}}']);
  const linux=await capture('docker',['run','--rm','--network','none','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=256m','--mount','type=bind,source='+path.join(directory,'context')+',target=/source,readonly','--workdir','/source',pins.runtime,'node','--test',...suite.files]);await writeFile(out+'.linux.log',linux.stdout+linux.stderr,{flag:'wx'});
  const unset={...process.env};for(const name of ['TIME_IMAGE','REMOTE_SIGNER_IMAGE','OPERATOR_CONFIG','SIGNER_CONFIG'])delete unset[name];const composeRef=path.join(root,suite.compose);const missing=await capture('docker',['compose','--file',composeRef,'config','--quiet'],unset);
  const configured={...unset,TIME_IMAGE:pins.runtime,REMOTE_SIGNER_IMAGE:pins.go,OPERATOR_CONFIG:path.join(root,'releases','operator-configuration-example'),SIGNER_CONFIG:path.join(root,'releases','signer-configuration-example')};const compose=await capture('docker',['compose','--file',composeRef,'config','--quiet'],configured);
  const unchanged=(await Promise.all(sourceFiles.map(async file=>sha256(await readFile(path.join(root,file.path)))===file.sha256))).every(Boolean);
  const checks={host_tests:windows.code===0&&counted(windows.stdout,'tests',suite.tests)&&counted(windows.stdout,'pass',suite.tests),linux_tests:linux.code===0&&counted(linux.stdout,'tests',suite.tests)&&counted(linux.stdout,'pass',suite.tests),linux_docker_server:docker.code===0&&JSON.parse(docker.stdout).Os==='linux',compose_missing_configuration_rejected:missing.code!==0,compose_schema_valid:compose.code===0,source_unchanged:unchanged};
  const report={schema_version:1,status:Object.values(checks).every(Boolean)?'PASS_OPERATOR_SOFTWARE_TESTS':'FAIL',...(engine==='v4'?{}:{engine,expected_tests:suite.tests,test_files:suite.files}),checks,created_utc:new Date().toISOString(),host_platform:process.platform,linux_runtime_image:pins.runtime,docker_server:docker.code===0?JSON.parse(docker.stdout):null,source_files:sourceFiles,test_context_release_id:manifest.release_id,test_context:directory,public_funds_allowed:false,multi_host_network_validated:false,remote_signer_validated:false,external_review_complete:false,logs:{host_sha256:sha256(Buffer.from(windows.stdout+windows.stderr)),linux_sha256:sha256(Buffer.from(linux.stdout+linux.stderr))},notes:['Linux tests ran on a single Docker Desktop Linux VM with no network and only an allowlisted readonly source mount.','The configured signer image in compose schema validation is a dummy digest solely for YAML validation; no signer container was started.','No validator network, independent custody, hardware signer or cross-host fencing is certified by these tests.']};
  await writeFile(out,JSON.stringify(report,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify({status:report.status,checks,report:out},null,2));if(report.status!=='PASS_OPERATOR_SOFTWARE_TESTS')process.exitCode=1;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(e=>{console.error(e.message);process.exitCode=1;});
