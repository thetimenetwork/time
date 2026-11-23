#!/usr/bin/env node
import {spawn} from 'node:child_process';
import {readFile,writeFile,lstat} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {validateRelease,sha256,imagePin,json,releaseEngine,ENGINES} from './lib.mjs';

// The Dockerfile, node binary and label follow the validated manifest's engine.
// For v4 (no `engine` field) the arguments are exactly the pre-v5 arguments.
export function dockerBuildArgs(directory,manifest,tag,iidFile){
  const engine=releaseEngine(manifest);
  return ['build','--platform',manifest.platform,'--pull','--iidfile',iidFile,'--build-arg','RUST_IMAGE='+manifest.image_pins.rust,'--build-arg','GO_IMAGE='+manifest.image_pins.go,'--build-arg','RUNTIME_IMAGE='+manifest.image_pins.runtime,'--label','org.timecurrency.release-id='+manifest.release_id,...(engine==='v4'?[]:['--label','org.timecurrency.engine='+engine]),'--file',path.join(directory,'context',...ENGINES[engine].dockerfile.split('/')),'--tag',tag,path.join(directory,'context')];
}
// v4 keeps its original substring check; v5 must print exactly its version line.
export function checkVersions(engine,appVersion,cometVersion){
  const expected=ENGINES[engine]?.version;if(!expected)throw new Error('Unsupported release engine');
  if(!(engine==='v4'?appVersion.includes(expected):appVersion===expected)||!cometVersion.includes('0.38.26'))throw new Error('Unexpected runtime binary version');
  return true;
}

export function checkEnvironment(env=process.env){
  for(const name of ['TIME_IMAGE','REMOTE_SIGNER_IMAGE'])if(!imagePin(env[name]))throw new Error(name+' requires a pinned digest');
  for(const name of ['OPERATOR_CONFIG','SIGNER_CONFIG'])if(!env[name]||!path.isAbsolute(env[name]))throw new Error(name+' requires an absolute directory');
  return true;
}
async function command(args,capture=false){
  return new Promise((resolve,reject)=>{
    const child=spawn('docker',args,{stdio:capture?['ignore','pipe','inherit']:'inherit',windowsHide:true});let result='';
    if(capture)child.stdout.on('data',chunk=>{result+=chunk;if(result.length>1024*1024){child.kill();reject(new Error('Docker output exceeds bound'));}});
    child.on('error',reject);child.on('exit',code=>code===0?resolve(result):reject(new Error('Docker command failed: '+code)));
  });
}
async function sourceFile(directory,relative){
  if(typeof relative!=='string'||relative.includes('\\')||relative.includes('\0')||/^(?:\/|[A-Za-z]:)/.test(relative)||relative.split('/').some(p=>!p||p==='.'||p==='..'))throw new Error('Unsafe manifest path');
  let location=directory;
  for(const part of relative.split('/')){location=path.join(location,part);if((await lstat(location)).isSymbolicLink())throw new Error('Symlink in build input');}
  if(!(await lstat(location)).isFile())throw new Error('Nonregular build source');return location;
}
export async function buildCandidate(directory,tag){
  directory=path.resolve(directory);if(!/^[a-z0-9][a-z0-9./:_-]+$/.test(tag??''))throw new Error('Explicit local candidate image tag required');
  const manifest=validateRelease(await json(path.join(directory,'release.json'))),engine=releaseEngine(manifest),binary=ENGINES[engine].binary;
  for(const file of manifest.source_files)if(sha256(await readFile(await sourceFile(path.join(directory,'context'),file.path)))!==file.sha256)throw new Error('Build source digest mismatch');
  if(sha256(await readFile(path.join(directory,'sbom.spdx.json')))!==manifest.sbom_sha256)throw new Error('SBOM digest mismatch');
  if(sha256(await readFile(path.join(directory,'context','.dockerignore')))!==manifest.generated_dockerignore_sha256)throw new Error('Build allowlist changed');
  if(!manifest.source_files.some(file=>file.path===ENGINES[engine].dockerfile))throw new Error('Release does not contain the '+engine+' Dockerfile');
  const iidFile=path.join(directory,'image-id.txt');try{await lstat(iidFile);throw new Error('Existing build identity preserved; create a new release directory');}catch(e){if(e.code!=='ENOENT')throw e;}
  await command(dockerBuildArgs(directory,manifest,tag,iidFile));
  const imageId=(await readFile(iidFile,'utf8')).trim();if(!/^sha256:[a-f0-9]{64}$/.test(imageId))throw new Error('Unexpected Docker immutable image identity');
  const appVersion=(await command(['run','--rm','--network','none','--read-only','--entrypoint',binary,imageId,'--version'],true)).trim();
  const cometVersion=(await command(['run','--rm','--network','none','--read-only','--entrypoint','cometbft',imageId,'version'],true)).trim();
  checkVersions(engine,appVersion,cometVersion);
  const binaries=[];
  for(const name of [binary,'cometbft']){
    const output=await command(['run','--rm','--network','none','--read-only','--entrypoint','sha256sum',imageId,'/usr/local/bin/'+name],true);
    const digest=/^([a-f0-9]{64})\s/.exec(output)?.[1];if(!digest)throw new Error('Runtime binary digest missing');binaries.push({name,sha256:digest,platform:manifest.platform});
  }
  await command(['run','--rm','--network','none','--read-only',imageId,'help']);
  const artifact={release_id:manifest.release_id,image_id:imageId,platform:manifest.platform,binaries,sbom_sha256:manifest.sbom_sha256,image_pins:manifest.image_pins};
  const report={...artifact,artifact_identity_sha256:sha256(Buffer.from(JSON.stringify(artifact))),created_utc:new Date().toISOString(),status:'PASS_BUILD_AND_VERSION_ONLY',...(engine==='v4'?{}:{engine}),app_version:appVersion,comet_version:cometVersion,public_funds_allowed:false,multi_host_network_validated:false,remote_signer_validated:false};
  await writeFile(path.join(directory,'linux-build-smoke.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify(report,null,2));return report;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  (async()=>{if(process.argv[2]==='check-env'){checkEnvironment();console.log('Pinned operator environment accepted');}else if(process.argv[2]==='build')await buildCandidate(process.argv[3],process.argv[4]);else throw new Error('Usage: build.mjs build RELEASE_DIRECTORY LOCAL_TAG | check-env');})().catch(e=>{console.error(e.message);process.exitCode=1;});
}
