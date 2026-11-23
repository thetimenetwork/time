#!/usr/bin/env node
// Source-only by default. Runtime data, caches and private keys are never a
// build context. This creates a devnet candidate, never a monetary launch.
import { createHash, randomUUID } from 'node:crypto';
import { access, lstat, mkdir, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {validateRelease,releaseEngine} from '../deploy/lib.mjs';

export const CLIENT_FILES = [
 // account-security.mjs and own-node.mjs: imported by server-auth.mjs and server.mjs. Changes the distribution identity only, never the native release identity.
 'client-v4/server.mjs','client-v4/server-auth.mjs','client-v4/account-security.mjs','client-v4/own-node.mjs','client-v4/order-store.mjs','client-v4/blog-store.mjs','client-v4/archive.mjs','client-v4/certified-view.mjs','client-v4/light-client.mjs','client-v4/proof-verifier.mjs','client-v4/time-sdk.js','client-v4/external-signer.mjs','client-v4/checkpoint-refresh.mjs','client-v4/README.md','client-v4/nginx.example.conf',
 // The public API (deploy/api/README.md) and the security watch (deploy/watch/README.md), whose webhook, lock and log code the API uses. The same rule: distribution identity only.
 'client-v4/indexer.mjs','client-v4/api.mjs','client-v4/api/openapi.json','client-v4/security-watch.mjs','client-v4/security-watch-service.mjs','docs/integration-guide.md',
 'web-v4/wallet/index.html','web-v4/wallet/styles.css','web-v4/wallet/app.js','web-v4/wallet/vault.mjs','web-v4/wallet/names.mjs','web-v4/wallet/protection.mjs','web-v4/wallet/guards.mjs','web-v4/wallet/actions.mjs','web-v4/wallet/recovery.mjs','web-v4/wallet/vault-backup.mjs','web-v4/wallet/pos-ui.mjs','web-v4/wallet/security-ui.mjs','web-v4/wallet/security-flows.mjs','web-v4/wallet/signing.mjs','web-v4/wallet/upgrade-signal.mjs','web-v4/wallet/upgrade-signal-ui.mjs','web-v4/wallet/papers.mjs','web-v4/wallet/signup.mjs','web-v4/wallet/signup-ui.mjs','web-v4/wallet/reset.mjs','web-v4/wallet/README.md','web-v4/wallet/BACKUP_FORMAT.md','web-v4/wallet/vendor/argon2-4.12.0.umd.min.js','web-v4/wallet/vendor/LICENSE.hash-wasm','web-v4/wallet/vendor/PROVENANCE.json','web-v4/wallet/vendor/README.hash-wasm.md',
 // The demo blog on the gateway's second origin (it replaced the sample shop page and its login-only page). blog-store.mjs above keeps its posts.
 'web-v4/merchant/index.html','web-v4/merchant/app.js','web-v4/merchant/style.css','web-v4/shared/verifier/timecurrency_verifier_v4.js','web-v4/shared/verifier/timecurrency_verifier_v4_bg.wasm',
 // The menu of the public networks that the wallet, the blog and the explorer carry (the API reads it at start). Distribution identity only.
 'web-v4/shared/network-menu.js','web-v4/shared/network-menu.css',
 'deploy/gateway/start.mjs','deploy/gateway/Dockerfile','deploy/gateway/settings.example.json','deploy/gateway/README.md','deploy/gateway/time-gateway.service',
 'deploy/api/start.mjs','deploy/api/config.example.json','deploy/api/README.md','deploy/watch/start.mjs','deploy/watch/config.example.json','deploy/watch/README.md',
 // The explorer, which the API serves when its serve_explorer setting is on (web-v4/explorer/README.md). Distribution identity only.
 'web-v4/explorer/index.html','web-v4/explorer/styles.css','web-v4/explorer/app.js','web-v4/explorer/strings.mjs','web-v4/explorer/format.mjs','web-v4/explorer/route.mjs','web-v4/explorer/describe.mjs','web-v4/explorer/client.mjs','web-v4/explorer/check.mjs','web-v4/explorer/dom.mjs','web-v4/explorer/views.mjs','web-v4/explorer/README.md'
];

export const REQUIRED_FILES = ['Cargo.toml','Cargo.lock','rust-toolchain.toml','v2/Cargo.toml','v2/Cargo.lock','v4/Cargo.toml','v4/Cargo.lock','pos/Cargo.toml','pos/Cargo.lock','treasury/Cargo.toml','treasury/Cargo.lock','bitcoin-bridge/Cargo.toml','bitcoin-bridge/Cargo.lock','history/Cargo.toml','history/Cargo.lock','history/vectors.json','registration/Cargo.toml','registration/Cargo.lock','consensus/go.mod','consensus/go.sum','spec/action-v1.json'];
export const SOURCE_DIRS = ['src','v2/src','v4/src','pos/src','treasury/src','bitcoin-bridge/src','history/src','registration/src','v2/tests','v4/tests','pos/tests','treasury/tests','bitcoin-bridge/tests','registration/tests'];
export const TOOL_FILES = ['tools/release-v4.mjs','tools/release-v4.test.mjs'];
// A profile names everything that differs between engine releases. The v4
// profile reproduces the pre-v5 packager exactly: same allowlist, same identity
// bytes (no `engine` key), same SBOM name. tools/release-v5.mjs defines v5.
// optionalFiles are allowlisted and packaged only when present.
export const V4_PROFILE = Object.freeze({engine:'v4',script:'tools/release-v4.mjs',requiredFiles:REQUIRED_FILES,optionalFiles:[],sourceDirs:SOURCE_DIRS,toolFiles:TOOL_FILES,dockerfiles:['deploy/Dockerfile'],binaries:['time-node-v4','cometbft'],clientFiles:CLIENT_FILES});
const FORBIDDEN_PARTS = new Set(['.local','.tools','.git','target','node_modules','secrets','private','runtime','backups']);
const SECRET_NAME = /(?:^\.env(?:\.|$)|\.cookie$|wallet\.dat$|(?:private|secret|mnemonic|credential|seed)(?:[._-]|$)|\.(?:pem|key|p12|pfx)$)/i;
const PRIVATE_CONTENT = /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b/;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
function inspectCredentials(bytes,file){const value=bytes.toString('utf8');if(PRIVATE_CONTENT.test(value))throw new Error('Private credential material in release source');if(file.endsWith('.json')){const parsed=JSON.parse(value.replace(/^\uFEFF/,''));const inspect=node=>{if(!node||typeof node!=='object')return;for(const[key,item]of Object.entries(node)){if(/^(?:priv_key|private_key|privateKey|mnemonic|seed|password|cookie|access_token|refresh_token)$/.test(key)&&item!==null&&item!==''&&item!==false)throw new Error('Private credential field in release JSON');inspect(item);}};inspect(parsed);}}

export function safeRelative(value) {
  if (typeof value !== 'string' || !value || !/^[A-Za-z0-9._/-]+$/.test(value) || path.posix.isAbsolute(value) || /^[A-Za-z]:/.test(value) || path.posix.normalize(value) !== value) throw new Error('Noncanonical or escaping release path');
  const parts=value.split('/');
  if (parts.some(part=>part==='..'||part==='.'||!part||FORBIDDEN_PARTS.has(part.toLowerCase())||SECRET_NAME.test(part))) throw new Error('Forbidden runtime/secret path in release');
  return value;
}
export function validateImagePins(pins) {
  for (const kind of ['rust','go','runtime']) if (!/^[a-zA-Z0-9][a-zA-Z0-9./:_-]*@sha256:[a-f0-9]{64}$/.test(pins?.[kind]??'')) throw new Error(`Pinned ${kind} image digest required`);
  return pins;
}
async function regular(root, relative) {
  safeRelative(relative);let current=root;
  for (const part of relative.split('/')) {current=path.join(current,part);const info=await lstat(current);if(info.isSymbolicLink())throw new Error('Symlink/junction in release input');}
  const info=await lstat(current);if(!info.isFile()||info.nlink!==1)throw new Error('Release input is not a single-link regular file');return current;
}
async function noLinks(location, missing = false) {
  const resolved=path.resolve(location),parts=resolved.slice(path.parse(resolved).root.length).split(path.sep);let current=path.parse(resolved).root;
  for(const part of parts){current=path.join(current,part);try{if((await lstat(current)).isSymbolicLink())throw new Error('Symlink/junction in release path');}catch(error){if(missing&&error.code==='ENOENT')return;throw error;}}
}
function allowed(relative, profile=V4_PROFILE) {return profile.requiredFiles.includes(relative)||profile.optionalFiles.includes(relative)||profile.toolFiles.includes(relative)||profile.sourceDirs.some(dir=>relative.startsWith(dir+'/')&&relative.endsWith('.rs'))||relative.startsWith('deploy/')&&!relative.startsWith('deploy/results/')&&/\.(?:mjs|go|json|md|toml|ya?ml|service|sh)$/.test(relative)||profile.dockerfiles.includes(relative);}
export async function collectReleaseFiles(root, extraPaths=[], profile=V4_PROFILE) {
  root=await realpath(root);const files=[...profile.requiredFiles,...profile.toolFiles];
  async function walk(relative) {
    const info=await lstat(path.join(root,relative));if(info.isSymbolicLink())throw new Error('Symlink/junction in build source');
    for(const entry of await readdir(path.join(root,relative),{withFileTypes:true})){
      const file=path.posix.join(relative,entry.name);if(file==='deploy/results')continue;safeRelative(file);if(entry.isSymbolicLink())throw new Error('Symlink/junction in build source');
      if(entry.isDirectory())await walk(file);else if(entry.isFile()&&allowed(file,profile))files.push(file);
    }
  }
  for(const dir of [...profile.sourceDirs,'deploy'])await walk(dir);
  // Exact-case name match, also on case-insensitive file systems.
  for(const file of profile.optionalFiles){safeRelative(file);let names=[];try{names=await readdir(path.join(root,path.posix.dirname(file)));}catch(error){if(error.code!=='ENOENT')throw error;}if(names.includes(path.posix.basename(file)))files.push(file);}
  for(const file of extraPaths){safeRelative(file);if(!allowed(file,profile))throw new Error('Input is outside the release allowlist');files.push(file);}
  const result=[];
  for(const file of [...new Set(files)].sort()){
    if(!allowed(file,profile))throw new Error('Input is outside the release allowlist');const location=await regular(root,file);const bytes=await readFile(location);
    inspectCredentials(bytes,file);
    result.push({path:file,size:bytes.length,sha256:digest(bytes)});
  }
  return result;
}
export function cargoPackages(text) {
  const result=[];
  for(const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)){
    const field=name=>new RegExp('^'+name+' = "([^"\\n]+)"','m').exec(block)?.[1];const name=field('name'),version=field('version');
    if(!name||!version)throw new Error('Cargo lock package fields missing');result.push({name,version,source:field('source')??'workspace',checksum:field('checksum')??null});
  }
  return result;
}
export async function createRelease({root,out,imagePins,platform='linux/amd64',binaries={},evidence=[],sourceDateEpoch=0,profile=V4_PROFILE}) {
  root=await realpath(root);out=path.resolve(out);validateImagePins(imagePins);imagePins={rust:imagePins.rust,go:imagePins.go,runtime:imagePins.runtime};if(!['linux/amd64','linux/arm64'].includes(platform))throw new Error('Unsupported operator platform');if(!Number.isSafeInteger(sourceDateEpoch)||sourceDateEpoch<0)throw new Error('Invalid reproducible source epoch');
  const relative=path.relative(root,out).split(path.sep).join('/');if(!relative||relative.startsWith('..')||path.isAbsolute(relative)||profile.sourceDirs.some(dir=>relative.toLowerCase()===dir||relative.toLowerCase().startsWith(dir+'/')))throw new Error('Release output must be a new non-runtime directory within production');safeRelative(relative);await noLinks(out,true);
  try{await access(out);throw new Error('Existing release output preserved');}catch(error){if(error.code!=='ENOENT')throw error;}
  const files=await collectReleaseFiles(root,[],profile);await mkdir(path.join(out,'context'),{recursive:true});
  for(const file of files){const bytes=await readFile(await regular(root,file.path));if(digest(bytes)!==file.sha256)throw new Error('Source changed while packaging');const target=path.join(out,'context',file.path);await mkdir(path.dirname(target),{recursive:true});await writeFile(target,bytes,{flag:'wx'});}
  const dockerignore='**\n!**/\n'+files.map(file=>'!'+file.path).join('\n')+'\n';await writeFile(path.join(out,'context','.dockerignore'),dockerignore,{flag:'wx'});
  const executableRecords=[];
  for(const [name,source] of Object.entries(binaries)){
    if(!profile.binaries.includes(name))throw new Error('Unsupported executable name');const relative=path.relative(root,path.resolve(source)).split(path.sep).join('/');
    // Compiled binaries are admitted explicitly and never copied into build context.
    if(relative.startsWith('../')||path.isAbsolute(relative)||relative.split('/').some(part=>['.local','.tools'].includes(part.toLowerCase())))throw new Error('Binary outside approved production build output');
    await noLinks(source);const info=await lstat(source);if(!info.isFile()||info.isSymbolicLink())throw new Error('Binary must be a regular file');const bytes=await readFile(source);
    const machine=bytes.length>=20?bytes.readUInt16LE(18):0;if(bytes[0]!==127||bytes.toString('ascii',1,4)!=='ELF'||machine!==(platform==='linux/amd64'?62:183))throw new Error('Linux executable architecture mismatch');
    await mkdir(path.join(out,'bin'),{recursive:true});await writeFile(path.join(out,'bin',name),bytes,{flag:'wx',mode:0o755});executableRecords.push({name,size:bytes.length,sha256:digest(bytes),platform});
  }
  const evidenceRecords=[];
  for(const source of evidence){const relative=path.relative(root,path.resolve(source)).split(path.sep).join('/');safeRelative(relative);if(!/^(?:results-v4(?:-engine)?|results-fixes|bitcoin-bridge\/results|deploy\/results)\/.+\.json$/.test(relative))throw new Error('Evidence outside public result allowlist');const file=await regular(root,relative);const bytes=await readFile(file);inspectCredentials(bytes,relative);evidenceRecords.push({path:relative,sha256:digest(bytes),size:bytes.length});}
  executableRecords.sort((a,b)=>a.name.localeCompare(b.name));evidenceRecords.sort((a,b)=>a.path.localeCompare(b.path));
  // Key order matches deploy/lib.mjs releaseIdentity. A v4 profile writes no `engine` key.
  const sourceIdentity={schema_version:2,protocol_version:4,...(profile.engine==='v4'?{}:{engine:profile.engine}),platform,image_pins:imagePins,source_files:files,generated_dockerignore_sha256:digest(Buffer.from(dockerignore)),binaries:executableRecords,evidence:evidenceRecords};
  const sourceId=digest(Buffer.from(JSON.stringify(sourceIdentity)));
  const packages=new Map();for(const lock of profile.requiredFiles.filter(file=>file.endsWith('Cargo.lock')))for(const pkg of cargoPackages(await readFile(path.join(root,lock),'utf8')))packages.set(pkg.name+'@'+pkg.version+'#'+pkg.source,pkg);
  const created=new Date(sourceDateEpoch*1000).toISOString();
  const inventory=[...packages.values()].map(pkg=>({SPDXID:'SPDXRef-'+digest(Buffer.from(pkg.name+'@'+pkg.version+pkg.source)).slice(0,24),name:pkg.name,versionInfo:pkg.version,downloadLocation:pkg.source==='workspace'?'NOASSERTION':pkg.source,filesAnalyzed:false,licenseConcluded:'NOASSERTION',licenseDeclared:'NOASSERTION',copyrightText:'NOASSERTION',...(pkg.checksum?{checksums:[{algorithm:'SHA256',checksumValue:pkg.checksum}]}:{})}));
  for(const line of (await readFile(path.join(root,'consensus/go.sum'),'utf8')).split('\n')){const [name,version,sum]=line.trim().split(/\s+/);if(!sum||version.endsWith('/go.mod'))continue;inventory.push({SPDXID:'SPDXRef-go-'+digest(Buffer.from(name+'@'+version)).slice(0,24),name,versionInfo:version,downloadLocation:'NOASSERTION',filesAnalyzed:false,licenseConcluded:'NOASSERTION',licenseDeclared:'NOASSERTION',copyrightText:'NOASSERTION',comment:'Go checksum inventory; may include unused historical modules. Go h1 module-directory checksum: '+sum});}
  const sbom={spdxVersion:'SPDX-2.3',dataLicense:'CC0-1.0',SPDXID:'SPDXRef-DOCUMENT',name:'timecurrency-'+profile.engine+'-source-'+sourceId,documentNamespace:'https://example.invalid/timecurrency/sources/'+sourceId,creationInfo:{created,creators:['Tool: timecurrency-release-'+profile.engine]},packages:inventory,relationships:inventory.map(pkg=>({spdxElementId:'SPDXRef-DOCUMENT',relationshipType:'DESCRIBES',relatedSpdxElement:pkg.SPDXID}))};
  const sbomBytes=Buffer.from(JSON.stringify(sbom,null,2)+'\n');await writeFile(path.join(out,'sbom.spdx.json'),sbomBytes,{flag:'wx'});
  const identity={...sourceIdentity,sbom_sha256:digest(sbomBytes)},id=digest(Buffer.from(JSON.stringify(identity)));
  const manifest={...identity,release_id:id,created_utc:new Date().toISOString(),source_date_epoch:sourceDateEpoch,status:'DEVELOPMENT_CANDIDATE',public_funds_allowed:false,mainnet_receipts_enabled:false,monetary_enable_toggle:false,sbom_scope:'Cargo.lock and Go checksum inventory; Go entries can overinclude historical modules. Exact binary module usage, license completeness and vulnerability review require external tooling.',external_gates:{independent_security_review:'OUTSTANDING_SIGNED_ATTESTATION_REQUIRED',operator_independence:'OUTSTANDING_SIGNED_ATTESTATIONS_REQUIRED',multi_host_linux_fault_validation:'OUTSTANDING_SIGNED_ATTESTATION_REQUIRED',remote_signer_fencing:'OUTSTANDING_SIGNED_ATTESTATION_REQUIRED',bitcoin_mainnet_custody:'NOT_CONFIGURED_NO_MAINNET_FUNDS'},linux_runtime_validation:'NOT_RUN_BY_PACKAGER'};
  await writeFile(path.join(out,'release.json'),JSON.stringify(manifest,null,2)+'\n',{flag:'wx'});return manifest;
}

export async function createSdkDistribution({root,nativeDirectory,out,evidence=[],profile=V4_PROFILE}) {
 root=await realpath(root);await noLinks(nativeDirectory);nativeDirectory=await realpath(nativeDirectory);out=path.resolve(out);const nativeRelative=path.relative(root,nativeDirectory).split(path.sep).join('/');safeRelative(nativeRelative);if(!nativeRelative.startsWith('releases/'))throw Error('Native component must be an allowlisted production release');const relative=path.relative(root,out).split(path.sep).join('/');safeRelative(relative);if(!relative.startsWith('releases/'))throw Error('SDK distribution must use a NEW production/releases subdirectory');await noLinks(out,true);try{await access(out);throw Error('Existing distribution preserved');}catch(error){if(error.code!=='ENOENT')throw error;}
 const nativeArtifacts=new Map();for(const file of ['release.json','sbom.spdx.json','linux-build-smoke.json','linux-native-validation/report.json']){const bytes=await readFile(await regular(nativeDirectory,file));inspectCredentials(bytes,file);nativeArtifacts.set(file,bytes);}const parsed=file=>JSON.parse(nativeArtifacts.get(file).toString('utf8').replace(/^\uFEFF/,''));
 const native=validateRelease(parsed('release.json')),smoke=parsed('linux-build-smoke.json'),validation=parsed('linux-native-validation/report.json');
 if(releaseEngine(native)!==profile.engine)throw Error('Native release engine does not match this distribution');
 if(smoke.release_id!==native.release_id||smoke.status!=='PASS_BUILD_AND_VERSION_ONLY'||validation.release_id!==native.release_id||validation.status!=='PASS_LINUX_NATIVE_TESTS_AND_CLIPPY')throw Error('Native component requires source-bound Linux build, tests and Clippy');
 const artifactIdentity={release_id:smoke.release_id,image_id:smoke.image_id,platform:smoke.platform,binaries:smoke.binaries,sbom_sha256:smoke.sbom_sha256,image_pins:smoke.image_pins};if(!/^sha256:[a-f0-9]{64}$/.test(smoke.image_id??'')||digest(Buffer.from(JSON.stringify(artifactIdentity)))!==smoke.artifact_identity_sha256||smoke.sbom_sha256!==native.sbom_sha256)throw Error('Native binary/image artifact identity mismatch');
 const nativeCore=native.source_files.filter(file=>!file.path.startsWith('deploy/')&&!file.path.startsWith('tools/')&&!file.path.startsWith('consensus/'));if(validation.host_context_unchanged!==true||validation.source_checks_after_present!==true||JSON.stringify(validation.source_files)!==JSON.stringify(nativeCore))throw Error('Native validation source scope mismatch');
 const ignored=await readFile(await regular(nativeDirectory,'context/.dockerignore'));if(digest(ignored)!==native.generated_dockerignore_sha256)throw Error('Native Docker allowlist changed');
 const sdk=[];await mkdir(path.join(out,'gateway-context'),{recursive:true});for(const file of profile.clientFiles){const bytes=await readFile(await regular(root,file));inspectCredentials(bytes,file);const target=path.join(out,'gateway-context',file);await mkdir(path.dirname(target),{recursive:true});await writeFile(target,bytes,{flag:'wx'});sdk.push({path:file,size:bytes.length,sha256:digest(bytes)});}
 const ignore='**\n!**/\n'+sdk.map(file=>'!'+file.path).join('\n')+'\n';await writeFile(path.join(out,'gateway-context','.dockerignore'),ignore,{flag:'wx'});
 const nativeRecords=[];for(const file of native.source_files){if(!allowed(file.path,profile))throw Error('Native source outside release allowlist');const bytes=await readFile(await regular(path.join(nativeDirectory,'context'),file.path));inspectCredentials(bytes,file.path);if(digest(bytes)!==file.sha256)throw Error('Native context changed');const target=path.join(out,'native','context',file.path);await mkdir(path.dirname(target),{recursive:true});await writeFile(target,bytes,{flag:'wx'});nativeRecords.push(file);}
 const artifacts=[];for(const[file,bytes]of nativeArtifacts){const target=path.join(out,'native',file);await mkdir(path.dirname(target),{recursive:true});await writeFile(target,bytes,{flag:'wx'});artifacts.push({path:'native/'+file,size:bytes.length,sha256:digest(bytes)});}await writeFile(path.join(out,'native/context/.dockerignore'),ignored,{flag:'wx'});
 const packagingTools=[];for(const file of profile.toolFiles){const bytes=await readFile(await regular(root,file));inspectCredentials(bytes,file);const target=path.join(out,'packager',file);await mkdir(path.dirname(target),{recursive:true});await writeFile(target,bytes,{flag:'wx'});packagingTools.push({path:file,size:bytes.length,sha256:digest(bytes)});}
 const proofs=[];const requested=[...new Set([...native.evidence.map(file=>file.path),...evidence])].sort();for(const file of requested){safeRelative(file);if(!/^(?:results-v4(?:-engine)?|results-fixes|bitcoin-bridge\/results|deploy\/results)\/.+\.json$/.test(file))throw Error('Distribution evidence outside allowlist');const bytes=await readFile(await regular(root,file));inspectCredentials(bytes,file);const expected=native.evidence.find(row=>row.path===file);if(expected&&expected.sha256!==digest(bytes))throw Error('Native evidence changed');const target=path.join(out,'evidence',file);await mkdir(path.dirname(target),{recursive:true});await writeFile(target,bytes,{flag:'wx'});proofs.push({path:file,size:bytes.length,sha256:digest(bytes)});}
 for(const file of sdk)if(digest(await readFile(await regular(root,file.path)))!==file.sha256)throw Error('SDK source changed during packaging');const sbomBytes=await readFile(path.join(out,'native/sbom.spdx.json'));if(digest(sbomBytes)!==native.sbom_sha256)throw Error('Native SBOM changed');
 const identity={schema_version:1,kind:'COMBINED_PRIVATE_DEVNET_DISTRIBUTION',...(profile.engine==='v4'?{}:{engine:profile.engine}),native_release_id:native.release_id,native_image_id:smoke.image_id,native_binaries:smoke.binaries,native_artifacts:artifacts,packaging_tools:packagingTools,sdk_files:sdk,gateway_dockerignore_sha256:digest(Buffer.from(ignore)),runtime_image:native.image_pins.runtime,evidence:proofs};const distribution={...identity,distribution_id:digest(Buffer.from(JSON.stringify(identity))),created_utc:new Date().toISOString(),node_version:'26.13.0',public_funds_allowed:false,mainnet_receipts_enabled:false,monetary_enable_toggle:false,external_gates:native.external_gates,gateway_container_validation:'NOT_RUN_BY_PACKAGER',scope:'Native and gateway components have separate identities. Native signer leases remain scoped to the native release ID. No automatic publishing, certificate provisioning or public monetary launch.'};await writeFile(path.join(out,'distribution.json'),JSON.stringify(distribution,null,2)+'\n',{flag:'wx'});return distribution;
}
export async function cli(profile=V4_PROFILE,argv=process.argv){const script=profile.script,name=script.split('/').at(-1);if(argv[2]==='distribution'){const[nativeDirectory,out,...evidence]=argv.slice(3);if(!out)throw Error('Usage: '+name+' distribution NATIVE_DIRECTORY NEW_OUTPUT_DIRECTORY [PUBLIC_EVIDENCE_JSON...]');const result=await createSdkDistribution({root:fileURLToPath(new URL('../',import.meta.url)),nativeDirectory,out,evidence,profile});console.log(JSON.stringify({distribution_id:result.distribution_id,out:path.resolve(out),public_funds_allowed:false},null,2));return;}const options={root:fileURLToPath(new URL('../',import.meta.url)),out:null,imagePins:{},binaries:{},evidence:[],profile};for(let i=2;i<argv.length;i++){const flag=argv[i];if(flag==='--help'){console.log('node '+script+' --out NEW_RELEASE_DIR --rust-image NAME@sha256:DIGEST --go-image NAME@sha256:DIGEST --runtime-image NAME@sha256:DIGEST [--platform linux/amd64] [--binary NAME=PATH] [--evidence RESULT_JSON]\nDevelopment candidate only; private/runtime data is never included and external launch gates remain outstanding.');return;}const value=argv[++i];if(!value)throw Error('Missing option value');if(flag==='--out')options.out=value;else if(flag==='--platform')options.platform=value;else if(flag==='--rust-image')options.imagePins.rust=value;else if(flag==='--go-image')options.imagePins.go=value;else if(flag==='--runtime-image')options.imagePins.runtime=value;else if(flag==='--evidence')options.evidence.push(value);else if(flag==='--binary'){const split=value.indexOf('=');if(split<=0)throw Error('Binary requires NAME=PATH');options.binaries[value.slice(0,split)]=value.slice(split+1);}else throw Error('Unsupported option');}if(!options.out)options.out=path.join(options.root,'releases',profile.engine+'-'+randomUUID());const manifest=await createRelease(options);console.log(JSON.stringify({release_id:manifest.release_id,...(manifest.engine?{engine:manifest.engine}:{}),out:path.resolve(options.out),public_funds_allowed:false,external_gates:manifest.external_gates},null,2));}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))cli(V4_PROFILE).catch(error=>{console.error(error.message);process.exitCode=1;});
