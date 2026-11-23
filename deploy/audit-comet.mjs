#!/usr/bin/env node
// Public binary and provenance only. No repository/runtime/private-key mounts.
import {spawn} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {createReadStream} from 'node:fs';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {json,sha256} from './lib.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
const TOOL_VERSION='v1.9.0',TOOL_SUM='h1:12VaqnI9kJfqwRoPptxoqsUhQtdfrSbdksT7X/KY/sc=',TOOL_COMMIT='e672cbe8fbc8c76e28fcb6db0efd9ce354e0dac5';
async function hash(file){const result=createHash('sha256');for await(const chunk of createReadStream(file))result.update(chunk);return result.digest('hex');}
async function run(args){return new Promise((resolve,reject)=>{const child=spawn('docker',args,{cwd:root,windowsHide:true,stdio:['ignore','pipe','pipe']});let stdout='',stderr='';child.stdout.on('data',chunk=>stdout+=chunk);child.stderr.on('data',chunk=>stderr+=chunk);child.on('error',reject);child.on('exit',code=>resolve({code,stdout,stderr}));});}
function documents(text){const messages=[];let depth=0,start=0,quoted=false,escaped=false;for(let index=0;index<text.length;index++){const char=text[index];if(quoted){if(escaped)escaped=false;else if(char==='\\')escaped=true;else if(char==='"')quoted=false;continue;}if(char==='"')quoted=true;else if(char==='{'){if(depth++===0)start=index;}else if(char==='}'&&--depth===0)messages.push(JSON.parse(text.slice(start,index+1)));}if(depth||quoted)throw new Error('Incomplete scanner JSON stream');return messages;}
async function main(){
 const release=path.resolve(process.argv[2]??path.join(root,'releases/devnet-v4-linux-candidate-001')),image=process.argv[3]??'time-v4:devnet-candidate-001';const baseline=await json(path.join(release,'release.json')),pins=await json(path.join(root,'deploy/images.verified.json'));
 const folder=path.join(root,'deploy/results','comet-audit-'+randomUUID());await mkdir(folder,{recursive:true});
 const inspection=await run(['image','inspect',image]);if(inspection.code!==0)throw new Error('Candidate image unavailable');const inspected=JSON.parse(inspection.stdout)[0];if(inspected.Config.Labels['org.timecurrency.release-id']!==baseline.release_id)throw new Error('Candidate image/source manifest mismatch');
 const locks=[];for(const name of ['consensus/go.mod','consensus/go.sum']){const expected=baseline.source_files.find(file=>file.path===name);if(!expected||await hash(path.join(root,name))!==expected.sha256)throw new Error('Comet source lock changed since image build');locks.push(expected);}
 const owned='time-comet-audit-'+randomUUID();let created=false;try{const creation=await run(['create','--network','none','--name',owned,'--entrypoint','cometbft',inspected.Id,'version']);if(creation.code!==0)throw new Error('Could not create stopped extraction container');created=true;const copy=await run(['cp',owned+':/usr/local/bin/cometbft',path.join(folder,'cometbft')]);if(copy.code!==0)throw new Error('Could not extract public consensus binary');}finally{if(created)await run(['rm',owned]);}
 const binaryHash=await hash(path.join(folder,'cometbft'));
 const script=`#!/bin/sh
set -eu
export GOTOOLCHAIN=local CGO_ENABLED=0 GOMAXPROCS=2 GOFLAGS=-p=1
go version > /evidence/go-version.txt
go mod download -json golang.org/x/vuln@${TOOL_VERSION} > /evidence/tool-module.json
grep -F '"Sum": "${TOOL_SUM}"' /evidence/tool-module.json > /dev/null
grep -F '"Hash": "${TOOL_COMMIT}"' /evidence/tool-module.json > /dev/null
go install golang.org/x/vuln/cmd/govulncheck@${TOOL_VERSION}
cp /go/bin/govulncheck /evidence/govulncheck
go version -m /evidence/govulncheck > /evidence/tool-buildinfo.txt
go version -m /evidence/cometbft > /evidence/comet-buildinfo.txt
/evidence/cometbft version > /evidence/comet-version.txt
curl --proto '=https' --fail --show-error --location https://vuln.go.dev/index/db.json > /evidence/database.json
/evidence/govulncheck -help > /evidence/tool-help.txt 2>&1
/evidence/govulncheck -db https://vuln.go.dev -mode binary -json /evidence/cometbft > /evidence/raw.json
`;
 await writeFile(path.join(folder,'scan.sh'),script,{flag:'wx'});console.log('Scanning immutable Comet image with pinned official govulncheck...');
 const scan=await run(['run','--rm','--network','default','--mount','type=bind,source='+folder+',target=/evidence',pins.go,'sh','/evidence/scan.sh']);await writeFile(path.join(folder,'scanner-stderr.log'),scan.stderr,{flag:'wx'});if(scan.code!==0)throw new Error('Scanner failed; raw logs preserved at '+folder);
 const raw=await readFile(path.join(folder,'raw.json'),'utf8'),messages=documents(raw),config=messages.find(message=>message.config)?.config,sbom=messages.find(message=>message.SBOM)?.SBOM;if(!config||!sbom)throw new Error('Scanner omitted required configuration/SBOM');
 const findings=messages.filter(message=>message.finding).map(message=>message.finding),advisories=messages.filter(message=>message.osv).map(message=>message.osv);const module=await json(path.join(folder,'tool-module.json'));
 const files=[];for(const name of ['cometbft','govulncheck','tool-module.json','tool-buildinfo.txt','comet-buildinfo.txt','comet-version.txt','go-version.txt','database.json','raw.json','scan.sh','scanner-stderr.log'])files.push({name,sha256:await hash(path.join(folder,name))});
 const unchanged=await hash(path.join(folder,'cometbft'))===binaryHash&&(await Promise.all(locks.map(async file=>await hash(path.join(root,file.path))===file.sha256))).every(Boolean);
 const report={schema_version:1,status:findings.length?'KNOWN_BINARY_FINDINGS':'NO_KNOWN_BINARY_FINDINGS',recorded_utc:new Date().toISOString(),source_release_id:baseline.release_id,source_manifest_sha256:await hash(path.join(release,'release.json')),candidate_image_id:inspected.Id,go_image:pins.go,comet_source:{module:'github.com/cometbft/cometbft',version:'v0.38.26',commit:'94d77f9f51a72e2b7d832798859f6222f08028f8',sum:'h1:MIPYgOSvyyiN1jo3SZljKy4ZXqs896aQnj3pQFfUmaE=',locks},comet_version:(await readFile(path.join(folder,'comet-version.txt'),'utf8')).trim(),tool:{version:TOOL_VERSION,module_sum:module.Sum,commit:module.Origin.Hash,source:'https://go.googlesource.com/vuln',documentation:'https://pkg.go.dev/golang.org/x/vuln@v1.9.0/cmd/govulncheck'},database:await json(path.join(folder,'database.json')),scanner:config,sbom,findings,advisories,files,source_binary_unchanged:unchanged,public_funds_allowed:false,limitations:['Known Go vulnerability database and this precise Linux binary only; this is not a whole-platform security clearance.','Binary symbol presence is not runtime reachability; reflection/unsafe and unknown vulnerabilities limit analysis.','Comet custom main module is unversioned in Go build metadata. Its explicitly pinned upstream version and advisories require separate source-version review; no findings are ignored or suppressed.','This pre-history Comet binary remains relevant only while the recorded consensus/go.mod and go.sum remain exactly unchanged. The application source is not assessed by this scan.']};
 if(!unchanged||module.Sum!==TOOL_SUM||module.Origin.Hash!==TOOL_COMMIT)throw new Error('Source/tool binding verification failed');await writeFile(path.join(folder,'report.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify({status:report.status,findings:findings.length,advisories:advisories.length,report:path.join(folder,'report.json')},null,2));if(findings.length)process.exitCode=1;
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
