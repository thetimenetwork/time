#!/usr/bin/env node
import{spawn}from'node:child_process';import{readFile,writeFile,copyFile}from'node:fs/promises';import path from'node:path';import{fileURLToPath}from'node:url';import{sha256,json}from'./lib.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
async function run(args){return new Promise((resolve,reject)=>{const child=spawn('docker',args,{cwd:root,windowsHide:true,stdio:['ignore','pipe','pipe']});let stdout='',stderr='';child.stdout.on('data',chunk=>stdout+=chunk);child.stderr.on('data',chunk=>stderr+=chunk);child.on('error',reject);child.on('exit',code=>resolve({code,stdout,stderr}));});}
const folder=path.resolve(process.argv[2]??'');if(!folder.startsWith(path.join(root,'deploy/results/comet-audit-')))throw new Error('Use an existing owned Comet binary-audit evidence directory');
const report=await json(path.join(folder,'report.json')),pins=await json(path.join(root,'deploy/images.verified.json'));
for(const lock of report.comet_source.locks){const bytes=await readFile(path.join(root,lock.path));if(sha256(bytes)!==lock.sha256)throw new Error('Consensus lock changed');await writeFile(path.join(folder,path.basename(lock.path)),bytes,{flag:'wx'});}
await copyFile(path.join(root,'deploy/comet-source-review.go'),path.join(folder,'source-review.go'));
const script=`#!/bin/sh
set -eu
export GOTOOLCHAIN=local CGO_ENABLED=0 GOMAXPROCS=2 GOFLAGS=-p=1
go mod download -json github.com/cometbft/cometbft@v0.38.26 > /evidence/comet-module.json
grep -F '"Sum": "h1:MIPYgOSvyyiN1jo3SZljKy4ZXqs896aQnj3pQFfUmaE="' /evidence/comet-module.json >/dev/null
grep -F '"Hash": "94d77f9f51a72e2b7d832798859f6222f08028f8"' /evidence/comet-module.json >/dev/null
mkdir /source
cp -a /go/pkg/mod/github.com/cometbft/cometbft@v0.38.26/. /source/
chmod -R u+w /source
cp /evidence/go.mod /evidence/go.sum /source/
cd /source
sha256sum go.mod go.sum > /evidence/locks-before.txt
go mod download
go mod verify > /evidence/source-modules-verified.txt
go list -mod=readonly -deps ./cmd/cometbft > /evidence/source-packages.txt
sha256sum --check /evidence/locks-before.txt > /evidence/locks-after.txt
go mod download -json golang.org/x/vuln@v1.9.0 > /evidence/review-tool-module.json
grep -F '"Sum": "h1:12VaqnI9kJfqwRoPptxoqsUhQtdfrSbdksT7X/KY/sc="' /evidence/review-tool-module.json >/dev/null
cd /go/pkg/mod/golang.org/x/vuln@v1.9.0
go run -mod=readonly /evidence/source-review.go /evidence/report.json /evidence/source-packages.txt > /evidence/main-module-review.raw.json
`;
await writeFile(path.join(folder,'source-scan.sh'),script,{flag:'wx'});console.log('Reviewing every returned main-module OSV entry against exact pinned package graph...');const scan=await run(['run','--rm','--network','default','--mount','type=bind,source='+folder+',target=/evidence',pins.go,'sh','/evidence/source-scan.sh']);await writeFile(path.join(folder,'source-review-stderr.log'),scan.stderr,{flag:'wx'});if(scan.code!==0)throw new Error('Source review failed; logs preserved');
const reviewed=await json(path.join(folder,'main-module-review.raw.json'));const files=[];for(const name of ['go.mod','go.sum','source-review.go','source-scan.sh','comet-module.json','source-modules-verified.txt','source-packages.txt','locks-before.txt','locks-after.txt','review-tool-module.json','main-module-review.raw.json','source-review-stderr.log'])files.push({name,sha256:sha256(await readFile(path.join(folder,name)))});
for(const lock of report.comet_source.locks)if(sha256(await readFile(path.join(root,lock.path)))!==lock.sha256)throw new Error('Consensus lock changed during review');
const output={schema_version:1,recorded_utc:new Date().toISOString(),...reviewed,binary_report_sha256:sha256(await readFile(path.join(folder,'report.json'))),candidate_image_id:report.candidate_image_id,go_image:pins.go,files,source_unchanged:true};await writeFile(path.join(folder,'main-module-review.json'),JSON.stringify(output,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify({status:output.status,advisories:output.reviewed.length,applicable:output.applicable,report:path.join(folder,'main-module-review.json')},null,2));if(output.applicable.length)process.exitCode=1;
