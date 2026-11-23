#!/usr/bin/env node
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const metadata=JSON.parse(await readFile(new URL('../web/wallet/vendor/PROVENANCE.json',import.meta.url),'utf8'));
const bytes=await readFile(new URL('../web/wallet/vendor/'+metadata.vendoredFile,import.meta.url));
const actual=createHash('sha256').update(bytes).digest('hex');
if(actual!==metadata.vendoredSHA256)throw new Error('Vendored browser dependency checksum mismatch');
const response=await fetch('https://api.osv.dev/v1/query',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({package:{name:metadata.package,ecosystem:'npm'},version:metadata.version}),signal:AbortSignal.timeout(20000)});
if(!response.ok)throw new Error('OSV query failed');
const result=await response.json();if(result.error||result.next_page_token)throw new Error('OSV results incomplete');
const findings=(result.vulns||[]).map(value=>({id:value.id,summary:value.summary,aliases:value.aliases}));
const report={recordedAt:new Date().toISOString(),publicLaunchAllowed:false,method:'OSV exact-version npm query + local vendored SHA256',package:metadata.package,version:metadata.version,vendoredSha256:actual,nodeVersion:process.version,status:findings.length?'KNOWN_ADVISORIES_FOUND':'NO_KNOWN_ADVISORIES_REPORTED',findings,limitations:['Known package matches only; browser, Node runtime, first-party code and unknown issues are not covered.','An advisory database and byte-integrity check do not prove an Argon2 implementation is safe.']};
await writeFile(new URL('../results/js-dependency-audit.json',import.meta.url),JSON.stringify(report,null,2));
console.log(`${report.package}@${report.version}: ${report.status}; SHA256 verified`);process.exitCode=findings.length?1:0;
