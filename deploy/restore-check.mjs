#!/usr/bin/env node
import{fileURLToPath}from'node:url';import path from'node:path';
import{json,signed,exactU64,hex32}from'./lib.mjs';
// Check signed signer-export state against a separately obtained CURRENT signer
// authority floor. Restoring an old disk snapshot never resets this authority.
export function checkRestore(backup,floor,trust,expected,now=Date.now()){
 for(const key of ['release_id','genesis_sha256','validator_public_key_hex'])hex32(expected[key],key);
 const old=signed(backup,trust,{kind:'signer_backup',...expected},now).payload,current=signed(floor,trust,{kind:'signer_floor',...expected},now).payload;
 if(old.fence_domain!==current.fence_domain||typeof old.fence_domain!=='string'||!old.fence_domain)throw new Error('Signer fencing domain mismatch');
 const a=[exactU64(old.height),exactU64(old.round),exactU64(old.step)],b=[exactU64(current.height),exactU64(current.round),exactU64(current.step)];let compare=0;for(let i=0;i<3;i++)if(a[i]!==b[i]){compare=a[i]>b[i]?1:-1;break;}
 if(compare<0)throw new Error('Signer state rollback rejected');if(compare===0&&(old.sign_bytes_sha256!==current.sign_bytes_sha256||old.signature_sha256!==current.signature_sha256))throw new Error('Same height/round/step with conflicting signing state');
 hex32(old.sign_bytes_sha256);hex32(old.signature_sha256);if(exactU64(old.fence_token)<exactU64(current.fence_token))throw new Error('Old signer fencing token rejected');
 if(Date.parse(current.issued_utc)<now-60000)throw new Error('Authority floor must be independently refreshed within 60 seconds');
 return{status:'RESTORE_PREFLIGHT_PASSED',automatic_restore:false,public_funds_allowed:false,required_next_action:'Acquire a NEW monotonic lease from the live signing authority, prove the former lease cannot sign, run the offline authenticated application audit, and reconcile consensus/app heights before starting. This check does not unlock a signer.'};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){const[b,f,t,e]=process.argv.slice(2);if(!e)throw new Error('Usage: restore-check.mjs BACKUP_ATTESTATION LIVE_FLOOR TRUST EXPECTED_CONTEXT');Promise.all([json(b),json(f),json(t),json(e)]).then(args=>console.log(JSON.stringify(checkRestore(...args),null,2))).catch(e=>{console.error(e.message);process.exitCode=1;});}
