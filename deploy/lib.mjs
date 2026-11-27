import { createHash, createPublicKey, verify } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import path from 'node:path';
export const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
export const imagePin=value=>typeof value==='string'&&/^[a-zA-Z0-9][a-zA-Z0-9./:_-]*@sha256:[a-f0-9]{64}$/.test(value);
export function canonical(value){if(value===null||typeof value==='boolean'||typeof value==='string')return JSON.stringify(value);if(typeof value==='number'&&Number.isSafeInteger(value))return JSON.stringify(value);if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';if(typeof value==='object'&&value&&Object.getPrototypeOf(value)===Object.prototype)return '{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonical(value[key])).join(',')+'}';throw new Error('Noncanonical signed value');}
export const signingBytes=payload=>Buffer.from('TIME-OPERATOR-ATTESTATION-V1\0'+canonical(payload));
export async function json(file){const info=await lstat(file);if(info.isSymbolicLink()||!info.isFile()||info.size>4*1024*1024)throw new Error('Expected bounded regular JSON file');return JSON.parse(await readFile(file,'utf8'));}
export function hex32(value,label='hash'){if(typeof value!=='string'||!/^[a-f0-9]{64}$/.test(value))throw new Error('Invalid '+label);return value;}
export function rawEd25519(key){hex32(key,'public key');return createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(key,'hex')]),format:'der',type:'spki'});}
export function signed(attestation,trust,expected,now=Date.now()){
  const {payload,signature,issuer}=attestation??{};const authority=trust?.authorities?.find(item=>item.id===issuer);
  if(!authority||!authority.roles?.includes(expected.kind))throw new Error('Attestation authority/role is not independently pinned');
  if(typeof signature!=='string'||!/^[A-Za-z0-9+/]{86}==$/.test(signature))throw new Error('Noncanonical Ed25519 signature');
  if(!verify(null,signingBytes(payload),rawEd25519(authority.public_key_hex),Buffer.from(signature,'base64')))throw new Error('Invalid signed attestation');
  for(const [key,value]of Object.entries(expected))if(payload[key]!==value)throw new Error('Attestation scope mismatch: '+key);
  const issued=Date.parse(payload.issued_utc),expires=Date.parse(payload.expires_utc);
  if(!Number.isFinite(issued)||!Number.isFinite(expires)||issued>now||expires<=now||expires<=issued)throw new Error('Attestation expired or future-dated');
  return {payload,authority};
}
// Node engines a release can build and run. Both execute the protocol-4 ledger.
// The `protocol=` part of a version line names the protocol versions the program implements, not
// the version a chain runs: `protocol=4` for a program that implements version 4 only. A release
// that also implements a version 5 will print `protocol=4..5`, before and after the network
// activates it (docs/design/upgrade-mechanism.md, 8.2); this kit then pins that line.
// A manifest WITHOUT an `engine` field is v4: its identity bytes are exactly the
// pre-v5 bytes. Only "v5" may be written; "v4" is never written, so every
// release has one canonical identity.
export const ENGINES=Object.freeze({
 v4:Object.freeze({binary:'time-node-v4',dockerfile:'deploy/Dockerfile',version:'time-node-v4 0.4.0 devnet-only publicLaunchAllowed=false'}),
 v5:Object.freeze({binary:'time-node-v5',dockerfile:'deploy/Dockerfile.v5',version:'time-node-v5 0.10.0 protocol=4 devnet-only publicLaunchAllowed=false'})
});
export function releaseEngine(manifest){if(!Object.hasOwn(manifest,'engine'))return 'v4';if(manifest.engine!=='v5')throw new Error('Unsupported release engine');return 'v5';}
// JSON.stringify omits `engine` when it is undefined, so v4 identities are unchanged.
export function releaseIdentity(manifest){const {schema_version,protocol_version,engine,platform,image_pins,source_files,generated_dockerignore_sha256,binaries,evidence,sbom_sha256}=manifest;return {schema_version,protocol_version,engine,platform,image_pins,source_files,generated_dockerignore_sha256,binaries,evidence,sbom_sha256};}
// `protocol_version` in a release manifest is the first protocol version of the networks the
// release is for, 4. It is part of the release identity and does not change when a network
// upgrades. A release that implements later versions as well will say so in a separate field.
export function validateRelease(manifest){if(manifest.schema_version!==2||manifest.protocol_version!==4||manifest.status!=='DEVELOPMENT_CANDIDATE'||manifest.public_funds_allowed!==false||manifest.mainnet_receipts_enabled!==false||manifest.monetary_enable_toggle!==false)throw new Error('Only nonmonetary development candidates are supported');releaseEngine(manifest);hex32(manifest.sbom_sha256);if(sha256(Buffer.from(JSON.stringify(releaseIdentity(manifest))))!==manifest.release_id)throw new Error('Release identity mismatch');for(const kind of ['rust','go','runtime'])if(!imagePin(manifest.image_pins[kind]))throw new Error('Image digest pin missing');return manifest;}
export function safeOutput(file){const resolved=path.resolve(file);if(resolved.split(path.sep).some(part=>['.local','.tools','context'].includes(part.toLowerCase())))throw new Error('Operator state must be outside build/runtime fixture directories');return resolved;}
export function exactU64(value){if(typeof value!=='string'||! /^(?:0|[1-9][0-9]{0,19})$/.test(value)||BigInt(value)>18446744073709551615n)throw new Error('Expected canonical u64 decimal string');return BigInt(value);}
