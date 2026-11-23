// Protocol Ed25519 adapter. A transport must explicitly support exact raw bytes.
// P-256 WebAuthn assertions and arbitrary hardware products are not accepted.
export function createExternalSigner({publicKey,signBytes,sdk=globalThis.TimeSDK}){
 if(!sdk||typeof signBytes!=='function')throw Error('An explicit Ed25519 byte-signing transport is required');sdk.hexToBytes(publicKey,32);
 return Object.freeze({publicKey,async signAction(args){
  if(args.publicKey!==publicKey)throw Error('External signer public key mismatch');const bytes=sdk.buildAction(args),returned=await signBytes(new Uint8Array(bytes),{networkId:args.networkId,kind:args.kind,accountId:args.from});
  const signature=typeof returned==='string'?sdk.hexToBytes(returned,64):returned;
  if(!(signature instanceof Uint8Array)||signature.length!==64)throw Error('External signer must return one Ed25519 signature');
  const key=await crypto.subtle.importKey('raw',sdk.hexToBytes(publicKey,32),'Ed25519',false,['verify']);
  if(!await crypto.subtle.verify('Ed25519',key,signature,bytes))throw Error('External signer signed different bytes or used another key');return sdk.concat(bytes,signature);
 }});
}
