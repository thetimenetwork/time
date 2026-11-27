// Header and both validator sets are untrusted until the local WASM client verifies them.
export async function fetchLightBlock({rpc,height}){
 if(height!==undefined&&(typeof height!=='string'||!/^[1-9][0-9]*$/.test(height)))throw Error('Invalid light-block height');
 const result=await rpc('/commit',height?{height}:{}),signed=result?.signed_header;
 const h=signed?.header?.height;if(typeof h!=='string'||!/^[1-9][0-9]*$/.test(h)||height&&h!==height)throw Error('Certified header height unavailable');
 async function validators(at){
  const result=await rpc('/validators',{height:at,page:'1',per_page:'100'});
  if(String(result.block_height)!==at||!Array.isArray(result.validators)||result.validators.length===0||result.validators.length>100||BigInt(result.total)!==BigInt(result.validators.length))throw Error('Complete bounded validator set unavailable');
  return result.validators;
 }
 const [current,next]=await Promise.all([validators(h),validators((BigInt(h)+1n).toString())]);
 return {signed_header:signed,validators:current,next_validators:next};
}
// `at`, when given, is the height of the state to read: the state after that block, which the header of the next
// block commits to. Without it the newest state is read. A node keeps the states of its last blocks only (32 unless it
// is run otherwise); asked for an older one it refuses ("proof version pruned"), and the refusal is passed on in the
// error's message. A reader that follows the chain block by block asks this way (market-index.mjs).
export async function fetchCertifiedView({rpc,selection,attempts=3,at}){
 if(at!==undefined&&(typeof at!=='string'||!/^[1-9][0-9]{0,15}$/.test(at)))throw Error('Invalid state height');
 let last;
 for(let attempt=0;attempt<(at===undefined?attempts:1);attempt++)try{
  let light;
  if(at!==undefined)light=await fetchLightBlock({rpc,height:(BigInt(at)+1n).toString()});
  else try{light=await fetchLightBlock({rpc});}catch(first){
   const commit=await rpc('/commit');const h=BigInt(commit.signed_header.header.height);if(h<3n)throw first;
   light=await fetchLightBlock({rpc,height:(h-1n).toString()});
  }
  const h=BigInt(light.signed_header.header.height);if(h<2n)throw Error('Two finalized headers are required');const version=(h-1n).toString();
  const result=await rpc('/abci_query',{path:JSON.stringify('/v4/state'),data:'0x'+Buffer.from(JSON.stringify(selection)).toString('hex'),height:version,prove:'false'});
  if(Number(result?.response?.code||0))throw Error('Pinned state unavailable: '+String(result?.response?.log||'query failed'));
  const encoded=result?.response?.value;if(typeof encoded!=='string'||encoded.length>5*1024*1024)throw Error('Compact state response exceeds limit');
  const snapshot=JSON.parse(Buffer.from(encoded,'base64').toString('utf8'));
  if(!Array.isArray(snapshot.entries)||snapshot.entries.length>256||String(snapshot.height)!==version||String(result.response.height)!==version)throw Error('Pinned state height mismatch');
  if(typeof snapshot.root!=='string'||!/^[0-9a-f]{64}$/.test(snapshot.root)||snapshot.root!==light.signed_header.header.app_hash.toLowerCase())throw Error('Pinned application root mismatch');
  return {height:version,entries:snapshot.entries,history_proofs:snapshot.history_proofs||{},light_block:light};
 }catch(error){last=error;}
 throw Error('Could not obtain compatible certified V4 state: '+String(last?.message));
}
