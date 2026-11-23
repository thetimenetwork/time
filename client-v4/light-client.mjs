// Only the verifier can advance trust. RPC rosters, timestamps and 'verified'
// fields are untrusted input; an expired checkpoint requires an external pin.
function canonicalHeight(value){
  if(typeof value!=='string'||!/^[1-9][0-9]*$/.test(value)||BigInt(value)>18446744073709551615n)throw Error('INVALID_LIGHT_HEIGHT');
  return BigInt(value);
}
function clone(value){return JSON.parse(JSON.stringify(value));}
export function createLightClient({trust,fetchBlock,verifier,storage,now=Date.now,maxSteps=64}){
  if(!trust||trust.app_version!=='4'||!trust.chain_id||!/^[0-9a-f]{64}$/.test(trust.network_id)||typeof fetchBlock!=='function'
    ||typeof verifier?.verifyLightUpdate!=='function'||typeof verifier?.verifyTrust!=='function')throw Error('An independent V4 manifest and locally installed dynamic verifier are required');
  const pin=clone(trust),key='timecurrency-v4-checkpoint:'+pin.network_id;
  let checkpoint=pin.checkpoint?clone(pin.checkpoint):null,initialized=false,queue=Promise.resolve();
  const effective=()=>({...pin,...(checkpoint?{checkpoint}:{}),...(checkpoint?{}:{checkpoint:undefined})});
  function serial(operation){const result=queue.then(operation);queue=result.catch(()=>{});return result;}
  async function persist(next){
    if(!next||!next.block_hash||!next.block)throw Error('Verifier returned an incomplete checkpoint');
    if(checkpoint){
      const before=canonicalHeight(checkpoint.height),after=canonicalHeight(next.height);
      if(after<before||after===before&&next.block_hash!==checkpoint.block_hash)throw Error('CHECKPOINT_ROLLBACK_OR_CONFLICT');
    }
    // Keep the highest verified checkpoint in memory even if durable storage
    // fails; that failure still prevents this operation from authorizing use.
    checkpoint=clone(next);
    if(storage)await storage.setItem(key,JSON.stringify({networkId:pin.network_id,chainId:pin.chain_id,appVersion:'4',checkpoint}));
  }
  // `again`: read the store once more. Another tab or process may have saved a newer
  // checkpoint since this client last looked.
  async function loadStored(again=false){
    if(!initialized||again){
      if(storage){
        let text;try{text=await storage.getItem(key);}catch{throw Error('CHECKPOINT_STORAGE_UNAVAILABLE');}
        if(text!==null&&text!==undefined){
          let saved;try{saved=JSON.parse(text);}catch{throw Error('CHECKPOINT_STORAGE_INVALID: authenticate a replacement checkpoint independently');}
          if(saved.networkId!==pin.network_id||saved.chainId!==pin.chain_id||saved.appVersion!=='4'||!saved.checkpoint)throw Error('CHECKPOINT_STORAGE_INVALID');
          const candidate=saved.checkpoint;canonicalHeight(candidate.height);
          if(!checkpoint||canonicalHeight(candidate.height)>canonicalHeight(checkpoint.height))checkpoint=clone(candidate);
          else if(candidate.height===checkpoint.height&&candidate.block_hash!==checkpoint.block_hash)throw Error('CHECKPOINT_STORAGE_CONFLICT');
        }
      }
      initialized=true;
    }
  }
  async function init(){
    await loadStored();
    // This check occurs BEFORE fetching a candidate. A fresh-looking RPC block
    // cannot turn an expired genesis/anchor into usable trust.
    return verifier.verifyTrust(effective(),now());
  }
  async function accept(candidate){
    const checked=await verifier.verifyLightUpdate(candidate,effective(),now());
    if(checked?.verified===true&&checked.status==='VERIFIED'){await persist(checked.checkpoint);return checked;}
    if(checked?.verified===false&&checked.status==='NEEDS_BISECTION')return checked;
    throw Error('Independent light-client verification failed');
  }
  async function advance(candidate){
    await init();
    const target=canonicalHeight(candidate?.signed_header?.header?.height);
    if(!checkpoint){
      const first=target===1n?candidate:await fetchBlock('1');
      if(canonicalHeight(first?.signed_header?.header?.height)!==1n)throw Error('RPC returned another bootstrap height');
      const bootstrap=await accept(first);if(!bootstrap.verified)throw Error('Pinned genesis bootstrap did not verify');
    }
    const pending=[candidate];let steps=0;
    while(pending.length){
      if(++steps>maxSteps)throw Error('LIGHT_UPDATE_BUDGET: continue synchronization from the persisted verified checkpoint');
      const block=pending.pop(),height=canonicalHeight(block?.signed_header?.header?.height),before=canonicalHeight(checkpoint.height);
      const result=await accept(block);
      if(result.verified)continue;
      const middle=canonicalHeight(result.suggestedHeight);
      if(height<=before+1n||middle<=before||middle>=height||String(result.trustedHeight)!==checkpoint.height||BigInt(result.targetHeight)!==height)throw Error('Invalid verifier bisection coordinates');
      pending.push(block);const intermediate=await fetchBlock(middle.toString());
      if(canonicalHeight(intermediate?.signed_header?.header?.height)!==middle)throw Error('RPC returned another bisection height');
      pending.push(intermediate);
    }
    if(canonicalHeight(checkpoint.height)!==target)throw Error('Light-client target was not authenticated');
    return clone(checkpoint);
  }
  return Object.freeze({
    ready:()=>serial(init),
    updateTo:height=>serial(async()=>{await init();const block=await fetchBlock(height);if(height!==undefined&&canonicalHeight(block?.signed_header?.header?.height)!==canonicalHeight(String(height)))throw Error('RPC returned another requested height');return advance(block);}),
    updateToBlock:block=>serial(()=>advance(block)),
    getCheckpoint:()=>checkpoint?clone(checkpoint):null,
    getTrust:()=>clone(effective()),
    importTrustedCheckpoint:(next,independentlyExpectedHash)=>serial(async()=>{
      if(typeof independentlyExpectedHash!=='string'||!/^[0-9a-f]{64}$/i.test(independentlyExpectedHash)||next?.block_hash!==independentlyExpectedHash.toLowerCase())throw Error('INDEPENDENT_CHECKPOINT_HASH_REQUIRED');
      // Deliberately does not call RPC or automatically pick a reported anchor.
      await loadStored(true);
      const candidate=clone(next);
      if(checkpoint){
        const before=canonicalHeight(checkpoint.height),after=canonicalHeight(candidate.height);
        if(after<before||after===before&&candidate.block_hash!==checkpoint.block_hash)throw Error('CHECKPOINT_ROLLBACK_OR_CONFLICT');
      }
      // A trust anchor that is still valid advances only by verifying signed blocks.
      // A pasted checkpoint may replace it once it has expired, never before: otherwise
      // whoever talks a user into pasting a block could move the wallet to another chain.
      let valid=false;
      try{await verifier.verifyTrust(effective(),now());valid=true;}catch(error){if(!/CHECKPOINT_REFRESH_REQUIRED/.test(String(error?.message||error)))throw error;}
      if(valid)throw Error('CURRENT_TRUST_STILL_VALID: this wallet updates itself from verified blocks; an imported checkpoint is accepted only after the current one has expired');
      await verifier.verifyTrust({...pin,checkpoint:candidate},now());
      await persist(candidate);initialized=true;return clone(checkpoint);
    }),
  });
}
