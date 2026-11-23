// Executable verification code is installed with the wallet/SDK, never fetched
// from a caller-selected RPC gateway.
//
// Two things here keep one bad answer from costing the honest ones after it (AUDIT-2026-11.md,
// "Found by fuzzing"):
//
// 1. Texts the compiled verifier's libraries cannot take are refused before they reach it
//    (`refusal`, below). The libraries panic on them instead of refusing them, and in
//    WebAssembly a panic is a trap.
// 2. An instance that has trapped, for whatever reason, is thrown away. The next call gets a
//    new one. An instance that goes on after a trap keeps what the trap left behind (about
//    a hundred traps and it fails on every answer, honest ones too).

// ---------------------------------------------------------------------------------------------
// Texts the libraries of the compiled verifier cannot take. The two rules are those of
// verifier-v4/src/untrusted.rs, which says where they come from and holds them against the
// libraries themselves; spec/untrusted-text-vectors.json holds both files to the same answers.

const encoder=new TextEncoder();
// What Rust's `char::is_whitespace` says of a byte read as one character.
const WHITE=new Set([9,10,11,12,13,32,0x85,0xa0]);
/// Whether the base64 decoder of the verifier's libraries panics on this text.
function base64StopsTheDecoder(text){
  // Without a `=` the decoder returns, with bytes or with an error.
  if(!text.includes('='))return false;
  const bytes=encoder.encode(text),length=bytes.length;
  if(WHITE.has(bytes[length-1]))return false;
  // The `=` signs at the end (the first character is never counted as one), and the room they leave.
  let padding=0;
  while(padding<length-1&&bytes[length-1-padding]===61)padding++;
  const room=Math.floor((length-padding)*3/4);
  // Every four characters but the last one to four are written as three bytes.
  const whole=Math.floor((length-1)/4);
  if(3*whole>room)return true;
  // The last one to four, up to the first `=`: one byte fewer than their number.
  let filled=0;
  while(4*whole+filled<length&&bytes[4*whole+filled]!==61)filled++;
  return filled===0||3*whole+filled-1>room;
}
/// Whether the date reader of the verifier's libraries panics on this text: the last day of the
/// year 9999, with an offset behind UTC that carries the time into the year 10000.
function dateStopsTheReader(text){
  if(!text.startsWith('9999-12-31'))return false;
  const bytes=encoder.encode(text),length=bytes.length,digit=(at)=>bytes[at]>=48&&bytes[at]<=57;
  const two=(at)=>digit(at)&&digit(at+1)?(bytes[at]-48)*10+bytes[at+1]-48:null;
  if(length<25||bytes[13]!==58||bytes[16]!==58)return false;
  const offset=length-6;
  if(bytes[offset]!==45||bytes[offset+3]!==58)return false;
  const parts=[two(11),two(14),two(17),two(offset+1),two(offset+4)];
  if(parts.includes(null))return false;
  const [hour,minute,second,hoursBehind,minutesBehind]=parts;
  return hour*3600+minute*60+Math.min(second,59)+hoursBehind*3600+minutesBehind*60>=86400;
}
const BASE64_REFUSAL='a text is not base64: its `=` signs are not where base64 has them';
const DATE_REFUSAL='a date is beyond the year 9999 when it is converted to UTC';
/// Why a text must not reach the compiled verifier, or null if it may.
function refusal(text){return base64StopsTheDecoder(text)?BASE64_REFUSAL:dateStopsTheReader(text)?DATE_REFUSAL:null;}

// ---------------------------------------------------------------------------------------------
// The compiled verifier and its instances.

/// Loads the compiled verifier as a new instance. The generated loader keeps the one instance
/// it made for as long as it lives, so every instance after the first needs a loader of its
/// own: the same file, imported under an address that differs after its `#`. A browser and Node
/// take that for another module and run the file again; what a server is asked for is the same
/// address as before, since nothing after a `#` is sent (a server may refuse an address with a
/// `?`, as the API service does for the explorer's files).
async function loadInstalled(number){
  const js=new URL('../web-v4/shared/verifier/timecurrency_verifier_v4.js',import.meta.url),wasm=new URL('../web-v4/shared/verifier/timecurrency_verifier_v4_bg.wasm',import.meta.url);
  if(number)js.hash=`instance-${number}`;
  const module=await import(js.href);
  if(typeof process!=='undefined'&&process.versions?.node){const {readFile}=await import('node:fs/promises');await module.default({module_or_path:await readFile(wasm)});}
  else await module.default({module_or_path:wasm});
  return module;
}
/// A verifier of its own: its instances come from `load(number)`, and `refuse(text)` names the
/// texts that are kept from them. The defaults are the installed verifier and the rules above.
/// Other values are for tests; a verifier that refuses nothing leaves its instances to the
/// panics of their libraries.
function createVerifier({load=loadInstalled,refuse=refusal}={}){
  let loading,live,loaded=0;
  // The first reason to refuse among all the texts of a value. Field names are not looked at:
  // no library decodes them.
  const firstRefusal=(value)=>{
    if(typeof value==='string')return refuse(value);
    if(value===null||typeof value!=='object')return null;
    for(const inner of Array.isArray(value)?value:Object.values(value)){const reason=firstRefusal(inner);if(reason)return reason;}
    return null;
  };
  async function instance(){
    loading??=(async()=>{const module=await load(loaded++);live=module;return module;})().catch(error=>{loading=undefined;throw error;});
    return loading;
  }
  // The compiled verifier throws each refusal as a string. A refusal that begins `UPGRADE_REQUIRED:`
  // (a protocol version the verifier does not implement, read from a header it authenticated) gets
  // the code 'UPGRADE_REQUIRED' here. This is the one place where those words can only have come
  // from the verifier itself: nothing a gateway sends is an argument that reaches this string
  // unchecked, and no other code may set the code on an error it did not raise itself.
  async function call(name,values,nowMs){
    // The texts as the compiled verifier will read them: what JSON.stringify wrote, read back.
    const texts=values.map((value)=>JSON.stringify(value));
    for(const text of texts){
      const reason=text===undefined?null:firstRefusal(JSON.parse(text));
      if(reason)throw new Error(`INVALID_JSON: ${reason}`);
    }
    let module;try{module=await instance();while(module!==live)module=await instance();}catch(error){throw error instanceof Error?error:new Error(String(error));}
    let answer;
    try{answer=module[name](...texts,nowMs);}catch(thrown){
      // Anything but a string is not a refusal of the verifier: it is a trap (or an error of the
      // engine that runs it), and the instance is not used again. Calls that already wait for it
      // see that it is gone and take the next one.
      if(typeof thrown!=='string'&&module===live){live=undefined;loading=undefined;}
      const error=thrown instanceof Error?thrown:new Error(String(thrown));
      if(typeof thrown==='string'&&thrown.startsWith('UPGRADE_REQUIRED:'))error.code='UPGRADE_REQUIRED';
      throw error;
    }
    return JSON.parse(answer);
  }
  return {
    verifyTrust:(trust,nowMs=Date.now())=>call('verify_trust',[trust],nowMs),
    verifyLightUpdate:(block,trust,nowMs=Date.now())=>call('verify_light_update',[block,trust],nowMs),
    verifyViewProof:(proof,trust,request={},nowMs=Date.now())=>call('verify_view_proof',[proof,trust,request],nowMs),
    verifyReceipt:(proof,trust,nowMs=Date.now())=>call('verify_receipt',[proof,trust],nowMs),
    // A receipt that needs only the transaction's own block to be final: proof is {tx, headers},
    // and trust must hold the verified checkpoint the headers end at.
    verifyFastReceipt:(proof,trust,nowMs=Date.now())=>call('verify_fast_receipt',[proof,trust],nowMs),
    /// How many instances this verifier has loaded so far.
    instances:()=>loaded,
  };
}
// The exports of this module are the five functions below and no other: the module that stands
// in for it in an upgrade rehearsal (campaign/lib/upgrade-kit.mjs) exports the same, and a test
// holds the two to that. What this file's own tests need beside them (a verifier of their own,
// the two rules) is reached through `verifyTrust`, under a name no caller comes upon by chance.
const installed=createVerifier();
Object.defineProperty(installed.verifyTrust,Symbol.for('time-currency.proof-verifier.internals'),{value:Object.freeze({createVerifier,refusal,base64StopsTheDecoder,dateStopsTheReader,BASE64_REFUSAL,DATE_REFUSAL})});
export const verifyTrust=installed.verifyTrust;
export const verifyLightUpdate=installed.verifyLightUpdate;
export const verifyViewProof=installed.verifyViewProof;
export const verifyReceipt=installed.verifyReceipt;
export const verifyFastReceipt=installed.verifyFastReceipt;
