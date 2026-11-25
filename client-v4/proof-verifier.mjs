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
// What a caller is told of a refusal (web audit of November 2026, W-2). Some refusals of the
// compiled verifier quote what it was given: a field name it does not know, a value of the wrong
// kind, the debug form of a header. Whoever sent the answer (a gateway, or the node behind it)
// chooses that text, and a page that shows an error's message would show it as its own words. So
// a refusal reaches the caller as an Error whose message is
// - the verifier's text itself when it is one of the verifier's own sentences (OWN_SENTENCES, with
//   or without the code INVALID_LIGHT_BLOCK in front), or one of its sentences whose variable part
//   is another of them, a hexadecimal key the caller asked for, or the version numbers of an
//   authenticated header (ownSentence). Callers compare several of these whole or by their
//   beginning: the explorer's clock check, the light client's refresh, the SDK's retries;
// - else, for a sentence of the verifier that ends with the words of a library (`<own words>: <the
//   library's>`), the verifier's own words alone (OWN_PREFIXES);
// - else the code the text begins with and a fixed sentence of this file for that code
//   (CODE_WORDS), or VERIFIER_REFUSED when it begins with no code this file knows.
// The verifier's own text is kept in `error.detail`, for logs and tests, and never in the message.

/// The verifier's sentences that hold nothing it was given: every string literal of verifier-v4/src and history/src
/// that has a space (tests aside), and the one code that is a refusal by itself. proof-verifier-untrusted.test.mjs
/// reads those sources and holds this list to them.
const OWN_SENTENCES=new Set([
  'INVALID_CLOCK',
  'BOOTSTRAP_HEADER_REQUIRED: verify height one against the pinned genesis first',
  'CHECKPOINT_MISMATCH: proof must use the exact independently verified checkpoint',
  'CHECKPOINT_REFRESH_REQUIRED: genesis-only bootstrap expired; a fresh RPC roster is not a trust anchor',
  'CHECKPOINT_REFRESH_REQUIRED: genesis-only bootstrap expired; authenticate a current checkpoint independently',
  'CHECKPOINT_REFRESH_REQUIRED: local trusted checkpoint expired; obtain an independently authenticated checkpoint',
  'CHECKPOINT_REQUIRED: advance the dynamic light client first','CONFLICTING_FINALITY: adjacent header does not extend the trusted block',
  'CONFLICTING_FINALITY: different certified header at trusted height','FAST_RECEIPT_NEEDS_CHECKPOINT: verify the block\'s light block first',
  'HEADER_ROLLBACK: header is below the highest trusted checkpoint','INVALID_TRUST: checkpoint metadata differs from its certified header',
  'INVALID_TRUST: explicit V4 chain/network/application pin required','INVALID_TRUST: genesis is from the future',
  'INVALID_TRUST: trusting period must be at most seven days and shorter than unbonding accountability',
  'JSON_LIMIT: verification input exceeds eight MiB','Merkle leaf does not match transaction','PoS owner key mismatch',
  'STALE_STATE: fresh current authority proof is required','V4 history version one is required',
  'a date is beyond the year 9999 when it is converted to UTC','accepted guardian','account authority epoch exceeds nonce','account count',
  'account device count invalid','account epoch','account escrow exceeds aggregate','account exceeds aggregate liquid','account id',
  'account id exceeds allocated registry','account key mismatch','account lacks managing or spending authority','account name binding mismatch',
  'account nonce','account value exceeds protocol size limit','adjacent validator transition lacked a valid quorum','ambiguous validator power',
  'application root is not 32 bytes','application version is lower than the trusted checkpoint\'s','archive internal node mismatch',
  'archive leaf alias','archive offset overflow','archive prefix differs from authenticated history root','archive recount mismatch',
  'archive/trusted network mismatch','authenticated aggregate supply differs from elapsed minting',
  'authenticated index or guardian refers to absent account','authenticated-aggregate-counters; independent-global-recount-not-performed','bid epoch',
  'bid key mismatch','bid owner','block height','bootstrap header predates pinned genesis','bootstrap roster differs from pinned genesis',
  'cannot split a leaf','canonical history height/key mismatch','canonical history summary network/height/time mismatch',
  'canonical receipt history inclusion missing','certified execution results are not all successful defaults','commit creation','commit expiry',
  'commit height','committed state time differs from fresh header','compact proof entry bound exceeded','configured recovery delay',
  'delegation names unknown pool','delegation operator','delegation shares','duplicate account device','duplicate validator authority',
  'empty history subtree','empty upgrade row','empty/duplicate compact proof key','epoch key mismatch','epoch row',
  'exit release clock outside authenticated chain coordinates','exit release coordinate mismatch','exit release height','exit request height',
  'extra proof siblings','fast receipt header chain/version mismatch','fast receipt header count outside supported bounds',
  'fast receipt headers are not one finalized chain','fast receipt headers do not end at the trusted checkpoint',
  'fast receipt transaction is not in the proven block','genesis time','global legacy name commitments are forbidden on sponsored V4',
  'guardian budget','guardian id','guardian threshold','header exceeds future clock bound','header predates pinned genesis',
  'historical header chain/version/time mismatch','historical receipt is not in freshly authenticated canonical history',
  'history append node count mismatch','history archive already has a writer; never share it between live engines',
  'history archive missing committed prefix; replay/recover archive before use','history archive network/format mismatch',
  'history frontier has extra peaks','history frontier/root mismatch','history height outside committed size','history inclusion proof mismatch',
  'history node count overflow','history proof bounds','history selection budget exceeded','history shape/version bound','history state height',
  'history state time','history time did not advance','incomplete security policy','incomplete security row','invalid Merkle proof bounds',
  'invalid accepted guardians','invalid account delegations','invalid account devices','invalid account name','invalid application root',
  'invalid archive leaf','invalid authenticated value JSON','invalid compact proof key','invalid delegation ownership','invalid device key',
  'invalid guardian consent set','invalid guardian identity/order','invalid guardians','invalid hash length','invalid history height',
  'invalid included data','invalid managing permission','invalid name commitment','invalid pool metadata','invalid prepared history append',
  'invalid public key','invalid recovery approval set','invalid recovery approvals','invalid recovery cases','invalid recovery identifier',
  'invalid recovery key','invalid recovery quorum or delay','invalid recovery ready quorum/time','invalid registration entry',
  'invalid registration key','invalid registry bounds','invalid requested name','invalid requested public key','invalid security policy',
  'invalid security row','invalid selected owner exits','invalid sibling hash','invalid spending permission',
  'invalid sponsored commitment coordinates','invalid transaction bytes','invalid transaction proof coordinates','invalid transaction size',
  'invalid unbonding list','invalid upgrade plan','invalid upgrade row','invalid upgrade signal','invalid validator key/address/power',
  'invalid validator record','invalid value base64','invalid/duplicate unbond entry','legacy economic collections forbidden on V4',
  'legacy economics forbidden on V4','live exit lacks retained release clock','missing history frontier','missing included data',
  'missing proof sibling','missing recovery policy version','missing registration key','missing transaction bytes','missing validator power',
  'name index','name/account binding mismatch','next account id','no plan','node position overflow','noncanonical account device order',
  'noncanonical decimal','noncanonical history hash','noncanonical/oversized value base64','nonconsecutive history append','plan scheduling time',
  'plan spec hash','plan start time','plan version','policy version','pool shares','proof height','proof includes different transaction bytes',
  'receipt headers are not the same finalized chain','receipt height','recovery approval','recovery approval window',
  'recovery case order/duplicate identifier','recovery delay','recovery delay overflow','recovery epoch','recovery expiry',
  'recovery key/target mismatch','recovery policy version','recovery quorum lacks ready time','recovery ready time','recovery target',
  'recovery threshold','recovery without active policy','registration fee','registration index','registration lifetime','registration sponsor',
  'registration/account binding mismatch','requested canonical history proof missing','requested id','required state value is absent',
  'reserved sponsor id','retained exit release clock','row owner','selected exit budget exceeded','selection budget exceeded','selection id',
  'short history proof','signal change time','signal owner','signal spec hash','signal start time','signal version',
  'sponsored commitment key mismatch','stake owner','state differs from pinned network/genesis','state height','state predates genesis','state time',
  'state/header version or height mismatch','subtree overflow','supply overflow','too many delegations','too many recovery cases',
  'too many unbonding entries','too many upgrade signals','transaction hash mismatch','transaction inclusion is not bound to the signed header',
  'transaction index','trusting period','unaligned complete subtree','unbond aggregate','unbond amount','unbond id','unbond sum overflow',
  'unbond unlock','unbonding period','unsupported compact receipt or recovery approval configuration','unsupported paid registration configuration',
  'unsupported reward version; explicit proportional reward version one is required','upgrade plan',
  'upgrade plan is not for the next protocol version','upgrade row has unknown fields','upgrade row lacks its signals','upgrade signal',
  'upgrade signal lacks its owner','upgrade signal names an owner that is not an account','upgrade signals are not one per owner in ascending order',
  'validator count outside supported bounds','value exceeds compact proof limit','voting power exceeds Comet limit','voting power overflow',
  'withdrawn upgrade signal','wrong independently pinned chain or application version',
]);
/// The verifier's sentences that end with a library's words: what is kept of them is the verifier's part.
const OWN_PREFIXES=['invalid validator','header/quorum/hash verification failed','trusted validator update failed'].map((words)=>`INVALID_LIGHT_BLOCK: ${words}`)
  .concat(['invalid Merkle proof','invalid canonical receipt inclusion','invalid canonical history inclusion','invalid canonical history root','invalid canonical history summary','invalid key/value proof']);
const UPGRADE_TEXT=/^UPGRADE_REQUIRED: the network runs protocol version ([1-9][0-9]{0,19}); this software implements versions [1-9][0-9]{0,19} to [1-9][0-9]{0,19}\. Install a release that implements version \1\.$/;
/// Whether `text` is wholly the verifier's own words.
function ownSentence(text){
  const own=(words)=>OWN_SENTENCES.has(words);
  if(own(text)||(text.startsWith('INVALID_LIGHT_BLOCK: ')&&own(text.slice(21)))||UPGRADE_TEXT.test(text)||/^missing requested proof for [0-9a-f]{2,256}$/.test(text))return true;
  // A sentence about a field: the name of the field is one of the verifier's own words too.
  const field=/^(?:INVALID_DECIMAL: (?:noncanonical (.+)|overflow in (.+)|(.+) must be a decimal string)|(.+) (?:must be 64 lowercase hexadecimal characters|has missing or unknown fields|must be a decimal string))$/.exec(text);
  return Boolean(field)&&own(field.slice(1).find((part)=>part!==undefined));
}
/// A fixed sentence for each code the verifier begins a refusal with.
const CODE_WORDS=Object.freeze({
  INVALID_JSON:'the answer is not in the form the verifier reads',
  JSON_LIMIT:'verification input exceeds eight MiB',
  INVALID_DECIMAL:'a number in the answer is not written as the verifier reads numbers',
  INVALID_LIGHT_BLOCK:'the block does not check against the validators this client trusts',
  INVALID_TRUST:'the trust data is not usable',
  INVALID_CLOCK:'the clock of this device cannot be used',
  STALE_STATE:'fresh current authority proof is required',
  CHECKPOINT_REFRESH_REQUIRED:'the trusted checkpoint expired; authenticate a current checkpoint independently',
  CHECKPOINT_REQUIRED:'advance the dynamic light client first',
  CHECKPOINT_MISMATCH:'proof must use the exact independently verified checkpoint',
  HEADER_ROLLBACK:'header is below the highest trusted checkpoint',
  CONFLICTING_FINALITY:'two different certified headers were offered for one height',
  BOOTSTRAP_HEADER_REQUIRED:'verify height one against the pinned genesis first',
  FAST_RECEIPT_NEEDS_CHECKPOINT:'verify the block\'s light block first',
  UPGRADE_REQUIRED:'the network runs a protocol version this software does not implement; install a release that implements it',
});
/// The message of a refusal that begins with no code this file knows.
const VERIFIER_REFUSED='The verifier refused this answer.';
/// The message a caller gets for the verifier's refusal `text` (see above).
function refusalWords(text){
  if(ownSentence(text))return text;
  const prefix=OWN_PREFIXES.find((words)=>text.startsWith(`${words}: `));
  if(prefix)return prefix;
  const code=/^([A-Z][A-Z0-9_]+)(?::|$)/.exec(text)?.[1];
  return code&&Object.hasOwn(CODE_WORDS,code)?`${code}: ${CODE_WORDS[code]}`:VERIFIER_REFUSED;
}

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
      if(typeof thrown!=='string')throw thrown instanceof Error?thrown:new Error(String(thrown));
      // A refusal: its message is the verifier's own words, or a code and fixed words; its text is the detail.
      const error=new Error(refusalWords(thrown));
      error.detail=thrown;
      if(thrown.startsWith('UPGRADE_REQUIRED:'))error.code='UPGRADE_REQUIRED';
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
Object.defineProperty(installed.verifyTrust,Symbol.for('time-currency.proof-verifier.internals'),{value:Object.freeze({createVerifier,refusal,base64StopsTheDecoder,dateStopsTheReader,BASE64_REFUSAL,DATE_REFUSAL,refusalWords,OWN_SENTENCES,OWN_PREFIXES,CODE_WORDS,VERIFIER_REFUSED})});
export const verifyTrust=installed.verifyTrust;
export const verifyLightUpdate=installed.verifyLightUpdate;
export const verifyViewProof=installed.verifyViewProof;
export const verifyReceipt=installed.verifyReceipt;
export const verifyFastReceipt=installed.verifyFastReceipt;
