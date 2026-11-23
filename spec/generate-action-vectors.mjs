// Public deterministic TEST keys only. Never use these seeds for live funds.
import {createHash,createPrivateKey,createPublicKey,sign} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
const hex = bytes => Buffer.from(bytes).toString('hex');
const bytes = text => Buffer.from(text,'hex');
const be = (number,size=8) => {const out=Buffer.alloc(size);size===8?out.writeBigUInt64BE(BigInt(number)):out.writeUInt32BE(Number(number));return out;};
const domain=Buffer.from('TCDEVNET-ACTION-V1\0');
function key(seed) {return createPrivateKey({key:Buffer.concat([bytes('302e020100300506032b657004220420'),Buffer.alloc(32,seed)]),format:'der',type:'pkcs8'});}
const publicKey=seed=>createPublicKey(key(seed)).export({format:'der',type:'spki'}).subarray(-32);
const network='11'.repeat(32), signer=hex(publicKey(3)), salt='ab'.repeat(32);
const commitment=hex(createHash('sha256').update(Buffer.concat([Buffer.from('TCDEVNET-NAME-V1\0'),bytes(network),bytes(signer),Buffer.from('alice\0'),bytes(salt)])).digest());
const deviceMessage=Buffer.concat([Buffer.from('TCDEVNET-DEVICE-V1\0'),bytes(network),be(42),be(2),publicKey(5),Buffer.from([1,1])]);
const proof=hex(sign(null,deviceMessage,key(5)));
const recoveryID='ef'.repeat(32), recoveryExpiry='660000000';
const recoveryMessage=Buffer.concat([Buffer.from('TCDEVNET-RECOVERY-V1\0'),bytes(network),be(42),be(2),be(1),bytes(recoveryID),publicKey(5),be(recoveryExpiry)]);
const recoveryProof=hex(sign(null,recoveryMessage,key(5)));
function vector(kind,name,payload,from='42',nonce='4294967296',authEpoch='2') {
 const payloadText=JSON.stringify(payload);
 const message=Buffer.concat([domain,bytes(network),Buffer.from([kind]),be(from),be(nonce),be(authEpoch),bytes(signer),be(Buffer.byteLength(payloadText),4),Buffer.from(payloadText)]);
 const signature=sign(null,message,key(3));
 return {kind,name,network_id:network,from,nonce,auth_epoch:authEpoch,public_key:signer,payload,payload_utf8:payloadText,signing_bytes_hex:hex(message),signature_hex:hex(signature),raw_hex:hex(Buffer.concat([message,signature]))};
}
const data={
 status:'DEVNET_ONLY_NOT_A_PRODUCTION_SECURITY_PROOF',
 version:1,
 domains:{action:'TCDEVNET-ACTION-V1\u0000',name:'TCDEVNET-NAME-V1\u0000',device:'TCDEVNET-DEVICE-V1\u0000'},
 header:['domain ASCII with NUL','network_id 32 raw bytes','kind u8','from u64 big endian','nonce u64 big endian','auth_epoch u64 big endian','signer Ed25519 key 32 raw bytes','payload_length u32 big endian','canonical compact JSON UTF8','Ed25519 signature 64 bytes over all preceding bytes'],
 integer_encoding:'Every JSON u64/i64 is a canonical decimal string. No leading zero, plus sign, exponent, whitespace or negative zero. Header integers are raw big endian unsigned 64-bit.',
 canonical_payload:'Exactly the field order shown below, compact JSON, no unknown or duplicate fields, no trailing bytes. Signature verification is strict Ed25519 with canonical non-weak public keys.',
 action_kinds:[
  {kind:1,name:'commit',fields:['commitment','expires_elapsed_micros'],fee_micros:'0',anonymous:true},
  {kind:2,name:'reveal',fields:['name','salt'],fee_micros:'0',anonymous:true},
  {kind:3,name:'transfer',fields:['to','amount'],fee_micros:'1000',permission:'can_spend'},
  {kind:4,name:'synthetic_bid',fields:['epoch','weight'],fee_micros:'0',permission:'can_spend'},
  {kind:5,name:'delegate',fields:['operator','amount','min_shares'],fee_micros:'1000',permission:'can_spend'},
  {kind:6,name:'undelegate',fields:['operator','shares','min_amount'],fee_micros:'1000',permission:'can_spend'},
  {kind:7,name:'withdraw',fields:['entry'],fee_micros:'1000',permission:'can_spend'},
  {kind:8,name:'add_device',fields:['public_key','can_manage','can_spend','proof'],fee_micros:'1000',permission:'can_manage'},
  {kind:9,name:'revoke_device',fields:['public_key'],fee_micros:'1000',permission:'can_manage'},
  {kind:10,name:'merchant_payment',fields:['to','amount','reference'],fee_micros:'1000',permission:'can_spend',reference:'Exact random 32-byte merchant orderID, canonical lowercase hex. Plain kind3 transfers cannot fulfill merchant orders.'}
 ],
 authorization:{anonymous_from:'18446744073709551615',anonymous_nonce:'0',anonymous_auth_epoch:'0',account_nonce:'state.nonce + 1',account_auth_epoch:'state.auth_epoch',management_epoch:'Every successful add/revoke increments auth_epoch; nonce also increments. Legacy V0 transfers are disabled after first management change and unavailable for registered accounts.',login:'Any active device may prove sign-in; sign-in grants no spending permission. Devices with both permission flags false are login-only.',device_proof:'new key signs device-domain || network32 || accountIDBE8 || currentAuthEpochBE8 || newKey32 || can_manage:u8 || can_spend:u8',device_limit:8,last_authority:'At least one can_manage and one can_spend key must remain.'},
 registration:{commitment:'SHA256(name-domain || network32 || signer32 || ASCII username || NUL || salt32)',name:'2..15 lowercase ASCII letters, digits, underscore; exact unique permanent names',signed_deadline:'now < expires_elapsed_micros <= now + 120000000; old signatures cannot reopen expired commitments',reveal:'Requires commitment at a strictly earlier committed height; valid until exact signed expiry. Same-block reveal is rejected.',initial_key:'One registered initial identity per key; no recycling',limits:{accounts:100000,pending_commits:10000},production_blocker:'Free bounded registration is Sybil vulnerable; durable public anti-spam/name policy not implemented.'},
 economics:{currency_unit:'1 second = 1000000 micros',supply_invariant:'bank + sum(accounts.balance) + sum(pools.assets) + sum(accounts.unbonding.amount) == time_micros - genesis.genesis_time_micros',modes:['bank_only (default)','devnet_auction (explicit laboratory configuration)'],synthetic_bid:'No BTC is transferred or verified. Test-weight 1..1000000, one bid/account/epoch; payout is proportionate existing bank only, floor dust remains bank.',reward:'Cumulative validator budget floor(elapsed/5); eligible preceding-commit operators receive budget*power/ALL_configured_power, floored. Missing share stays bank. Empty pools pay operator liquid; otherwise commission to operator and remainder compounds assets.',auction_boundary:'Accrue to old epoch close, settle old bids, then accrue subsequent time. No old bid can claim later unattended epochs.',pool:'Initial shares=deposited micros; later floor(amount*total_shares/assets), u128 intermediates. Caller min_shares and min_amount required >0. Deposit rounding loss is capped at 1% plus 1 micro.',unbond:'Escrow delay uses accepted elapsed time; lab 60s must be explicit, default14days. This is fixed genesis consensus, not complete permissionless PoS.',production_blockers:['Bitcoin payment/custody and reorg verification absent','Fixed genesis validator membership; no economic slashing/churn','No guardian recovery implemented','No independent external security review or million-user scaling evidence']},
 public_test_key:{seed_hex:'03'.repeat(32),public_key_hex:signer,warning:'PUBLIC TEST KEY. DO NOT FUND.'},
 commitment_vector:{network_id:network,public_key:signer,name:'alice',salt,commitment},
 device_proof_vector:{new_public_key:hex(publicKey(5)),new_test_seed_hex:'05'.repeat(32),account_id:'42',auth_epoch:'2',can_manage:true,can_spend:true,signing_bytes_hex:hex(deviceMessage),proof_hex:proof},
 vectors:[vector(1,'commit',{commitment,expires_elapsed_micros:'90000000'},'18446744073709551615','0','0'),vector(2,'reveal',{name:'alice',salt},'18446744073709551615','0','0'),
  vector(3,'transfer',{to:'9007199254740993',amount:'1234567'}),vector(4,'bid',{epoch:'123',weight:'100'}),vector(5,'delegate',{operator:'0',amount:'2000000',min_shares:'2000000'}),
  vector(6,'undelegate',{operator:'0',shares:'1000000',min_amount:'1100000'}),vector(7,'withdraw',{entry:'9007199254740993'}),
  vector(8,'add_device',{public_key:hex(publicKey(5)),can_manage:true,can_spend:true,proof}),vector(9,'revoke_device',{public_key:hex(publicKey(5))}),
  vector(10,'merchant_payment',{to:'9007199254740993',amount:'1234567',reference:'cd'.repeat(32)})]
};
data.domains.recovery='TCDEVNET-RECOVERY-V1\u0000';
data.action_kinds.push(
 {kind:11,name:'set_recovery',fields:['guardians','threshold','delay_seconds'],fee_micros:'1000',permission:'can_manage'},
 {kind:12,name:'consent_recovery',fields:['target','policy_version','accept'],fee_micros:'1000 when accept=true; 0 when opting out',permission:'can_manage'},
 {kind:13,name:'approve_recovery',fields:['target','policy_version','recovery_id','new_public_key','expires_elapsed_micros','proof'],fee_micros:'1000',permission:'can_manage'},
 {kind:14,name:'cancel_recovery',fields:[],fee_micros:'0',permission:'can_manage'},
 {kind:15,name:'finalize_recovery',fields:['recovery_id'],fee_micros:'0',permission:'new key specified by threshold-approved case signs target account header'});
data.recovery={
 policy:'2..5 sorted distinct other account IDs, strict majority threshold >=2, explicit delay30..2592000 seconds. 30seconds is laboratory policy, not a production recommendation. Disable with guardians=[],threshold=0,delay_seconds=0.',
 consent:'Each nominated guardian explicitly consents to target+policy_version using its active manager key. Setting policy does not coerce participation.',
 proof:'new key signs recovery-domain || network32 || targetIDBE8 || targetAuthEpochBE8 || policyVersionBE8 || recoveryID32 || newPublicKey32 || expiresElapsedBE8',
 case_expiry:'Signed now<expiry<=now+delay+600seconds. Once threshold reached, full delay must still fit before expiry.',
 voting:'At most one vote per guardian per target. Moving a vote permits correcting a claim. Up to5 cases prevent minority preemption; strict majority ensures at most one freezing case.',
 freeze:'Only threshold-approved case freezes spending and management. Existing owner manager may emergency-cancel with zero fee. Incoming funds remain allowed.',
 delay:'Starts only when threshold actually reached. Optout below threshold clears ready time; regaining threshold starts the full delay anew.',
 epochs:'Setting policy, ownercancel, finalization or device management invalidate old target-epoch cases. Consent optout removes guardian votes. Later guardian device changes do not undo a historical approval; guardian must opt out explicitly.',
 finalization:'New key signs TARGET account header with next nonce and current auth_epoch. After threshold delay, rotates every device to new key and increments auth_epoch. Fee0 permits recovery with no liquid balance.',
 limits:'Case state bounded by guardians and 4MiB consensus capacity; expired or stale cases only deleted by background transitions.',
 compatibility:'Empty fields omitted canonically: recovery_version=0, recovery_policy=None, recovery_cases=[]. Old canonical snapshots roundtrip unchanged.',
 trust_limitations:['Consenting guardian majority can take control by design','Compromised owner can cancel attempts repeatedly','No production recovery-policy assessment or notification network implemented']
};
data.economics.production_blockers=data.economics.production_blockers.map(text=>text==='No guardian recovery implemented'?'Guardian recovery implemented only as explicitly trusted laboratory policy':text);
data.recovery_proof_vector={network_id:network,target:'42',auth_epoch:'2',policy_version:'1',recovery_id:recoveryID,new_public_key:hex(publicKey(5)),expires_elapsed_micros:recoveryExpiry,signing_bytes_hex:hex(recoveryMessage),proof_hex:recoveryProof};
data.vectors.push(vector(11,'set_recovery',{guardians:['0','1','3'],threshold:'2',delay_seconds:'30'}),
 vector(12,'consent_recovery',{target:'42',policy_version:'1',accept:true}),
 vector(13,'approve_recovery',{target:'42',policy_version:'1',recovery_id:recoveryID,new_public_key:hex(publicKey(5)),expires_elapsed_micros:recoveryExpiry,proof:recoveryProof}),
 vector(14,'cancel_recovery',{}),vector(15,'finalize_recovery',{recovery_id:recoveryID}));
data.protocol_version=1;
data.consensus_limits={mode:'FRESH VERSION1 DEVELOPMENT NETWORK; no implicit legacy history migration',block_max_bytes:'1048576',raw_transaction_aggregate_max_bytes:'1048576',evidence_max_bytes:'65536',evidence_max_age_blocks:'100000',evidence_max_age_seconds:'172800',app_version:'1',abci_request_frame_max_bytes:'8388608',policy:'InitChain and every FinalizeBlock return the same complete Block/Evidence/Version updates; Validator and ABCI categories remain untouched. Full response bytes repeat identically after commit/restart. Legacy durable protocol0 is refused without modification.'};
data.action_kinds.push({kind:16,name:'cancel_pending',fields:[],fee_micros:'0',permission:'can_manage'});
data.vectors.push(vector(16,'cancel_pending',{}));
data.pending_cancellation='Kind16 is explicit manager-authorized nonce replacement: current nextnonce/current epoch, zero lab fee, increments nonce and auth_epoch, clears recovery cases, preserves all device keys. Threshold-frozen owners must use kind14 instead. The original pending action may win the nonce race; only a verified cancellation receipt proves invalidation, never refund or undo an already finalized payment.';
data.economics.pool='Initial shares=deposit micros; later M=floor(D*S/A) with u128 intermediates. Caller min_shares>0; NAV-priced wallet uses min_shares=1 and reviews the amount. Exact rounding donation cap0.1%: r=D*S-A*M; reject r*1000>D*(S+M), all checked u128. Minimum redemption min_amount remains required >0.';
writeFileSync(fileURLToPath(new URL('action-v1.json',import.meta.url)),JSON.stringify(data,null,2)+'\n');
console.log('Wrote 16 deterministic Node-crypto vectors; test keys are public fixtures.');
