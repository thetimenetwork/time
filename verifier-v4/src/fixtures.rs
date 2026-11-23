//! Test-only real Ed25519 commits, using Tendermint's canonical vote encoder.
use crate::light::{Checkpoint, LightBlock, Trust};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use tendermint::{
    AppHash, Hash, PublicKey, Signature, Time, Vote,
    block::{self, Commit, CommitSig, header::Version, signed_header::SignedHeader},
    validator,
};
pub const T0: i64 = 1_000_000;
pub fn key(id: u8) -> SigningKey {
    SigningKey::from_bytes(&[id; 32])
}
pub fn roster(entries: &[(u8, u64)]) -> validator::Set {
    validator::Set::without_proposer(
        entries
            .iter()
            .map(|(id, power)| {
                validator::Info::new(
                    PublicKey::from_raw_ed25519(&key(*id).verifying_key().to_bytes()).unwrap(),
                    (*power).try_into().unwrap(),
                )
            })
            .collect(),
    )
}
pub fn values(set: &validator::Set) -> Vec<Value> {
    set.validators()
        .iter()
        .map(|v| serde_json::to_value(v).unwrap())
        .collect()
}
pub fn trust(initial: &[(u8, u64)], checkpoint: Option<Checkpoint>) -> Trust {
    Trust {
        chain_id: "time-devnet-v4-fixture".into(),
        network_id: "ab".repeat(32),
        app_version: "4".into(),
        genesis_time_micros: ((T0 + 1) * 1_000_000).to_string(),
        trusting_period_seconds: "604800".into(),
        unbonding_period_seconds: "1209600".into(),
        initial_validators: values(&roster(initial)),
        checkpoint,
    }
}
pub fn block(
    height: u64,
    current: &[(u8, u64)],
    next: &[(u8, u64)],
    previous: Option<&LightBlock>,
    seconds: i64,
) -> LightBlock {
    block_at(4, height, current, next, previous, seconds)
}
/// A signed block whose header carries application version `app`.
pub fn block_at(
    app: u64,
    height: u64,
    current: &[(u8, u64)],
    next: &[(u8, u64)],
    previous: Option<&LightBlock>,
    seconds: i64,
) -> LightBlock {
    let validators = roster(current);
    let nextset = roster(next);
    let time = Time::from_unix_timestamp(seconds, 0).unwrap();
    let header = block::Header {
        version: Version { block: 11, app },
        chain_id: "time-devnet-v4-fixture".parse().unwrap(),
        height: height.try_into().unwrap(),
        time,
        last_block_id: previous.map(|b| b.signed_header.commit.block_id),
        last_commit_hash: None,
        data_hash: None,
        validators_hash: validators.hash(),
        next_validators_hash: nextset.hash(),
        consensus_hash: Hash::Sha256([4; 32]),
        app_hash: AppHash::try_from(vec![0u8; 32]).unwrap(),
        last_results_hash: None,
        evidence_hash: None,
        proposer_address: validators.validators()[0].address,
    };
    sign_header(header, current, next)
}
pub fn sign_header(header: block::Header, current: &[(u8, u64)], next: &[(u8, u64)]) -> LightBlock {
    let validators = roster(current);
    let nextset = roster(next);
    let time = header.time;
    let block_id = block::Id {
        hash: header.hash(),
        part_set_header: block::parts::Header::new(1, Hash::Sha256([9; 32])).unwrap(),
    };
    let signatures = validators
        .validators()
        .iter()
        .enumerate()
        .map(|(index, info)| {
            let signing = current
                .iter()
                .find_map(|(id, _)| {
                    let signing = key(*id);
                    (signing.verifying_key().to_bytes().as_slice() == info.pub_key.to_bytes())
                        .then_some(signing)
                })
                .unwrap();
            let vote = Vote {
                vote_type: tendermint::vote::Type::Precommit,
                height: header.height,
                round: 0u8.into(),
                block_id: Some(block_id),
                timestamp: Some(time),
                validator_address: info.address,
                validator_index: index.try_into().unwrap(),
                signature: None,
                extension: vec![],
                extension_signature: None,
            };
            let bytes = vote.into_signable_vec(header.chain_id.clone());
            CommitSig::BlockIdFlagCommit {
                validator_address: info.address,
                timestamp: time,
                signature: Signature::new(signing.sign(&bytes).to_bytes()).unwrap(),
            }
        })
        .collect();
    let commit = Commit {
        height: header.height,
        round: 0u8.into(),
        block_id,
        signatures,
    };
    LightBlock {
        signed_header: SignedHeader::new(header, commit).unwrap(),
        validators: values(&validators),
        next_validators: values(&nextset),
    }
}
pub fn bootstrap(initial: &[(u8, u64)]) -> (LightBlock, Trust) {
    let first = block(1, initial, initial, None, T0 + 1);
    let trust = trust(initial, None);
    (first, trust)
}
pub fn now() -> i128 {
    i128::from(T0 + 100) * 1_000_000
}
pub fn checkpoint_from(result: &Value) -> Checkpoint {
    serde_json::from_value(result["checkpoint"].clone()).unwrap()
}
pub fn public_fixture() -> Value {
    let a = [(1, 10), (2, 10), (3, 10), (4, 10)];
    let b = [(5, 10), (6, 10), (7, 10), (8, 10)];
    let (first, pin) = bootstrap(&a);
    let second = block(2, &a, &b, Some(&first), T0 + 2);
    let third = block(3, &b, &b, Some(&second), T0 + 3);
    let refreshed = block(4, &b, &b, Some(&third), T0 + 604900);
    json!({"trust":pin,"blocks":[first,second,third],"now_ms":(T0+100)*1000,"external_checkpoint":crate::light::checkpoint(refreshed),"refresh_now_ms":(T0+604901)*1000})
}
