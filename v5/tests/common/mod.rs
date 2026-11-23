//! Shared test fixtures: one genesis, usable by both engine generations.
#![allow(dead_code)]
use bitcoin_bridge::{
    BitcoinNetwork, BridgeConfig,
    bitcoin::{
        PublicKey,
        secp256k1::{Secp256k1, SecretKey},
    },
};
use ed25519_dalek::{Signer, SigningKey};
use timecurrency_node::ledger::{self, Account, Action, ActionPayload, GenesisAccount};

pub const GENESIS_ACCOUNTS: u64 = 12;

pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
pub fn pk(seed: u8) -> String {
    hex::encode(key(seed).verifying_key().as_bytes())
}
/// The protocol-4 genesis used by the protocol-4 engine's own tests.
pub fn genesis_v4() -> timecurrency_v4::genesis::Genesis {
    genesis_v4_with(GENESIS_ACCOUNTS)
}
/// The same genesis with another number of accounts (at most 64).
pub fn genesis_v4_with(accounts: u64) -> timecurrency_v4::genesis::Genesis {
    use timecurrency_v4::genesis::{AuctionConfig, BootstrapValidator, Genesis};
    let secp = Secp256k1::new();
    Genesis {
        history_version: 1,
        bitcoin_receipt_version: 1,
        reward_version: 1,
        ledger: ledger::Genesis {
            chain_id: "time-devnet-v4-engine-test".into(),
            genesis_time_micros: 1_800_000_000_000_000,
            accounts: (0..accounts)
                .map(|id| GenesisAccount {
                    id,
                    name: format!("person_{id}"),
                    public_key: pk(id as u8 + 1),
                })
                .collect(),
            economics: Default::default(),
        },
        profile: pos::Profile::Laboratory,
        validators: (0..4)
            .map(|owner| BootstrapValidator {
                owner,
                consensus_key: pk(owner as u8 + 101),
                commission_bps: 1000,
            })
            .collect(),
        bitcoin: BridgeConfig::for_network(BitcoinNetwork::Regtest),
        treasury: treasury::Policy {
            revision: 1,
            governance_keys: (150..157).map(pk).collect(),
            treasury_keys: (150..157)
                .map(|seed| {
                    PublicKey::new(
                        bitcoin_bridge::bitcoin::secp256k1::PublicKey::from_secret_key(
                            &secp,
                            &SecretKey::from_slice(&[seed; 32]).unwrap(),
                        ),
                    )
                    .to_string()
                })
                .collect(),
        },
        auction: AuctionConfig {
            epoch_seconds: 10,
            bid_lead_epochs: 1,
            max_future_epochs: 48,
            min_sats: 100,
            max_sats: 1_000_000,
        },
        registration: registration::Config::default(),
        recovery_min_delay_micros: 30 * pos::SECOND,
        recovery_approval_window_micros: 7 * pos::DAY,
        trusting_period_seconds: 7 * 86400,
    }
}
/// The same genesis for the version-5 engine. The two types share one
/// canonical encoding, so the conversion goes through it.
pub fn genesis_v5() -> timecurrency_v5::genesis::Genesis {
    serde_json::from_slice(&serde_json::to_vec(&genesis_v4()).unwrap()).unwrap()
}
pub fn network_id() -> String {
    genesis_v4().network_id().unwrap()
}
pub fn sha(value: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(value.to_be_bytes()).into()
}
/// A legacy (kinds 1..16) action signed by `signer`.
pub fn legacy(
    from: u64,
    nonce: u64,
    auth_epoch: u64,
    signer: u8,
    payload: ActionPayload,
) -> Vec<u8> {
    ledger::sign_action(
        &Action {
            network_id: network_id(),
            from,
            nonce,
            auth_epoch,
            public_key: pk(signer),
            payload,
            signature: vec![],
        },
        &key(signer),
    )
    .unwrap()
}
pub fn transfer(row: &Account, signer: u8, to: u64, amount: u64) -> Vec<u8> {
    legacy(
        row.id,
        row.nonce + 1,
        row.auth_epoch,
        signer,
        ActionPayload::Transfer(ledger::Transfer { to, amount }),
    )
}
/// An extension (kinds 17 and up) action signed by `signer`.
pub fn extension(row: &Account, signer: u8, kind: u8, payload: serde_json::Value) -> Vec<u8> {
    timecurrency_v5::wire::sign(
        &network_id(),
        row.id,
        row.nonce + 1,
        row.auth_epoch,
        kind,
        &payload,
        &key(signer),
    )
    .unwrap()
}
/// Raw action bytes with full control over every field, for malformed cases.
pub fn raw_action(
    network: &str,
    kind: u8,
    from: u64,
    nonce: u64,
    auth_epoch: u64,
    signer: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut raw = timecurrency_v5::wire::DOMAIN.to_vec();
    raw.extend(hex::decode(network).unwrap());
    raw.push(kind);
    for value in [from, nonce, auth_epoch] {
        raw.extend(value.to_be_bytes());
    }
    raw.extend(key(signer).verifying_key().as_bytes());
    raw.extend((payload.len() as u32).to_be_bytes());
    raw.extend(payload);
    let signature = key(signer).sign(&raw).to_bytes();
    raw.extend(signature);
    raw
}
