use bitcoin_bridge::{
    BitcoinNetwork, BridgeConfig,
    bitcoin::{
        PublicKey,
        secp256k1::{Secp256k1, SecretKey},
    },
};
use ed25519_dalek::SigningKey;
use timecurrency_node::ledger::{self, GenesisAccount};
use timecurrency_v4::genesis::{AuctionConfig, BootstrapValidator, Genesis};
pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
pub fn pk(seed: u8) -> String {
    hex::encode(key(seed).verifying_key().as_bytes())
}
pub fn genesis() -> Genesis {
    let secp = Secp256k1::new();
    Genesis {
        history_version: 1,
        bitcoin_receipt_version: 1,
        reward_version: 1,
        ledger: ledger::Genesis {
            chain_id: "time-devnet-v4-engine-test".into(),
            genesis_time_micros: 1_800_000_000_000_000,
            accounts: (0..12)
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
