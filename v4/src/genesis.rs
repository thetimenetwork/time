use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use timecurrency_node::ledger;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapValidator {
    #[serde(with = "pos::decimal::u64")]
    pub owner: u64,
    pub consensus_key: String,
    pub commission_bps: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuctionConfig {
    #[serde(with = "pos::decimal::u64")]
    pub epoch_seconds: u64,
    #[serde(with = "pos::decimal::u64")]
    pub bid_lead_epochs: u64,
    #[serde(with = "pos::decimal::u64")]
    pub max_future_epochs: u64,
    #[serde(with = "pos::decimal::u64")]
    pub min_sats: u64,
    #[serde(with = "pos::decimal::u64")]
    pub max_sats: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub history_version: u8,
    pub bitcoin_receipt_version: u8,
    pub reward_version: u8,
    pub ledger: ledger::Genesis,
    pub profile: pos::Profile,
    pub validators: Vec<BootstrapValidator>,
    pub bitcoin: bitcoin_bridge::BridgeConfig,
    pub treasury: treasury::Policy,
    pub auction: AuctionConfig,
    pub registration: registration::Config,
    #[serde(with = "pos::decimal::u64")]
    pub recovery_min_delay_micros: u64,
    #[serde(with = "pos::decimal::u64")]
    pub recovery_approval_window_micros: u64,
    #[serde(with = "pos::decimal::u64")]
    pub trusting_period_seconds: u64,
}
impl Genesis {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.reward_version==1,"explicit proportional reward version one required");
        ensure!(
            self.history_version == 1,
            "explicit authenticated history version one required"
        );
        ensure!(
            self.bitcoin_receipt_version == 1,
            "explicit compact Bitcoin receipt version one required"
        );
        ensure!(
            self.recovery_approval_window_micros == 7 * pos::DAY,
            "recovery approval window must be seven accepted days"
        );
        self.registration.validate()?;
        ensure!(
            self.ledger.chain_id.starts_with("time-devnet-v4-"),
            "explicit development-v4 chain required"
        );
        let canonical = ledger::new(self.ledger.clone())?;
        ensure!(
            canonical.genesis == self.ledger,
            "noncanonical ledger genesis"
        );
        ensure!(
            self.ledger.economics.mode == ledger::EconomicMode::BankOnly
                && self.ledger.economics.operators.is_empty(),
            "v4 uses separate actual PoS, not legacy economic operators"
        );
        ensure!(
            (4..=20).contains(&self.validators.len()),
            "bootstrap roster must contain four to twenty validators"
        );
        if self.profile == pos::Profile::Production {
            ensure!(
                self.validators.len() == 20,
                "production profile requires twenty bootstrap organizations"
            );
        }
        let mut owners = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for validator in &self.validators {
            ensure!(
                owners.insert(validator.owner) && keys.insert(&validator.consensus_key),
                "duplicate bootstrap validator"
            );
            ensure!(
                self.ledger.accounts.iter().any(|a| a.id == validator.owner),
                "bootstrap owner missing"
            );
            let raw: [u8; 32] = hex::decode(&validator.consensus_key)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid consensus key"))?;
            let public = ed25519_dalek::VerifyingKey::from_bytes(&raw)?;
            ensure!(
                !public.is_weak()
                    && hex::encode(raw) == validator.consensus_key
                    && validator.commission_bps <= 2000,
                "invalid bootstrap authority"
            );
        }
        self.treasury.validate()?;
        ensure!(
            self.treasury.revision == 1,
            "initial treasury revision must be one"
        );
        ensure!(
            !self.bitcoin.mainnet_receipts_enabled,
            "valuable Bitcoin receipt acceptance is disabled in this candidate"
        );
        ensure!(
            (1..=86_400).contains(&self.auction.epoch_seconds)
                && (1..=48).contains(&self.auction.max_future_epochs)
                && self.auction.bid_lead_epochs > 0
                && self.auction.bid_lead_epochs <= self.auction.max_future_epochs,
            "invalid auction window"
        );
        ensure!(
            self.auction.min_sats > 0
                && self.auction.min_sats <= self.auction.max_sats
                && self.auction.max_sats <= 2_100_000_000_000_000,
            "invalid Bitcoin amount bounds"
        );
        ensure!(
            self.trusting_period_seconds == 7 * 86_400
                && self.trusting_period_seconds * 1_000_000 < pos::UNBOND_DELAY,
            "trust must be shorter than slashable withdrawal delay"
        );
        ensure!(
            self.recovery_min_delay_micros >= 30_000_000
                && self.recovery_min_delay_micros <= 30 * pos::DAY,
            "invalid recovery delay"
        );
        if self.profile == pos::Profile::Production {
            ensure!(
                self.auction.epoch_seconds == 3600
                    && self.recovery_min_delay_micros >= 2 * pos::DAY,
                "production timing requires hourly auction and at least two-day recovery"
            );
        }
        Ok(())
    }
    pub fn network_id(&self) -> Result<String> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"TCDEVNET-NETWORK-V4\0");
        hash.update(serde_json::to_vec(self)?);
        Ok(hex::encode(hash.finalize()))
    }
}
