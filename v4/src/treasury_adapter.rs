//! Governance transitions execute only over authenticated Time/Bitcoin state.
//! Bitcoin spending keys are never accepted by this process.
use crate::{bitcoin_adapter, engine::ExtensionHost, wire::SignedAction};
use anyhow::{Result, anyhow, ensure};
use serde::Deserialize;

pub const STATE_KEY: &[u8] = b"treasury/state";
pub const RECEIVING_KEY: &[u8] = b"treasury/receiving";
pub fn policy_key(revision: u64) -> Vec<u8> {
    [b"treasury/policy/".as_slice(), &revision.to_be_bytes()].concat()
}
pub fn network(host: &impl ExtensionHost) -> Result<[u8; 32]> {
    hex::decode(&host.meta().network_id)?
        .try_into()
        .map_err(|_| anyhow!("invalid Time network"))
}
pub fn get(host: &impl ExtensionHost) -> Result<treasury::Treasury> {
    let row = host
        .get(STATE_KEY)?
        .ok_or_else(|| anyhow!("missing treasury state"))?;
    let state: treasury::Treasury = serde_json::from_slice(&row)?;
    state.validate_persisted(network(host)?)?;
    Ok(state)
}
fn context(host: &impl ExtensionHost) -> Result<treasury::Context> {
    Ok(treasury::Context {
        time_height: u64::try_from(host.meta().height)?,
        elapsed_micros: host.meta().elapsed_micros()?,
        bitcoin_height: u64::from(bitcoin_adapter::get(host)?.meta.best_height),
    })
}
fn store(host: &mut impl ExtensionHost, state: &treasury::Treasury) -> Result<()> {
    host.put(STATE_KEY.to_vec(), Some(serde_json::to_vec(state)?))
}
fn receiving(
    host: &impl ExtensionHost,
    state: &treasury::Treasury,
) -> Result<bitcoin_bridge::ReceivingPolicy> {
    let config = &host.meta().config;
    Ok(bitcoin_bridge::ReceivingPolicy {
        network: config.bitcoin.network,
        time_network: network(host)?,
        revision: state.active().revision,
        script_pubkey: state.active().witness_script()?.to_p2wsh().into_bytes(),
        min_sats: config.auction.min_sats,
        max_sats: config.auction.max_sats,
        btc_start_height: bitcoin_adapter::get(host)?.meta.best_height,
        btc_end_height: None,
        time_start_micros: host.meta().elapsed_micros()?,
        time_end_micros: None,
    })
}
pub fn initialize(host: &mut impl ExtensionHost) -> Result<()> {
    let state = treasury::Treasury::new(
        network(host)?,
        host.meta().config.treasury.clone(),
        context(host)?,
    )?;
    let policy = receiving(host, &state)?;
    host.put(RECEIVING_KEY.to_vec(), Some(serde_json::to_vec(&policy)?))?;
    host.put(
        policy_key(policy.revision),
        Some(serde_json::to_vec(&policy)?),
    )?;
    store(host, &state)
}
pub fn begin_block(_host: &mut impl ExtensionHost) -> Result<()> {
    Ok(())
}
pub fn receiving_policy(host: &impl ExtensionHost) -> Result<bitcoin_bridge::ReceivingPolicy> {
    let state = get(host)?;
    ensure!(!state.paused(), "foundation Bitcoin earning is paused");
    let policy: bitcoin_bridge::ReceivingPolicy = serde_json::from_slice(
        &host
            .get(RECEIVING_KEY)?
            .ok_or_else(|| anyhow!("missing receiving policy"))?,
    )?;
    policy.validate()?;
    ensure!(
        policy.revision == state.active().revision
            && policy.script_pubkey == state.receiving_script()?.into_bytes(),
        "treasury receiving state mismatch"
    );
    Ok(policy)
}
pub const CONFIRMED_OLD_POLICY_GRACE: u64 = pos::DAY;
fn late_receipt_policy(
    mut policy: bitcoin_bridge::ReceivingPolicy,
    now: u64,
) -> Result<bitcoin_bridge::ReceivingPolicy> {
    policy.validate()?;
    let closed = policy
        .time_end_micros
        .ok_or_else(|| anyhow!("old policy lacks authenticated closure"))?;
    ensure!(
        policy.btc_end_height.is_some()
            && now >= closed
            && now
                <= closed
                    .checked_add(CONFIRMED_OLD_POLICY_GRACE)
                    .ok_or_else(|| anyhow!("policy grace overflow"))?,
        "old receiving policy receipt grace expired"
    );
    // Keep the Bitcoin cutoff: only outputs already included before rotation
    // can qualify. This relaxes receipt delivery time, never payment height.
    policy.time_end_micros = None;
    Ok(policy)
}
pub fn receiving_policy_for_claim(
    host: &impl ExtensionHost,
    revision: u64,
) -> Result<bitcoin_bridge::ReceivingPolicy> {
    let state = get(host)?;
    ensure!(!state.paused(), "foundation Bitcoin earning is paused");
    if revision == state.active().revision {
        return receiving_policy(host);
    }
    ensure!(
        revision > 0 && revision < state.active().revision,
        "unknown receiving policy revision"
    );
    let policy: bitcoin_bridge::ReceivingPolicy = serde_json::from_slice(
        &host
            .get(&policy_key(revision))?
            .ok_or_else(|| anyhow!("unknown archived receiving policy"))?,
    )?;
    ensure!(
        policy.revision == revision
            && policy.network == host.meta().config.bitcoin.network
            && policy.time_network == network(host)?
            && policy.min_sats == host.meta().config.auction.min_sats
            && policy.max_sats == host.meta().config.auction.max_sats,
        "archived receiving policy context mismatch"
    );
    late_receipt_policy(policy, host.meta().elapsed_micros()?)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    public_key: String,
    signature: String,
}
fn approvals(rows: Vec<Approval>) -> Result<Vec<treasury::Approval>> {
    ensure!(
        (5..=7).contains(&rows.len()),
        "five of seven approvals required"
    );
    rows.into_iter()
        .map(|a| {
            let signature = hex::decode(&a.signature)?;
            ensure!(
                signature.len() == 64 && hex::encode(&signature) == a.signature,
                "noncanonical governance signature"
            );
            Ok(treasury::Approval {
                public_key: a.public_key,
                signature,
            })
        })
        .collect()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    next: treasury::Policy,
    #[serde(with = "pos::decimal::u64")]
    activate_after_time: u64,
    #[serde(with = "pos::decimal::u64")]
    activate_after_bitcoin_height: u64,
    #[serde(with = "pos::decimal::u64")]
    proposal_expires: u64,
}
pub fn apply(host: &mut impl ExtensionHost, action: &SignedAction) -> Result<()> {
    let current = get(host)?;
    let context = context(host)?;
    let next = match action.kind {
        60 => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Input {
                proposal: Proposal,
                old: Vec<Approval>,
                new: Vec<Approval>,
            }
            let p: Input = serde_json::from_value(action.payload.clone())?;
            current.propose(
                treasury::Proposal {
                    next: p.proposal.next,
                    activate_after_time: p.proposal.activate_after_time,
                    activate_after_bitcoin_height: p.proposal.activate_after_bitcoin_height,
                    proposal_expires: p.proposal.proposal_expires,
                },
                &approvals(p.old)?,
                &approvals(p.new)?,
                context,
            )?
        }
        61 => {
            ensure!(
                action.payload.as_object().is_some_and(|p| p.is_empty()),
                "activation payload must be empty"
            );
            ensure!(
                bitcoin_adapter::get(host)?.meta.halted.is_none(),
                "cannot rotate receiving address while Bitcoin validation is halted"
            );
            current.activate(context)?
        }
        62 => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Input {
                control: String,
                #[serde(with = "pos::decimal::u64")]
                expires: u64,
                approvals: Vec<Approval>,
            }
            let p: Input = serde_json::from_value(action.payload.clone())?;
            let control = match p.control.as_str() {
                "pause" => treasury::Control::Pause,
                "resume" => treasury::Control::Resume,
                "cancel" => treasury::Control::Cancel,
                _ => return Err(anyhow!("unsupported treasury control")),
            };
            current.control(control, p.expires, &approvals(p.approvals)?, context)?
        }
        _ => return Err(anyhow!("unsupported treasury action")),
    };
    if next.active().revision != current.active().revision {
        let mut old: bitcoin_bridge::ReceivingPolicy = serde_json::from_slice(
            &host
                .get(RECEIVING_KEY)?
                .ok_or_else(|| anyhow!("missing receiving policy"))?,
        )?;
        old.time_end_micros = Some(context.elapsed_micros);
        old.btc_end_height = Some(
            u32::try_from(context.bitcoin_height)?
                .checked_add(1)
                .ok_or_else(|| anyhow!("Bitcoin height exhausted"))?,
        );
        host.put(policy_key(old.revision), Some(serde_json::to_vec(&old)?))?;
        let new = receiving(host, &next)?;
        host.put(RECEIVING_KEY.to_vec(), Some(serde_json::to_vec(&new)?))?;
        host.put(policy_key(new.revision), Some(serde_json::to_vec(&new)?))?;
    }
    store(host, &next)
}
pub fn audit(
    snapshot: &crate::store::VerifiedAudit<'_>,
    meta: &crate::engine::Meta,
) -> Result<u64> {
    use crate::engine::canonical_decode;
    let state: treasury::Treasury = canonical_decode(
        &snapshot
            .get(STATE_KEY)?
            .ok_or_else(|| anyhow!("missing treasury"))?,
    )?;
    state.validate_persisted(
        hex::decode(&meta.network_id)?
            .try_into()
            .map_err(|_| anyhow!("network size"))?,
    )?;
    let active: bitcoin_bridge::ReceivingPolicy = canonical_decode(
        &snapshot
            .get(RECEIVING_KEY)?
            .ok_or_else(|| anyhow!("missing receiving state"))?,
    )?;
    active.validate()?;
    ensure!(
        active.revision == state.active().revision
            && active.script_pubkey == state.active().witness_script()?.to_p2wsh().into_bytes(),
        "active receiving policy mismatch"
    );
    let mut policies = 0u64;
    snapshot.for_each_prefix(b"treasury/policy/", |key, value| {
        let policy: bitcoin_bridge::ReceivingPolicy = canonical_decode(value)?;
        policy.validate()?;
        ensure!(
            key == policy_key(policy.revision)
                && policy.revision <= active.revision
                && policy.time_network == active.time_network
                && policy.network == meta.config.bitcoin.network
                && policy.min_sats == meta.config.auction.min_sats
                && policy.max_sats == meta.config.auction.max_sats,
            "receiving history mismatch"
        );
        if policy.revision == active.revision {
            ensure!(
                value == serde_json::to_vec(&active)?
                    && policy.time_end_micros.is_none()
                    && policy.btc_end_height.is_none(),
                "active policy archive mismatch"
            );
        } else {
            ensure!(
                policy.time_end_micros.is_some() && policy.btc_end_height.is_some(),
                "old policy lacks closed interval"
            );
        }
        policies += 1;
        Ok(())
    })?;
    ensure!(policies == active.revision, "receiving policy revision gap");
    let mut actual = 0;
    snapshot.for_each_prefix(b"treasury/", |_, _| {
        actual += 1;
        Ok(())
    })?;
    ensure!(actual == policies + 2, "unexpected treasury namespace leaf");
    Ok(actual)
}
#[cfg(test)]
mod grace_tests {
    use super::*;
    fn policy() -> bitcoin_bridge::ReceivingPolicy {
        bitcoin_bridge::ReceivingPolicy {
            network: bitcoin_bridge::BitcoinNetwork::Regtest,
            time_network: [1; 32],
            revision: 1,
            script_pubkey: vec![0, 32, 1],
            min_sats: 1,
            max_sats: 1000,
            btc_start_height: 0,
            btc_end_height: Some(1009),
            time_start_micros: 0,
            time_end_micros: Some(7 * pos::DAY),
        }
    }
    #[test]
    fn previously_included_payments_get_bounded_delivery_grace_without_extending_btc_cutoff() {
        let old = policy();
        let accepted = late_receipt_policy(old.clone(), 7 * pos::DAY + pos::DAY).unwrap();
        assert_eq!(accepted.btc_end_height, old.btc_end_height);
        assert_eq!(accepted.script_pubkey, old.script_pubkey);
        assert!(accepted.time_end_micros.is_none());
        assert!(late_receipt_policy(old.clone(), 8 * pos::DAY + 1).is_err());
        assert!(late_receipt_policy(old, 7 * pos::DAY - 1).is_err());
        let mut missing = policy();
        missing.btc_end_height = None;
        assert!(late_receipt_policy(missing, 7 * pos::DAY).is_err());
    }
}
