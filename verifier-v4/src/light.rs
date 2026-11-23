use crate::{decimal, parse};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::HashSet, time::Duration};
use tendermint::{Time, block::signed_header::SignedHeader, validator};
use tendermint_light_client_verifier::{
    ProdVerifier, Verdict, Verifier,
    options::Options,
    types::{TrustedBlockState, UntrustedBlockState},
};

pub const MAX_VALIDATORS: usize = 100;
pub const MAX_TRUST_SECONDS: u64 = 7 * 86400;
pub const FRESH_MICROS: i128 = 45_000_000;
pub const FUTURE_MICROS: i128 = 10_000_000;
/// The first protocol version of a network: the one in its genesis and in the
/// trust manifest (`Trust::app_version`). It never changes. An upgrade raises
/// the version that certified headers carry, never this.
pub const FIRST_VERSION: u64 = 4;
/// The newest protocol version whose state and blocks this build can judge.
/// This build implements versions `FIRST_VERSION` to `KNOWN_VERSION`.
pub const KNOWN_VERSION: u64 = 4;
/// The refusal of data at a protocol version this build does not implement.
/// Every caller raises it only for a version read from a header that is
/// already authenticated (certified by the validators, or tied by hashes to
/// a certified header), so no gateway can produce it by its own word.
pub fn upgrade_required(found: u64) -> String {
    format!(
        "UPGRADE_REQUIRED: the network runs protocol version {found}; this software implements versions {FIRST_VERSION} to {KNOWN_VERSION}. Install a release that implements version {found}."
    )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LightBlock {
    pub signed_header: SignedHeader,
    pub validators: Vec<Value>,
    pub next_validators: Vec<Value>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub height: String,
    pub block_hash: String,
    pub time_micros: String,
    pub block: LightBlock,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Trust {
    pub chain_id: String,
    pub network_id: String,
    pub app_version: String,
    pub genesis_time_micros: String,
    pub trusting_period_seconds: String,
    pub unbonding_period_seconds: String,
    pub initial_validators: Vec<Value>,
    #[serde(default)]
    pub checkpoint: Option<Checkpoint>,
}
pub struct ParsedBlock {
    pub block: LightBlock,
    pub validators: validator::Set,
    pub next_validators: validator::Set,
}
fn err(message: &str) -> String {
    format!("INVALID_LIGHT_BLOCK: {message}")
}
pub fn now_micros(now_ms: f64) -> Result<i128, String> {
    if !now_ms.is_finite()
        || now_ms < 0.0
        || now_ms.fract() != 0.0
        || now_ms > 9_007_199_254_740_991.0
    {
        return Err("INVALID_CLOCK".into());
    }
    Ok((now_ms as i128) * 1000)
}
fn time_from_micros(now: i128) -> Result<Time, String> {
    let seconds = i64::try_from(now / 1_000_000).map_err(|_| "INVALID_CLOCK")?;
    Time::from_unix_timestamp(seconds, ((now % 1_000_000) * 1000) as u32)
        .map_err(|_| "INVALID_CLOCK".into())
}
pub fn parse_set(values: &[Value]) -> Result<validator::Set, String> {
    if values.is_empty() || values.len() > MAX_VALIDATORS {
        return Err(err("validator count outside supported bounds"));
    }
    let mut infos = Vec::new();
    let mut addresses = HashSet::new();
    let mut keys = HashSet::new();
    let mut power = 0u64;
    for value in values {
        let mut value = value.clone();
        let map = value
            .as_object_mut()
            .ok_or_else(|| err("invalid validator record"))?;
        if let (Some(a), Some(b)) = (map.get("power"), map.get("voting_power"))
            && a != b
        {
            return Err(err("ambiguous validator power"));
        }
        if let Some(value) = map.remove("voting_power") {
            map.entry("power").or_insert(value);
        }
        if !map.contains_key("power") {
            return Err(err("missing validator power"));
        }
        map.entry("proposer_priority").or_insert(json!("0"));
        // A validator record is read by a type of the `tendermint` crates,
        // whose base64 reader panics on certain texts (`crate::untrusted`).
        // Records that came in through `crate::parse` have been looked at;
        // this function also takes values from callers that did not.
        crate::untrusted::value(&value).map_err(|reason| err(&format!("invalid validator: {reason}")))?;
        let info: validator::Info =
            serde_json::from_value(value).map_err(|e| err(&format!("invalid validator: {e}")))?;
        if info.power.value() == 0
            || info.pub_key.ed25519().is_none()
            || tendermint::account::Id::from(info.pub_key) != info.address
        {
            return Err(err("invalid validator key/address/power"));
        }
        if !addresses.insert(info.address.to_string()) || !keys.insert(info.pub_key.to_bytes()) {
            return Err(err("duplicate validator authority"));
        }
        power = power
            .checked_add(info.power.value())
            .ok_or_else(|| err("voting power overflow"))?;
        infos.push(info);
    }
    if power > validator::Set::MAX_TOTAL_VOTING_POWER {
        return Err(err("voting power exceeds Comet limit"));
    }
    Ok(validator::Set::without_proposer(infos))
}
pub fn policy(trust: &Trust) -> Result<(u64, i128), String> {
    if trust.app_version != "4"
        || !trust.chain_id.starts_with("time-devnet-v4-")
        || trust.network_id.len() != 64
        || !trust
            .network_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("INVALID_TRUST: explicit V4 chain/network/application pin required".into());
    }
    let period = decimal(&json!(trust.trusting_period_seconds), "trusting period")?;
    let unbond = decimal(&json!(trust.unbonding_period_seconds), "unbonding period")?;
    if !(60..=MAX_TRUST_SECONDS).contains(&period) || period >= unbond {
        return Err("INVALID_TRUST: trusting period must be at most seven days and shorter than unbonding accountability".into());
    }
    let genesis = i128::from(decimal(&json!(trust.genesis_time_micros), "genesis time")?);
    parse_set(&trust.initial_validators)?;
    Ok((period, genesis))
}
pub fn validate_block(block: &LightBlock, trust: &Trust, now: i128) -> Result<ParsedBlock, String> {
    let validators = parse_set(&block.validators)?;
    let next = parse_set(&block.next_validators)?;
    let header = &block.signed_header.header;
    // The version is at least the network's first one. There is no upper
    // bound here: checking a header uses no application rule, so a checkpoint
    // keeps advancing across an upgrade this build does not implement. What
    // such a build must not do is read state or receipts of that version
    // (view.rs, receipt.rs).
    if header.chain_id.as_str() != trust.chain_id || header.version.app < FIRST_VERSION {
        return Err(err(
            "wrong independently pinned chain or application version",
        ));
    }
    if header.time.unix_timestamp_nanos() / 1000 > now + FUTURE_MICROS {
        return Err(err("header exceeds future clock bound"));
    }
    if header.time.unix_timestamp_nanos() / 1000
        < i128::from(decimal(&json!(trust.genesis_time_micros), "genesis time")?)
    {
        return Err(err("header predates pinned genesis"));
    }
    if header.app_hash.as_bytes().len() != 32 {
        return Err(err("application root is not 32 bytes"));
    }
    let untrusted = UntrustedBlockState {
        signed_header: &block.signed_header,
        validators: &validators,
        next_validators: Some(&next),
    };
    let verifier = ProdVerifier::default();
    for verdict in [
        verifier.verify_validator_sets(&untrusted),
        verifier.verify_commit(&untrusted),
    ] {
        if verdict != Verdict::Success {
            return Err(err(&format!(
                "header/quorum/hash verification failed: {verdict:?}"
            )));
        }
    }
    let mut normalized = block.clone();
    normalized.validators = validators
        .validators()
        .iter()
        .map(|v| serde_json::to_value(v).unwrap())
        .collect();
    normalized.next_validators = next
        .validators()
        .iter()
        .map(|v| serde_json::to_value(v).unwrap())
        .collect();
    Ok(ParsedBlock {
        block: normalized,
        validators,
        next_validators: next,
    })
}
pub fn checkpoint(block: LightBlock) -> Checkpoint {
    let header = &block.signed_header.header;
    Checkpoint {
        height: header.height.value().to_string(),
        block_hash: header.hash().to_string().to_lowercase(),
        time_micros: (header.time.unix_timestamp_nanos() / 1000).to_string(),
        block,
    }
}
pub fn validate_checkpoint(
    checkpoint: &Checkpoint,
    trust: &Trust,
    now: i128,
) -> Result<ParsedBlock, String> {
    let (period, _) = policy(trust)?;
    let block = validate_block(&checkpoint.block, trust, now)?;
    let expected = self::checkpoint(block.block.clone());
    if checkpoint.height != expected.height
        || checkpoint.block_hash != expected.block_hash
        || checkpoint.time_micros != expected.time_micros
    {
        return Err("INVALID_TRUST: checkpoint metadata differs from its certified header".into());
    }
    if now - (block.block.signed_header.header.time.unix_timestamp_nanos() / 1000)
        >= i128::from(period) * 1_000_000
    {
        return Err("CHECKPOINT_REFRESH_REQUIRED: local trusted checkpoint expired; obtain an independently authenticated checkpoint".into());
    }
    Ok(block)
}
pub fn ensure_fresh(block: &LightBlock, now: i128) -> Result<(), String> {
    if now - block.signed_header.header.time.unix_timestamp_nanos() / 1000 > FRESH_MICROS {
        return Err("STALE_STATE: fresh current authority proof is required".into());
    }
    Ok(())
}
pub fn trust_status(trust: &Trust, now: i128) -> Result<Value, String> {
    let (period, genesis) = policy(trust)?;
    if let Some(checkpoint) = &trust.checkpoint {
        validate_checkpoint(checkpoint, trust, now)?;
        Ok(
            json!({"ready":true,"bootstrapRequired":false,"height":checkpoint.height,"blockHash":checkpoint.block_hash}),
        )
    } else {
        if genesis > now + FUTURE_MICROS {
            return Err("INVALID_TRUST: genesis is from the future".into());
        }
        if now - genesis >= i128::from(period) * 1_000_000 {
            return Err("CHECKPOINT_REFRESH_REQUIRED: genesis-only bootstrap expired; authenticate a current checkpoint independently".into());
        }
        Ok(json!({"ready":true,"bootstrapRequired":true,"height":"0"}))
    }
}
pub fn update(candidate: LightBlock, trust: &Trust, now: i128) -> Result<Value, String> {
    let (period, genesis) = policy(trust)?;
    let candidate = validate_block(&candidate, trust, now)?;
    let Some(pinned) = &trust.checkpoint else {
        if genesis > now + FUTURE_MICROS {
            return Err("INVALID_TRUST: genesis is from the future".into());
        }
        if now - genesis >= i128::from(period) * 1_000_000 {
            return Err("CHECKPOINT_REFRESH_REQUIRED: genesis-only bootstrap expired; a fresh RPC roster is not a trust anchor".into());
        }
        let header = &candidate.block.signed_header.header;
        if header.height.value() != 1 {
            return Err(
                "BOOTSTRAP_HEADER_REQUIRED: verify height one against the pinned genesis first"
                    .into(),
            );
        }
        if header.time.unix_timestamp_nanos() / 1000 < genesis {
            return Err(err("bootstrap header predates pinned genesis"));
        }
        if candidate.validators.hash() != parse_set(&trust.initial_validators)?.hash() {
            return Err(err("bootstrap roster differs from pinned genesis"));
        }
        return Ok(
            json!({"verified":true,"status":"VERIFIED","checkpoint":checkpoint(candidate.block),"verificationMode":"dynamic-validator-bootstrap"}),
        );
    };
    let trusted = validate_checkpoint(pinned, trust, now)?;
    let before = &trusted.block.signed_header.header;
    let after = &candidate.block.signed_header.header;
    if after.height < before.height {
        return Err("HEADER_ROLLBACK: header is below the highest trusted checkpoint".into());
    }
    if after.height == before.height {
        if after.hash() != before.hash() {
            return Err(
                "CONFLICTING_FINALITY: different certified header at trusted height".into(),
            );
        }
        return Ok(
            json!({"verified":true,"status":"VERIFIED","checkpoint":checkpoint(candidate.block),"verificationMode":"dynamic-validator-same-height"}),
        );
    }
    // The version of a chain never goes down: a header above the trusted
    // checkpoint carries its version or a higher one.
    if after.version.app < before.version.app {
        return Err(err(
            "application version is lower than the trusted checkpoint's",
        ));
    }
    if after.height.value() == before.height.value() + 1
        && after
            .last_block_id
            .as_ref()
            .is_none_or(|id| id.hash != before.hash())
    {
        return Err(
            "CONFLICTING_FINALITY: adjacent header does not extend the trusted block".into(),
        );
    }
    // Crucial: the trusted next validator set was independently hash-bound by
    // validate_checkpoint, never accepted from a relayer's claimed authority.
    let trusted_state = TrustedBlockState {
        chain_id: &before.chain_id,
        header_time: before.time,
        height: before.height,
        next_validators: &trusted.next_validators,
        next_validators_hash: before.next_validators_hash,
    };
    let untrusted = UntrustedBlockState {
        signed_header: &candidate.block.signed_header,
        validators: &candidate.validators,
        next_validators: Some(&candidate.next_validators),
    };
    let options = Options {
        trust_threshold: tendermint::trust_threshold::TrustThresholdFraction::ONE_THIRD,
        trusting_period: Duration::from_secs(period),
        clock_drift: Duration::from_secs(10),
    };
    match ProdVerifier::default().verify_update_header(
        untrusted,
        trusted_state,
        &options,
        time_from_micros(now)?,
    ) {
        Verdict::Success => Ok(
            json!({"verified":true,"status":"VERIFIED","checkpoint":checkpoint(candidate.block),"verificationMode":"dynamic-validator-trusted-update"}),
        ),
        Verdict::NotEnoughTrust(tally) => {
            let distance = after.height.value() - before.height.value();
            if distance < 2 {
                return Err(err("adjacent validator transition lacked a valid quorum"));
            }
            Ok(
                json!({"verified":false,"status":"NEEDS_BISECTION","trustedHeight":before.height.value().to_string(),"targetHeight":after.height.value().to_string(),"suggestedHeight":(before.height.value()+distance/2).to_string(),"overlap":format!("{tally:?}")}),
            )
        }
        other => Err(err(&format!("trusted validator update failed: {other:?}"))),
    }
}
pub fn update_json(candidate_json: &str, trust_json: &str, now_ms: f64) -> Result<Value, String> {
    update(
        parse(candidate_json)?,
        &parse(trust_json)?,
        now_micros(now_ms)?,
    )
}
