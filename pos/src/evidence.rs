use super::*;
use tendermint::Vote;

/// Two votes of one validator for one consensus slot.
///
/// Anyone may send evidence, so the two votes are text from outside. They
/// are read with the vote type of the `tendermint` crate, and two of its
/// readers panic on certain texts instead of refusing them (`untrusted`).
/// The type therefore cannot be read from JSON without the check below: a
/// vote whose signature or timestamp is such a text is an error like any
/// other malformed vote. Nothing else is refused that was read before, and
/// nothing is read that was refused.
#[derive(Clone, Debug, Serialize)]
pub struct DoubleSignEvidence {
    pub first: Vote,
    pub second: Vote,
}

impl<'de> Deserialize<'de> for DoubleSignEvidence {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        // The votes as plain JSON first: the same two fields and no other,
        // as before.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, rename = "DoubleSignEvidence")]
        struct Unread {
            first: serde_json::Value,
            second: serde_json::Value,
        }
        let unread = Unread::deserialize(deserializer)?;
        let vote = |value: serde_json::Value| -> Result<Vote, D::Error> {
            vote_text(&value).map_err(D::Error::custom)?;
            serde_json::from_value(value).map_err(D::Error::custom)
        };
        Ok(Self {
            first: vote(unread.first)?,
            second: vote(unread.second)?,
        })
    }
}

/// The two fields of a vote in JSON that reach a reader which can panic:
/// `signature` (base64) and `timestamp` (a date). Every other field is read
/// as a number, as hexadecimal or as a list of numbers, by readers that
/// return an error on what they cannot read; a test puts each of the texts
/// in question into every place of a vote (`tests/untrusted_text.rs`).
fn vote_text(vote: &serde_json::Value) -> Result<(), &'static str> {
    if vote["signature"].as_str().is_some_and(|text| untrusted::base64_stops_the_decoder(text.as_bytes())) {
        return Err(untrusted::BASE64);
    }
    if vote["timestamp"].as_str().is_some_and(untrusted::date_stops_the_reader) {
        return Err(untrusted::DATE);
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalMembership {
    #[serde(with = "decimal::u64")]
    pub height: u64,
    #[serde(with = "decimal::u64")]
    pub elapsed_micros: u64,
    pub validators: Vec<Validator>,
}
/// Authenticated history and replay absence are supplied by the tree adapter.
/// Canonical Comet vote bytes include chain ID, type, height, round, block ID
/// and timestamp. Differences in timestamp alone are never double signing.
pub fn verify_double_sign(
    chain_id: &str,
    evidence: &DoubleSignEvidence,
    history: &HistoricalMembership,
    now: u64,
    already_seen: bool,
) -> Result<(u64, [u8; 32])> {
    ensure!(!already_seen, "evidence replay");
    validate_set(&history.validators)?;
    let (a, b) = (&evidence.first, &evidence.second);
    ensure!(
        a.height == b.height
            && a.height.value() == history.height
            && a.round == b.round
            && a.vote_type == b.vote_type
            && a.validator_address == b.validator_address
            && a.block_id != b.block_id,
        "not conflicting votes at one consensus slot"
    );
    ensure!(
        history.elapsed_micros <= now && now - history.elapsed_micros <= UNBOND_DELAY,
        "evidence outside slash window"
    );
    let member = history
        .validators
        .iter()
        .find(|v| {
            hex32(&v.consensus_key)
                .is_ok_and(|key| Sha256::digest(key)[..20] == a.validator_address.as_bytes()[..])
        })
        .ok_or_else(|| anyhow!("signer was not a validator at the offense height"))?;
    let key = public_key(&member.consensus_key)?;
    let chain: tendermint::chain::Id = chain_id.parse()?;
    for vote in [a, b] {
        let mut bytes = Vec::new();
        vote.to_signable_bytes(chain.clone(), &mut bytes)?;
        let signature = vote
            .signature
            .as_ref()
            .ok_or_else(|| anyhow!("missing vote signature"))?;
        key.verify_strict(&bytes, &Signature::from_slice(signature.as_bytes())?)?;
    }
    let mut hash = Sha256::new();
    hash.update(b"TIME-POS-EVIDENCE-SLOT-V1\0");
    hash.update((chain_id.len() as u64).to_be_bytes());
    hash.update(chain_id.as_bytes());
    hash.update(hex32(&member.consensus_key)?);
    hash.update(history.height.to_be_bytes());
    hash.update(a.round.value().to_be_bytes());
    hash.update([if a.vote_type == tendermint::vote::Type::Prevote {
        1
    } else {
        2
    }]);
    Ok((member.owner, hash.finalize().into()))
}
