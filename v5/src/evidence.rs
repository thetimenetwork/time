//! Double-signing evidence, checked with the signature rule consensus uses.
//!
//! CometBFT accepts a vote when its Ed25519 signature passes the ZIP-215
//! rule. Protocol 4 checked evidence with the strict rule, which refuses some
//! signatures that ZIP-215 accepts. A validator could therefore sign two
//! conflicting votes that consensus counted and that no evidence could ever
//! prove. Here evidence is accepted exactly when consensus would have
//! accepted both votes.
//!
//! This does not make evidence forgeable: producing either signature still
//! requires the validator's private key. Every other condition is the one
//! protocol 4 applies, and the replay key is computed the same way.
use anyhow::{Result, anyhow, ensure};
use pos::{DoubleSignEvidence, HistoricalMembership, UNBOND_DELAY, hex32, validate_set};
use sha2::{Digest, Sha256};

/// Returns the offending validator's owner account and the replay key of the
/// consensus slot (validator, height, round, vote type).
pub fn verify_double_sign(
    chain_id: &str,
    evidence: &DoubleSignEvidence,
    history: &HistoricalMembership,
    now: u64,
) -> Result<(u64, [u8; 32])> {
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
    let key_bytes = hex32(&member.consensus_key)?;
    let key = ed25519_consensus::VerificationKey::try_from(key_bytes)
        .map_err(|_| anyhow!("invalid consensus key"))?;
    let chain: tendermint::chain::Id = chain_id.parse()?;
    for vote in [a, b] {
        let mut bytes = Vec::new();
        vote.to_signable_bytes(chain.clone(), &mut bytes)?;
        let signature = vote
            .signature
            .as_ref()
            .ok_or_else(|| anyhow!("missing vote signature"))?;
        let signature = ed25519_consensus::Signature::try_from(signature.as_bytes())
            .map_err(|_| anyhow!("malformed vote signature"))?;
        key.verify(&signature, &bytes)
            .map_err(|_| anyhow!("vote signature does not verify"))?;
    }
    let mut hash = Sha256::new();
    hash.update(b"TIME-POS-EVIDENCE-SLOT-V1\0");
    hash.update((chain_id.len() as u64).to_be_bytes());
    hash.update(chain_id.as_bytes());
    hash.update(key_bytes);
    hash.update(history.height.to_be_bytes());
    hash.update(a.round.value().to_be_bytes());
    hash.update([if a.vote_type == tendermint::vote::Type::Prevote {
        1
    } else {
        2
    }]);
    Ok((member.owner, hash.finalize().into()))
}
