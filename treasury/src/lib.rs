//! Policy prototype. No Bitcoin wallet, spending key, RPC, bid admission or
//! consensus integration is provided here. Context must come from validated
//! Time and Bitcoin chains; unauthenticated web/API data cannot authorize it.
use anyhow::{Context as _, Result, ensure};
use bitcoin::{
    Address, Network, PublicKey, ScriptBuf, opcodes::all::OP_CHECKMULTISIG, script::Builder,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MIN_DELAY_MICROS: u64 = 7 * 86_400 * 1_000_000;
pub const MIN_BITCOIN_DELAY_BLOCKS: u64 = 1_008;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub revision: u64,
    /// Seven compressed secp256k1 public keys, canonical lowercase hex.
    pub treasury_keys: Vec<String>,
    /// Seven independent governance keys; these never spend the Bitcoin.
    pub governance_keys: Vec<String>,
}

fn bytes<const N: usize>(value: &str) -> Result<[u8; N]> {
    ensure!(value.len() == N * 2, "wrong hex length");
    let decoded = hex::decode(value)?;
    ensure!(hex::encode(&decoded) == value, "noncanonical hex");
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong byte length"))
}

impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.revision > 0, "zero policy revision");
        ensure!(
            self.treasury_keys.len() == 7 && self.governance_keys.len() == 7,
            "seven distinct keys per authority required"
        );
        let mut treasury = BTreeSet::new();
        for key in &self.treasury_keys {
            let encoded = bytes::<33>(key)?;
            let public = PublicKey::from_slice(&encoded)?;
            ensure!(
                public.compressed && treasury.insert(encoded),
                "duplicate or uncompressed Bitcoin key"
            );
        }
        let mut governance = BTreeSet::new();
        for key in &self.governance_keys {
            let encoded = bytes::<32>(key)?;
            let public = VerifyingKey::from_bytes(&encoded)?;
            ensure!(
                !public.is_weak() && governance.insert(encoded),
                "duplicate or weak governance key"
            );
        }
        Ok(())
    }
    pub fn hash(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut h = Sha256::new();
        h.update(b"TIME-TREASURY-POLICY-V1\0");
        h.update(self.revision.to_be_bytes());
        // Order is part of the policy signature; Bitcoin script sorts keys.
        for key in &self.treasury_keys {
            h.update(bytes::<33>(key)?);
        }
        for key in &self.governance_keys {
            h.update(bytes::<32>(key)?);
        }
        Ok(h.finalize().into())
    }
    pub fn witness_script(&self) -> Result<ScriptBuf> {
        self.validate()?;
        let mut keys = self
            .treasury_keys
            .iter()
            .map(|s| bytes::<33>(s))
            .collect::<Result<Vec<_>>>()?;
        keys.sort();
        let mut script = Builder::new().push_int(4);
        for key in keys {
            script = script.push_key(&PublicKey::from_slice(&key)?);
        }
        Ok(script
            .push_int(7)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script())
    }
    pub fn address(&self, network: Network) -> Result<Address> {
        Ok(Address::p2wsh(&self.witness_script()?, network))
    }
}

/// These coordinates must be independently validated, including Bitcoin PoW,
/// difficulty, chain selection and reorganization/finality handling.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub time_height: u64,
    pub elapsed_micros: u64,
    pub bitcoin_height: u64,
}
impl Context {
    fn follows_time(self, previous: Self) -> bool {
        self.time_height >= previous.time_height && self.elapsed_micros >= previous.elapsed_micros
    }
    fn follows(self, previous: Self) -> bool {
        self.follows_time(previous) && self.bitcoin_height >= previous.bitcoin_height
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub public_key: String,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub next: Policy,
    pub activate_after_time: u64,
    pub activate_after_bitcoin_height: u64,
    pub proposal_expires: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Treasury {
    network_id: [u8; 32],
    active: Policy,
    pending: Option<Proposal>,
    paused: bool,
    sequence: u64,
    context: Context,
}
impl Treasury {
    /// Only restore a value read through an authenticated state root. This
    /// structural check does not replace proof verification or authorize a
    /// proposed policy received from a gateway.
    pub fn validate_persisted(&self, expected_network: [u8; 32]) -> Result<()> {
        ensure!(
            self.network_id == expected_network,
            "treasury network mismatch"
        );
        self.active.validate()?;
        if let Some(pending) = &self.pending {
            pending.next.validate()?;
            ensure!(
                pending.next.revision
                    == self
                        .active
                        .revision
                        .checked_add(1)
                        .context("revision exhausted")?,
                "pending revision mismatch"
            );
            ensure!(
                pending.proposal_expires > pending.activate_after_time,
                "invalid pending expiry"
            );
        }
        Ok(())
    }
    pub fn new(network_id: [u8; 32], active: Policy, context: Context) -> Result<Self> {
        active.validate()?;
        ensure!(active.revision == 1, "initial policy revision must be one");
        Ok(Self {
            network_id,
            active,
            pending: None,
            paused: false,
            sequence: 0,
            context,
        })
    }
    pub fn active(&self) -> &Policy {
        &self.active
    }
    pub fn pending(&self) -> Option<&Proposal> {
        self.pending.as_ref()
    }
    pub fn paused(&self) -> bool {
        self.paused
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    fn base_message(&self, kind: u8) -> Result<Vec<u8>> {
        let mut data = b"TIME-TREASURY-CONTROL-V1\0".to_vec();
        data.extend_from_slice(&self.network_id);
        data.extend_from_slice(&self.active.hash()?);
        data.extend_from_slice(&self.sequence.to_be_bytes());
        data.push(kind);
        Ok(data)
    }
    pub fn proposal_message(&self, proposal: &Proposal, new_council: bool) -> Result<Vec<u8>> {
        let mut message = self.base_message(if new_council { 2 } else { 1 })?;
        message.extend_from_slice(&proposal.next.hash()?);
        message.extend_from_slice(&proposal.activate_after_time.to_be_bytes());
        message.extend_from_slice(&proposal.activate_after_bitcoin_height.to_be_bytes());
        message.extend_from_slice(&proposal.proposal_expires.to_be_bytes());
        Ok(message)
    }
    /// Pause/resume/cancel messages bind pending policy too, avoiding a signature
    /// issued for one proposal being applied to a replacement at the same state.
    pub fn control_message(&self, control: Control, expires: u64) -> Result<Vec<u8>> {
        let mut message = self.base_message(control as u8)?;
        let pending = self
            .pending
            .as_ref()
            .map(|proposal| {
                let mut hash = Sha256::new();
                hash.update(b"TIME-TREASURY-PENDING-V1\0");
                hash.update(proposal.next.hash()?);
                hash.update(proposal.activate_after_time.to_be_bytes());
                hash.update(proposal.activate_after_bitcoin_height.to_be_bytes());
                hash.update(proposal.proposal_expires.to_be_bytes());
                Ok::<[u8; 32], anyhow::Error>(hash.finalize().into())
            })
            .transpose()?
            .unwrap_or([0; 32]);
        message.extend_from_slice(&pending);
        message.extend_from_slice(&expires.to_be_bytes());
        Ok(message)
    }
    fn authorize(keys: &[String], message: &[u8], approvals: &[Approval]) -> Result<()> {
        ensure!(
            (5..=7).contains(&approvals.len()),
            "five of seven governance approvals required"
        );
        let mut seen = BTreeSet::new();
        for approval in approvals {
            ensure!(
                keys.contains(&approval.public_key) && seen.insert(&approval.public_key),
                "unknown or duplicate signer"
            );
            let key = VerifyingKey::from_bytes(&bytes::<32>(&approval.public_key)?)?;
            let signature = Signature::from_slice(&approval.signature)?;
            key.verify_strict(message, &signature)?;
        }
        Ok(())
    }
    pub fn propose(
        &self,
        proposal: Proposal,
        old: &[Approval],
        new: &[Approval],
        context: Context,
    ) -> Result<Self> {
        ensure!(
            context.follows(self.context),
            "chain coordinates rolled back"
        );
        ensure!(
            self.pending.is_none(),
            "cancel or finish the current proposal first"
        );
        ensure!(
            proposal.next.revision
                == self
                    .active
                    .revision
                    .checked_add(1)
                    .context("revision exhausted")?,
            "incorrect next revision"
        );
        ensure!(
            proposal.activate_after_time
                >= context
                    .elapsed_micros
                    .checked_add(MIN_DELAY_MICROS)
                    .context("time overflow")?,
            "rotation delay too short"
        );
        ensure!(
            proposal.activate_after_bitcoin_height
                >= context
                    .bitcoin_height
                    .checked_add(MIN_BITCOIN_DELAY_BLOCKS)
                    .context("height overflow")?,
            "Bitcoin delay too short"
        );
        ensure!(
            proposal.proposal_expires > proposal.activate_after_time
                && proposal.proposal_expires
                    <= context
                        .elapsed_micros
                        .checked_add(30 * 86_400 * 1_000_000)
                        .context("expiry overflow")?,
            "proposal expiry outside allowed window"
        );
        Self::authorize(
            &self.active.governance_keys,
            &self.proposal_message(&proposal, false)?,
            old,
        )?;
        Self::authorize(
            &proposal.next.governance_keys,
            &self.proposal_message(&proposal, true)?,
            new,
        )?;
        let mut next = self.clone();
        next.pending = Some(proposal);
        next.sequence = next.sequence.checked_add(1).context("sequence exhausted")?;
        next.context = context;
        Ok(next)
    }
    pub fn activate(&self, context: Context) -> Result<Self> {
        ensure!(
            context.follows(self.context),
            "chain coordinates rolled back"
        );
        let proposal = self.pending.as_ref().context("no pending policy")?;
        ensure!(
            context.elapsed_micros >= proposal.activate_after_time
                && context.bitcoin_height >= proposal.activate_after_bitcoin_height,
            "policy timelock not satisfied"
        );
        ensure!(
            context.elapsed_micros <= proposal.proposal_expires,
            "policy proposal expired"
        );
        let mut next = self.clone();
        next.active = proposal.next.clone();
        next.pending = None;
        // An emergency pause is never silently lifted by rotation.
        next.sequence = next.sequence.checked_add(1).context("sequence exhausted")?;
        next.context = context;
        Ok(next)
    }
    pub fn control(
        &self,
        control: Control,
        expires: u64,
        approvals: &[Approval],
        context: Context,
    ) -> Result<Self> {
        // A greatest-work Bitcoin fork can be shorter. Restrictive emergency
        // controls must remain available; neither enables receipts or redirects
        // money. Resume/activation retain the full Bitcoin high-water guard.
        let restrictive = matches!(control, Control::Pause | Control::Cancel);
        ensure!(
            if restrictive {
                context.follows_time(self.context)
            } else {
                context.follows(self.context)
            },
            "chain coordinates rolled back"
        );
        ensure!(
            expires >= context.elapsed_micros
                && expires
                    <= context
                        .elapsed_micros
                        .checked_add(3_600_000_000)
                        .context("control expiry overflow")?,
            "control expired or deadline too far in future"
        );
        Self::authorize(
            &self.active.governance_keys,
            &self.control_message(control, expires)?,
            approvals,
        )?;
        let mut next = self.clone();
        match control {
            Control::Pause => {
                ensure!(!self.paused, "already paused");
                next.paused = true;
            }
            Control::Resume => {
                ensure!(
                    self.paused && self.pending.is_none(),
                    "resume requires no pending rotation"
                );
                next.paused = false;
            }
            Control::Cancel => {
                ensure!(self.pending.is_some(), "no pending rotation");
                next.pending = None;
            }
        }
        next.sequence = next.sequence.checked_add(1).context("sequence exhausted")?;
        next.context = Context {
            bitcoin_height: context.bitcoin_height.max(self.context.bitcoin_height),
            ..context
        };
        Ok(next)
    }
    pub fn receiving_script(&self) -> Result<ScriptBuf> {
        ensure!(!self.paused, "foundation Bitcoin bids paused");
        Ok(self.active.witness_script()?.to_p2wsh())
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Control {
    Pause = 3,
    Resume = 4,
    Cancel = 5,
}
