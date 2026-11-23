//! Paid onboarding rows and the sponsor fee share the engine's staged action.
//! Sponsor authority never becomes account/device or recovery authority.
use crate::engine::{ExtensionHost, Meta};
use crate::wire::SignedAction;
use anyhow::{Result, anyhow, ensure};

pub use registration::{STATE_KEY, commit_key};
fn network(meta: &Meta) -> Result<[u8; 32]> {
    registration::key32(&meta.network_id)
}
fn context(meta: &Meta, sponsor: u64) -> Result<registration::Context> {
    Ok(registration::Context {
        network: network(meta)?,
        sponsor,
        elapsed_micros: meta.elapsed_micros()?,
        height: u64::try_from(meta.height)?,
    })
}
struct Read<'a, H>(&'a H);
impl<H: ExtensionHost> registration::Reader for Read<'_, H> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.0.get(key)
    }
}
struct Write<'a, H>(&'a mut H);
impl<H: ExtensionHost> registration::Reader for Write<'_, H> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.0.get(key)
    }
}
impl<H: ExtensionHost> registration::Host for Write<'_, H> {
    fn put(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) -> Result<()> {
        self.0.put(key, value)
    }
    fn registered(&self, public_key: &[u8; 32]) -> Result<bool> {
        Ok(self
            .0
            .get(&crate::engine::pubkey_key(&hex::encode(public_key))?)?
            .is_some())
    }
    fn debit(&mut self, sponsor: u64, amount: u64) -> Result<()> {
        self.0.debit(sponsor, amount)
    }
    fn bank_credit(&mut self, amount: u64) -> Result<()> {
        self.0.bank_credit(amount)
    }
}
pub fn initialize(host: &mut impl ExtensionHost) -> Result<()> {
    let config = host.meta().config.registration.clone();
    let network = network(host.meta())?;
    registration::initialize(&mut Write(host), &config, network)
}
pub fn begin_block(host: &mut impl ExtensionHost) -> Result<()> {
    let config = host.meta().config.registration.clone();
    let context = context(host.meta(), 0)?;
    registration::cleanup(
        &mut Write(host),
        &config,
        context,
        registration::CLEANUP_LIMIT,
    )?;
    Ok(())
}
pub fn apply(host: &mut impl ExtensionHost, action: &SignedAction) -> Result<()> {
    ensure!(action.kind == 44, "unsupported registration extension");
    let input: registration::CommitInput = serde_json::from_value(action.payload.clone())?;
    let config = host.meta().config.registration.clone();
    let context = context(host.meta(), action.from)?;
    registration::commit(&mut Write(host), &config, context, input)?;
    Ok(())
}
/// Supply ONLY this commitment to the existing identity adapter. The adapter
/// still verifies the new device signature, name/salt, uniqueness and next-block
/// delay. Consume in the SAME successful action stage after account creation.
pub fn for_reveal(
    host: &impl ExtensionHost,
    public_key: &str,
) -> Result<(timecurrency_node::ledger::NameCommit, String)> {
    let key = registration::key32(public_key)?;
    let context = context(host.meta(), 0)?;
    let commit =
        registration::get_commit(&Read(host), &host.meta().config.registration, context, &key)?
            .ok_or_else(|| anyhow!("paid registration commitment missing or consumed"))?;
    ensure!(
        commit.expires_elapsed_micros >= context.elapsed_micros,
        "paid registration commitment expired"
    );
    Ok((
        timecurrency_node::ledger::NameCommit {
            public_key: commit.public_key,
            commitment: commit.commitment,
            height: i64::try_from(commit.height)?,
            expires_elapsed_micros: commit.expires_elapsed_micros,
        },
        commit.entry_id,
    ))
}
pub fn consume_commit(
    host: &mut impl ExtensionHost,
    public_key: &str,
    expected_entry_id: &str,
) -> Result<()> {
    let config = host.meta().config.registration.clone();
    let context = context(host.meta(), 0)?;
    let key = registration::key32(public_key)?;
    registration::consume(&mut Write(host), &config, context, &key, expected_entry_id)
}
struct AuditReader<'a, 'b>(&'a crate::store::VerifiedAudit<'b>);
impl registration::Reader for AuditReader<'_, '_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.0.get(key)
    }
}
impl registration::Scanner for AuditReader<'_, '_> {
    fn registered(&self, public_key: &[u8; 32]) -> Result<bool> {
        Ok(self
            .0
            .get(&crate::engine::pubkey_key(&hex::encode(public_key))?)?
            .is_some())
    }
    fn sponsor_exists(&self, sponsor: u64) -> Result<bool> {
        Ok(self.0.get(&crate::engine::account_key(sponsor))?.is_some())
    }
    fn for_each_prefix<F>(&self, prefix: &[u8], visit: F) -> Result<()>
    where
        F: FnMut(&[u8], &[u8]) -> Result<()>,
    {
        self.0.for_each_prefix(prefix, visit)
    }
}
pub fn audit(snapshot: &crate::store::VerifiedAudit<'_>, meta: &Meta) -> Result<u64> {
    registration::audit(
        &AuditReader(snapshot),
        &meta.config.registration,
        context(meta, 0)?,
    )
}
