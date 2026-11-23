//! Account security: separate keys for signing in, for spending and for
//! recovery.
//!
//! An account that adopts these rules ("secured") gives each of its keys one
//! role. The role is stored in the two flags a device row already has, so the
//! account row keeps its protocol-4 encoding:
//!
//! | role     | can_manage | can_spend | alone, the key may |
//! |----------|------------|-----------|--------------------|
//! | sign-in  | no         | no        | prove the account's identity off chain; nothing on chain |
//! | spend    | no         | yes       | pay within the daily limit; start what waits (a larger payment, a raise of the limit); add and remove sign-in keys; freeze; cancel what is waiting |
//! | recovery | yes        | no        | freeze; cancel what is waiting; vote |
//!
//! Everything else needs proofs from several keys ("root operation"). A spend
//! key counts as one proof however many spend keys sign, each recovery key as
//! one, a sign-in key as none. With at least `threshold` proofs:
//!
//! - if a spend key is among them the operation happens at once (the owner is
//!   present with a second proof);
//! - if not, only a replacement of the keys can be asked for. It waits
//!   `delay_seconds`, the account is frozen meanwhile, and a key that the new
//!   set names as a spend or recovery key finishes it, whatever that key was
//!   until then. `threshold` proofs can cancel it; a spend key alone cannot.
//!
//! Approvals name the version of the security row, an expiry, the operation
//! and the full list of approving keys. They cannot be moved to another
//! account, operation or set of approvers, and are worthless once the version
//! has moved on. Until then, and until they expire, anyone who holds a spend
//! or recovery key of the account can submit them: wallets should date them
//! as short as the situation allows. Approvals for a payment can be used only
//! in the last hour before they expire, so a wallet dates them an hour ahead
//! at most.
//!
//! What a stolen key can do is bounded by its role:
//!
//! - a sign-in key signs nothing this chain accepts. It moves nothing,
//!   changes no key, and can neither freeze the account nor cancel anything.
//!   All it does is sign in as the account, off chain. The key that is used
//!   most and guarded least is thereby the one whose theft costs least, and a
//!   spend key alone replaces it at once. Were a sign-in key able to freeze,
//!   whoever stole one could keep the account frozen, and with it the spend
//!   key's power to remove the stolen key;
//! - a spend key moves what the daily limit allows, fees included. The limit
//!   is an allowance of `daily_limit_micros` that refills evenly over 24
//!   hours: at most that much at once, and at most twice that much in any 24
//!   hours. A limit below the fee leaves the spend key unable to do anything
//!   alone, and since lowering the limit is immediate, whoever holds a spend
//!   key can put the account in that state; a root operation sets the limit
//!   again. What else a spend key can start that takes value out of the
//!   account waits `delay_seconds` in the open: a larger payment, a raise of
//!   the limit. Any spend or recovery key can cancel what is waiting. A spend
//!   key also adds and removes sign-in keys, so whoever holds one can sign in
//!   as the account and sign its owner out. It cannot touch spend or recovery
//!   keys, cancel a replacement or lift a freeze. Cancelling costs the
//!   account a fee outside the limit, so a spend key can make it pay up to
//!   about twice the limit in fees a day by starting and cancelling;
//! - one recovery key decides nothing. Like a spend key it can freeze the
//!   account, once per half freeze period, at one fee each time.
//!
//! Any spend or recovery key can freeze the account for `freeze_seconds`. A
//! freeze names the freeze count and the version of the settings it was
//! signed for, so one that was signed earlier cannot land on keys that have
//! been replaced since. Lifting a freeze does not stop the key that placed it
//! from freezing again: the answer to a freeze the owner did not place is to
//! replace keys, not only to lift it.
//! While frozen (by a freeze, or while a replacement of the keys waits) no
//! action of a spend key may lower the balance, sign-in keys are neither
//! added nor removed, and what was waiting is dropped, so that it cannot go
//! through the moment the freeze ends. Actions that leave the balance alone
//! or raise it still work: a freeze costs the account nothing it was owed. A
//! freeze ends early through a root operation with the spend key (which can
//! also pay during a freeze), or when a replacement of the keys is finished.
//! Websites that follow the login rule of the wallet library accept no
//! sign-in of a frozen account: freezing also stops whoever took a device
//! from signing in with it.
//!
//! The actions that protect an account (freeze, cancel, root operation,
//! finishing a replacement) do not use the account's nonce. Whoever holds a
//! spend key can use up nonces as fast as blocks are made, and could otherwise
//! keep every protective action of the owner out for as long as its daily limit
//! pays the fees: long enough for a payment it started to finish waiting. Each
//! protective action is instead tied to a number that only grows (the count of
//! freezes, the number of the waiting item it cancels, the version of the
//! security row), so it can be included once and never again, whatever else
//! the account does. Protective actions are also accepted during a validator
//! safety hold, when ordinary actions are not: waiting periods keep running
//! through a hold. Those whose rate something else already limits (a freeze,
//! a replacement asked for by recovery keys alone, finishing one, cancelling
//! a waiting item) cost the standard fee or, if that is more than the account
//! has, what is left, so that an emptied account can still be frozen and
//! recovered. Every other root operation costs the full fee: each one makes
//! the next one valid, and an account with nothing left must not be able to
//! fill blocks for free.
//!
//! A replacement names the whole new set of keys. A sign-in key that it keeps
//! without a fresh acceptance, and that a spend key has removed since the
//! approvals were given, is left out instead of making the replacement fail:
//! whoever holds a spend key removes sign-in keys at once and must not be able
//! to void a recovery that way.
//!
//! A secured account does not use protocol 4's single-key device management or
//! its guardian recovery (kinds 8, 9, 11 to 16): the engine refuses them for
//! it, except withdrawing its consent to be someone else's guardian. One
//! recovery key signs that withdrawal, so it is refused while a recovery of
//! the other account rests on an approval this account gave earlier: one key
//! alone must not decide anything. Staking and the other spending actions
//! count against the daily limit like payments. Protocol-4 accounts are
//! unaffected until they adopt the rules with `secure`.
//!
//! Every payload has one accepted form: the fields of its kind, each list
//! sorted by key, nothing else. A request cannot be written in two ways.
//!
//! # The clock of the waits
//!
//! Everything that waits here is stored as a moment on one clock and
//! compared with that clock: when a waiting payment, a raise of the limit or
//! a replacement is ready, when a replacement lapses, until when a freeze
//! lasts, and the moment the allowance was last counted. On a network
//! without `waits_survive_stops` the clock is the chain's time since genesis
//! (the protocol-4 rule). A chain that stops for a day then comes back a day
//! later, and every wait has run out while no owner could act.
//!
//! On a network with the setting the clock is the active clock
//! (`Meta::active_micros`): the chain's time minus the total of all stops,
//! where a stop is the part of the gap between a block and its parent beyond
//! `STOP_THRESHOLD_MICROS` (five minutes). A block moves it by the time since
//! its parent, and by five minutes at most. The fields keep their names
//! (`..._elapsed_micros`) and their encoding; what they hold on such a
//! network is a moment on the active clock. The allowance refills on the
//! same clock: a stop gives whoever holds the spend key no second day's
//! worth to take before the owner can freeze.
//!
//! The dates that keys sign are not moved: the expiry of a freeze and of the
//! approvals of a root operation is compared with the chain's time on every
//! network. A signature says until when it may be used, and a stop must
//! never keep one alive past that moment.
//!
//! # An account that is protected from its first block
//!
//! Adopting the rules costs a fee, and a new account holds nothing. On a
//! network with `protected_registration`, a registration can therefore carry
//! the set of keys and the policy itself (kind 45, `REGISTER`): the reveal
//! that follows a sponsored registration creates the account with its keys
//! in their roles and its security row, in one action that pays nothing, as
//! a reveal pays nothing. The set is the one `secure` takes and is judged by
//! the same code (`first_set`). Two things differ, because the account has
//! no number yet: a key accepts its role for the registration key that will
//! create the account (`registration_key_message`), and the commitment the
//! sponsor paid for names the set (`registration_commitment`), so that the
//! name cannot be taken with any other keys or policy, not even by whoever
//! holds the registration key. The registration key is the account's
//! identity key, as after any registration; it is a key of the account only
//! if the set lists it, in one role and with its acceptance like any other.
//!
//! On the same networks a genesis can list accounts that start with a set of
//! keys and a policy (`genesis::Genesis::protected_accounts`, `genesis_set`).
use crate::engine::{ExtensionHost, Meta, account_key, canonical_decode, valid_public_key};
use crate::wire::SignedAction;
use anyhow::{Result, anyhow, bail, ensure};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use timecurrency_node::ledger::{self, Account, Device};

/// Adopt the rules: replaces the account's keys by a set with roles.
pub const SECURE: u8 = 70;
/// A spend key adds and removes sign-in keys.
pub const SIGNIN: u8 = 71;
/// A spend or recovery key stops all outgoing payments for a while.
pub const FREEZE: u8 = 72;
/// An operation approved by several keys.
pub const ROOT: u8 = 73;
/// A spend or recovery key of the new set finishes a replacement that has
/// waited.
pub const FINALIZE: u8 = 74;
/// A spend key starts or completes a payment above the daily limit.
pub const PAYMENT: u8 = 75;
/// A spend or recovery key cancels something that is waiting.
pub const CANCEL: u8 = 76;
/// A spend key changes the daily limit (a raise waits).
pub const LIMIT: u8 = 77;
/// A registration that creates its account with a set of keys with roles:
/// the reveal of a sponsored registration on a network with
/// `protected_registration`. Signed by the registration key, with the header
/// of a reveal (no account, no nonce, no authority epoch). Its payload is
/// `{name, salt, security: {keys, policy}}`, where `security` is what
/// `secure` takes. The engine creates the account
/// (`engine::Overlay::apply_protected_registration`); it is not one of the
/// kinds of an existing account (`is_kind`).
pub const REGISTER: u8 = 45;

/// The clock of the waits on a network with `waits_survive_stops`: the part
/// of the gap between a block and its parent beyond this is a stop, and the
/// active clock does not run during it (`Meta::active_micros`). Five
/// minutes, in both profiles.
///
/// It is the clock's own threshold, not the hour after which the upgrade
/// rule cancels a plan (`upgrade::Params::max_gap`). Each stop still takes
/// this much from every wait, because the chain cannot tell a stop from a
/// slow block before it has passed: with an hour, 48 stops and restarts ran
/// out a wait of two days; with five minutes it takes 576. A chain that
/// works makes a block every second or so, also with no traffic (CometBFT
/// makes empty blocks unless `create_empty_blocks` is off or its interval
/// is long), and a round that fails costs seconds: a height that takes five
/// minutes is, in practice, a chain that has lost more than a third of its
/// voting power or its network, when nobody could act either. A network
/// that makes no empty blocks, or makes them less often than every five
/// minutes, has its waits run slower than real time. The laboratory profile
/// uses the same five minutes, so that a rehearsal of a stop shows what a
/// production network does; the lowest wait it allows (30 seconds) is
/// shorter than any threshold that tells a stop from a slow block anyway.
pub const STOP_THRESHOLD_MICROS: u64 = 300 * pos::SECOND;
/// The threshold of the clock of the waits for a network of `profile`
/// (`STOP_THRESHOLD_MICROS` in both profiles).
pub fn stop_threshold(profile: pos::Profile) -> u64 {
    match profile {
        pos::Profile::Production | pos::Profile::Laboratory => STOP_THRESHOLD_MICROS,
    }
}

pub fn is_kind(kind: u8) -> bool {
    (SECURE..=LIMIT).contains(&kind)
}
/// Kinds that take the account's next nonce, like every protocol-4 action.
pub fn sequenced(kind: u8) -> bool {
    matches!(kind, SECURE | SIGNIN | PAYMENT | LIMIT)
}
/// Kinds that protect an account. They carry nonce and authority epoch zero,
/// and are accepted during a validator safety hold.
pub fn protective(kind: u8) -> bool {
    matches!(kind, FREEZE | ROOT | FINALIZE | CANCEL)
}


pub const KEY_DOMAIN: &[u8] = b"TCDEVNET-ACCOUNT-KEY-V1\0";
pub const ROOT_DOMAIN: &[u8] = b"TCDEVNET-ACCOUNT-ROOT-V1\0";
/// What a key signs to accept a role on an account that is being registered.
pub const REGISTER_KEY_DOMAIN: &[u8] = b"TCDEVNET-REGISTER-KEY-V1\0";
/// The commitment of a registration that carries a set of keys.
pub const REGISTER_NAME_DOMAIN: &[u8] = b"TCDEVNET-NAME-PROTECTED-V1\0";
pub const MAX_PENDING_PAYMENTS: usize = 4;
const DAY_MICROS: u64 = 86_400 * ledger::MICROS_PER_SECOND;
const MAX_SECONDS: u64 = 30 * 86_400;
/// How far ahead a freeze or the approvals of a root operation may be dated.
const MAX_LIFETIME_MICROS: u64 = MAX_SECONDS * ledger::MICROS_PER_SECOND;
/// How far ahead the approvals of a payment may be dated.
const MAX_PAY_LIFETIME_MICROS: u64 = 3_600 * ledger::MICROS_PER_SECOND;

mod decimal {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        let value = text.parse::<u64>().map_err(D::Error::custom)?;
        if value.to_string() != text {
            return Err(D::Error::custom("noncanonical decimal"));
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Signin,
    Spend,
    Recover,
}
impl Role {
    /// The role of a device row; none if it carries both flags, as the keys of
    /// protocol-4 accounts do.
    pub fn of(device: &Device) -> Option<Role> {
        match (device.can_manage, device.can_spend) {
            (false, false) => Some(Role::Signin),
            (false, true) => Some(Role::Spend),
            (true, false) => Some(Role::Recover),
            (true, true) => None,
        }
    }
    fn device(self, public_key: String) -> Device {
        let (can_manage, can_spend) = match self {
            Role::Signin => (false, false),
            Role::Spend => (false, true),
            Role::Recover => (true, false),
        };
        Device {
            public_key,
            can_manage,
            can_spend,
        }
    }
    fn byte(self) -> u8 {
        match self {
            Role::Signin => 0,
            Role::Spend => 1,
            Role::Recover => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Proofs a root operation needs.
    #[serde(with = "decimal")]
    pub threshold: u64,
    /// The allowance of the spend keys: what they may move without waiting.
    /// It refills evenly over 24 hours and never holds more than this.
    #[serde(with = "decimal")]
    pub daily_limit_micros: u64,
    /// How long anything waits that a spend key starts alone, or that recovery
    /// keys decide without the spend key.
    #[serde(with = "decimal")]
    pub delay_seconds: u64,
    /// How long a freeze lasts.
    #[serde(with = "decimal")]
    pub freeze_seconds: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingLimit {
    #[serde(with = "decimal")]
    pub id: u64,
    #[serde(with = "decimal")]
    pub daily_limit_micros: u64,
    #[serde(with = "decimal")]
    pub ready_elapsed_micros: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingPayment {
    #[serde(with = "decimal")]
    pub id: u64,
    #[serde(with = "decimal")]
    pub to: u64,
    #[serde(with = "decimal")]
    pub amount: u64,
    #[serde(with = "decimal")]
    pub ready_elapsed_micros: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRoot {
    pub devices: Vec<Device>,
    pub policy: Policy,
    #[serde(with = "decimal")]
    pub ready_elapsed_micros: u64,
    #[serde(with = "decimal")]
    pub expires_elapsed_micros: u64,
}
/// The security row of one account, stored under `security/<id>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Security {
    /// Counts root changes. Approvals name the version they were given for,
    /// so none can be used twice or after a root change.
    #[serde(with = "decimal")]
    pub version: u64,
    pub policy: Policy,
    /// What was left of the daily limit at `allowance_elapsed_micros`.
    #[serde(with = "decimal")]
    pub allowance_micros: u64,
    #[serde(with = "decimal")]
    pub allowance_elapsed_micros: u64,
    /// The account is frozen until this moment. A moment in the past, or
    /// zero, means it is not.
    #[serde(with = "decimal")]
    pub frozen_until_elapsed_micros: u64,
    /// How many times the account has been frozen. A freeze, and the lifting
    /// of one, name the count they expect, so neither is included twice or
    /// applied to a later freeze.
    #[serde(with = "decimal")]
    pub freezes: u64,
    pub pending_limit: Option<PendingLimit>,
    pub pending_payments: Vec<PendingPayment>,
    /// Number of the next waiting item. Never reused.
    #[serde(with = "decimal")]
    pub next_id: u64,
    pub pending_root: Option<PendingRoot>,
}

pub fn key(id: u64) -> Vec<u8> {
    [b"security/".as_slice(), &id.to_be_bytes()].concat()
}
pub fn encode(security: &Security) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(security)?)
}
/// The security row of `account`, if it has adopted the rules. An account
/// with a key that carries both flags cannot have one (`validate` and every
/// action here keep that true), so such accounts cost no lookup.
pub fn load(
    get: impl FnOnce(&[u8]) -> Result<Option<Vec<u8>>>,
    account: &Account,
) -> Result<Option<Security>> {
    if account.devices.iter().any(|d| d.can_manage && d.can_spend) {
        return Ok(None);
    }
    match get(&key(account.id))? {
        Some(bytes) => Ok(Some(canonical_decode(&bytes)?)),
        None => Ok(None),
    }
}

fn micros(seconds: u64) -> Result<u64> {
    seconds
        .checked_mul(ledger::MICROS_PER_SECOND)
        .ok_or_else(|| anyhow!("duration overflow"))
}
fn after(now: u64, micros: u64) -> Result<u64> {
    now.checked_add(micros)
        .ok_or_else(|| anyhow!("time overflow"))
}
/// `now` is the chain's time since genesis, on every network: a date that a
/// key signed is never read on the active clock.
///
/// `margin` is zero when a block is executed. When the mempool decides
/// admission it is the time an action must still have ahead of it: admission
/// runs on the clock of the last block, the block that would include the
/// action has a later one, and what is admitted must be includable.
fn dated(now: u64, margin: u64, expires_elapsed_micros: u64, lifetime: u64) -> Result<()> {
    ensure!(
        expires_elapsed_micros > after(now, margin)?
            && expires_elapsed_micros <= after(now, lifetime)?,
        "expired, expiring too soon to be included, or dated too far ahead"
    );
    Ok(())
}

impl Security {
    /// Brings the time-dependent parts up to `now`: a raise of the limit that
    /// has waited long enough takes effect, and a replacement nobody finished
    /// within its claim window is dropped.
    pub fn settle(&mut self, now: u64) {
        if let Some(raise) = self.pending_limit.clone()
            && raise.ready_elapsed_micros <= now
        {
            // Up to the moment the raise was due the allowance filled under
            // the old limit; from that moment on it fills under the new one,
            // whenever the row is next looked at.
            self.allowance_micros = self.level(raise.ready_elapsed_micros);
            self.allowance_elapsed_micros = raise.ready_elapsed_micros;
            self.policy.daily_limit_micros = raise.daily_limit_micros;
            self.pending_limit = None;
        }
        if self
            .pending_root
            .as_ref()
            .is_some_and(|pending| pending.expires_elapsed_micros < now)
        {
            self.pending_root = None;
        }
    }
    /// What spend keys may still move at `now`: the limit refills evenly over
    /// 24 hours and never holds more than one day's worth. Rounds down.
    pub fn level(&self, now: u64) -> u64 {
        let limit = self.policy.daily_limit_micros;
        let waited = now.saturating_sub(self.allowance_elapsed_micros);
        let refill = (u128::from(limit) * u128::from(waited) / u128::from(DAY_MICROS))
            .min(u128::from(limit)) as u64;
        self.allowance_micros.saturating_add(refill).min(limit)
    }
    /// Frozen by a freeze, or while a replacement of the keys waits. Call
    /// after `settle`.
    pub fn frozen(&self, now: u64) -> bool {
        now < self.frozen_until_elapsed_micros || self.pending_root.is_some()
    }
    fn charge(&mut self, outflow: u64, now: u64) -> Result<()> {
        let level = self.level(now);
        ensure!(
            outflow <= level,
            "over the daily limit of this account: use a payment that waits, or a second proof"
        );
        self.allowance_micros = level - outflow;
        self.allowance_elapsed_micros = now;
        Ok(())
    }
    fn take_id(&mut self) -> Result<u64> {
        let id = self.next_id;
        self.next_id = id
            .checked_add(1)
            .ok_or_else(|| anyhow!("waiting-item number exhausted"))?;
        Ok(id)
    }
    /// Drops everything a spend key has started and that has not happened yet.
    fn drop_waiting(&mut self) {
        self.pending_payments.clear();
        self.pending_limit = None;
    }
    /// The check an action of a spend key passes when it lowers the balance
    /// of a secured account by `outflow` (amount and fee): not frozen, and
    /// within the daily limit. An action that does not lower the balance
    /// (`outflow` zero) passes frozen or not.
    pub fn spend(&mut self, outflow: u64, now: u64) -> Result<()> {
        self.settle(now);
        if outflow == 0 {
            return Ok(());
        }
        ensure!(!self.frozen(now), "account is frozen");
        self.charge(outflow, now)
    }
}

/// Whether `account` is secured and frozen at `now`: a freeze still running,
/// or a replacement of its keys waiting. `now` is a moment on the clock of
/// the waits (`Meta::active_micros`), like every `now` the methods of
/// `Security` take. Read-only: the stored row is not changed. An account
/// that has not adopted the rules is never frozen by them (its guardian
/// recovery is the engine's to judge).
pub fn frozen_at(
    get: impl FnOnce(&[u8]) -> Result<Option<Vec<u8>>>,
    account: &Account,
    now: u64,
) -> Result<bool> {
    Ok(match load(get, account)? {
        Some(mut security) => {
            security.settle(now);
            security.frozen(now)
        }
        None => false,
    })
}

fn hex32(text: &str) -> Result<[u8; 32]> {
    ensure!(
        text.len() == 64
            && text
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "noncanonical 32-byte value"
    );
    hex::decode(text)?
        .try_into()
        .map_err(|_| anyhow!("value length"))
}
fn verify(public_key: &str, message: &[u8], signature: &str) -> Result<()> {
    ensure!(
        signature.len() == 128
            && signature
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "signature must be canonical 64-byte hex"
    );
    valid_public_key(public_key)?;
    let key = VerifyingKey::from_bytes(&hex32(public_key)?)?;
    ensure!(!key.is_weak(), "weak key");
    key.verify_strict(message, &Signature::from_slice(&hex::decode(signature)?)?)
        .map_err(|_| anyhow!("signature does not verify"))
}
/// What the holder of a key signs to accept a role on an account.
pub fn key_message(network: &str, account: u64, role: Role, public_key: &str) -> Result<Vec<u8>> {
    let mut message = KEY_DOMAIN.to_vec();
    message.extend(hex32(network)?);
    message.extend(account.to_be_bytes());
    message.push(role.byte());
    message.extend(hex32(public_key)?);
    Ok(message)
}
/// What the holder of a key signs to accept a role on the account that the
/// registration key `registration` is about to create. That account has no
/// number yet; a registration key creates one account at most, so naming it
/// names the account. The domain differs from `key_message`, so an
/// acceptance given for a registration is good for nothing else, and none
/// given for an account is good here.
pub fn registration_key_message(
    network: &str,
    registration: &str,
    role: Role,
    public_key: &str,
) -> Result<Vec<u8>> {
    let mut message = REGISTER_KEY_DOMAIN.to_vec();
    message.extend(hex32(network)?);
    message.extend(hex32(registration)?);
    message.push(role.byte());
    message.extend(hex32(public_key)?);
    Ok(message)
}
/// The commitment a sponsor pays for when the registration will carry a set
/// of keys: SHA-256 of the domain, the network, the registration key, the
/// name, a zero byte, the salt and the SHA-256 of `setup`, the `security`
/// object of the registration as JSON with sorted keys and no spaces.
///
/// It is the protocol-4 commitment (`ledger::action_commitment`) under
/// another domain and with the set of keys added. So a commitment is good
/// for one kind of registration only: the reveal of protocol 4 (kind 2)
/// never matches a commitment made this way, this one never matches a
/// protocol-4 commitment, and neither matches with another name, salt, key
/// or policy than the one committed to.
pub fn registration_commitment(
    network: &str,
    registration: &str,
    name: &str,
    salt: &str,
    setup: &Value,
) -> Result<String> {
    ensure!(setup.is_object(), "the security setup must be an object");
    let mut hash = Sha256::new();
    hash.update(REGISTER_NAME_DOMAIN);
    hash.update(hex32(network)?);
    hash.update(hex32(registration)?);
    // A name holds no zero byte, so the zero byte that follows it ends it.
    // (The engine has checked the name as an account name before.)
    ensure!(!name.as_bytes().contains(&0), "invalid name");
    hash.update(name.as_bytes());
    hash.update([0]);
    hash.update(hex32(salt)?);
    hash.update(Sha256::digest(serde_json::to_vec(setup)?));
    Ok(hex::encode(hash.finalize()))
}
/// What a key signs to approve a root operation. `operation` is the `op`
/// object of the action exactly as submitted; `approvers` are the public
/// keys of everyone approving, in the order of the action (sorted).
pub fn root_message(
    network: &str,
    account: u64,
    version: u64,
    expires_elapsed_micros: u64,
    operation: &Value,
    approvers: &[&str],
) -> Result<Vec<u8>> {
    ensure!(operation.is_object(), "operation must be an object");
    let mut message = ROOT_DOMAIN.to_vec();
    message.extend(hex32(network)?);
    message.extend(account.to_be_bytes());
    message.extend(version.to_be_bytes());
    message.extend(expires_elapsed_micros.to_be_bytes());
    message.extend(Sha256::digest(serde_json::to_vec(operation)?));
    let mut keys = Sha256::new();
    for approver in approvers {
        keys.update(hex32(approver)?);
    }
    message.extend(keys.finalize());
    Ok(message)
}

/// Reads a payload as `T` and requires that `T` writes back exactly what was
/// sent: no second spelling of a field, no null where a field may be left
/// out, no list where an object belongs.
fn strict<T: DeserializeOwned + Serialize>(value: &Value) -> Result<T> {
    let typed: T = serde_json::from_value(value.clone())?;
    ensure!(
        serde_json::to_value(&typed)? == *value,
        "payload is not in its one accepted form"
    );
    Ok(typed)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyInput {
    public_key: String,
    role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    public_key: String,
    signature: String,
}

/// The rules a set of keys and its policy must satisfy. `minimum` is the
/// network's least waiting period, in microseconds
/// (`recovery_min_delay_micros` of its genesis).
fn check(minimum: u64, devices: &[Device], policy: &Policy) -> Result<()> {
    ensure!(
        !devices.is_empty()
            && devices.len() <= ledger::MAX_DEVICES
            && devices.windows(2).all(|w| w[0].public_key < w[1].public_key),
        "keys must be distinct, sorted and at most eight"
    );
    let mut spend = 0u64;
    let mut recover = 0u64;
    for device in devices {
        valid_public_key(&device.public_key)?;
        match Role::of(device) {
            Some(Role::Spend) => spend += 1,
            Some(Role::Recover) => recover += 1,
            Some(Role::Signin) => {}
            None => bail!("a key of a secured account has exactly one role"),
        }
    }
    ensure!(spend >= 1, "at least one spend key is required");
    ensure!(
        policy.threshold >= 2 && policy.threshold <= recover,
        "the threshold is at least two and at most the number of recovery keys"
    );
    for seconds in [policy.delay_seconds, policy.freeze_seconds] {
        ensure!(
            seconds <= MAX_SECONDS && micros(seconds)? >= minimum,
            "waiting periods must be at least the network minimum and at most 30 days"
        );
    }
    Ok(())
}
/// A requested set of keys, checked for everything except the signatures.
struct Shaped<'a> {
    devices: Vec<Device>,
    /// Acceptances still to verify: key, role, signature.
    acceptances: Vec<(&'a str, Role, &'a str)>,
}
/// Turns requested keys into device rows. A key that is not already on the
/// account in the same role must carry its holder's acceptance. Signatures
/// are not verified here: `accepted` does that once every cheap check of the
/// action has passed.
///
/// `replacing`: the keys are those of a replacement. A sign-in key that is
/// kept without a fresh acceptance and is no longer on the account at all is
/// then left out. A spend key removes sign-in keys at once; if that made the
/// replacement fail, whoever holds a spend key could void a recovery by
/// removing a sign-in key it keeps.
fn shape<'a>(
    minimum: u64,
    current: &[Device],
    keys: &'a [KeyInput],
    policy: &Policy,
    replacing: bool,
) -> Result<Shaped<'a>> {
    ensure!(keys.len() <= ledger::MAX_DEVICES, "too many keys");
    // The list as submitted is checked, not only the keys that are kept: an
    // entry that is left out below must not be a way to carry anything else.
    ensure!(
        keys.windows(2).all(|w| w[0].public_key < w[1].public_key),
        "keys must be distinct, sorted and at most eight"
    );
    let mut devices = Vec::with_capacity(keys.len());
    let mut acceptances = Vec::new();
    for key in keys {
        valid_public_key(&key.public_key)?;
        let device = key.role.device(key.public_key.clone());
        match &key.proof {
            Some(proof) => acceptances.push((key.public_key.as_str(), key.role, proof.as_str())),
            None if current.contains(&device) => {}
            None => {
                ensure!(
                    replacing
                        && key.role == Role::Signin
                        && !current.iter().any(|d| d.public_key == key.public_key),
                    "a new key, or a key in a new role, must carry its holder's acceptance"
                );
                continue;
            }
        }
        devices.push(device);
    }
    check(minimum, &devices, policy)?;
    Ok(Shaped {
        devices,
        acceptances,
    })
}
/// Verifies acceptances. `message` gives what the holder of a key signs for
/// a role: `key_message` for an account, `registration_key_message` for an
/// account that is being registered.
fn accepted_as(
    acceptances: &[(&str, Role, &str)],
    message: impl Fn(Role, &str) -> Result<Vec<u8>>,
) -> Result<()> {
    for (public_key, role, proof) in acceptances {
        verify(public_key, &message(*role, public_key)?, proof)?;
    }
    Ok(())
}
fn accepted(meta: &Meta, account: u64, acceptances: &[(&str, Role, &str)]) -> Result<()> {
    accepted_as(acceptances, |role, public_key| {
        key_message(&meta.network_id, account, role, public_key)
    })
}
/// The security row of an account whose first set of keys comes into force
/// at `now`, a moment on the clock of the waits: nothing waits, nothing is
/// frozen, and the allowance is full.
fn first_row(policy: Policy, now: u64) -> Security {
    Security {
        version: 1,
        allowance_micros: policy.daily_limit_micros,
        allowance_elapsed_micros: now,
        policy,
        frozen_until_elapsed_micros: 0,
        freezes: 0,
        pending_limit: None,
        pending_payments: Vec::new(),
        next_id: 1,
        pending_root: None,
    }
}

/// The first set of keys of an account that a registration creates
/// (`REGISTER`): its keys in their roles, its security row, and the
/// acceptances that `accepted` still has to verify.
pub struct FirstSet {
    pub devices: Vec<Device>,
    pub security: Security,
    acceptances: Vec<(String, Role, String)>,
}
impl FirstSet {
    /// Verifies that every key of the set accepted its role for the account
    /// that the registration key `registration` creates. Signatures are
    /// verified here, after every check of the registration that costs
    /// little.
    pub fn accepted(&self, network: &str, registration: &str) -> Result<()> {
        let acceptances: Vec<(&str, Role, &str)> = self
            .acceptances
            .iter()
            .map(|(public_key, role, proof)| (public_key.as_str(), *role, proof.as_str()))
            .collect();
        accepted_as(&acceptances, |role, public_key| {
            registration_key_message(network, registration, role, public_key)
        })
    }
}
/// The payload of a registration that carries a set of keys.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterInput {
    name: String,
    salt: String,
    security: Value,
}
/// Reads the payload of a `REGISTER` action in its one accepted form: the
/// name, the salt, and the `security` object exactly as submitted, which is
/// what the commitment names (`registration_commitment`).
pub fn registration_payload(payload: &Value) -> Result<(String, String, Value)> {
    let input: RegisterInput = strict(payload)?;
    Ok((input.name, input.salt, input.security))
}
/// Judges the set of keys a registration carries, as `secure` judges the
/// set an account adopts: the same payload (`SecureInput`), the same rules
/// for the keys and the policy (`shape`, with no key on the account yet, so
/// every key carries its acceptance), the same first row. `now` is the
/// clock of the waits. The acceptances are verified by `FirstSet::accepted`.
pub fn first_set(meta: &Meta, setup: &Value, now: u64) -> Result<FirstSet> {
    let input: SecureInput = strict(setup)?;
    let shaped = shape(
        meta.config.recovery_min_delay_micros,
        &[],
        &input.keys,
        &input.policy,
        false,
    )?;
    let acceptances = shaped
        .acceptances
        .iter()
        .map(|(public_key, role, proof)| (public_key.to_string(), *role, proof.to_string()))
        .collect();
    Ok(FirstSet {
        devices: shaped.devices,
        security: first_row(input.policy, now),
        acceptances,
    })
}
/// The keys and the security row of a genesis account that starts protected
/// (`genesis::Genesis::protected_accounts`): `keys` in their roles, sorted
/// by key, under `policy`, judged by the rules every set of keys satisfies
/// (`check`). A genesis carries no acceptances: it is a document its
/// network's operators agree on as a whole, like the identity key of each
/// of its accounts.
pub fn genesis_set<'a>(
    minimum: u64,
    keys: impl IntoIterator<Item = (&'a str, Role)>,
    policy: &Policy,
) -> Result<(Vec<Device>, Security)> {
    let devices: Vec<Device> = keys
        .into_iter()
        .map(|(public_key, role)| role.device(public_key.to_string()))
        .collect();
    check(minimum, &devices, policy)?;
    Ok((devices, first_row(policy.clone(), 0)))
}

/// Sign-in keys prove the account's identity off chain and sign nothing the
/// chain accepts: what is open to any one key is open to spend and recovery
/// keys.
fn guards(role: Option<Role>) -> Result<()> {
    ensure!(
        matches!(role, Some(Role::Spend | Role::Recover)),
        "a spend or recovery key of this account is required"
    );
    Ok(())
}

struct Votes {
    count: u64,
    spend: bool,
}
/// Counts the proofs behind a root operation from who claims to approve it.
/// The signatures are verified by `approved`, after the cheap checks.
fn votes(account: &Account, approvals: &[Approval]) -> Result<Votes> {
    ensure!(
        !approvals.is_empty()
            && approvals.len() <= ledger::MAX_DEVICES
            && approvals.windows(2).all(|w| w[0].public_key < w[1].public_key),
        "approvals must name each key once, sorted by key"
    );
    let mut recover = 0u64;
    let mut spend = false;
    for approval in approvals {
        let device = account
            .devices
            .iter()
            .find(|d| d.public_key == approval.public_key)
            .ok_or_else(|| anyhow!("approval from a key that is not on the account"))?;
        match Role::of(device) {
            Some(Role::Recover) => recover += 1,
            Some(Role::Spend) => spend = true,
            _ => bail!("only spend and recovery keys approve root operations"),
        }
    }
    Ok(Votes {
        count: recover + u64::from(spend),
        spend,
    })
}
fn approved(
    meta: &Meta,
    account: u64,
    version: u64,
    expires_elapsed_micros: u64,
    operation: &Value,
    approvals: &[Approval],
) -> Result<()> {
    let approvers: Vec<&str> = approvals.iter().map(|a| a.public_key.as_str()).collect();
    let message = root_message(
        &meta.network_id,
        account,
        version,
        expires_elapsed_micros,
        operation,
        &approvers,
    )?;
    for approval in approvals {
        verify(&approval.public_key, &message, &approval.signature)?;
    }
    Ok(())
}

/// Charges the fee and, for an action that takes a nonce, records it.
///
/// `reduced`: the action costs the standard fee or, if the account has less,
/// what is left. Only actions whose rate something else already limits are
/// charged this way, so that an emptied account can still be frozen and
/// recovered: a freeze (one per half freeze period), a replacement asked for
/// by recovery keys alone (one at a time; calling one off costs the full
/// fee), finishing one, and cancelling a waiting item (each was paid for in
/// full when it was started). Everything else costs the full fee. A root
/// operation moves the version on and so makes the next one valid at once:
/// charged less, an account with nothing left could fill every block for
/// free.
fn settle_fee(
    host: &mut impl ExtensionHost,
    action: &SignedAction,
    reduced: bool,
) -> Result<Account> {
    // The fee is a setting of the network (`Genesis::fee`).
    let fee = host.meta().config.fee();
    let fee = if reduced {
        fee.min(host.account(action.from)?.balance)
    } else {
        fee
    };
    host.debit(action.from, fee)?;
    host.fee_credit(fee)?;
    let mut row = host.account(action.from)?;
    if sequenced(action.kind) {
        row.nonce = action.nonce;
    }
    Ok(row)
}
fn bump(row: &mut Account) -> Result<()> {
    row.auth_epoch = row
        .auth_epoch
        .checked_add(1)
        .ok_or_else(|| anyhow!("authority epoch exhausted"))?;
    Ok(())
}
/// Writes the account row and its security row, after checking that the two
/// are what the recount will accept.
fn store(host: &mut impl ExtensionHost, row: Account, security: &Security) -> Result<()> {
    validate(host.meta(), &row, security)?;
    let id = row.id;
    host.set_account(row)?;
    host.put(key(id), Some(encode(security)?))
}
fn next_version(security: &mut Security) -> Result<()> {
    security.version = security
        .version
        .checked_add(1)
        .ok_or_else(|| anyhow!("security version exhausted"))?;
    Ok(())
}
/// Puts a new set of keys and a new policy in force. Whoever held the old
/// keys may have started things: every wait and freeze ends here.
fn install(
    host: &mut impl ExtensionHost,
    action: &SignedAction,
    mut security: Security,
    devices: Vec<Device>,
    policy: Policy,
    now: u64,
    reduced: bool,
) -> Result<()> {
    security.allowance_micros = security.level(now).min(policy.daily_limit_micros);
    security.allowance_elapsed_micros = now;
    security.policy = policy;
    security.frozen_until_elapsed_micros = 0;
    security.drop_waiting();
    security.pending_root = None;
    next_version(&mut security)?;
    let mut row = settle_fee(host, action, reduced)?;
    row.devices = devices;
    // The keys changed, so the authority epoch moves on, and the nonce with
    // it: nothing the old keys signed can be included any more.
    row.nonce = row
        .nonce
        .checked_add(1)
        .ok_or_else(|| anyhow!("nonce exhausted"))?;
    bump(&mut row)?;
    store(host, row, &security)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecureInput {
    keys: Vec<KeyInput>,
    policy: Policy,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigninAdd {
    public_key: String,
    proof: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigninInput {
    add: Vec<SigninAdd>,
    remove: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FreezeInput {
    #[serde(with = "decimal")]
    freezes: u64,
    #[serde(with = "decimal")]
    version: u64,
    #[serde(with = "decimal")]
    expires_elapsed_micros: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootInput {
    op: Value,
    #[serde(with = "decimal")]
    expires_elapsed_micros: u64,
    approvals: Vec<Approval>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum Operation {
    Replace {
        keys: Vec<KeyInput>,
        policy: Policy,
    },
    Cancel {},
    Unfreeze {
        #[serde(with = "decimal")]
        freezes: u64,
    },
    Pay {
        #[serde(with = "decimal")]
        to: u64,
        #[serde(with = "decimal")]
        amount: u64,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizeInput {
    #[serde(with = "decimal")]
    version: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum PaymentInput {
    Request {
        #[serde(with = "decimal")]
        to: u64,
        #[serde(with = "decimal")]
        amount: u64,
    },
    Execute {
        #[serde(with = "decimal")]
        id: u64,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum CancelInput {
    Payment {
        #[serde(with = "decimal")]
        id: u64,
    },
    Limit {
        #[serde(with = "decimal")]
        id: u64,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitInput {
    #[serde(with = "decimal")]
    daily_limit_micros: u64,
}

/// Applies one action of kinds 70 to 77. The engine has checked the envelope:
/// network, signature and, for the kinds that take one, the account's nonce
/// and authority epoch. Who may sign is decided here, because it depends on
/// the kind. `hold` says that a validator safety hold is in force: the engine
/// then lets only protective kinds through, and no payment is made here.
///
/// In every branch the checks that cost little come first and signatures
/// inside the payload are verified last, so that an action that cannot
/// succeed is refused cheaply.
pub fn apply(host: &mut impl ExtensionHost, action: &SignedAction, hold: bool) -> Result<()> {
    // Two clocks (see "The clock of the waits" above). `now` is the clock
    // everything that waits is stored on and compared with: the active
    // clock on a network with `waits_survive_stops`, the chain's time on
    // any other. `chain_time` is the chain's time on every network: the
    // dates that keys sign are compared with it, and with nothing else.
    let now = host.meta().active_micros()?;
    let chain_time = host.meta().elapsed_micros()?;
    let minimum = host.meta().config.recovery_min_delay_micros;
    let margin = host.expiry_margin();
    // What an action costs on this network.
    let fee = host.meta().config.fee();
    let account = host.account(action.from)?;
    let role = account
        .devices
        .iter()
        .find(|d| d.public_key == action.public_key)
        .map(Role::of);
    let stored = match host.get(&key(account.id))? {
        Some(bytes) => Some(canonical_decode::<Security>(&bytes)?),
        None => None,
    };
    if action.kind == SECURE {
        ensure!(stored.is_none(), "account is already secured");
        ensure!(
            role == Some(None),
            "only a key with full authority can adopt the security rules"
        );
        ensure!(
            account.recovery_policy.is_none(),
            "turn guardian recovery off before adopting the security rules"
        );
        let input: SecureInput = strict(&action.payload)?;
        // Every key of the first set proves that its holder accepts the role.
        let shaped = shape(minimum, &[], &input.keys, &input.policy, false)?;
        ensure!(account.balance >= fee, "insufficient funds for fee");
        accepted(host.meta(), account.id, &shaped.acceptances)?;
        let security = first_row(input.policy, now);
        let mut row = settle_fee(host, action, false)?;
        row.devices = shaped.devices;
        bump(&mut row)?;
        return store(host, row, &security);
    }
    let mut security =
        stored.ok_or_else(|| anyhow!("account has not adopted the security rules"))?;
    security.settle(now);
    // `Some(None)` cannot occur: a secured account has no key with both flags.
    let role = role.flatten();
    match action.kind {
        SIGNIN => {
            ensure!(role == Some(Role::Spend), "a spend key is required");
            let input: SigninInput = strict(&action.payload)?;
            ensure!(
                input.add.len() + input.remove.len() >= 1
                    && input.add.len() <= ledger::MAX_DEVICES
                    && input.remove.len() <= ledger::MAX_DEVICES
                    && input.add.windows(2).all(|w| w[0].public_key < w[1].public_key)
                    && input.remove.windows(2).all(|w| w[0] < w[1]),
                "name between one and eight sign-in keys, each once, sorted by key"
            );
            ensure!(!security.frozen(now), "account is frozen");
            security.charge(fee, now)?;
            let mut devices = account.devices.clone();
            // A sign-in key holds no power on chain, so nothing is lost when
            // one goes: removing is immediate, like adding. This is how a
            // stolen login is answered with the spend key alone.
            for public_key in &input.remove {
                let before = devices.len();
                devices.retain(|d| {
                    !(d.public_key == *public_key && Role::of(d) == Some(Role::Signin))
                });
                ensure!(
                    devices.len() < before,
                    "no such sign-in key on the account"
                );
            }
            let mut acceptances = Vec::new();
            for add in &input.add {
                valid_public_key(&add.public_key)?;
                ensure!(
                    !devices.iter().any(|d| d.public_key == add.public_key),
                    "key is already on the account"
                );
                acceptances.push((add.public_key.as_str(), Role::Signin, add.proof.as_str()));
                devices.push(Role::Signin.device(add.public_key.clone()));
            }
            devices.sort_by(|a, b| a.public_key.cmp(&b.public_key));
            check(minimum, &devices, &security.policy)?;
            accepted(host.meta(), account.id, &acceptances)?;
            // The keys changed, so the authority epoch moves on: every
            // session a website keeps for the account ends.
            let mut row = settle_fee(host, action, false)?;
            row.devices = devices;
            bump(&mut row)?;
            store(host, row, &security)
        }
        FREEZE => {
            guards(role)?;
            let input: FreezeInput = strict(&action.payload)?;
            dated(chain_time, margin, input.expires_elapsed_micros, MAX_LIFETIME_MICROS)?;
            // The action names the count of freezes it expects, so it is
            // included once.
            ensure!(
                input.freezes == security.freezes,
                "the account has been frozen since: read its state again"
            );
            // And the settings it was signed under, so that a freeze signed
            // earlier cannot land on keys that were replaced since.
            ensure!(
                input.version == security.version,
                "the security settings have changed: read them again"
            );
            let length = micros(security.policy.freeze_seconds)?;
            // A fresh freeze cannot be renewed at once: each one costs a fee,
            // and a stolen key must not be able to spend the balance on them.
            ensure!(
                security.frozen_until_elapsed_micros.saturating_sub(now) <= length / 2,
                "account is already frozen"
            );
            security.freezes = security
                .freezes
                .checked_add(1)
                .ok_or_else(|| anyhow!("freeze count exhausted"))?;
            security.frozen_until_elapsed_micros = after(now, length)?;
            security.drop_waiting();
            let row = settle_fee(host, action, true)?;
            store(host, row, &security)
        }
        ROOT => {
            guards(role)?;
            let input: RootInput = strict(&action.payload)?;
            dated(chain_time, margin, input.expires_elapsed_micros, MAX_LIFETIME_MICROS)?;
            let votes = votes(&account, &input.approvals)?;
            ensure!(
                votes.count >= security.policy.threshold,
                "not enough proofs for a root operation"
            );
            let version = security.version;
            let prove = |meta: &Meta| {
                approved(
                    meta,
                    account.id,
                    version,
                    input.expires_elapsed_micros,
                    &input.op,
                    &input.approvals,
                )
            };
            // Only a replacement asked for by recovery keys alone is charged
            // what the account can pay (see `settle_fee`). Every other root
            // operation costs the full fee, which is checked before any
            // signature in the payload.
            let operation = strict::<Operation>(&input.op)?;
            let reduced = !votes.spend && matches!(operation, Operation::Replace { .. });
            ensure!(
                reduced || account.balance >= fee,
                "insufficient funds for fee"
            );
            match operation {
                Operation::Replace { keys, policy } => {
                    let shaped = shape(minimum, &account.devices, &keys, &policy, true)?;
                    if !votes.spend {
                        ensure!(
                            security.pending_root.is_none(),
                            "a replacement is already waiting: cancel it first"
                        );
                    }
                    prove(host.meta())?;
                    accepted(host.meta(), account.id, &shaped.acceptances)?;
                    if votes.spend {
                        return install(host, action, security, shaped.devices, policy, now, false);
                    }
                    // Nobody who holds the spend key takes part: the account
                    // freezes now, what the spend keys had started is
                    // dropped, and the new keys take over after the wait.
                    let ready = after(now, micros(security.policy.delay_seconds)?)?;
                    security.pending_root = Some(PendingRoot {
                        devices: shaped.devices,
                        policy,
                        ready_elapsed_micros: ready,
                        expires_elapsed_micros: after(
                            ready,
                            host.meta().config.recovery_approval_window_micros,
                        )?,
                    });
                    security.drop_waiting();
                }
                Operation::Cancel {} => {
                    ensure!(security.pending_root.is_some(), "no replacement is waiting");
                    prove(host.meta())?;
                    security.pending_root = None;
                }
                Operation::Unfreeze { freezes } => {
                    ensure!(votes.spend, "a spend key must take part");
                    // Named by its count, so that approvals given to lift one
                    // freeze cannot lift a later one.
                    ensure!(
                        freezes == security.freezes
                            && security.frozen_until_elapsed_micros > now,
                        "account is not frozen, or has been frozen again since"
                    );
                    prove(host.meta())?;
                    security.frozen_until_elapsed_micros = 0;
                }
                Operation::Pay { to, amount } => {
                    ensure!(votes.spend, "a spend key must take part");
                    ensure!(!hold, "no payments during a validator safety hold");
                    dated(chain_time, margin, input.expires_elapsed_micros, MAX_PAY_LIFETIME_MICROS)?;
                    ensure!(
                        security.pending_root.is_none(),
                        "a replacement of the keys is waiting"
                    );
                    ensure!(
                        to != account.id && amount > 0,
                        "invalid payment amount or recipient"
                    );
                    ensure!(
                        amount
                            .checked_add(fee)
                            .is_some_and(|cost| account.balance >= cost),
                        "insufficient liquid funds"
                    );
                    host.account(to)?;
                    prove(host.meta())?;
                    host.debit(account.id, amount)?;
                    host.credit(to, amount)?;
                }
            }
            next_version(&mut security)?;
            let row = settle_fee(host, action, reduced)?;
            store(host, row, &security)
        }
        FINALIZE => {
            let input: FinalizeInput = strict(&action.payload)?;
            ensure!(
                input.version == security.version,
                "the security settings have changed: read them again"
            );
            // `settle` has dropped a replacement whose claim window passed.
            let pending = security
                .pending_root
                .clone()
                .ok_or_else(|| anyhow!("no replacement is waiting"))?;
            ensure!(
                now >= pending.ready_elapsed_micros,
                "the waiting period is not over"
            );
            // A spend or recovery key of the new set may finish: all of them
            // were named by the proofs that asked for the replacement.
            ensure!(
                pending.devices.iter().any(|d| {
                    d.public_key == action.public_key && Role::of(d) != Some(Role::Signin)
                }),
                "only a spend or recovery key of the new set finishes the replacement"
            );
            install(host, action, security, pending.devices, pending.policy, now, true)
        }
        PAYMENT => {
            ensure!(role == Some(Role::Spend), "a spend key is required");
            ensure!(!security.frozen(now), "account is frozen");
            // The fee of either step comes out of the daily limit, like
            // every cost a spend key causes with a nonce.
            security.charge(fee, now)?;
            match strict::<PaymentInput>(&action.payload)? {
                PaymentInput::Request { to, amount } => {
                    ensure!(
                        to != account.id && amount > 0,
                        "invalid payment amount or recipient"
                    );
                    host.account(to)?;
                    ensure!(
                        security.pending_payments.len() < MAX_PENDING_PAYMENTS,
                        "too many payments are waiting"
                    );
                    let id = security.take_id()?;
                    security.pending_payments.push(PendingPayment {
                        id,
                        to,
                        amount,
                        ready_elapsed_micros: after(now, micros(security.policy.delay_seconds)?)?,
                    });
                }
                PaymentInput::Execute { id } => {
                    let index = security
                        .pending_payments
                        .iter()
                        .position(|p| p.id == id)
                        .ok_or_else(|| anyhow!("no such waiting payment"))?;
                    let payment = security.pending_payments.remove(index);
                    ensure!(
                        now >= payment.ready_elapsed_micros,
                        "the waiting period is not over"
                    );
                    // The amount is outside the daily limit: it waited in the
                    // open, and any spend or recovery key could have cancelled.
                    host.debit(account.id, payment.amount)?;
                    host.credit(payment.to, payment.amount)?;
                }
            }
            let row = settle_fee(host, action, false)?;
            store(host, row, &security)
        }
        CANCEL => {
            guards(role)?;
            match strict::<CancelInput>(&action.payload)? {
                CancelInput::Payment { id } => {
                    let index = security
                        .pending_payments
                        .iter()
                        .position(|p| p.id == id)
                        .ok_or_else(|| anyhow!("no such waiting payment"))?;
                    security.pending_payments.remove(index);
                }
                CancelInput::Limit { id } => ensure!(
                    security
                        .pending_limit
                        .take()
                        .is_some_and(|raise| raise.id == id),
                    "no such raise of the limit is waiting"
                ),
            }
            let row = settle_fee(host, action, true)?;
            store(host, row, &security)
        }
        LIMIT => {
            ensure!(role == Some(Role::Spend), "a spend key is required");
            let input: LimitInput = strict(&action.payload)?;
            ensure!(
                input.daily_limit_micros != security.policy.daily_limit_micros,
                "the limit already has this value"
            );
            ensure!(!security.frozen(now), "account is frozen");
            security.charge(fee, now)?;
            if input.daily_limit_micros < security.policy.daily_limit_micros {
                // Lowering protects: at once.
                security.policy.daily_limit_micros = input.daily_limit_micros;
                security.allowance_micros = security.allowance_micros.min(input.daily_limit_micros);
                security.pending_limit = None;
            } else {
                // A new request replaces one that is waiting and starts the
                // wait again.
                security.pending_limit = Some(PendingLimit {
                    id: security.take_id()?,
                    daily_limit_micros: input.daily_limit_micros,
                    ready_elapsed_micros: after(now, micros(security.policy.delay_seconds)?)?,
                });
            }
            let row = settle_fee(host, action, false)?;
            store(host, row, &security)
        }
        _ => bail!("unsupported action"),
    }
}

/// What a stored security row must satisfy together with its account row.
pub fn validate(meta: &Meta, account: &Account, security: &Security) -> Result<()> {
    let minimum = meta.config.recovery_min_delay_micros;
    check(minimum, &account.devices, &security.policy)?;
    ensure!(
        account.recovery_policy.is_none(),
        "secured account has a guardian policy"
    );
    ensure!(
        security.version >= 1
            && security.next_id >= 1
            && security.allowance_micros <= security.policy.daily_limit_micros
            && security.pending_payments.len() <= MAX_PENDING_PAYMENTS
            && security
                .pending_payments
                .windows(2)
                .all(|w| w[0].id < w[1].id)
            && security.pending_payments.iter().all(|p| {
                p.id >= 1 && p.id < security.next_id && p.amount > 0 && p.to != account.id
            }),
        "invalid security row"
    );
    if let Some(raise) = &security.pending_limit {
        ensure!(
            raise.daily_limit_micros > security.policy.daily_limit_micros
                && raise.id >= 1
                && raise.id < security.next_id,
            "waiting limit is not a raise or has no valid number"
        );
    }
    if let Some(pending) = &security.pending_root {
        check(minimum, &pending.devices, &pending.policy)?;
        ensure!(
            pending.ready_elapsed_micros <= pending.expires_elapsed_micros
                && security.pending_payments.is_empty()
                && security.pending_limit.is_none(),
            "invalid waiting replacement"
        );
    }
    Ok(())
}
/// Recounts the security rows; returns how many leaves they occupy.
pub fn audit(snapshot: &crate::store::VerifiedAudit<'_>, meta: &Meta) -> Result<u64> {
    let mut rows = 0u64;
    snapshot.for_each_prefix(b"security/", |key, value| {
        ensure!(key.len() == 17, "invalid security row key");
        let id = u64::from_be_bytes(key[9..].try_into()?);
        let account: Account = canonical_decode(
            &snapshot
                .get(&account_key(id))?
                .ok_or_else(|| anyhow!("orphan security row"))?,
        )?;
        let security: Security = canonical_decode(value)?;
        validate(meta, &account, &security)?;
        rows += 1;
        Ok(())
    })?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(limit: u64) -> Security {
        Security {
            version: 1,
            policy: Policy {
                threshold: 2,
                daily_limit_micros: limit,
                delay_seconds: 60,
                freeze_seconds: 120,
            },
            allowance_micros: limit,
            allowance_elapsed_micros: 0,
            frozen_until_elapsed_micros: 0,
            freezes: 0,
            pending_limit: None,
            pending_payments: Vec::new(),
            next_id: 1,
            pending_root: None,
        }
    }

    #[test]
    fn the_daily_limit_refills_evenly_and_never_exceeds_one_day() {
        let mut security = row(86_400);
        security.spend(86_400, 0).unwrap();
        assert_eq!(security.level(0), 0);
        assert!(security.spend(1, 0).is_err(), "nothing is left");
        // One microsecond of allowance per second of time at this limit.
        assert_eq!(security.level(ledger::MICROS_PER_SECOND), 1);
        assert_eq!(security.level(DAY_MICROS / 2), 43_200);
        assert_eq!(security.level(DAY_MICROS), 86_400);
        assert_eq!(security.level(10 * DAY_MICROS), 86_400, "one day at most");
        security.spend(43_200, DAY_MICROS / 2).unwrap();
        assert_eq!(security.level(DAY_MICROS / 2), 0);
        assert_eq!(security.level(DAY_MICROS), 43_200);
    }

    #[test]
    fn at_most_twice_the_limit_leaves_in_any_24_hours() {
        // The worst case: a full allowance spent at once, then everything
        // that refills spent the moment it appears.
        let limit = 1_000_000;
        let mut security = row(limit);
        let mut total = 0u64;
        let mut now = 0;
        while now <= DAY_MICROS {
            let level = security.level(now);
            security.spend(level, now).unwrap();
            total += level;
            now += DAY_MICROS / 10_000;
        }
        assert!(total <= 2 * limit, "moved {total} with a limit of {limit}");
        assert!(total > 2 * limit - limit / 100, "the bound is tight");
    }

    #[test]
    fn rounding_never_gives_more_than_was_earned() {
        let mut security = row(3);
        security.spend(3, 0).unwrap();
        // A third of a day earns one unit, not before.
        assert_eq!(security.level(DAY_MICROS / 3 - 1), 0);
        assert_eq!(security.level(DAY_MICROS / 3), 1);
        // Spending in many small steps cannot earn more than spending once.
        let mut total = 0;
        let mut now = 0;
        for _ in 0..1000 {
            now += DAY_MICROS / 1000;
            let level = security.level(now);
            security.spend(level, now).unwrap();
            total += level;
        }
        assert!(total <= 3, "earned {total} of a limit of 3 in one day");
    }

    #[test]
    fn a_zero_limit_allows_nothing_and_a_huge_limit_does_not_overflow() {
        let mut none = row(0);
        assert!(none.spend(1, DAY_MICROS).is_err());
        none.spend(0, DAY_MICROS).unwrap();
        let mut all = row(u64::MAX);
        all.spend(u64::MAX, 0).unwrap();
        assert_eq!(all.level(u64::MAX), u64::MAX);
        assert_eq!(all.level(DAY_MICROS / 2), u64::MAX / 2);
    }

    #[test]
    fn a_freeze_and_a_waiting_replacement_stop_what_lowers_the_balance() {
        let mut security = row(1000);
        security.frozen_until_elapsed_micros = 500;
        assert!(security.spend(1, 499).is_err());
        // An action that takes nothing out passes, frozen or not.
        security.spend(0, 499).unwrap();
        security.spend(1, 500).unwrap();
        security.pending_root = Some(PendingRoot {
            devices: Vec::new(),
            policy: security.policy.clone(),
            ready_elapsed_micros: 600,
            expires_elapsed_micros: 700,
        });
        assert!(security.spend(1, 650).is_err(), "frozen while it waits");
        security.spend(0, 650).unwrap();
        assert!(security.spend(1, 700).is_err(), "still inside the claim window");
        security.spend(1, 701).unwrap();
        assert!(security.pending_root.is_none(), "dropped after its window");
    }

    #[test]
    fn a_raise_of_the_limit_takes_effect_only_after_its_wait() {
        let mut security = row(100);
        security.spend(100, 0).unwrap();
        security.pending_limit = Some(PendingLimit {
            id: 1,
            daily_limit_micros: 1_000_000,
            ready_elapsed_micros: DAY_MICROS,
        });
        security.settle(DAY_MICROS - 1);
        assert_eq!(security.policy.daily_limit_micros, 100);
        assert_eq!(security.level(DAY_MICROS - 1), 99);
        // Looked at only much later: the result is the same as if it had been
        // looked at when the raise was due.
        let mut late = security.clone();
        security.settle(DAY_MICROS);
        assert_eq!(security.policy.daily_limit_micros, 1_000_000);
        // What was earned under the old limit is kept, no more.
        assert_eq!(security.level(DAY_MICROS), 100);
        assert!(security.pending_limit.is_none());
        late.settle(DAY_MICROS + DAY_MICROS / 2);
        assert_eq!(late, security);
        assert_eq!(late.level(DAY_MICROS + DAY_MICROS / 2), 500_100);
    }

    #[test]
    fn roles_follow_the_two_flags() {
        for (role, manage, spend) in [
            (Role::Signin, false, false),
            (Role::Spend, false, true),
            (Role::Recover, true, false),
        ] {
            let device = role.device("00".repeat(32));
            assert_eq!((device.can_manage, device.can_spend), (manage, spend));
            assert_eq!(Role::of(&device), Some(role));
        }
        let both = Device {
            public_key: "00".repeat(32),
            can_manage: true,
            can_spend: true,
        };
        assert_eq!(Role::of(&both), None);
    }

    #[test]
    fn a_payload_has_one_accepted_form() {
        use serde_json::json;
        let good = json!({"threshold": "2", "daily_limit_micros": "5", "delay_seconds": "60", "freeze_seconds": "120"});
        strict::<Policy>(&good).unwrap();
        // The same four values as a list, a number in place of a string, an
        // extra field, a role spelled as an object, a null proof.
        assert!(strict::<Policy>(&json!(["2", "5", "60", "120"])).is_err());
        assert!(strict::<Policy>(&json!({"threshold": 2, "daily_limit_micros": "5", "delay_seconds": "60", "freeze_seconds": "120"})).is_err());
        assert!(strict::<Policy>(&json!({"threshold": "2", "daily_limit_micros": "5", "delay_seconds": "60", "freeze_seconds": "120", "x": "1"})).is_err());
        let key = "11".repeat(32);
        strict::<KeyInput>(&json!({"public_key": key, "role": "spend"})).unwrap();
        assert!(strict::<KeyInput>(&json!({"public_key": key, "role": {"spend": null}})).is_err());
        assert!(strict::<KeyInput>(&json!({"public_key": key, "role": "spend", "proof": null})).is_err());
        strict::<Operation>(&json!({"type": "cancel"})).unwrap();
        assert!(strict::<Operation>(&json!({"type": "cancel", "x": "1"})).is_err());
        assert!(strict::<Operation>(&json!({"type": "unfreeze"})).is_err());
        strict::<Operation>(&json!({"type": "unfreeze", "freezes": "3"})).unwrap();
        strict::<CancelInput>(&json!({"type": "limit", "id": "4"})).unwrap();
        assert!(strict::<CancelInput>(&json!({"type": "removal", "id": "4"})).is_err());
    }

    #[test]
    fn approvals_name_who_else_approves() {
        use serde_json::json;
        let network = "22".repeat(32);
        let (a, b, c) = ("11".repeat(32), "33".repeat(32), "44".repeat(32));
        let op = json!({"type": "cancel"});
        let both = root_message(&network, 5, 1, 9, &op, &[&a, &b]).unwrap();
        assert_ne!(both, root_message(&network, 5, 1, 9, &op, &[&a]).unwrap());
        assert_ne!(both, root_message(&network, 5, 1, 9, &op, &[&a, &c]).unwrap());
        assert_ne!(both, root_message(&network, 5, 1, 9, &op, &[&a, &b, &c]).unwrap());
        assert_ne!(both, root_message(&network, 6, 1, 9, &op, &[&a, &b]).unwrap());
        assert_ne!(both, root_message(&network, 5, 2, 9, &op, &[&a, &b]).unwrap());
        assert_ne!(both, root_message(&network, 5, 1, 10, &op, &[&a, &b]).unwrap());
        assert_ne!(both, root_message(&network, 5, 1, 9, &json!({"type": "unfreeze", "freezes": "0"}), &[&a, &b]).unwrap());
        assert_eq!(both.len(), ROOT_DOMAIN.len() + 32 + 8 + 8 + 8 + 32 + 32);
    }

    #[test]
    fn the_row_encoding_is_stable() {
        let security = row(5);
        let bytes = encode(&security).unwrap();
        assert_eq!(canonical_decode::<Security>(&bytes).unwrap(), security);
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"{"version":"1","policy":{"threshold":"2","daily_limit_micros":"5","delay_seconds":"60","freeze_seconds":"120"},"allowance_micros":"5","allowance_elapsed_micros":"0","frozen_until_elapsed_micros":"0","freezes":"0","pending_limit":null,"pending_payments":[],"next_id":"1","pending_root":null}"#
        );
    }
}
