//! Strictly encoded device-authorized laboratory actions. No password or key
//! derivation occurs in the consensus application.
use super::*;

pub const ACTION_DOMAIN: &[u8] = b"TCDEVNET-ACTION-V1\0";
pub const NAME_DOMAIN: &[u8] = b"TCDEVNET-NAME-V1\0";
pub const DEVICE_DOMAIN: &[u8] = b"TCDEVNET-DEVICE-V1\0";
const HEADER_SIZE: usize = ACTION_DOMAIN.len() + 32 + 1 + 3 * 8 + 32 + 4;
const MAX_PAYLOAD: usize = 1024;
const COMMIT_LIFETIME_MICROS: u64 = 120 * MICROS_PER_SECOND;

macro_rules! payload {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name { $(pub $field: $ty),* }
    };
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub commitment: String,
    #[serde(with = "decimal::u64")]
    pub expires_elapsed_micros: u64,
}
payload!(Reveal {
    name: String,
    salt: String
});
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transfer {
    #[serde(with = "decimal::u64")]
    pub to: u64,
    #[serde(with = "decimal::u64")]
    pub amount: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantPayment {
    #[serde(with = "decimal::u64")]
    pub to: u64,
    #[serde(with = "decimal::u64")]
    pub amount: u64,
    pub reference: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bid {
    #[serde(with = "decimal::u64")]
    pub epoch: u64,
    #[serde(with = "decimal::u64")]
    pub weight: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegate {
    #[serde(with = "decimal::u64")]
    pub operator: u64,
    #[serde(with = "decimal::u64")]
    pub amount: u64,
    #[serde(with = "decimal::u64")]
    pub min_shares: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Undelegate {
    #[serde(with = "decimal::u64")]
    pub operator: u64,
    #[serde(with = "decimal::u64")]
    pub shares: u64,
    #[serde(with = "decimal::u64")]
    pub min_amount: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Withdraw {
    #[serde(with = "decimal::u64")]
    pub entry: u64,
}
payload!(AddDevice {
    public_key: String,
    can_manage: bool,
    can_spend: bool,
    proof: String
});
payload!(RevokeDevice { public_key: String });
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetRecovery {
    #[serde(with = "decimal::u64_vec")]
    pub guardians: Vec<u64>,
    #[serde(with = "decimal::u64")]
    pub threshold: u64,
    #[serde(with = "decimal::u64")]
    pub delay_seconds: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentRecovery {
    #[serde(with = "decimal::u64")]
    pub target: u64,
    #[serde(with = "decimal::u64")]
    pub policy_version: u64,
    pub accept: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveRecovery {
    #[serde(with = "decimal::u64")]
    pub target: u64,
    #[serde(with = "decimal::u64")]
    pub policy_version: u64,
    pub recovery_id: String,
    pub new_public_key: String,
    #[serde(with = "decimal::u64")]
    pub expires_elapsed_micros: u64,
    pub proof: String,
}
payload!(CancelRecovery {});
payload!(FinalizeRecovery {
    recovery_id: String
});
payload!(CancelPending {});

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ActionPayload {
    Commit(Commit),
    Reveal(Reveal),
    Transfer(Transfer),
    Bid(Bid),
    Delegate(Delegate),
    Undelegate(Undelegate),
    Withdraw(Withdraw),
    AddDevice(AddDevice),
    RevokeDevice(RevokeDevice),
    MerchantPayment(MerchantPayment),
    SetRecovery(SetRecovery),
    ConsentRecovery(ConsentRecovery),
    ApproveRecovery(ApproveRecovery),
    CancelRecovery(CancelRecovery),
    FinalizeRecovery(FinalizeRecovery),
    CancelPending(CancelPending),
}
impl ActionPayload {
    pub fn kind(&self) -> u8 {
        match self {
            Self::Commit(_) => 1,
            Self::Reveal(_) => 2,
            Self::Transfer(_) => 3,
            Self::Bid(_) => 4,
            Self::Delegate(_) => 5,
            Self::Undelegate(_) => 6,
            Self::Withdraw(_) => 7,
            Self::AddDevice(_) => 8,
            Self::RevokeDevice(_) => 9,
            Self::MerchantPayment(_) => 10,
            Self::SetRecovery(_) => 11,
            Self::ConsentRecovery(_) => 12,
            Self::ApproveRecovery(_) => 13,
            Self::CancelRecovery(_) => 14,
            Self::FinalizeRecovery(_) => 15,
            Self::CancelPending(_) => 16,
        }
    }
    fn decode(kind: u8, bytes: &[u8]) -> Result<Self> {
        macro_rules! parse {
            ($ty:ident) => {
                Self::$ty(
                    serde_json::from_slice::<$ty>(bytes)
                        .map_err(|e| invalid(format!("invalid action payload: {e}")))?,
                )
            };
        }
        let value = match kind {
            1 => parse!(Commit),
            2 => parse!(Reveal),
            3 => parse!(Transfer),
            4 => parse!(Bid),
            5 => parse!(Delegate),
            6 => parse!(Undelegate),
            7 => parse!(Withdraw),
            8 => parse!(AddDevice),
            9 => parse!(RevokeDevice),
            10 => parse!(MerchantPayment),
            11 => parse!(SetRecovery),
            12 => parse!(ConsentRecovery),
            13 => parse!(ApproveRecovery),
            14 => parse!(CancelRecovery),
            15 => parse!(FinalizeRecovery),
            16 => parse!(CancelPending),
            _ => return Err(invalid("unsupported action kind")),
        };
        if serde_json::to_vec(&value).map_err(|e| invalid(e.to_string()))? != bytes {
            return Err(invalid("noncanonical action payload"));
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    pub network_id: String,
    pub from: u64,
    pub nonce: u64,
    pub auth_epoch: u64,
    pub public_key: String,
    pub payload: ActionPayload,
    pub signature: Vec<u8>,
}

fn action_bytes(action: &Action) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(&action.payload).map_err(|e| invalid(e.to_string()))?;
    if payload.len() > MAX_PAYLOAD {
        return Err(invalid("action payload exceeds limit"));
    }
    let mut raw = Vec::with_capacity(HEADER_SIZE + payload.len() + 64);
    raw.extend_from_slice(ACTION_DOMAIN);
    raw.extend_from_slice(&hex32(&action.network_id, "network ID")?);
    raw.push(action.payload.kind());
    for value in [action.from, action.nonce, action.auth_epoch] {
        raw.extend_from_slice(&value.to_be_bytes());
    }
    raw.extend_from_slice(&hex32(&action.public_key, "signer public key")?);
    raw.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    raw.extend_from_slice(&payload);
    Ok(raw)
}

pub fn sign_action(action: &Action, key: &SigningKey) -> Result<Vec<u8>> {
    let mut raw = action_bytes(action)?;
    raw.extend_from_slice(&key.sign(&raw).to_bytes());
    Ok(raw)
}

pub fn decode_action(raw: &[u8]) -> Result<Action> {
    if raw.len() < HEADER_SIZE + 64
        || raw.len() > HEADER_SIZE + MAX_PAYLOAD + 64
        || !raw.starts_with(ACTION_DOMAIN)
    {
        return Err(invalid("malformed action envelope"));
    }
    let mut p = ACTION_DOMAIN.len();
    let network_id = hex::encode(&raw[p..p + 32]);
    p += 32;
    let kind = raw[p];
    p += 1;
    let mut next = || {
        let mut b = [0; 8];
        b.copy_from_slice(&raw[p..p + 8]);
        p += 8;
        u64::from_be_bytes(b)
    };
    let (from, nonce, auth_epoch) = (next(), next(), next());
    let signer = hex::encode(&raw[p..p + 32]);
    p += 32;
    let mut len = [0; 4];
    len.copy_from_slice(&raw[p..p + 4]);
    p += 4;
    let len = u32::from_be_bytes(len) as usize;
    if raw.len() != HEADER_SIZE + len + 64 {
        return Err(invalid("action payload length mismatch"));
    }
    Ok(Action {
        network_id,
        from,
        nonce,
        auth_epoch,
        public_key: signer,
        payload: ActionPayload::decode(kind, &raw[p..p + len])?,
        signature: raw[p + len..].to_vec(),
    })
}

pub fn action_commitment(network: &str, signer: &str, name: &str, salt: &str) -> Result<String> {
    if !valid_name(name) {
        return Err(invalid("invalid canonical username"));
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(NAME_DOMAIN);
    bytes.extend_from_slice(&hex32(network, "network ID")?);
    bytes.extend_from_slice(&hex32(signer, "signer public key")?);
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&hex32(salt, "registration salt")?);
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn device_proof(state: &State, account: &Account, device: &AddDevice) -> Result<()> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DEVICE_DOMAIN);
    bytes.extend_from_slice(&hex32(&state.network_id, "network ID")?);
    bytes.extend_from_slice(&account.id.to_be_bytes());
    bytes.extend_from_slice(&account.auth_epoch.to_be_bytes());
    bytes.extend_from_slice(&hex32(&device.public_key, "new device key")?);
    bytes.extend_from_slice(&[u8::from(device.can_manage), u8::from(device.can_spend)]);
    if device.proof.len() != 128
        || !device
            .proof
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(invalid(
            "device possession proof must be canonical 64-byte hex",
        ));
    }
    let proof = hex::decode(&device.proof).map_err(|_| invalid("invalid device proof"))?;
    public_key(&device.public_key)?
        .verify_strict(
            &bytes,
            &Signature::from_slice(&proof).map_err(|_| invalid("invalid device proof"))?,
        )
        .map_err(|_| invalid("device possession proof failed"))
}

enum Effect {
    Commit(usize, NameCommit),
    Reveal(usize, Account),
    Account(Box<AccountEffect>),
}
struct AccountEffect {
    index: usize,
    account: Account,
    recipient: Option<(usize, Account)>,
    pool: Option<(usize, Pool)>,
    bid: Option<(usize, AuctionBid)>,
    bank: u64,
    next_unbond: u64,
    recovery: Option<super::recovery::RecoveryEffect>,
}

fn effect(state: &State, raw: &[u8]) -> Result<Effect> {
    effect_with_recovery_window(state, raw, super::recovery::CLAIM_WINDOW)
}
fn effect_with_recovery_window(
    state: &State,
    raw: &[u8],
    approval_window_micros: u64,
) -> Result<Effect> {
    super::recovery::validate_approval_window(approval_window_micros)?;
    let action = decode_action(raw)?;
    if action.network_id != state.network_id {
        return Err(invalid("wrong network"));
    }
    public_key(&action.public_key)?
        .verify_strict(
            &raw[..raw.len() - 64],
            &Signature::from_slice(&action.signature)
                .map_err(|_| invalid("invalid action signature"))?,
        )
        .map_err(|_| invalid("invalid action signature"))?;
    if matches!(
        action.payload,
        ActionPayload::Commit(_) | ActionPayload::Reveal(_)
    ) {
        if action.from != u64::MAX || action.nonce != 0 || action.auth_epoch != 0 {
            return Err(invalid("registration requires anonymous header"));
        }
        let pending = state
            .name_commits
            .binary_search_by(|c| c.public_key.cmp(&action.public_key));
        return match action.payload {
            ActionPayload::Commit(payload) => {
                hex32(&payload.commitment, "name commitment")?;
                let now = state.elapsed_micros()?;
                if payload.expires_elapsed_micros <= now
                    || payload.expires_elapsed_micros
                        > now
                            .checked_add(COMMIT_LIFETIME_MICROS)
                            .ok_or_else(|| invalid("commit expiry overflow"))?
                    || state
                        .accounts
                        .iter()
                        .any(|a| a.public_key == action.public_key)
                {
                    return Err(invalid(
                        "expired commitment, excessive lifetime, or identity key already registered",
                    ));
                }
                if state.accounts.len() >= MAX_ACCOUNTS
                    || state.name_commits.len() >= MAX_PENDING_COMMITS
                {
                    return Err(invalid("devnet registration capacity reached"));
                }
                let index = pending
                    .map_or_else(Ok, |_| Err(invalid("pending commitment already exists")))?;
                Ok(Effect::Commit(
                    index,
                    NameCommit {
                        public_key: action.public_key,
                        commitment: payload.commitment,
                        height: state.height,
                        expires_elapsed_micros: payload.expires_elapsed_micros,
                    },
                ))
            }
            ActionPayload::Reveal(payload) => {
                let index = pending.map_err(|_| invalid("name reveal has no commitment"))?;
                let commit = &state.name_commits[index];
                if state.height <= commit.height {
                    return Err(invalid("name reveal requires a later committed height"));
                }
                if state.elapsed_micros()? > commit.expires_elapsed_micros {
                    return Err(invalid("name commitment expired"));
                }
                if commit.commitment
                    != action_commitment(
                        &state.network_id,
                        &action.public_key,
                        &payload.name,
                        &payload.salt,
                    )?
                {
                    return Err(invalid("name reveal does not match commitment"));
                }
                if state.accounts.len() >= MAX_ACCOUNTS
                    || state.accounts.iter().any(|a| a.name == payload.name)
                {
                    return Err(invalid("username unavailable or registry full"));
                }
                let id = state
                    .accounts
                    .last()
                    .map_or(Some(0), |a| a.id.checked_add(1))
                    .filter(|id| *id != u64::MAX)
                    .ok_or_else(|| invalid("account ID space exhausted"))?;
                Ok(Effect::Reveal(
                    index,
                    Account {
                        id,
                        name: payload.name,
                        public_key: action.public_key.clone(),
                        balance: 0,
                        nonce: 0,
                        auth_epoch: 0,
                        devices: vec![Device {
                            public_key: action.public_key,
                            can_manage: true,
                            can_spend: true,
                        }],
                        delegations: Vec::new(),
                        unbonding: Vec::new(),
                        recovery_version: 0,
                        recovery_policy: None,
                    },
                ))
            }
            _ => unreachable!(),
        };
    }
    let index = state
        .accounts
        .binary_search_by_key(&action.from, |a| a.id)
        .map_err(|_| invalid("account does not exist"))?;
    let original = &state.accounts[index];
    if action.auth_epoch != original.auth_epoch {
        return Err(invalid("stale authority epoch"));
    }
    if original.nonce.checked_add(1) != Some(action.nonce) {
        return Err(invalid("incorrect nonce or nonce exhausted"));
    }
    let management = matches!(
        action.payload,
        ActionPayload::AddDevice(_)
            | ActionPayload::RevokeDevice(_)
            | ActionPayload::SetRecovery(_)
            | ActionPayload::ConsentRecovery(_)
            | ActionPayload::ApproveRecovery(_)
            | ActionPayload::CancelRecovery(_)
            | ActionPayload::CancelPending(_)
    );
    let finalizing = matches!(action.payload, ActionPayload::FinalizeRecovery(_));
    if recovery_frozen(state, original.id)?
        && !matches!(
            action.payload,
            ActionPayload::CancelRecovery(_) | ActionPayload::FinalizeRecovery(_)
        )
    {
        return Err(invalid("account is frozen by threshold guardian recovery"));
    }
    if !finalizing {
        let device = original
            .devices
            .iter()
            .find(|d| d.public_key == action.public_key)
            .ok_or_else(|| invalid("device is not authorized"))?;
        if (management && !device.can_manage) || (!management && !device.can_spend) {
            return Err(invalid("device permission denied"));
        }
    }
    let mut account = original.clone();
    account.nonce = action.nonce;
    let mut recipient = None;
    let mut pool_effect = None;
    let mut bid_effect = None;
    let mut next_unbond = state.next_unbond_id;
    let fee = if matches!(
        action.payload,
        ActionPayload::Bid(_)
            | ActionPayload::CancelRecovery(_)
            | ActionPayload::FinalizeRecovery(_)
            | ActionPayload::CancelPending(_)
            | ActionPayload::ConsentRecovery(ConsentRecovery { accept: false, .. })
    ) {
        0
    } else {
        FEE_MICROS
    };
    let bank = state
        .bank
        .checked_add(fee)
        .ok_or_else(|| invalid("bank fee overflow"))?;
    let mut recovery = super::recovery::action_effect_with_approval_window(
        state,
        &action,
        &mut account,
        &mut recipient,
        approval_window_micros,
    )?;
    let payload = match action.payload {
        ActionPayload::MerchantPayment(payment) => {
            hex32(&payment.reference, "merchant order reference")?;
            ActionPayload::Transfer(Transfer {
                to: payment.to,
                amount: payment.amount,
            })
        }
        payload => payload,
    };
    match payload {
        ActionPayload::Transfer(payload) => {
            if payload.to == action.from || payload.amount == 0 {
                return Err(invalid("invalid transfer amount or recipient"));
            }
            let to = state
                .accounts
                .binary_search_by_key(&payload.to, |a| a.id)
                .map_err(|_| invalid("recipient does not exist"))?;
            let mut target = state.accounts[to].clone();
            target.balance = target
                .balance
                .checked_add(payload.amount)
                .ok_or_else(|| invalid("recipient balance overflow"))?;
            account.balance = account
                .balance
                .checked_sub(payload.amount)
                .ok_or_else(|| invalid("insufficient funds"))?;
            recipient = Some((to, target));
        }
        ActionPayload::Bid(payload) => {
            require_auction(state)?;
            if payload.epoch != state.auction_epoch
                || !(1..=1_000_000).contains(&payload.weight)
                || state.auction_bids.len() >= MAX_AUCTION_BIDS
            {
                return Err(invalid("invalid synthetic auction bid"));
            }
            let position = state
                .auction_bids
                .binary_search_by_key(&action.from, |b| b.account_id)
                .map_or_else(Ok, |_| {
                    Err(invalid("one synthetic bid per account per epoch"))
                })?;
            bid_effect = Some((
                position,
                AuctionBid {
                    account_id: action.from,
                    weight: payload.weight,
                },
            ));
        }
        ActionPayload::Delegate(payload) => {
            require_auction(state)?;
            let pi = pool_index(state, payload.operator)?;
            let mut pool = state.pools[pi].clone();
            if payload.amount == 0 {
                return Err(invalid("zero delegation"));
            }
            let shares = if pool.total_shares == 0 {
                payload.amount
            } else {
                ratio(payload.amount, pool.total_shares, pool.assets)?
            };
            if payload.min_shares == 0 || shares < payload.min_shares {
                return Err(invalid("delegation share slippage limit"));
            }
            let new_total_shares = pool
                .total_shares
                .checked_add(shares)
                .ok_or_else(|| invalid("pool share overflow"))?;
            if pool.total_shares != 0 {
                let deposit_times_shares = (payload.amount as u128)
                    .checked_mul(pool.total_shares as u128)
                    .ok_or_else(|| invalid("delegation rounding arithmetic overflow"))?;
                let assets_times_minted = (pool.assets as u128)
                    .checked_mul(shares as u128)
                    .ok_or_else(|| invalid("delegation rounding arithmetic overflow"))?;
                let remainder = deposit_times_shares
                    .checked_sub(assets_times_minted)
                    .ok_or_else(|| invalid("delegation rounding arithmetic underflow"))?;
                let loss_scaled = remainder
                    .checked_mul(1000)
                    .ok_or_else(|| invalid("delegation rounding arithmetic overflow"))?;
                let deposit_scaled = (payload.amount as u128)
                    .checked_mul(new_total_shares as u128)
                    .ok_or_else(|| invalid("delegation rounding arithmetic overflow"))?;
                if loss_scaled > deposit_scaled {
                    return Err(invalid("delegation rounding loss exceeds 0.1 percent"));
                }
            }
            pool.assets = pool
                .assets
                .checked_add(payload.amount)
                .ok_or_else(|| invalid("pool asset overflow"))?;
            pool.total_shares = new_total_shares;
            account.balance = account
                .balance
                .checked_sub(payload.amount)
                .ok_or_else(|| invalid("insufficient funds"))?;
            match account
                .delegations
                .binary_search_by_key(&payload.operator, |d| d.operator)
            {
                Ok(i) => {
                    account.delegations[i].shares = account.delegations[i]
                        .shares
                        .checked_add(shares)
                        .ok_or_else(|| invalid("delegation share overflow"))?
                }
                Err(i) => account.delegations.insert(
                    i,
                    Delegation {
                        operator: payload.operator,
                        shares,
                    },
                ),
            }
            pool_effect = Some((pi, pool));
        }
        ActionPayload::Undelegate(payload) => {
            require_auction(state)?;
            let pi = pool_index(state, payload.operator)?;
            let mut pool = state.pools[pi].clone();
            let di = account
                .delegations
                .binary_search_by_key(&payload.operator, |d| d.operator)
                .map_err(|_| invalid("no delegation in operator pool"))?;
            if payload.shares == 0
                || payload.shares > account.delegations[di].shares
                || account.unbonding.len() >= MAX_UNBONDING
            {
                return Err(invalid("invalid unbond share amount or entry limit"));
            }
            let amount = ratio(payload.shares, pool.assets, pool.total_shares)?;
            if payload.min_amount == 0 || amount < payload.min_amount {
                return Err(invalid("unbond amount slippage limit"));
            }
            pool.assets -= amount;
            pool.total_shares -= payload.shares;
            account.delegations[di].shares -= payload.shares;
            if account.delegations[di].shares == 0 {
                account.delegations.remove(di);
            }
            let unlock = state
                .elapsed_micros()?
                .checked_add(state.genesis.economics.unbond_seconds * MICROS_PER_SECOND)
                .ok_or_else(|| invalid("unbond unlock overflow"))?;
            next_unbond = state
                .next_unbond_id
                .checked_add(1)
                .ok_or_else(|| invalid("unbond ID exhausted"))?;
            account.unbonding.push(Unbonding {
                id: state.next_unbond_id,
                amount,
                unlock_elapsed_micros: unlock,
            });
            pool_effect = Some((pi, pool));
        }
        ActionPayload::Withdraw(payload) => {
            let entry = account
                .unbonding
                .binary_search_by_key(&payload.entry, |u| u.id)
                .map_err(|_| invalid("unbonding entry does not exist"))?;
            if state.elapsed_micros()? < account.unbonding[entry].unlock_elapsed_micros {
                return Err(invalid("unbonding delay not elapsed"));
            }
            account.balance = account
                .balance
                .checked_add(account.unbonding[entry].amount)
                .ok_or_else(|| invalid("withdraw balance overflow"))?;
            account.unbonding.remove(entry);
        }
        ActionPayload::AddDevice(payload) => {
            if account.devices.len() >= MAX_DEVICES {
                return Err(invalid("device limit reached"));
            }
            device_proof(state, original, &payload)?;
            let position = account
                .devices
                .binary_search_by(|d| d.public_key.cmp(&payload.public_key))
                .map_or_else(Ok, |_| Err(invalid("device already exists")))?;
            account.devices.insert(
                position,
                Device {
                    public_key: payload.public_key,
                    can_manage: payload.can_manage,
                    can_spend: payload.can_spend,
                },
            );
            account.auth_epoch = account
                .auth_epoch
                .checked_add(1)
                .ok_or_else(|| invalid("authority epoch exhausted"))?;
        }
        ActionPayload::RevokeDevice(payload) => {
            let position = account
                .devices
                .binary_search_by(|d| d.public_key.cmp(&payload.public_key))
                .map_err(|_| invalid("device does not exist"))?;
            account.devices.remove(position);
            if !account.devices.iter().any(|d| d.can_manage)
                || !account.devices.iter().any(|d| d.can_spend)
            {
                return Err(invalid(
                    "cannot revoke last management or spending authority",
                ));
            }
            account.auth_epoch = account
                .auth_epoch
                .checked_add(1)
                .ok_or_else(|| invalid("authority epoch exhausted"))?;
        }
        ActionPayload::Commit(_) | ActionPayload::Reveal(_) | ActionPayload::MerchantPayment(_) => {
            unreachable!()
        }
        ActionPayload::SetRecovery(_)
        | ActionPayload::ConsentRecovery(_)
        | ActionPayload::ApproveRecovery(_)
        | ActionPayload::CancelRecovery(_)
        | ActionPayload::FinalizeRecovery(_) => {}
        ActionPayload::CancelPending(_) => {
            account.auth_epoch = account
                .auth_epoch
                .checked_add(1)
                .ok_or_else(|| invalid("authority epoch exhausted"))?;
        }
    }
    if account.auth_epoch != original.auth_epoch && recovery.is_none() {
        recovery = Some(super::recovery::RecoveryEffect {
            target: account.id,
            cases: Vec::new(),
        });
    }
    account.balance = account
        .balance
        .checked_sub(fee)
        .ok_or_else(|| invalid("insufficient funds for fee"))?;
    Ok(Effect::Account(Box::new(AccountEffect {
        index,
        account,
        recipient,
        pool: pool_effect,
        bid: bid_effect,
        bank,
        next_unbond,
        recovery,
    })))
}

pub(super) fn check_action(state: &State, raw: &[u8]) -> Result<()> {
    effect(state, raw).map(|_| ())
}
pub(super) fn apply_action(state: &mut State, raw: &[u8]) -> Result<()> {
    apply_action_with_recovery_window(state, raw, super::recovery::CLAIM_WINDOW)
}
pub(super) fn check_action_with_recovery_window(
    state: &State,
    raw: &[u8],
    window: u64,
) -> Result<()> {
    effect_with_recovery_window(state, raw, window).map(|_| ())
}
pub(super) fn apply_action_with_recovery_window(
    state: &mut State,
    raw: &[u8],
    window: u64,
) -> Result<()> {
    match effect_with_recovery_window(state, raw, window)? {
        Effect::Commit(index, commit) => state.name_commits.insert(index, commit),
        Effect::Reveal(index, account) => {
            state.name_commits.remove(index);
            state.accounts.push(account);
        }
        Effect::Account(changes) => {
            let AccountEffect {
                index,
                account,
                recipient,
                pool,
                bid,
                bank,
                next_unbond,
                recovery,
            } = *changes;
            state.accounts[index] = account;
            if let Some((index, account)) = recipient {
                state.accounts[index] = account;
            }
            if let Some((index, pool)) = pool {
                state.pools[index] = pool;
            }
            if let Some((index, bid)) = bid {
                state.auction_bids.insert(index, bid);
            }
            state.bank = bank;
            state.next_unbond_id = next_unbond;
            if let Some(recovery) = recovery {
                super::recovery::apply_effect(state, recovery);
            }
        }
    }
    Ok(())
}

fn require_auction(state: &State) -> Result<()> {
    if state.genesis.economics.mode != EconomicMode::DevnetAuction {
        return Err(invalid("synthetic devnet economics disabled"));
    }
    Ok(())
}
fn pool_index(state: &State, operator: u64) -> Result<usize> {
    state
        .pools
        .binary_search_by_key(&operator, |p| p.operator)
        .map_err(|_| invalid("unknown operator pool"))
}
fn ratio(a: u64, b: u64, denominator: u64) -> Result<u64> {
    if denominator == 0 {
        return Err(invalid("zero ratio denominator"));
    }
    u64::try_from((a as u128 * b as u128) / denominator as u128)
        .map_err(|_| invalid("share ratio overflow"))
}

fn accrue(state: &mut State, start: u64, end: u64, eligible: &[String]) -> Result<()> {
    let issuance = end
        .checked_sub(start)
        .ok_or_else(|| invalid("negative issuance interval"))?;
    state.bank = state
        .bank
        .checked_add(issuance)
        .ok_or_else(|| invalid("issuance overflow"))?;
    if state.genesis.economics.mode == EconomicMode::BankOnly || issuance == 0 {
        return Ok(());
    }
    // Cumulative schedule makes the 20% split independent of block cadence.
    let validator_budget = end / 5 - start / 5;
    let total_power: u64 = state
        .genesis
        .economics
        .operators
        .iter()
        .map(|o| o.power)
        .sum();
    for index in 0..state.genesis.economics.operators.len() {
        let operator = &state.genesis.economics.operators[index];
        if !eligible.contains(&operator.consensus_key) {
            continue;
        }
        let reward = ratio(validator_budget, operator.power, total_power)?;
        if reward == 0 {
            continue;
        }
        let account_id = operator.account_id;
        let commission = if state.pools[index].total_shares == 0 {
            reward
        } else {
            ratio(reward, operator.commission_bps as u64, 10_000)?
        };
        let operator_index = state
            .accounts
            .binary_search_by_key(&account_id, |a| a.id)
            .map_err(|_| invalid("missing operator account"))?;
        state.accounts[operator_index].balance = state.accounts[operator_index]
            .balance
            .checked_add(commission)
            .ok_or_else(|| invalid("operator balance overflow"))?;
        state.pools[index].assets = state.pools[index]
            .assets
            .checked_add(reward - commission)
            .ok_or_else(|| invalid("pool reward overflow"))?;
        state.bank -= reward;
    }
    Ok(())
}

fn settle(state: &mut State) -> Result<()> {
    let total_weight: u64 = state.auction_bids.iter().map(|b| b.weight).sum();
    if total_weight != 0 {
        let pot = state.bank;
        for bid in &state.auction_bids {
            let payout = ratio(pot, bid.weight, total_weight)?;
            let index = state
                .accounts
                .binary_search_by_key(&bid.account_id, |a| a.id)
                .map_err(|_| invalid("auction account missing"))?;
            state.accounts[index].balance = state.accounts[index]
                .balance
                .checked_add(payout)
                .ok_or_else(|| invalid("auction payout overflow"))?;
            state.bank -= payout;
        }
    }
    state.auction_bids.clear();
    Ok(())
}

pub(super) fn advance_economics(
    state: &mut State,
    previous: u64,
    delta: u64,
    eligible: &[String],
) -> Result<()> {
    // Reject unknown/duplicate input evidence rather than accidentally paying an
    // ambiguous signer set. Membership and >2/3 finality are CometBFT's job.
    let mut seen = HashSet::new();
    for key in eligible {
        if !seen.insert(key)
            || !state
                .genesis
                .economics
                .operators
                .iter()
                .any(|o| &o.consensus_key == key)
        {
            return Err(invalid("unknown or duplicate eligible operator"));
        }
    }
    let end = previous
        .checked_add(delta)
        .ok_or_else(|| invalid("elapsed issuance overflow"))?;
    let period = state.genesis.economics.auction_epoch_seconds * MICROS_PER_SECOND;
    let target_epoch = end / period;
    if target_epoch != state.auction_epoch {
        let boundary = (state.auction_epoch + 1)
            .checked_mul(period)
            .ok_or_else(|| invalid("auction boundary overflow"))?;
        accrue(state, previous, boundary, eligible)?;
        settle(state)?;
        // Unattended intermediate epochs had no bids. Their bank issuance is
        // retained; the old bid never captures time after its closing boundary.
        accrue(state, boundary, end, eligible)?;
    } else {
        accrue(state, previous, end, eligible)?;
    }
    state.auction_epoch = target_epoch;
    Ok(())
}
