//! Explicit opt-in guardian recovery for a laboratory. A consenting majority
//! can ultimately take control; a compromised owner can repeatedly cancel.
//! Those are policy tradeoffs, not equivalent to a sole Bitcoin signing key.
use super::*;

pub(super) const RECOVERY_DOMAIN: &[u8] = b"TCDEVNET-RECOVERY-V1\0";
const MAX_DELAY: u64 = 30 * 86_400;
pub(super) const CLAIM_WINDOW: u64 = 600 * MICROS_PER_SECOND;
pub(super) fn validate_approval_window(window: u64) -> Result<()> {
    if window == 0 || window > 30 * 86_400 * MICROS_PER_SECOND {
        return Err(invalid(
            "recovery approval window must be positive and at most30days",
        ));
    }
    Ok(())
}

pub(super) struct RecoveryEffect {
    pub target: u64,
    pub cases: Vec<RecoveryCase>,
}

fn policy_valid(state: &State, target: u64, policy: &RecoveryPolicy) -> Result<()> {
    if !(2..=MAX_GUARDIANS).contains(&policy.guardians.len())
        || policy.threshold < 2
        || policy.threshold > policy.guardians.len() as u64
        || policy.threshold <= policy.guardians.len() as u64 / 2
        || !(30..=MAX_DELAY).contains(&policy.delay_seconds)
        || !policy.guardians.windows(2).all(|w| w[0] < w[1])
        || !policy.accepted.windows(2).all(|w| w[0] < w[1])
    {
        return Err(invalid(
            "recovery requires 2..5 distinct guardians, strict majority, and explicit 30s..30day delay",
        ));
    }
    for guardian in &policy.guardians {
        if *guardian == target || state.account(*guardian).is_none() {
            return Err(invalid(
                "recovery guardian must be another existing account",
            ));
        }
    }
    if policy
        .accepted
        .iter()
        .any(|id| policy.guardians.binary_search(id).is_err())
    {
        return Err(invalid(
            "recovery consent is not from a configured guardian",
        ));
    }
    Ok(())
}

pub(super) fn validate_recovery_state(state: &State) -> Result<()> {
    for account in &state.accounts {
        if account.recovery_version > account.auth_epoch {
            return Err(invalid("recovery version exceeds authority epoch"));
        }
        if let Some(policy) = &account.recovery_policy {
            if account.recovery_version == 0 {
                return Err(invalid("unversioned recovery policy"));
            }
            policy_valid(state, account.id, policy)?;
        }
    }
    if state.recovery_cases.len() > MAX_ACCOUNTS * MAX_GUARDIANS
        || !state
            .recovery_cases
            .windows(2)
            .all(|w| (w[0].target, &w[0].recovery_id) < (w[1].target, &w[1].recovery_id))
    {
        return Err(invalid(
            "recovery cases exceed bounds or canonical ordering",
        ));
    }
    let now = state.elapsed_micros()?;
    let mut votes = HashSet::new();
    let mut counts = std::collections::HashMap::<u64, usize>::new();
    for case in &state.recovery_cases {
        let target = state
            .account(case.target)
            .ok_or_else(|| invalid("recovery target missing"))?;
        let policy = target
            .recovery_policy
            .as_ref()
            .ok_or_else(|| invalid("recovery case has no policy"))?;
        hex32(&case.recovery_id, "recovery ID")?;
        public_key(&case.new_public_key)?;
        let count = counts.entry(case.target).or_default();
        *count += 1;
        if *count > MAX_GUARDIANS
            || case.policy_version != target.recovery_version
            || case.auth_epoch != target.auth_epoch
            || case.expires_elapsed_micros < now
            || case.approvals.is_empty()
            || case.approvals.len() > policy.guardians.len()
            || !case.approvals.windows(2).all(|w| w[0] < w[1])
        {
            return Err(invalid("invalid recovery case coordinates or approval set"));
        }
        for id in &case.approvals {
            if policy.accepted.binary_search(id).is_err() || !votes.insert((case.target, *id)) {
                return Err(invalid(
                    "guardian approval lacks consent or votes in multiple cases",
                ));
            }
        }
        let threshold = case.approvals.len() as u64 >= policy.threshold;
        if threshold != case.ready_elapsed_micros.is_some()
            || case.ready_elapsed_micros.is_some_and(|ready| {
                ready < policy.delay_seconds * MICROS_PER_SECOND
                    || ready > case.expires_elapsed_micros
            })
        {
            return Err(invalid("recovery threshold delay is inconsistent"));
        }
    }
    Ok(())
}

pub fn recovery_frozen(state: &State, target: u64) -> Result<bool> {
    let now = state.elapsed_micros()?;
    let start = state
        .recovery_cases
        .partition_point(|case| case.target < target);
    let end = state
        .recovery_cases
        .partition_point(|case| case.target <= target);
    Ok(state.recovery_cases[start..end]
        .iter()
        .any(|case| case.ready_elapsed_micros.is_some() && case.expires_elapsed_micros >= now))
}

pub(super) fn purge_recovery(state: &mut State) -> Result<()> {
    let now = state.elapsed_micros()?;
    let accounts = &state.accounts;
    state.recovery_cases.retain(|case| {
        case.expires_elapsed_micros >= now
            && accounts
                .binary_search_by_key(&case.target, |a| a.id)
                .is_ok_and(|index| {
                    accounts[index].auth_epoch == case.auth_epoch
                        && accounts[index].recovery_version == case.policy_version
                })
    });
    Ok(())
}

fn target_cases(state: &State, target: u64) -> Vec<RecoveryCase> {
    let start = state
        .recovery_cases
        .partition_point(|case| case.target < target);
    let end = state
        .recovery_cases
        .partition_point(|case| case.target <= target);
    state.recovery_cases[start..end].to_vec()
}
pub(super) fn apply_effect(state: &mut State, effect: RecoveryEffect) {
    let start = state
        .recovery_cases
        .partition_point(|case| case.target < effect.target);
    let end = state
        .recovery_cases
        .partition_point(|case| case.target <= effect.target);
    state.recovery_cases.splice(start..end, effect.cases);
}
fn bump_epoch(account: &mut Account) -> Result<()> {
    account.auth_epoch = account
        .auth_epoch
        .checked_add(1)
        .ok_or_else(|| invalid("authority epoch exhausted"))?;
    Ok(())
}
fn target(state: &State, id: u64, version: u64) -> Result<(usize, &Account, &RecoveryPolicy)> {
    let index = state
        .accounts
        .binary_search_by_key(&id, |a| a.id)
        .map_err(|_| invalid("recovery target not found"))?;
    let account = &state.accounts[index];
    if account.recovery_version != version {
        return Err(invalid("recovery policy version changed"));
    }
    let policy = account
        .recovery_policy
        .as_ref()
        .ok_or_else(|| invalid("target has no recovery policy"))?;
    Ok((index, account, policy))
}
fn possession(state: &State, account: &Account, request: &ApproveRecovery) -> Result<()> {
    let mut message = Vec::new();
    message.extend_from_slice(RECOVERY_DOMAIN);
    message.extend_from_slice(&hex32(&state.network_id, "network ID")?);
    message.extend_from_slice(&account.id.to_be_bytes());
    message.extend_from_slice(&account.auth_epoch.to_be_bytes());
    message.extend_from_slice(&request.policy_version.to_be_bytes());
    message.extend_from_slice(&hex32(&request.recovery_id, "recovery ID")?);
    message.extend_from_slice(&hex32(&request.new_public_key, "new recovery key")?);
    message.extend_from_slice(&request.expires_elapsed_micros.to_be_bytes());
    if request.proof.len() != 128
        || !request
            .proof
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(invalid(
            "recovery possession proof must be canonical 64-byte hex",
        ));
    }
    public_key(&request.new_public_key)?
        .verify_strict(
            &message,
            &Signature::from_slice(
                &hex::decode(&request.proof).map_err(|_| invalid("invalid recovery proof"))?,
            )
            .map_err(|_| invalid("invalid recovery proof"))?,
        )
        .map_err(|_| invalid("new recovery key possession proof failed"))
}

pub(super) fn action_effect_with_approval_window(
    state: &State,
    action: &Action,
    account: &mut Account,
    recipient: &mut Option<(usize, Account)>,
    approval_window_micros: u64,
) -> Result<Option<RecoveryEffect>> {
    validate_approval_window(approval_window_micros)?;
    let now = state.elapsed_micros()?;
    match &action.payload {
        ActionPayload::SetRecovery(request) => {
            let policy = if request.guardians.is_empty() {
                if request.threshold != 0 || request.delay_seconds != 0 {
                    return Err(invalid("disabled recovery policy must be [],0,0"));
                }
                None
            } else {
                let policy = RecoveryPolicy {
                    guardians: request.guardians.clone(),
                    accepted: Vec::new(),
                    threshold: request.threshold,
                    delay_seconds: request.delay_seconds,
                };
                policy_valid(state, account.id, &policy)?;
                Some(policy)
            };
            account.recovery_version = account
                .recovery_version
                .checked_add(1)
                .ok_or_else(|| invalid("recovery version exhausted"))?;
            account.recovery_policy = policy;
            bump_epoch(account)?;
            Ok(Some(RecoveryEffect {
                target: account.id,
                cases: Vec::new(),
            }))
        }
        ActionPayload::ConsentRecovery(request) => {
            let (index, original, policy) = target(state, request.target, request.policy_version)?;
            if policy.guardians.binary_search(&account.id).is_err() {
                return Err(invalid("account is not a nominated recovery guardian"));
            }
            let mut target_account = original.clone();
            let new_policy = target_account
                .recovery_policy
                .as_mut()
                .expect("policy checked");
            let mut cases = target_cases(state, request.target);
            match (
                new_policy.accepted.binary_search(&account.id),
                request.accept,
            ) {
                (Err(index), true) => new_policy.accepted.insert(index, account.id),
                (Ok(index), false) => {
                    new_policy.accepted.remove(index);
                    for case in &mut cases {
                        case.approvals.retain(|id| *id != account.id);
                        if (case.approvals.len() as u64) < new_policy.threshold {
                            case.ready_elapsed_micros = None;
                        }
                    }
                    cases.retain(|case| !case.approvals.is_empty());
                }
                _ => return Err(invalid("guardian consent already has requested value")),
            }
            *recipient = Some((index, target_account));
            Ok(Some(RecoveryEffect {
                target: request.target,
                cases,
            }))
        }
        ActionPayload::ApproveRecovery(request) => {
            let (_, target_account, policy) =
                target(state, request.target, request.policy_version)?;
            if policy.accepted.binary_search(&account.id).is_err() {
                return Err(invalid(
                    "guardian must explicitly consent before approving recovery",
                ));
            }
            let delay = policy.delay_seconds * MICROS_PER_SECOND;
            if request.expires_elapsed_micros <= now
                || request.expires_elapsed_micros
                    > now
                        .checked_add(delay)
                        .and_then(|v| v.checked_add(approval_window_micros))
                        .ok_or_else(|| invalid("recovery claim expiry overflow"))?
            {
                return Err(invalid("recovery claim expired or lifetime excessive"));
            }
            possession(state, target_account, request)?;
            let mut cases = target_cases(state, request.target);
            let existing = cases
                .iter()
                .find(|case| case.recovery_id == request.recovery_id);
            if existing.is_some_and(|case| {
                case.new_public_key != request.new_public_key
                    || case.expires_elapsed_micros != request.expires_elapsed_micros
                    || case.auth_epoch != target_account.auth_epoch
                    || case.policy_version != request.policy_version
            }) {
                return Err(invalid("recovery ID already names a different claim"));
            }
            if existing.is_some_and(|case| case.approvals.binary_search(&account.id).is_ok()) {
                return Err(invalid("guardian already approved this case"));
            }
            // A guardian may move its vote, but cannot occupy multiple case slots.
            for case in &mut cases {
                case.approvals.retain(|id| *id != account.id);
                if (case.approvals.len() as u64) < policy.threshold {
                    case.ready_elapsed_micros = None;
                }
            }
            cases.retain(|case| !case.approvals.is_empty());
            let index =
                match cases.binary_search_by(|case| case.recovery_id.cmp(&request.recovery_id)) {
                    Ok(index) => index,
                    Err(index) => {
                        if cases.len() >= MAX_GUARDIANS {
                            return Err(invalid("recovery case budget exceeded"));
                        }
                        cases.insert(
                            index,
                            RecoveryCase {
                                target: request.target,
                                policy_version: request.policy_version,
                                auth_epoch: target_account.auth_epoch,
                                recovery_id: request.recovery_id.clone(),
                                new_public_key: request.new_public_key.clone(),
                                expires_elapsed_micros: request.expires_elapsed_micros,
                                approvals: Vec::new(),
                                ready_elapsed_micros: None,
                            },
                        );
                        index
                    }
                };
            let case = &mut cases[index];
            let position = case
                .approvals
                .binary_search(&account.id)
                .expect_err("duplicate rejected");
            case.approvals.insert(position, account.id);
            if (case.approvals.len() as u64) >= policy.threshold
                && case.ready_elapsed_micros.is_none()
            {
                let ready = now
                    .checked_add(delay)
                    .ok_or_else(|| invalid("recovery delay overflow"))?;
                if ready > case.expires_elapsed_micros {
                    return Err(invalid("claim expires before threshold delay can elapse"));
                }
                case.ready_elapsed_micros = Some(ready);
            }
            Ok(Some(RecoveryEffect {
                target: request.target,
                cases,
            }))
        }
        ActionPayload::CancelRecovery(_) => {
            if !state
                .recovery_cases
                .iter()
                .any(|case| case.target == account.id)
            {
                return Err(invalid("no recovery case to cancel"));
            }
            bump_epoch(account)?;
            Ok(Some(RecoveryEffect {
                target: account.id,
                cases: Vec::new(),
            }))
        }
        ActionPayload::FinalizeRecovery(request) => {
            hex32(&request.recovery_id, "recovery ID")?;
            let case = state
                .recovery_cases
                .iter()
                .find(|case| case.target == account.id && case.recovery_id == request.recovery_id)
                .ok_or_else(|| invalid("recovery case missing"))?;
            if case.new_public_key != action.public_key
                || case.expires_elapsed_micros < now
                || case.auth_epoch != account.auth_epoch
                || case.policy_version != account.recovery_version
                || case.ready_elapsed_micros.is_none_or(|ready| now < ready)
            {
                return Err(invalid(
                    "recovery key, epoch, expiry, threshold or delay is invalid",
                ));
            }
            account.devices = vec![Device {
                public_key: action.public_key.clone(),
                can_manage: true,
                can_spend: true,
            }];
            bump_epoch(account)?;
            Ok(Some(RecoveryEffect {
                target: account.id,
                cases: Vec::new(),
            }))
        }
        _ => Ok(None),
    }
}
