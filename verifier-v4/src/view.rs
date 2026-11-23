//! Bounded JMT selections bound to an independently advanced dynamic checkpoint.
use crate::{
    decimal,
    light::{self, LightBlock, Trust},
    parse,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashSet};
const MAX_ENTRIES: usize = 256;
const MAX_VALUE: usize = 512 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateProof {
    pub height: String,
    pub entries: Vec<ProofEntry>,
    pub light_block: LightBlock,
    #[serde(default)]
    pub history_proofs: BTreeMap<String, history::Proof>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofEntry {
    key_hex: String,
    value_b64: Option<String>,
    proof: jmt::proof::SparseMerkleProof<sha2_10::Sha256>,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    ids: Vec<String>,
    #[serde(default)]
    public_keys: Vec<String>,
    #[serde(default)]
    owners: Vec<String>,
    #[serde(default)]
    candidates: Vec<String>,
    #[serde(default)]
    epochs: Vec<String>,
    #[serde(default)]
    blocks: Vec<String>,
    #[serde(default)]
    include_pos: bool,
    #[serde(default)]
    include_bitcoin: bool,
    #[serde(default)]
    include_policy: bool,
    #[serde(default)]
    include_security: bool,
    #[serde(default)]
    include_upgrade: bool,
}
/// The key of the row that holds a scheduled change of the protocol version
/// and the validators' signals for one.
const UPGRADE_KEY: &[u8] = b"upgrade/state";
/// Most entries the row can hold: one per validator candidate. With the
/// form checked below, that keeps the row under 64 KiB.
const MAX_SIGNALS: usize = 256;
fn spec_hash(value: &Value, field: &str) -> Result<(), String> {
    if !value.as_str().is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    }) {
        return Err(format!("{field} must be 64 lowercase hexadecimal characters"));
    }
    Ok(())
}
/// The fields of `object`, which must be exactly `fields`.
fn exact_fields<'a>(
    object: &'a serde_json::Map<String, Value>,
    fields: &[&str],
    what: &str,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(format!("{what} has missing or unknown fields"));
    }
    Ok(object)
}
/// The `upgrade/state` row as the engine stores it, checked for its form:
///
/// `{"plan":{"activate_elapsed_micros":"D","scheduled_elapsed_micros":"D","spec":"H","version":"D"},"signals":[ENTRY,…]}`
///
/// - `plan` is there only while a plan is scheduled, and names the version
///   after the one in force (`current`);
/// - an entry supports a plan (`activate_elapsed_micros`,
///   `changed_elapsed_micros`, `owner`, `spec`, `version`) or records a
///   withdrawal (`changed_elapsed_micros`, `owner`);
/// - entries are sorted by owner as a number, one per owner, at most 256;
/// - a row with no plan and no entry does not exist (the engine removes it).
///
/// The content is authenticated by the proof and the engine is what enforces
/// its rules. Anything else than this form is refused: this build could not
/// say what it means.
fn upgrade_row(row: &Value, current: u64) -> Result<Value, String> {
    let object = row.as_object().ok_or("invalid upgrade row")?;
    if !object.keys().all(|key| key == "plan" || key == "signals") {
        return Err("upgrade row has unknown fields".into());
    }
    let signals = object
        .get("signals")
        .and_then(Value::as_array)
        .ok_or("upgrade row lacks its signals")?;
    if signals.len() > MAX_SIGNALS {
        return Err("too many upgrade signals".into());
    }
    let mut previous = None;
    for entry in signals {
        let entry = entry.as_object().ok_or("invalid upgrade signal")?;
        let owner = state_integer(
            entry.get("owner").ok_or("upgrade signal lacks its owner")?,
            "signal owner",
        )?;
        if owner == u64::MAX {
            return Err("upgrade signal names an owner that is not an account".into());
        }
        if previous.is_some_and(|before| before >= owner) {
            return Err("upgrade signals are not one per owner in ascending order".into());
        }
        previous = Some(owner);
        if entry.len() == 2 {
            exact_fields(entry, &["changed_elapsed_micros", "owner"], "withdrawn upgrade signal")?;
        } else {
            exact_fields(
                entry,
                &[
                    "activate_elapsed_micros",
                    "changed_elapsed_micros",
                    "owner",
                    "spec",
                    "version",
                ],
                "upgrade signal",
            )?;
            state_integer(&entry["activate_elapsed_micros"], "signal start time")?;
            state_integer(&entry["version"], "signal version")?;
            spec_hash(&entry["spec"], "signal spec hash")?;
        }
        state_integer(&entry["changed_elapsed_micros"], "signal change time")?;
    }
    match object.get("plan") {
        Some(plan) => {
            let plan = exact_fields(
                plan.as_object().ok_or("invalid upgrade plan")?,
                &[
                    "activate_elapsed_micros",
                    "scheduled_elapsed_micros",
                    "spec",
                    "version",
                ],
                "upgrade plan",
            )?;
            state_integer(&plan["activate_elapsed_micros"], "plan start time")?;
            state_integer(&plan["scheduled_elapsed_micros"], "plan scheduling time")?;
            spec_hash(&plan["spec"], "plan spec hash")?;
            // A plan is for the version after the one in force, and is
            // removed by the block that puts it in force.
            if Some(state_integer(&plan["version"], "plan version")?) != current.checked_add(1) {
                return Err("upgrade plan is not for the next protocol version".into());
            }
        }
        None if signals.is_empty() => return Err("empty upgrade row".into()),
        None => {}
    }
    Ok(row.clone())
}
/// The security row of an account, as the version-5 engine stores it: checked
/// for shape only. Its content is authenticated by the proof, and the engine
/// is what enforces its rules.
fn security_row(row: &Value, account: u64) -> Result<Value, String> {
    let object = row.as_object().ok_or("invalid security row")?;
    for field in [
        "version",
        "allowance_micros",
        "allowance_elapsed_micros",
        "frozen_until_elapsed_micros",
        "freezes",
        "next_id",
    ] {
        state_integer(object.get(field).ok_or("incomplete security row")?, field)?;
    }
    let policy = object
        .get("policy")
        .and_then(Value::as_object)
        .ok_or("invalid security policy")?;
    for field in [
        "threshold",
        "daily_limit_micros",
        "delay_seconds",
        "freeze_seconds",
    ] {
        state_integer(policy.get(field).ok_or("incomplete security policy")?, field)?;
    }
    if !object.get("pending_payments").is_some_and(Value::is_array)
        || !object.contains_key("pending_limit")
        || !object.contains_key("pending_root")
    {
        return Err("incomplete security row".into());
    }
    let mut row = row.clone();
    row["account"] = json!(account.to_string());
    Ok(row)
}
fn state_integer(value: &Value, field: &str) -> Result<u64, String> {
    if !value.is_string() {
        return Err(format!("{field} must be a decimal string"));
    }
    decimal(value, field)
}
fn raw_id(namespace: &[u8], id: u64) -> Vec<u8> {
    [namespace, &id.to_be_bytes()].concat()
}
fn key_hash(raw: &[u8]) -> jmt::KeyHash {
    use sha2_10::Digest as _;
    jmt::KeyHash(sha2_10::Sha256::digest([b"TCDEVNET-KEY-V2\0".as_slice(), raw].concat()).into())
}
fn canonical_u64(text: &str, label: &str) -> Result<u64, String> {
    state_integer(&json!(text), label)
}
fn get<'a>(
    rows: &'a std::collections::BTreeMap<Vec<u8>, Option<Value>>,
    key: &[u8],
) -> Result<Option<&'a Value>, String> {
    rows.get(key)
        .map(Option::as_ref)
        .ok_or_else(|| format!("missing requested proof for {}", hex::encode(key)))
}
fn required<'a>(
    rows: &'a std::collections::BTreeMap<Vec<u8>, Option<Value>>,
    key: &[u8],
) -> Result<&'a Value, String> {
    get(rows, key)?.ok_or_else(|| "required state value is absent".into())
}
fn name_key(name: &str) -> Result<Vec<u8>, String> {
    if !(2..=15).contains(&name.len())
        || !name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
    {
        return Err("invalid requested name".into());
    }
    Ok([b"name/".as_slice(), name.as_bytes()].concat())
}
fn public_key(text: &str) -> Result<Vec<u8>, String> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("invalid requested public key".into());
    }
    Ok([
        b"pubkey/".as_slice(),
        &hex::decode(text).map_err(|_| "invalid public key")?,
    ]
    .concat())
}
fn validate_account(account: &Value, meta: &Value) -> Result<(), String> {
    let id = state_integer(&account["id"], "account id")?;
    if id >= state_integer(&meta["next_account_id"], "next account id")? {
        return Err("account id exceeds allocated registry".into());
    }
    public_key(
        account["public_key"]
            .as_str()
            .ok_or("missing registration key")?,
    )?;
    let devices = account["devices"]
        .as_array()
        .ok_or("invalid account devices")?;
    let mut seen = HashSet::new();
    let mut managers = 0;
    let mut spenders = 0;
    let mut previous = None;
    if devices.is_empty() || devices.len() > 8 {
        return Err("account device count invalid".into());
    }
    for device in devices {
        let key = device["public_key"].as_str().ok_or("invalid device key")?;
        public_key(key)?;
        if !seen.insert(key) {
            return Err("duplicate account device".into());
        }
        if previous.is_some_and(|v| v >= key) {
            return Err("noncanonical account device order".into());
        }
        previous = Some(key);
        let manage = device["can_manage"]
            .as_bool()
            .ok_or("invalid managing permission")?;
        let spend = device["can_spend"]
            .as_bool()
            .ok_or("invalid spending permission")?;
        managers += usize::from(manage);
        spenders += usize::from(spend);
    }
    if managers == 0 || spenders == 0 {
        return Err("account lacks managing or spending authority".into());
    }
    if state_integer(&account["auth_epoch"], "account epoch")?
        > state_integer(&account["nonce"], "account nonce")?
    {
        return Err("account authority epoch exceeds nonce".into());
    }
    let pools = meta["pools"].as_array().ok_or("invalid pool metadata")?;
    let delegations = account["delegations"]
        .as_array()
        .ok_or("invalid account delegations")?;
    if delegations.len() > pools.len() {
        return Err("too many delegations".into());
    }
    let mut operators = HashSet::new();
    for delegation in delegations {
        let operator = state_integer(&delegation["operator"], "delegation operator")?;
        let shares = state_integer(&delegation["shares"], "delegation shares")?;
        let pool = pools
            .iter()
            .find(|pool| state_integer(&pool["operator"], "operator").ok() == Some(operator))
            .ok_or("delegation names unknown pool")?;
        if !operators.insert(operator)
            || shares == 0
            || shares > state_integer(&pool["total_shares"], "pool shares")?
        {
            return Err("invalid delegation ownership".into());
        }
    }
    let unbonding = account["unbonding"]
        .as_array()
        .ok_or("invalid unbonding list")?;
    if unbonding.len() > 64 {
        return Err("too many unbonding entries".into());
    }
    let mut entries = HashSet::new();
    let mut escrow = 0u64;
    for entry in unbonding {
        let amount = state_integer(&entry["amount"], "unbond amount")?;
        let id = state_integer(&entry["id"], "unbond id")?;
        state_integer(&entry["unlock_elapsed_micros"], "unbond unlock")?;
        if amount == 0 || !entries.insert(id) {
            return Err("invalid/duplicate unbond entry".into());
        }
        escrow = escrow.checked_add(amount).ok_or("unbond sum overflow")?;
    }
    if escrow > state_integer(&meta["unbond_total"], "unbond aggregate")? {
        return Err("account escrow exceeds aggregate".into());
    }
    if let Some(policy) = account.get("recovery_policy").filter(|v| !v.is_null()) {
        let guardians = policy["guardians"].as_array().ok_or("invalid guardians")?;
        let accepted = policy["accepted"]
            .as_array()
            .ok_or("invalid accepted guardians")?;
        let threshold = state_integer(&policy["threshold"], "guardian threshold")?;
        let delay = state_integer(&policy["delay_seconds"], "recovery delay")?;
        if delay.checked_mul(1_000_000).is_none_or(|micros| {
            micros
                < state_integer(
                    &meta["config"]["recovery_min_delay_micros"],
                    "configured recovery delay",
                )
                .unwrap_or(u64::MAX)
        }) || !(2..=5).contains(&guardians.len())
            || threshold < 2
            || threshold as usize > guardians.len()
            || threshold as usize <= guardians.len() / 2
            || !(30..=2_592_000).contains(&delay)
        {
            return Err("invalid recovery quorum or delay".into());
        }
        let ids = guardians
            .iter()
            .map(|g| state_integer(g, "guardian id"))
            .collect::<Result<Vec<_>, _>>()?;
        if ids.contains(&id) || ids.windows(2).any(|w| w[0] >= w[1]) {
            return Err("invalid guardian identity/order".into());
        }
        let accepted = accepted
            .iter()
            .map(|g| state_integer(g, "accepted guardian"))
            .collect::<Result<Vec<_>, _>>()?;
        if accepted.windows(2).any(|w| w[0] >= w[1]) || accepted.iter().any(|id| !ids.contains(id))
        {
            return Err("invalid guardian consent set".into());
        }
        if state_integer(&account["recovery_version"], "recovery policy version")? == 0 {
            return Err("missing recovery policy version".into());
        }
    }
    Ok(())
}

fn active_recovery_cases(
    cases: &Value,
    account: &Value,
    elapsed: u64,
) -> Result<Vec<Value>, String> {
    let cases = cases.as_array().ok_or("invalid recovery cases")?;
    if cases.len() > 5 {
        return Err("too many recovery cases".into());
    }
    let id = state_integer(&account["id"], "account id")?;
    let epoch = state_integer(&account["auth_epoch"], "account epoch")?;
    let policy_version = account
        .get("recovery_version")
        .map(|v| state_integer(v, "policy version"))
        .transpose()?
        .unwrap_or(0);
    let mut result = Vec::new();
    let mut votes = HashSet::new();
    let mut last = None;
    for case in cases {
        if state_integer(&case["target"], "recovery target")? != id {
            return Err("recovery key/target mismatch".into());
        }
        public_key(
            case["new_public_key"]
                .as_str()
                .ok_or("invalid recovery key")?,
        )?;
        let recovery_id = case["recovery_id"]
            .as_str()
            .ok_or("invalid recovery identifier")?;
        public_key(recovery_id)?;
        if last.is_some_and(|v| v >= recovery_id) {
            return Err("recovery case order/duplicate identifier".into());
        }
        last = Some(recovery_id);
        let expiry = state_integer(&case["expires_elapsed_micros"], "recovery expiry")?;
        let case_epoch = state_integer(&case["auth_epoch"], "recovery epoch")?;
        let case_policy = state_integer(&case["policy_version"], "recovery policy version")?;
        // The incremental engine intentionally leaves authenticated inactive rows
        // until this target is touched. They confer no authority and no freeze.
        if expiry < elapsed || case_epoch != epoch || case_policy != policy_version {
            continue;
        }
        let approvals = case["approvals"]
            .as_array()
            .ok_or("invalid recovery approvals")?;
        let accepted = account["recovery_policy"]["accepted"]
            .as_array()
            .ok_or("recovery without active policy")?;
        let ids = approvals
            .iter()
            .map(|v| state_integer(v, "recovery approval"))
            .collect::<Result<Vec<_>, _>>()?;
        if ids.is_empty()
            || ids.windows(2).any(|w| w[0] >= w[1])
            || approvals.iter().any(|v| !accepted.contains(v))
            || ids.iter().any(|id| !votes.insert(*id))
        {
            return Err("invalid recovery approval set".into());
        }
        let threshold = state_integer(
            &account["recovery_policy"]["threshold"],
            "recovery threshold",
        )?;
        if !case["ready_elapsed_micros"].is_null() {
            let ready = state_integer(&case["ready_elapsed_micros"], "recovery ready time")?;
            let delay = state_integer(
                &account["recovery_policy"]["delay_seconds"],
                "recovery delay",
            )?
            .checked_mul(1_000_000)
            .ok_or("recovery delay overflow")?;
            if ready > expiry || ready < delay || ids.len() < threshold as usize {
                return Err("invalid recovery ready quorum/time".into());
            }
        } else if ids.len() >= threshold as usize {
            return Err("recovery quorum lacks ready time".into());
        }
        result.push(case.clone());
    }
    Ok(result)
}

pub fn authenticate_entries(
    entries: Vec<ProofEntry>,
    root: [u8; 32],
) -> Result<std::collections::BTreeMap<Vec<u8>, Option<Value>>, String> {
    if entries.is_empty() || entries.len() > MAX_ENTRIES {
        return Err("compact proof entry bound exceeded".into());
    }
    let mut rows = std::collections::BTreeMap::new();
    for entry in entries {
        if entry.key_hex.len() > 256
            || entry.key_hex.len() % 2 != 0
            || !entry
                .key_hex
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("invalid compact proof key".into());
        }
        let key = hex::decode(&entry.key_hex).map_err(|_| "invalid compact proof key")?;
        if key.is_empty() || rows.contains_key(&key) {
            return Err("empty/duplicate compact proof key".into());
        }
        let bytes = entry
            .value_b64
            .map(|encoded| {
                if encoded.len() > MAX_VALUE * 4 / 3 + 8 {
                    return Err("value exceeds compact proof limit");
                }
                let value = STANDARD
                    .decode(&encoded)
                    .map_err(|_| "invalid value base64")?;
                if value.len() > MAX_VALUE || STANDARD.encode(&value) != encoded {
                    return Err("noncanonical/oversized value base64");
                }
                Ok(value)
            })
            .transpose()?;
        entry
            .proof
            .verify(jmt::RootHash(root), key_hash(&key), bytes.as_deref())
            .map_err(|e| format!("invalid key/value proof: {e}"))?;
        if key.starts_with(b"account/") && bytes.as_ref().is_some_and(|b| b.len() > 32 * 1024) {
            return Err("account value exceeds protocol size limit".into());
        }
        let value = bytes
            .map(|value| {
                serde_json::from_slice::<Value>(&value)
                    .map_err(|_| "invalid authenticated value JSON")
            })
            .transpose()?;
        rows.insert(key, value);
    }
    Ok(rows)
}

type AuthenticatedRows = BTreeMap<Vec<u8>, Option<Value>>;
pub fn current_rows(
    proof: StateProof,
    trust: &Trust,
    now: f64,
) -> Result<(AuthenticatedRows, Value, [u8; 32]), String> {
    if proof.history_proofs.len() > 16 {
        return Err("history selection budget exceeded".into());
    }
    let now = light::now_micros(now)?;
    let trusted = trust
        .checkpoint
        .as_ref()
        .ok_or("CHECKPOINT_REQUIRED: advance the dynamic light client first")?;
    // Requiring this exact checkpoint prevents a caller from treating NEEDS_BISECTION as authority.
    if proof
        .light_block
        .signed_header
        .header
        .height
        .value()
        .to_string()
        != trusted.height
        || proof
            .light_block
            .signed_header
            .header
            .hash()
            .to_string()
            .to_lowercase()
            != trusted.block_hash
    {
        return Err(
            "CHECKPOINT_MISMATCH: proof must use the exact independently verified checkpoint"
                .into(),
        );
    }
    let checked = light::update(proof.light_block.clone(), trust, now)?;
    if checked["verified"] != true {
        return Err("HEADER_NOT_VERIFIED".into());
    }
    // The version in force is the one in this header, which the validators
    // certified; the state proven under it carries the same number (checked
    // below). A build that does not implement that version says so before it
    // reads a single row: it could not judge them. The check comes before
    // the freshness check because its answer stays true: the version of a
    // chain never goes down.
    let version = proof.light_block.signed_header.header.version.app;
    if version > light::KNOWN_VERSION {
        return Err(light::upgrade_required(version));
    }
    light::ensure_fresh(&proof.light_block, now)?;
    let header = &proof.light_block.signed_header.header;
    let root: [u8; 32] = header
        .app_hash
        .as_bytes()
        .try_into()
        .map_err(|_| "invalid application root")?;
    let rows = authenticate_entries(proof.entries, root)?;
    let meta = required(&rows, b"meta")?.clone();
    let height = decimal(&meta["height"], "state height")?;
    // The state at height h is proven under header h + 1, and that header
    // carries the version the state names: never a gateway's word, and never
    // a number written here.
    if decimal(&meta["protocol_version"], "protocol")? != version
        || height.checked_add(1) != Some(header.height.value())
        || canonical_u64(&proof.height, "proof height")? != height
    {
        return Err("state/header version or height mismatch".into());
    }
    if meta["network_id"] != trust.network_id
        || meta["genesis"]["chain_id"] != trust.chain_id
        || meta["genesis"]["genesis_time_micros"] != trust.genesis_time_micros
        || meta["config"]["ledger"] != meta["genesis"]
    {
        return Err("state differs from pinned network/genesis".into());
    }
    if meta["config"]["reward_version"] != json!(1) {
        return Err(
            "unsupported reward version; explicit proportional reward version one is required"
                .into(),
        );
    }
    if meta["config"]["history_version"] != json!(1) {
        return Err("V4 history version one is required".into());
    }
    if meta["config"]["bitcoin_receipt_version"] != json!(1)
        || decimal(
            &meta["config"]["recovery_approval_window_micros"],
            "recovery approval window",
        )? != 604_800_000_000
    {
        return Err("unsupported compact receipt or recovery approval configuration".into());
    }
    if decimal(
        &meta["config"]["registration"]["max_lifetime_micros"],
        "registration lifetime",
    )? != 86_400_000_000
        || decimal(
            &meta["config"]["registration"]["fee_micros"],
            "registration fee",
        )? < 1_000
    {
        return Err("unsupported paid registration configuration".into());
    }
    let time = decimal(&meta["time_micros"], "state time")?;
    let genesis = decimal(&meta["genesis"]["genesis_time_micros"], "genesis time")?;
    let elapsed = time.checked_sub(genesis).ok_or("state predates genesis")?;
    let header_time = header.time.unix_timestamp_nanos() / 1000;
    if i128::from(time) > header_time || header_time - i128::from(time) > light::FRESH_MICROS {
        return Err("committed state time differs from fresh header".into());
    }
    if decimal(&meta["account_count"], "account count")?
        > decimal(&meta["next_account_id"], "next account id")?
        || decimal(&meta["next_account_id"], "next account id")? == u64::MAX
    {
        return Err("invalid registry bounds".into());
    }
    for name in ["unbond_total", "next_unbond_id"] {
        if decimal(&meta[name], name)? != 0 {
            return Err("legacy economics forbidden on V4".into());
        }
    }
    for name in ["pools", "pool_share_totals", "auction_bids"] {
        if !meta[name].as_array().is_some_and(Vec::is_empty) {
            return Err("legacy economic collections forbidden on V4".into());
        }
    }
    let mut total = 0u64;
    for name in [
        "bank",
        "liquid_total",
        "pos_assets_total",
        "auction_reserve_total",
    ] {
        total = total
            .checked_add(decimal(&meta[name], name)?)
            .ok_or("supply overflow")?;
    }
    if total != elapsed {
        return Err("authenticated aggregate supply differs from elapsed minting".into());
    }
    Ok((rows, meta, root))
}

pub fn view(
    proof_json: &str,
    trust_json: &str,
    request_json: &str,
    now: f64,
) -> Result<Value, String> {
    let trust: Trust = parse(trust_json)?;
    let request: Selection = parse(request_json)?;
    if request.names.len() > 8
        || request.ids.len() > 8
        || request.public_keys.len() > 8
        || request.names.len() + request.ids.len() + request.public_keys.len() > 16
        || request.owners.len() > 16
        || request.candidates.len() > 16
        || request.epochs.len() > 8
        || request.blocks.len() > 16
    {
        return Err("selection budget exceeded".into());
    }
    let proof: StateProof = parse(proof_json)?;
    let history_proofs = proof.history_proofs.clone();
    let (rows, mut state, root) = current_rows(proof, &trust, now)?;
    let elapsed = decimal(&state["time_micros"], "time")?
        - decimal(&state["genesis"]["genesis_time_micros"], "genesis")?;
    let mut wanted = BTreeSet::new();
    let mut mandatory = BTreeSet::new();
    let mut names = serde_json::Map::new();
    let mut keys = serde_json::Map::new();
    for name in &request.names {
        let id = get(&rows, &name_key(name)?)?
            .map(|v| decimal(v, "name index"))
            .transpose()?;
        if let Some(id) = id {
            wanted.insert(id);
            mandatory.insert(id);
        }
        names.insert(
            name.clone(),
            id.map_or(Value::Null, |n| json!(n.to_string())),
        );
    }
    for id in &request.ids {
        wanted.insert(canonical_u64(id, "requested id")?);
    }
    for key in &request.public_keys {
        let id = get(&rows, &public_key(key)?)?
            .map(|v| decimal(v, "registration index"))
            .transpose()?;
        if let Some(id) = id {
            wanted.insert(id);
            mandatory.insert(id);
        }
        keys.insert(
            key.clone(),
            id.map_or(Value::Null, |n| json!(n.to_string())),
        );
    }
    let mut commits = Vec::new();
    if !state["name_commits"].as_array().is_some_and(Vec::is_empty) {
        return Err("global legacy name commitments are forbidden on sponsored V4".into());
    }
    for key in &request.public_keys {
        let raw = [
            b"registration/commit/".as_slice(),
            &hex::decode(key).map_err(|_| "invalid registration key")?,
        ]
        .concat();
        if let Some(commit) = get(&rows, &raw)? {
            if commit["public_key"].as_str() != Some(key.as_str()) {
                return Err("sponsored commitment key mismatch".into());
            }
            public_key(
                commit["commitment"]
                    .as_str()
                    .ok_or("invalid name commitment")?,
            )?;
            public_key(
                commit["entry_id"]
                    .as_str()
                    .ok_or("invalid registration entry")?,
            )?;
            if decimal(&commit["sponsor"], "registration sponsor")? == u64::MAX {
                return Err("reserved sponsor id".into());
            }
            let created = decimal(&commit["created_elapsed_micros"], "commit creation")?;
            let expiry = decimal(&commit["expires_elapsed_micros"], "commit expiry")?;
            if created > elapsed
                || expiry < created
                || expiry - created
                    > decimal(
                        &state["config"]["registration"]["max_lifetime_micros"],
                        "registration lifetime",
                    )?
                || decimal(&commit["height"], "commit height")?
                    > decimal(&state["height"], "state height")?
            {
                return Err("invalid sponsored commitment coordinates".into());
            }
            if expiry >= elapsed {
                commits.push(commit.clone());
            }
        }
    }
    state["name_commits"] = json!(commits);
    let explicit = wanted.clone();
    for id in &explicit {
        if let Some(account) = get(&rows, &raw_id(b"account/", *id))?
            && let Some(guardians) = account["recovery_policy"]["guardians"].as_array()
        {
            if guardians.len() > 5 {
                return Err("guardian budget".into());
            }
            for guardian in guardians {
                let id = decimal(guardian, "guardian")?;
                wanted.insert(id);
                mandatory.insert(id);
            }
        }
    }
    let mut accounts = Vec::new();
    let mut recovery = Vec::new();
    let mut security = Vec::new();
    let mut absent = Vec::new();
    for id in wanted {
        let Some(account) = get(&rows, &raw_id(b"account/", id))? else {
            if mandatory.contains(&id) {
                return Err("authenticated index or guardian refers to absent account".into());
            }
            absent.push(id.to_string());
            continue;
        };
        if decimal(&account["id"], "account id")? != id {
            return Err("account key mismatch".into());
        }
        validate_account(account, &state)?;
        let name = account["name"].as_str().ok_or("invalid account name")?;
        if decimal(required(&rows, &name_key(name)?)?, "name index")? != id {
            return Err("account name binding mismatch".into());
        }
        if decimal(&account["balance"], "balance")? > decimal(&state["liquid_total"], "liquid")? {
            return Err("account exceeds aggregate liquid".into());
        }
        if let Some(cases) = get(&rows, &raw_id(b"recovery/", id))? {
            recovery.extend(active_recovery_cases(cases, account, elapsed)?);
        }
        if request.include_security
            && explicit.contains(&id)
            && let Some(row) = get(&rows, &raw_id(b"security/", id))?
        {
            security.push(security_row(row, id)?);
        }
        accounts.push(account.clone());
    }
    for (name, id) in &names {
        if !id.is_null()
            && !accounts
                .iter()
                .any(|a| a["id"] == *id && a["name"] == *name)
        {
            return Err("name/account binding mismatch".into());
        }
    }
    for (key, id) in &keys {
        if !id.is_null()
            && !accounts
                .iter()
                .any(|a| a["id"] == *id && a["public_key"] == *key)
        {
            return Err("registration/account binding mismatch".into());
        }
    }
    state["accounts"] = json!(accounts);
    state["recovery_cases"] = json!(recovery);
    if request.include_security {
        state["security"] = json!(security);
    }
    if request.include_pos {
        state["pos"] = required(&rows, b"pos/meta")?.clone();
    }
    if request.include_bitcoin {
        state["bitcoin"] = required(&rows, b"bitcoin/meta")?.clone();
    }
    if request.include_policy {
        state["treasury"] = required(&rows, b"treasury/state")?.clone();
        state["receiving_policy"] = required(&rows, b"treasury/receiving")?.clone();
    }
    if request.include_upgrade {
        // `get` refuses a proof that has no entry for the key: a gateway that
        // leaves the entry out is never read as "no plan". Only a proof that
        // the row is absent gives null.
        let current = decimal(&state["protocol_version"], "protocol")?;
        state["upgrade"] = match get(&rows, UPGRADE_KEY)? {
            Some(row) => upgrade_row(row, current)?,
            None => Value::Null,
        };
    }
    for (field, prefix, ids) in [
        ("stake_owners", b"pos/owner/".as_slice(), &request.owners),
        (
            "candidates",
            b"pos/candidate/".as_slice(),
            &request.candidates,
        ),
    ] {
        let mut selected = serde_json::Map::new();
        for id in ids {
            let n = canonical_u64(id, "selection id")?;
            let row = get(&rows, &raw_id(prefix, n))?;
            if let Some(row) = row
                && decimal(&row["owner"], "row owner")? != n
            {
                return Err("PoS owner key mismatch".into());
            }
            selected.insert(id.clone(), row.cloned().unwrap_or(Value::Null));
        }
        state[field] = Value::Object(selected);
    }
    let mut release_times = serde_json::Map::new();
    for owner in &request.owners {
        let id = canonical_u64(owner, "stake owner")?;
        if let Some(row) = get(&rows, &raw_id(b"pos/owner/", id))? {
            let exits = row["exits"]
                .as_array()
                .ok_or("invalid selected owner exits")?;
            if exits.len() > 64 {
                return Err("selected exit budget exceeded".into());
            }
            for exit in exits {
                let height = decimal(&exit["release_height"], "exit release height")?;
                if decimal(&exit["requested_height"], "exit request height")?.checked_add(2)
                    != Some(height)
                {
                    return Err("exit release coordinate mismatch".into());
                }
                let clock = get(&rows, &raw_id(b"pos/release_time/", height))?;
                if let Some(clock) = clock {
                    let time = decimal(clock, "retained exit release clock")?;
                    if height > decimal(&state["height"], "state height")?
                        || time > decimal(&state["time_micros"], "state time")?
                        || time < decimal(&state["genesis"]["genesis_time_micros"], "genesis time")?
                    {
                        return Err(
                            "exit release clock outside authenticated chain coordinates".into()
                        );
                    }
                } else if height <= decimal(&state["height"], "state height")? {
                    return Err("live exit lacks retained release clock".into());
                }
                release_times.insert(height.to_string(), clock.cloned().unwrap_or(Value::Null));
            }
        }
    }
    state["release_times"] = json!(release_times);
    let mut epochs = serde_json::Map::new();
    let mut bids = serde_json::Map::new();
    for epoch in &request.epochs {
        let e = canonical_u64(epoch, "epoch")?;
        let row = get(&rows, &raw_id(b"auction/epoch/", e))?;
        if let Some(row) = row
            && decimal(&row["epoch"], "epoch row")? != e
        {
            return Err("epoch key mismatch".into());
        }
        epochs.insert(epoch.clone(), row.cloned().unwrap_or(Value::Null));
        for id in &explicit {
            let raw = [
                b"auction/bid/".as_slice(),
                &e.to_be_bytes(),
                &id.to_be_bytes(),
            ]
            .concat();
            let row = get(&rows, &raw)?;
            if let Some(row) = row
                && (decimal(&row["owner"], "bid owner")? != *id
                    || decimal(&row["epoch"], "bid epoch")? != e)
            {
                return Err("bid key mismatch".into());
            }
            bids.insert(format!("{epoch}:{id}"), row.cloned().unwrap_or(Value::Null));
        }
    }
    state["earning_epochs"] = json!(epochs);
    state["earning_bids"] = json!(bids);
    let mut blocks = serde_json::Map::new();
    if !request.blocks.is_empty() {
        let summary = history_summary(&rows, &state, &trust)?;
        for height in &request.blocks {
            let n = canonical_u64(height, "block height")?;
            let proof = history_proofs
                .get(height)
                .ok_or("requested canonical history proof missing")?;
            let leaf = proof
                .verify(&summary)
                .map_err(|e| format!("invalid canonical history inclusion: {e}"))?;
            if leaf.height != n {
                return Err("canonical history height/key mismatch".into());
            }
            blocks.insert(
                height.clone(),
                json!({"hash":leaf.block_hash,"time_micros":leaf.time_micros.to_string()}),
            );
        }
    }
    state["canonical_blocks"] = json!(blocks);
    Ok(
        json!({"verified":true,"height":state["height"],"state":state,"root":hex::encode(root),"checkpoint":trust.checkpoint,"names":names,"registrationKeys":keys,"absentAccountIds":absent,"completeAccountSet":false,"verificationMode":"dynamic-validator-light-client-and-compact-jmt","supplyVerification":"authenticated-aggregate-counters; independent-global-recount-not-performed"}),
    )
}

pub fn history_summary(
    rows: &AuthenticatedRows,
    meta: &Value,
    trust: &Trust,
) -> Result<history::Summary, String> {
    let summary: history::Summary =
        serde_json::from_value(required(rows, history::KEY)?.clone())
            .map_err(|e| format!("invalid canonical history summary: {e}"))?;
    summary
        .validate()
        .map_err(|e| format!("invalid canonical history root: {e}"))?;
    if summary.network_id != trust.network_id
        || summary.size != decimal(&meta["height"], "history state height")?
        || summary.last_time_micros != decimal(&meta["time_micros"], "history state time")?
    {
        return Err("canonical history summary network/height/time mismatch".into());
    }
    Ok(summary)
}
