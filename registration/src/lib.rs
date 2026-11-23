//! Paid commitments are independent JMT rows; no global pending-name array.
//! Hosts MUST stage every mutation and money movement in one atomic action.
//! Failed actions must discard the stage, including fees and partial writes.
use anyhow::{Result, anyhow, ensure};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

pub const DAY: u64 = 86_400_000_000;
pub const HOUR: u64 = 3_600_000_000;
pub const BUCKETS: usize = 25;
pub const CLEANUP_LIMIT: usize = 128;
pub const STATE_KEY: &[u8] = b"registration/meta";
pub const CONSENT_DOMAIN: &[u8] = b"TIME-REGISTER-SPONSOR-V1\0";
const ENTRY_DOMAIN: &[u8] = b"TIME-REGISTER-ENTRY-V1\0";

pub mod decimal {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        let value: u64 = text.parse().map_err(D::Error::custom)?;
        if value.to_string() != text {
            return Err(D::Error::custom("noncanonical u64"));
        }
        Ok(value)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(with = "decimal")]
    pub fee_micros: u64,
    #[serde(with = "decimal")]
    pub max_lifetime_micros: u64,
    #[serde(with = "decimal")]
    pub bucket_micros: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            fee_micros: 10_000,
            max_lifetime_micros: DAY,
            bucket_micros: HOUR,
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.fee_micros >= 1_000,
            "registration fee below protocol minimum"
        );
        ensure!(
            self.max_lifetime_micros == DAY,
            "registration maximum lifetime must be one day"
        );
        ensure!(
            self.bucket_micros > 0 && self.bucket_micros <= DAY,
            "invalid registration bucket period"
        );
        ensure!(
            DAY.div_ceil(self.bucket_micros) < BUCKETS as u64,
            "registration expiry index exceeds twenty-five buckets"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitInput {
    pub public_key: String,
    pub commitment: String,
    #[serde(with = "decimal")]
    pub expires_elapsed_micros: u64,
    pub proof: String,
}
#[derive(Clone, Copy, Debug)]
pub struct Context {
    pub network: [u8; 32],
    pub sponsor: u64,
    pub elapsed_micros: u64,
    pub height: u64,
}
pub trait Reader {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
}
pub trait Host: Reader {
    fn put(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) -> Result<()>;
    fn registered(&self, public_key: &[u8; 32]) -> Result<bool>;
    fn debit(&mut self, sponsor: u64, amount: u64) -> Result<()>;
    fn bank_credit(&mut self, amount: u64) -> Result<()>;
}
pub trait Scanner: Reader {
    fn registered(&self, public_key: &[u8; 32]) -> Result<bool>;
    fn sponsor_exists(&self, sponsor: u64) -> Result<bool>;
    fn for_each_prefix<F>(&self, prefix: &[u8], visit: F) -> Result<()>
    where
        F: FnMut(&[u8], &[u8]) -> Result<()>;
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bucket {
    pub head: Option<String>,
    pub tail: Option<String>,
    #[serde(with = "decimal")]
    pub entries: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub network: String,
    pub config: Config,
    pub buckets: [Bucket; BUCKETS],
    pub cleanup_cursor: u8,
    #[serde(with = "decimal")]
    pub next_sequence: u64,
    #[serde(with = "decimal")]
    pub queue_entries: u64,
    #[serde(with = "decimal")]
    pub commitments: u64,
    #[serde(with = "decimal")]
    pub last_elapsed_micros: u64,
    #[serde(with = "decimal")]
    pub last_height: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub public_key: String,
    pub commitment: String,
    pub entry_id: String,
    #[serde(with = "decimal")]
    pub sponsor: u64,
    #[serde(with = "decimal")]
    pub expires_elapsed_micros: u64,
    #[serde(with = "decimal")]
    pub created_elapsed_micros: u64,
    #[serde(with = "decimal")]
    pub height: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub commit: Commit,
    #[serde(with = "decimal")]
    pub sequence: u64,
    pub next: Option<String>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cleanup {
    pub removed_entries: u64,
    pub removed_commitments: u64,
    pub examined_heads: u64,
}
pub fn key32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value)?;
    ensure!(hex::encode(&bytes) == value, "noncanonical hexadecimal");
    bytes
        .try_into()
        .map_err(|_| anyhow!("expected thirty-two bytes"))
}
pub fn commit_key(public_key: &[u8; 32]) -> Vec<u8> {
    [b"registration/commit/".as_slice(), public_key].concat()
}
pub fn entry_key(entry_id: &str) -> Result<Vec<u8>> {
    Ok([b"registration/entry/".as_slice(), &key32(entry_id)?].concat())
}
pub fn consent_bytes(
    network: [u8; 32],
    sponsor: u64,
    public_key: [u8; 32],
    commitment: [u8; 32],
    expiry: u64,
) -> Vec<u8> {
    let mut bytes = CONSENT_DOMAIN.to_vec();
    bytes.extend(network);
    bytes.extend(sponsor.to_be_bytes());
    bytes.extend(public_key);
    bytes.extend(commitment);
    bytes.extend(expiry.to_be_bytes());
    bytes
}
fn public_key(value: &str) -> Result<[u8; 32]> {
    let raw = key32(value)?;
    let key = VerifyingKey::from_bytes(&raw)?;
    ensure!(!key.is_weak(), "weak registration key");
    Ok(raw)
}
fn read<T: DeserializeOwned + Serialize>(reader: &impl Reader, key: &[u8]) -> Result<Option<T>> {
    reader
        .get(key)?
        .map(|bytes| {
            let row: T = serde_json::from_slice(&bytes)?;
            ensure!(
                serde_json::to_vec(&row)? == bytes,
                "noncanonical registration row"
            );
            Ok(row)
        })
        .transpose()
}
fn write(host: &mut impl Host, key: Vec<u8>, value: &impl Serialize) -> Result<()> {
    host.put(key, Some(serde_json::to_vec(value)?))
}
pub fn state(reader: &impl Reader, config: &Config, network: [u8; 32]) -> Result<State> {
    config.validate()?;
    let state: State =
        read(reader, STATE_KEY)?.ok_or_else(|| anyhow!("missing registration state"))?;
    ensure!(
        state.network == hex::encode(network)
            && state.config == *config
            && usize::from(state.cleanup_cursor) < BUCKETS,
        "registration state context mismatch"
    );
    let mut entries = 0u64;
    for bucket in &state.buckets {
        ensure!(
            bucket.head.is_some() == bucket.tail.is_some()
                && bucket.head.is_some() == (bucket.entries > 0),
            "registration queue endpoints mismatch"
        );
        if let Some(head) = &bucket.head {
            key32(head)?;
        }
        if let Some(tail) = &bucket.tail {
            key32(tail)?;
        }
        entries = entries
            .checked_add(bucket.entries)
            .ok_or_else(|| anyhow!("registration count overflow"))?;
    }
    ensure!(
        entries == state.queue_entries
            && state.commitments <= entries
            && entries <= state.next_sequence,
        "registration state counts mismatch"
    );
    Ok(state)
}
fn context(state: &State, context: Context) -> Result<()> {
    ensure!(
        state.last_elapsed_micros <= context.elapsed_micros && state.last_height <= context.height,
        "registration clock moved backwards"
    );
    Ok(())
}
fn slot(config: &Config, expiry: u64) -> usize {
    ((expiry / config.bucket_micros) % BUCKETS as u64) as usize
}
fn identity(network: [u8; 32], sequence: u64, commit: &Commit) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(ENTRY_DOMAIN);
    hash.update(network);
    hash.update(sequence.to_be_bytes());
    hash.update(commit.sponsor.to_be_bytes());
    hash.update(key32(&commit.public_key)?);
    hash.update(key32(&commit.commitment)?);
    hash.update(commit.expires_elapsed_micros.to_be_bytes());
    hash.update(commit.created_elapsed_micros.to_be_bytes());
    hash.update(commit.height.to_be_bytes());
    Ok(hex::encode(hash.finalize()))
}
fn validate_entry(entry: &Entry, state: &State, context: Context) -> Result<()> {
    public_key(&entry.commit.public_key)?;
    key32(&entry.commit.commitment)?;
    ensure!(
        entry.sequence < state.next_sequence
            && entry.commit.entry_id == identity(context.network, entry.sequence, &entry.commit)?,
        "registration entry identity mismatch"
    );
    ensure!(
        entry.commit.height > 0
            && entry.commit.height <= context.height
            && entry.commit.created_elapsed_micros <= context.elapsed_micros,
        "registration creation coordinates invalid"
    );
    ensure!(
        entry.commit.expires_elapsed_micros > entry.commit.created_elapsed_micros
            && entry.commit.expires_elapsed_micros - entry.commit.created_elapsed_micros
                <= state.config.max_lifetime_micros,
        "registration expiry interval invalid"
    );
    if let Some(next) = &entry.next {
        key32(next)?;
        ensure!(next != &entry.commit.entry_id, "registration self-cycle");
    }
    Ok(())
}
fn entry(reader: &impl Reader, state: &State, context: Context, id: &str) -> Result<Entry> {
    let entry: Entry = read(reader, &entry_key(id)?)?
        .ok_or_else(|| anyhow!("missing registration queue entry"))?;
    validate_entry(&entry, state, context)?;
    ensure!(
        entry.commit.entry_id == id,
        "registration entry alias mismatch"
    );
    Ok(entry)
}
pub fn initialize(host: &mut impl Host, config: &Config, network: [u8; 32]) -> Result<()> {
    config.validate()?;
    ensure!(
        host.get(STATE_KEY)?.is_none(),
        "registration already initialized"
    );
    write(
        host,
        STATE_KEY.to_vec(),
        &State {
            network: hex::encode(network),
            config: config.clone(),
            buckets: std::array::from_fn(|_| Bucket::default()),
            cleanup_cursor: 0,
            next_sequence: 0,
            queue_entries: 0,
            commitments: 0,
            last_elapsed_micros: 0,
            last_height: 0,
        },
    )
}
pub fn get_commit(
    reader: &impl Reader,
    config: &Config,
    context: Context,
    key: &[u8; 32],
) -> Result<Option<Commit>> {
    let state = state(reader, config, context.network)?;
    self::context(&state, context)?;
    let found: Option<Commit> = read(reader, &commit_key(key))?;
    if let Some(commit) = &found {
        ensure!(
            key32(&commit.public_key)? == *key,
            "registration public-key alias mismatch"
        );
        let node = entry(reader, &state, context, &commit.entry_id)?;
        ensure!(node.commit == *commit, "registration commit/queue mismatch");
    }
    Ok(found)
}
pub fn commit(
    host: &mut impl Host,
    config: &Config,
    context: Context,
    input: CommitInput,
) -> Result<Commit> {
    let mut state = state(host, config, context.network)?;
    self::context(&state, context)?;
    ensure!(
        context.height > 0,
        "registration requires an accepted block"
    );
    let public = public_key(&input.public_key)?;
    let commitment = key32(&input.commitment)?;
    ensure!(
        !host.registered(&public)?,
        "registration key already belongs to an account"
    );
    ensure!(
        input.expires_elapsed_micros > context.elapsed_micros
            && input.expires_elapsed_micros - context.elapsed_micros <= config.max_lifetime_micros,
        "registration expiry outside allowed lifetime"
    );
    let proof = hex::decode(&input.proof)?;
    ensure!(
        proof.len() == 64 && hex::encode(&proof) == input.proof,
        "noncanonical registration consent"
    );
    VerifyingKey::from_bytes(&public)?.verify_strict(
        &consent_bytes(
            context.network,
            context.sponsor,
            public,
            commitment,
            input.expires_elapsed_micros,
        ),
        &Signature::from_slice(&proof)?,
    )?;
    let old = get_commit(host, config, context, &public)?;
    ensure!(
        old.as_ref()
            .is_none_or(|old| old.expires_elapsed_micros < context.elapsed_micros),
        "unexpired registration commitment already exists"
    );
    let sequence = state.next_sequence;
    state.next_sequence = sequence
        .checked_add(1)
        .ok_or_else(|| anyhow!("registration sequence exhausted"))?;
    state.queue_entries = state
        .queue_entries
        .checked_add(1)
        .ok_or_else(|| anyhow!("registration queue count exhausted"))?;
    if old.is_none() {
        state.commitments = state
            .commitments
            .checked_add(1)
            .ok_or_else(|| anyhow!("registration commitment count exhausted"))?;
    }
    let mut record = Commit {
        public_key: input.public_key,
        commitment: input.commitment,
        entry_id: String::new(),
        sponsor: context.sponsor,
        expires_elapsed_micros: input.expires_elapsed_micros,
        created_elapsed_micros: context.elapsed_micros,
        height: context.height,
    };
    record.entry_id = identity(context.network, sequence, &record)?;
    let index = slot(config, record.expires_elapsed_micros);
    let mut tail = state.buckets[index]
        .tail
        .as_ref()
        .map(|id| entry(host, &state, context, id))
        .transpose()?;
    if let Some(tail) = &tail {
        ensure!(
            tail.next.is_none()
                && slot(config, tail.commit.expires_elapsed_micros) == index
                && tail.sequence < sequence,
            "registration queue tail invalid"
        );
    }
    ensure!(
        host.get(&entry_key(&record.entry_id)?)?.is_none(),
        "registration entry collision"
    );
    state.buckets[index].entries = state.buckets[index]
        .entries
        .checked_add(1)
        .ok_or_else(|| anyhow!("registration bucket count exhausted"))?;
    state.buckets[index].tail = Some(record.entry_id.clone());
    if state.buckets[index].head.is_none() {
        state.buckets[index].head = Some(record.entry_id.clone());
    }
    state.last_elapsed_micros = context.elapsed_micros;
    state.last_height = context.height;
    host.debit(context.sponsor, config.fee_micros)?;
    host.bank_credit(config.fee_micros)?;
    if let Some(tail) = &mut tail {
        tail.next = Some(record.entry_id.clone());
        write(host, entry_key(&tail.commit.entry_id)?, tail)?;
    }
    write(
        host,
        entry_key(&record.entry_id)?,
        &Entry {
            commit: record.clone(),
            sequence,
            next: None,
        },
    )?;
    write(host, commit_key(&public), &record)?;
    write(host, STATE_KEY.to_vec(), &state)?;
    Ok(record)
}
pub fn consume(
    host: &mut impl Host,
    config: &Config,
    context: Context,
    key: &[u8; 32],
    expected_id: &str,
) -> Result<()> {
    let mut state = state(host, config, context.network)?;
    self::context(&state, context)?;
    let commit = get_commit(host, config, context, key)?
        .ok_or_else(|| anyhow!("registration commitment missing or consumed"))?;
    ensure!(
        commit.entry_id == expected_id
            && commit.expires_elapsed_micros >= context.elapsed_micros
            && context.height > commit.height,
        "registration commitment changed or expired"
    );
    state.commitments = state
        .commitments
        .checked_sub(1)
        .ok_or_else(|| anyhow!("registration commitment count underflow"))?;
    state.last_elapsed_micros = context.elapsed_micros;
    state.last_height = context.height;
    host.put(commit_key(key), None)?;
    write(host, STATE_KEY.to_vec(), &state)
}
pub fn cleanup(
    host: &mut impl Host,
    config: &Config,
    context: Context,
    budget: usize,
) -> Result<Cleanup> {
    ensure!(
        budget <= CLEANUP_LIMIT,
        "registration cleanup budget exceeds protocol bound"
    );
    let mut state = state(host, config, context.network)?;
    self::context(&state, context)?;
    let mut stats = Cleanup::default();
    for _ in 0..BUCKETS {
        if stats.removed_entries as usize >= budget {
            break;
        }
        let index = usize::from(state.cleanup_cursor);
        state.cleanup_cursor = ((index + 1) % BUCKETS) as u8;
        while (stats.removed_entries as usize) < budget {
            let Some(id) = state.buckets[index].head.clone() else {
                break;
            };
            let node = entry(host, &state, context, &id)?;
            stats.examined_heads += 1;
            ensure!(
                slot(config, node.commit.expires_elapsed_micros) == index,
                "registration queue bucket mismatch"
            );
            if node.commit.expires_elapsed_micros >= context.elapsed_micros {
                break;
            }
            let key = public_key(&node.commit.public_key)?;
            let current: Option<Commit> = read(host, &commit_key(&key))?;
            if let Some(current) = current {
                ensure!(
                    current.public_key == node.commit.public_key,
                    "registration alias key mismatch"
                );
                if current.entry_id == id {
                    ensure!(current == node.commit, "registration alias record mismatch");
                    host.put(commit_key(&key), None)?;
                    state.commitments = state
                        .commitments
                        .checked_sub(1)
                        .ok_or_else(|| anyhow!("registration count underflow"))?;
                    stats.removed_commitments += 1;
                }
            }
            let bucket = &mut state.buckets[index];
            bucket.entries = bucket
                .entries
                .checked_sub(1)
                .ok_or_else(|| anyhow!("registration bucket underflow"))?;
            bucket.head = node.next.clone();
            if bucket.head.is_none() {
                ensure!(
                    bucket.tail.as_ref() == Some(&id) && bucket.entries == 0,
                    "registration final queue link mismatch"
                );
                bucket.tail = None;
            } else {
                ensure!(
                    bucket.tail.as_ref() != Some(&id) && bucket.entries > 0,
                    "registration intermediate queue link mismatch"
                );
            }
            host.put(entry_key(&id)?, None)?;
            state.queue_entries = state
                .queue_entries
                .checked_sub(1)
                .ok_or_else(|| anyhow!("registration queue underflow"))?;
            stats.removed_entries += 1;
        }
    }
    state.last_elapsed_micros = context.elapsed_micros;
    state.last_height = context.height;
    write(host, STATE_KEY.to_vec(), &state)?;
    Ok(stats)
}

/// Full streaming semantic audit. Queue sequence monotonicity excludes cycles
/// without retaining an unbounded visited set; namespace cardinality excludes
/// orphan rows. Merkle/value authentication is the caller's separate boundary.
pub fn audit(reader: &impl Scanner, config: &Config, context: Context) -> Result<u64> {
    let state = state(reader, config, context.network)?;
    self::context(&state, context)?;
    // Merge twenty-five monotonic queues to prove global sequence uniqueness
    // with a constant-size frontier, including duplicates in different buckets.
    let mut frontier = state
        .buckets
        .iter()
        .map(|bucket| {
            bucket
                .head
                .as_ref()
                .map(|id| entry(reader, &state, context, id))
                .transpose()
        })
        .collect::<Result<Vec<_>>>()?;
    let mut counts = [0u64; BUCKETS];
    let mut previous = None;
    let mut queued = 0u64;
    while let Some(index) = frontier
        .iter()
        .enumerate()
        .filter_map(|(index, node)| node.as_ref().map(|node| (index, node.sequence)))
        .min_by_key(|(_, sequence)| *sequence)
        .map(|(index, _)| index)
    {
        let node = frontier[index]
            .take()
            .ok_or_else(|| anyhow!("missing audit frontier"))?;
        ensure!(
            slot(config, node.commit.expires_elapsed_micros) == index
                && previous.is_none_or(|sequence| node.sequence > sequence),
            "registration global queue order/cycle mismatch"
        );
        previous = Some(node.sequence);
        ensure!(
            reader.sponsor_exists(node.commit.sponsor)?,
            "registration sponsor account missing"
        );
        counts[index] = counts[index]
            .checked_add(1)
            .ok_or_else(|| anyhow!("audit queue overflow"))?;
        ensure!(
            counts[index] <= state.buckets[index].entries,
            "registration queue count exceeded"
        );
        queued = queued
            .checked_add(1)
            .ok_or_else(|| anyhow!("audit queue overflow"))?;
        if let Some(next) = node.next {
            let following = entry(reader, &state, context, &next)?;
            ensure!(
                following.sequence > node.sequence,
                "registration backward queue link"
            );
            frontier[index] = Some(following);
        } else {
            ensure!(
                state.buckets[index].tail.as_ref() == Some(&node.commit.entry_id),
                "registration queue tail mismatch"
            );
        }
    }
    for (index, bucket) in state.buckets.iter().enumerate() {
        ensure!(
            counts[index] == bucket.entries,
            "registration queue endpoint/count mismatch"
        );
    }
    ensure!(
        queued == state.queue_entries,
        "registration queue total mismatch"
    );
    let mut actual_entries = 0u64;
    reader.for_each_prefix(b"registration/entry/", |key, value| {
        let row: Entry = serde_json::from_slice(value)?;
        ensure!(
            serde_json::to_vec(&row)? == value && key == entry_key(&row.commit.entry_id)?,
            "registration entry directory mismatch"
        );
        validate_entry(&row, &state, context)?;
        actual_entries += 1;
        Ok(())
    })?;
    ensure!(actual_entries == queued, "orphan registration queue entry");
    let mut commits = 0u64;
    reader.for_each_prefix(b"registration/commit/", |key, value| {
        let row: Commit = serde_json::from_slice(value)?;
        ensure!(
            serde_json::to_vec(&row)? == value && key == commit_key(&public_key(&row.public_key)?),
            "registration commit directory mismatch"
        );
        ensure!(
            entry(reader, &state, context, &row.entry_id)?.commit == row,
            "registration dangling commit"
        );
        ensure!(
            !reader.registered(&public_key(&row.public_key)?)?,
            "registered account retains pending commitment"
        );
        commits += 1;
        Ok(())
    })?;
    ensure!(
        commits == state.commitments,
        "registration commitment count mismatch"
    );
    let expected = 1u64
        .checked_add(queued)
        .and_then(|n| n.checked_add(commits))
        .ok_or_else(|| anyhow!("audit namespace overflow"))?;
    let mut total = 0u64;
    reader.for_each_prefix(b"registration/", |_, _| {
        total += 1;
        Ok(())
    })?;
    ensure!(total == expected, "unknown registration namespace row");
    Ok(expected)
}
