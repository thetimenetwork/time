//! Atomic application commits for the development-network foundation.
//!
//! Every acknowledged commit uses redb's immediate durability and updates the
//! head reference and immutable height record in one transaction. The state is
//! an opaque, bounded snapshot; its application hash must be SHA-256 of those
//! exact bytes. This module is not a signer, a backup authenticator, a pruning
//! policy, or evidence that a particular filesystem survives physical power loss.

use redb::backends::FileBackend;
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::path::Path;

pub const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
const CACHE_BYTES: usize = 64 * 1024 * 1024;
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata-v1");
const RECORDS: TableDefinition<u64, &[u8]> = TableDefinition::new("commits-v1");
const HEAD: &str = "head";
const MAGIC: &[u8; 8] = b"TCSTR001";
const ENVELOPE_BYTES: usize = 8 + 8 + 4 * 32 + 4;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub height: i64,
    pub app_hash: Vec<u8>,
    pub state: Vec<u8>,
    pub block_hash: Vec<u8>,
    pub parent_app_hash: Vec<u8>,
    #[serde(default)]
    pub request_hash: Vec<u8>,
}

#[derive(Debug)]
pub struct StoreError(String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

type Result<T> = std::result::Result<T, StoreError>;

fn invalid(message: &str) -> StoreError {
    StoreError(message.to_owned())
}

fn storage(error: impl fmt::Display) -> StoreError {
    StoreError(format!("application storage: {error}"))
}

pub struct Store {
    db: Database,
    #[cfg(test)]
    fail_next_commit: std::sync::atomic::AtomicBool,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if path.as_os_str().is_empty() {
            return Err(invalid("database path is empty"));
        }
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
        if let Some(parent) = parent {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(parent).map_err(storage)?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(storage)?;
        let mut builder = Database::builder();
        builder.set_cache_size(CACHE_BYTES);
        // redb owns the OS file lock. Do not implement a second, weaker lock.
        let backend = FileBackend::new(file).map_err(storage)?;
        let db = builder.create_with_backend(backend).map_err(storage)?;
        {
            let mut transaction = db.begin_write().map_err(storage)?;
            transaction
                .set_durability(Durability::Immediate)
                .map_err(storage)?;
            transaction.open_table(META).map_err(storage)?;
            transaction.open_table(RECORDS).map_err(storage)?;
            transaction.commit().map_err(storage)?;
        }
        #[cfg(unix)]
        if let Some(parent) = parent {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(storage)?;
        }
        let store = Self {
            db,
            #[cfg(test)]
            fail_next_commit: std::sync::atomic::AtomicBool::new(false),
        };
        // Fail opening a logically inconsistent head; never quietly reinitialize.
        store.load()?;
        Ok(store)
    }

    pub fn load(&self) -> Result<Option<Record>> {
        let transaction = self.db.begin_read().map_err(storage)?;
        let metadata = transaction.open_table(META).map_err(storage)?;
        let records = transaction.open_table(RECORDS).map_err(storage)?;
        let head = metadata
            .get(HEAD)
            .map_err(storage)?
            .map(|value| value.value().to_vec());
        load_head(
            head.as_deref(),
            records.last().map_err(storage)?.map(|(key, _)| key.value()),
            |height| {
                records
                    .get(height as u64)
                    .map_err(storage)?
                    .map(|value| decode_record(value.value(), height))
                    .transpose()
            },
        )
    }

    pub fn get(&self, height: i64) -> Result<Option<Record>> {
        if height < 0 {
            return Err(invalid("negative history height"));
        }
        let transaction = self.db.begin_read().map_err(storage)?;
        let metadata = transaction.open_table(META).map_err(storage)?;
        let records = transaction.open_table(RECORDS).map_err(storage)?;
        let head = metadata
            .get(HEAD)
            .map_err(storage)?
            .map(|value| value.value().to_vec());
        let current = load_head(
            head.as_deref(),
            records.last().map_err(storage)?.map(|(key, _)| key.value()),
            |height| {
                records
                    .get(height as u64)
                    .map_err(storage)?
                    .map(|value| decode_record(value.value(), height))
                    .transpose()
            },
        )?;
        if current
            .as_ref()
            .is_none_or(|current| height > current.height)
        {
            return Ok(None);
        }
        let record = records
            .get(height as u64)
            .map_err(storage)?
            .map(|value| decode_record(value.value(), height))
            .transpose()?
            .ok_or_else(|| invalid("committed history record is missing"))?;
        validate_parent(&record, |previous| {
            records
                .get(previous as u64)
                .map_err(storage)?
                .map(|value| decode_record(value.value(), previous))
                .transpose()
        })?;
        Ok(Some(record))
    }

    pub fn initialize(&self, record: &Record) -> Result<()> {
        if record.height != 0 {
            return Err(invalid("initialization requires height zero"));
        }
        self.write(record, true)
    }

    pub fn commit(&self, record: &Record) -> Result<()> {
        self.write(record, false)
    }

    #[cfg(test)]
    pub(crate) fn fail_next_commit_for_test(&self) {
        self.fail_next_commit
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn write(&self, record: &Record, initialization: bool) -> Result<()> {
        let encoded = encode_record(record)?;
        let mut transaction = self.db.begin_write().map_err(storage)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(storage)?;
        {
            let mut metadata = transaction.open_table(META).map_err(storage)?;
            let mut records = transaction.open_table(RECORDS).map_err(storage)?;
            let head = metadata
                .get(HEAD)
                .map_err(storage)?
                .map(|value| value.value().to_vec());
            let current = load_head(
                head.as_deref(),
                records.last().map_err(storage)?.map(|(key, _)| key.value()),
                |height| {
                    records
                        .get(height as u64)
                        .map_err(storage)?
                        .map(|value| decode_record(value.value(), height))
                        .transpose()
                },
            )?;
            match current {
                Some(current) if current.height == record.height => {
                    if current == *record {
                        return Ok(());
                    }
                    return Err(invalid("conflicting record at committed height"));
                }
                Some(_) if initialization => {
                    return Err(invalid("initialized database cannot be reset"));
                }
                None if !initialization => {
                    return Err(invalid("database has not been initialized"));
                }
                Some(current) => {
                    if current.height.checked_add(1) != Some(record.height) {
                        return Err(invalid("commit must advance exactly one height"));
                    }
                    if record.parent_app_hash != current.app_hash {
                        return Err(invalid(
                            "commit parent does not match current application hash",
                        ));
                    }
                }
                None => {}
            }
            if records
                .get(record.height as u64)
                .map_err(storage)?
                .is_some()
            {
                return Err(invalid("unreferenced history record would be overwritten"));
            }
            records
                .insert(record.height as u64, encoded.as_slice())
                .map_err(storage)?;
            let mut head = Vec::with_capacity(40);
            head.extend_from_slice(&record.height.to_be_bytes());
            head.extend_from_slice(&record.app_hash);
            metadata.insert(HEAD, head.as_slice()).map_err(storage)?;
        }
        #[cfg(test)]
        if self
            .fail_next_commit
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(invalid(
                "injected failure before durable transaction commit",
            ));
        }
        // No success is returned before both history and head are durable.
        transaction.commit().map_err(storage)
    }
}

fn validate_record(record: &Record) -> Result<()> {
    if record.height < 0 {
        return Err(invalid("negative committed height"));
    }
    if record.state.is_empty() || record.state.len() > MAX_STATE_BYTES {
        return Err(invalid(
            "state snapshot is empty or exceeds the milestone size limit",
        ));
    }
    if record.app_hash.len() != 32
        || Sha256::digest(&record.state).as_slice() != record.app_hash.as_slice()
    {
        return Err(invalid("state bytes do not match their application hash"));
    }
    if record.height == 0 {
        if !record.block_hash.is_empty()
            || !record.parent_app_hash.is_empty()
            || !record.request_hash.is_empty()
        {
            return Err(invalid(
                "genesis must not have block, parent or request hashes",
            ));
        }
    } else if record.block_hash.len() != 32
        || record.parent_app_hash.len() != 32
        || record.request_hash.len() != 32
    {
        return Err(invalid(
            "positive-height commit requires block, parent and request hashes",
        ));
    }
    Ok(())
}

fn encode_record(record: &Record) -> Result<Vec<u8>> {
    validate_record(record)?;
    let mut encoded = Vec::with_capacity(ENVELOPE_BYTES + record.state.len());
    encoded.extend_from_slice(MAGIC);
    encoded.extend_from_slice(&record.height.to_be_bytes());
    encoded.extend_from_slice(&record.app_hash);
    for hash in [
        &record.block_hash,
        &record.parent_app_hash,
        &record.request_hash,
    ] {
        if hash.is_empty() {
            encoded.extend_from_slice(&[0; 32]);
        } else {
            encoded.extend_from_slice(hash);
        }
    }
    encoded.extend_from_slice(&(record.state.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&record.state);
    Ok(encoded)
}

fn decode_record(encoded: &[u8], expected_height: i64) -> Result<Record> {
    if encoded.len() < ENVELOPE_BYTES
        || encoded.len() > ENVELOPE_BYTES + MAX_STATE_BYTES
        || &encoded[..8] != MAGIC
    {
        return Err(invalid("invalid stored record envelope"));
    }
    let height = i64::from_be_bytes(encoded[8..16].try_into().unwrap());
    let length = u32::from_be_bytes(encoded[144..148].try_into().unwrap()) as usize;
    if height != expected_height || length != encoded.len() - ENVELOPE_BYTES {
        return Err(invalid("stored record height or length mismatch"));
    }
    let genesis = height == 0;
    if genesis && encoded[48..144].iter().any(|byte| *byte != 0) {
        return Err(invalid("noncanonical genesis record envelope"));
    }
    let record = Record {
        height,
        app_hash: encoded[16..48].to_vec(),
        state: encoded[148..].to_vec(),
        block_hash: if genesis {
            vec![]
        } else {
            encoded[48..80].to_vec()
        },
        parent_app_hash: if genesis {
            vec![]
        } else {
            encoded[80..112].to_vec()
        },
        request_hash: if genesis {
            vec![]
        } else {
            encoded[112..144].to_vec()
        },
    };
    validate_record(&record)?;
    Ok(record)
}

fn validate_parent(
    record: &Record,
    mut get: impl FnMut(i64) -> Result<Option<Record>>,
) -> Result<()> {
    if record.height > 0 {
        let previous = get(record.height - 1)?
            .ok_or_else(|| invalid("committed record has no predecessor"))?;
        if previous.app_hash != record.parent_app_hash {
            return Err(invalid("stored record parent hash mismatch"));
        }
    }
    Ok(())
}

fn load_head(
    head: Option<&[u8]>,
    last_history_height: Option<u64>,
    mut get: impl FnMut(i64) -> Result<Option<Record>>,
) -> Result<Option<Record>> {
    let Some(head) = head else {
        if last_history_height.is_some() {
            return Err(invalid("history exists without a committed head"));
        }
        return Ok(None);
    };
    if head.len() != 40 {
        return Err(invalid("invalid committed head reference"));
    }
    let height = i64::from_be_bytes(head[..8].try_into().unwrap());
    if height < 0 {
        return Err(invalid("negative committed head reference"));
    }
    if last_history_height != Some(height as u64) {
        return Err(invalid("history tail does not match the committed head"));
    }
    let record = get(height)?.ok_or_else(|| invalid("committed head record is missing"))?;
    if record.app_hash != head[8..] {
        return Err(invalid("committed head hash does not match its record"));
    }
    validate_parent(&record, get)?;
    Ok(Some(record))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn record(height: i64, parent: &[u8], state: &[u8]) -> Record {
        Record {
            height,
            app_hash: Sha256::digest(state).to_vec(),
            state: state.to_vec(),
            block_hash: if height == 0 {
                vec![]
            } else {
                Sha256::digest([b"block/".as_slice(), state].concat()).to_vec()
            },
            parent_app_hash: parent.to_vec(),
            request_hash: if height == 0 {
                vec![]
            } else {
                Sha256::digest([b"request/".as_slice(), state].concat()).to_vec()
            },
        }
    }

    fn fixture() -> (TempDir, Store, Record) {
        let directory = TempDir::new().unwrap();
        let store = Store::open(&directory.path().join("state.redb")).unwrap();
        assert!(store.load().unwrap().is_none());
        let genesis = record(0, &[], br#"{"height":0}"#);
        store.initialize(&genesis).unwrap();
        (directory, store, genesis)
    }

    #[test]
    fn committed_head_and_history_survive_reopen() {
        let (directory, store, genesis) = fixture();
        let first = record(1, &genesis.app_hash, br#"{"height":1}"#);
        let second = record(2, &first.app_hash, br#"{"height":2}"#);
        store.commit(&first).unwrap();
        store.commit(&second).unwrap();
        drop(store);
        let reopened = Store::open(&directory.path().join("state.redb")).unwrap();
        assert_eq!(reopened.load().unwrap(), Some(second.clone()));
        for expected in [genesis, first, second] {
            assert_eq!(reopened.get(expected.height).unwrap(), Some(expected));
        }
        assert!(reopened.get(3).unwrap().is_none());
    }

    #[test]
    fn identical_current_retry_is_idempotent_but_conflicts_and_rollbacks_reject() {
        let (_directory, store, genesis) = fixture();
        store.initialize(&genesis).unwrap();
        let first = record(1, &genesis.app_hash, b"first");
        store.commit(&first).unwrap();
        store.commit(&first).unwrap();
        let changed = record(1, &genesis.app_hash, b"changed");
        assert!(store.commit(&changed).is_err());
        let mut changed = first.clone();
        changed.block_hash[0] ^= 1;
        assert!(store.commit(&changed).is_err());
        let mut changed = first.clone();
        changed.request_hash[0] ^= 1;
        assert!(store.commit(&changed).is_err());
        assert!(store.initialize(&genesis).is_err());
        assert!(store.commit(&genesis).is_err());
        assert_eq!(store.load().unwrap(), Some(first));
    }

    #[test]
    fn skipped_heights_and_wrong_parents_do_not_leave_partial_records() {
        let (_directory, store, genesis) = fixture();
        for bad in [
            record(2, &genesis.app_hash, b"skipped"),
            record(1, &[9; 32], b"wrong-parent"),
        ] {
            assert!(store.commit(&bad).is_err());
            assert_eq!(store.load().unwrap(), Some(genesis.clone()));
            assert!(store.get(bad.height).unwrap().is_none());
        }
    }

    #[test]
    fn malformed_records_and_initialization_errors_do_not_change_database() {
        let directory = TempDir::new().unwrap();
        let store = Store::open(&directory.path().join("state.redb")).unwrap();
        let genesis = record(0, &[], b"genesis");
        let next = record(1, &genesis.app_hash, b"next");
        assert!(store.commit(&next).is_err());
        assert!(store.initialize(&next).is_err());
        let mut cases = Vec::new();
        let mut bad = genesis.clone();
        bad.height = -1;
        cases.push(bad);
        let mut bad = genesis.clone();
        bad.app_hash.pop();
        cases.push(bad);
        let mut bad = genesis.clone();
        bad.app_hash[0] ^= 1;
        cases.push(bad);
        let mut bad = genesis.clone();
        bad.state.clear();
        cases.push(bad);
        let mut bad = genesis.clone();
        bad.state = vec![0; MAX_STATE_BYTES + 1];
        cases.push(bad);
        let mut bad = genesis.clone();
        bad.parent_app_hash = vec![0; 32];
        cases.push(bad);
        let mut bad = genesis.clone();
        bad.block_hash = vec![0; 32];
        cases.push(bad);
        let mut bad = genesis.clone();
        bad.request_hash = vec![0; 32];
        cases.push(bad);
        for bad in cases {
            assert!(store.initialize(&bad).is_err());
            assert!(store.load().unwrap().is_none());
        }
        assert!(store.get(-1).is_err());
    }

    #[test]
    fn loaded_state_buffers_are_detached() {
        let (_directory, store, mut genesis) = fixture();
        let expected = genesis.clone();
        genesis.app_hash[0] ^= 1;
        genesis.state[0] ^= 1;
        let mut loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded, expected);
        loaded.app_hash[0] ^= 1;
        loaded.state[0] ^= 1;
        assert_eq!(store.get(0).unwrap(), Some(expected));
    }

    #[test]
    fn database_has_one_writer_and_invalid_paths_fail() {
        let (directory, _store, _genesis) = fixture();
        assert!(Store::open(&directory.path().join("state.redb")).is_err());
        assert!(Store::open(Path::new("")).is_err());
        assert!(Store::open(directory.path()).is_err());
    }

    #[test]
    fn tampered_record_fails_closed_on_read_and_reopen() {
        let (directory, store, genesis) = fixture();
        let first = record(1, &genesis.app_hash, b"first");
        store.commit(&first).unwrap();
        {
            let transaction = store.db.begin_write().unwrap();
            {
                let mut table = transaction.open_table(RECORDS).unwrap();
                table.insert(1, b"corrupt".as_slice()).unwrap();
            }
            transaction.commit().unwrap();
        }
        assert!(store.load().is_err());
        assert!(store.get(1).is_err());
        drop(store);
        assert!(Store::open(&directory.path().join("state.redb")).is_err());
    }

    #[test]
    fn head_without_history_or_history_without_head_fails_closed() {
        let (_directory, store, genesis) = fixture();
        {
            let transaction = store.db.begin_write().unwrap();
            {
                let mut table = transaction.open_table(META).unwrap();
                table.remove(HEAD).unwrap();
            }
            transaction.commit().unwrap();
        }
        assert!(store.load().is_err());
        assert!(store.initialize(&genesis).is_err());
        {
            let transaction = store.db.begin_write().unwrap();
            {
                let mut table = transaction.open_table(META).unwrap();
                let mut head = 1_i64.to_be_bytes().to_vec();
                head.extend_from_slice(&[0; 32]);
                table.insert(HEAD, head.as_slice()).unwrap();
            }
            transaction.commit().unwrap();
        }
        assert!(store.load().is_err());
    }

    #[test]
    fn abandoned_transaction_changes_neither_head_nor_history() {
        let (_directory, store, genesis) = fixture();
        let next = record(1, &genesis.app_hash, b"next");
        {
            let transaction = store.db.begin_write().unwrap();
            {
                let mut table = transaction.open_table(RECORDS).unwrap();
                let encoded = encode_record(&next).unwrap();
                table.insert(1, encoded.as_slice()).unwrap();
            }
            // A failure before commit drops the entire transaction.
        }
        assert_eq!(store.load().unwrap(), Some(genesis));
        assert!(store.get(1).unwrap().is_none());
    }

    #[test]
    fn failure_after_writing_head_and_record_rolls_back_both() {
        let (_directory, store, genesis) = fixture();
        let next = record(1, &genesis.app_hash, b"next");
        store.fail_next_commit_for_test();
        assert!(store.commit(&next).is_err());
        assert_eq!(store.load().unwrap(), Some(genesis));
        assert!(store.get(1).unwrap().is_none());
        store.commit(&next).unwrap();
        assert_eq!(store.load().unwrap(), Some(next));
    }

    #[test]
    fn unreferenced_future_history_is_never_returned_as_committed() {
        let (_directory, store, genesis) = fixture();
        let next = record(1, &genesis.app_hash, b"unreferenced");
        let transaction = store.db.begin_write().unwrap();
        {
            let mut table = transaction.open_table(RECORDS).unwrap();
            let encoded = encode_record(&next).unwrap();
            table.insert(1, encoded.as_slice()).unwrap();
        }
        transaction.commit().unwrap();
        assert!(store.load().is_err());
        assert!(store.get(1).is_err());
        assert!(store.commit(&next).is_err());
    }

    #[test]
    fn missing_committed_historical_height_is_an_error() {
        let (_directory, store, genesis) = fixture();
        let first = record(1, &genesis.app_hash, b"first");
        let second = record(2, &first.app_hash, b"second");
        store.commit(&first).unwrap();
        store.commit(&second).unwrap();
        let transaction = store.db.begin_write().unwrap();
        {
            let mut table = transaction.open_table(RECORDS).unwrap();
            table.remove(0).unwrap();
        }
        transaction.commit().unwrap();
        assert!(store.get(0).is_err());
        assert!(store.get(1).is_err());
    }

    #[test]
    fn process_exit_after_commit_or_before_commit_preserves_atomicity() {
        for stage in ["committed", "uncommitted"] {
            let directory = TempDir::new().unwrap();
            let path = directory.path().join("exit.redb");
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::tests::process_exit_helper",
                    "--nocapture",
                ])
                .env("TIME_STORE_TEST_EXIT", &path)
                .env("TIME_STORE_TEST_STAGE", stage)
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(23), "helper did not run");
            let store = Store::open(&path).unwrap();
            let head = store.load().unwrap().unwrap();
            if stage == "committed" {
                assert_eq!(head.height, 1);
                assert!(store.get(1).unwrap().is_some());
            } else {
                assert_eq!(head.height, 0);
                assert!(store.get(1).unwrap().is_none());
            }
        }
    }

    #[test]
    fn process_exit_helper() {
        let Some(path) = std::env::var_os("TIME_STORE_TEST_EXIT") else {
            return;
        };
        let store = Store::open(Path::new(&path)).unwrap();
        let genesis = record(0, &[], b"genesis");
        store.initialize(&genesis).unwrap();
        let next = record(1, &genesis.app_hash, b"next");
        if std::env::var("TIME_STORE_TEST_STAGE").unwrap() == "committed" {
            store.commit(&next).unwrap();
        } else {
            let transaction = store.db.begin_write().unwrap();
            let mut table = transaction.open_table(RECORDS).unwrap();
            let encoded = encode_record(&next).unwrap();
            table.insert(1, encoded.as_slice()).unwrap();
            // Intentionally skip all Rust destructors, including rollback.
            std::process::exit(23);
        }
        // A process-exit test is not a physical power-loss test.
        std::process::exit(23);
    }
}
