use anyhow::{Result, anyhow};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
};
use time_registration::*;

#[test]
fn audit_rejects_duplicate_global_sequences_across_different_expiry_queues() {
    let (mut host, config, context) = fixture();
    commit(&mut host, &config, context, input(&key(1), context, 100)).unwrap();
    let old = commit(
        &mut host,
        &config,
        context,
        input(&key(2), context, HOUR + 1),
    )
    .unwrap();
    let mut node: Entry =
        serde_json::from_slice(&host.rows[&entry_key(&old.entry_id).unwrap()]).unwrap();
    node.sequence = 0;
    let c = &node.commit;
    let mut hash = Sha256::new();
    hash.update(b"TIME-REGISTER-ENTRY-V1\0");
    hash.update(context.network);
    hash.update(node.sequence.to_be_bytes());
    hash.update(c.sponsor.to_be_bytes());
    hash.update(key32(&c.public_key).unwrap());
    hash.update(key32(&c.commitment).unwrap());
    hash.update(c.expires_elapsed_micros.to_be_bytes());
    hash.update(c.created_elapsed_micros.to_be_bytes());
    hash.update(c.height.to_be_bytes());
    node.commit.entry_id = hex::encode(hash.finalize());
    host.rows.remove(&entry_key(&old.entry_id).unwrap());
    store(&mut host, &node, entry_key(&node.commit.entry_id).unwrap());
    store(
        &mut host,
        &node.commit,
        commit_key(key(2).verifying_key().as_bytes()),
    );
    let mut metadata = state(&host, &config, context.network).unwrap();
    metadata.buckets[1].head = Some(node.commit.entry_id.clone());
    metadata.buckets[1].tail = Some(node.commit.entry_id.clone());
    store(&mut host, &metadata, STATE_KEY.to_vec());
    assert!(audit(&host, &config, context).is_err());
}
#[test]
fn pure_consume_itself_refuses_same_block_before_identity_adapter() {
    let (mut host, config, context) = fixture();
    let record = commit(&mut host, &config, context, input(&key(1), context, 100)).unwrap();
    assert!(
        host.atomic(|h| consume(
            h,
            &config,
            context,
            key(1).verifying_key().as_bytes(),
            &record.entry_id
        ))
        .is_err()
    );
}
#[test]
fn full_audit_rejects_orphan_sponsor_account() {
    let (mut host, config, context) = fixture();
    commit(&mut host, &config, context, input(&key(1), context, 100)).unwrap();
    host.balances.remove(&7);
    assert!(audit(&host, &config, context).is_err());
}

#[derive(Clone, Default)]
struct Memory {
    rows: BTreeMap<Vec<u8>, Vec<u8>>,
    balances: BTreeMap<u64, u64>,
    bank: u64,
    registered: BTreeSet<[u8; 32]>,
    reads: Cell<usize>,
    fail_write: bool,
}
impl Reader for Memory {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.reads.set(self.reads.get() + 1);
        Ok(self.rows.get(key).cloned())
    }
}
impl Host for Memory {
    fn put(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) -> Result<()> {
        if self.fail_write {
            return Err(anyhow!("injected write failure"));
        }
        if let Some(value) = value {
            self.rows.insert(key, value);
        } else {
            self.rows.remove(&key);
        }
        Ok(())
    }
    fn registered(&self, key: &[u8; 32]) -> Result<bool> {
        Ok(self.registered.contains(key))
    }
    fn debit(&mut self, sponsor: u64, amount: u64) -> Result<()> {
        let balance = self
            .balances
            .get_mut(&sponsor)
            .ok_or_else(|| anyhow!("sponsor missing"))?;
        *balance = balance
            .checked_sub(amount)
            .ok_or_else(|| anyhow!("insufficient funds"))?;
        Ok(())
    }
    fn bank_credit(&mut self, amount: u64) -> Result<()> {
        self.bank = self
            .bank
            .checked_add(amount)
            .ok_or_else(|| anyhow!("bank overflow"))?;
        Ok(())
    }
}
impl Scanner for Memory {
    fn registered(&self, key: &[u8; 32]) -> Result<bool> {
        Ok(self.registered.contains(key))
    }
    fn sponsor_exists(&self, sponsor: u64) -> Result<bool> {
        Ok(self.balances.contains_key(&sponsor))
    }
    fn for_each_prefix<F>(&self, prefix: &[u8], mut visit: F) -> Result<()>
    where
        F: FnMut(&[u8], &[u8]) -> Result<()>,
    {
        for (key, value) in &self.rows {
            if key.starts_with(prefix) {
                visit(key, value)?;
            }
        }
        Ok(())
    }
}
impl Memory {
    fn atomic<T>(&mut self, action: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let mut stage = self.clone();
        let result = action(&mut stage)?;
        *self = stage;
        Ok(result)
    }
}
fn fixture() -> (Memory, Config, Context) {
    let config = Config::default();
    let mut host = Memory::default();
    host.balances.insert(7, 1_000_000_000);
    host.balances.insert(8, 1_000_000_000);
    let context = Context {
        network: [1; 32],
        sponsor: 7,
        elapsed_micros: 1,
        height: 1,
    };
    initialize(&mut host, &config, context.network).unwrap();
    (host, config, context)
}
fn key(index: u64) -> SigningKey {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&index.to_be_bytes());
    seed[31] = 41;
    SigningKey::from_bytes(&seed)
}
fn input(key: &SigningKey, context: Context, expiry: u64) -> CommitInput {
    let public = *key.verifying_key().as_bytes();
    let commitment = [3; 32];
    let proof = key.sign(&consent_bytes(
        context.network,
        context.sponsor,
        public,
        commitment,
        expiry,
    ));
    CommitInput {
        public_key: hex::encode(public),
        commitment: hex::encode(commitment),
        expires_elapsed_micros: expiry,
        proof: hex::encode(proof.to_bytes()),
    }
}
fn store(host: &mut Memory, value: &impl serde::Serialize, key: Vec<u8>) {
    host.rows.insert(key, serde_json::to_vec(value).unwrap());
}

#[test]
fn config_and_decimal_encoding_are_bounded_and_canonical() {
    let config = Config::default();
    config.validate().unwrap();
    for bad in [
        Config {
            fee_micros: 999,
            ..config.clone()
        },
        Config {
            max_lifetime_micros: DAY - 1,
            ..config.clone()
        },
        Config {
            bucket_micros: 0,
            ..config.clone()
        },
        Config {
            bucket_micros: HOUR - 1,
            ..config.clone()
        },
    ] {
        assert!(bad.validate().is_err());
    }
    for text in [
        r#"{"fee_micros":10000,"max_lifetime_micros":"86400000000","bucket_micros":"3600000000"}"#,
        r#"{"fee_micros":"010000","max_lifetime_micros":"86400000000","bucket_micros":"3600000000"}"#,
    ] {
        assert!(serde_json::from_str::<Config>(text).is_err());
    }
}
#[test]
fn consent_binds_every_coordinate_and_weak_keys_are_rejected() {
    let (host, config, context) = fixture();
    let device = key(1);
    let good = input(&device, context, 100);
    for index in 0..6 {
        let mut candidate = host.clone();
        let mut changed = good.clone();
        let mut ctx = context;
        match index {
            0 => ctx.network = [2; 32],
            1 => ctx.sponsor = 8,
            2 => changed.public_key = hex::encode(key(2).verifying_key().as_bytes()),
            3 => changed.commitment = "04".repeat(32),
            4 => changed.expires_elapsed_micros = 101,
            _ => changed.proof = "00".repeat(64),
        }
        assert!(
            candidate
                .atomic(|h| commit(h, &config, ctx, changed))
                .is_err()
        );
        assert_eq!(candidate.rows, host.rows);
        assert_eq!(candidate.bank, 0);
    }
    let mut candidate = host;
    let mut weak = good;
    weak.public_key = "00".repeat(32);
    assert!(commit(&mut candidate, &config, context, weak).is_err());
}
#[test]
fn paid_commit_conserves_bank_plus_sponsor_and_grants_no_account_authority() {
    let (mut host, config, context) = fixture();
    let before = host.balances[&7] + host.bank;
    let record = host
        .atomic(|h| commit(h, &config, context, input(&key(1), context, 100)))
        .unwrap();
    assert_eq!(host.bank, 10_000);
    assert_eq!(host.balances[&7], 999_990_000);
    assert_eq!(host.balances[&7] + host.bank, before);
    assert_eq!(record.sponsor, 7);
    assert_eq!(
        record.public_key,
        hex::encode(key(1).verifying_key().as_bytes())
    );
    assert_eq!(host.registered.len(), 0);
    assert_eq!(audit(&host, &config, context).unwrap(), 3);
}
#[test]
fn insufficient_funds_and_failed_storage_discard_all_money_and_rows() {
    let (mut host, config, context) = fixture();
    for mode in 0..3 {
        let mut candidate = host.clone();
        if mode == 0 {
            candidate.balances.insert(7, 9999);
        } else if mode == 1 {
            candidate.bank = u64::MAX;
        } else {
            candidate.fail_write = true;
        }
        let before = candidate.clone();
        assert!(
            candidate
                .atomic(|h| commit(h, &config, context, input(&key(1), context, 100)))
                .is_err()
        );
        assert_eq!(candidate.rows, before.rows);
        assert_eq!(candidate.balances, before.balances);
        assert_eq!(candidate.bank, before.bank);
    }
    host.balances.insert(7, 10_000);
    host.atomic(|h| commit(h, &config, context, input(&key(1), context, 100)))
        .unwrap();
    assert_eq!(host.balances[&7], 0);
}
#[test]
fn replay_duplicate_and_registered_identity_cannot_create_another_paid_reservation() {
    let (mut host, config, context) = fixture();
    let device = key(1);
    let signed = input(&device, context, 100);
    let first = commit(&mut host, &config, context, signed.clone()).unwrap();
    let unchanged = host.clone();
    assert!(
        host.atomic(|h| commit(h, &config, context, signed.clone()))
            .is_err()
    );
    assert_eq!(host.bank, unchanged.bank);
    assert_eq!(host.rows, unchanged.rows);
    let later = Context {
        height: 2,
        ..context
    };
    consume(
        &mut host,
        &config,
        later,
        device.verifying_key().as_bytes(),
        &first.entry_id,
    )
    .unwrap();
    host.registered.insert(*device.verifying_key().as_bytes());
    assert!(host.atomic(|h| commit(h, &config, later, signed)).is_err());
}
#[test]
fn unrelated_sponsor_cannot_replay_consent_or_replace_active_device_commit() {
    let (mut host, config, context) = fixture();
    let device = key(1);
    let signed = input(&device, context, 100);
    let other = Context {
        sponsor: 8,
        ..context
    };
    assert!(
        host.atomic(|h| commit(h, &config, other, signed.clone()))
            .is_err()
    );
    commit(&mut host, &config, context, signed).unwrap();
    assert!(
        host.atomic(|h| commit(h, &config, other, input(&device, other, 101)))
            .is_err()
    );
    assert_eq!(host.balances[&8], 1_000_000_000);
}
#[test]
fn conditional_consume_prevents_racing_reveal_and_preserves_expiry_boundary() {
    let (mut host, config, context) = fixture();
    let device = key(1);
    let record = commit(&mut host, &config, context, input(&device, context, 100)).unwrap();
    let later = Context {
        height: 2,
        elapsed_micros: 100,
        ..context
    };
    assert!(
        host.atomic(|h| consume(
            h,
            &config,
            later,
            device.verifying_key().as_bytes(),
            &"00".repeat(32)
        ))
        .is_err()
    );
    consume(
        &mut host,
        &config,
        later,
        device.verifying_key().as_bytes(),
        &record.entry_id,
    )
    .unwrap();
    assert!(
        consume(
            &mut host,
            &config,
            later,
            device.verifying_key().as_bytes(),
            &record.entry_id
        )
        .is_err()
    );
    assert_eq!(
        state(&host, &config, context.network).unwrap().commitments,
        0
    );
    assert_eq!(audit(&host, &config, later).unwrap(), 2);
}
#[test]
fn expired_lazy_replacement_survives_cleanup_of_its_old_entry() {
    let (mut host, config, context) = fixture();
    let device = key(1);
    let old = commit(&mut host, &config, context, input(&device, context, 100)).unwrap();
    let later = Context {
        height: 2,
        elapsed_micros: 101,
        ..context
    };
    let fresh = commit(&mut host, &config, later, input(&device, later, 200)).unwrap();
    assert_ne!(old.entry_id, fresh.entry_id);
    let result = cleanup(&mut host, &config, later, 128).unwrap();
    assert_eq!(result.removed_entries, 1);
    assert_eq!(result.removed_commitments, 0);
    assert_eq!(
        get_commit(&host, &config, later, device.verifying_key().as_bytes()).unwrap(),
        Some(fresh)
    );
    assert_eq!(audit(&host, &config, later).unwrap(), 3);
}
#[test]
fn more_than_256_pending_keys_use_constant_metadata_and_bounded_cleanup() {
    let (mut host, config, context) = fixture();
    for i in 0..600 {
        commit(&mut host, &config, context, input(&key(i), context, 100)).unwrap();
    }
    let stored = state(&host, &config, context.network).unwrap();
    assert_eq!(stored.commitments, 600);
    assert_eq!(stored.buckets.len(), 25);
    assert!(serde_json::to_vec(&stored).unwrap().len() < 8_000);
    assert_eq!(audit(&host, &config, context).unwrap(), 1201);
    let later = Context {
        height: 2,
        elapsed_micros: 101,
        ..context
    };
    let mut removed = 0;
    loop {
        let result = cleanup(&mut host, &config, later, 128).unwrap();
        assert!(result.removed_entries <= 128);
        assert!(result.examined_heads <= result.removed_entries + 25);
        removed += result.removed_entries;
        if result.removed_entries == 0 {
            break;
        }
    }
    assert_eq!(removed, 600);
    assert_eq!(audit(&host, &config, later).unwrap(), 1);
    assert!(cleanup(&mut host, &config, later, 129).is_err());
}
#[test]
fn old_backlog_and_new_expiry_cycles_never_expand_the_25_queue_frontier() {
    let (mut host, config, context) = fixture();
    for i in 0..80 {
        let current = Context {
            elapsed_micros: 1 + i * DAY,
            height: 1 + i,
            ..context
        };
        commit(
            &mut host,
            &config,
            current,
            input(&key(i), current, current.elapsed_micros + 100),
        )
        .unwrap();
    }
    let now = Context {
        height: 81,
        elapsed_micros: 79 * DAY + 2,
        ..context
    };
    assert_eq!(
        state(&host, &config, now.network).unwrap().queue_entries,
        80
    );
    assert_eq!(audit(&host, &config, now).unwrap(), 161);
    let result = cleanup(&mut host, &config, now, 128).unwrap();
    assert_eq!(result.removed_entries, 79);
    assert_eq!(audit(&host, &config, now).unwrap(), 3);
}
#[test]
fn failed_reveal_stage_keeps_commit_and_does_not_charge_again() {
    let (mut host, config, context) = fixture();
    let device = key(1);
    let record = commit(&mut host, &config, context, input(&device, context, 100)).unwrap();
    let later = Context {
        height: 2,
        ..context
    };
    let before = host.clone();
    let result: Result<()> = host.atomic(|h| {
        consume(
            h,
            &config,
            later,
            device.verifying_key().as_bytes(),
            &record.entry_id,
        )?;
        Err(anyhow!("injected invalid name/reveal"))
    });
    assert!(result.is_err());
    assert_eq!(host.rows, before.rows);
    assert_eq!(host.bank, before.bank);
}
#[test]
fn full_audit_detects_orphan_nodes_wrong_links_aliases_and_unknown_namespace() {
    let (mut host, config, context) = fixture();
    let record = commit(&mut host, &config, context, input(&key(1), context, 100)).unwrap();
    for mode in 0..4 {
        let mut bad = host.clone();
        match mode {
            0 => {
                bad.rows
                    .insert(b"registration/unknown".to_vec(), b"null".to_vec());
            }
            1 => {
                let mut node: Entry =
                    serde_json::from_slice(&bad.rows[&entry_key(&record.entry_id).unwrap()])
                        .unwrap();
                node.next = Some(record.entry_id.clone());
                store(&mut bad, &node, entry_key(&record.entry_id).unwrap());
            }
            2 => {
                bad.rows.remove(&entry_key(&record.entry_id).unwrap());
            }
            _ => {
                let mut alias = record.clone();
                alias.sponsor = 9;
                store(
                    &mut bad,
                    &alias,
                    commit_key(key(1).verifying_key().as_bytes()),
                );
            }
        }
        assert!(audit(&bad, &config, context).is_err());
    }
}
#[test]
fn backwards_clocks_and_out_of_range_lifetimes_are_rejected() {
    let (mut host, config, context) = fixture();
    let record = commit(&mut host, &config, context, input(&key(1), context, 100)).unwrap();
    for expiry in [context.elapsed_micros, context.elapsed_micros + DAY + 1] {
        assert!(
            host.atomic(|h| commit(h, &config, context, input(&key(2), context, expiry)))
                .is_err()
        );
    }
    let backwards = Context {
        height: 0,
        elapsed_micros: 0,
        ..context
    };
    assert!(cleanup(&mut host, &config, backwards, 128).is_err());
    assert!(get_commit(&host, &config, backwards, key(1).verifying_key().as_bytes()).is_err());
    assert!(
        consume(
            &mut host,
            &config,
            Context {
                height: 2,
                elapsed_micros: 101,
                ..context
            },
            key(1).verifying_key().as_bytes(),
            &record.entry_id
        )
        .is_err()
    );
}
