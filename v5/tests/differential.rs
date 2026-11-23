//! The version-5 engine must be the protocol-4 state machine, only faster.
//!
//! Every block here is run through three executions: the unmodified
//! protocol-4 engine (reading and proving its state from disk), the version-5
//! engine, and the version-5 engine's reference mode (protocol-4 rule adapter
//! for transfers, inline signature checks, no account cache). All three must
//! accept and reject the same transactions and produce the same Merkle root
//! and the same metadata bytes.
//!
//! Two actions are excluded because version 5 changes their rule on purpose
//! (see `tests/node.rs`): `CancelPending`, which now pays the fee, and
//! `SetRecovery` with no guardians, which is now accepted.
mod common;
use common::*;
use ed25519_dalek::Signer;
use std::collections::{BTreeMap, HashMap};
use timecurrency_node::ledger::{self, Account, ActionPayload};
use timecurrency_v4 as old;
use timecurrency_v5 as new;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

struct Claim {
    target: u64,
    request: ledger::ApproveRecovery,
    new_seed: u8,
}
struct Pending {
    seed: u8,
    name: String,
    salt: String,
}

struct Pair {
    _dir: tempfile::TempDir,
    old: old::engine::Engine,
    new: new::engine::Engine,
    rng: Rng,
    /// Key seed by public key, for every key the tests can create.
    seeds: HashMap<String, u8>,
    next_device_seed: u8,
    next_identity_seed: u8,
    claims: Vec<Claim>,
    reveals: Vec<Pending>,
    accepted: BTreeMap<&'static str, u64>,
    offered: BTreeMap<&'static str, u64>,
}

impl Pair {
    fn new(seed: u64) -> Self {
        Self::with_accounts(seed, GENESIS_ACCOUNTS)
    }
    fn with_accounts(seed: u64, accounts: u64) -> Self {
        let genesis_old = genesis_v4_with(accounts);
        let genesis_new: new::genesis::Genesis =
            serde_json::from_slice(&serde_json::to_vec(&genesis_old).unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut old_engine = old::engine::Engine::open_with_history(
            old::store::Store::open(dir.path().join("old.redb")).unwrap(),
            dir.path().join("old.history"),
        )
        .unwrap();
        let mut new_engine = new::engine::Engine::open_with_history(
            new::store::Store::open(dir.path().join("new.v5state")).unwrap(),
            dir.path().join("new.history"),
        )
        .unwrap();
        let a = old_engine.initialize(genesis_old).unwrap();
        let b = new_engine.initialize(genesis_new).unwrap();
        assert_eq!(a.root, b.root, "genesis root");
        assert_eq!(a.metadata, b.metadata, "genesis metadata");
        Self {
            _dir: dir,
            old: old_engine,
            new: new_engine,
            rng: Rng(seed),
            seeds: (1..=255u8).map(|seed| (pk(seed), seed)).collect(),
            next_device_seed: 60,
            next_identity_seed: 200,
            claims: Vec::new(),
            reveals: Vec::new(),
            accepted: BTreeMap::new(),
            offered: BTreeMap::new(),
        }
    }
    fn row(&self, key: &[u8]) -> Option<Vec<u8>> {
        let old = self.old.store().snapshot().unwrap().get(key).unwrap();
        let new = self.new.version().unwrap().get(key).map(|row| row.to_vec());
        assert_eq!(old, new, "row {}", String::from_utf8_lossy(key));
        new
    }
    fn account(&self, id: u64) -> Account {
        serde_json::from_slice(&self.row(&new::engine::account_key(id)).unwrap()).unwrap()
    }
    fn accounts(&self) -> u64 {
        self.new.meta().unwrap().next_account_id
    }
    fn now(&self) -> u64 {
        self.new.meta().unwrap().elapsed_micros().unwrap()
    }
    /// Seed of a device of `row` with the wanted permission, if the tests hold one.
    fn device(&self, row: &Account, manage: bool) -> Option<u8> {
        row.devices
            .iter()
            .find(|device| if manage { device.can_manage } else { device.can_spend })
            .and_then(|device| self.seeds.get(&device.public_key).copied())
    }

    /// Executes one block on all engines and commits the proposer-filtered
    /// result. Returns the transactions that were included.
    fn step(&mut self, delta: u64, candidates: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let meta = self.new.meta().unwrap();
        let (height, time) = (meta.height + 1, meta.time_micros + delta as i64);
        let eligible: Vec<String> = self
            .new
            .active_roster_at(meta.height as u64)
            .unwrap()
            .into_iter()
            .map(|validator| validator.consensus_key)
            .collect();
        let eligible_old: Vec<String> = self
            .old
            .active_roster_at(meta.height as u64)
            .unwrap()
            .into_iter()
            .map(|validator| validator.consensus_key)
            .collect();
        assert_eq!(eligible, eligible_old, "roster at height {height}");
        let hash = sha(height as u64);
        // Strict execution of the candidates as given: one bad transaction
        // rejects the block, on every engine or on none.
        let strict_old = self.old.prepare(height, time, &candidates, &eligible, hash);
        let strict_new = self.new.prepare(height, time, &candidates, &eligible, hash);
        let strict_ref = self
            .new
            .prepare_reference(height, time, &candidates, &eligible, hash);
        assert_eq!(
            strict_old.is_ok(),
            strict_new.is_ok(),
            "block acceptance at height {height}: old {:?}, new {:?}",
            strict_old.as_ref().err(),
            strict_new.as_ref().err()
        );
        assert_eq!(strict_old.is_ok(), strict_ref.is_ok(), "reference acceptance");
        if let (Ok(a), Ok(b), Ok(c)) = (&strict_old, &strict_new, &strict_ref) {
            assert_eq!(a.root, b.root, "strict root at height {height}");
            assert_eq!(a.root, c.root, "reference root at height {height}");
        }
        // Proposer filtering: the same transactions survive.
        let (prepared_old, kept_old) = self
            .old
            .prepare_filtered(height, time, &candidates, &eligible, 1 << 20, hash)
            .unwrap();
        let (prepared_new, kept) = self
            .new
            .prepare_filtered(height, time, &candidates, &eligible, 1 << 20, hash)
            .unwrap();
        assert_eq!(kept_old, kept, "filtered transactions at height {height}");
        assert_eq!(prepared_old.root, prepared_new.root, "filtered root");
        let reference = self
            .new
            .prepare_reference(height, time, &kept, &eligible, hash)
            .unwrap();
        assert_eq!(reference.root, prepared_new.root, "reference root of kept list");
        let head_old = self.old.commit(prepared_old, hash).unwrap();
        let head_new = self.new.commit(prepared_new, hash).unwrap();
        assert_eq!(head_old.version, head_new.version);
        assert_eq!(head_old.root, head_new.root, "committed root at height {height}");
        assert_eq!(head_old.metadata, head_new.metadata, "metadata at height {height}");
        kept
    }

    fn offer(&mut self, list: &mut Vec<(&'static str, Vec<u8>)>, label: &'static str, raw: Vec<u8>) {
        *self.offered.entry(label).or_default() += 1;
        list.push((label, raw));
    }

    /// One random candidate. `nonces` tracks nonces already used in this block
    /// so that several actions of one account form a valid sequence.
    fn candidate(&mut self, nonces: &mut BTreeMap<u64, u64>, list: &mut Vec<(&'static str, Vec<u8>)>) {
        let count = self.accounts();
        let id = self.rng.below(count);
        let mut row = self.account(id);
        row.nonce += nonces.get(&id).copied().unwrap_or(0);
        let other = (id + 1 + self.rng.below(count - 1)) % count;
        let spender = self.device(&row, false);
        let manager = self.device(&row, true);
        let network = network_id();
        let roll = self.rng.below(100);
        let mut used_nonce = true;
        match roll {
            0..=37 => {
                let Some(signer) = spender else { return };
                let amount = 1 + self.rng.below((row.balance / 6).max(2));
                self.offer(list, "transfer", transfer(&row, signer, other, amount));
            }
            38..=52 => {
                used_nonce = false;
                let signer = spender.unwrap_or(1);
                let pay = |to: u64, amount: u64| {
                    serde_json::to_vec(&ledger::Transfer { to, amount }).unwrap()
                };
                let raw = match self.rng.below(12) {
                    0 => {
                        let mut raw = transfer(&row, signer, other, 5);
                        *raw.last_mut().unwrap() ^= 1;
                        raw
                    }
                    1 => raw_action(&network, 3, id, row.nonce + 2, row.auth_epoch, signer, &pay(other, 5)),
                    2 => transfer(&row, signer, other, row.balance + 1),
                    3 => transfer(&row, signer, id, 5),
                    4 => transfer(&row, signer, other, 0),
                    5 => transfer(&row, signer, 1_000_000 + other, 5),
                    6 => raw_action(&"11".repeat(32), 3, id, row.nonce + 1, row.auth_epoch, signer, &pay(other, 5)),
                    7 => raw_action(&network, 3, id, row.nonce + 1, row.auth_epoch + 1, signer, &pay(other, 5)),
                    8 => raw_action(&network, 3, id, row.nonce + 1, row.auth_epoch, signer, br#"{"to":"1", "amount":"5"}"#),
                    9 => {
                        let mut raw = transfer(&row, signer, other, 5);
                        raw.pop();
                        raw
                    }
                    10 => raw_action(&network, 99, id, row.nonce + 1, row.auth_epoch, signer, b"{}"),
                    // Signed by a key that is not a device of the account.
                    _ => transfer(&row, 250, other, 5),
                };
                self.offer(list, "invalid", raw);
            }
            53..=56 => {
                let Some(signer) = spender else { return };
                let mut reference = Vec::new();
                reference.extend((row.nonce + 1).to_be_bytes());
                let expiry = if self.rng.chance(85) { self.now() + 60 * pos::SECOND } else { 1 };
                reference.extend(expiry.to_be_bytes());
                reference.extend([self.rng.next() as u8; 16]);
                let payload = ActionPayload::MerchantPayment(ledger::MerchantPayment {
                    to: other,
                    amount: 1 + self.rng.below(2000),
                    reference: hex::encode(reference),
                });
                self.offer(list, "merchant", legacy(id, row.nonce + 1, row.auth_epoch, signer, payload));
            }
            57..=66 => {
                let Some(signer) = spender else { return };
                let raw = match self.rng.below(3) {
                    0 => extension(&row, signer, 18, serde_json::json!({"amount":"10000"})),
                    1 => extension(&row, signer, 19, serde_json::json!({"amount":"1000","min_amount":"1000"})),
                    _ => legacy(
                        id,
                        row.nonce + 1,
                        row.auth_epoch,
                        signer,
                        ActionPayload::Delegate(ledger::Delegate {
                            operator: self.rng.below(4),
                            amount: 10_000,
                            min_shares: 1,
                        }),
                    ),
                };
                self.offer(list, "staking", raw);
            }
            67..=71 => {
                let Some(signer) = manager else { return };
                let seed = self.next_device_seed;
                self.next_device_seed = 60 + (seed - 60 + 1) % 40;
                let (can_manage, can_spend) = (self.rng.chance(50), self.rng.chance(70));
                let mut message = b"TCDEVNET-DEVICE-V1\0".to_vec();
                message.extend(hex::decode(&network).unwrap());
                message.extend(id.to_be_bytes());
                message.extend(row.auth_epoch.to_be_bytes());
                message.extend(key(seed).verifying_key().as_bytes());
                message.extend([u8::from(can_manage), u8::from(can_spend)]);
                let payload = ActionPayload::AddDevice(ledger::AddDevice {
                    public_key: pk(seed),
                    can_manage,
                    can_spend,
                    proof: hex::encode(key(seed).sign(&message).to_bytes()),
                });
                self.offer(list, "add_device", legacy(id, row.nonce + 1, row.auth_epoch, signer, payload));
            }
            72..=73 => {
                let Some(signer) = manager else { return };
                let victim = &row.devices[self.rng.below(row.devices.len() as u64) as usize];
                let payload = ActionPayload::RevokeDevice(ledger::RevokeDevice {
                    public_key: victim.public_key.clone(),
                });
                self.offer(list, "revoke_device", legacy(id, row.nonce + 1, row.auth_epoch, signer, payload));
            }
            74..=78 => {
                // Any device of the account, whether or not it may spend.
                let device = &row.devices[self.rng.below(row.devices.len() as u64) as usize];
                let Some(signer) = self.seeds.get(&device.public_key).copied() else { return };
                let amount = 1 + self.rng.below(500);
                self.offer(list, "device_transfer", transfer(&row, signer, other, amount));
            }
            79..=81 => {
                let Some(signer) = manager else { return };
                let mut guardians: Vec<u64> = (0..count).filter(|g| *g != id).collect();
                while guardians.len() > 3 {
                    let index = self.rng.below(guardians.len() as u64) as usize;
                    guardians.remove(index);
                }
                // Occasionally too many guardians, which both engines reject.
                if self.rng.chance(10) {
                    guardians = (0..count).filter(|g| *g != id).take(7).collect();
                }
                let payload = ActionPayload::SetRecovery(ledger::SetRecovery {
                    guardians,
                    threshold: 2,
                    delay_seconds: if self.rng.chance(85) { 30 } else { 5 },
                });
                self.offer(list, "set_recovery", legacy(id, row.nonce + 1, row.auth_epoch, signer, payload));
            }
            82..=86 => {
                // `id` acts as a guardian of some account that named it.
                let Some(signer) = manager else { return };
                let Some(target) = (0..count).map(|t| self.account(t)).find(|t| {
                    t.recovery_policy.as_ref().is_some_and(|p| p.guardians.contains(&id))
                }) else {
                    return;
                };
                let policy = target.recovery_policy.as_ref().unwrap();
                let payload = if !policy.accepted.contains(&id) || self.rng.chance(15) {
                    ActionPayload::ConsentRecovery(ledger::ConsentRecovery {
                        target: target.id,
                        policy_version: target.recovery_version,
                        accept: !policy.accepted.contains(&id),
                    })
                } else {
                    let index = self.claims.iter().position(|c| c.target == target.id);
                    let claim = match index {
                        Some(index) if self.rng.chance(80) => &self.claims[index],
                        _ => {
                            let new_seed = 220 + (self.rng.below(20) as u8);
                            let recovery_id = hex::encode(sha(self.rng.next()));
                            let expiry = self.now() + 30 * pos::SECOND + 7 * pos::DAY;
                            let mut message = b"TCDEVNET-RECOVERY-V1\0".to_vec();
                            message.extend(hex::decode(&network).unwrap());
                            message.extend(target.id.to_be_bytes());
                            message.extend(target.auth_epoch.to_be_bytes());
                            message.extend(target.recovery_version.to_be_bytes());
                            message.extend(hex::decode(&recovery_id).unwrap());
                            message.extend(key(new_seed).verifying_key().as_bytes());
                            message.extend(expiry.to_be_bytes());
                            self.claims.push(Claim {
                                target: target.id,
                                new_seed,
                                request: ledger::ApproveRecovery {
                                    target: target.id,
                                    policy_version: target.recovery_version,
                                    recovery_id,
                                    new_public_key: pk(new_seed),
                                    expires_elapsed_micros: expiry,
                                    proof: hex::encode(key(new_seed).sign(&message).to_bytes()),
                                },
                            });
                            self.claims.last().unwrap()
                        }
                    };
                    ActionPayload::ApproveRecovery(claim.request.clone())
                };
                self.offer(list, "guardian", legacy(id, row.nonce + 1, row.auth_epoch, signer, payload));
            }
            87..=89 => {
                // The account under recovery cancels, or the new key finalizes.
                let Some(index) = self.claims.iter().position(|c| c.target == id) else { return };
                let raw = if self.rng.chance(35) {
                    let Some(signer) = manager else { return };
                    legacy(id, row.nonce + 1, row.auth_epoch, signer, ActionPayload::CancelRecovery(ledger::CancelRecovery {}))
                } else {
                    let claim = &self.claims[index];
                    legacy(
                        id,
                        row.nonce + 1,
                        row.auth_epoch,
                        claim.new_seed,
                        ActionPayload::FinalizeRecovery(ledger::FinalizeRecovery {
                            recovery_id: claim.request.recovery_id.clone(),
                        }),
                    )
                };
                self.offer(list, "recovery_end", raw);
            }
            90..=94 => {
                let Some(signer) = spender else { return };
                let seed = self.next_identity_seed;
                if seed >= 220 {
                    return;
                }
                self.next_identity_seed += 1;
                let (name, salt) = (format!("new_{seed}"), hex::encode([seed; 32]));
                let commitment = ledger::action_commitment(&network, &pk(seed), &name, &salt).unwrap();
                let expiry = self.now() + 3600 * pos::SECOND;
                let consent = registration::consent_bytes(
                    pos::hex32(&network).unwrap(),
                    id,
                    pos::hex32(&pk(seed)).unwrap(),
                    pos::hex32(&commitment).unwrap(),
                    expiry,
                );
                let payload = serde_json::json!({"public_key":pk(seed),"commitment":commitment,"expires_elapsed_micros":expiry.to_string(),"proof":hex::encode(key(seed).sign(&consent).to_bytes())});
                self.reveals.push(Pending { seed, name, salt });
                self.offer(list, "sponsor", extension(&row, signer, 44, payload));
            }
            _ => {
                used_nonce = false;
                if self.reveals.is_empty() {
                    return;
                }
                let index = self.rng.below(self.reveals.len() as u64) as usize;
                let pending = &self.reveals[index];
                let raw = legacy(
                    u64::MAX,
                    0,
                    0,
                    pending.seed,
                    ActionPayload::Reveal(ledger::Reveal {
                        name: pending.name.clone(),
                        salt: pending.salt.clone(),
                    }),
                );
                self.offer(list, "reveal", raw);
            }
        }
        if used_nonce {
            *nonces.entry(id).or_default() += 1;
        }
    }
}

fn run(seed: u64, blocks: u64) -> Pair {
    let mut pair = Pair::new(seed);
    // Validator owners earn the first currency, then spread it.
    pair.step(60 * pos::SECOND, vec![]);
    let funding: Vec<Vec<u8>> = (0..4u64)
        .flat_map(|owner| {
            let row = pair.account(owner);
            (0..2u64).map(move |index| {
                let mut row = row.clone();
                row.nonce += index;
                transfer(&row, owner as u8 + 1, 4 + owner * 2 + index, 1_200_000)
            })
        })
        .collect();
    assert_eq!(pair.step(pos::SECOND, funding.clone()), funding);
    for _ in 0..blocks {
        let mut list = Vec::new();
        let mut nonces = BTreeMap::new();
        let wanted = pair.rng.below(11);
        for _ in 0..wanted {
            pair.candidate(&mut nonces, &mut list);
        }
        // Sometimes the same transaction is offered twice in one block.
        if list.len() > 1 && pair.rng.chance(15) {
            let copy = list[0].clone();
            list.push(copy);
        }
        let span = if pair.rng.chance(10) { 70 * pos::SECOND } else { 9 * pos::SECOND };
        let delta = 1 + pair.rng.below(span);
        let kept = pair.step(delta, list.iter().map(|(_, raw)| raw.clone()).collect());
        for (label, raw) in &list {
            if kept.contains(raw) {
                *pair.accepted.entry(label).or_default() += 1;
            }
        }
    }
    pair
}

#[test]
fn random_blocks_match_protocol_4_exactly() {
    let pair = run(0x5eed_0001, 260);
    // The workload must actually reach the rules it is meant to compare.
    println!("offered  {:?}", pair.offered);
    println!("accepted {:?}", pair.accepted);
    for label in [
        "transfer",
        "merchant",
        "staking",
        "add_device",
        "device_transfer",
        "set_recovery",
        "guardian",
        "sponsor",
        "reveal",
    ] {
        assert!(
            pair.accepted.get(label).copied().unwrap_or(0) > 0,
            "no accepted `{label}` action; the comparison did not cover it"
        );
    }
    // Almost all "invalid" candidates are rejected. A few become valid by
    // their position in the block (an overspend after an incoming transfer, a
    // next-epoch action after a device change); every engine agrees on those.
    let (offered, accepted) = (
        pair.offered.get("invalid").copied().unwrap_or(0),
        pair.accepted.get("invalid").copied().unwrap_or(0),
    );
    assert!(offered > 100 && accepted * 20 < offered, "{accepted} of {offered}");
    assert!(pair.accounts() > GENESIS_ACCOUNTS, "no account was registered");
    // Every account row is identical, and both full recounts pass and agree.
    for id in 0..pair.accounts() {
        pair.account(id);
    }
    let old = pair.old.audit().unwrap();
    let new = pair.new.audit().unwrap();
    assert_eq!(
        (old.account_count, old.liquid, old.unbond, old.last_id, old.authenticated_leaves),
        (new.account_count, new.liquid, new.unbond, new.last_id, new.authenticated_leaves)
    );
    assert!(new.history_archive_verified);
}

#[test]
fn guardian_recovery_freeze_cancel_and_finalize_match() {
    // A scripted pass through the recovery rules, which random blocks reach
    // only rarely: an account under an approved recovery is frozen for
    // transfers on both paths; cancelling releases it; a finalized recovery
    // replaces its devices.
    let mut pair = Pair::new(11);
    pair.step(60 * pos::SECOND, vec![]);
    let fund = |pair: &Pair, to: u64, index: u64| {
        let mut row = pair.account(0);
        row.nonce += index;
        transfer(&row, 1, to, 400_000)
    };
    let funding = vec![fund(&pair, 5, 0), fund(&pair, 6, 1), fund(&pair, 7, 2)];
    assert_eq!(pair.step(pos::SECOND, funding.clone()), funding);
    let network = network_id();
    let one = |pair: &mut Pair, raw: Vec<u8>, accepted: bool| {
        let kept = pair.step(pos::SECOND, vec![raw.clone()]);
        assert_eq!(kept.contains(&raw), accepted, "unexpected acceptance");
    };
    for round in 0..2u64 {
        let target = 5u64;
        let row = pair.account(target);
        let signer = pair.device(&row, true).unwrap();
        one(
            &mut pair,
            legacy(
                target,
                row.nonce + 1,
                row.auth_epoch,
                signer,
                ActionPayload::SetRecovery(ledger::SetRecovery {
                    guardians: vec![0, 6, 7],
                    threshold: 2,
                    delay_seconds: 30,
                }),
            ),
            true,
        );
        let version = pair.account(target).recovery_version;
        for guardian in [0u64, 6] {
            let row = pair.account(guardian);
            one(
                &mut pair,
                legacy(
                    guardian,
                    row.nonce + 1,
                    row.auth_epoch,
                    guardian as u8 + 1,
                    ActionPayload::ConsentRecovery(ledger::ConsentRecovery {
                        target,
                        policy_version: version,
                        accept: true,
                    }),
                ),
                true,
            );
        }
        let owner = pair.account(target);
        let new_seed = 230 + round as u8;
        let recovery_id = hex::encode(sha(900 + round));
        let expiry = pair.now() + 30 * pos::SECOND + 7 * pos::DAY;
        let mut message = b"TCDEVNET-RECOVERY-V1\0".to_vec();
        message.extend(hex::decode(&network).unwrap());
        message.extend(target.to_be_bytes());
        message.extend(owner.auth_epoch.to_be_bytes());
        message.extend(owner.recovery_version.to_be_bytes());
        message.extend(hex::decode(&recovery_id).unwrap());
        message.extend(key(new_seed).verifying_key().as_bytes());
        message.extend(expiry.to_be_bytes());
        let claim = ledger::ApproveRecovery {
            target,
            policy_version: owner.recovery_version,
            recovery_id: recovery_id.clone(),
            new_public_key: pk(new_seed),
            expires_elapsed_micros: expiry,
            proof: hex::encode(key(new_seed).sign(&message).to_bytes()),
        };
        // One approval does not freeze the account.
        let row = pair.account(0);
        one(
            &mut pair,
            legacy(0, row.nonce + 1, row.auth_epoch, 1, ActionPayload::ApproveRecovery(claim.clone())),
            true,
        );
        let row = pair.account(target);
        let signer = pair.device(&row, false).unwrap();
        one(&mut pair, transfer(&row, signer, 7, 10), true);
        // The second approval reaches the threshold: transfers are refused.
        let row = pair.account(6);
        one(
            &mut pair,
            legacy(6, row.nonce + 1, row.auth_epoch, 7, ActionPayload::ApproveRecovery(claim)),
            true,
        );
        let row = pair.account(target);
        one(&mut pair, transfer(&row, signer, 7, 10), false);
        // A transfer *to* the frozen account is still fine.
        let row = pair.account(7);
        one(&mut pair, transfer(&row, 8, target, 10), true);
        let row = pair.account(target);
        if round == 0 {
            // The owner cancels and can spend again.
            let manager = pair.device(&row, true).unwrap();
            one(
                &mut pair,
                legacy(
                    target,
                    row.nonce + 1,
                    row.auth_epoch,
                    manager,
                    ActionPayload::CancelRecovery(ledger::CancelRecovery {}),
                ),
                true,
            );
            let row = pair.account(target);
            one(&mut pair, transfer(&row, signer, 7, 10), true);
        } else {
            // Too early, then after the delay the new key takes over.
            let finalize = |row: &Account| {
                legacy(
                    target,
                    row.nonce + 1,
                    row.auth_epoch,
                    new_seed,
                    ActionPayload::FinalizeRecovery(ledger::FinalizeRecovery {
                        recovery_id: recovery_id.clone(),
                    }),
                )
            };
            one(&mut pair, finalize(&row), false);
            pair.step(40 * pos::SECOND, vec![]);
            let row = pair.account(target);
            one(&mut pair, finalize(&row), true);
            let row = pair.account(target);
            assert_eq!(row.devices.len(), 1);
            assert_eq!(row.devices[0].public_key, pk(new_seed));
            one(&mut pair, transfer(&row, signer, 7, 10), false);
            one(&mut pair, transfer(&row, new_seed, 7, 10), true);
        }
    }
    pair.new.audit().unwrap();
    pair.old.audit().unwrap();
}

#[test]
fn a_second_seed_matches_too() {
    let pair = run(0xfeed_beef_0002, 140);
    pair.new.audit().unwrap();
}

#[test]
fn large_blocks_of_transfers_match() {
    // The fast path under load: many transfers per block, repeated senders,
    // every account touched many times, including a row that overspends.
    let mut pair = Pair::new(3);
    pair.step(60 * pos::SECOND, vec![]);
    for round in 0..6u64 {
        let mut txs = Vec::new();
        let rows: Vec<Account> = (0..GENESIS_ACCOUNTS).map(|id| pair.account(id)).collect();
        let mut balance: Vec<u64> = rows.iter().map(|row| row.balance).collect();
        let mut nonce: Vec<u64> = rows.iter().map(|row| row.nonce).collect();
        for index in 0..400u64 {
            let from = (index * 7 + round) % 4;
            let to = (from + 1 + index % (GENESIS_ACCOUNTS - 1)) % GENESIS_ACCOUNTS;
            let amount = 1 + (index * 37) % 900;
            if balance[from as usize] < amount + ledger::FEE_MICROS {
                continue;
            }
            balance[from as usize] -= amount + ledger::FEE_MICROS;
            balance[to as usize] += amount;
            let mut row = rows[from as usize].clone();
            row.nonce = nonce[from as usize];
            nonce[from as usize] += 1;
            txs.push(transfer(&row, from as u8 + 1, to, amount));
        }
        assert!(txs.len() > 300, "round {round} built {} transfers", txs.len());
        let kept = pair.step(30 * pos::SECOND, txs.clone());
        assert_eq!(kept, txs, "every transfer of round {round} is valid");
    }
    pair.new.audit().unwrap();
}

/// A precommit of validator `owner` for a block named by `block_byte`.
fn vote(owner: u64, height: u64, block_byte: u8, sign: fn(u8, &[u8]) -> [u8; 64]) -> tendermint::Vote {
    use tendermint::{Hash, Signature, Time, Vote, account, block};
    let seed = owner as u8 + 101;
    let public = tendermint::PublicKey::from_raw_ed25519(&hex::decode(pk(seed)).unwrap()).unwrap();
    let mut vote = Vote {
        vote_type: tendermint::vote::Type::Precommit,
        height: height.try_into().unwrap(),
        round: 0u32.try_into().unwrap(),
        block_id: Some(block::Id {
            hash: Hash::Sha256([block_byte; 32]),
            part_set_header: block::parts::Header::new(1, Hash::Sha256([block_byte + 1; 32])).unwrap(),
        }),
        timestamp: Some(Time::from_unix_timestamp(1_800_000_000, 0).unwrap()),
        validator_address: account::Id::from(public),
        validator_index: (owner as u32).try_into().unwrap(),
        signature: None,
        extension: vec![],
        extension_signature: None,
    };
    let mut bytes = Vec::new();
    vote.to_signable_bytes("time-devnet-v4-engine-test".parse().unwrap(), &mut bytes)
        .unwrap();
    vote.signature = Some(Signature::try_from(sign(seed, &bytes).to_vec()).unwrap());
    vote
}
fn ordinary_signature(seed: u8, message: &[u8]) -> [u8; 64] {
    key(seed).sign(message).to_bytes()
}
/// A signature that the consensus rule (ZIP-215) accepts and the strict rule
/// refuses: the nonce point carries an extra component of order eight, which
/// the consensus rule multiplies away. Only the key's owner can make one.
fn consensus_only_signature(seed: u8, message: &[u8]) -> [u8; 64] {
    use curve25519_dalek::{
        constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION},
        scalar::Scalar,
    };
    use sha2::{Digest, Sha512};
    let expanded: [u8; 64] = Sha512::digest([seed; 32]).into();
    let mut secret: [u8; 32] = expanded[..32].try_into().unwrap();
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    let secret = Scalar::from_bytes_mod_order(secret);
    let public = (ED25519_BASEPOINT_POINT * secret).compress();
    assert_eq!(hex::encode(public.as_bytes()), pk(seed));
    let wide = |parts: &[&[u8]]| -> Scalar {
        let mut hasher = Sha512::new();
        for part in parts {
            hasher.update(part);
        }
        let digest: [u8; 64] = hasher.finalize().into();
        Scalar::from_bytes_mod_order_wide(&digest)
    };
    let nonce = wide(&[&expanded[32..], message]);
    let point = (ED25519_BASEPOINT_POINT * nonce + EIGHT_TORSION[1]).compress();
    let challenge = wide(&[point.as_bytes(), public.as_bytes(), message]);
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(point.as_bytes());
    signature[32..].copy_from_slice((nonce + challenge * secret).as_bytes());
    signature
}
fn safety_hold(engine: &new::engine::Engine) -> bool {
    let row = engine
        .version()
        .unwrap()
        .get(new::pos_adapter::SUMMARY_KEY)
        .unwrap();
    serde_json::from_slice::<pos::Summary>(&row).unwrap().safety_hold
}

#[test]
fn double_signing_is_punished_as_in_protocol_4() {
    let mut pair = Pair::new(21);
    pair.step(60 * pos::SECOND, vec![]);
    assert!(!safety_hold(&pair.new));
    let evidence = serde_json::to_value(pos::DoubleSignEvidence {
        first: vote(0, 1, 1, ordinary_signature),
        second: vote(0, 1, 3, ordinary_signature),
    })
    .unwrap();
    let raw = extension(&pair.account(2), 3, 20, evidence.clone());
    // Same decision, same state on both engines.
    assert_eq!(pair.step(pos::SECOND, vec![raw.clone()]), vec![raw]);
    assert!(safety_hold(&pair.new));
    // The same offence cannot be reported twice, and votes for the same block
    // are no offence.
    let replay = extension(&pair.account(2), 3, 20, evidence);
    assert!(pair.step(pos::SECOND, vec![replay]).is_empty());
    let same = serde_json::to_value(pos::DoubleSignEvidence {
        first: vote(1, 1, 1, ordinary_signature),
        second: vote(1, 1, 1, ordinary_signature),
    })
    .unwrap();
    let harmless = extension(&pair.account(2), 3, 20, same);
    assert!(pair.step(pos::SECOND, vec![harmless]).is_empty());
}

#[test]
fn votes_that_only_consensus_accepts_can_be_punished_too() {
    // Protocol 4 verified evidence with a stricter signature rule than the
    // one consensus applies to votes. A validator could sign conflicting
    // votes that consensus counted and no evidence could prove.
    let mut pair = Pair::new(22);
    pair.step(60 * pos::SECOND, vec![]);
    let first = vote(0, 1, 1, consensus_only_signature);
    let second = vote(0, 1, 3, consensus_only_signature);
    // The signatures are what the test claims: valid for consensus, refused
    // by the strict rule.
    for vote in [&first, &second] {
        let mut bytes = Vec::new();
        vote.to_signable_bytes("time-devnet-v4-engine-test".parse().unwrap(), &mut bytes)
            .unwrap();
        let signature: [u8; 64] = vote.signature.as_ref().unwrap().as_bytes().try_into().unwrap();
        let public = key(101).verifying_key();
        assert!(
            public
                .verify_strict(&bytes, &ed25519_dalek::Signature::from_bytes(&signature))
                .is_err()
        );
        ed25519_consensus::VerificationKey::try_from(public.to_bytes())
            .unwrap()
            .verify(&ed25519_consensus::Signature::from(signature), &bytes)
            .unwrap();
    }
    let evidence = serde_json::to_value(pos::DoubleSignEvidence { first, second }).unwrap();
    let raw = extension(&pair.account(2), 3, 20, evidence);
    // The protocol-4 engine refuses this evidence.
    assert!(pair.old.validate_tx(&raw).is_err());
    // The version-5 engine acts on it.
    pair.new.validate_tx(&raw).unwrap();
    let meta = pair.new.meta().unwrap();
    let (height, time) = (meta.height + 1, meta.time_micros + pos::SECOND as i64);
    let eligible: Vec<String> = pair
        .new
        .active_roster_at(meta.height as u64)
        .unwrap()
        .into_iter()
        .map(|validator| validator.consensus_key)
        .collect();
    let prepared = pair
        .new
        .prepare(height, time, &[raw], &eligible, sha(height as u64))
        .unwrap();
    pair.new.commit(prepared, sha(height as u64)).unwrap();
    assert!(safety_hold(&pair.new));
    pair.new.audit().unwrap();
    // Evidence still needs both signatures to be the validator's own.
    let mut forged = vote(1, 1, 3, ordinary_signature);
    let mut bytes = forged.signature.as_ref().unwrap().as_bytes().to_vec();
    bytes[40] ^= 1;
    forged.signature = Some(tendermint::Signature::try_from(bytes).unwrap());
    let evidence = serde_json::to_value(pos::DoubleSignEvidence {
        first: vote(1, 1, 1, ordinary_signature),
        second: forged,
    })
    .unwrap();
    let row: Account = serde_json::from_slice(
        &pair
            .new
            .version()
            .unwrap()
            .get(&new::engine::account_key(2))
            .unwrap(),
    )
    .unwrap();
    assert!(pair.new.validate_tx(&extension(&row, 3, 20, evidence)).is_err());
}

#[test]
fn accounts_loaded_ahead_on_all_cores_match_protocol_4() {
    // With enough accounts that are not cached yet, a block's accounts are
    // decoded and checked on all cores before the block is executed. The
    // result must be what protocol 4 computes one row at a time.
    let mut pair = Pair::with_accounts(31, 64);
    let network = pair.new.meta().unwrap().network_id.clone();
    let send = |row: &Account, offset: u64, signer: u8, to: u64, amount: u64| {
        ledger::sign_action(
            &ledger::Action {
                network_id: network.clone(),
                from: row.id,
                nonce: row.nonce + 1 + offset,
                auth_epoch: row.auth_epoch,
                public_key: pk(signer),
                payload: ActionPayload::Transfer(ledger::Transfer { to, amount }),
                signature: vec![],
            },
            &key(signer),
        )
        .unwrap()
    };
    pair.step(60 * pos::SECOND, vec![]);
    // The four validator owners pay the sixty other accounts, none of which
    // has been read before.
    let owners: Vec<Account> = (0..4).map(|id| pair.account(id)).collect();
    let mut sent = [0u64; 4];
    let mut txs = Vec::new();
    for to in 4..64u64 {
        let owner = (to % 4) as usize;
        txs.push(send(&owners[owner], sent[owner], owner as u8 + 1, to, 30_000));
        sent[owner] += 1;
    }
    // Among them: a forged signature, a recipient that does not exist, and a
    // sender whose key is not a device of the account it names.
    let mut forged = send(&owners[0], sent[0], 1, 9, 5);
    *forged.last_mut().unwrap() ^= 1;
    let missing = send(&owners[1], sent[1], 2, 7_000, 5);
    let stranger = send(&pair.account(40), 0, 250, 41, 5);
    let mut offered = txs.clone();
    offered.insert(10, forged);
    offered.insert(20, missing);
    offered.insert(30, stranger);
    // The parallel load really happens, and only for accounts that exist.
    assert!(pair.new.cached_accounts() <= 4);
    pair.new.preload(&offered);
    assert_eq!(pair.new.cached_accounts(), 64);
    assert_eq!(pair.step(pos::SECOND, offered), txs);
    for to in 4..64u64 {
        assert_eq!(pair.account(to).balance, 30_000);
    }
    // Every account pays its neighbour, through the mempool path as well.
    let ring: Vec<Vec<u8>> = (4..64u64)
        .map(|from| send(&pair.account(from), 0, from as u8 + 1, 4 + (from - 3) % 60, 7))
        .collect();
    pair.new.preload(&ring);
    let mut pending = pair.new.check_state().unwrap();
    for tx in &ring {
        pending.admit(tx, new::sigcache::SigStatus::Unknown).unwrap();
    }
    assert_eq!(pair.step(pos::SECOND, ring.clone()), ring);
    pair.new.audit().unwrap();
    pair.old.audit().unwrap();
}

#[test]
fn a_refused_transaction_leaves_nothing_in_the_mempool_state() {
    let mut pair = Pair::new(41);
    pair.step(60 * pos::SECOND, vec![]);
    let mut pending = pair.new.check_state().unwrap();
    let unknown = new::sigcache::SigStatus::Unknown;
    assert_eq!(pending.rows(), 0);
    // Signed by a key that is no device of the account it names: the sender
    // and recipient rows were read to find that out, and are forgotten again.
    let stranger = transfer(&pair.account(7), 1, 9, 5);
    assert!(pending.admit(&stranger, unknown).is_err());
    assert_eq!(pending.rows(), 0);
    // An admitted transfer keeps its two rows.
    let row = pair.account(0);
    pending.admit(&transfer(&row, 1, 5, 1000), unknown).unwrap();
    assert_eq!(pending.rows(), 2);
    // A refused one that touches an admitted row and a new row drops only the new row.
    let mut next = row.clone();
    next.nonce += 1;
    assert!(pending.admit(&transfer(&next, 1, 9, u64::MAX / 2), unknown).is_err());
    assert_eq!(pending.rows(), 2);
    // The admitted sequence continues where it was.
    pending.admit(&transfer(&next, 1, 5, 1000), unknown).unwrap();
    assert!(pending.admit(&transfer(&next, 1, 5, 1000), unknown).is_err());
    assert_eq!(pending.rows(), 2);
    // A guardian list naming many accounts is refused before any is read.
    let guardians = legacy(
        0,
        next.nonce + 2,
        next.auth_epoch,
        1,
        ActionPayload::SetRecovery(ledger::SetRecovery {
            guardians: (1..12).collect(),
            threshold: 6,
            delay_seconds: 30,
        }),
    );
    assert!(pending.admit(&guardians, unknown).is_err());
    assert_eq!(pending.rows(), 2);
}
