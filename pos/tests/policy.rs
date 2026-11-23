use ed25519_dalek::{Signer, SigningKey};
use tendermint::{Hash, Signature, Time, Vote, account, block};
use time_pos::*;
fn signing(id: u64) -> SigningKey {
    use sha2::{Digest, Sha256};
    SigningKey::from_bytes(&Sha256::digest(id.to_be_bytes()).into())
}
fn public(id: u64) -> String {
    hex::encode(signing(id).verifying_key().as_bytes())
}
fn candidate(id: u64, genesis: bool) -> Candidate {
    Candidate {
        owner: id,
        consensus_key: public(id),
        commission_bps: 1000,
        self_bond: 0,
        pool_assets: 0,
        pool_shares: 0,
        self_exits: ExitPool::default(),
        delegated_exits: ExitPool::default(),
        pending_reward_exits: Vec::new(),
        jailed: false,
        genesis,
        archived: false,
        last_active_end: 0,
    }
}
fn boot(profile: Profile) -> (Summary, Vec<Candidate>) {
    let candidates = (0..20).map(|id| candidate(id, true)).collect::<Vec<_>>();
    let roster = candidates
        .iter()
        .map(|c| Validator {
            owner: c.owner,
            consensus_key: c.consensus_key.clone(),
            power: profile.genesis_power(),
        })
        .collect();
    (Summary::with_profile(roster, profile).unwrap(), candidates)
}
fn admit(summary: &mut Summary, candidates: &mut Vec<Candidate>, id: u64, extra: u64) {
    let proof = signing(id)
        .sign(&register_message([4; 32], id, &public(id), 1000).unwrap())
        .to_bytes();
    let (mut item, movement) =
        register_bonded([4; 32], id, public(id), 1000, &proof, summary.profile).unwrap();
    assert_eq!(movement.debit, summary.profile.min_self_bond());
    if extra > 0 {
        bond_self(&mut item, extra).unwrap();
    }
    summary.admit_candidate(&item, candidates).unwrap();
    candidates.push(item);
}
#[test]
fn zero_supply_bootstrap_survives_day90_and_hands_off_without_resurrection_by_day120() {
    let (mut summary, mut candidates) = boot(Profile::Production);
    assert_eq!(summary.escrow, 0);
    let mut bank = 0;
    let mut issued = 0;
    for day in 1..=120u64 {
        issued += DAY;
        bank += DAY;
        summary
            .begin_block(day, day * DAY, &mut candidates)
            .unwrap();
        if day <= 100 {
            admit(&mut summary, &mut candidates, 19 + day, 0);
            bank -= SELF_BOND_MIN;
        }
        summary.reconcile(&candidates, None).unwrap();
        assert_eq!(summary.escrow + bank, issued);
        assert!(summary.churn.iter().map(|c| c.units).sum::<u64>() <= 333_333_333);
        if day == 90 {
            assert!(summary.escrow <= 90 * DAY);
        }
    }
    assert!(
        summary.bootstrap_ended,
        "funded power must finish replacing virtual genesis power"
    );
    assert!(summary.active.iter().all(|v| v.owner >= 20));
    assert!(summary.active.len() >= 7);
    for candidate in &mut candidates {
        if !candidate.genesis {
            candidate.jailed = true;
        }
    }
    summary
        .begin_block(121, 121 * DAY, &mut candidates)
        .unwrap();
    summary.reconcile(&candidates, None).unwrap();
    assert!(summary.safety_hold);
    assert!(summary.active.iter().all(|v| v.owner >= 20));
    // Lack of funded candidates cannot trigger an implicit founder reset.
    assert!(summary.bootstrap_ended);
}
#[test]
fn day90_without_seven_funded_validators_preserves_explicit_bootstrap() {
    let (mut summary, mut candidates) = boot(Profile::Production);
    for day in 1..=120 {
        summary
            .begin_block(day, day * DAY, &mut candidates)
            .unwrap();
        summary.reconcile(&candidates, None).unwrap();
    }
    assert!(!summary.bootstrap_ended);
    assert_eq!(summary.active.len(), 20);
    assert_eq!(summary.escrow, 0);
}
#[test]
fn rolling_budget_cannot_reset_at_an_hour_boundary_and_h2_is_exact() {
    let (mut s, mut candidates) = boot(Profile::Laboratory);
    for id in 20..35 {
        admit(&mut s, &mut candidates, id, 0);
    }
    s.begin_block(1, 19 * SECOND, &mut candidates).unwrap();
    let initial = s.active.clone();
    let first = s.reconcile(&candidates, None).unwrap().unwrap();
    assert_eq!(first.effective_height, 3);
    assert_eq!(s.active, initial);
    let spent = s.churn.iter().map(|c| c.units).sum::<u64>();
    assert!(spent > 0);
    s.begin_block(2, 20 * SECOND, &mut candidates).unwrap();
    s.reconcile(&candidates, None).unwrap();
    assert!(s.churn.iter().map(|c| c.units).sum::<u64>() >= spent);
    assert!(s.churn.iter().map(|c| c.units).sum::<u64>() <= 333_333_333);
    s.begin_block(3, 21 * SECOND, &mut candidates).unwrap();
    assert_eq!(s.active, first.validators);
}
#[test]
fn normalized_voting_power_churn_charges_additions_even_without_removals() {
    let old = (0..7)
        .map(|id| Validator {
            owner: id,
            consensus_key: public(id),
            power: 10,
        })
        .collect::<Vec<_>>();
    let mut new = old.clone();
    new.push(Validator {
        owner: 7,
        consensus_key: public(7),
        power: 1_000_000,
    });
    assert!(churn_units(&old, &new).unwrap() > 999_000_000);
    let mut scaled = old.clone();
    for v in &mut scaled {
        v.power *= 2;
    }
    assert_eq!(churn_units(&old, &scaled).unwrap(), 0);
}
#[test]
fn real_bond_delegation_reward_unbond_slash_and_withdraw_conserve_every_unit() {
    let mut validator = candidate(100, false);
    let mut owner = OwnerStake::new(100);
    let mut delegator = OwnerStake::new(200);
    let total = SELF_BOND_MIN + 2_000_000;
    let mut liquid = total;
    let mut bank = 100_000;
    liquid -= bond_self(&mut validator, SELF_BOND_MIN).unwrap().debit;
    liquid -= delegate(&mut validator, &mut delegator, 2_000_000, 1)
        .unwrap()
        .debit;
    let reward = reward(&mut validator, 100_000).unwrap();
    bank -= reward.bank_debit;
    liquid += reward.credit;
    assert_eq!(liquid + bank + validator.escrow().unwrap(), total + 100_000);
    unbond(
        &mut validator,
        &mut owner,
        ExitKind::SelfBond,
        SELF_BOND_MIN,
        1,
        10,
        1,
    )
    .unwrap();
    unbond(
        &mut validator,
        &mut delegator,
        ExitKind::Delegation,
        1_000_000,
        1,
        10,
        2,
    )
    .unwrap();
    let penalty = slash(&mut validator).unwrap().bank_credit;
    bank += penalty;
    assert_eq!(liquid + bank + validator.escrow().unwrap(), total + 100_000);
    assert!(withdraw(&mut validator, &mut owner, 1, 12, UNBOND_DELAY, 1, false).is_err());
    assert!(withdraw(&mut validator, &mut owner, 1, 12, UNBOND_DELAY + 1, 1, true).is_err());
    liquid += withdraw(
        &mut validator,
        &mut owner,
        1,
        12,
        UNBOND_DELAY + 1,
        1,
        false,
    )
    .unwrap()
    .credit;
    liquid += withdraw(
        &mut validator,
        &mut delegator,
        2,
        12,
        UNBOND_DELAY + 1,
        1,
        false,
    )
    .unwrap()
    .credit;
    assert_eq!(liquid + bank + validator.escrow().unwrap(), total + 100_000);
    assert!(slash(&mut validator).is_err());
}
fn vote(id: u64, block_byte: u8) -> Vote {
    let raw = hex::decode(public(id)).unwrap();
    let key = tendermint::PublicKey::from_raw_ed25519(&raw).unwrap();
    let mut vote = Vote {
        vote_type: tendermint::vote::Type::Precommit,
        height: 10u64.try_into().unwrap(),
        round: 0u32.try_into().unwrap(),
        block_id: Some(block::Id {
            hash: Hash::Sha256([block_byte; 32]),
            part_set_header: block::parts::Header::new(1, Hash::Sha256([block_byte + 1; 32]))
                .unwrap(),
        }),
        timestamp: Some(Time::from_unix_timestamp(100, 0).unwrap()),
        validator_address: account::Id::from(key),
        validator_index: 0u32.try_into().unwrap(),
        signature: None,
        extension: vec![],
        extension_signature: None,
    };
    let mut bytes = Vec::new();
    vote.to_signable_bytes("time-devnet-v4-test".parse().unwrap(), &mut bytes)
        .unwrap();
    vote.signature =
        Some(Signature::try_from(signing(id).sign(&bytes).to_bytes().to_vec()).unwrap());
    vote
}
#[test]
fn double_sign_checks_actual_comet_signatures_history_chain_slot_age_and_replay() {
    let history = HistoricalMembership {
        height: 10,
        elapsed_micros: 100,
        validators: vec![Validator {
            owner: 100,
            consensus_key: public(100),
            power: 100,
        }],
    };
    let evidence = DoubleSignEvidence {
        first: vote(100, 1),
        second: vote(100, 3),
    };
    let (owner, key) =
        verify_double_sign("time-devnet-v4-test", &evidence, &history, 200, false).unwrap();
    assert_eq!(owner, 100);
    assert_ne!(key, [0; 32]);
    assert!(verify_double_sign("other-chain", &evidence, &history, 200, false).is_err());
    assert!(verify_double_sign("time-devnet-v4-test", &evidence, &history, 200, true).is_err());
    assert!(
        verify_double_sign(
            "time-devnet-v4-test",
            &evidence,
            &history,
            UNBOND_DELAY + 101,
            false
        )
        .is_err()
    );
    let same = DoubleSignEvidence {
        first: vote(100, 1),
        second: vote(100, 1),
    };
    assert!(verify_double_sign("time-devnet-v4-test", &same, &history, 200, false).is_err());
    let stranger = DoubleSignEvidence {
        first: vote(101, 1),
        second: vote(101, 3),
    };
    assert!(verify_double_sign("time-devnet-v4-test", &stranger, &history, 200, false).is_err());
}

#[test]
fn candidate_registration_is_bonded_bounded_and_failed_admission_is_atomic() {
    let (mut summary, mut candidates) = boot(Profile::Laboratory);
    let mut unfunded = candidate(100, false);
    assert!(summary.admit_candidate(&unfunded, &candidates).is_err());
    bond_self(&mut unfunded, SECOND).unwrap();
    summary.escrow = u64::MAX;
    let before = summary.clone();
    assert!(summary.admit_candidate(&unfunded, &candidates).is_err());
    assert_eq!(summary, before);
    summary.escrow = 0;
    for id in 20..MAX_CANDIDATES as u64 {
        admit(&mut summary, &mut candidates, id, 0);
    }
    let mut extra = candidate(1000, false);
    bond_self(&mut extra, SECOND).unwrap();
    let before = summary.clone();
    assert!(summary.admit_candidate(&extra, &candidates).is_err());
    assert_eq!(summary, before);
    assert_eq!(summary.candidate_ids.len(), MAX_CANDIDATES);
}

#[test]
fn oversized_single_key_is_capped_and_empty_or_missing_rosters_are_rejected() {
    let (mut summary, mut candidates) = boot(Profile::Laboratory);
    for id in 20..27 {
        admit(
            &mut summary,
            &mut candidates,
            id,
            if id == 20 { 1_000_000 * SECOND } else { 0 },
        );
    }
    for height in 1..=160 {
        summary
            .begin_block(height, height * SECOND, &mut candidates)
            .unwrap();
        summary.reconcile(&candidates, None).unwrap();
        let latest = summary.latest();
        let total: u64 = latest.iter().map(|v| v.power).sum();
        assert!(latest.iter().all(|v| v.power as u128 * 3 < total as u128));
        assert!(summary.churn.len() <= 61);
    }
    assert!(summary.bootstrap_ended);
    assert!(summary.active.len() >= MIN_FUNDED);
    let before = summary.clone();
    let mut incomplete = candidates[1..].to_vec();
    assert!(
        summary
            .begin_block(161, 161 * SECOND, &mut incomplete)
            .is_err()
    );
    assert_eq!(summary, before);
    assert!(validate_set(&[]).is_err());
    // After bootstrap, seven is a handoff threshold, not a permanent minimum:
    // a healthy six-authority set can remain below the one-third power bound.
    for row in &mut candidates {
        if (20..24).contains(&row.owner) {
            summary.escrow -= row.escrow().unwrap();
            row.self_bond = 0;
        }
    }
    let before = summary.clone();
    assert!(summary.reconcile(&candidates, Some(20)).is_err());
    assert_eq!(summary, before);
}

#[test]
fn retirement_waits_for_all_claims_actual_removal_and_evidence_window() {
    let (mut summary, mut candidates) = boot(Profile::Laboratory);
    admit(&mut summary, &mut candidates, 100, 0);
    let index = candidates.iter().position(|c| c.owner == 100).unwrap();
    candidates[index].last_active_end = 1;
    assert!(summary.retire_candidate(&mut candidates[index]).is_err());
    let mut owner = OwnerStake::new(100);
    unbond(
        &mut candidates[index],
        &mut owner,
        ExitKind::SelfBond,
        SECOND,
        1,
        1,
        0,
    )
    .unwrap();
    assert!(summary.retire_candidate(&mut candidates[index]).is_err());
    let credit = withdraw(
        &mut candidates[index],
        &mut owner,
        0,
        3,
        UNBOND_DELAY + 1,
        1,
        false,
    )
    .unwrap()
    .credit;
    summary.escrow -= credit;
    summary.last_elapsed = UNBOND_DELAY + 2;
    summary.retire_candidate(&mut candidates[index]).unwrap();
    assert!(!summary.candidate_ids.contains(&"100".to_string()));
}

#[test]
fn evidence_identity_is_order_independent_and_updates_include_zero_power_removals() {
    let history = HistoricalMembership {
        height: 10,
        elapsed_micros: 1,
        validators: vec![Validator {
            owner: 100,
            consensus_key: public(100),
            power: 10,
        }],
    };
    let first = DoubleSignEvidence {
        first: vote(100, 1),
        second: vote(100, 3),
    };
    let second = DoubleSignEvidence {
        first: vote(100, 3),
        second: vote(100, 1),
    };
    assert_eq!(
        verify_double_sign("time-devnet-v4-test", &first, &history, 2, false)
            .unwrap()
            .1,
        verify_double_sign("time-devnet-v4-test", &second, &history, 2, false)
            .unwrap()
            .1
    );
    let new = vec![Validator {
        owner: 200,
        consensus_key: public(200),
        power: 20,
    }];
    let changes = validator_updates(&history.validators, &new).unwrap();
    assert_eq!(changes.len(), 2);
    assert!(changes.iter().any(|v| v.owner == 100 && v.power == 0));
    assert!(changes.iter().any(|v| v.owner == 200 && v.power == 20));
}

#[test]
fn self_exit_waits_fourteen_days_after_actual_late_removal() {
    let mut validator = candidate(100, false);
    let mut owner = OwnerStake::new(100);
    bond_self(&mut validator, SELF_BOND_MIN + SECOND).unwrap();
    unbond(
        &mut validator,
        &mut owner,
        ExitKind::SelfBond,
        SECOND,
        1,
        10,
        0,
    )
    .unwrap();
    // This identity continued voting for a month after the original exit.
    validator.last_active_end = 30 * DAY;
    let before = validator.clone();
    let owner_before = owner.clone();
    assert!(withdraw(&mut validator, &mut owner, 0, 100, 30 * DAY, SECOND, false).is_err());
    assert_eq!(validator, before);
    assert_eq!(owner, owner_before);
    assert!(
        withdraw(
            &mut validator,
            &mut owner,
            0,
            100,
            44 * DAY - 1,
            SECOND,
            false
        )
        .is_err()
    );
    assert_eq!(
        withdraw(&mut validator, &mut owner, 0, 100, 44 * DAY, SECOND, false)
            .unwrap()
            .credit,
        SECOND
    );
}

#[test]
fn verified_jailed_authority_is_removed_despite_spent_churn_but_unsafe_survivors_hold() {
    let (mut s, mut rows) = boot(Profile::Laboratory);
    s.churn = vec![ChurnCharge {
        expires_at: 10 * SECOND,
        units: 333_333_333,
    }];
    rows[0].jailed = true;
    let planned = s.reconcile(&rows, None).unwrap().unwrap();
    assert_eq!(planned.effective_height, 2);
    assert_eq!(planned.validators.len(), 19);
    assert!(!planned.validators.iter().any(|v| v.owner == 0));
    assert!(s.safety_hold);
    assert_eq!(s.churn[0].units, 333_333_333);
    // Fewer than four remaining authorities cannot restore a secure quorum.
    for c in &mut rows {
        if c.owner < 18 {
            c.jailed = true;
        }
    }
    assert!(s.reconcile(&rows, None).unwrap().is_none());
    assert!(s.safety_hold);
    assert!(!s.bootstrap_ended); // no reset or new virtual authority is created.
}

#[test]
fn full_directory_admits_stronger_candidate_without_archiving_live_or_exposed_authority() {
    let (mut s, mut rows) = boot(Profile::Laboratory);
    for id in 20..MAX_CANDIDATES as u64 {
        admit(&mut s, &mut rows, id, 0);
    }
    let mut entrant = candidate(1000, false);
    bond_self(&mut entrant, 2 * SECOND).unwrap();
    let old_total = s.escrow;
    let victim = s.admit_with_priority(&entrant, &mut rows).unwrap().unwrap();
    assert_eq!(victim, 255);
    assert_eq!(s.candidate_ids.len(), MAX_CANDIDATES);
    assert!(rows.iter().find(|c| c.owner == victim).unwrap().archived);
    assert_eq!(s.archived_escrow, SECOND);
    assert_eq!(s.escrow, old_total + 2 * SECOND);
    assert!(s.active.iter().all(|v| v.owner != victim));
    let mut active: Vec<_> = rows.iter().filter(|c| !c.archived).cloned().collect();
    active.push(entrant);
    let mut equal = candidate(1001, false);
    bond_self(&mut equal, SECOND).unwrap();
    let before = s.clone();
    assert!(s.admit_with_priority(&equal, &mut active).is_err());
    assert_eq!(s, before);
    for row in &mut active {
        if !s.current_or_scheduled(row.owner) {
            row.last_active_end = 1;
        }
    }
    s.last_elapsed = 2;
    let mut richer = candidate(1002, false);
    bond_self(&mut richer, 100 * SECOND).unwrap();
    let before = s.clone();
    assert!(s.admit_with_priority(&richer, &mut active).is_err());
    assert_eq!(s, before);
    assert!(active.iter().all(|c| !c.archived));
}
