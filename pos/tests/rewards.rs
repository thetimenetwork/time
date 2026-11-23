use ed25519_dalek::{Signer, SigningKey};
use time_pos::*;

fn validator(commission: u16) -> Candidate {
    let key = SigningKey::from_bytes(&[81; 32]);
    let public = hex::encode(key.verifying_key().as_bytes());
    let proof = key
        .sign(&register_message([4; 32], 100, &public, commission).unwrap())
        .to_bytes();
    register([4; 32], 100, public, commission, &proof).unwrap()
}

#[test]
fn a_one_microsecond_delegation_cannot_capture_the_validators_own_capital_reward() {
    for commission in [0, 1000, 2000] {
        let mut candidate = validator(commission);
        bond_self(&mut candidate, SELF_BOND_MIN).unwrap();
        let mut owner = OwnerStake::new(200);
        delegate(&mut candidate, &mut owner, 1, 1).unwrap();
        let before = candidate.pool_assets;
        let movement = reward(&mut candidate, SECOND).unwrap();
        assert_eq!(candidate.pool_assets - before, 0);
        assert_eq!(movement.credit, SECOND - 1);
        assert_eq!(movement.bank_debit, SECOND - 1);
    }
}

#[test]
fn equal_live_capital_receives_half_each_with_commission_only_on_delegated_gross() {
    let mut candidate = validator(1000);
    bond_self(&mut candidate, SECOND).unwrap();
    let mut owner = OwnerStake::new(200);
    delegate(&mut candidate, &mut owner, SECOND, 1).unwrap();
    let movement = reward(&mut candidate, 10_000).unwrap();
    assert_eq!(movement.credit, 5500);
    assert_eq!(candidate.pool_assets, SECOND + 4500);
    assert_eq!(movement.bank_debit, 10_000);
}

#[test]
fn bootstrap_virtual_capital_tracks_previous_power_without_rewarding_unbacked_pool_dust() {
    for power in [86_400, 43_200, 1] {
        for commission in [0, 1000, 2000] {
            let mut candidate = validator(commission);
            candidate.genesis = true;
            let mut owner = OwnerStake::new(200);
            delegate(&mut candidate, &mut owner, 1, 1).unwrap();
            let movement = reward_with_weights(&mut candidate, 10_000, 8, Some(power)).unwrap();
            assert_eq!(candidate.pool_assets, 1);
            assert_eq!(movement.credit, 9999);
            assert_eq!(movement.bank_debit, 9999);
        }
    }
    let mut candidate = validator(1000);
    assert_eq!(
        reward_with_weights(&mut candidate, 10_000, 8, None).unwrap(),
        Movement::default()
    );
    assert!(reward_with_weights(&mut candidate, 10_000, 8, Some(1)).is_err());
    candidate.genesis = true;
    assert_eq!(
        reward_with_weights(&mut candidate, 10_000, 8, None).unwrap(),
        Movement::default()
    );
    assert_eq!(
        reward_with_weights(&mut candidate, 10_000, 8, Some(1))
            .unwrap()
            .credit,
        10_000
    );
}

#[test]
fn partial_self_exit_withholds_its_fraction_through_the_last_old_roster_interval() {
    let mut candidate = validator(1000);
    let mut operator = OwnerStake::new(100);
    let mut delegator = OwnerStake::new(200);
    bond_self(&mut candidate, 2 * SECOND).unwrap();
    delegate(&mut candidate, &mut delegator, SECOND, 1).unwrap();
    unbond(
        &mut candidate,
        &mut operator,
        ExitKind::SelfBond,
        SECOND,
        1,
        10,
        0,
    )
    .unwrap();
    assert_eq!(candidate.pending_reward_exits[0].release_height, 12);
    for height in [11, 12] {
        // Independent copies avoid reward compounding changing the test weights.
        let mut paid = candidate.clone();
        let before = paid.escrow().unwrap();
        let movement = reward_with_weights(&mut paid, 9000, height, None).unwrap();
        assert_eq!(movement.credit, 3300);
        assert_eq!(movement.bank_debit, 6000);
        assert_eq!(paid.pool_assets, SECOND + 2700);
        assert_eq!(
            paid.escrow().unwrap() - before + movement.credit,
            movement.bank_debit
        );
        assert_eq!(paid.self_exits.assets, SECOND);
    }
    candidate.prune_reward_exits(12);
    let movement = reward_with_weights(&mut candidate, 9000, 13, None).unwrap();
    assert_eq!(movement.credit, 4950);
    assert_eq!(movement.bank_debit, 9000);
}

#[test]
fn full_self_exit_and_last_pool_exit_cannot_redirect_departed_rewards() {
    let mut candidate = validator(0);
    let mut operator = OwnerStake::new(100);
    let mut delegator = OwnerStake::new(200);
    bond_self(&mut candidate, 2 * SECOND).unwrap();
    delegate(&mut candidate, &mut delegator, 1, 1).unwrap();
    unbond(
        &mut candidate,
        &mut operator,
        ExitKind::SelfBond,
        2 * SECOND,
        1,
        10,
        0,
    )
    .unwrap();
    assert_eq!(
        reward_with_weights(&mut candidate, SECOND, 12, None).unwrap(),
        Movement::default()
    );
    assert_eq!(candidate.pool_assets, 1);

    let mut candidate = validator(1000);
    let mut delegator = OwnerStake::new(200);
    bond_self(&mut candidate, SECOND).unwrap();
    delegate(&mut candidate, &mut delegator, SECOND, 1).unwrap();
    unbond(
        &mut candidate,
        &mut delegator,
        ExitKind::Delegation,
        SECOND,
        1,
        10,
        0,
    )
    .unwrap();
    let movement = reward_with_weights(&mut candidate, 10_000, 12, None).unwrap();
    assert_eq!(movement.credit, 5000);
    assert_eq!(movement.bank_debit, 5000);
    assert_eq!(candidate.pool_assets, 0);
    assert_eq!(candidate.delegated_exits.assets, SECOND);
}

#[test]
fn same_height_exits_coalesce_and_third_height_reclaims_the_oldest_bucket() {
    let mut candidate = validator(1000);
    let mut owner = OwnerStake::new(100);
    bond_self(&mut candidate, 10 * SECOND).unwrap();
    for (id, height) in [10, 10, 11, 12].into_iter().enumerate() {
        unbond(
            &mut candidate,
            &mut owner,
            ExitKind::SelfBond,
            SECOND,
            1,
            height,
            id as u64,
        )
        .unwrap();
        candidate.validate_reward_height(height).unwrap();
        assert!(candidate.pending_reward_exits.len() <= 2);
        if id == 1 {
            assert_eq!(candidate.pending_reward_exits[0].self_amount, 2 * SECOND);
        }
    }
    assert_eq!(
        candidate
            .pending_reward_exits
            .iter()
            .map(|v| v.release_height)
            .collect::<Vec<_>>(),
        vec![13, 14]
    );
    let mut corrupt = candidate.clone();
    corrupt.pending_reward_exits[0].release_height = 12;
    assert!(corrupt.validate_reward_height(12).is_err());
    corrupt = candidate.clone();
    corrupt.pending_reward_exits.push(PendingRewardExit {
        release_height: 15,
        self_amount: 1,
        pool_amount: 0,
    });
    assert!(corrupt.validate().is_err());
}

#[test]
fn slash_erases_ineligible_reward_weights_and_archived_claims_create_no_buckets() {
    let mut candidate = validator(1000);
    let mut owner = OwnerStake::new(100);
    bond_self(&mut candidate, 3 * SECOND).unwrap();
    unbond(
        &mut candidate,
        &mut owner,
        ExitKind::SelfBond,
        SECOND,
        1,
        10,
        0,
    )
    .unwrap();
    slash(&mut candidate).unwrap();
    assert!(candidate.pending_reward_exits.is_empty());
    assert!(reward_with_weights(&mut candidate, 10_000, 11, None).is_err());
    candidate.validate().unwrap();

    let mut candidate = validator(1000);
    let mut owner = OwnerStake::new(200);
    delegate(&mut candidate, &mut owner, 3 * SECOND, 1).unwrap();
    candidate.archived = true;
    for (id, height) in [10, 1000, 2000].into_iter().enumerate() {
        unbond(
            &mut candidate,
            &mut owner,
            ExitKind::Delegation,
            SECOND,
            1,
            height,
            id as u64,
        )
        .unwrap();
        assert!(candidate.pending_reward_exits.is_empty());
        candidate.validate_reward_height(height).unwrap();
    }
}

#[test]
fn varied_cash_weights_conserve_every_debited_unit_and_never_pay_exits() {
    for own in [0, 1, 17, SECOND] {
        for pool in [0, 1, 19, SECOND] {
            for exiting in [0, 1, 23, SECOND] {
                for commission in [0, 1000, 2000] {
                    let mut candidate = validator(commission);
                    if own + exiting > 0 {
                        bond_self(&mut candidate, own + exiting).unwrap();
                    }
                    let mut operator = OwnerStake::new(100);
                    if exiting > 0 {
                        unbond(
                            &mut candidate,
                            &mut operator,
                            ExitKind::SelfBond,
                            exiting,
                            1,
                            10,
                            0,
                        )
                        .unwrap();
                    }
                    if pool > 0 {
                        delegate(&mut candidate, &mut OwnerStake::new(200), pool, 1).unwrap();
                    }
                    let before = candidate.escrow().unwrap();
                    let effect = reward_with_weights(&mut candidate, 10_003, 11, None).unwrap();
                    let denominator = u128::from(own + pool + exiting);
                    let expected = (10_003 * u128::from(own))
                        .checked_div(denominator)
                        .unwrap_or(0)
                        + (10_003 * u128::from(pool))
                            .checked_div(denominator)
                            .unwrap_or(0);
                    assert_eq!(u128::from(effect.bank_debit), expected);
                    assert_eq!(
                        candidate.escrow().unwrap() - before + effect.credit,
                        effect.bank_debit
                    );
                    assert_eq!(candidate.self_exits.assets, exiting);
                    assert!(effect.bank_debit <= 10_003);
                }
            }
        }
    }
}
