use crate::{fixtures::*, light::*};
use serde_json::{Value, json};
use tendermint::block::CommitSig;

const A: [(u8, u64); 4] = [(1, 10), (2, 10), (3, 10), (4, 10)];
const B: [(u8, u64); 4] = [(5, 10), (6, 10), (7, 10), (8, 10)];
#[test]
fn real_quorums_require_bisection_then_authenticate_h_plus_two_rotation() {
    let (first, mut pin) = bootstrap(&A);
    let result = update(first.clone(), &pin, now()).unwrap();
    pin.checkpoint = Some(checkpoint_from(&result));
    let second = block(2, &A, &B, Some(&first), T0 + 2);
    let third = block(3, &B, &B, Some(&second), T0 + 3);
    let skipped = update(third.clone(), &pin, now()).unwrap();
    assert_eq!(skipped["verified"], false);
    assert_eq!(skipped["status"], "NEEDS_BISECTION");
    assert_eq!(skipped["suggestedHeight"], "2");
    pin.checkpoint = Some(checkpoint_from(&update(second, &pin, now()).unwrap()));
    let accepted = update(third, &pin, now()).unwrap();
    assert_eq!(accepted["verified"], true);
    assert_eq!(accepted["checkpoint"]["height"], "3");
}
#[test]
fn new_committee_cannot_activate_one_height_early() {
    let (first, mut pin) = bootstrap(&A);
    pin.checkpoint = Some(checkpoint(first.clone()));
    let early = block(2, &B, &B, Some(&first), T0 + 2);
    assert!(update(early, &pin, now()).is_err());
}
#[test]
fn next_set_and_trusted_next_set_must_match_the_signed_hashes() {
    let (first, mut pin) = bootstrap(&A);
    pin.checkpoint = Some(checkpoint(first.clone()));
    let second = block(2, &A, &B, Some(&first), T0 + 2);
    let mut forged = second.clone();
    forged.next_validators = values(&roster(&A));
    assert!(update(forged, &pin, now()).is_err());
    pin.checkpoint.as_mut().unwrap().block.next_validators = values(&roster(&B));
    assert!(update(second, &pin, now()).is_err());
}
#[test]
fn overlap_uses_old_voting_power_rather_than_key_count_or_new_power() {
    let old = [(1, 70), (2, 10), (3, 10), (4, 10)];
    let new = [(2, 50), (3, 20), (4, 20), (5, 10)];
    let (first, mut pin) = bootstrap(&old);
    pin.checkpoint = Some(checkpoint(first.clone()));
    let second = block(2, &old, &new, Some(&first), T0 + 2);
    let third = block(3, &new, &new, Some(&second), T0 + 3);
    assert_eq!(
        update(third, &pin, now()).unwrap()["status"],
        "NEEDS_BISECTION"
    );
    let enough = [(1, 5), (5, 95)];
    let second = block(2, &old, &enough, Some(&first), T0 + 2);
    let third = block(3, &enough, &enough, Some(&second), T0 + 3);
    assert_eq!(update(third, &pin, now()).unwrap()["verified"], true);
}
#[test]
fn exactly_one_third_overlap_is_insufficient() {
    let old = [(1, 100), (2, 100), (3, 100)];
    let new = [(1, 100), (4, 100), (5, 100)];
    let (first, mut pin) = bootstrap(&old);
    pin.checkpoint = Some(checkpoint(first.clone()));
    let second = block(2, &old, &new, Some(&first), T0 + 2);
    let third = block(3, &new, &new, Some(&second), T0 + 3);
    assert_eq!(
        update(third, &pin, now()).unwrap()["status"],
        "NEEDS_BISECTION"
    );
}
#[test]
fn expired_genesis_and_checkpoint_cannot_be_refreshed_by_a_fresh_rpc_header() {
    let (first, mut pin) = bootstrap(&A);
    let stale_now = i128::from(T0 + 1 + 604801) * 1_000_000;
    let forged_first = block(1, &A, &A, None, T0 + 1 + 604800);
    assert!(
        update(forged_first, &pin, stale_now)
            .unwrap_err()
            .starts_with("CHECKPOINT_REFRESH_REQUIRED")
    );
    pin.checkpoint = Some(checkpoint(first.clone()));
    let fresh = block(2, &A, &A, Some(&first), T0 + 1 + 604800);
    assert!(
        update(fresh, &pin, stale_now)
            .unwrap_err()
            .starts_with("CHECKPOINT_REFRESH_REQUIRED")
    );
}
#[test]
fn wrong_network_version_quorum_rollback_parent_or_checkpoint_metadata_fail_closed() {
    let (first, mut pin) = bootstrap(&A);
    let second = block(2, &A, &A, Some(&first), T0 + 2);
    pin.checkpoint = Some(checkpoint(first.clone()));
    let mut bad = second.clone();
    bad.signed_header.commit.signatures[0] = CommitSig::BlockIdFlagAbsent;
    bad.signed_header.commit.signatures[1] = CommitSig::BlockIdFlagAbsent;
    assert!(update(bad, &pin, now()).is_err());
    let mut bad = second.clone();
    bad.signed_header.header.version.app = 3;
    assert!(update(bad, &pin, now()).is_err());
    let bad = block(2, &A, &A, None, T0 + 2);
    assert!(update(bad, &pin, now()).is_err());
    pin.checkpoint.as_mut().unwrap().block_hash = "00".repeat(32);
    assert!(update(second.clone(), &pin, now()).is_err());
    pin.checkpoint = Some(checkpoint(second));
    assert!(
        update(first, &pin, now())
            .unwrap_err()
            .starts_with("HEADER_ROLLBACK")
    );
}
#[test]
fn checkpoint_policy_requires_explicit_four_and_accountability_longer_than_trust() {
    let (_, mut pin) = bootstrap(&A);
    pin.app_version = "3".into();
    assert!(policy(&pin).is_err());
    pin.app_version = "4".into();
    pin.unbonding_period_seconds = "604800".into();
    assert!(policy(&pin).is_err());
    let _fixture: Value = public_fixture();
    assert_eq!(_fixture["trust"]["app_version"], json!("4"));
}
#[test]
fn export_public_dynamic_fixture_when_explicitly_requested() {
    if std::env::var("V4_REBUILD_PUBLIC_FIXTURES").ok().as_deref() == Some("1") {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(
            path.join("dynamic.json"),
            serde_json::to_vec_pretty(&public_fixture()).unwrap(),
        )
        .unwrap();
    }
}
