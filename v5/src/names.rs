//! Names that look alike.
//!
//! An account name is 2 to 15 bytes of `a-z`, `0-9` and `_`, so uppercase
//! letters, letters of other alphabets and spaces cannot be used to imitate a
//! name. What is left is inside that alphabet: `paypa1` for `paypal`, `al_ice`
//! for `alice`, `barn` for `bam`. A network whose genesis sets
//! `distinct_names` refuses a new name that looks like a name that exists.
//!
//! Two names look alike when they have the same *skeleton*. The skeleton of a
//! name, in this order:
//!
//! 1. every `_` is removed;
//! 2. every `0` becomes `o`, every `1` becomes `l` and every `w` becomes `vv`;
//! 3. in one pass from left to right over the result, without overlap, `rn`
//!    becomes `m` and `vv` becomes `w`.
//!
//! Step 2 reads `w` as `vv` so that a row of `v` and `w` has one skeleton
//! however it is cut: `vw`, `wv` and `vvv` are one name to the rule.
//!
//! `spec/name-skeleton-vectors.json` holds test vectors, which the SDK
//! (`client-v4/time-sdk.js`) and the genesis ceremony (`tools/genesis-v5.mjs`)
//! are tested against as well.
//!
//! On such a network:
//!
//! - the state holds one row per account, `name_skeleton/` ‖ skeleton, whose
//!   value is the account's name as a JSON string. It is a row like any
//!   other: under the state root, in snapshots, and proven present or absent
//!   like any row;
//! - a genesis in which two account names have the same skeleton, or a name
//!   has the empty skeleton (underscores only), is refused
//!   (`genesis::Genesis::validate`);
//! - a reveal (kind 2), which is the one action that creates a name and the
//!   point where a sponsored registration makes its name known, is refused
//!   if the skeleton of its name is empty or has a row. The refusal names
//!   the existing name. Like any refused reveal it changes nothing: the paid
//!   commitment stays until it expires, and the sponsor's charge is not
//!   returned (`engine::Overlay::apply_legacy`).
//!
//! A network without the setting has no such row and accepts every name
//! protocol 4 accepts.
//!
//! What the rule does not catch is left to wallets: one changed letter, `i`
//! for `l`, `b1nance` for `binance` (its skeleton is `blnance`).

/// The rows of the rule: `PREFIX` followed by a skeleton.
pub const PREFIX: &[u8] = b"name_skeleton/";

/// The skeleton of `name`. Defined for every string; the rule only ever
/// takes it of a valid name, whose skeleton is at most as long as the name
/// and holds only `a-z` and `2-9`.
pub fn skeleton(name: &str) -> String {
    let mut read = String::with_capacity(name.len() * 2);
    for character in name.chars() {
        match character {
            '_' => {}
            '0' => read.push('o'),
            '1' => read.push('l'),
            'w' => read.push_str("vv"),
            other => read.push(other),
        }
    }
    let mut out = String::with_capacity(read.len());
    let mut rest = read.chars().peekable();
    while let Some(character) = rest.next() {
        match (character, rest.peek()) {
            ('r', Some('n')) => {
                rest.next();
                out.push('m');
            }
            ('v', Some('v')) => {
                rest.next();
                out.push('w');
            }
            _ => out.push(character),
        }
    }
    out
}

/// The key of the row that records which name owns `skeleton`.
pub fn key(skeleton: &str) -> Vec<u8> {
    [PREFIX, skeleton.as_bytes()].concat()
}

/// Why a name whose skeleton is empty is refused.
pub const EMPTY: &str = "this name has no letter and no digit: a name of underscores alone cannot be told from another";

/// Why a name is refused whose skeleton `existing` already has.
pub fn too_close(name: &str, existing: &str) -> String {
    format!("the name {name} is too close to the existing name {existing}: choose a name that does not look like it")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Vector {
        name: String,
        skeleton: String,
    }
    #[derive(serde::Deserialize)]
    struct Vectors {
        vectors: Vec<Vector>,
    }

    fn vectors() -> Vec<Vector> {
        let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/name-skeleton-vectors.json");
        let bytes = std::fs::read(&file).unwrap_or_else(|error| panic!("{}: {error}", file.display()));
        serde_json::from_slice::<Vectors>(&bytes).unwrap().vectors
    }

    #[test]
    fn the_skeleton_of_every_vector() {
        let vectors = vectors();
        // The file is shared with the SDK's test: neither may pass on a
        // shortened list.
        assert_eq!(vectors.len(), 33);
        for vector in &vectors {
            assert_eq!(skeleton(&vector.name), vector.skeleton, "{}", vector.name);
        }
        // The cases the rule is made of are among them.
        let of = |name: &str| vectors.iter().find(|vector| vector.name == name).map(|vector| vector.skeleton.as_str()).unwrap();
        assert_eq!(of("al_ice"), of("alice"));
        assert_eq!(of("paypa1"), of("paypal"));
        assert_eq!(of("barn"), of("bam"));
        assert_eq!(of("vvv"), "wv");
        assert_eq!(of("__"), "");
        assert_ne!(of("b1nance"), of("binance"));
    }

    #[test]
    fn a_skeleton_is_shorter_or_equal_and_its_own_skeleton() {
        // Every name of up to five characters over the letters the rule
        // touches: the pass leaves no `_`, `0`, `1`, `rn` or `vv` behind.
        let letters = ['r', 'n', 'v', 'w', 'm', '_', '0', '1', 'a'];
        let mut names: Vec<String> = letters.iter().map(|letter| letter.to_string()).collect();
        let mut checked = 0;
        for _ in 2..=5 {
            names = names
                .iter()
                .flat_map(|name| letters.iter().map(move |letter| format!("{name}{letter}")))
                .collect();
            for name in &names {
                let once = skeleton(name);
                assert!(once.len() <= name.len(), "{name}");
                assert!(!once.contains(['_', '0', '1']) && !once.contains("rn") && !once.contains("vv"), "{name}");
                assert_eq!(skeleton(&once), once, "{name}");
                checked += 1;
            }
        }
        assert_eq!(checked, 9usize.pow(2) + 9usize.pow(3) + 9usize.pow(4) + 9usize.pow(5));
    }

    #[test]
    fn the_key_of_a_skeleton() {
        assert_eq!(key("alice"), b"name_skeleton/alice");
        // Never under the prefix of the name index, `name/`.
        assert!(!key("alice").starts_with(b"name/"));
        assert_eq!(key(""), PREFIX);
    }

    #[test]
    fn the_refusal_names_both_names() {
        let refusal = too_close("paypa1", "paypal");
        assert!(refusal.contains("paypa1") && refusal.contains("too close to the existing name paypal"), "{refusal}");
    }
}
