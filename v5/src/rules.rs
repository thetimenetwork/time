//! The versions of the rules this program implements, and the gate by which
//! code asks which rules execute a block.
//!
//! The version of a chain is the number in `Meta::protocol_version`. It names
//! the rules that execute the *next* block. A program holds a list of the
//! versions it implements, each with the hash of its specification, and
//! executes nothing on a head whose version is not in that list
//! (`crate::upgrade::runnable`).
//!
//! **A version never changes what an existing action kind or payload does.**
//! The action header carries no version, approvals of a root operation live
//! up to thirty days, and a transaction signed before an activation can land
//! after it: bytes signed under one version must mean the same under the
//! next. New behaviour is a new kind, or a new field that is refused before
//! its version:
//!
//! ```text
//! ensure!(self.rules.since(5), "this action needs protocol version 5");
//! ```
//!
//! A version may stop accepting a kind; it never makes one do something else.
use crate::engine::Meta;
use anyhow::{Result, ensure};

/// The version every network starts at. It is the one in the genesis and in
/// the trust manifest of a network, and those never change.
pub const FIRST_VERSION: u64 = 4;

/// SHA-256 of `spec/protocol-4.md`, the rules of version 4 as release 1
/// executes them. A test compares it with the file.
pub const SPEC_4: &str = "f5210c50c56000f8dda94dd4d89583d7642b587c8e1a290699f55348b39a32c1";

/// The version a rehearsal build adds, and the hash it goes by. It is
/// SHA-256 of the ASCII text `time-currency rehearsal: protocol version 5
/// with the rules of version 4`, not the hash of any specification: no
/// specification of a version 5 exists.
pub const REHEARSAL_VERSION: u64 = 5;
pub const REHEARSAL_SPEC: &str = "21233a92e2258d1174a70424162524dce6bf9b4409e766c759cf9d35cf6bf442";
/// The text `REHEARSAL_SPEC` is the hash of.
pub const REHEARSAL_SPEC_TEXT: &str =
    "time-currency rehearsal: protocol version 5 with the rules of version 4";

/// Whether this build carries the rehearsal version (`--features
/// rehearsal-v5`). Such a build is for rehearsing an activation with two real
/// programs. It says so in its version line, which no release may carry.
pub const REHEARSAL: bool = cfg!(feature = "rehearsal-v5");

/// What this build implements: contiguous from `FIRST_VERSION`.
#[cfg(not(feature = "rehearsal-v5"))]
pub const IMPLEMENTED: &[(u64, &str)] = &[(FIRST_VERSION, SPEC_4)];
#[cfg(feature = "rehearsal-v5")]
pub const IMPLEMENTED: &[(u64, &str)] =
    &[(FIRST_VERSION, SPEC_4), (REHEARSAL_VERSION, REHEARSAL_SPEC)];

/// The rule switches compiled into this build, each as the network it is
/// for, the version it switches to and where (`Switch::parse`). **This
/// release has none: it is not a fix release.**
///
/// A fix release (design, section 10) is made by a change of this source,
/// reviewed like any other: the new version and the hash of its
/// specification are added to `IMPLEMENTED`, and one line is added here. It
/// then changes the rules of that one network at that one place without a
/// plan, and of no other network. Every later release keeps the line, so
/// that it replays that chain from its first block.
pub const SWITCHES: &[(&str, u64, &str)] = &[];

/// A rehearsal build may carry one switch to the rehearsal version, read
/// from the environment of the compiler (`TIME_REHEARSAL_SWITCH`, in the
/// form of `Switch::parse`). Only a rehearsal build looks at it: in a
/// release build the variable is not read and changes nothing.
#[cfg(feature = "rehearsal-v5")]
pub const REHEARSAL_SWITCH: Option<&str> = option_env!("TIME_REHEARSAL_SWITCH");
#[cfg(not(feature = "rehearsal-v5"))]
pub const REHEARSAL_SWITCH: Option<&str> = None;

/// REHEARSAL BUILDS ONLY. The amount, in microseconds, of the payment that
/// the deliberately faulty rule of a rehearsal build cannot finalize
/// (`app::App::try_finalize`): a decided block that carries a payment of
/// exactly this amount fails its check, on every node alike, until the
/// rehearsal version is in force or the block is the one a fix release
/// repairs. It exists to rehearse a stop in the middle of a block. No
/// release build contains the rule. (The amount is small, 0.081081 s: an
/// owner account of a network that is minutes old must be able to pay it.)
pub const REHEARSAL_FAULT_MICROS: u64 = 81_081;

/// Where a fix release changes the rules without a plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwitchAt {
    /// At a height the validators agreed on (design, section 10): the block
    /// after `height` carries exactly one transaction, the switch (action
    /// kind 81), and nothing else. The faulty rules run up to and including
    /// that block; the fix applies from the block after it.
    After { height: u64 },
    /// At a block that was decided and that no program could execute (a
    /// stop in the middle of a block): the block `height` with the hash
    /// `block_hash`, on the state whose root is `parent_root`, is executed
    /// by this program, and ends by writing the new version. The design
    /// names no such case; `docs/emergency-fix.md` says why it is needed.
    Block {
        height: u64,
        /// The hash of the decided block: 64 lowercase hex characters.
        block_hash: String,
        /// The root of the state the block is executed on.
        parent_root: String,
    },
}

/// One rule switch of a fix release: on one network, to one version, at one
/// place. It can happen once: the block it names has one height, and the
/// version before it is in force only until then.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Switch {
    /// The one network it is for (`Genesis::network_id`): a height means
    /// nothing on another chain, and a release runs on more than one.
    pub network_id: String,
    /// The version the switch block ends by writing: the one after the
    /// version in force until then.
    pub version: u64,
    pub at: SwitchAt,
}
impl Switch {
    /// The height of the switch block: the block that ends by writing the
    /// version. The block after it is the first whose header carries it.
    pub fn block_height(&self) -> u64 {
        match &self.at {
            SwitchAt::After { height } => height.saturating_add(1),
            SwitchAt::Block { height, .. } => *height,
        }
    }
    /// `NETWORK:after:H` or `NETWORK:block:S:BLOCKHASH:PARENTROOT`, with the
    /// network id and the two hashes as 64 lowercase hex characters and the
    /// heights as decimal numbers without leading zeros. One form only, so
    /// that two people who agree on a switch write the same text.
    pub fn parse(text: &str, version: u64) -> Result<Self> {
        let form = || anyhow::anyhow!("a switch is NETWORK:after:HEIGHT or NETWORK:block:HEIGHT:BLOCKHASH:PARENTROOT");
        let height = |text: &str| -> Result<u64> {
            ensure!(
                !text.is_empty() && text.bytes().all(|c| c.is_ascii_digit()) && !(text.len() > 1 && text.starts_with('0')),
                form()
            );
            text.parse().map_err(|_| form())
        };
        let parts: Vec<&str> = text.split(':').collect();
        let at = match parts.as_slice() {
            [_, "after", at] => SwitchAt::After { height: height(at)? },
            [_, "block", at, block_hash, parent_root] => SwitchAt::Block {
                height: height(at)?,
                block_hash: (*block_hash).to_string(),
                parent_root: (*parent_root).to_string(),
            },
            _ => return Err(form()),
        };
        let switch = Self { network_id: parts[0].to_string(), version, at };
        switch.validate()?;
        Ok(switch)
    }
    fn validate(&self) -> Result<()> {
        ensure!(valid_spec(&self.network_id), "a switch names its network by 64 lowercase hexadecimal characters");
        ensure!(self.version > FIRST_VERSION, "a switch leads to a version above the first");
        match &self.at {
            SwitchAt::After { height } => ensure!(
                *height >= 1 && *height < i64::MAX as u64,
                "a switch follows a block height, at least 1"
            ),
            SwitchAt::Block { height, block_hash, parent_root } => ensure!(
                *height >= 1 && *height <= i64::MAX as u64 && valid_spec(block_hash) && valid_spec(parent_root),
                "a repaired block is named by its height, its hash and the root of the state before it"
            ),
        }
        Ok(())
    }
    /// In words, for the node's log and its reports.
    pub fn describe(&self) -> String {
        match &self.at {
            SwitchAt::After { height } => format!(
                "after block {height} of network {} the next block carries exactly the rule switch to protocol version {}",
                self.network_id, self.version
            ),
            SwitchAt::Block { height, block_hash, parent_root } => format!(
                "the decided block {height} of network {} (hash {block_hash}), on the state with root {parent_root}, is executed by this program and ends under protocol version {}",
                self.network_id, self.version
            ),
        }
    }
}

/// The rules in force for one block: those of the committed head it is
/// executed on. Set once when the block starts; the activating block writes
/// the new number after its last transaction, so nothing in it sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rules(u64);
impl Rules {
    /// The rules that execute the block after the state `meta` describes.
    pub fn of(meta: &Meta) -> Self {
        Self(meta.protocol_version)
    }
    /// The rules of a network's first block.
    pub fn first() -> Self {
        Self(FIRST_VERSION)
    }
    /// Whether the rules in force include what `version` introduced.
    pub fn since(self, version: u64) -> bool {
        self.0 >= version
    }
    pub fn version(self) -> u64 {
        self.0
    }
}

/// One implemented version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Implemented {
    pub version: u64,
    /// SHA-256 of the version's specification: 64 lowercase hex characters.
    pub spec: String,
}

/// The list of versions a program implements. The engine takes it as a
/// parameter (`Engine::implementing`), so that tests run two programs from
/// one source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Versions {
    list: Vec<Implemented>,
    /// The rule switches of a fix release, and of every release after it
    /// (`with_switch`). Empty in a program that is not one.
    switches: Vec<Switch>,
}
impl Versions {
    /// A list is not empty, starts at `FIRST_VERSION` and has no gap: every
    /// release keeps all versions back to the first, so that it replays the
    /// chain from genesis, from any of its own snapshots and from any
    /// snapshot a peer offers.
    pub fn new(list: impl IntoIterator<Item = (u64, String)>) -> Result<Self> {
        let list: Vec<Implemented> = list
            .into_iter()
            .map(|(version, spec)| Implemented { version, spec })
            .collect();
        ensure!(!list.is_empty(), "a program implements at least one version");
        for (index, entry) in list.iter().enumerate() {
            ensure!(
                entry.version == FIRST_VERSION + index as u64,
                "implemented versions are contiguous from {FIRST_VERSION}"
            );
            ensure!(valid_spec(&entry.spec), "a specification hash is 64 lowercase hexadecimal characters");
        }
        Ok(Self { list, switches: Vec::new() })
    }
    /// The same program as a fix release that carries `switch`. The version
    /// must be in the list. On one network a version has one switch, a
    /// block has one switch, and a later version switches at a later block.
    pub fn with_switch(mut self, switch: Switch) -> Result<Self> {
        switch.validate()?;
        ensure!(
            self.spec_of(switch.version).is_some(),
            "a switch leads to a version this program implements"
        );
        for other in self.switches.iter().filter(|other| other.network_id == switch.network_id) {
            ensure!(
                other.version != switch.version && other.block_height() != switch.block_height(),
                "one network has one switch to a version, and one switch at a block"
            );
            ensure!(
                (other.version < switch.version) == (other.block_height() < switch.block_height()),
                "on one network a later version switches at a later block"
            );
        }
        self.switches.push(switch);
        Ok(self)
    }
    /// What this build implements (`IMPLEMENTED`, `SWITCHES`, and in a
    /// rehearsal build `REHEARSAL_SWITCH`).
    pub fn release() -> Self {
        let mut versions = Self::new(IMPLEMENTED.iter().map(|(version, spec)| (*version, (*spec).to_string())))
            .expect("the built-in list of versions is valid");
        for (network, version, at) in SWITCHES {
            versions = Switch::parse(&format!("{network}:{at}"), *version)
                .and_then(|switch| versions.with_switch(switch))
                .expect("the built-in list of switches is valid");
        }
        if let Some(text) = REHEARSAL_SWITCH {
            versions = Switch::parse(text, REHEARSAL_VERSION)
                .and_then(|switch| versions.with_switch(switch))
                .expect("TIME_REHEARSAL_SWITCH, which this rehearsal program was built with, is a valid switch");
        }
        versions
    }
    pub fn list(&self) -> &[Implemented] {
        &self.list
    }
    /// The rule switches this program carries, for every network.
    pub fn switches(&self) -> &[Switch] {
        &self.switches
    }
    /// The switch of this program whose switch block is `height` on this
    /// network, if it has one.
    pub fn switch_block(&self, network_id: &str, height: u64) -> Option<&Switch> {
        self.switches
            .iter()
            .find(|switch| switch.network_id == network_id && switch.block_height() == height)
    }
    /// The hash under which this program implements `version`, if it does.
    pub fn spec_of(&self, version: u64) -> Option<&str> {
        self.list
            .iter()
            .find(|entry| entry.version == version)
            .map(|entry| entry.spec.as_str())
    }
    /// Whether this program implements `version` with exactly these rules.
    pub fn implements(&self, version: u64, spec: &str) -> bool {
        self.spec_of(version) == Some(spec)
    }
    pub fn highest(&self) -> u64 {
        self.list.last().map_or(FIRST_VERSION, |entry| entry.version)
    }
    /// `4`, or `4 to 5`.
    pub fn describe(&self) -> String {
        if self.list.len() == 1 {
            format!("version {FIRST_VERSION}")
        } else {
            format!("versions {FIRST_VERSION} to {}", self.highest())
        }
    }
}

/// 64 lowercase hexadecimal characters.
pub fn valid_spec(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn the_gate_compares_with_the_version_in_force() {
        let four = Rules::first();
        assert!(four.since(4) && !four.since(5));
        assert_eq!(four.version(), 4);
        let five = Rules(5);
        assert!(five.since(4) && five.since(5) && !five.since(6));
    }

    #[test]
    fn a_list_is_contiguous_from_the_first_version() {
        let spec = |byte: &str| byte.repeat(32);
        assert!(Versions::new([]).is_err());
        assert!(Versions::new([(5, spec("aa"))]).is_err());
        assert!(Versions::new([(4, spec("aa")), (6, spec("bb"))]).is_err());
        assert!(Versions::new([(4, spec("aa")), (4, spec("bb"))]).is_err());
        assert!(Versions::new([(4, "AA".repeat(32))]).is_err());
        assert!(Versions::new([(4, "aa".repeat(31))]).is_err());
        let two = Versions::new([(4, spec("aa")), (5, spec("bb"))]).unwrap();
        assert_eq!(two.highest(), 5);
        assert!(two.implements(5, &spec("bb")) && !two.implements(5, &spec("aa")) && !two.implements(6, &spec("bb")));
        assert_eq!(two.spec_of(4), Some(spec("aa").as_str()));
        assert_eq!(two.describe(), "versions 4 to 5");
        assert_eq!(Versions::new([(4, spec("aa"))]).unwrap().describe(), "version 4");
    }

    #[test]
    fn a_switch_has_one_form_and_names_one_network_one_version_and_one_block() {
        let (net, hash, root) = ("ab".repeat(32), "cd".repeat(32), "ef".repeat(32));
        let after = Switch::parse(&format!("{net}:after:1234"), 5).unwrap();
        assert_eq!(after, Switch { network_id: net.clone(), version: 5, at: SwitchAt::After { height: 1234 } });
        assert_eq!(after.block_height(), 1235);
        let block = Switch::parse(&format!("{net}:block:77:{hash}:{root}"), 5).unwrap();
        assert_eq!(block.at, SwitchAt::Block { height: 77, block_hash: hash.clone(), parent_root: root.clone() });
        assert_eq!(block.block_height(), 77);
        assert!(after.describe().contains("after block 1234") && block.describe().contains("block 77"));
        for bad in [
            String::new(),
            format!("{net}:after"),
            format!("{net}:after:0"),
            format!("{net}:after:01"),
            format!("{net}:after:+5"),
            format!("{net}:after:5:6"),
            format!("{net}:after: 5"),
            format!("{net}:after:18446744073709551616"),
            format!("{net}:after:{}", i64::MAX),
            format!("{net}:before:5"),
            format!("{}:after:5", &net[1..]),
            format!("{}:after:5", net.to_uppercase()),
            format!("{net}:block:77:{hash}"),
            format!("{net}:block:0:{hash}:{root}"),
            format!("{net}:block:77:{}:{root}", &hash[2..]),
            format!("{net}:block:77:{hash}:{}", root.to_uppercase()),
            format!("{net}:block:77:{hash}:{root}:"),
        ] {
            assert!(Switch::parse(&bad, 5).is_err(), "{bad}");
        }
        // To the first version, or to a version the program does not hold: no switch.
        assert!(Switch::parse(&format!("{net}:after:5"), FIRST_VERSION).is_err());
        let spec = |byte: &str| byte.repeat(32);
        let two = || Versions::new([(4, spec("aa")), (5, spec("bb"))]).unwrap();
        assert!(two().switches().is_empty() && two().switch_block(&net, 1235).is_none());
        assert!(two().with_switch(Switch::parse(&format!("{net}:after:5"), 6).unwrap()).is_err());
        let fix = two().with_switch(after.clone()).unwrap();
        assert_eq!(fix.switches(), std::slice::from_ref(&after));
        assert_eq!(fix.switch_block(&net, 1235), Some(&after));
        // Another height, and another network: nothing.
        assert!(fix.switch_block(&net, 1234).is_none() && fix.switch_block(&net, 1236).is_none());
        assert!(fix.switch_block(&"ac".repeat(32), 1235).is_none());
        assert_ne!(fix, two());
        // One switch to a version and one switch at a block, per network.
        assert!(fix.clone().with_switch(Switch::parse(&format!("{net}:after:2000"), 5).unwrap()).is_err());
        let three = || Versions::new([(4, spec("aa")), (5, spec("bb")), (6, spec("cc"))]).unwrap().with_switch(after.clone()).unwrap();
        assert!(three().with_switch(Switch::parse(&format!("{net}:block:1235:{hash}:{root}"), 6).unwrap()).is_err());
        // A later version switches at a later block.
        assert!(three().with_switch(Switch::parse(&format!("{net}:after:1000"), 6).unwrap()).is_err());
        let later = three().with_switch(Switch::parse(&format!("{net}:block:2000:{hash}:{root}"), 6).unwrap()).unwrap();
        assert_eq!(later.switch_block(&net, 2000).map(|switch| switch.version), Some(6));
        assert_eq!(later.switch_block(&net, 1235).map(|switch| switch.version), Some(5));
        // The same version may switch on another network, where the heights mean something else.
        let other = "ac".repeat(32);
        assert!(three().with_switch(Switch::parse(&format!("{other}:after:10"), 5).unwrap()).is_ok());
    }

    #[test]
    fn a_release_build_carries_no_switch() {
        assert!(SWITCHES.is_empty(), "this release is not a fix release");
        let release = Versions::release();
        if REHEARSAL {
            // A rehearsal build carries the switch it was built with, if any.
            assert_eq!(release.switches().len(), usize::from(REHEARSAL_SWITCH.is_some()));
            assert!(release.switches().iter().all(|switch| switch.version == REHEARSAL_VERSION));
        } else {
            assert_eq!(REHEARSAL_SWITCH, None);
            assert!(release.switches().is_empty());
        }
    }

    #[test]
    fn the_release_list_names_version_four_by_the_hash_of_its_specification() {
        let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/protocol-4.md");
        let bytes = std::fs::read(&file).unwrap_or_else(|error| panic!("{}: {error}", file.display()));
        assert_eq!(hex::encode(Sha256::digest(&bytes)), SPEC_4, "SPEC_4 must be the SHA-256 of spec/protocol-4.md");
        assert_eq!(hex::encode(Sha256::digest(REHEARSAL_SPEC_TEXT.as_bytes())), REHEARSAL_SPEC);
        let release = Versions::release();
        assert_eq!(release.spec_of(FIRST_VERSION), Some(SPEC_4));
        if REHEARSAL {
            assert_eq!(release.list().len(), 2);
            assert!(release.implements(REHEARSAL_VERSION, REHEARSAL_SPEC));
        } else {
            // Release 1 implements version 4 and nothing else.
            assert_eq!(release.list().len(), 1);
            assert_eq!(release.highest(), FIRST_VERSION);
        }
    }
}
