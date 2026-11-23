# Bitcoin header and receipt core

This crate verifies Bitcoin header work and bid-payment inclusion. Mainnet
receipt acceptance is disabled by default. It does not replace Bitcoin Core,
prove that an output remains unspent, guarantee that confirmations never
reorganize, or establish an arbitrary Time validator history from OP_RETURN.

`HeaderChain::prepare_headers` validates the explicit network's genesis or
independently trusted checkpoint, parent links, exact difficulty, proof of work,
median time past, future-time policy and obsolete block-version rules. Fork
selection compares accumulated work. Header batches and the fork frontier are
bounded; low-work tips cannot fill the frontier and prevent a higher-work batch
from taking over. Headers and height indices live in external authenticated
rows; the serializable chain metadata remains below 64 KiB.

The difficulty rules follow [Bitcoin Core's proof-of-work implementation](https://github.com/bitcoin/bitcoin/blob/v30.0/src/pow.cpp).
Mainnet retarget regression values come from [Core's reference tests](https://github.com/bitcoin/bitcoin/blob/v30.0/src/test/pow_tests.cpp).
Integer work, targets, header hashing and BIP37 proof verification use pinned
[`rust-bitcoin` 0.32.102](https://docs.rs/bitcoin/0.32.102/bitcoin/).

The checkpoint constructor is a separate trust operation. Its pinned hash and
chainwork must come from an independently authenticated deployment decision.
The supplied consecutive context reaches the current retarget period's start
and the preceding MTP window; predecessor links authenticate that context to
the pin. This does not independently validate history preceding the checkpoint.
Testnet3, mainnet and regtest are distinct; signet/testnet4 are unsupported.

`prepare_receipt` takes immutable receiving-policy windows and a caller-derived
Time context. It verifies the exact receiving script and satoshi value, one
minimal zero-valued OP_RETURN output containing
`TIMEBID1 || TimeNetwork[32] || account_u64_BE || epoch_u64_BE || revision_u64_BE`,
and a single-match Bitcoin Core `gettxoutproof` / MerkleBlock proof. The payment
must be on the retained greatest-work chain with the configured confirmation
depth (default 12). The supplied clock must be Time consensus time, never a
machine-local wall clock or an RPC assertion. Proof framing is checked before
deserializing attacker-controlled allocation counts.

The application must atomically apply each `HeaderTransition`'s metadata,
header rows, deletions and height-index rows. It must atomically apply each
`ReceiptTransition`'s updated credited anchor, outpoint-consumed row and auction
credit; its `ReceiptIndex` must include earlier changes staged in that same
Time block. Do not store the test `MemoryHeaderStore` or receipt set inline in
production metadata. Retained proofs expire when their header context is
pruned, while consumed outpoints remain authenticated application state.

A higher-work reorganization crossing a credited receipt or the configured
depth pauses new Bitcoin-backed earnings. Already finalized Time payments are
not rolled back. Recovery requires an explicit reviewed checkpoint/governance
operation; it is not an automatic RPC override. An eclipsed verifier cannot
prove the absence of a higher-work Bitcoin chain. Honest header availability
and Bitcoin's full-validating mining majority remain SPV assumptions.

`bitcoin-bridge-check SCENARIO.json NEW_RESULT.json` exercises real Core regtest
header hex and `gettxoutproof` bytes without using RPC as a consensus oracle.
The independent Core runner creates the funded multisig payment and supplies
the data. Unit PoW/Merkle fixtures test verifier boundaries; they are not
represented as fully validated Bitcoin blocks.
