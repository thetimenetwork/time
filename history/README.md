# Authenticated history

`time-history` commits canonical block hashes and accepted microsecond timestamps
without retaining every historical key in the current JMT. A fresh, independently
verified Time state root must authenticate `history/meta` before using any proof.
The summary's network, size and last timestamp must match the proved ledger.

The binary tree has RFC6962's split rule: the largest power of two strictly below
the subtree size. The exact encodings are:

```
domain    = UTF8("TIME-HISTORY-V1\0")
leaf      = SHA256(0x00 || domain || network32 || heightBE8 || blockHash32 || utcMicrosBE8)
node      = SHA256(0x01 || left32 || right32)
emptyTree = SHA256(empty bytes)
root      = SHA256(0x02 || domain || network32 || sizeBE8 || treeRoot32)
```

The explicit root wrapper binds size and network even for a proof whose unshown
subtree would otherwise hide a changed declared size. A summary has at most 63
complete-subtree roots, ordered left to right by decreasing set-bit sizes. Their
right-associated combination produces `treeRoot`. Proof siblings are bottom up;
height and tree size determine every left/right choice. Extra, short, reordered,
cross-network or changed-leaf proofs reject. All protocol u64 values are canonical
decimal strings in JSON. The maximum height is `i64::MAX`.

`make-vectors.mjs` produces independent recursive JavaScript vectors. Rust tests
compare append/frontier roots and exact proof paths against those vectors and a
separate recursive tree calculation. Tests also cover crash-ahead replacement,
corrupt archives and competing writers. These are bounded executable checks,
not a mathematical proof of the entire blockchain.

The local archive has two files, each with an eight-byte format marker and a
32-byte network ID. `leaves.bin` stores 40 bytes per block (hash plus timestamp).
`nodes.bin` stores each 32-byte node once in append/postorder. For N blocks there
are `2N-popcount(N)` nodes. This is approximately 104 archive bytes per block,
before filesystem overhead. At one block per second, the format itself uses
about 3.28 GB per 365-day year. This is a format calculation, not a measured
whole-node disk budget. Account state, Bitcoin receipts, Comet data and indexes
have additional costs. Operators must budget and maintain storage.

The archive is untrusted proof material. Wrong bytes cannot authorize a payment;
they can make proofs unavailable. Preserve or independently rebuild it from
canonical blocks. A local OS file lock rejects concurrent archive writers. This
lock is not a cross-host validator signing fence.

The commit caller must hold its commit lock and compare the current authenticated
head and summary to the prepared append **before any archive mutation**. It then
fsyncs the archive append before committing/acknowledging the ledger. A crash may
leave an archive tail ahead of the ledger. On retry, only a matching currently
committed prefix permits truncating that tail. A stale prepared block must reject
before the archive write. Archive mutation alone never commits a ledger block.

Current-state history indexes can be pruned outside the 14-day evidence window.
Live stake exits retain their own referenced release clocks until the last claim
is withdrawn, so accessing money does not depend on an old receipt archive.
Historical receipts use inclusion proofs for both their block and the following
header under a fresh current history summary. A wallet offline beyond its
seven-day trust period still needs an independently authenticated checkpoint.
