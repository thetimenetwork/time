# Dependency review record

The repeatable command is `node production/tools/audit-dependencies-v4.mjs` from
the project root. It records the exact lockfile hashes, cargo-audit executable
hash, advisory database metadata, complete JSON findings and stderr. A failed
fetch, malformed report or changing lockfile does not pass. Rerun after the
final lockfiles are frozen; earlier scans apply only to their recorded hashes.

The initial scan found no published RustSec vulnerabilities and reported
`RUSTSEC-2024-0436` for `paste 1.0.15`. The dependency path is
`Tendermint 0.40.4 -> flex-error 0.4.4 -> paste 1.0.15`. The same path occurs in
the native node, PoS vote verification and WASM light verifier. `paste` executes
as a compile-time procedural macro. RustSec classifies this advisory as
unmaintained and lists no patched version; this is a maintenance/supply-chain
concern, not a reported runtime exploit. See the [primary advisory](https://rustsec.org/advisories/RUSTSEC-2024-0436.html).

The warning remains visible. It is not suppressed or relabeled as a clean scan.
Replacing an official consensus dependency with a private fork would itself
require compatibility testing and independent review. Locked versions and
registry checksums are enforced; reviewed upstream replacement or a documented
maintainer disposition remains a release review item. This scan does not cover
the Go consensus binary, Bitcoin Core, the browser, operating system, container
base images, or correctness flaws absent from the advisory database.
