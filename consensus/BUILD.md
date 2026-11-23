# Consensus binary provenance

This laboratory uses upstream CometBFT **v0.38.26**, source commit `94d77f9f51a72e2b7d832798859f6222f08028f8`, module archive checksum `h1:MIPYgOSvyyiN1jo3SZljKy4ZXqs896aQnj3pQFfUmaE=`. Consensus source is unchanged. The checked-in `go.mod` and `go.sum` pin a local dependency update; this is a custom build, not an unmodified upstream release binary.

The initial binary scan matched 51 advisory IDs by binary symbol presence. Most were old transitive crypto, HTTP/2, compression and gRPC versions. Symbol presence alone does not prove exploitation in this configuration. The upstream main-module match GO-2025-3442 has a separate v1 affected package range; the applicable v0.38 blocksync fix is v0.38.17, earlier than our pin. Keep the raw scan and triage visible rather than treating a scanner count as a risk score.

The dependency overrides pin `golang.org/x/crypto` to `v0.58.1-0.20261009181718-2f1f834330b2` (the published unsafe OpenPGP removal identified by [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), beyond the latest tagged v0.58.0), x/net v0.62.0, x/sys v0.49.0, x/text v0.43.0, gRPC v1.85.0 and klauspost/compress v1.20.3. Their required transitive updates are in the lockfiles. Go is pinned to **1.27.3**, CGO disabled. Changes require renewed compatibility and advisory checks.

Rebuild on this Windows development machine:

```powershell
.\tools\build-comet.ps1
node tools/audit-go.mjs .tools/bin/cometbft-updated.exe
```

The build verifies the upstream source pin and module checksums. Local component and four-validator tests provide compatibility evidence; no claim of identical binaries across platforms or a complete reproducible-build security ceremony is made. Production needs independently reviewed provenance, reproducibility, release signing and continued dependency maintenance.

Relevant upstream advisories: [blocksync](https://pkg.go.dev/vuln/GO-2025-3442) and [Tachyon timestamp vulnerability](https://github.com/cometbft/cometbft/security/advisories/GHSA-c32p-wcqj-j677). Tachyon's v0.38 fix is v0.38.21. Using a patched timestamp implementation is necessary for this currency's accepted-time accounting; it does not prove that node clocks equal UTC.
