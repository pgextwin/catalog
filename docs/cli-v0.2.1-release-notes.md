# pgextwin CLI v0.2.1 — Windows x64

**One line, 70 original extension ZIPs:**

```powershell
.\pgextwin.exe download-all --pg all
```

The current directory is the destination parent; the command creates a new `pgextwin-pg14-18/` folder containing 14 original per-major extension ZIPs for each PG14, PG15, PG16, PG17, PG18 and a `DOWNLOAD-INFO.json` receipt. For only 14 packages, use `--pg 18` or one other supported PostgreSQL major. An existing completed destination is never overwritten and partial batches are rolled back.

Unlike v0.2.0, there is no need to download a separate Catalog snapshot, policy file, externally entered SHA256 or to specify an output directory. This signed CLI executable embeds the exact historical candidate P1 policy SHA256 `dc1e52bbb10f52d0c1f14913e99bf30e6dc4855e0c39d0547b78f39da549f201`; it downloads **only** the immutable policy `4dcf3b9c601c6fd43a7ee34bb0f73592f5509a34` and Catalog `e372e2c6a95adcf8227ea82d6253df3792b6f029` originals from fixed HTTPS GitHub raw paths, rehashes all 16 originals against their fixed expected byte values and then invokes the previously validated 14/70 original ZIP GitHub Release bounded downloader with immutable numeric Release/asset IDs and SHA256. No mutable default-branch/latest-version feed is trusted.

**Trust meaning:** this is a frozen 2026-10-17 Catalog candidate selection, NOT 70 formally accepted original-release Sigstore signatures. Each downloaded ZIP only passes `INTEGRITY_ONLY` SHA256 and exact GitHub Release numeric identity checks. It does not assert original PostgreSQL extension SLSA/SPDX authenticity, sign a new master ZIP, apply installation or restart PostgreSQL. It fails closed if a pinned historical GitHub Release asset is unavailable, changed or inaccessible.

The former explicit `download-all --catalog-dir PATH --policy FILE --policy-sha256 DIGEST --output DIR` remains supported for separately approved snapshots. `list`, `search`, single `download` and `verify-report` remain. Original extension Sigstore `verify` stays DENY.

## Independently verify this CLI executable

```powershell
Get-FileHash .\pgextwin.exe -Algorithm SHA256
gh attestation verify .\pgextwin.exe --repo pgextwin/catalog --signer-workflow pgextwin/catalog/.github/workflows/cli-candidate.yml --source-ref refs/heads/main --source-digest 79db0018cd930847330c024770328892eb46cf3c
```

Expected original EXE SHA256: `78de25e4ac3b8d40ba173f3369a12cf92e97ee0e2a65695820390231e3d08aca`.

The protected-main original v0.2.1 binary R6 [Run 39210035547](https://github.com/pgextwin/catalog/actions/runs/39210035547) completed build, clean Windows SHA/runtime, isolated GitHub Sigstore attest, and independent signer/workflow/source verification. SPDX2.3, SHA256SUMS, .NET runtime 10.0.13 license and third-party notices accompany the release. No Authenticode signature. No extension Release changes, credential or protection changes, or #75 GO B/G4/G5 bypass.
