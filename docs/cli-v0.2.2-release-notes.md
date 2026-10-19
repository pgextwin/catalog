# pgextwin CLI v0.2.2 — Windows x64, one-line 70 ZIP download

**PowerShell (no other arguments):**
```powershell
.\pgextwin.exe download-all --pg all
```

This creates `pgextwin-pg14-18` in the current directory and retrieves 70 *original separate extension ZIP files* (14 for each of PostgreSQL 14, 15, 16, 17, and 18). To download just one major, use `--pg 18`.

## v0.2.2 real transport recovery

The original v0.2.1 command was independently tested on Windows, and **failed closed**: GitHub's anonymous REST Release API returned HTTP 403; see [failed, never waived real 70 ZIP Run 39211137784](https://github.com/pgextwin/catalog/actions/runs/39211137784). This release fixes that actual failure rather than asking users for a GitHub token or manually supplied pin paths.

The signed CLI retains a fixed historical P1 candidate policy independently baked SHA256 `dc1e52bbb10f52d0c1f14913e99bf30e6dc4855e0c39d0547b78f39da549f201`, at policy source SHA `4dcf3b9c601c6fd43a7ee34bb0f73592f5509a34` and Catalog original `e372e2c6a95adcf8227ea82d6253df3792b6f029`. These 16 raw original files are fetched at immutable GitHub HTTPS paths and exact hash checked before any ZIP GET. For the one-line mode, ZIP bytes come through *exact pinned public GitHub Release browser URLs*, not anonymous GitHub REST API endpoints, with strict HTTPS/CDN redirect allowlist, max 64 MiB per ZIP, original ZIP SHA256/ZIP magic verification and atomic rollback. This avoids anonymous GitHub REST quota by design. Existing explicit advanced `download` / `download-all --catalog-dir --policy --policy-sha256 --output` modes still perform live API numeric Release ID checks.

Original numeric repository/release/asset IDs in the auto mode are independently **policy pinned**, but **not live REST queried**; `DOWNLOAD-INFO.json` records `releaseMetadataVerified=false`. Download success means only `INTEGRITY_ONLY`, not formal P1 acceptance of all 70 originally signed extension releases or Sigstore authenticity. Never treat a stale, changed, missing or mismatched original asset as PASS. The snapshot is frozen and does not auto-select newer releases.

No installation, service change, ZIP extraction, automatic privilege elevation, signed enclosing archive, extension release publication or original extension SLSA/SPDX verification. #75 GO B/G4/G5 safety gates remain unchanged.

## Verify the CLI executable

```powershell
Get-FileHash .\pgextwin.exe -Algorithm SHA256
gh attestation verify .\pgextwin.exe --repo pgextwin/catalog --signer-workflow pgextwin/catalog/.github/workflows/cli-candidate.yml --source-ref refs/heads/main --source-digest 594df3d703d983d5978b640a03c64d498765035a
```

Expected SHA256: `3567e34cf9f7347cfab7a1292f58965b7bd15e2d8a2bb5b1f0479685633862a0`.

Protected original R6 signer+Windows verifier [Run 39211701760](https://github.com/pgextwin/catalog/actions/runs/39211701760). Includes SPDX2.3, original SHA256SUMS and Microsoft .NET runtime notices (self-contained runtime 10.0.13). No Windows Authenticode signature.
