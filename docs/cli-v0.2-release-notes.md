# pgextwin CLI v0.2.0 — Windows x64

A self-contained Windows x64 command-line tool to browse the 14 pgextwin PostgreSQL extensions and download individually published original ZIPs in bulk.

## New in v0.2.0

**`download-all`** downloads the 14 original ZIP files of any one PostgreSQL major, or up to **70 original ZIP files for PG14–18**. Files are grouped under `pg14/` ... `pg18/`, with `DOWNLOAD-INFO.json` recording exact source ZIP bytes, SHA256, and numerical GitHub Release IDs. An entire batch is staged privately and renamed to its final new directory only after every selected ZIP passes identity and checksum validation. No partial completed batch is exposed and existing output cannot be overwritten.

```powershell
.\pgextwin.exe --version
.\pgextwin.exe list --catalog-dir C:\approved\catalog --pg 18 --format json
New-Item -ItemType Directory -Force C:\pgextwin-downloads
.\pgextwin.exe download-all --pg 18 --catalog-dir C:\approved\catalog `
  --policy C:\approved\policy.json --policy-sha256 INDEPENDENT_APPROVED_64_HEX `
  --output C:\pgextwin-downloads
# For all 70 original ZIPs: use --pg all instead of --pg 18.
```

**Requirements:** an intact locally saved Catalog v2 with all 14 extensions, a separately approved P1 policy file and its genuine independently authenticated SHA256, network access to the existing official GitHub Releases, and a pre-existing output parent folder. If independent pins are not available, this command **fails closed**. A checksum copied only from the Catalog itself is not an independent policy approval.

The ZIPs are original already-published upstream extension release assets, not a newly signed/attested enclosing offline distribution bundle. Download success means **INTEGRITY_ONLY**; it does NOT claim to verify original extension Sigstore signatures. There is no ZIP extraction, installation, service modification, SQL execution, publisher privilege or Authenticode signature.

## Existing features

Local `list`/`search` (text or JSON), exact pinned single-file `download`, and offline signed P1 report-claim authentication (`verify-report`). `verify-report` authenticates the report source, **not** actual original release provenance. All extension authenticity/install/publication claims remain DENY.

## Verifying the CLI binary itself

Compare `pgextwin.exe` against the attached `SHA256SUMS.txt`. The genuine GitHub SLSA provenance is for **this CLI executable** (not the downloaded extension ZIPs):

```powershell
Get-FileHash .\pgextwin.exe -Algorithm SHA256
gh attestation verify .\pgextwin.exe --repo pgextwin/catalog --signer-workflow pgextwin/catalog/.github/workflows/cli-candidate.yml --source-ref refs/heads/main --source-digest 529718ac8ff829c8a98b57d26adb1d74971588c1
```

Original EXE SHA256: `1764d2f5a54b9fa715a2bba1d068493ef1d5dcb159b895e3f24becf2dee6fdc0`.

Build chain: [protected main Windows R6 signer/independent verifier Run 39205817118](https://github.com/pgextwin/catalog/actions/runs/39205817118). The EXE is not Windows Authenticode-signed. SDK 10.0.402 and self-contained runtime 10.0.13 were pinned; SPDX 2.3 and runtime LICENSE/third-party notices are attached.

Install `--apply`, one signed master ZIP bundle, genuine extension SLSA/SPDX verification, auto elevation, PostgreSQL service changes and #75 GO B/G4/G5 are out of scope; their gates are not waived.
