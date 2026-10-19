# pgextwin CLI v0.1.0-preview.1 — Windows x64

Early read-only preview. This release is **only the pgextwin CLI executable**, not an installer or newly signed release of PostgreSQL extensions.

## What works
- Standalone self-contained Windows x64 `pgextwin.exe` (.NET 10 runtime included).
- `--help`, `--version`, `list` and `search` across the local 14-extension Catalog v2, with `--pg 14` through `--pg 18` and `--format text|json`.
- Explicit user-authorized single-asset `download` with externally approved exact Catalog/Release/policy SHA256 pins; success is **INTEGRITY_ONLY**, not attestation/authenticity verification.
- Optional independently signed P1 report authentication is **P1_REPORT_AUTHENTICATED_ONLY**, not genuine original Release Sigstore verification.

## Get started (PowerShell)
Download `pgextwin.exe` from this Release and a trusted copy of the Catalog source (the exact main snapshot may be identified independently). Extract the Catalog with its `index.json` and `extensions` directory.

```powershell
.\pgextwin.exe --version
.\pgextwin.exe list --catalog-dir C:\path\to\catalog --pg 18
.\pgextwin.exe search cron --catalog-dir C:\path\to\catalog --format json
Get-FileHash .\pgextwin.exe -Algorithm SHA256
```

Compare the SHA256 with the release's `SHA256SUMS.txt`, then independently verify the GitHub Sigstore build provenance against the exact owner/repo, signer workflow and source commit:

```powershell
gh attestation verify .\pgextwin.exe --repo pgextwin/catalog --signer-workflow pgextwin/catalog/.github/workflows/cli-candidate.yml --source-ref refs/heads/main --source-digest d0056b688dc27095d2d7ffd6f8b77aff965def79
```

The provenance is a signed GitHub/Sigstore attestation of this **CLI executable's SHA256**. The EXE is **not Authenticode-signed** and Windows may display an unrecognized publisher warning. Neither SHA256SUMS nor the CLI Sigstore attestation proves the authenticity of downloaded extension ZIPs.

## Safety and non-features
- Local Catalog listing remains `LOCAL_UNAUTHENTICATED / UNVERIFIED`.
- Genuine `verify` for extension SLSA/SPDX is not implemented: fail-closed / exit 2. Do not call downloaded extensions signature-verified.
- No `install --apply`, no PostgreSQL service modifications, no bundled offline ZIP generator or autonomous elevation.
- No extension, Catalog or Website Release is implicitly created by this CLI preview.
- The project does not provide malware-free guarantees. Prefer verifying the exact GitHub signed provenance and locally scanning downloaded executables.

The R6 protected-main Windows candidate, isolated signer and independent verifier completed on run [39200819667](https://github.com/pgextwin/catalog/actions/runs/39200819667). Re-run independent checks against the actual public Release binary rather than trusting these notes alone.
