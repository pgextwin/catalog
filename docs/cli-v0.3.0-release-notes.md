# pgextwin CLI v0.3.0 — authenticated Catalog latest by default

Windows x64 self-contained single-file `pgextwin.exe`, read-only original ZIP downloader.

## One-line latest registered packages

```powershell
.\pgextwin.exe download-all --pg all
```

The standard command selects the *current Catalog-registered official Release* for each of the 14 pgextwin extensions, for PG14/15/16/17/18. It does **not** guess from upstream tags, draft Releases or GitHub's separate `releases/latest`. To retrieve one major, use `--pg 18`. For explicit legacy v0.2.2 fixed 2026-10-17 inventory:

```powershell
.\pgextwin.exe download-all --pg all --fixed
```

An explicit `--latest` flag is accepted but not required.

The CLI retrieves the canonical public Catalog feed and its Sigstore bundle via stable GitHub Release browser/download URLs without GitHub REST API calls. It independently verifies the OIDC identity for `pgextwin/catalog/.github/workflows/cli-signed-catalog-feed.yml@refs/heads/main`, Sigstore transparency log, verified timestamps, the Catalog source commit and all 15 immutable record bytes against signed SHA256. The feed producer separately checks protected main/required Validate and original public Release/asset IDs and hashes. Original ZIPs use the previously validated bounded GitHub HTTPS browser transport, streamed SHA256, 64 MiB per ZIP, exact ZIP magic and all-or-nothing output staging. The `DOWNLOAD-INFO.json` receipt includes Release tag and Catalog commit for each original ZIP. `INTEGRITY_ONLY` is not original extension Sigstore signature verification; `signatureVerified=false`, `provenanceVerified=false`, `publicationAuthorized=false`, `distributionAuthorized=false`, `installAuthorized=false` remain explicit.

Missing/invalid Sigstore trust root, signature mismatch, source commit mismatch, Catalog drift, wrong tags, asset digest mismatch, unsafe redirects, non-200 public HTTP responses and local directory collision fail closed; there is **no silent fallback** to frozen versions. The read-only signed-commit determination is independently verified GitHub Actions Sigstore identity and original feed bytes, not independently verified original extension signatures.

## Acceptance evidence

- Protected Catalog PR #123 and genuine Windows authenticated selected-Catalog real 70 ZIP SHA256: https://github.com/pgextwin/catalog/actions/runs/39236569189
- Postmerge selected-Catalog 70 real ZIP Windows SHA256: https://github.com/pgextwin/catalog/actions/runs/39236902866
- PR #124 clean Windows **anonymous**, no GitHub token, real public 70 ZIP SHA256 70/70: https://github.com/pgextwin/catalog/actions/runs/39237271741

The new v0.3.0 **public EXE** requires separate current-source R6 Sigstore attest, independent original-byte SHA256, owner-approved create-only CLI R7 intent, complete CI, and then actual public EXE re-download and one-line 70 ZIP verification. The historic extension P1 gaps and #75 GO B/G4/G5 are not claimed as fixed by a CLI binary release.

## Binary authenticity

Check `pgextwin.exe` against the published `SHA256SUMS.txt` and verify its GitHub SLSA attestation. **The source digest and exact EXE SHA256 will be populated only from the accepted original protected-main R6 run**, never inferred from PR test artifacts.

No Windows Authenticode signature, ZIP extraction, installation, service mutation, new extension Publisher authorization, offline signed bundle, or formal original extension SLSA/SPDX acceptance.
