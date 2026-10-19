# CLI v0.3.0 authenticated latest Catalog — default download (2026-10-19)

Status: anonymous Windows 70 ZIP GET-only canary passed on [Run 39237271741](https://github.com/pgextwin/catalog/actions/runs/39237271741), SHA256=70/70 without GH_TOKEN. CLI v0.3.0 changes the default only after protected PR and publisher gates.

```powershell
.\pgextwin.exe download-all --pg all  # verified Catalog latest (default)
.\pgextwin.exe download-all --pg all --latest  # explicit equivalent
.\pgextwin.exe download-all --pg all --fixed  # historical SHA-pinned snapshot
```

The `--latest` path selects **only** the exact Release tags, PG major ZIP URLs, and SHA256 values in the protected `pgextwin/catalog` main snapshot. It does not use GitHub's `releases/latest`, upstream latest tags, draft Releases, candidate PRs or failed workflow runs.

It requires an authenticated GitHub HTTPS REST response reporting all of:
- `main.protected == true` and a full immutable HEAD commit ID;
- signed GitHub `web-flow` merge commit with `commit.verification.verified=true`, reason `valid`, expected GitHub committer identity;
- a completed successful **push** `validate.yml` workflow run at that **exact same main SHA** and attempt 1;
- a complete 14-extension Catalog v2 read at the immutable commit SHA, stable HEAD before and after the snapshot;
- exact live repository ID, public Release tag/ID, uploaded asset IDs, browser URLs and GitHub Release SHA256 digests consistent with every Catalog-selected ZIP.

The existing `PinnedBrowserDownloader`, `BatchReleaseDownloader.StageAsync`, 64MiB ZIP caps, SHA256 streamed checks, URL/redirect guards, ZIP magic checks, no-overwrite staging, whole-batch atomic promotion and rollback are reused. No ZIP extraction, install, Sigstore assertion or publisher privilege is introduced. The receipt remains `INTEGRITY_ONLY`, `signatureVerified=false`, `publicationAuthorized=false`, `distributionAuthorized=false`, `installAuthorized=false`. A GitHub-reported signed commit is *not* an independently evaluated OpenPGP signature or original Release attestation.

## Critical usability gate

The latest path needs read access to GitHub REST **branch, commit, Actions run, repository and Release metadata**. The previously observed anonymous HTTP 403 cannot be waived or converted into a success. The runtime optionally uses an existing `GH_TOKEN`/`GITHUB_TOKEN` environment variable, but does not prompt for, persist or generate credentials. The anonymous Windows canary passed all 70 original ZIP SHA256 without a GitHub token at PR #124. The v0.2.2 historical snapshot remains available through `--fixed`. A future 403/429 is an explicit fail-closed error (no silent fallback to old ZIPs or false latest claim); a single canary does not guarantee GitHub API availability for every machine.

Synthetic hostile tests exercise protected-branch denial, signature-status failure, missing successful exact-head CI, head racing, incorrect record identity, HTTP 403, mutated Release digest, draft Release and clean staging rollback. PR Windows self-contained packaging smoke and existing App15368 required Validate are the acceptance path; a green compile alone is not public download acceptance.

This design uses GitHub API TLS and GitHub's server-side commit signature/CI verdict as its online authorization source. It is not a detached end-user-verified publisher signature. If the required interpretation of independently authenticated Catalog demands a separate pinned signer key/Sigstore bundle, a further issuer-and-root gated implementation is required before default promotion.

Safety remains Issue #75 GO B/G4/G5 NO-GO for its separate signed-Publisher scope. Formal historical P1 gaps are not reclassified.
