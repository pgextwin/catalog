# CLI authenticated latest Catalog — guarded opt-in implementation (2026-10-19)

Status: PR canary only. **No default flip or public CLI release without Windows success and independent approval.**

```powershell
.\pgextwin.exe download-all --pg all --latest
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

The latest path needs read access to GitHub REST **branch, commit, Actions run, repository and Release metadata**. The previously observed anonymous HTTP 403 cannot be waived or converted into a success. The runtime optionally uses an existing `GH_TOKEN`/`GITHUB_TOKEN` environment variable, but does not prompt for, persist or generate credentials. **Do not make this path the unqualified default until real anonymous Windows networking works reliably or a separate cryptographically authenticated public no-REST feed is validated.** The fixed v0.2.2 path must remain intact until then.

Synthetic hostile tests exercise protected-branch denial, signature-status failure, missing successful exact-head CI, head racing, incorrect record identity, HTTP 403, mutated Release digest, draft Release and clean staging rollback. PR Windows self-contained packaging smoke and existing App15368 required Validate are the acceptance path; a green compile alone is not public download acceptance.

This design uses GitHub API TLS and GitHub's server-side commit signature/CI verdict as its online authorization source. It is not a detached end-user-verified publisher signature. If the required interpretation of independently authenticated Catalog demands a separate pinned signer key/Sigstore bundle, a further issuer-and-root gated implementation is required before default promotion.

Safety remains Issue #75 GO B/G4/G5 NO-GO for its separate signed-Publisher scope. Formal historical P1 gaps are not reclassified.
