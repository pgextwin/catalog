# pgextwin CLI v0.3.0 — locally verified Sigstore Catalog feed

## Behavior

The user command `pgextwin.exe download-all --pg all` selects the **Catalog-registered** published Release per extension and retrieves the 14 × PG14–18 original public ZIPs; `--pg 18` restricts to 14. The `--latest` argument is equivalent to the default. `--fixed` retains the frozen historical 2026-10-17 policy and original packages from v0.2.2.

Unlike PR #123's experimental GitHub REST online metadata verifier, v0.3.0 does **not call anonymous GitHub REST APIs**. The #125 first default attempt correctly failed with HTTP403 and was **not** waived. Instead, the protected-main signed-feed publisher introduced in PR #126 runs only after an independently verified exact-main `Validate catalog` push SUCCESS. A separate GitHub Actions OIDC signer signs `catalog-latest.json` using Sigstore; a separate write-scoped job cryptographically validates the original signed bytes before create-only **metadata-only** Release publication.

Each public feed Release has a create-only `catalog-feed-<40-char-sha>` tag and exactly:
- `catalog-latest.json` — raw Catalog SHA256 digests for 15 files and 70 published asset URL, original SHA256, Repo/Release/Asset IDs.
- `catalog-latest.sigstore.json` — its original GitHub Actions Sigstore/SLSA signature bundle.

Current public feed: [GitHub Catalog latest stable Release](https://github.com/pgextwin/catalog/releases/latest).

The CLI retrieves both files from `https://github.com/pgextwin/catalog/releases/latest/download/...` using bounded, HTTPS-only redirects to approved GitHub asset hosts, no API calls or GitHub account login. It rejects cross-release feed/bundle redirects. **Before accepting any metadata**, the CLI verifies the bundle cryptographically using the pinned **Sigstore 1.1.1** managed verifier and a TUF trust root independent of the feed. The exact GitHub Actions OIDC issuer, signer workflow SAN, protected main ref, source repository ID and SHA, SLSA predicate and verified timestamps must match. It then fetches the 15 Catalog JSON files by exact immutable commit SHA and rehashes every byte against the signed feed, checks all 14 latest tags/70 asset URLs/digests/IDs, and invokes the existing bounded `PinnedBrowserDownloader` and all-or-nothing `BatchReleaseDownloader.StageAsync`.

`DOWNLOAD-INFO.json` records each package's original Catalog commit/Release tag/SHA256 and `source=SIGSTORE_SIGNED_CATALOG_FEED_ORIGINAL_ZIPS`, `releaseMetadataVerified=false` because numeric GitHub Release IDs are **signed feed pins** and not live API audited by the client, `verificationLevel=INTEGRITY_ONLY`, `signatureVerified=false` for **original extension ZIP signatures**, `provenanceVerified=false` for the same originals, `installAuthorized=false` and `publicationAuthorized=false`. `CATALOG_AUTH=SIGSTORE_VERIFIED_FEED` means *only the Catalog feed's* Sigstore attestation passed.

## Safety, availability and policy

- Any incorrect Sigstore identity, revoked/missing trust root, incorrect original ZIP SHA256, unsigned/mismatched feed, cross-Release redirect, unexpected Catalog commit, stale/missing raw files, HTTP 403/429, incomplete 70 entries, duplicate/unsafe names or output collisions fail closed.
- A GitHub stable `releases/latest` pointer is an online freshness locator. Stateles clients cannot prove an absent new signed feed against rollback by a compromised GitHub Release latest pointer. The signed feed provenance and exact immutable contents are independently authenticated; automatic update freshness still depends on GitHub's public latest Release endpoint. No mutable untrusted feed hash authorizes itself.
- This new metadata-only Release **does not publish/authorize any extension ZIP or bundle**, change #75 GO B/G4/G5, upgrade historical P1 acceptance, or attest the extension original ZIP bytes individually.
- Existing v0.2.2 CLI, Releases and safety gates remain intact.

## Acceptance gates

1. PR #126 produced a real signed metadata feed via [Run 39239324505](https://github.com/pgextwin/catalog/actions/runs/39239324505): protected current-main Validate, Sigstore genuine attestation, independent signed-asset verification, create-only Release, re-read and byte compare.
2. v0.3.0 independent Windows PR, postmerge, clean **tokenless** Windows 70/70 real ZIP checks must succeed and use only public signed feed. Test failures cannot be waived.
3. Protected-main CLI R6 genuine original EXE Sigstore SLSA, source commit identity, SHA256, .NET runtime and NuGet third-party licensing/SBOM verification must succeed.
4. Only then a separately signed **CLI-only** R7 publication intent may authorize a unique v0.3.0 Release. Finally fetch the public original EXE and re-verify the default command's actual 70 ZIP SHA256 on Windows.

No step above is an original extension Publisher authorization; it cannot turn INTEGRITY_ONLY into extension SIGNATURE_VERIFIED.
