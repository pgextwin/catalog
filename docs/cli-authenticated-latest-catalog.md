# pgextwin CLI — locally verified Sigstore Catalog feed

## Behavior

The user command `pgextwin.exe download-all --pg all` selects the **Catalog-registered** published Release per extension and retrieves the original public ZIPs for every signed-feed package; `--pg <major>` restricts the selection to one PostgreSQL major. `--latest` is equivalent to the default. `--fixed` is a separate, frozen historical selection and does not use the signed feed.

The CLI does **not call anonymous GitHub REST APIs** and needs no GitHub account login. A protected-main signed-feed publisher runs only after an independently verified exact-main `Validate catalog` push SUCCESS. A GitHub Actions OIDC signer signs `catalog-latest.json` using Sigstore; a separate write-scoped job cryptographically validates the original signed bytes before create-only Release publication as the repository's latest Release.

Each public feed Release has a create-only `catalog-feed-<40-char-sha>` tag and exactly:

- `catalog-latest.json` — the signed feed (schema `pgextwin-signed-catalog-zip-feed/v2`): raw Catalog SHA256 digests for `index.json` and every `extensions/*.json`, plus, per extension, the Release tag, repository/Release/checksum Asset IDs and one package row per PostgreSQL major with its asset name, original SHA256 and download URL.
- `catalog-latest.sigstore.json` — its GitHub Actions Sigstore/SLSA signature bundle.

The feed declares the required PostgreSQL majors and at most one optional major immediately after them. Every registered extension contributes a package row for each required major and, where its Catalog record marks the optional major available, for that major too; `zipCount` is the actual number of package rows. When no extension has an available optional-major package, the feed omits the optional major and carries required rows only.

Current public feed: [GitHub Catalog latest Release](https://github.com/pgextwin/catalog/releases/latest).

## Retrieval and verification

The CLI resolves `https://github.com/pgextwin/catalog/releases/latest/download/catalog-latest.json` exactly once, through bounded, HTTPS-only redirects to approved GitHub asset hosts. From that redirect chain it takes the exact `catalog-feed-<40-char-sha>` Release tag and fetches `catalog-latest.sigstore.json` pinned to that same tag, so a latest advance during the fetch cannot mix two Releases. There is no discovery ref, no alternate asset name and no fallback: a 404, a redirect to a different tag, or any verification failure is a fetch failure.

**Before accepting any metadata**, the CLI verifies the bundle cryptographically using the pinned **Sigstore 1.1.1** managed verifier and a TUF trust root independent of the feed. The exact GitHub Actions OIDC issuer, signer workflow SAN, protected main ref, source repository ID and SHA, SLSA predicate and verified timestamps must match. It then fetches the Catalog JSON files by exact immutable commit SHA and rehashes every byte against the signed feed, checks every extension's latest tag and package URLs/digests/IDs against the immutable Catalog records, and invokes the existing bounded `PinnedBrowserDownloader` and all-or-nothing `BatchReleaseDownloader.StageAsync`.

`DOWNLOAD-INFO.json` records each package's original Catalog commit/Release tag/SHA256 and `source=SIGSTORE_SIGNED_CATALOG_FEED_ORIGINAL_ZIPS`, `releaseMetadataVerified=false` because numeric GitHub Release IDs are **signed feed pins** and not live API audited by the client, `verificationLevel=INTEGRITY_ONLY`, `signatureVerified=false` for **original extension ZIP signatures**, `provenanceVerified=false` for the same originals, `installAuthorized=false` and `publicationAuthorized=false`. `CATALOG_AUTH=SIGSTORE_VERIFIED_FEED` means *only the Catalog feed's* Sigstore attestation passed.

External binaries are a separate path: the CLI reads `external/direct-get.json` / `external/standalone-get.json` records directly and does not route them through the signed feed or any signed admission.

## Safety, availability and policy

- Any incorrect Sigstore identity, revoked/missing trust root, incorrect original ZIP SHA256, unsigned/mismatched feed, cross-Release redirect, unexpected Catalog commit, stale/missing raw files, HTTP 403/429, incomplete package rows, duplicate/unsafe names or output collisions fail closed.
- A GitHub `releases/latest` pointer is an online freshness locator. Stateless clients cannot prove an absent new signed feed against rollback by a compromised GitHub Release latest pointer. The signed feed provenance and exact immutable contents are independently authenticated; automatic update freshness still depends on GitHub's public latest Release endpoint. No mutable untrusted feed hash authorizes itself.
- A feed Release **does not publish or authorize any extension ZIP**, and does not attest the extension original ZIP bytes individually. The feed signature never turns INTEGRITY_ONLY into extension SIGNATURE_VERIFIED.
