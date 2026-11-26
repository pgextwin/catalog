# pgextwin CLI — locally verified Sigstore Catalog feed

## Behavior

Use `pgextwin download hypopg --source pgextwin --pg 15` to get the newest approved HypoPG Windows x64 ZIP for PostgreSQL 15. Add `--version 1.4.4` to get that exact upstream version if its package is in the signed inventory. An unavailable version produces a selection error. Named downloads without `--source` use the external Catalog.

`pgextwin download-all --pg all` selects the latest approved ZIP for every extension and supported PostgreSQL major. Use `--pg MAJOR` for a single major. The default bulk mode is `--latest`. `--fixed` selects the historical snapshot. Internal `--version` requires a named download from the signed feed.


The signed feed supplies pgextwin builds for its approved PostgreSQL cohort,
starting at PG15. For external originals, select an item with
`pgextwin download postgis --source external --pg 18`. Independently pinned
local policies are inputs to `pgextwin verify report`.

Automatic downloads require CLI v0.6.0 once the v3 feed becomes the public latest. CLI v0.4.0 and v0.5.0 read the previous v2 format.

External downloads (the `external/direct-get.json` / `external/standalone-get.json` records) require CLI v0.6.1 or later. v0.6.1 accepts multi-architecture standalone records (for example psqlODBC 18.00.0006 as separate x64 and x86 records). Earlier CLIs fail closed with an `InvalidDataException` when parsing the current standalone record set — they serve no incorrect bytes — so upgrade to v0.6.1 for external downloads.

A protected-main signed-feed publisher runs only after an independently verified exact-main `Validate catalog` push SUCCESS. A GitHub Actions OIDC signer signs `catalog-latest.json` using Sigstore; a separate write-scoped job cryptographically validates the original signed bytes before create-only Release publication as the repository's latest Release.

Each public feed Release has a create-only `catalog-feed-<40-char-sha>` tag and exactly:

- `catalog-latest.json` contains the signed inventory (`pgextwin-signed-catalog-zip-feed/v3`). Each extension has a repository ID, latest Release tag, and one or more Catalog-approved Releases. Each Release has its GitHub ID and Catalog admission commit. Its packages carry the PostgreSQL major, exact upstream version, ZIP name, asset ID, SHA-256 and commit-pinned license evidence.
- `catalog-latest.sigstore.json` contains the GitHub Actions Sigstore/SLSA bundle.

Each latest Release covers the required PostgreSQL majors. The feed declares the optional major when at least one latest package supports it. History may contain fewer majors. The protected Catalog controls current admission for each historical package. Removing a history row withdraws it in the next signed feed.

[Current public Catalog feed Release](https://github.com/pgextwin/catalog/releases/latest)

## Retrieval and verification

The CLI resolves `https://github.com/pgextwin/catalog/releases/latest/download/catalog-latest.json` exactly once, through bounded, HTTPS-only redirects to approved GitHub asset hosts. From that redirect chain it takes the exact `catalog-feed-<40-char-sha>` Release tag and fetches `catalog-latest.sigstore.json` pinned to that same tag, so a latest advance during the fetch cannot mix two Releases. There is no discovery ref, no alternate asset name and no fallback: a 404, a redirect to a different tag, or any verification failure is a fetch failure.

**Before accepting any metadata**, the CLI verifies the bundle cryptographically using the pinned **Sigstore 1.1.1** managed verifier and a TUF trust root independent of the feed. The exact GitHub Actions OIDC issuer, signer workflow SAN, protected main ref, source repository ID and SHA, SLSA predicate and verified timestamps must match. The CLI validates package key uniqueness and latest pointers in the authenticated inventory. Both latest and exact selection use the same inventory and bounded `PinnedBrowserDownloader` to verify original ZIP bytes. Bulk download stages all selected ZIPs before committing the output directory.

`DOWNLOAD-INFO.json` records the actual ZIP count and each package’s Catalog commit, Release tag, PostgreSQL major, version, license and SHA-256 and `source=SIGSTORE_SIGNED_CATALOG_FEED_ORIGINAL_ZIPS`, `releaseMetadataVerified=false` because numeric GitHub Release IDs are **signed feed pins** and not live API audited by the client, `verificationLevel=INTEGRITY_ONLY`, `signatureVerified=false` for **original extension ZIP signatures**, `provenanceVerified=false` for the same originals, `installAuthorized=false` and `publicationAuthorized=false`. `CATALOG_AUTH=SIGSTORE_VERIFIED_FEED` means *only the Catalog feed's* Sigstore attestation passed.

External binaries are a separate path: the CLI reads `external/direct-get.json` / `external/standalone-get.json` records directly and does not route them through the signed feed or any signed admission.

## Safety, availability and policy

- Any incorrect Sigstore identity, revoked/missing trust root, incorrect original ZIP SHA256, unsigned/mismatched feed, cross-Release redirect, unexpected Catalog commit, HTTP 403/429, incomplete package rows, duplicate/unsafe names or output collisions fail closed.
- A GitHub `releases/latest` pointer is an online freshness locator. Stateless clients cannot prove an absent new signed feed against rollback by a compromised GitHub Release latest pointer. The signed feed provenance and exact immutable contents are independently authenticated; automatic update freshness still depends on GitHub's public latest Release endpoint. No mutable untrusted feed hash authorizes itself.
- A feed Release **does not publish or authorize any extension ZIP**, and does not attest the extension original ZIP bytes individually. The feed signature never turns INTEGRITY_ONLY into extension SIGNATURE_VERIFIED.
