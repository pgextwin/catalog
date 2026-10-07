# pgextwin catalog

[日本語](README_ja.md) | English

Machine-readable distribution metadata for Windows x64 PostgreSQL extension binaries published by **pgextwin**.

The catalog stores metadata only. Binary files, checksums, SBOMs, vulnerability reports, and attestations remain canonical in each extension repository's GitHub Release / GitHub Artifact Attestations.

## Layout

```text
index.json
schema/
  index.schema.json
  extension.schema.json
extensions/
  <extension>.json
scripts/
  validate_catalog.py
tests/
  test_validate_catalog.py
```

## Catalog schema v2

Schema v2 keeps the v1 fields used by the current website and adds stable machine-readable distribution metadata for future Website/CLI consumers.

The following compatibility fields remain unchanged:

- `displayName`
- `description`
- `upstream`
- `repository`
- `license`
- `architecture`
- `latest.releaseTag`
- `postgresql.<major>.available`
- `postgresql.<major>.asset`

New v2 metadata includes:

- release publication time, canonical Release URL, and checksum asset name,
- canonical direct download URL and SHA-256 for each available PostgreSQL-major ZIP,
- per-major supply-chain evidence availability,
- user-facing runtime requirements projected from Test Contract v2,
- current CI capability coverage and functional scenario metadata,
- an immutable `capabilitiesSource` pointing to the exact extension-repository commit.

## Availability is not maintenance

`postgresql.<major>.available` remains **historical binary availability**:

- `true` means a published and verified Windows x64 binary asset exists for that PostgreSQL major,
- `false` means such a verified published asset is not recorded,
- it does **not** mean the PostgreSQL community currently maintains that major.

PostgreSQL lifecycle dates and current maintenance state remain canonical only in [`pgextwin/build/metadata/postgresql.json`](https://github.com/pgextwin/build/blob/main/metadata/postgresql.json). Extension records deliberately contain no EOL date or date-dependent `maintained` boolean.

Existing published binaries may remain available after PostgreSQL EOL as historical downloads.

## Direct downloads and SHA-256

For every `available: true` entry, schema v2 requires:

```json
{
  "available": true,
  "asset": "example-pg18-windows-x64.zip",
  "downloadUrl": "https://github.com/pgextwin/example/releases/download/v1/example-pg18-windows-x64.zip",
  "sha256": "<64 lowercase hex>"
}
```

`downloadUrl` must match the record's repository, release tag, and asset filename. CI remote verification reads the **published `SHA256SUMS.txt`** from the current GitHub Release and checks the catalog SHA-256 against that file. GitHub's release-asset digest is also cross-checked when GitHub exposes it.

## Runtime requirements

`runtime.requirements` is the canonical user-facing runtime snapshot from Test Contract v2:

- `extensionCreation`
- `preload`
- `backgroundWorker`
- `clientExecutable.required`
- `clientExecutable.packagePaths`

`runtime.sharedPreloadLibraries` is retained only for backward compatibility with existing consumers. It must not be interpreted as proof that shared preload is mandatory.

This distinction matters because CI test setup and user runtime requirements are intentionally separate. For example, CI may use `shared_preload_libraries` even when Test Contract v2 says the extension supports `either` shared/session preload or that preload is `optional`.

## Test Contract-derived capabilities

`capabilities` exposes what current pgextwin CI actually asserts without copying `smoke-test.ps1` implementation details:

- Test Contract version,
- CREATE EXTENSION coverage,
- background-worker coverage,
- client-executable coverage,
- server-log assertion coverage,
- upgrade coverage,
- stable functional scenario IDs and descriptions,
- evidence types,
- optional PostgreSQL-major scope for a scenario.

Coverage values retain Test Contract v2 semantics: `covered`, `not-covered`, and `not-applicable`.

`capabilitiesSource` records the exact source:

```json
{
  "repository": "pgextwin/pg_cron",
  "path": "config/test-contract.json",
  "commit": "<40-character commit SHA>"
}
```

CI fetches this file at the immutable commit and verifies that the catalog runtime/capability snapshot still matches it. Mutable refs such as `main` are not accepted as source identity.

## Supply-chain evidence

Each available PostgreSQL-major binary has an `evidence` object for:

- Build Provenance Attestation,
- SPDX SBOM Release asset,
- SBOM Attestation,
- vulnerability-report Release asset.

Attestations are not Release assets, so attestation states do not carry asset filenames.

For SBOM and vulnerability-report assets, `available: true` requires an asset filename, canonical download URL, and SHA-256. `available: false` must not carry fictional asset metadata.

The initial eight currently published Releases predate the Step 6-10 release path and contain only PostgreSQL 14-18 ZIPs plus `SHA256SUMS.txt`. Their v2 records therefore correctly show Build Provenance Attestation, SBOM asset, SBOM Attestation, and vulnerability report as unavailable. Historical Releases are not modified retroactively.

Future Releases built by the Step 6-10-enabled release path can set the corresponding evidence fields to available when those artifacts/evidence actually exist.

## Vulnerability reports are point-in-time evidence

A vulnerability report records what a particular Grype scan observed for a particular SBOM and vulnerability database state. It is not a durable security verdict.

The catalog intentionally does not define fields such as `secure`, `safe`, `trusted`, `vulnerabilityFree`, or a mutable current `vulnerabilities: 0` count.

Step 10 remains a report-only baseline; Catalog schema v2 only exposes whether a release-specific vulnerability report exists.

## Validation

Local validation:

```text
python scripts/validate_catalog.py
python -m unittest discover -s tests -v
```

CI additionally runs:

```text
python scripts/validate_catalog.py --verify-remote
```

Remote verification uses immutable Test Contract commits and the current canonical GitHub Releases. It checks release identity, asset URLs, published `SHA256SUMS.txt` values, and the Test Contract-derived snapshot. Requests use bounded retries; GitHub API requests use the workflow token with `contents: read`.

## Catalog v2 vs Website v2

Catalog v2 is the machine-readable API contract. It does **not** implement Website v2.

The current Website continues to consume the v1-compatible fields listed above and independently combines them with PostgreSQL lifecycle metadata. A later Website v2 may opt into direct-download integrity, runtime requirements, capability coverage, and supply-chain evidence fields without changing their meaning in the catalog.
