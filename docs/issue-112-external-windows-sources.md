# External Windows binary discovery and selection (Issue #112)

Status: **CANDIDATE_ONLY, metadata/read-only; no new download authority, mirror, install or Release.**

## User-facing contract

The user sees only two source groups: **external** (upstream or community-provided
Windows binary) and **pgextwin** (both adapted/reference-based and native builds).
Adapted and native are pgextwin's internal implementation methods, not
competing user-facing products. Website cards should prioritize extension name,
upstream stable version, supported PostgreSQL major, compatible Windows x64
environment, provider, availability, and a verified download action. Do **not**
dump candidate-rejection explanations, upstream reference history or builder
internals onto Website cards. Put the provenance, considered approaches,
reasons for non-adoption, licenses, dependency requirements and reproducible
evidence in the repository README and technical documentation. Release notes
should describe only visible changes to availability, usage or compatibility.

For ambiguous download paths, expose **only** an artifact that passed independent
trust/compatibility/rights gates. A discovered-but-unreviewed external file is
searchable as *not yet available*, not offered as an approved download.

## Contract and precedence

1. Filter by extension, PG major, architecture, PostgreSQL distribution, ABI,
   dependencies, rights, original ZIP SHA256, source identity and provenance.
   PG major alone is **not** an ABI compatibility claim.
2. Among eligible candidates select the **latest stable upstream version**;
   within that exact version and environment rank
   external > adapted > native.
3. At identical external rank, prefer independently verified upstream-official
   over independently verified community sources, then use a deterministic
   provider/ID tie-break. Unknown verification does not gain priority merely
   from an upstream-official label.
4. An older official Windows ZIP **must not** hide a newer eligible pgextwin
   build. Source selection is by extension version+PG environment, not a
   permanently fixed per-extension provider. A newly published official build
   can become a candidate after authentic Catalog refresh and independent gates.
5. Historical versions, including EOL PG binaries, remain discoverable; require
   explicit exact-version and EOL opt-in for selection. Do not build new EOL
   targets by default. Nothing silently overwrites or deletes old native
   Releases or installed files.
6. Admission filtering may exclude unverified candidates *before* selection.
   Once a candidate is selected, download, hash, Sigstore, dependency or network
   failure terminates the transaction: **no implicit fallback**.

## Registry and security boundary

- evidence/issue112-external-release-inventory-20261103.json contains the
  complete paginated authenticated GitHub Release **metadata** GET
  for three pilot providers. It is a finite, audited discovery snapshot, not
  proof of exhaustive external Internet coverage.
- external/windows-candidates-v1.json flattens every identified Windows
  ZIP/EXE into a versioned candidate with separate release tag, asset version,
  PG major, architecture, provider/source repository, release/asset numeric
  IDs, API-provided digest (if present), original independently rehashed SHA256
  (currently null), compatibility, dependencies, license, lifecycle, verification
  and separate direct-download vs mirror authority. Historical/EOL and missing
  digest entries are retained; **all current entries are metadata-only and
  download DENY**. An API digest is not independent raw-byte verification.
- schema/external-windows-source-v1.schema.json is additive; original
  Catalog v2 index.json/extension shape, signed feed ZIP pins and
  download-all --fixed remain unchanged. The optional
  externalSourceRegistry link is purely descriptive and cannot grant trust.
- WindowsSourceSelector is a pure, network-free selection function intended
  for use **only after an independently authenticated, gate-approved snapshot**.
  It has hostile synthetic tests covering version ordering, current vs old
  official, PG/ABI mismatch, dependency and identity failure, EOL and no fallback.
  The local registry reader deliberately never creates an authorized ZIP pin.

### Current CLI

list/search --catalog-dir PATH --source external|pgextwin|all performs
**local untrusted discovery**, and optional --format json returns explicitly
untrusted result sets. --source omitted keeps the old listing format.
download and download-all with --source pgextwin retain the existing
pgextwin path; --source external|all is intentionally denied until a protected
Catalog commit, signed external feed extension and independent original-byte,
identity, rights, ABI and provenance verification authorize the chosen file.
Existing source-omitted latest mode, download-all --fixed, staging, checksums,
rollback, and failure isolation are untouched. This PR is **not** a new
downloadable CLI release.

### Pilot evidence and blockers

- HypoPG upstream 1.4.1 has historical PG14-16 Windows assets; upstream 1.4.5
  has no comparable official Windows ZIP. The newer pgextwin 1.4.5 remains
  preferred. This is a metadata comparison, not an ABI compatibility approval.
- oracle_fdw upstream 2.9.0 publishes PG14-18 Windows ZIPs. PG18 Release ID
  335861225, Asset ID 442625860, and GitHub API SHA256
  ad1fc057888b89f968de34f14bd7088c2b05d674a8df4b40ba47ed772c317678
  identify a **candidate**, and independent SHA256/ZIP CRC bytes passed in the read-only
  GitHub Actions pilot. Oracle Instant Client compatibility, license and
  signer provenance are not verified.
- A community pgvector Windows repository
  andreiramani/pgvector_pgsql_windows has version 0.8.7 ZIPs for PG13-18.
  This is **unofficial**; its PG18 ZIP original SHA256 and CRC passed the
  read-only GitHub Actions pilot, but signature, ABI and source provenance
  acceptance remain blocked.
- Read-only GitHub Actions Run 41638680503 (attempt 1) at commit
  db39ed5ff289f1d6ada4817dcdb28f5a1d6e9acd verified the original ZIP
  SHA256, CRC, member structure and bounds for **both** pilots. This is a
  genuine byte-integrity check, NOT Sigstore/identity/ABI/license acceptance.
  Evidence: evidence/issue112-external-original-byte-pilot-20261103.json.
  Candidate admission remains blocked even after the bytes match.

## Remaining integration

Extend the **authenticated, versioned** Catalog feed with admitted candidate
pins only after full validation, extend the existing batch downloader to consume
selected pins without source-specific bypasses, run actual Windows verified
official + community ZIP pilots and original postmerge tests, then separately
gate any mirror or formal Publisher publication. Do not rewrite old Releases.


## Additional GitHub community provider (read-only, 2026-11-03)

The independently enumerated `portalcorp/pgvector_compiled` source contains **6
Releases / 6 Windows ZIPs**, all for PostgreSQL 16. The GitHub Release tags
`v0.16.*` are build counters; release bodies indicate actual pgvector versions
0.7.3, 0.7.4 and 0.8.0. These are older historical candidates, not current
automatic selection. See `evidence/issue112-external-provider-portalcorp-20261103.json`
and `external/windows-candidates-portalcorp-v1.json` for the exact six immutable
asset IDs and metadata. This addendum is **metadata-only**: original ZIP digests,
source commit pins, independent signature/provenance, dependency and ABI proof,
redistribution evidence and formal approval are missing. Even though the
repository declares an MIT license, that does not alone clear the included
pgvector binary, its notices, or any bundled libraries. No external download is enabled.

Not adopted as extension-only providers: `YukeonWayne/pg_pgvector_binary`
(complete PostgreSQL server + pgvector bundle), `pgRouting/pgrouting`
(GitHub ZIPs contain source rather than Windows compiled DLLs). PostGIS
Windows OSGeo/StackBuilder bundles also require a dedicated multi-extension
package adapter and per-file runtime/licensing review. No provider is labeled
verified solely from a GitHub README, release title, SPDX tag, or digest.

### Automatic all-page discovery and admission rule

The protected source allowlist in `external/discovery-providers-v1.json` is
scanned by `scripts/discover_external_windows_releases.py`. Its read-only
GitHub API loop requires an explicit terminal empty page, checks release/asset
IDs, filenames, owner/repository-bound HTTPS URLs, duplicate IDs, bytes and
API SHA256 formatting, then reports additions/removals/metadata modifications
against **two pinned historical baseline snapshots**. The optional Actions
workflow `issue112-external-discovery.yml` runs on relevant PR/main changes
or on an explicit workflow dispatch. It does not add recurring cron, commit to
main, upload a Release, update the signed feed, or automatically authorize
downloads. A newly discovered source requires an allowlist change through
protected CI; new upstream Release versions are flagged when the scan is
next invoked. No claim of continuous off-platform monitoring is made.

**Adoption policy:** when source/payload/third-party-license terms and required
NOTICEs permit the intended action, exact upstream release and source commit
are pinned, original ZIP bytes are independently rehashed and structurally
checked, signer/attestation provenance is verified or an independently approved
equivalent proof is established, Windows PostgreSQL major/distribution/ABI and
runtime dependencies are verified, and the existing protected Catalog,
signed-feed and formal Publisher gates succeed, the eligible external asset
can be admitted for the precise target environment without an additional
discretionary review step. Direct original-asset download and redistribution
or mirroring are **separate permissions**; a license that permits use does not
by itself prove provenance, or authorize repackaging. Missing or conflicting
evidence is a fail-closed DENY, never a basis to silently substitute another
provider. Promotion happens only in an independently reviewed protected PR
and the authenticated existing pipeline, not in the discovery snapshot.

## OSGeo PostGIS / pgRouting / pgSphere Windows bundle adapter

This is a **separate distribution format**, not an extra GitHub Release or
three independent extension ZIPs. The PostGIS project directs Windows users
to OSGeo ZIP and StackBuilder installers:
https://postgis.net/documentation/getting_started/install_windows/released_versions/
The official released bundle 3.6.2 (PG14–18) includes PostGIS 3.6.2,
pgRouting 4.0.1, pgSphere 1.5.2, and substantial GEOS/PROJ/GDAL/SFCGAL
and other runtime components. Its source-content and binary-dependency
version constraints cannot be inferred from the bundle's PostGIS version.

### Historical discovery

`scripts/discover_osgeo_windows_bundles.py` enumerates exactly
`https://ftp2.osuosl.org/pub/osgeo/download/postgis/windows/` (public
OSGeo mirror) or the pinned `https://download-cache.osgeo.org/postgis/windows/`
index by explicit `--index`. It strictly accepts only `pgNN/` directories
plus their immediate optional `archive/`; no general crawl, recursive links,
source/extras trees, redirects or arbitrary origin. It parses all matching
PostGIS ZIP and setup EXE filenames while preserving unparsed archive filename
identities. For historical `pg80`–`pg96` paths, the PG major is normalized
to 8.0–9.6, **not** 80–96. New `pg19` path presence does not certify GA.
It records whether an MD5 sidecar appears but never accepts MD5 as SHA256,
signature, provenance or original-byte validation.

The scanner emits local **metadata-only** JSON to the Actions runner temp
folder; on PR/main changes and explicit dispatch the read-only
`issue112-osgeo-readonly.yml` workflow runs hostile offline tests and the
finite online index scan. No ZIP/EXE/MD5 body download, unpacking, install,
signed Catalog feed mutation, publication, mirror or stateful scheduled task
is performed. This directory scanner is **not** a GitHub Release adapter and
does not grant source-chooser priority to any particular extension.

### Admission, rights and required evidence

For each exact external bundle and each included extension, record:
- Exact target PG major, vendor/EDB Windows distribution, x64 MSVC ABI, ZIP/EXE
  identity, original independently verified SHA256, and package source identity.
- Bundle **component manifest** with distinct versions and file inventory:
  PostGIS core, pgRouting, pgSphere, supporting extensions, GEOS, PROJ, GDAL,
  SFCGAL and other shared DLLs. Record which files and licenses/NOTICES are
  necessary for a *direct-download link* versus *pgextwin redistribution*.
- Legitimate source and build provenance, authentic signatures/attestations
  or separately reviewed equivalent independent trustworthy evidence, runtime
  tests for PG major/vendor ABI, dependencies, upgrade/collision behavior and
  adverse extraction cases.
- Reviewer-readable exact proof refs and protected Catalog signed-feed/Pubisher
  authorization *for the intended operation*. Direct download and mirroring
  are independent gates. A directory name, MD5 sidecar, liberal source license
  or an official provider label cannot authorize a binary.

Only independently **admitted package-specific files** may later enter a
versioned signed feed and the existing fail-closed .NET downloader. PostGIS
bundle files must not be repackaged into individual pgRouting or pgSphere ZIPs
merely because those binaries are present: this changes distribution and
license scope. The current signed feed/CLI and all existing native packages
are unchanged; **OSGeo bundle download/mirror/install = DENY**.
