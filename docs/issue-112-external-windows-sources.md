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

**Adoption policy (provider-proportionate):** external publishers do **not**
have to reproduce pgextwin's internal build outputs. Preserve the authentic
provider Release + asset identity, independently verified original bytes and a
documented origin/risk assessment; a fixed source commit is valuable when
available, but is not a universal prerequisite for third-party binaries.
Likewise upstream Sigstore, SBOM, Grype and reproducible-build records are
optional supporting evidence, **not a mandatory uniform checklist**.
Authenticated GitHub Release/asset identity and independently hashed immutable
bytes may support an origin decision where upstream signing is absent; a
community repository is **not** automatically upstream-official or trusted.
Do not substitute an unreviewed README claim, mutable tag or unsigned checksum
for a verified original binary.

Every admitted asset still needs complete extension payload, archive safety,
exact Windows PostgreSQL major/distribution/architecture/ABI runtime evidence,
required runtime dependencies, terms for the intended use plus *applicable*
license notices, and an authenticated signed Catalog pin and formal **pgextwin**
download authorization. Direct links to original third-party Releases are
different from pgextwin-hosted reupload, redistribution or repackaging; the
latter requires a separate rights and publication decision. Reject conflicting
or missing **essential** evidence without silently selecting another provider.
Promotion uses a protected PR and the existing authenticated pipeline; an
untrusted discovery snapshot never grants authority.

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

## Fail-closed individual external admission preflight

`scripts/external_admission_preflight.py --output PATH` is an **offline
gap reporter**, not a publishable Catalog authority. It joins the existing
two explicit source-registry files against the exact original-byte pilot Run
41638680503 using **repository + Release ID + Asset ID**, then verifies the
extension name, upstream version, target PostgreSQL major and reported SHA256
against any matching GitHub API digest. Its report preserves independent
`BYTE_INTEGRITY_ONLY` pilot identity and enumerates missing proof conditions
per candidate, without modifying trusted download pins.

The gap reporter distinguishes **essential** requirements from evidence
that may be useful but is not uniformly available. Essential conditions are
independent original ZIP bytes, reviewed provider Release origin/attribution,
applicable license and NOTICE terms for the intended use, actual Windows
PostgreSQL ABI testing, dependency closure, authenticated signed Catalog pin
and formal pgextwin download authorization. The upstream source commit is
recorded when it exists but is **not** an unconditional blocker; upstream
signature, SBOM, Grype and reproducibility reports are not required merely
because pgextwin publishes them. The provider's maturity and delivery practice
determine the evidence used to establish origin and risk, not whether runtime
compatibility or exact asset bytes can be skipped.

Mirroring still requires separate redistribution rights and authorization.
Reported green booleans in unsigned JSON cannot replace independent checks
or protected pgextwin Publisher gates. Neither external Release metadata nor
a prior successful ZIP byte pilot alone constitutes admission.

Current initial registry: **203 discovery candidates remain blocked**.
The original 2 pilot assets are merely linked as byte-integrity observations;
they still lack independent signature/provenance and other conditions.
Future valid candidates should be admitted only through a separately reviewed,
protected PR carrying genuine evidence, verified signed feed and authorized
Publisher. The untrusted discovery JSON must not be rewritten in place to
turn a `downloadAuthorized` boolean on.

Run this preflight from the Catalog checkout:

```sh
python3 scripts/external_admission_preflight.py --output /tmp/external-admission-untrusted.json
```

The output is local-only; no ZIP download, extension install or new Release.


## Proportionate pilot assessment: original provider bytes, not pgextwin output parity

A practical admission review asks whether the downloaded package is a usable,
attributable PostgreSQL extension for its declared target, not whether the
provider builds a pgextwin-style SBOM/attestation/scan bundle. The **required
payload** depends on the extension: the DLL, control/SQL files, any helper EXE
or runtime DLL actually needed, and enough installation/dependency instructions
to avoid installing into the wrong PostgreSQL environment.

| Pilot | Established independent evidence | Essential evidence still missing |
| --- | --- | --- |
| Official `laurenz/oracle_fdw` 2.9.0 PG18, asset 442625860 | Authenticated upstream Release and source tag commit `3ea9a4522c445c15c741d4f2bc89bccde740d283`; independent original 365101-byte ZIP SHA256 `ad1fc057888b89f968de34f14bd7088c2b05d674a8df4b40ba47ed772c317678` and CRC pilot | Assess actual ZIP file inventory and notices, Oracle Client (>=11.2, user-supplied rather than mirrored), runtime ABI on Windows PostgreSQL 18, reviewed provider-to-binary attribution, signed pin and pgextwin authorization |
| Community `andreiramani/pgvector_pgsql_windows` 0.8.7 PG18, asset 661612613 | Authenticated community Release (explicitly unofficial) and independent original 174796-byte ZIP SHA256 `7c4ae0e2b2cb1e547779209a34a7d3f05b82fd7912818bf3d7042266eda87e7d` and CRC pilot | Complete payload and license notices, demonstrate Windows 18 ABI/SQL/vector behavior, document community origin and compiler/runtime risk, signed pin and pgextwin authorization |

For oracle_fdw, the upstream source LICENSE permits copying and distribution
provided its copyright and disclaimer text is retained. This does **not**
automatically clear every embedded binary or Oracle Instant Client licensing;
the upstream README explicitly requires Oracle Client 11.2 or newer and
matching PostgreSQL/Oracle architectures. Do not bundle Oracle's runtime
without a separate rights review. See the exact upstream
[`LICENSE`](https://github.com/laurenz/oracle_fdw/blob/ORACLE_FDW_2_9_0/LICENSE)
and [`README.oracle_fdw`](https://github.com/laurenz/oracle_fdw/blob/ORACLE_FDW_2_9_0/README.oracle_fdw).

For pgvector, the community provider calls its binaries unofficial; the
upstream pgvector project documents compiling Windows binaries with MSVC
and does not certify this community ZIP merely by publishing source code.
See the [provider README](https://github.com/andreiramani/pgvector_pgsql_windows)
and [upstream Windows instructions](https://github.com/pgvector/pgvector#readme).

**Current decision: both remain DENY for real downloader use.** Neither has
a completed Windows runtime and dependency review or formal approved feed.
The provided hashes and identities are precise observations, not implied
upstream cryptographic signatures, package vulnerability clearances or
redistribution authorizations. Successful historic CI is not rerun merely
to generate additional provenance.


## Current PG18 provider admission assessment

The exact provider-origin matching, original pgvector ZIP README/NOTICE inventory,
oracle_fdw/Instant Client licensing separation and minimal no-Oracle-DB OCI load
acceptance are maintained in
[PG18 provider review](issue-112-provider-review-pg18.md).
That later evidence supersedes the earlier initial pilot gap descriptions above.
All 203 discovery entries still remain DOWNLOAD_DENY / MIRROR_DENY; the dedicated
OCI smoke is nonpublishing and does not grant signed feed or downloader authority.

## pg_trickle official Windows Release discovery — 2026-11-04 JST

Authenticated, read-only GitHub REST GET of `trickle-labs/pg-trickle`
(`/releases?per_page=100&page=1..3`) returned **100 / 39 / 0**
Releases (139 total); each has one uploaded Windows ZIP, and every Windows
asset currently has a GitHub API `sha256:` digest. **137** ZIP names match
`pg_trickle-X.Y.Z-pg18-windows-amd64.zip`. The two earliest archives are
named `pg_stream-0.1.0/0.1.1-pg18-windows-amd64.zip`; they are
**deliberately excluded** from automatic `pg_trickle` discovery because
their former name/extension identity needs separate review.

The newest observed Release is
[`v0.108.3`](https://github.com/trickle-labs/pg-trickle/releases/tag/v0.108.3),
published 2026-10-06 UTC, Release ID `404988260`, Windows Asset ID
`616203967`, `7029107` bytes and *API-reported* SHA256
`c2841dacee6fa1a09400c7e9a0f74159f2b7f36847a60ef10291d1beb06bd96b`.
This hash was read from release metadata, **not independently computed
from downloaded ZIP bytes**. The repository advertises Apache-2.0 licensing;
package license notices and any bundled dependencies remain to be reviewed.

The declarative allowlist now adds only
`trickle-labs/pg-trickle`, marked `upstream-official` for this
upstream-owned repository and restricted to exact PG18 Windows amd64 ZIP
names. Reuse the existing all-page release scanner and metadata-only
comparison; no extra scripts, triggers, candidate admission, or public
distribution path are added. Existing 203 persisted metadata-only candidates
are unchanged; the 137 newly discoverable matches **are not 137 newly
admitted binaries**. Upstream's Release Process describes the Windows amd64
build as best-effort/build-only, not evidence of verified Windows runtime.

**Still missing before any pgextwin user-byte operation:** independently
rehash each intended original ZIP and check archive safety/payload, identify
source-to-Release and compiled binary provenance, review applicable Apache-2.0
and dependency notices, demonstrate Windows PG18 x64 ABI/runtime behavior,
and complete the signed source-specific Catalog plus genuine owner-event
Publisher and independent formal authorization. A GitHub API digest, a
passing metadata-discovery CI job, and this documentation are not approval.
All existing and newly discoverable external assets remain
**DOWNLOAD_DENY / MIRROR_DENY**; no external Release, signed public feed,
CLI download or Website user-byte acceptance is changed.
