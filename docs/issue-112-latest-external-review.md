# Issue #112 — latest-observed external per-PG review and shared spatial bundles

**CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY.**
This is an offline selection/qualification tool, **not a user-facing CLI
download, source authorization, immutable signed feed, or a new release**.

## Why this unit

Production `pgextwin download-all --source external [--pg MAJOR|all]
[--extension NAME [--version EXACT]]` already parses the requested selectors
and requires independently Sigstore-verified, source-specific signed admission.
Do not reimplement that production path or add an unsigned shortcut.

The reusable nonpublishing review selector chooses the **highest numeric stable
version observed** in already checked-in discovery data for each extension ×
supported PG major, or an explicitly requested exact version. This reduces
work spent on old releases without claiming the discovery inventory is complete,
that an observed version is the current upstream release, or that it has any
permission to download. When two providers offer the same observed version,
both review candidates remain visible; trust precedence is decided **only**
by the existing authenticated production selector and independent gates.

Two additional bounded, previously researched original sets are now included:
PGroonga 4.1.0 official ZIPs and postgresonline.com community http ZIPs.
Their five-major original SHA256/byte pins are reused from the existing
PGroonga rights auditor and http Windows research, with no new binary GET,
download permission, signed admission, or live-upstream-latest assertion.
For http, the per-major version label is **publisher-advertised and unverified**.

The selector consumes existing `issue112_external_batch_plan.build()`, which
checks **the complete** GitHub candidate registries, prevents a selected filter
from hiding a poisoned unselected row and inherits P3 holds. It also reuses
the five independently rehashed original OSGeo SHA/length pins from
`issue112_osgeo_winnie_version_receipt.ORIGINALS`. Those pins are evidence of
original bytes, **not** an exact producer-signed provenance certificate.

## Offline examples (no network and no ZIP copying)

```bash
python scripts/issue112_latest_external_review.py --catalog . --pg all --output /tmp/issue112-all.json
python scripts/issue112_latest_external_review.py --catalog . --source osgeo --extension postgis --pg all --output /tmp/issue112-postgis.json
python scripts/issue112_latest_external_review.py --catalog . --source osgeo --extension pgrouting --pg all --output /tmp/issue112-pgrouting.json
python scripts/issue112_latest_external_review.py --catalog . --source github --extension hypopg --version 1.4.1 --pg 16 --output /tmp/issue112-hypopg.json
python scripts/issue112_latest_external_review.py --catalog . --source pgroonga --extension pgroonga --version 4.1.0 --pg all --output /tmp/issue112-pgroonga.json
python scripts/issue112_latest_external_review.py --catalog . --source http --extension http --version 1.7.1 --pg all --output /tmp/issue112-http.json
```

All outputs are create-only JSON, `admittedAssets=0`, with explicit denial
flags at root and on every selection. `--version` requires `--extension`.
Unknown PG majors, unsafe input, malformed metadata, source authorization
claims and duplicate GitHub release/asset identities fail closed.
No implicit fallback or publishing operation is performed.

## PostGIS, pgRouting and PostGIS subextensions: ONE original per major

For each selected PG14–18 major, **one** previously rehashed
`postgis-bundle-pg<PG>-<POSTGIS_BUNDLE_VERSION>x64.zip` is the shared
review candidate for seven named extension components:

- `postgis`, `pgrouting`
- `postgis_raster`, `postgis_sfcgal`, `postgis_topology`
- `address_standardizer`, `postgis_tiger_geocoder`

This expands component selection from 2 to 7 **without increasing the five
unique original ZIPs**. `uniqueOriginalPackageIdentities` still deduplicates
the shared ZIP, while separate rows retain requested component and PG coverage.
The component names follow the official PostGIS Windows installation
instructions: https://postgis.net/documentation/getting_started/install_windows/enabling_postgis/
This is a **documented bundle-component observation only**: individual
control/SQL/DLL inclusion and Windows runtime/ABI acceptance, producer
provenance, applicable NOTICE/dependency clearance and authorization are
still required independently for any formal public GET. No public Catalog
feed, issuer, Publisher, Release, CLI, or Website admission was modified.

The version in the bundle filename is the **PostGIS bundle version, not
the independently determined pgRouting or subextension version**.
The five previously pinned, tested original observations are not a live
latest-release feed. Newer ZIPs require new real-byte, rights, runtime and
provenance checks. `--version` on this offline review refers to the bundle
version; bundle-specific versions are not per-component version claims.

## PGroonga and http: five pinned original candidates each, never public GET

- PGroonga 4.1.0 has an original SHA256/size observation for PG14–18 in
  `issue112_pgroonga_rights_audit.PINS`. Its legal/NOTICE joins, dynamic
  dependencies and original producer attestation still require independent
  closure. A reviewed official release version is **not** a live check of the
  latest upstream release.
- http uses the community `pg14http_w64.zip` … `pg18http_w64.zip`
  originals and the exact original SHA256/size observations from
  `issue112_http_windows_runtime.PINS`. Advertised versions differ by
  PG major (14: 1.5.0; 15–16: 1.6.1; 17–18: 1.7.1). Treat these as
  **unverified publisher labels**, not upstream source semver proofs.
- `--source pgroonga|http`, `--pg`, `--extension` and exact `--version`
  select candidate review rows only. The SHA/size pins are observational
  integrity evidence; neither source is admitted into the signed Catalog feed,
  actual CLI downloads, the Publisher, Releases or Website. All trust flags
  remain DENY, including when one PG major is omitted or another is selected.

## Rights and producer admission blockers (remain real)

- **pg_track_settings 2.1.2:** Cybertec original PG14–18 bytes and EDB SQL
  behavior were already verified in Catalog PR #303. The originals omit
  LICENSE/NOTICE; upstream Julien Rouhaud source licensing alone does not prove
  original-distribution notice compliance. Cybertec did not supply a
  cryptographically authenticated, original-SHA-bound build provenance receipt
  within the evidence reviewed. The current tool **does not** claim closure.
- **pg_permissions REL_1_4:** original and EDB Windows behavior qualified in PR
  #305, but this Cybertec packaging revision is not upstream release 1.4.1.
  LICENSE/NOTICE and producer-origin signature remain unresolved.
- **OSGeo:** original ZIP digest and Windows test evidence alone does not
  establish component-wide NOTICE/dependency/source-to-DLL identity.
- To advance public retrieval, obtain genuine provider-specific copyright and
  notice compliance, exact-binary producer evidence and independently signed
  admission under the existing protected Build issuer/Publisher controls,
  **or** create a distinctly labeled, licensed source-pinned pgextwin-owned
  build through the legitimate independent build/signing/publishing route.
  Do not attach a self-authored sidecar to an unchanged provider ZIP and
  represent it as a Cybertec producer signature. Do not rewrite provider ZIPs.

All existing signed-feed checks, CLI real GET paths, P3 holds, protected
branches, and formal Publisher authorization gates remain unchanged.

## PGroonga latest-stable official Release watch (metadata only, 2026-11-12)

The existing read-only GitHub discovery monitor also scans official
`pgroonga/pgroonga` Releases for Windows PG14–18 ZIPs. Its first immutable
metadata baseline is the official 4.1.0 GitHub Release (ID `407467158`)
and the five original ZIP asset IDs in
`external/pgroonga-release-watch-baseline-v1.json`.
Each baseline size and SHA256 is strictly cross-checked against the already
independently rehashed `issue112_pgroonga_rights_audit.PINS`. Every run
also checks the original GitHub asset names, IDs, sizes and API digests.
Changed or missing pinned assets are rejected, not automatically upgraded.
A newly observed higher stable Release tag is only a **new review alert**;
it is never an automatic source/rights/runtime approval.

The watcher includes no `.asc` signatures, source archives or non-PG14–18
binaries as candidate Windows ZIPs. The public original signatures are
**not** counted as independently verified producer provenance in this
change. This does not make newer Release assets, or the unchanged 4.1.0
originals, available through the published CLI: `PUBLIC_GET_DENY`,
`MIRROR_DENY`, `RELEASE_DENY` and `PUBLISH_DENY` remain in force.
The original signed feed, formal Publisher, Website and user-facing CLI
are unchanged.


## TimescaleDB official Windows stable Release monitor (metadata only, 2026-11-12)

The existing read-only GitHub Release monitor now includes official
`timescale/timescaledb` Windows x64 ZIP names for PostgreSQL 14–18 *where
upstream provides them*. The observed latest stable Release `2.31.0`
(Release ID `418582851`, 2026-10-20) supplies PG16, PG17 and PG18 ZIPs
only; PG14/15 support is **not inferred**. The three exact asset IDs, names,
API-reported lengths and API-reported SHA256 digests are frozen in
`external/timescaledb-release-watch-baseline-v1.json`. Missing or modified original metadata fails closed,
while a higher numeric stable tag generates a review alert only.

These pins are **untrusted GitHub API observations**, not independent original
ZIP byte hashes, producer signatures, source-to-binary provenance or license
and dependency admission. No provider binary GET, additional schedule, new
privilege, release, signed feed, public CLI or Website change is added.
All new assets remain CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY /
RELEASE_DENY / PUBLISH_DENY.

## TimescaleDB PG16–18 observed latest selector (metadata-only, 2026-11-12)

The offline review planner now consumes the **existing**, strict
`external/timescaledb-release-watch-baseline-v1.json` instead of inventing
a parallel source inventory. It selects exactly three officially observed
`2.31.0` Windows ZIP *metadata* records (PG16, PG17, PG18). No binary is
downloaded. PG14/15 are not inferred or fabricated.

```bash
python scripts/issue112_latest_external_review.py --catalog . --source timescaledb --pg all --output /tmp/issue112-timescaledb.json
python scripts/issue112_latest_external_review.py --catalog . --source timescaledb --extension timescaledb --version 2.31.0 --pg 17 --output /tmp/issue112-timescaledb-pg17.json
```

The planner independently rejects duplicate-key or permission-elevated
baseline JSON, missing/duplicate PG majors or asset IDs, noncanonical
names, inconsistent schemas and invalid digest *metadata*, even if a
different `--source` is selected. Output rows carry the original provider's
**API-observed** sizes and digests in `apiObservedBytes` and
`apiObservedSha256`. The independent original-byte fields
`originalBytes`/`originalSha256` stay `null` deliberately.

This adds TimescaleDB to the shared review selection, **not** to the
production authenticated CLI download feed. The genuine daily watcher
independently checks live source metadata; the offline planner does not.
Package rights, notices, dependency closure, producer provenance,
Windows runtime, signed admission and formal publication remain unapproved.
Every row stays `PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY /
PUBLISH_DENY` and `admittedAssets=0`. No renewed owner signature,
Environment review, publisher, CLI Release, Catalog signed feed or Website
download has been produced.
