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
