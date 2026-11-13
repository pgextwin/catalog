# Issue #112 — latest external physical-package review cohorts

**CANDIDATE_ONLY. This is NOT a download manifest. No newly authorized GET,
mirror, issuer, Publisher, Release, signature, or redistribution.**

The prior `issue112_latest_external_review.py` already selects the highest
**observed** stable version for each extension and PostgreSQL major, with
`--extension NAME --version EXACT` for older explicit selections.
It also preserves OSGeo's PostGIS/pgRouting/subextension sharing of one ZIP.

This follow-up reuses that tested selector **without copying its source-specific
validation**, then prefers the single highest observed stable version of each
non-bundle extension **across PG majors**. A PG major with only an older binary
is reported as unobserved at that newest version, **not silently downgraded**.
Explicit `--extension NAME --version EXACT` bypasses this latest-only filter.
Unrankable Cybertec packaging labels remain separate unverified leads, not
claimed newest upstream semver. Bundles retain per-major observed versions:
there is no false requirement that a PostGIS bundle's label equals the
pgRouting component version. The selected logical extension rows are compiled
into bounded, physical-original review cohorts. A shared OSGeo bundle is represented **once**
for each PostgreSQL major rather than downloading seven copies. Plain per-major
provider ZIPs retain independent package identities. Versions in OSGeo filenames
are *bundle versions*, not verified pgRouting component versions.

Example commands (offline, no provider requests):

```bash
python scripts/issue112_external_package_cohorts.py --catalog . --pg all --output /tmp/all-external-review.json
python scripts/issue112_external_package_cohorts.py --catalog . --source osgeo --pg all --output /tmp/spatial-review.json
python scripts/issue112_external_package_cohorts.py --catalog . --source osgeo --pg all --single-bundle --output /tmp/latest-one-bundle-review.json
python scripts/issue112_external_package_cohorts.py --catalog . --source osgeo --extension pgrouting --pg all --output /tmp/pgrouting-review.json
python scripts/issue112_external_package_cohorts.py --catalog . --source github --extension hypopg --version 1.4.1 --pg 16 --output /tmp/hypopg-historical-review.json
```

Output is **create-only** JSON with `reviewBatchCount`,
`olderObservedRowsOmitted`, distinct
`uniqueOriginalPackages`, per-package `extensions`, immutable candidate
identities, observed bytes/SHA256 *where independently known*, and
`unobservedMajorsNotSupportVerdict`. The last field identifies missing
observations, **not** a claim that upstream does not support those majors.

When a user does **not** need a separate OSGeo PostGIS/pgRouting ZIP per PG
major, `--single-bundle --pg all` selects **one physical original**: the
highest *observed* stable PostGIS bundle version, breaking equal-version ties
by the higher observed PG major. The other external extensions keep their
ordinary independently selected per-major ZIP rows. This option never claims
that a PG18-compiled ZIP works on PG14–17 or that the observed bundle is the
current live upstream newest. The output marks
`singleBundleMajorIsNotCrossMajorCompatibility=true` and retains missing PG
majors as unobserved. `--pg 18 --single-bundle`, an exact `--version` with
`--single-bundle`, and requests with no OSGeo bundle are rejected, instead of
silently producing an ambiguous plan. Existing default five-major bundles and
`--extension/--version` behavior remain unchanged. This only reduces **review
packages**, not real network requests (which remain zero).

Validation is now performed on the entire selected source inventory **before**
either newest-version or single-bundle thinning. This prevents invalid older
records or unchosen bundles from hiding forbidden permission fields.

Each batch is bounded at 1–20 original packages (default 12); each actual
package occurs once. One held/failed candidate never silently substitutes
another upstream provider. All root, batch and package download/Publisher flags
are false, with `admittedAssets=0`, `userDownloadAvailable=false`, and
`networkRequests=0`.

The underlying selector validates **all** discovery inputs before filters.
This compiler rejects contradictory package IDs, bytes, versions, PG majors,
duplicate bundle components, malformed hashes, missing blockers, elevated
permissions and incompatible aggregate counts. Hostile Python unit tests run
under the existing required Catalog Validate job. No current signed Catalog,
CLI public GET, admission, Website, or published Release is modified.

## Completion boundary

This is one independent, nonpublishing implementation unit for scaling the
latest-first / exact-version / bundle-once **review**. Actual all-major external
downloads still require genuine source-specific per-package admission, current
signed source pins, compatibility/NOTICE/provenance verification, owner
authorization and the existing formal release gates. A currently unobserved
major or older unpinned version is never invented. In particular, the existing
long-term P3 holds for the original oracle_fdw / andreiramani source pair
remain in force; discovery and review do not undo those holds.
