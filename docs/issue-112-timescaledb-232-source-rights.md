# Issue #112 — TimescaleDB 2.32.0 tagged-source license continuity (DENY-only)

Status: **CANDIDATE_ONLY / NONPUBLISHING**. This scoped check completes a
source-document continuity observation, not binary rights clearance or producer
signing. The user-facing original-provider GET, mirror, redistribution, Release
and Publisher operations remain denied.

Authenticated GitHub reads of the immutable upstream 2.32.0 tag (commit
`b0474c32504c54edb44a23d33dc8a783745600cd`) found that all four
license/NOTICE source documents have the **same exact Git blob IDs** as 2.31.0:

| Tagged source file | Git blob |
| --- | --- |
| LICENSE | `6b7980745c9892ba0d79368acab331dea2246ac2` |
| LICENSE-APACHE | `f433b1a53f5b830a205fd2df78e2b34974656c7b` |
| NOTICE | `a47a53c48d921bef9023e41e8def002d45465a7d` |
| tsl/LICENSE-TIMESCALE | `e92b2d902723571c921cfe59b841e6d7ab40f30d` |

The tagged `.github/workflows/release_release.yml` Git blob
`f9cab87e5116a23f0b116690b8b3598e8c598a71` remains unchanged; it
delegates Windows build to
`timescale/release-build-scripts/.github/workflows/timescaledb-windows.yml@main`.
That mutable workflow reference is **not a pinned or source-to-ZIP signed
producer record**, and an upstream post-release Windows packaging test is not
a substitute.

`scripts/issue112_timescaledb_232_source_rights.py` checks all five source
file paths and exact blob bytes against that tag, and reuses the historical
2.31.0 rights validator and the separately verified 2.32.0 PG16–18 original
ZIP evidence. Every version and PG major is validated before any reporting.
The dedicated CI only reads GitHub source JSON; it retrieves no original ZIP,
writes no artifact, does not re-run prior successful Windows tests and cannot
authorize user download.

The original 2.32.0 ZIPs (Release 442824242) remain byte-pinned and Windows
SQL-tested under existing protected-main original Runs 43242594902 and
43248977400. Those results do **not** establish exact per-DLL license
attribution; complete bundled NOTICE/dependency resolution; legal clearance
of the original Windows setup; a genuine signed producer source-to-ZIP link;
or a new source-specific owner-signed, Environment-controlled Publisher
admission.

**Next acceptance work:** obtain a verifiable original producer build Run,
immutable toolchain and exact source/input pin, and its independently verifiable
signed binding to each ZIP SHA256; reconcile every included DLL and embedded
setup component to the corresponding license and dependencies; then seek a
new genuine owner/Publisher approval. Do not promote old 2.31.0 receipts or
the expired external 11-ZIP issuer admission for this 2.32.0 source.
