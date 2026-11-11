# Issue #112: canonical original Winnie receipt, nonpublishing

This single-purpose, PR-only pilot is **CANDIDATE_ONLY / PUBLIC_GET_DENY /
MIRROR_DENY / RELEASE_DENY**. It does not rerun the already-successful
PostGIS/pgRouting SQL matrix or signing and Publisher jobs.

For PG14–18 the read-only Linux job downloads exactly the previously
independently rehashed OSGeo original binary ZIP from
`https://download-cache.osgeo.org/postgis/windows/pgNN/` to an ephemeral
temporary file. Redirects, mirrors, alternate filenames, and fallback originals
are prohibited. It must match both the immutable prior byte length and full
SHA256 before the already-reviewed offline `version.txt` inspector executes.
The inspector validates safe ZIP paths, CRC and PE AMD64 presence and then
reports either the exact inner member's SHA256/byte length and self-reported
component versions, or an explicit missing-member observation. Archive bytes
are immediately deleted; no ZIP/source asset is uploaded or redistributed.

New tests reject unknown major, wrong original byte hash/length, unexpected
positive/missing admission gates, misleading `PUBLIC_COMPLETE` state, and
redirect-enabled default transport. The workflow has only `contents: read`,
no artifact upload, `workflow_dispatch`, owner/signer/Publisher privileges,
Release, Catalog admission, or public CLI modifications.

**Interpretation:** version.txt is self-reported metadata, not an authenticated
producer build, source-to-exact-DLL relationship, complete component legal
notices, or actual dynamic-load closure. Even five successful runs cannot
clear these outstanding conditions or authorize user downloads. A failed GET
or missing file must not be counted as successful version evidence.

Independently investigate exact installer-source indexes, including whether
`postgis-bundle-pg18x64-3.7.0-installer-src.zip` has appeared on the canonical
OSGeo origin. A separately observed OSGeo mirror listing is only a clue and
must not be substituted for the canonical origin or a signed build attestation.
