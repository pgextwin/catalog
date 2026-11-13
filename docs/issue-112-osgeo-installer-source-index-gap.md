# Issue #112 — OSGeo original bundle versus installer-source listing coverage

**NONPUBLISHING / CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY.**

The original Windows PostGIS/pgRouting SQL matrix is already complete: Catalog
PR #297, original Windows Run 42990325882 (PG14–17 4/4 SUCCESS). That successful
run is **not** retriggered by this work. The original ZIP byte sizes and SHA256
remain recorded in Issue #112 comment 6791571591. This audit only compares
public HTML **directory filenames**, not ZIP or installer-source archive bytes.

## Official source directory observations, 2026-11-11 JST

| PG major | Previously original-byte-verified PostGIS binary | Installer-source versions shown in OSGeo source directory | Matching versioned installer-source archive listed? |
| --- | --- | --- | --- |
| 14 | 3.6.1 | 3.2.2, 3.3.2, 3.5.0 | No |
| 15 | 3.6.2 | 3.3.2, 3.5.0 | No |
| 16 | 3.6.2 | 3.5.0 | No |
| 17 | 3.6.2 | 3.5.0 | No |
| 18 | 3.7.0 | 3.6.1 | No |

Exact primary-source indexes:
- https://download-cache.osgeo.org/postgis/windows/source/pg14/
- https://download-cache.osgeo.org/postgis/windows/source/pg15/
- https://download-cache.osgeo.org/postgis/windows/source/pg16/
- https://download-cache.osgeo.org/postgis/windows/source/pg17/
- https://download-cache.osgeo.org/postgis/windows/source/pg18/

The files are named *-installer-src.zip. These are installer packaging source
candidates; **they are not necessarily the entire dependency or PostGIS source
revision used to compile the final bundled DLLs**. The indexed matching-version
absence is a narrow observed **listing gap**, not proof the source was never
published or is missing from a different producer build location.

## Subsequent OSUOSL mirror filename observation, 2026-11-13 JST

The public OSGeo OSUOSL mirror directory now lists
`postgis-bundle-pg18x64-3.7.0-installer-src.zip` (displayed modification date
2026-11-08). Thus the previous **PG18 no-name-match** observation is historical:
a matching **installer-source filename** is now visible on the mirror for
the independently pinned PG18 binary 3.7.0. The PG14-17 directories still do
not list matching names for the pinned 3.6.1/3.6.2 binaries.

Mirror index (observational, not signing authority):
https://ftp2.osuosl.org/pub/osgeo/download/postgis/windows/source/pg18/

This new finding establishes **only NAME_MATCH_ONLY_NOT_PROVENANCE**.
No source-archive bytes, build input closure, Winnie job identity, binary
producer signature, dependency licenses/NOTICE or original ZIP attestations
were verified by inspecting the directory. Do not issue an owner-signed
admission, change Publisher or turn on public GET based on this name match.
The offline adversarial tests now cover the old nonmatching and newly matching
PG18 listing states while preserving every publication DENY.

## Bounded repeatable metadata audit

Run: python scripts/issue112_osgeo_installer_source_gap.py

This performs five exact-origin, no-redirect, size-bounded directory-listing GET
requests. Only the exact postgis-bundle-pgNNx64-X.Y.Z-installer-src.zip basename
is accepted as a name match; a cross-major filename is rejected. The script
never downloads the original binary, source ZIP, sidecar or executable. There
is no write, workflow dispatch, artifact upload, Catalog admission, signed
issuer, Publisher or Website path.

**Even if a matching installer-source filename subsequently appears**, the
result remains NAME_MATCH_ONLY_NOT_PROVENANCE, with false producer, license/
NOTICE, GET and Publisher gates. Names, neighboring timestamps and index
directory proximity cannot prove the original source-to-compiled-byte binding,
dependency closure, producer identity, independent signing or formal approval.

Official Winnie packaging scripts and the PostGIS licensing index are
starting points for source and component attribution, but not signed links to
these exact released Windows ZIPs:
- https://github.com/postgis/postgis/tree/master/ci/winnie
- https://github.com/postgis/postgis/blob/master/LICENSE.TXT

**Next acceptance work:** obtain an immutable original producer build job
linking input source revision, toolchain/dependency versions and exact output
hash for each PG major; map every bundled DLL to its component/version and
complete canonical licenses/NOTICE; independently verify loader closure and
authentic source-specific issuer/Publisher before enabling public GET.
