# Issue #112 — PostGIS PG18 immutable source-rights references (non-authorizing)

**CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY.**
This is a source-side audit of the upstream **PostGIS 3.7.0 tag**, not a
producer attestation for OSGeo's Windows **PostGIS + pgRouting** bundle, and
not a final DLL-specific license/NOTICE review.

## Exact first-party, source-only identities

Authenticated GitHub GET resolved upstream `postgis/postgis` tag
`3.7.0` to annotated tag object
`37eb1427a9fa90834c5c4fea1347d096c81549d3`, targeting commit
`1fdbb1cbb0e076816be06c401c5a5a2cf2c487f9`.
The following source files are pinned by their Git blob SHA-1; the
read-only audit independently checks both path-to-commit membership from
GitHub Contents and each Git blob byte identity.

| Tagged source file | Git blob SHA-1 | Observed role |
| --- | --- | --- |
| `LICENSE.TXT` | `403c98bb6d2c550f629a639faa63cebe14ee3111` | Source-level PostGIS and upstream dependency terms |
| `COPYING` | `d159169d1050894d3ea3b98e1c965c4058208fe1` | GPL version 2 text |
| `ci/winnie/package_postgis.sh` | `54ec34672841ee282dadfe500e79c0063cf57349` | Winnie native DLL and external-dependency copy rules |
| `ci/winnie/winnie_common.sh` | `19795c7413cd1114afa7b0864eef3cf7034dd900` | Default dependency variables, with override support |

The tagged `LICENSE.TXT` identifies PostGIS as GPL-2.0-or-later,
PROJ as X/MIT, GEOS as LGPL, LibXML as X/MIT, GDAL as X/MIT-style,
SFCGAL as GPL-v2+, and CGAL as GPL/LGPL-v3. These are **upstream
source-level descriptions** with their own exceptions and license
conditions; they do not automatically attach to an arbitrary binary by
filename. In particular, this is **not** a license determination for
the separately bundled pgRouting DLL or other bundled tools.

The tagged Winnie packaging script copies PostGIS/SFCGAL/topology/raster
DLLs as well as GEOS, GDAL, PROJ, OpenSSL and other libraries from
external build trees and PostgreSQL directories. The common script has
defaults for some dependency versions but explicitly permits overrides.
Neither the defaults nor this tagged script proves the actual OSGeo
build environment, the contents of every ZIP member, or a matching
version of every copied library.

## Original Windows archive remains independently pinned

OSGeo PG18 original:
`postgis-bundle-pg18-3.7.0x64.zip`
— **83,320,975 bytes**, SHA256
`fa3db8060d8d376e869d961659bf4eff326c0d99a731396701af61a13dc12a40`.
This pin was **not** recalculated in this review: prior genuine original
byte, DLL import and SQL tests remain valid as previously recorded.

The existing OSGeo original rights audit detected **131 distinct DLL
paths**, three license-named members, unresolved third-party imports,
and duplicate DLL basenames in GUI/non-GUI paths. Those separate actual
binary findings must be reconciled *per exact member* with the intended
source component, exact version, complete license/NOTICE conditions and
build producer before public admission. A PostGIS source-tag receipt
does not prove that the OSGeo bundle came from this source commit, nor
that the bundled third-party binaries were produced using the tagged
Winnie scripts.

## Reproducible, fail-closed check

Run `python scripts/issue112_osgeo_tagged_source_rights.py`.
The script uses authenticated, bounded, no-redirect GitHub GET for the
tag and four **source files only**, checks Git blob byte identity and
fixed source declarations, prints a DENY-only JSON receipt, and exits on
unexpected source changes. Hostile offline tests use synthetic blobs and
do not make network requests. The dedicated CI workflow has
`contents: read` only; it downloads no provider ZIP, emits no
artifacts, and cannot sign, publish or authorize direct GET.

**Remaining blockers:** exact per-DLL source/version and notice mapping
including pgRouting; resolution of external and dynamic dependency
paths; an immutable, genuine OSGeo producer Run/toolchain/source input
record signed and cryptographically bound to this **exact original ZIP
SHA256**; new source-specific owner authorization and formal Publisher
gates. Until each independent prerequisite is met, every existing
DENY flag remains unchanged.
