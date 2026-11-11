# Issue #112 — OSGeo Winnie version.txt receipt, no public admission

**NONPUBLISHING: CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY /
RELEASE_DENY.** This is an offline component-version *lead*, not a signed
producer/source attestation or an authorization change.

## Why inspect version.txt?

The official PostGIS packaging script
[ci/winnie/package_postgis.sh](https://github.com/postgis/postgis/blob/master/ci/winnie/package_postgis.sh)
writes a version.txt path under the packaged release directory (near its
RELDIR/RELVERDIR setup) and appends GEOS, GDAL, PROJ, libiconv, and optional
CGAL/Boost/SFCGAL version strings. The companion
[ci/winnie/winnie_common.sh](https://github.com/postgis/postgis/blob/master/ci/winnie/winnie_common.sh)
defines packaging environment defaults. These files describe the current
packaging recipe; **they do not establish which specific code revision or
toolchain built a historical released ZIP**, nor do arbitrary text values
establish a license or NOTICE for any particular binary.

OSGeo official installer-source directory filenames are **5/5 version mismatched**
against the known tested Windows bundle ZIPs (Catalog PR #298). A
version.txt *inside the independently rehashed ZIP*, if present, would be
better evidence of the archive's self-reported packaging versions than a
neighboring source directory listing. But it still is not a provenance
statement bound by the original producer's signature.

## Offline command (already held original bytes only)

    python scripts/issue112_osgeo_winnie_version_receipt.py --pg 18 --zip PATH_TO_ORIGINAL_ZIP

Use --pg 14, 15, 16, 17 or 18 for the matching existing local original.
There is **no network download**. For each major, the script checks the
full original byte count and SHA256 previously observed in Issue #112
comment 6791571591 and the existing PG18 independent byte audit; then
reuses the bounded ZIP-member, symlink, AMD64 and CRC inspector. The
expected single in-ZIP path is strictly derived from its pinned major and
PostGIS bundle version. The version file is read in memory with a 64 KiB cap
and its own SHA256, returning only syntactically bounded component version
*claims*. An absent exact member is reported as a gap, not treated as
positive evidence. It does not extract, install, execute or upload content.

As a separate step, compare each claim with the independently obtained
exact-DLL receipts in scripts/issue112_osgeo_rights_audit.py and the
existing dependency inventory. **The script does not perform or assert
that attribution automatically.** Different DLL paths, repeated basenames
and GUI subcomponents may have different licensing requirements. The
official PostGIS source/NOTICE material must still be connected to the
exact binaries and their producer release.

## Acceptance boundary

- No source revision, compiler/toolchain, Windows producer job or signed
  exact-output provenance has been authenticated by version.txt.
- No per-component DLL identity, complete canonical license/NOTICE,
  dynamic loader dependency, or independent signed source-specific
  admission has been established by this offline text audit.
- The tool never changes existing Catalog or CLI public selections,
  public download allowlists, issuer/publisher policy, Release, Website or
  provider original bytes; all authority flags remain false.
- Existing successful OSGeo real-Windows Run 42990325882 **must not be
  rerun** for this inspection. The new unit tests are deterministic and
  network-free.

Next: examine the real exact-pinned archive version.txt results, trace
each version claim to actual DLL provenance, canonical licenses and
producer-attested immutable build inputs/outputs, or record missing
version.txt as a proven gap. Inspect independent eligible latest Windows
providers separately; do not convert metadata into public GET permission.
