# Issue #112 — OSGeo PG18 original DLL dependencies and provenance gap

**Status: CANDIDATE_ONLY / GET_DENY / MIRROR_DENY / RELEASE_DENY.**
This is an additive read-only audit, not a direct-provider adapter or authorization.

Pinned original: https://download-cache.osgeo.org/postgis/windows/pg18/postgis-bundle-pg18-3.7.0x64.zip
SHA256: fa3db8060d8d376e869d961659bf4eff326c0d99a731396701af61a13dc12a40
Size: 83,320,975 bytes. Previous PG18 SQL and licensing-inventory runs are preserved unchanged.

Run the new PR-only CI to enumerate, for each bundled DLL, bounded PE32+ AMD64
static and delay-load imported DLL names; list imports not present inside the bundle,
ambiguous bundled DLL filenames, nonparsed binaries and three observed in-ZIP
license files. It does not overwrite PostgreSQL dependencies or distribute files.

An import not in the ZIP may be a Windows system, EDB PostgreSQL, or an unresolved
third-party dependency. **Do not treat name matching or passing SQL as proof of
dynamic LoadLibrary closure.** Resolve such imports and runtime-loaded components
against the exact Windows target independently before accepting dynamic dependency
coverage. Review all separate component licenses/NOTICE obligations, not only
the three existing in-archive files.


## Original PE import evidence triage (PR-only read-only)

[Original OSGeo DLL inventory Run 42879312471](https://github.com/pgextwin/catalog/actions/runs/42879312471)
observed 131 DLL paths; 129 PE32+ AMD64 parses; 27 distinct names not
present in the ZIP by basename. The added `unbundledImportTriage` report now
attributes each external import name to its exact referencing DLL path, and
classifies **name hints, never verified runtime resolution**:

- **23 Windows OS DLL name hints** (for example `kernel32.dll`, `ws2_32.dll`,
  `crypt32.dll`): no target Windows path, version, publisher, signature or
  actual load resolution is asserted.
- **One PostgreSQL host executable name**, `postgres.exe`: the successful
  PG18 SQL smoke demonstrates some working database paths, but does not prove
  all other imports or all DLL loads.
- **Three unresolved non-bundled components**, with exact consumers:
  - `libnghttp2-14.dll` ← `bin/libcurl.dll` (not GUI-scoped).
  - `libicuuc74.dll` ← `bin/postgisgui/libharfbuzz-icu-0.dll`.
  - `libgailutil-18.dll` ←
    `bin/postgisgui/lib/gtk-2.0/modules/libgail.dll`.

The last two importers are in `bin/postgisgui/`; this does **not** establish
that they are safe to omit, or that the entire original bundle is closed.
Two GUI-area DLLs remain unparsed in the prior PE scan:
`bin/postgisgui/lib/GNU.Gettext.dll` (non-AMD64 PE) and
`bin/postgisgui/libgtk-win32-2.0-0.dll` (PE import-name validation failed).
Additionally, 33 DLL basenames appear at multiple bundle paths; basename
presence cannot establish Windows loader search-order resolution.

The PR also adds a **finite, same-URL-only HTTP retry** for the original
nonpublishing inspector after the prior PR CI's transient OSGeo HTTP 525:
up to three attempts only for 502/503/504/525. It does not retry a 404,
an invalid redirect, an incomplete ZIP, mismatched hash, or an unsafe path.
Offline deterministic tests cover success-after-525 and strict DENY cases.
No alternative origin or softer original-byte acceptance is introduced.

**Remaining concrete acceptance work:** independently inspect the exact
target Windows + EDB PG18 loader paths and the three missing third-party
libraries (especially the non-GUI libcurl dependency); validate relevant
dynamic `LoadLibrary` paths, the GUI exceptions and license/NOTICE
obligations; then obtain actual producer provenance and independent
authorized signing. Do not replace missing DLLs, mirror the ZIP, authorize a
GET or make positive acceptance claims using these triage hints alone.
`targetWindowsImportResolutionVerified=false` remains mandatory.

First-party provenance references for follow-on manual/audited verification:
- PostGIS release/source: https://postgis.net/development/source_code/
- Windows packaging documentation: https://postgis.net/development/docs/environment/windows/
- Installer source listing: https://download-cache.osgeo.org/postgis/windows/source/pg18/
- Official packaging scripts: https://github.com/postgis/postgis/tree/master/ci/winnie

These references establish public source locations and build-process documentation,
**not a cryptographic source-to-this-ZIP build attestation**. No source revision,
toolchain identity or installer-source ZIP is to be claimed cryptographically bound
to the pinned ZIP without separate producer provenance evidence.

This new audit runs only for its own PR changes, with read-only permissions and
no uploaded ZIP/artifact. It does not rerun a successful SQL or signer workflow.


## Exact per-DLL rights and producer intake ledger (nonpublishing)

The original rights-inventory job now derives `dllComponentIntakeReceipts`
for **every DLL member path** in the original ZIP: its exact member byte size,
SHA256, and whether the member sits within `bin/postgisgui/`. Even duplicate
basenames receive distinct rows. The existing original ZIP size/hash, archive
bounds, safe-path and CRC checks remain mandatory; this ledger is *not* a
replacement for the independently authenticated original ZIP pin.

Each DLL row explicitly leaves **component identity, license/NOTICE and exact
source-to-binary provenance unverified**, while the archive-wide
`allComponentLicensesAndNoticesVerified` flag is false. The three existing
in-archive licensing files are recorded, but none may be automatically mapped
to all DLLs or asserted to satisfy an individual component's obligations.
GUI-directory classification is a **path observation only**, not a claim of
Windows loader safety or permission to drop a file. Existing tests and
public GET, mirror, signing and Publisher denials remain unchanged.

Primary-source review starting points, not exact-binary attestations:

- PostGIS licensing index (including different terms for PROJ, GEOS, GDAL,
  LibXML, SFCGAL/CGAL): https://github.com/postgis/postgis/blob/master/LICENSE.TXT
- Official Windows packaging sources and build methods:
  https://postgis.net/development/docs/environment/windows/
- Nearby OSGeo PG18 installer-source archive listing:
  https://download-cache.osgeo.org/postgis/windows/source/pg18/

**Remaining for actual acceptance:** match every separately licensed component
in the pinned DLL receipts to its *exact version*, canonical license and NOTICE
text, exact source/source-ref, binary producer and build evidence. Inspect the
actual installer source archive and verify any claimed connection to the **same
83,320,975-byte ZIP**; directory proximity, timestamps, a matching filename,
source code alone, or an MD5 listing do not supply a signed provenance link.
Keep `CANDIDATE_ONLY / GET_DENY / MIRROR_DENY / RELEASE_DENY` until the
independent legal/provenance/runtime and authentic issuer gates all pass.
