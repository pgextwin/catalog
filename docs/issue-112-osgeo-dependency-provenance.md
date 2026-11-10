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
