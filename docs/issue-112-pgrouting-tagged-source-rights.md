# Issue #112 — pgRouting v4.0.0 source-rights evidence (non-authorizing)

**CANDIDATE_ONLY; PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY.**

This verifies an immutable **pgRouting upstream source reference**, not the
identity, legal clearance or build provenance of the actual OSGeo Windows DLL.
The OSGeo original PG18 PostGIS + pgRouting bundle was already pinned and
tested in previous genuine CI. No original successful binary audit or Windows SQL
Run is repeated by this source-only check.

## Source identity and precise scope

Authenticated GitHub GET resolves `pgRouting/pgrouting` annotated
`v4.0.0` tag object `83985fc60ec73355cc9bd8b59080a4c42dc6ad6b`
to source commit `4f0eec583f0c9e6a82a5b3356ff300029d11ed53`.
Four source files are checked against their **original Git blob SHA-1 and bytes**:

| File | Git blob SHA-1 | Observed source information |
| --- | --- | --- |
| `LICENSE` | `d159169d1050894d3ea3b98e1c965c4058208fe1` | GPL version 2 text |
| `BOOST_LICENSE_1_0.txt` | `36b7cd93cdfbac762f5be4c6ce276df2ea6305c2` | Boost Software License 1.0 full source license |
| `README.md` | `1f563b4b009fe77c31f578b7de05fd1934163eb7` | Most features GPL-2.0-or-later; some Boost extensions under Boost terms; some iMaptools.com-contributed code claimed MIT-X |
| `CMakeLists.txt` | `b7b00200696c8045869a36d4f2fddc2c1ead9427` | Project version 4.0.0 and Boost build dependency |

These **source-level** statements are not license classification of all
linked DLL bytes. In particular, the README's iMaptools MIT-X claim is **not**
a pinned, precise per-file MIT notice or verification of its distribution in
the Windows bundle. The Boost text itself includes an object-code exception;
the exact binary/source linkage and applicability are not inferred from it.

## Separate OSGeo original candidate

Previously recorded original (not downloaded or recalculated by this audit):
`postgis-bundle-pg18-3.7.0x64.zip`, **83,320,975 bytes**, SHA256
`fa3db8060d8d376e869d961659bf4eff326c0d99a731396701af61a13dc12a40`.

The earlier original PE inventory included a member named
`libpgrouting-4.0.dll`. A matching major-version string is **not proof**
that the exact member was compiled from upstream `v4.0.0`, that it includes
or excludes specific Boost/iMaptools code, or that the in-bundle
`LICENSE`/`COPYING` files fulfill its exact notices. Source files at
this tag are reference candidates only, and the separately bundled
PostGIS component must keep its own licensing investigation.

### Exact blockers still open

- Identify the **exact original member SHA256** from existing OSGeo original
  receipts and match it to the producer's immutable source revision, build
  options, toolchain, transitive component versions and signed output digest.
- Obtain a file-specific source/rights map for the pgRouting DLL, including
  the MIT-X-contributed files (if compiled), Boost source/object-code
  applicability, required notices and any separately licensed components.
- Resolve actual Windows loader behavior, especially nonbundled dependencies,
  rather than equating static import names to runtime satisfaction.
- Require independently authentic **new source-specific owner admission** and
  genuine formal Publisher approval. A source tag, Git blob hash, existing
  ZIP pin, copyright statement, or passing CI is not that authorization.

Run `python scripts/issue112_pgrouting_tagged_source_rights.py`.
The read-only purpose-built CI uses `contents: read` only and exact upstream
GitHub GETs; no OSGeo binary, source ZIP, mirror, artifact, or Release is
downloaded or published. Offline hostile tests reject altered tag, source
revision, path, blob bytes, missing rights statements and untrusted endpoints.
The JSON result has explicit `false` fields for binary attribution,
NOTICE closure, producer signature, public GET, mirror, release and Publisher.
