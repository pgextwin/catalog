# Issue #112 — OSGeo PostGIS + pgRouting PG18 live Windows DLL root origins (deny-only)

**Scope:** exact official OSGeo `postgis-bundle-pg18-3.7.0x64.zip`,
83,320,975 bytes, SHA256
`fa3db8060d8d376e869d961659bf4eff326c0d99a731396701af61a13dc12a40`.
This reuses the previously working, ephemeral EDB PostgreSQL 18 real SQL path;
it is **not** a second distributor, third-party ZIP mirror or new admission
policy. All public GET, mirror, release and Publisher permissions remain denied.

The isolated Windows test now samples the **actual target `postgres.exe`
processes** during successful PostGIS spatial SQL and pgRouting Dijkstra SQL.
One backend additionally executes both native paths before a six-second sampling
window. The read-only sampler records loaded module paths, live SHA256 and an
informational Authenticode status. It never treats an Authenticode observation
as a verified signer or owner admission.

The exact already-downloaded, independently pinned provider archive is
reopened **without a second GET** to compute SHA256 of the two original ZIP
members `lib/postgis-3.dll` and `lib/libpgrouting-4.0.dll`.
The strict join requires one observed module for each, located inside the
actual disposable EDB PG18 `lib` directory, with matching live hash.
Any missing path, wrong directory, swapped PG major, changed original
ZIP identity, conflicting receipt, duplicate module or false permission
claim fails closed. A separate offline unittest suite covers these attacks.

This check reuses the successful shared EDB installer, original provider
asset byte gate, ZIP stage, SQL assertions and preinstalled EDB `libcurl.dll`
preservation. It does **not** change the source candidate selection logic or
retroactively qualify other PG majors.

**Limits:** the sampler is a bounded set of process observations, not proof of
all dynamic `LoadLibrary` resolutions or every GUI component. A checked
matching root DLL hash does not prove license/NOTICE completion, linked
third-party dependency rights, exact producer source/toolchain provenance,
an independently signed producer attestation, current owner authorization
or formal Publisher Environment/App acceptance. EDB-provided `libcurl.dll`
must remain identified separately from OSGeo's original copy and cannot
be claimed to have inherited its rights or build lineage.

**Decision:** CANDIDATE_ONLY. `PUBLIC_GET=DENY`,
`MIRROR=DENY`, `RELEASE=DENY`, `PUBLISH=DENY`.
Do not reuse this evidence for another original bundle/version/PG major.


## Follow-up: sampled server dependency original-member reconciliation

The Windows SQL test now reopens the **same** independently pinned original
83,320,975-byte ZIP after successful PostGIS and pgRouting execution. It hashes
each direct original server-directory DLL member under `bin/` and `lib/`
(the GUI subtree is excluded), and checks all actually sampled DLL paths
directly under the disposable EDB PostgreSQL 18 `bin` and `lib` directories.

The strict offline join reports, by exact loaded path and SHA256:

- `EXACT_ORIGINAL_MEMBER_BYTE_MATCH`: sampled live file equals a corresponding
  member of the independently pinned OSGeo original archive.
- `PRESERVED_EDB_HOST_NOT_ORIGINAL`: observed PostgreSQL-host `libcurl.dll`
  equals the separately pinned pre-staging EDB copy; **this is not** OSGeo
  component provenance or OSGeo's dependency/rights acceptance.
- `UNVERIFIED_ORIGINAL_PATH_HASH_MISMATCH` or
  `PG_HOST_OR_UNMAPPED_NOT_ORIGINAL`: unresolved original/host relationship.
  Such files are never silently promoted to a verified bundled dependency.

Both root DLLs must still be observed at the exact PG18 lib paths with byte
matches. All original members that were not observed, DLLs outside the two
sampled EDB directories, GUI components and future dynamic loading remain
**unverified**. In particular, a non-root mismatch may be reported, but cannot
be converted into a PASS for full dependency closure.

The receipt rejects changed original ZIP identity, cross-PG data, path escapes,
wrong directory/basename, duplicate modules and attempts to assert public GET
or publisher permissions. The test creates no artifact and has no issuer,
private signer, mirror, public downloader or Publisher credentials.

**State remains CANDIDATE_ONLY.** Full dependency search-order and transitive
rights/NOTICE completeness, complete load coverage, producer-signed source-to-
binary provenance, current owner-signed authorization and protected Publisher
acceptance remain unresolved. All formal-publication and GET gates stay DENY.
