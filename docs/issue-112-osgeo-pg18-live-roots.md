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
