# Issue #112 — TimescaleDB 2.31.0 Windows PE imports (PG16–18)

**CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY.**

This additive, read-only inspection addresses a distinct remaining gap after
[exact per-DLL SHA256/header receipts](issue-112-timescaledb-dll-receipts.md).
It does not replay the already successful original ZIP rehash or SQL workflows.
Only a purpose-built original provider GET per PG major is made by this new
audit, inside ephemeral CI storage, with no uploaded binary or mirrored asset.

Reused guards verify the immutable upstream Release asset identity, original
ZIP byte length and SHA256, redirect destination, ZIP member safety, CRC,
bounded decompression, and exact three DLL member size/SHA256 receipts
**before** interpreting PE ordinary and delay-load import tables. The existing
OSGeo bounded PE32+ AMD64 parser is reused, not copied. Each result is keyed
by the case-preserved ZIP member path and original SHA256. Duplicate basenames
and unexpected DLL identities fail closed. Unparseable import tables remain
explicitly `NOT_PARSED`, never silently accepted as resolved.

For each name imported but not present as one of the three DLL basenames,
the report lists the exact referencing DLL paths. Windows system and
`postgres.exe` names are **triage hints only**; all other non-bundled names
remain unresolved. This deliberately does not infer search-order resolution,
dependence on installed PostgreSQL binaries, LoadLibrary/LoadLibraryEx calls,
dynamic hook paths, target Windows files/signatures, or whether any dependency
is distributed under different terms. Even a complete parsed import inventory
is not runtime dependency closure.

Prior exact original asset pins, source/license blob receipts, per-DLL SHA256
and the upstream delegated builder provenance gap remain unchanged. Final
delivery still requires dependency closure on the exact supported Windows
targets, precise per-DLL Apache/Timescale/third-party rights and notices,
signed producer-build-to-exact-ZIP provenance, a new genuine source-specific
admission and formal Publisher authorization. Every corresponding flag in the
machine-readable report is false; **this audit grants no download, mirror,
Release or signing privilege.**
