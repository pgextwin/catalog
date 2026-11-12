# Issue #112 — PGroonga 4.1.0 exact Windows/EDB liblz4.dll loader observation

**CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY.** Read-only, nonpublishing follow-up to Catalog PR #279: exact PGroonga original `bin/libgroonga.dll` imports `liblz4.dll`, which is absent from the official 4.1.0 ZIP. Previous real Windows indexed SQL success did not establish the effective loader path.

A separate path-triggered CI runs against PostgreSQL 14–18 on disposable Windows runners. It installs only the previously pinned EDB PG versions using the immutable Build installer at `07449a2384ae4e2fc01820e263ed4bc45cd73abf`; observes the installed EDB `PGROOT/bin/liblz4.dll` file version, company, Authenticode **status**, and SHA256 before touching the upstream ZIP. The signed upstream PGroonga release ZIP is independently pinned by exact size/SHA256. Constrained extraction never overwrites EDB files; the extracted original `pgroonga.dll` is loaded inside a living `postgres.exe` session.

A positive observation requires the exact `PGROOT/lib/pgroonga.dll`, `PGROOT/bin/libgroonga.dll`, and `PGROOT/bin/liblz4.dll` paths **all loaded by one backend PID**, with the host LZ4 hash unchanged. Basename guesses, a binary elsewhere in PATH, modules in different PIDs, absent EDB binaries, changed hashes and inaccessible module lists fail closed. There is a separate offline hostile test for mistaken paths/PIDs, plus exact-PG-major byte and read-only workflow contract tests.

This evidence is narrower than complete dynamic dependency closure: it does **not** verify all Groonga plugin load paths or 43 binaries, per-binary NOTICE/license requirements, exact producer/source-to-binary attestation, LZ4 source package provenance or independent signing authorization. FileVersion, CompanyName and Authenticode status are observations, not proof of vendor or signature. A positive PG14–18 run must not be promoted to complete provider GET authorization.

No issuer, token, Environment, catalog public pin, ZIP upload, mirror, download, release or Website changes; no successful original SQL/rights jobs re-run merely to create duplicate receipts. The separately blocked OSGeo bundles and existing public CLI v0.3.13 scope remain unchanged.


## Exact original-member to live Windows DLL sample (2026-11-13)

On new, path-scoped PR/push runs the existing five-major disposable EDB Windows
test has an opt-in AuditModuleOrigins switch. The verifier SHA256-hashes all
original DLL members in bin and lib, including plugin DLLs, directly from each
pinned official release ZIP. In the existing LOAD pgroonga plus pg_sleep probe,
it examines actual PostgreSQL backend module paths, obtains independent
on-disk hashes, and classifies exact original matches, preserved EDB host LZ4,
different-byte host collisions, and unmapped PGROOT DLLs separately. It requires
the loaded pgroonga.dll and libgroonga.dll to match original member SHA256s;
the loaded preexisting EDB liblz4.dll must match its pre-staging hash. The
hostile offline tests reject root tampering, host tampering, duplicate modules,
missing host DLL and forged outside-root module paths.

Only DLLs loaded at that observation moment are in scope. Missing optional
modules, all other Windows DLL origins, binary-specific third-party licensing
and NOTICE, mutable historical Groonga source input, signed producer lineage,
and owner/Environment/Publisher approvals remain unverified. This observation
is DENY-only and neither redistributes the original ZIP nor changes the
public CLI, catalog feed, Release, or GET admission.
