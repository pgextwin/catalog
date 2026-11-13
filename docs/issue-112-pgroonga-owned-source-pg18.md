# Issue #112 — PGroonga 4.1.0 source-pinned pgextwin-owned PG18 pilot

**PRIVATE CANDIDATE; PUBLIC_GET/MIRROR/RELEASE/PUBLISH DENY.** This produces NEW first-party Windows bytes, never the historical official PGroonga 4.1.0 ZIPs. The official historical Windows run consumed mutable groonga-latest.zip without recording its digest; this new builder does not retroactively prove those bytes.

## Fixed inputs

- PGroonga source: pgroonga/pgroonga commit 47d0252f76dccbdc2ebeee9ed6cf941dd9552bcc (exact checkout, unsigned upstream tag).
- Groonga source ZIP: official v16.1.3 release, groonga-16.1.3.zip, **136,286,598 bytes**, SHA256 **ad892560511e5886dea2373101f0780e0a16394d30e5a20a8d3df12d7ef9e85d**.
- Exact detached source .zip.asc: 833 bytes; SHA256 **edc58ee987bf8ef92436a7c11373ddb382af4063d59aac8bd2c4943f65223848**. On Linux, isolate and verify only Groonga's official key fingerprint **2701F317CFCCCB975CADE9C2624CF77434839225**, separately from SHA checks.
- Groonga v16.1.3 annotated tag resolves to commit **9085dd417e5cd42cd8f1a367aaf24cfe45dd9f1f**. This is candidate source-rights context, NOT proof that the signed source ZIP equals the Git tree or the historical mutable ZIP.
- Reuse pgextwin/build protected HEAD **1906c7203d5b0c98cf1da705d4a70d496ad930e9** tested Windows PostgreSQL install helper with PG18 18.6.5; adapt the upstream PGroonga CMake/Meson recipe. The runner image, MSVC/Meson and vendored inputs have not been fully attested.

The new read-only PR workflow runs adversarial offline source gates, verifies original Groonga source ZIP + detached GPG signature, creates a disposable source-owned Groonga/PGroonga Windows build under RUNNER_TEMP for PG18, and executes real CREATE EXTENSION, version/index and indexed search SQL. It neither uploads a ZIP nor invokes an issuer or Publisher. The input gate rejects altered hashes, unexpected length/name, symlinks, ZIP path traversal, missing CMake source, duplicate names, unbounded expansion and wrong PGroonga Git commit.

A passing Windows SQL job proves only that **one new source-owned PG18 build functions**. It is not a reproduction of the historical 4.1.0 provider ZIP. PG14–17 require independent builds and runtime tests. License and NOTICE completeness (MRuby, Ruby-derived file-stat, xxHash etc.), exact dependency and toolchain closure, signed first-party provenance, owner-specific authorization, independent Sigstore and publication remain explicit DENY gates. No successful job can promote those fields by implication.

## Independent nonpublishing candidates

- OSGeo PostGIS/pgRouting PG18 single physical bundle: 83,320,975 bytes, SHA256 fa3db8060d8d376e869d961659bf4eff326c0d99a731396701af61a13dc12a40. Component rights, runtime imports and signed original provenance remain unclosed.
- TimescaleDB 2.32.0 PG16–18: original ZIPs are pinned and functional evidence exists; delegated mutable Windows producer and third-party NOTICE remain blocked.

Existing public CLI v0.3.15 11 original-provider ZIPs and their expiry (2026-11-13 16:03:30 JST) are untouched. The already completed --latest-per-pg, --single-bundle and explicit-version selection logic is reused rather than reimplemented.

**Never use this pilot as a workflow_dispatch owner event, signed approval or public GET permission.**
