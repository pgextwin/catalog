# Issue #112 — TimescaleDB 2.31.0 PG16–18 actual Windows loaded-module observations

**CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY.**

This independent, additive Windows CI observation fills a narrower gap left by
the exact original ZIP receipts, parsed PE ordinary/delay-import tables and
already completed PostgreSQL real SQL tests. It does not authorize distribution.

For each PG major, the workflow reuses the exact immutable pgextwin EDB
PostgreSQL installer, the existing original upstream Windows SQL script and
the reviewed TimescaleDB per-DLL import auditor. The immutable original Release
ZIP identity/size/SHA256 and member receipts must match **before** the new
module-provenance sampling begins. During the existing true PostgreSQL SQL test,
a separate read-only Windows process sampler matches the actual PostgreSQL
executable path and collects loaded module file paths. It then hashes observed
import-name providers and original TimescaleDB DLLs, and records Windows local
Authenticode **status** as an observation only, not as producer proof.
The Python join requires a matched PostgreSQL process and at least one exact
original TimescaleDB DLL SHA256 among observed loaded paths. Hostile offline
tests reject forged/missing imports, digest mismatches, duplicate/conflicting
module receipts and wrong-PG attribution. The Python report labels each
nonbundled static import as observed or not observed in the *sampled* processes.

Important limitations: a DLL absent in process enumeration may be API-set
forwarded, delay-loaded, loaded into a different process, or loaded and unloaded
between samples; its absence is not proof of incompatibility. A DLL file path,
SHA256, or local Authenticode status does not prove the Windows loader used that
file for every code path, correct resolution across supported installations,
license/NOTICE completeness, independent signed upstream build provenance, or
permission to redistribute or provide public GET links. An observed
\`postgres.exe\` host path is not a resolved DLL import proof. The standalone
upstream delegated builder source remains unavailable to this audit.

Every run uses disposable GitHub-hosted Windows CI, read-only GitHub checkout,
the exact pinned original provider bytes and no artifact uploads. The previous
successful SQL workflow is **not rerun as the same Actions Run**; its reviewed
script is reused inside a new job to obtain a fresh simultaneous live process
observation. All rights, source-specific owner admission, producer attestation,
and formal Publisher gates remain independent and **DENY**. Nothing changes
the CLI, catalog signed feed, issuer, publisher, Website, mirror, or Releases.
