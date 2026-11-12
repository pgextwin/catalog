# Issue #112 — TimescaleDB 2.31.0 exact DLL member receipts (PG16–18)

**CANDIDATE_ONLY / NONPUBLISHING / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY.**

The earlier successful original-byte Run 43116446694 already established
the three published ZIP hashes, safe archive member counts, and an observed
count of **three DLL members for each PG16/17/18 original**. Do not rerun it.
The SQL acceptance Run 43119688374 is also complete and is not replayed.

This separate, purpose-built read-only audit adds evidence that was not in
that successful ZIP-level result: **the exact case-preserved path, size,
SHA256 and bounded AMD64 PE32+ header observation for each DLL member**.
The output preserves duplicate basenames by path, and all three original
provider downloads are bound to the existing exact immutable Release asset
size/SHA256 pins before DLL bytes are consumed. Archive path, duplicate,
CRC, decompression and redirect defenses reuse the prior audited helpers.
All working bytes are ephemeral; no ZIP/DLL artifact is uploaded or mirrored.

The three receipt rows are **not** an attribution of Apache versus Timescale
License source scope. PE headers and filename patterns cannot identify which
source was linked into a DLL, whether the upstream binary was modified, the
compiler or link inputs, transitive dependencies, or notice completeness.
In particular the prior original inventory found zero matching
LICENSE/NOTICE/COPYING filenames; that observation remains filename-only.
All component source, license, notice, runtime and producer-identity fields
are explicitly UNVERIFIED. A passed workflow is **never a signed admission**.

New genuine PR CI and main-push CI, each with read-only credentials, run the
component-intake auditor for PG16/17/18. The older success Run is not retried.
Audit records can be compared with the already pinned tag 2.31.0 source
LICENSE, LICENSE-APACHE, NOTICE and tsl/LICENSE-TIMESCALE Git blob SHA rows
in `external/timescaledb-rights-provenance-intake-v1.json`.
The delegated release builder
`timescale/release-build-scripts/.github/workflows/timescaledb-windows.yml@main`
is still not immutably bound to these producer assets.

**Remaining before any formal delivery:** exact per-DLL source/license/NOTICE
mapping, dependencies and installer notices; independently signed
producer-Run-to-all-three-exact-output-SHA256 attestation; fresh authentic
source-specific owner admission, approved Publisher and end-user original-byte
acceptance. No current feed, CLI, signed issuer, Release or Website policy
is modified.
