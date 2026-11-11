# Issue #112 — Cybertec pg_permissions `REL_1_4` original ZIP pilot

**CANDIDATE_ONLY; public GET, mirrors, signer, Publisher and Release all DENY.**
This additive PR-only read-only test does not re-audit merged PR #304 and does
not claim the original Cybertec ZIP is the new upstream package version 1.4.1.

Upstream: `cybertec-postgresql/pg_permissions`. Original provider filename is
`pg_permissions-<PG>-public-REL_1_4-1.zip` for PG14–18 at
`https://repository.cybertec.at/windows/public/<PG>/extension/`.
The `-1` is the provider packaging revision. Upstream `REL_1_4` commit
`f622556f511231521b5e30e662a93e838c6a2b2f`; the later upstream release
`REL_1_4_1` peeled commit `3360447e0668fed2b9db6a0ae1d086533781f9bd`.
Source-only PR #304 independently established all seven SQL files, control and
LICENSE are identical Git blobs at these commits. **SQL extension
`default_version = '1.4'` is not package version 1.4.1.**

The PR-only workflow performs 5 bounded no-redirect HTTPS original ZIP GETs on
Linux CI, computes SHA256 of the actual original response bytes, verifies ZIP
CRC, member path safety and no duplicate installable filenames, and checks all
7 SQL files and control exact-byte-equivalent to pinned, independently checked
upstream `REL_1_4`. The existing source pin verifier additionally asserts all
9 source Git blob IDs (including LICENSE). Then 5 disposable EDB Windows
PostgreSQL 14–18 hosts independently obtain and inspect original ZIPs, stage
only allowlisted original ZIP SQL/control member bytes, execute CREATE
EXTENSION and SQL permission-view / target / diff behavior. Both independent
GETs print actual original SHA256 in job logs; compare the 5 per-major values
between Linux and Windows, not merely a filename or HTTP metadata.

No original ZIP is uploaded or retained as an artifact, mirrored, signed,
committed, or published. Actual dynamic results must be reviewed before any
Windows/functionality or original-byte PASS claim. ZIP manifest and any license
or NOTICE member names are observational only; even full SQL equality does not
establish all component notices, a Cybertec producer signature, source-to-ZIP
attestation, or formal source-specific authorization.

`pg_track_settings` 2.1.2 rights and Cybertec producer-provenance obligations
from PRs #303–304 remain independently unresolved; do not alter its 5
provider originals or issue a self-signed substitute as a producer receipt.

**PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY.**
