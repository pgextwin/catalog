# Issue #112 — TimescaleDB 2.32.0 official ZIP independent original-byte pilot

**PRIVATE AUDIT ONLY / CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY.**

New official stable Release 2.32.0 (2026-11-12) contains three observed PG16/17/18
Windows ZIPs, tracked by protected Catalog PR #356 as **untrusted API-only**
metadata. The previous exact 2.31.0 original byte and rights ledger is retained.

This scoped job uses the existing common `checked_url`, `OnlyOfficialRedirects`,
`copy_checked_bytes` and `inspect_zip` functions. Its source pin comes from
`make_plan(source="timescaledb", extension="timescaledb", version="2.32.0")`,
which independently validates the frozen exact new GitHub Release and asset
IDs/digests as well as the unchanged historical rights ledger. It never
borrows 2.31.0 original hashes or trusts the old Release merely because it
has compatible asset filenames.

PR and protected-main original `pull_request`/`push` jobs, each with
read-only contents permissions, GET only the official 2.32.0 original ZIP
from its pinned HTTPS Release URL; reject redirects outside GitHub's approved
asset hosts, a wrong size/hash, unsafe ZIP members, zip-bomb bounds, traversal
paths, duplicate names and CRC failures. The exactly checked original bytes
are held under a disposable runner temp directory, then removed; there is no
artifact upload, mirror, installer execution, signature mint, manual fake event
or Publisher credential.

The output receipt is an independently rehashed **byte-integrity and ZIP-safety**
audit only. It explicitly denies rights/NOTICE closure, producer-signed
source-to-binary attestation, Windows runtime acceptance, independent
signed admission, user-facing GET, redistribution, Release and Publisher.
Only a separate authentic owner-signed/Environment-controlled Publisher and
signed Catalog admission can authorize future public delivery. The older
2.31.0 independent audits are not manually re-run by this workflow.
