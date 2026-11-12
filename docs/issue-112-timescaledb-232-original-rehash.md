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

## Bound protected-main independent original evidence

The original protected-main `push` Run [43242594902](https://github.com/pgextwin/catalog/actions/runs/43242594902),
attempt 1 at exact merge HEAD `84f6aa357a4b7dcbc33af4db72986b29a9530de9`, has three successful original GET
jobs: PG16 `131266732291`, PG17 `131266732923`, PG18 `131266732862`.
The authenticated job logs independently report the exact 2.32.0 API-size
and SHA256 matches, bounded CRC-checked ZIP inventories (78 members, three
DLLs per major), and zero candidate notices by filename search.

The separate `external/timescaledb-232-original-evidence-v1.json` ledger
is validated as an all-major exact source/asset/job/run/ZIP join before any
`--pg`, `--extension`, `--version` or source filter. The latest review
accurately reports original SHA256 and size without falsely reusing the
2.31.0 receipts. The ledger is **not** a producer-signed build attestation,
independent owner signature, complete notice scan or runtime acceptance.
Publication, GET, mirror, and release are always denied; no ZIP is stored
in the repository. A later genuine Windows SQL test is separate.
