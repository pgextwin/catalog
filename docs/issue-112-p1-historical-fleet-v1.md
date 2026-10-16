# Issue #112 — original 12-Release historical windows.yml/push P1 verifier

Protected-main, read-only, nonpublishing shared path. No special PG14 exception is copied to other PG rows.

## Fixed immutable inputs

`config/issue112-p1-historical-source-pins-20261017.json` is itself pinned by original Git Blob SHA256-independent Git object SHA-1 `c04a8c34688265cfd598fe99c399aa032321ed61` inside the verifier. It contains **12** exact repositories and original immutable packaging SHA, `windows.yml` Git Blob, `config/extension.json` Git Blob, numeric Repo/Release ID, full 40-digit official builder signer SHA, Run ID, run_attempt, source `refs/heads/release/*`, full **60** numeric PG build Job IDs and **12** original publication Job IDs. The original Run for **orafce is attempt 2**; other 11 Runs are attempt 1. The fixed signer groups are: 8 Releases `8246f4d3415a48b1ad4af13f421277057886b58f`; 3 Releases `43993b864e59bd35870e15c410ac13c85def8531`; hypopg `26be1eed57d8945e5e0a970d432074c530679b8f`.

## Actual verification path

The shared original Release audit first checks **every** numeric Asset ID, all 16 original bytes + independent SHA256 and checksum, then all ZIP CRC and SPDX/Grype structure checks. The new dedicated `distribution_p1_historical_fleet.py` receives the original path, not a mock or CI artifact. It then GETs original immutable `windows.yml` and config files at the exact original packaging commit and independently validates Git Blob IDs; matches exact workflow `push/release/*` and builder signer SHA; compares untrusted PACKAGE-INFO to the separately verified original GitHub Run/attempt/PG Job/publication Job and numeric IDs. It then verifies upstream repository/ref/version/commit against the original config and independent official upstream GitHub commit, corroborates the same commit/ref in the **actual original PG checkout Job log**, and only then calls the real pinned official `gh attestation verify`, authentic TUF root and **both** SLSA v1/SPDX 2.3 predicates. Exact X.509/OIDC, signer full SHA, workflow path, source/ref, run_attempt, signed subject and source digest remain mandatory.

An unsupported profile, changed original source commit, failed Run or PG Job, incomplete original pagination, missing historical checkout log or failed cryptographic verification is **DENY/BLOCKED**, never an accepted row. The older `pg_bigm PG14` formal bridge and its original sealed receipt are untouched. The five previously admitted `wal2json PG14–18` genuine main-Promotion rows are not recounted. The prior failure of `plpgsql_check Run 38128142145 attempt 1` remains denied.

The dedicated main-only read-only workflow runs automatically when the verifier/config changes, with `contents:read`, no user Dispatch/Re-run, Publisher, signing, Release, Tag, installation or Secret. Its diagnostic receipt artifact is never treated as a substitute for the original public Release or actual Sigstore proof. Both main and historical hostile tests execute without claiming mocked cryptography as evidence.

## Formal acceptance boundary

Previous formal record: **6/70** (pg_bigm PG14 1 + wal2json PG14–18 5). Historical source formally accepted **0/40**. The remaining **59 historical rows** are merely new **candidates for actual evaluation**, not already accepted; the other five plpgsql_check rows remain failed. Only real main-run PASS_CANDIDATE evidence can be considered for a new versioned ledger and Issue #112 admission. P1 BLOCKED, P2 NO-GO, fleetComplete=false, publicationAuthorized=false, distributionAuthorized=false and formal distribution DENY persist until separately proven.
