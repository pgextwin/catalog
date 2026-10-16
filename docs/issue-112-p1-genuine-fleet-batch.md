# Issue #112 — Genuine read-only fleet P1 batch v1

This protected-main batch is NOT a new Release, permission to publish, or formal fleet acceptance. Sealed pg_bigm PG14 remains formally admitted **1/70**; historical source remains **0/40**. P1 BLOCKED, P2 NO-GO, fleetComplete=false, publicationAuthorized=false and distributionAuthorized=false. All original archives, receipts and Issue statements remain intact. plpgsql_check Run 38128142145 attempt 1 failure is never waived.

## Input and trust

Candidate policy: config/issue112-p1-fleet-pins-20261017.json. Exact Catalog snapshot e372e2c6a95adcf8227ea82d6253df3792b6f029. It fixes all 14 public repositories and their 224 Asset numeric IDs, SHA256 of Catalog index and 14 records, 14 Release IDs, five PG majors (14–18), original trusted signer full SHA, and pg_bigm PG14 Work-proven official gh executable/TUF-root SHA256. The runner's unverified installed gh digest or a changed TUF root never silently becomes trusted: the impacted cryptographic rows stay BLOCKED until reviewed pinned policy amendment.

The engine reuses existing immutable Catalog/Release checks, entire Release real-byte rehash + checksum, ZIP member and CRC validation, SPDX/Grype/PACKAGE-INFO checks, per-PG immutable source and packaging identity, original workflow Run/attempt, successful PG build and formal publish jobs, and separately executes real gh Sigstore SLSA v1 and SPDX 2.3 verification using a freshly validated TUF root. Historical PG14's exceptional bridge is not reused for other rows. Unsupported or unproven profile is DENY. The saved SHA256-addressed original bytes are always independently rehashed; no cached receipt can become a new signature result. A missing gh/TUF trust bootstrap may leave common original-byte checks running but cannot produce cryptographic PASS.

Execution:
    python scripts/distribution_p1_batch.py --policy config/issue112-p1-fleet-pins-20261017.json --cache PRIVATE-OBJECT-CACHE --output PRIVATE-RECEIPTS

Output is one common original-Release receipt per successful Release, one row receipt per PG, and summary.json, all NONPUBLISHING. PASS_CANDIDATE means true live row verification in that run, not formal admission. Previously admitted PG14 is recorded ALREADY_ACCEPTED once only; its genuine sealed original is not replaced with synthetic tests. All failing rows record BLOCKED or DENY separately and independent rows continue.

## Protected GitHub Actions

The dedicated workflow runs on relevant protected main pushes and weekly Sundays 00:00 UTC (=09:00 JST). No manual Dispatch, no Publisher permissions, no write permission, no Secret, no new signatures, no Release/Tag or installation. It uploads 14-day diagnostic receipts, not downloaded Release originals. Failure is nonzero, never falsely accepted. PR-required validate continues to run the offline hostile tests.

## Remaining gates

This first engineering slice does not add 69 rows or historical source 40. To accept any new row, inspect a real main-run receipt and original release identities, resolve an actual unsupported historical profile only on its own fully proven original evidence, and add a new versioned idempotent formal P1/source ledger + Issue #112 record. An Actions Artifact or mocked unittest alone never counts. #75 GO A/GO B/G4/G5 remain NO-GO. Future per-PG offline ZIP creation belongs exclusively to a local CLI; existing individual Release/Website downloads are unchanged.
