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

## Real protected-main measurement and strictly scoped follow-up

First real batch: [Run 38977438979](https://github.com/pgextwin/catalog/actions/runs/38977438979), exact main fca5900e41d1727d3a03f63e4eead90cf58db372, exit 2 by intentional incomplete-fleet guard; attached 74-file diagnostic receipt Artifact ID 12079861029 with ZIP SHA256 634d1042284d04c59f90e12a2b020944b849ee04e17210ee57a86eaffd742617. The snapshot contains 70 row receipts: already formally accepted 1 (pg_bigm PG14), 55 BLOCKED, 14 DENY, 0 new cryptographic PASS. Never count CI Artifact as an original Release proof.

Initial common Release verification: pg_bigm, plpgsql_check, wal2json all 16/16 Asset SHA256 checks passed, but 11 Releases stopped after their asset rehash because ordinary checksum filename parser rejected original literal ./basename. The new runner version preserves the existing strict ordinary P1 parser, adds a bounded original-byte-only checksum-transport parser for fully original-numeric-pinned Releases, rejects mixed/aliased/duplicate/traversal lines and still independently rehashes all 16 original Assets and 15 checksums. This changes NO promotion, signer, trusted root or Sigstore condition. The previous pg_bigm PG14 exceptional profile remains exactly pinned and is never generalized.

First-run row-denials remain binding until verified: pg_bigm PG15–18 upstream ref/version/full SHA mismatch (4 DENY), plpgsql_check and wal2json unapproved signer SHA (5 + 5 DENY). New diagnostics may record observed untrusted PACKAGE-INFO signer/run fields but do not add them to the trusted allowlist. The historical plpgsql_check failed Run 38128142145 attempt 1 remains DENY. No automatic Formal P1/source admission follows from this syntax fix.

Formal baseline is independently preserved in evidence/p1/formal-acceptance-20261017-v2.json; the read-only verifier deliberately rejects all synthetic new admissions or publication flag changes until a separate genuine main-run receipt and verifiable official evidence are available. Old Work receipts/ledgers remain unmodified.

## Full-Release structural verification and evidence-only profile classification

Run 38978154548 established 14/14 whole-Release original 16-Asset SHA256 and checksum equivalence, but no new genuine Sigstore PASS. Exact 70 rows: 1 ALREADY_ACCEPTED, 69 DENY, 0 BLOCKED, 0 PASS_CANDIDATE. Its 85-file receipt Artifact ID 12080325191 has outer SHA256 66c71fd0752f77738dd8989f62de1b7cf2aac91a0fec60d071774ae4c09e4709. This is a CI diagnostic artifact, never source material for the Release originals. The earlier 14/14 check did not independently inspect all ZIP member CRC/SPDX/Grype structures.

The subsequent common inspection now reads each original Asset ZIP without extracting, applies existing zip-slip/link/duplicate/collision/bomb constraints, streams and checks CRC for every member, strictly parses sole PACKAGE-INFO, SPDX 2.3 and Grype report, checks PG major/platform/arch and stores observed original workflow Run/event/ref/upstream full SHA/signer. It also GETs the actual numeric GitHub Run metadata; its candidate grouping is UNVERIFIED observation, not an authorization. Only normal main/promote/workflow_dispatch with original signed source/run/jobs and both exact verified SLSA/SPDX predicates can qualify after separate row gates. The historically accepted pg_bigm PG14 is a fixed exception limited to its own original ID; the other 69 rows never inherit its profile.

Observed profile candidates are labeled EXACT_PG14_ALREADY_ACCEPTED, CANDIDATE_MAIN_PROMOTION_UNVERIFIED or UNSUPPORTED_OR_FAILED_PROFILE_DENY. Even a candidate main profile is not a Signature Verified verdict; invalid failed Run stays DENY. If any original ZIP CRC or SPDX/Grype structure fails, the entire affected common Release fails and its PG rows are blocked instead of claiming common PASS.

## Exact later main Promotion job/signer observations: wal2json only

After genuine 14/14 Release ZIP/CRC/SPDX/Grype main-run 38978875227, 59 unadmitted historical push/windows.yml PG rows, five failed plpgsql_check Promotion rows and five wal2json successful main Promotion candidate rows remain. Original wal2json Promotion Run 38230537748 attempt 1, immutable source 1198ff30137ee3fd01a9e168647a7167324bb713: actual GitHub path .github/workflows/promote.yml, event workflow_dispatch, head main, exact 8/8 original Jobs successful including individual PG14–18 and publisher job ID 114753316427, exact name "Check signatures, exact SHA256 and create-only Release ID". The prior v1 runner only recognized an older exact literal publisher Job name. The v3 runner now recognizes both precisely demonstrated names, still requires exactly one successful publisher plus the exact PG build Job, and leaves all nonmatching, failed, skipped, ambiguous original Runs DENY.

Builder signer 5756b3c5136a8bf4db710016cfe97555f0a71c6d is a real pgextwin/build commit and protected main ancestor; wal2json Promotion workflow at full source SHA references exactly that reusable workflow commit. Original immutable promoting workflow Git Blob 6a3ea8404ef944a02769c0e4d9010f8e0acc8a9f and build reusable workflow Blob 93a0a7641253735cf5adb845c768981c79f75b46 were independently fetched. Candidate policy now explicitly allows this SHA beside 8246f4d3415a48b1ad4af13f421277057886b58f but DOES NOT infer any signature from an unsigned field. Official authenticated TUF root, per-PG genuine gh Sigstore verification of SLSA v1 and SPDX 2.3, X.509/OIDC/repo ID/subject/full-SHA/run_attempt remain hard mandatory gates. The known failed plpgsql_check Run 38128142145 attempt 1 remains DENY.
