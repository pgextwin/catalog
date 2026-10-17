# Issue #112 — original orafce cross-attempt formal v5 (65/70)

Formal v5 appends **only** orafce PG14–17 to sealed formal v4 (61/70).
Old v2/v3/v4 ledgers and their immutable Git Blobs are unchanged.
No overlap with pre-existing 61; 5 plpgsql_check rows remain DENY.

## Actual protected-main audit (never simulated)
- [Read-only original-byte/Sigstore audit 38993139365](https://github.com/pgextwin/catalog/actions/runs/38993139365), verifier protected main `92d711c5c9d45b3cb39d6fa5b6de9742197cbae8`.
- Actions Run **failure** and actual P1 batch exit **2** are preserved: 5 original plpgsql_check rows DENY. Artifact ID **12085967964**, downloaded diagnostic ZIP SHA256 `bb05e70aa7aab687be4f562aa6a867a7f5cc6d1d3f26ad7f57ded1abc505cbce`.
- ZIP **85/85 diagnostic JSON CRC**, SHA256(summary.json) `8ce904315db8ed8a16d9ea1cc56fddf3c8a05e652ff6be3b67ee47fa24698b1f`. 14/14 original Release receipts separately report **224/224 original Asset bytes rehashed**, 70 ZIP CRC and SPDX/Grype structure verified. These verified receipts are not substitutes for the original Release assets.
- Row classifications at this run: **ALREADY_ACCEPTED 6**, **PASS_CANDIDATE 59** (55 previous v4, **4 new orafce**), **DENY 5**, BLOCKED 0. All new four row receipts independently SHA256-fixed inside v5; their original released ZIP hashes agree with live numeric GitHub Release ID `409043426`.
- Original orafce Run `38062983035` **attempt 1 FAILED** because PG18 failed. PG14–17 individual build Jobs succeeded, and each emitted real SLSA v1 and SPDX2.3 attestations; original Build jobs `114244899868 / 114244899833 / 114244899844 / 114244899848`. Original upload Artifact digests equal the independently archived Publish download Artifact digests, and the published ZIP SHA256 equals the signed original ZIP SHA256 for every row.
- **attempt 2 SUCCESS**, original Publish Job `114251123808` SUCCESS. No attempt-1 Run-wide success waiver, no PG18-attempt-2 signature replay.
- Original pinned source `e538f81acccf73bd9c40977e22e8c4984e452622`; packaging SHA `9f10b9039abe8c909df1ed17133481f4d64da1e4`; signer `43993b864e59bd35870e15c410ac13c85def8531`. Protected-main official gh 2.102.0 SHA `7469124f706944133d6a169691dd1c6c3511b12e85878d255e044e2948df4c9b` and TUF root `65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c`; original X.509/OIDC, source, Run attempt, signer and both signed predicates verified per new PG row.
- `distribution_p1_formal_ledger_v5.py` is strictly **record integrity checker**, never a fixture or substitute for genuine Sigstore. Hostile tests reject replay, swapped bytes, attempts, omitted rows, previous-ledger tampering and all gates' unsafe changes.

## Formal decision
**65/70** formally admitted after verified v5 checker/required CI and safe protected merge. Source independent accepted **0/40**. **P1 BLOCKED / P2 NO-GO / publicationAuthorized=false / distributionAuthorized=false / fleetComplete=false / distribution DENY**. Issue #75 GO A/B/G4/G5 all NO-GO. No Release, tag, new signature, workflow dispatch/rerun, install or public bundle.
