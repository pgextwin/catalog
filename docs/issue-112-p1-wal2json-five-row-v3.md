# Issue #112 — wal2json PG14–18 formal P1 intake v3 (2026-10-17 JST)

## Genuine original Release verification

The protected-main, nonpublishing GitHub Actions [Run 38979537796](https://github.com/pgextwin/catalog/actions/runs/38979537796) returned 5 PASS_CANDIDATE real Sigstore rows for wal2json PG14–18, 1 previously formally accepted historical pg_bigm PG14 row, 64 DENY, zero BLOCKED. Actual ZIP/CRC/PACKAGE-INFO/SPDX/Grype and all 224 original Release Asset SHA256 checks were run; every Release common result passed all 5 ZIP CRC and SPDX/Grype checks.

The actual official gh/TUF root, SLSA v1 and SPDX 2.3 cryptographic attestations, subject hashes, X.509/OIDC workflow/source identities, signer, packaging/upstream SHA, Run/attempt and successful PG Jobs were checked for each PG row. This is not a fixture result. Same-profile rows do not require manual one-by-one Work replay: Work個別監査不要：自動実検査済み.

Immutable diagnostic Artifact ID 12080557446 has ZIP SHA256 59e2ab4338ba0c75a3b9406b6288dd7e2b58ae777be1bb0c1899c738d59aea5d (85 JSON files). wal2json full Release common receipt SHA256 44d091a754e10049a280247bf5c1be1028e7e27286fdf82b19147ee3e5fe11f2; batch summary SHA256 1ba85e6b0ba251f7db48fdc4e4447599ca9ac47f22212afa0337bc66abafed2a. Action artifacts are diagnostic outputs, NEVER original GitHub Release bytes or self-authenticating Sigstore proof.

Original immutable wal2json Release: https://github.com/pgextwin/wal2json/releases/tag/v2.7-windows.1 ; numeric Repo ID 1412861698; Release ID 410447206; source full SHA 1198ff30137ee3fd01a9e168647a7167324bb713. Real original workflow promote.yml Run 38230537748 attempt 1, workflow_dispatch, main, success, 8 original jobs success, exact publication job 114753316427. Original official builder signer SHA 5756b3c5136a8bf4db710016cfe97555f0a71c6d, genuine official gh digest 7469124f706944133d6a169691dd1c6c3511b12e85878d255e044e2948df4c9b, TUF-root SHA 65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c.

Formal new ledger: evidence/p1/formal-acceptance-20261017-v3.json. Precisely 5 new real Sigstore rows (PG14, 15, 16, 17, 18), plus the single unchanged historically accepted pg_bigm PG14 baseline from v2. Row-level SHA256, original ZIP numeric Asset IDs and SHA, bundle hashes and build Jobs are pinned in the ledger. The v3 integrity validator is NOT a synthetic Sigstore verifier or approval. v2 is untouched.

## Authorization remains DENY

Formal P1 acceptance is now 6/70; historical source acceptance remains independently 0/40; the other 64 remain denied and unaccepted. P1 BLOCKED, P2 NO-GO, fleetComplete=false, publicationAuthorized=false, distributionAuthorized=false, formal distribution DENY. Failed plpgsql_check Run 38128142145 attempt 1 is not waived.

The 59 unsupported historical push/windows.yml rows cannot inherit the special pg_bigm PG14 bridge. Genuine original workflow, exact upstream source SHA, Run/attempt/jobs, dual cryptography, TUF and signer identity still need independent proof before any new admission. Each future acceptance requires a separate versioned record. There was no GitHub Dispatch/Re-run, Release, Tag, signing, installation, aggregate ZIP, secrets, publisher or protection change.
