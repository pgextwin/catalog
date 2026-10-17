# Issue #112 — Formal P1 61/70 (v4, 2026-10-17 JST)

## What was actually verified

Catalog protected-main, read-only [genuine Run 38984927984](https://github.com/pgextwin/catalog/actions/runs/38984927984) at immutable verifier commit `2330d9027f33c7ab3317e382539725feda285a1e` completed all **14 original public Release** shared receipts, each 16/16 actual bytes, checksum, five PG ZIP CRC, SPDX 2.3 and Grype checks. It also ran the real official pinned gh 2.102.0 with independently authenticated TUF trusted root and **both SLSA v1 and SPDX 2.3 per-PG Sigstore predicate** checks against the original signed ZIP, X.509/OIDC identities, original signed subjects, packaging/source full SHAs, original workflow/config Git blobs, exact source refs, immutable upstream full commits and original Run/attempt/PG build/publish jobs. Shared original checkout Job logs are SHA-pinned 60 full texts in the protected Git tree, with exact original Git blob archive hashes.

The actual original audit diagnostic Artifact ID is `12082613192`, SHA256 `071cf1c7d41338382546ba61ad6cbc63ac58af4285dcf7bad2fcebc044bb897c`, 85 JSON files and valid ZIP CRC; summary.json SHA256 `4025b7c773e194b42f4b3b65fb8b2d0ebf5c54810c8b7abbb1707c5e57fe0abe`. These are **diagnostic receipts only**, **never a substitute for the original public Release bytes or Sigstore bundles**.

The independent inspection of all 70 original row receipts reported **6 ALREADY_ACCEPTED, 55 genuine PASS_CANDIDATE, 9 DENY, 0 BLOCKED**. The complete 55 candidate rows' immutable original receipt identities (numeric Repo/Release/ZIP Asset ID, exact per-PG successful build and publishing Job ID, source full SHA, signer full SHA, run/attempt, signed bundle evidence in individually hashed original JSON) were reconstructed independently from the downloaded actual diagnostic Artifact and matched to `formal-acceptance-20261017-v4.json`. The canonical identities' additional independently computed Git Blob hash is `32187dc5badf0bd471e9936cc6a1d3f66a6d5db6`.

## Formal counting

The original sealed `pg_bigm PG14` formal admission (v2) and five previously genuine signed `wal2json PG14–18` formal admissions (v3) remain unchanged and counted only **once**: 6/70. The **55 new** original historic successful rows are added in **a separate versioned v4 admission ledger**. **Formal P1 becomes 61/70**, remaining **9 DENY**.

Four denied rows are `orafce PG14–17`: they were built in original Run attempt 1 but final publication was attempt 2. The exact attempt transition is still **not** an authenticated allowed profile; preserve DENY, even though their original build Jobs were successful. The other five denied rows are `plpgsql_check PG14–18`: failed Promotion Run `38128142145` attempt 1 remains **unwaived**.

The separate formal historical **source ledger remains 0/40** until its *independent* acceptance gates are complete. Fleet P1 **BLOCKED**, P2 **NO-GO**, Issue #75 GO A/GO B/G4/G5 **NO-GO**, publicationAuthorized=false, distributionAuthorized=false, fleetComplete=false, formal distribution **DENY**. Formal receipt acceptance is **not** release/publishing authorization. No direct bulk ZIP distribution. Current individual historical Release bytes and Website links remain unchanged; future offline aggregate ZIP is created locally by the CLI.

## Security gates and Work-free operation

`scripts/distribution_p1_formal_ledger_v4.py` is an *immutable ledger integrity checker*, not a synthetic cryptographic verifier. It pins exact original v3 and history source Git Blobs and the new v4 Blob hash, 55 independently reconstructed row SHA256 identities, protected original main Run, official gh/TUF digests, exact 12 historical repo/source/Run/signer/PG jobs, and the 9 immutable denied rows. All hostile CI tests reject forged signatures, changed Asset/Run/attempt/source/PG identity, replayed prior rows, or unauthorized publication and source acceptance.

All 55 same-profile rows were processed automatically by trusted main, not replayed manually in Work one by one: **Work個別監査不要：自動実検査済み**. No new permission, Secret, token privilege, Publisher, Tag, Release, signing, attestation issuance, Dispatch/Re-run, installation or protection change. The prior v2/v3 receipt archive and ledgers are never mutated.
