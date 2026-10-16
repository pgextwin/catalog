# Issue #112 — historical PG14 evidence intake vs formal P1 acceptance (2026-10-16)

## Decision: register technical proof; do not promote a formal counter

This is a **read-only intake ledger**, not a second P1 verifier, automatic Release-audit adapter, signed evidence registry, or publication permission. It stores the **unaltered 1,856-byte Work receipt** under `evidence/p1/`, a narrowly pinned row/provenance descriptor, and a fail-closed SHA256 intake check. The local checker rehashes only the receipt (and optionally a supplied complete archive); **it does not independently rerun original ZIP/TUF/SLSA/SPDX cryptography**.

Canonical links: [Issue #112 technical receipt comment](https://github.com/pgextwin/build/issues/112#issuecomment-6215234245), [historical verifier](../scripts/distribution_historical_p1_pg14.py), [ordinary P1 contract](issue-112-p1-release-verifier.md), [historical profile](issue-112-historical-pg14-verifier.md). Original verifier implementation commit `40dcac693773c710d2b65fa5fe797bfca17ffb82`; data Catalog snapshot `2e850bb5e5a3441edaa887fa5f7c378d22aea4c6`. PR #69/#70/#71 are already merged; do not repeat those steps.

| Separate condition | State | What it means |
| --- | --- | --- |
| Historical PG14 technical evidence | **Work reports PASS** | Original strict complete single-row verifier exit 0; 4/4 original PG14 assets, TUF, both genuine SLSA/SPDX real-gh outcomes, source and original run/attempt matched **in Work** |
| Intake receipt byte match | **PASS** | Original locally available JSON receipt SHA256 `010dbff810264bf46e8d0b62e88f787d72756ced7d5dba7118359161404dd294`; hash check is **not** an independent signature validation |
| Private archive byte match here | **NOT CHECKED** | 533,654-byte original archive has external expected SHA256 `4e126798ea4fa84b50c441143ff3294d675831843c3b2bb3e57ff8a2f30e9ba3`, but its bytes were not present in this Chat's accessible evidence |
| Original Release Asset bytes | **4/16 measured in Work** | 12 original assets not independently rehashed; metadata SHA values and all 15 SHA256SUMS comparisons are **not** a substitute |
| Formal PG14 P1 admission | **NO** | No authoritative all-16 byte audit and no approved, narrow historical acceptance bridge |
| Historical source admitted | **0/40** | Source SHA corroboration in a Work receipt is not automatically entered into formal source registry |
| Formal fleet P1 admitted | **0/70** | The current authoritative fleet count remains unchanged; 69 other rows cannot inherit this row's evidence |
| P2, Release, installation, distribution | **DENY** | `publicationAuthorized=false`, `distributionAuthorized=false`; #75 GO A/GO B/G4/G5 NO-GO |

## Precise existing acceptance-contract requirements

Ordinary P1 `distribution_release_verify_p1.py` and `distribution_release_audit_p1.py` require all original stable/nondraft Release Asset **numeric IDs**, exact Release/tag/catalog/snapshot pinning, and all original Asset **bytes** rehashed against their GitHub digest and all original checksum-file entries. All original assets of one Release are required before calling `rehash_release`. Source needs original per-PG upstream **full SHA**, repository/ref/version and packaging SHA corroboration; signed evidence must bind subject hash/name, workflow full signer SHA, GitHub repository numeric ID, OIDC/X.509 identity, SLSA v1 and SPDX 2.3 predicate/subject, verified TUF root, actual `gh attestation verify` exit 0, immutable Run/attempt and a successful formal Promotion event.

For **new/normal** releases the original main Promotion `promote.yml` / `workflow_dispatch` / `refs/heads/main`, successful same attempt, and full upstream SHA remain mandatory **unchanged**. pg_bigm PG14 is one explicit historical **push** case: original `windows.yml` run `38007421492` attempt 1, PG14 job `114079409058` and Release publish job `114082606852` both SUCCESS; source upstream commit `735dceba0ecdd8ac1aaaaa207226a7102b6bbd71` corroborated against signed package and old checkout. This is not modern Promotion and is not a generalized waiver.

Original pg_bigm `SHA256SUMS.txt` has **15 literal `./basename` entries**, total 1,780 bytes, SHA256 `e94beee9258f8137d6161f102d8bac0e8045a17fa58e79eb7285fcbfdf3fad0a`. Only the explicit historical profile may normalize exactly one `./` *in memory*; the ordinary P1 `parse_sums()` must keep rejecting it. An all-16 historical verifier must apply the identical narrow allowlist and compare **all** 15 checksum entries to actual downloaded Asset payload hashes, not just Release metadata; rejecting invalid/duplicate/mixed names and size discrepancies. Do not alter the original Release or checksum file.

## Proposed narrowly scoped formal admission bridge (NOT active)

A future reviewed, code-enforced *historical-pg_bigm-pg14* acceptance contract can mark this row formally admitted **only after all** of:

1. Externally pinned original repo/Release/16 Asset numeric identities, immutable original Catalog snapshot digests, signer/packaging/upstream source and run/attempt are independently rechecked. A mutable current upstream tag alone is insufficient.
2. All **16 original Release Asset payloads** (5 ZIP, 5 SPDX, 5 Grype, 1 SHA256SUMS) are downloaded through bounded authenticated-TLS **GET-only**, each independently rehashed vs full original Asset SHA256 and the 15 filename+digest lines; the missing 12 cannot be inferred.
3. Exact original pg_bigm **PG14** ZIP/SPDX/Grype/package safe-member, CRC, X.509, SLSA v1 and SPDX 2.3 tests, verified official gh binary and TUF Root all reproduce or are independently validated from authenticated preserved originals. Confirm original successful `push`/jobs/attempt without pretending it was modern Promotion. Include complete evidence provenance and immutable archive/file SHA256; ordinary synthetic fixture checks count as zero.
4. A reviewed acceptance-policy change explicitly allows **this single immutable historical row identity**, with no fallback for other rows or failed normal Promotion, and establishes a documented Release-all-assets-first/row-signature-afterwards aggregation rule. The accepted counters can then become at most **1/70** for this row; the remaining 69 rows are untouched. Other PG-major signature verification is needed before their own formal row acceptance; a Release-wide asset hash does not validate their signatures.
5. Tests reject replaced Asset IDs, missing 12 assets, checksum aliasing, unsigned/SPDX-only bundles, TUF rotation mismatch, changed signer, ref or full SHA, replayed/different run attempt, `plpgsql_check` failed attempt 1, unauthorized status fields, and any P2/publication implication. Validate the protected PR with App15368 and exact-head merge before counter changes.

Neither that contract nor its 16/16 evidence exists in this PR. Do **not** promote formal P1 acceptance based solely on `workReportedTechnicalPass=true`, verified receipt SHA or downloaded archive checksum. No independent administrator approval register, signature or extra reviewer is required.

## Read-only intake usage and trust limits

```sh
python scripts/distribution_historical_p1_intake_ledger.py
# Optional when the original complete private archive is locally available:
python scripts/distribution_historical_p1_intake_ledger.py --archive PRIVATE/pgextwin-issue112-pgbigm-pg14-reaudit-evidence-20261016.tar.gz
python -m unittest discover -s tests -p 'test_distribution_historical_p1_intake_ledger.py'
```

The checker rejects altered original receipt bytes, changed identities/states, duplicate JSON keys, unreadable/symlinked evidence, wrong archive SHA256/size, and unknown ledger fields. Its output always states formal P1 **0/70**, historical source **0/40**, publication/distribution **false**. A successful intake exit 0 means *only* byte-pinned receipt and ledger data are coherent; it never validates the original cryptographic claims. Supplying archive bytes only adds an archive SHA256 check, not an extraction or internal evidence validation.

## Next independently bounded Work GET-only gate

Only the **remaining 12 assets** from **the same** pg_bigm Release ID `408449466`, original Repo ID `1405047175` may be fetched after explicit launch of the Work handoff. Verify exact original IDs/names/sizes, SHA256 of the original bytes against original Release API and all 15 original checksum entries. Reuse the existing four original assets and anchored Work evidence; never rewrite the old ZIP, root, checksum or source files. Save a sealed manifest with per-asset hashes, 16/16 combined audit report and complete tool provenance, and identify any missing or invalid item as BLOCKED. This next action alone is **not** formal row promotion; real signature/source/run proofs must still be reconciled under a reviewed acceptance contract. No expansion to other extensions, new Release, Workflow Dispatch/re-run, Publisher, tag, signing, P2, installation, or automatically created offline bundle.

**Distribution direction:** Do not directly publish a new prebuilt all-extension ZIP. Future CLI may generate a local offline ZIP arranged under `packages/pg<major>/<extension>/<version>/`. Existing individual GitHub Releases and Website links stay unchanged.
