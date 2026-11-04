# Issue #112 — PG18 original-provider internal verification guide (NONPUBLISHING)

> **Scope:** exactly the two already-reviewed PG18 Windows x64 upstream/community ZIPs. **This is a nonpublishing operator/reference guide, not a public pgextwin download offering, a source-specific owner event, a Publisher instruction, a license to mirror, or permission to bypass the existing CLI DENY.** No Release, Catalog signed public feed, Website download, App, Environment, protected policy, or workflow is changed by these instructions.

## 1. Canonical evidence (2026-11-05 JST)

| Field | Official oracle_fdw | Unofficial community pgvector |
| --- | --- | --- |
| Source | `laurenz/oracle_fdw` (official extension provider) | `andreiramani/pgvector_pgsql_windows` (community compiler; **not** endorsed by upstream pgvector) |
| Version / tested target | 2.9.0 / EDB PostgreSQL 18.6.5 x64 Windows | 0.8.7 / EDB PostgreSQL 18.6.5 x64 Windows |
| Repository ID | `14332609` | `838202416` |
| Release ID | `335861225` (`ORACLE_FDW_2_9_0`) | `419235203` (`0.8.7`) |
| Asset ID | `442625860` | `661612613` |
| Original ZIP name | `oracle_fdw-2.9.0-pg18-win64.zip` | `vector.v0.8.7-pg18.zip` |
| Original byte size | `365101` | `174796` |
| Original independent SHA256 | `ad1fc057888b89f968de34f14bd7088c2b05d674a8df4b40ba47ed772c317678` | `7c4ae0e2b2cb1e547779209a34a7d3f05b82fd7912818bf3d7042266eda87e7d` |
| Existing Windows test | [original Run 41661506504, attempt 1](https://github.com/pgextwin/catalog/actions/runs/41661506504), `CREATE EXTENSION oracle_fdw` + `oracle_diag()` PASS | [original Run 41657903202, attempt 1](https://github.com/pgextwin/catalog/actions/runs/41657903202), `CREATE EXTENSION vector` + SQL distance PASS |

The two GitHub API asset digests, byte sizes and IDs matched the above independently reviewed ledger in the latest authenticated GET. This review did **not** newly retrieve, rehash or execute either ZIP. The original runtime results were verified as `push/attempt1/completed/success`; no successful Run was rerun.

Canonical independent review: [PG18 provider review](issue-112-provider-review-pg18.md), [immutable-review-ledger format](../evidence/issue112-external-pg18-direct-link-review-v1.json), [original-link fail-closed validator](../scripts/external_direct_link_review.py), [hostile tests](../tests/test_external_direct_link_review.py), [source-specific policy](../config/issue112-external-publisher-policy.json).

## 2. Read-only origin and rights procedure

1. Read the exact upstream release **at the provider's GitHub repository**, without treating an external Release as a pgextwin Release:
   - [oracle_fdw original Release](https://github.com/laurenz/oracle_fdw/releases/tag/ORACLE_FDW_2_9_0), original asset `oracle_fdw-2.9.0-pg18-win64.zip`.
   - [unofficial pgvector community Release](https://github.com/andreiramani/pgvector_pgsql_windows/releases/tag/0.8.7), original asset `vector.v0.8.7-pg18.zip`.
2. On any future fresh review, reauthenticate **repository ID + Release ID + Asset ID**, original filename, tag, size, original GitHub host and API digest against the ledger. An API digest is *metadata*, not a substitute for a separately trusted hash or actual ZIP inspection. Do not silently adopt an updated asset, a redirect to a different provider, or a different PG build.
3. Preserve and show applicable terms before any operator considers using the original files:
   - **oracle_fdw:** [tagged extension LICENSE](https://github.com/laurenz/oracle_fdw/blob/ORACLE_FDW_2_9_0/LICENSE) and [upstream runtime instructions](https://github.com/laurenz/oracle_fdw/blob/ORACLE_FDW_2_9_0/README.oracle_fdw). Oracle Instant Client (x64, at least 11.2 per upstream requirements) is **not part of the oracle_fdw ZIP**. The end user obtains it independently under the [Oracle Instant Client license](https://www.oracle.com/downloads/licenses/instant-client-lic.html); **never redistribute or mirror it through pgextwin**.
   - **pgvector:** the provider is an **unofficial community compiler**; the original ZIP has **no LICENSE/NOTICE file**. Preserve attribution and link the [pgvector v0.8.7 PostgreSQL License](https://github.com/pgvector/pgvector/blob/v0.8.7/LICENSE). Do not silently repackage the ZIP to add a notice or describe it as an official upstream binary.

A person may visit the provider's public Release page and independently obtain the original ZIP for an isolated, self-managed evaluation under applicable terms. Such a manual original-provider action is **outside pgextwin's distribution service**; it does not authorize pgextwin CLI, public Catalog, Website download, proxy, mirror or redistribution. No tool or automated pgextwin provider download is introduced here.

## 3. Local evidence checks after optional independent retrieval

In a **disposable Windows PG18 test environment**, first compare an independently obtained *unmodified* ZIP with the exact byte size and SHA256 listed above. Example PowerShell, run separately for each file with its actual filename:

```powershell
$file = '.\oracle_fdw-2.9.0-pg18-win64.zip'  # or .\vector.v0.8.7-pg18.zip
(Get-Item -LiteralPath $file).Length
(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
```

**Fail closed** on a missing file, mismatch, unsupported target, unknown dependency, unexpectedly modified archive, license discrepancy or uncertain provider identity. Do not extract an untrusted ZIP into a PostgreSQL installation, production path, or privileged directory. Byte-size + SHA256 matching establishes integrity against the expected **reviewed digest**; it is not independent signing, Sigstore provenance, authorization, ZIP-structure validation, or production suitability.

In a checked-out copy of the protected Catalog repository, an **offline record/policy review** (not a new ZIP byte test) can reuse:

```sh
python3 scripts/external_direct_link_review.py
python3 tests/test_external_direct_link_review.py
```

Expected validator scope: `referenceLinksReviewed=2`, `signedExternalCatalogPins=0`, `downloadAuthorized=false`, `mirrorAuthorized=false`, `scope=CANDIDATE_ONLY`. The commands inspect the existing ledger against reviewed candidate identities and reject tampering. They do **not** download, extract, rehash, install or cryptographically authenticate new source assets.

The prior original Windows PG18 functional CI is evidence for **EDB PostgreSQL 18.6.5 x64 only**. oracle_fdw was smoke-tested with separately obtained Oracle Basic Light, `CREATE EXTENSION` and local `oracle_diag()`; remote Oracle DB connectivity was **not** tested. pgvector was tested via extension creation/version/distance SQL. Other PostgreSQL vendors, ABIs and production installation are **not** established by these proofs.

## 4. Hard DENY boundary and handoff

- As of the 2026-11-05 authenticated review, protected `build/main=0f985976bc428b6fe7f8c4d392dfd640a7298420` and `catalog/main=47b8351250c283a923b5e4f6d0ed74f9d7db6d10`. The exact protected Catalog policy remains `formalSourceSpecificAuthorization=false`, `originalMainIndependentSigstoreVerified=false`, `approvedOperation=NONE`, with both source records `downloadAuthorized=false` and `mirrorAuthorized=false`. The previous source inventory report has **344 read-only/discovery items**, all DOWNLOAD_DENY/MIRROR_DENY; this guide does not rescan the full inventory.
- Original central [Publisher Run 41878569169](https://github.com/pgextwin/build/actions/runs/41878569169) was `issue_comment/attempt1/completed/skipped`; every listed Publisher job SKIPPED. Pending Environment deployments: `[]`. [Catalog signed-public-feed Run 41870485705](https://github.com/pgextwin/catalog/actions/runs/41870485705) had gate SUCCESS but attest and publish-metadata-only SKIPPED. Neither is a public external asset acceptance.
- **No** owner-command rewording/replay, substitute comment, simulated `issue_comment`/actor/run, CI success substitution, policy change, Environment/branch/App permission relaxation, manual feed upload, alternate signed feed, CLI unguarding or Release/Website publication may be justified by this guide.
- A formal public pgextwin delivery remains **BLOCKED** pending an independently permissible genuine source-specific owner event and exact event/actor/Run/attempt/HEAD proof, required actual Environment authorization (only if pending), independently verified exact source bytes and signed source-specific admission, protected PR/CI/merge/postmerge, approved signed public feed, and fail-closed .NET/Website end-user-byte acceptance. No pending Environment approval currently exists to send to Work.

**Independent result:** the two provider-specific PG18 candidates and existing tests are **CANDIDATE_ONLY COMPLETE**. This guide consolidates **nonpublishing** operator information only; no additional distribution right, cryptographic proof, or production support is claimed. Primary audit: [Issue #112, comment 6637512764](https://github.com/pgextwin/build/issues/112#issuecomment-6637512764).
