# Issue #112 — Hiraoka pg_bigm discovery and pg_trickle private byte review

**Status: CANDIDATE_ONLY.** Evidence only, NOT a genuine owner-event, Publisher admission, Release, signed Catalog feed, user download or mirror approval. The previously rejected owner-comment command is neither retried nor replaced.

## Additional community provider: HiraokaHyperTools/pg_bigm

Authenticated GitHub Release GET on 2026-11-04 JST; page 1 returned 4, page 2 returned 0:

| Tag | Release ID | Asset ID | Name | Size (bytes) | API SHA256 |
| --- | ---: | ---: | --- | ---: | --- |
| v20260107 | 274728862 | 337322081 | 20260107.7z | 139599 | 4d627c5373886a37414b775f11f2bd4e78262a9b641cc155f0edf332fed132e5 |
| v20250925 | 249964468 | 297130937 | 20250925.7z | 128344 | f76cf2af7df9cd7942d850b0e2381c53851ea36e35fbbe006785408f4c01af04 |
| v20181102 | 13780323 | 9511366 | 20181102.7z | 87243 | unavailable |
| v20181101 | 13760166 | 9494650 | 20181101.7z | 85146 | unavailable |

All four match the new strict eight-digit-date 7z allowlist. The GitHub API digests have **not** been independently rehashed. They are discovered metadata and are NOT added to the persistent authorized Catalog or windows-candidates registries.

The provider is explicitly **community, not pg_bigm upstream**. Its [README](https://github.com/HiraokaHyperTools/pg_bigm) advertises Windows PG9.6–18.0 and a PG18 x64 folder inside the 7z archive. [build.md](https://github.com/HiraokaHyperTools/pg_bigm/blob/master/build.md) names Visual Studio 2022, CMake, Python and 7-Zip. A date-like release name does NOT tell us which pg_bigm upstream version was compiled. Source code [provider LICENSE](https://github.com/HiraokaHyperTools/pg_bigm/blob/master/LICENSE) and [upstream license](https://github.com/pgbigm/pg_bigm/blob/master/LICENSE) retain copyright/disclaimer requirements. Contents and notices inside the 7z were NOT inspected.

**Remaining:** independent original 7z byte hash and 7z-safe bounded member audit (not the ZIP-only validator); identify per-PG payload/ABI and upstream extension version, compiler/CRT and dependency closure; review embedded LICENSE/NOTICE and applicable third-party rights; Windows PG runtime; authenticated signed Catalog pin, independently permitted source-specific owner-event and formal approval. No 7z file is offered to users.

## Upstream pg_trickle latest ZIP: private review

Authenticated GET confirms upstream [v0.108.3](https://github.com/trickle-labs/pg-trickle/releases/tag/v0.108.3) tag source commit ce709f06327b4801f79fc48934bc96107b450907, Release ID 404988260, Windows asset ID 616203967, filename pg_trickle-0.108.3-pg18-windows-amd64.zip, size 7029107, GitHub API SHA256 c2841dacee6fa1a09400c7e9a0f74159f2b7f36847a60ef10291d1beb06bd96b. API metadata is not independently verified bytes.

The [Apache-2.0 upstream LICENSE](https://github.com/trickle-labs/pg-trickle/blob/v0.108.3/LICENSE) applies to source; package notice contents and dependency licensing still need review. Upstream release documentation says the Windows amd64 build is optional/best-effort and **build-only**, not Windows runtime-qualified. The package advertises PG18 only; installation calls for shared_preload_libraries and restart.

[scripts/issue112-pg-trickle-byte-review.py](../scripts/issue112-pg-trickle-byte-review.py) is a nonpublishing original-asset private PR check. It rechecks pinned Release, asset and tag commit; privately retrieves the original ZIP into CI memory, compares independently calculated SHA256 and size, reuses the existing bounded ZIP CRC/path/duplicate/symlink inspection with per-package caps, checks presence of pg_trickle DLL, control and SQL, inspects AMD64 PE32+ headers and reports package LICENSE/NOTICE filenames. It neither extracts nor executes the DLL and does not upload or republish the binary.

Passing private ZIP checks does NOT show Windows PostgreSQL 18 ABI/runtime compatibility, dependency closure, build-to-source cryptographic provenance, legal notice acceptance, or approved external distribution. These remain separate fail-closed gates.

**Current immutable boundary:** persistent external registry 203 DOWNLOAD_DENY/MIRROR_DENY; 137 pg_trickle matches and four Hiraoka archives are additional metadata-only discoveries; Catalog formalSourceSpecificAuthorization=false and approvedOperation=NONE. No signed external Catalog, .NET user-download, Release, mirror, owner-event or Website-public-byte path is changed.
