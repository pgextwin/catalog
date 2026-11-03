# Issue #112 — external PG18 pilot admission review (direct provider downloads only)

Status: **CANDIDATE_ONLY**. This records provider-proportionate, independently
observable evidence. It does **not** grant any source an authenticated signed
Catalog pin, `.NET` downloader admission, Publisher authorization, mirror,
or permission to republish third-party binaries.

## Community pgvector 0.8.7 for EDB PostgreSQL 18 Windows x64

- **Provider:** [andreiramani/pgvector_pgsql_windows](https://github.com/andreiramani/pgvector_pgsql_windows),
  explicitly marked **unofficial**. Its README attributes versions 0.8.0–0.8.7
  to compiler `andreiramani`. This is not an endorsement from upstream pgvector.
- **Exact provider Release:** tag `0.8.7`, asset ID `661612613`,
  `vector.v0.8.7-pg18.zip`, 174796 bytes, independent original SHA256
  `7c4ae0e2b2cb1e547779209a34a7d3f05b82fd7912818bf3d7042266eda87e7d`.
- **Additional original attribution check:** authenticated GitHub contents GET
  at `zip/0.8.7/vector.v0.8.7-pg18.zip` in the provider repository yields
  Git blob `d7a00122661615a4e13ee78d7ba49789bf212906`; an independent
  SHA256 over the repository's actual 174796 bytes equals the Release asset's
  original SHA256 above. This connects the Release ZIP to a second provider
  repository location. It is byte/origin evidence, **not** a build attestation.
- **Windows runtime:** original main Run
  [41657903202](https://github.com/pgextwin/catalog/actions/runs/41657903202)
  at Catalog main `72320cbf5113d89f69af86c5eafcc630f2aaa02c` PASS:
  EDB PostgreSQL 18.6.5 x64 `CREATE EXTENSION vector`, 0.8.7 version and
  vector-distance SQL. No need to repeat this successful original Run.
- **Actual archive inventory:** 56 members (44 relevant DLL/control/SQL).
  `readme.txt` (892 uncompressed bytes) gives Windows PG18 install/upgrade
  instructions; the original ZIP contains **no separate LICENSE or NOTICE file**.
  The upstream pgvector [PostgreSQL License](https://github.com/pgvector/pgvector/blob/v0.8.7/LICENSE)
  requires preservation of its copyright/disclaimer paragraphs in copies.
  Treat the absent packaged notice as a documentation/rights-review item.
  For any eventual direct-provider offer, link the upstream license/notice
  and identify the package as unofficial. Do **not** silently repackage it to
  insert a notice. A pgextwin mirror needs its own rights gate.
- **Decision:** provider and original bytes attributable, and PG18 Windows SQL
  works; licensing notice treatment, signed external Catalog feed identity,
  and formal pgextwin download authorization are not yet completed. **DENY**.

## Official oracle_fdw 2.9.0 for EDB PostgreSQL 18 Windows x64

- **Provider:** official upstream
  [laurenz/oracle_fdw](https://github.com/laurenz/oracle_fdw);
  source tag `ORACLE_FDW_2_9_0`, source commit
  `3ea9a4522c445c15c741d4f2bc89bccde740d283`.
  The Release publishes a PG18 x64 ZIP with asset ID `442625860`.
- **Original ZIP:** `oracle_fdw-2.9.0-pg18-win64.zip`,
  365101 bytes, original independent SHA256
  `ad1fc057888b89f968de34f14bd7088c2b05d674a8df4b40ba47ed772c317678`.
  Ten ZIP members include five extension DLL/control/SQL payload files;
  structural verification PASS in original Run 41657903202.
- **Extension license:** upstream
  [LICENSE](https://github.com/laurenz/oracle_fdw/blob/ORACLE_FDW_2_9_0/LICENSE)
  permits use, copying and redistribution provided the copyright, grant and
  disclaimer paragraphs are retained. This permission does **not** govern
  separately supplied Oracle Client DLLs.
- **OCI dependency:** the upstream
  [README.oracle_fdw](https://github.com/laurenz/oracle_fdw/blob/ORACLE_FDW_2_9_0/README.oracle_fdw)
  requires Oracle Client **11.2+**, matching x64 architecture and a supported
  Windows PostgreSQL ABI. Oracle publishes an independently hashed
  [Instant Client Windows x64 Basic Light](https://www.oracle.com/database/technologies/instant-client/winx64-64-downloads.html);
  its [own license](https://www.oracle.com/downloads/licenses/instant-client-lic.html)
  is independent of oracle_fdw. pgextwin must not bundle or mirror Instant
  Client under an oracle_fdw source license.
- **Minimal acceptance only:** an isolated read-only/nonpublishing Windows
  workflow downloads Oracle's Basic Light **23.26.4.0.0** directly for ephemeral
  test use (60406433 bytes; published SHA256
  `7586c02a2926f619a0b16a9ae32e85bb3605798aa177155b065fffb48a1ee0b8`),
  stages only the original oracle_fdw DLL/control/SQL into disposable
  EDB PostgreSQL 18.6.5, executes `CREATE EXTENSION oracle_fdw` and
  no-argument `oracle_diag()`. **No remote Oracle DB or credential is
  needed**. CI outcome must be observed; code existence is not runtime PASS.
- **Observed OCI result:** original protected-main Run
  [41661506504 attempt1](https://github.com/pgextwin/catalog/actions/runs/41661506504)
  verified PostgreSQL 18.6.5 x64 with official Basic Light 23.26.4.0.0:
  `CREATE EXTENSION oracle_fdw` and `SELECT oracle_diag()` PASS.
  Remote Oracle database connectivity was intentionally NOT TESTED and is not
  a condition for this pilot.
- **Decision:** original Windows functionality passes, but **DOWNLOAD_DENY**
  remains until an authenticated signed external Catalog pin and genuine formal
  pgextwin Publisher authorization exist. Oracle Client redistribution remains
  separately prohibited under this review.

## Admission boundary and next safe transition

A **direct link to the original provider Release asset** is not the same as
uploading, mirroring or repackaging its ZIP. Review rights for the chosen
operation, retain any required notice references in user-facing details, and
preserve exact original bytes. Do not require every community provider to
supply an upstream Sigstore bundle, SPDX SBOM, Grype report, fixed source SHA
or reproducible-build proof as a universal admission checklist.

**Neither of these external entries is a signed authorized download pin yet.**
The local discovery JSON and pure `WindowsSourceSelector` cannot authorize
`download --source external`. The existing signed Catalog feed builder and
`SignedPublicCatalogFeed`/batch downloader currently cover pgextwin Releases
and must not be bypassed with a local boolean or an unsigned parallel feed.
Implement a narrowly versioned external signed-feed admission and exact
source-asset download binding **only after** independent review, genuine
formal Publisher authorization and hostile tests. Until then, preserve
`download --source external|all` fail-closed; preserve all 203 discovery
candidates and existing native downloads unchanged.

Website: only provider identity, target environment, dependencies, availability
and approved action; keep detailed refusal/provenance in these docs.

## Exact original-provider direct-link rights and NOTICE treatment

A focused **reference-link-only** review now binds the two PG18 assets to
their original provider Release URLs, numeric repository/Release/asset IDs,
independently verified byte SHA256, tested PG18 environment, license sources,
required dependency notices and original successful Windows Runs:

- [Exact review ledger](../evidence/issue112-external-pg18-direct-link-review-v1.json)
- [Read-only fail-closed validator](../scripts/external_direct_link_review.py)
  and [adversarial tests](../tests/test_external_direct_link_review.py)

**Operation reviewed:** a reference to the original, unmodified GitHub-hosted
provider asset and its associated legal/dependency information. Neither a
deep link nor a permissive source-code license authorizes pgextwin to
republish, mirror, edit, bundle, serve or make an installed-binary security
warranty. Do not redirect through pgextwin storage. A provider may change
availability or terms; the exact origin, identity and hash must be checked
again during genuine formally authorized automated retrieval.

**oracle_fdw (upstream-official):** link the tagged original oracle_fdw LICENSE
(including copyright, permission and warranty disclaimer) alongside the
original-provider reference. Explain that Oracle Instant Client must be
obtained by the user separately, with independently applicable Oracle terms;
the original oracle_fdw ZIP must never be represented as including it.
Dependency: Oracle Client >=11.2, matching x64 and target PG ABI. Original
PG18 extension load and local oracle_diag() passed. No Oracle DB connection is
required or claimed. No Oracle Client mirror.

**pgvector (unofficial community):** clearly name
`andreiramani/pgvector_pgsql_windows` as the compiler/provider, not the
official pgvector project. The original ZIP has **no bundled LICENSE or
NOTICE**. Provide a visible upstream pgvector v0.8.7 PostgreSQL License link
with its copyright/permission/disclaimer when showing the direct-provider
reference; do not append files or repackage this ZIP. PG18 SQL passed, but a
working extension does not create an upstream endorsement or republishing
permission.

**Authorization boundary:** this is `CANDIDATE_ONLY`, not an authenticated
signed source-asset pin or Publisher decision. The review ledger and offline
validator must not be loaded by the .NET downloader as policy, and the
discovery registry remains untrusted with every `downloadAuthorized=false`.
All **203 discovery candidates retain DOWNLOAD_DENY/MIRROR_DENY**. In
particular, the current signed Catalog v1 feed is limited to pgextwin-owned
Releases and cannot be relabeled as a verified external feed. A later external
admission must have a separately authenticated signed pin and formal
source-specific Publisher approval, then preserve fail-closed original-byte,
provider/Release/asset-ID and target environment checks; no fallback or mirror.
