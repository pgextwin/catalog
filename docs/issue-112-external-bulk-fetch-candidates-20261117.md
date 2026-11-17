# Issue #112 — external bulk-fetch candidate decision (2026-11-17)

**No candidate in this survey is ready for public signed fetching.** All remain
`CANDIDATE_ONLY / GET_DENY / MIRROR_DENY / RELEASE_DENY`. This is a survey,
not a registration, admission, signature verification run or publication request.
The [observation receipt](../evidence/issue112-external-bulk-fetch-survey-20261117.json)
records live API identities, exact source-license blobs, PG15–18 directory
observations and three bounded original-byte observations. Unknown facts are
marked **未取得**; a provider filename is not a verified extension version.

## Existing path to reuse

At Catalog `1b06cff8f4c384dd051bc8c6874c0714da4537db` (full SHA in the receipt), `index.json` contains
17 native extensions; Build's protected `metadata/automation-fleet.json` has
19 entries at `d8bb725` (full SHA in the receipt). Neither count means there
are 17/19 externally admitted upstream binaries.

- The native `scripts/cli_signed_feed.py` builds from published
  `extensions/*.json`; `config/cli-feed-majors.json` selects **15–18**.
  A source tarball or an unregistered issuer repository is not a native ZIP.
- External GET already uses `ExternalSignedCatalogCohort` →
  `ExternalSignedDirectGetAdmission` → `ExternalProviderAssetTransport` →
  `ExternalOriginalBatchStager`. Keep its independently verified Build/main
  Sigstore admission, exact original hash/size binding, and atomic batch save.
  `--extension` / `--version` already select exact signed current records.
- Build's existing `external-direct-get-qualified-cohort-issuer.py` and
  `external-direct-get-issuer.yml` assemble, attest and independently verify
  source-specific GET-only metadata; the pin-PR path binds Catalog's latest
  selection. Do not create another issuer, feed, CLI selector or permission
  boolean from this survey.

The four acceptance requirements here are **signature verification, fetched-byte
hash binding, valid admission, and the license of the exact fetched version**.
No new runtime, SBOM, vulnerability, loader-closure or reproducibility gate is
proposed. Existing historical investigations are evidence pointers, not new
work to repeat. A source tag signature does not bind a separately built DLL.
PG14 stays historical and is outside this proposed support cohort.

## Candidate decisions and priority

“PG15–18 listing” below means each of the four Cybertec PGEE directory indexes
contains that packaging label. It does **not** establish community/EDB ABI,
exact upstream source, signed provenance, or permission. Each linked official
GitHub Release below has **zero attached assets**: GitHub's generated source
ZIP/tarball is source distribution, not a Windows binary package.

| Priority / candidate | Latest upstream observation | Windows PG15 / 16 / 17 / 18 | Exact-version license evidence | Verdict / smallest next input |
| --- | --- | --- | --- | --- |
| 1. pglogical 2.4.8 | [REL2_4_8](https://github.com/2ndQuadrant/pglogical/releases/tag/REL2_4_8); community [2.4.8-w1](https://github.com/semihkiroglu/pglogical-windows/releases/tag/2.4.8-w1) has per-major ZIPs and GitHub SHA256 digests | Four 2.4.8 original ZIPs, exact IDs/lengths/hashes in receipt; historical independent Sigstore jobs succeeded for each | [Upstream COPYRIGHT at exact source](https://github.com/2ndQuadrant/pglogical/blob/9a0e182745885ad0152ea387988c95a483396a81/COPYRIGHT), PostgreSQL License; [producer notices at exact packaging commit](https://github.com/semihkiroglu/pglogical-windows/blob/98f8f67e5c3b963cbd93ef452ecf456d880bbfc4/THIRD_PARTY_NOTICES.md) claim the same license for the Windows patch. Independent reconciliation of patch contributors/packaged notice treatment remains 未取得 | **Blocked by core four: exact binary rights/admission**. Reuse existing byte pins and Sigstore evidence after that rights question closes; then extend the existing issuer/record allowlists for PG15–18, never promote the candidate JSON itself |
| 2. pg_show_plans 2.1.8 | [v2.1.8](https://github.com/cybertec-postgresql/pg_show_plans/releases/tag/v2.1.8); GitHub reports a verified annotated **source** tag | Each index lists `v2.1.7-1`; 2.1.8 binary for each major **未取得** | [Exact v2.1.8 LICENSE](https://github.com/cybertec-postgresql/pg_show_plans/blob/92ecb21f8f2307a4bc7db8f01623599e75930fc2/LICENSE): PostgreSQL License; no binding to the older provider DLL | **Blocked by core four + missing binary production**. Existing native pilot is reusable feasibility evidence, not a signed published package; do not repeat it or serve 2.1.7 as 2.1.8 |
| 3. pg_wait_sampling 1.1.11 | [v1.1.11](https://github.com/postgrespro/pg_wait_sampling/releases/tag/v1.1.11), source only | Each index lists `v1.1.9-1`; 1.1.11 binary **未取得** for all four | [Exact v1.1.11 LICENSE](https://github.com/postgrespro/pg_wait_sampling/blob/7e3a5fc937393596c0a51c5881dd63d7208408d1/LICENSE): PostgreSQL License; binary binding **未取得** | **Blocked by core four + missing binary production**. Need latest signed binary cohort; use existing native source-owned pipeline if separately pursued |
| 4. pg_squeeze 1.9.4 | [REL1_9_4](https://github.com/cybertec-postgresql/pg_squeeze/releases/tag/REL1_9_4); GitHub reports a verified annotated **source** tag | Each index lists `REL1_9_1-1`; 1.9.4 binary **未取得** for all four | [Exact REL1_9_4 LICENSE](https://github.com/cybertec-postgresql/pg_squeeze/blob/400c5f6ae9bc911073a6824e9a19f4d475fb7331/LICENSE): PostgreSQL-style permission and disclaimer; binary binding **未取得** | **Blocked by core four + missing binary production**. Same native path as above; source signature cannot authorize the old DLL |
| 5. pg_failover_slots | [Latest Release v1.2.0](https://github.com/EnterpriseDB/pg_failover_slots/releases/tag/v1.2.0), but a newer [v1.2.1 source tag](https://github.com/EnterpriseDB/pg_failover_slots/tree/v1.2.1) exists; latest binary choice is unresolved | Each index lists `v1.2.0-1`; v1.2.1 binaries **未取得** for all four | Both exact v1.2.0 and [v1.2.1 LICENSE](https://github.com/EnterpriseDB/pg_failover_slots/blob/27b1ef236ddd8488be6707196517fb4f9aa90140/LICENSE) have PostgreSQL-style permission; binary binding **未取得** | **Blocked by core four + missing binary production**. Do not label v1.2.0 “latest” solely from `/releases/latest` while hiding the newer tag |
| 6. pldebugger v1.10 | [v1.10](https://github.com/EnterpriseDB/pldebugger/releases/tag/v1.10), source only; SQL extension is named `pldbgapi`, not the release version | Each index lists `v1.9-1`; v1.10 binary **未取得** for all four | [Exact v1.10 README, Licence](https://github.com/EnterpriseDB/pldebugger/blob/bf57aa61d5eb131ece767cd7a9db0c167787d1e6/README-pldebugger.md#licence) and Makefile: Artistic-2.0; GitHub repository `license` field is null and must not substitute for these files | **Blocked by core four + missing binary production**. Need latest binary/source/license binding before any issuer addition |
| 7. pg_crash (requested v0.3.0) | Canonical [Release/tag is v0.3](https://github.com/cybertec-postgresql/pg_crash/releases/tag/v0.3), not v0.3.0; GitHub reports a verified annotated **source** tag | Each index lists `v0.3-1`; exact DLL version/source binding **未取得** | [Exact v0.3 LICENSE](https://github.com/cybertec-postgresql/pg_crash/blob/1f261763895e94cabe3c5005d7a95093a7c58381/LICENSE): BSD-3-Clause; observed PG18 ZIP has only a DLL, no notice/license member | **Blocked by core four**: signed binary provenance, exact binary license treatment and admission **未取得**. Also requires a new provider transport/admission contract; do not normalize the requested version into an unproven binary identity |
| 8. pg_lockout 1.3.0 | Public upstream source/release identity, latest status and exact source license **未取得**; exact-name GitHub repository search returned no results (not proof of nonexistence elsewhere) | Each index lists `1.3.0-1`; PG18 ZIP observed, no license/notice member | **未取得** for the fetched binary; a similarly named project is not license evidence | **Blocked by core four + missing provider machinery**. Need producer-signed byte/source/license evidence and valid admission before considering another transport |
| 9. pg_prohibit_commands 1.2.2 | Public upstream source/release identity, latest status and exact source license **未取得**; exact-name GitHub repository search returned no results | Each index lists `v1.2.2-1`; PG18 ZIP observed, no license/notice member | **未取得** for the fetched binary | **Blocked by core four + missing provider machinery**, same as pg_lockout |

None is **supportable now**. A preparatory support PR need not already contain
an active admission, but it must have a defensible exact-version license and
signed-byte basis to implement an issuer rule. Merely copying a candidate into
an allowlist would not close those gaps. The current GitHub Release transport
requires GitHub repository/Release/asset identities; it cannot directly consume
Cybertec HTTPS directory URLs. Adding that adapter now would leave core gaps
open, so it is not part of this tranche.

## Reused evidence and limited new observations

The [existing pglogical intake](issue-112-pglogical-248-intake.md) already
records the exact patch and notice question. Live GitHub API inspection of
[Run 43443993355](https://github.com/pgextwin/catalog/actions/runs/43443993355)
confirmed attempt 1, PR head `be04287af8da83c990446e1f8950d836a197ddb9`,
completed success. Job-level results: `hostile-offline-sigstore`, all five
`independent-provider-sigstore (14…18)` jobs and all five
`two-node-replication` jobs succeeded. PG14 in that receipt is historical.
These jobs were **not rerun**. Their success does not settle patch rights or
create a fresh Build/main admission. Signature verification in this survey
itself: **not performed**; historical independent results were inspected.

The existing index observer was reused for **only PG15–18**. To distinguish
actual license members from assumptions, three small current PG18 originals
were read once, in memory, without extraction, execution, rehosting or signing:

| Original Cybertec basename | Bytes / SHA256 | Archive observation |
| --- | --- | --- |
| `pg_crash-18-public-v0.3-1.zip` | 34,331 / `37b9dbb8e38500efd9264656decb3a60eaf984c50fc7e67b36b61652e7605cb7` | `lib/pg_crash.dll` only (plus directory entry) |
| `pg_lockout-18-public-1.3.0-1.zip` | 45,654 / `432f8066c701319bf80ae81606fa6b5a60f67ba483bbae45651b6c16c2b9d817` | DLL + nine-byte `share/doc/contrib/pg_lockout.md`; no license/notice member |
| `pg_prohibit_commands-18-public-v1.2.2-1.zip` | 65,427 / `452cef5ffe66e4c84a329ac5a5c59b958010e5d2a2d5e156f8f6dbcbc87c5e30` | DLL + nine-byte `share/doc/contrib/pg_prohibit_commands.md`; no license/notice member |

These are measured hashes, **not signed hash bindings**. No signed producer
assertion or source-specific GET admission for these bytes was obtained.
Absence of a license member does not by itself establish legal prohibition;
it means an exact binary license basis has not been established here. PG15–17
byte hashes for these three remain **未取得**; fetching more unsigned originals
would not close their signature/admission gap. No older-version ZIPs were
fetched for the other candidates merely to repeat that conclusion.

## PostGIS/pgRouting and parked candidates

The supplied `OSGEO-BLOCKERS-20261117.md` was read with the corresponding
[adapter](issue-112-osgeo-https-candidate-adapter.md),
[source rights](issue-112-osgeo-tagged-source-rights.md) and
[dependency provenance](issue-112-osgeo-dependency-provenance.md) records.
The current PG18 bundle digest is
`ac9e9486b3f9161ad86aea948c99b34ca67438f59263f91d2bcb961b51c7a419`,
83,739,256 bytes. It is recorded as PostGIS 3.7.0 / pgRouting **4.0.1**,
while the provider listing advertises 4.0.2. Do not inherit the replaced bundle's
rights or runtime results or reinterpret its component version.

Core blockers remain: producer-signed binding to current binary bytes (G01),
exact component license/notice basis (G03), and genuine GET-only admission and
Catalog binding (G05/G06). Existing `OsgeoSignedAdmission` explicitly represents
`CANDIDATE_ONLY_GET_DENY`; its HTTPS/hash transport cannot manufacture missing
producer evidence or permission. A latest shared-bundle selection already
exists in the package review planner, so no duplicate selector/pilot is useful.
Leave the OSGeo path unchanged. No additional runtime/dependency checklist is
being imposed as part of this survey's core-four decision.

PGroonga and TimescaleDB are parked by instruction and were not investigated,
modified or added to any support path.

## Result

No registration/fetch-code change is justified by the available evidence.
The requested 2–3-extension end-to-end tranche is blocked, not implemented.
This documentation-only PR preserves all candidate/publication states and
records how to resume using existing machinery; it does not claim an expanded
CLI, new signed feed, successful public GET or a new binary release.
