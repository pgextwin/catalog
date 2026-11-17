# External binary bulk fetch — RELAXED policy, 2026-11-17

**Fetchable latest additions: pglogical 2.4.8 and pg_crash 0.3, each on PG15–18.**
The five older-only candidates are blocked on **NO LATEST BINARY**; pg_lockout,
pg_prohibit_commands and the OSGeo bundle remain blocked on **LICENSE EVIDENCE**.
No candidate is blocked on signatures, admission, producer attestation, runtime
checks or publication authorization. No new issuer, pilot or gate was added.

This review supersedes the strict-policy conclusion in Catalog draft
[PR #435](https://github.com/pgextwin/catalog/pull/435). A separate implementation
branch is appropriate because #435 is a historical documentation-only survey;
its branch is left unchanged. Source-only release facts and source licenses were
refreshed, rather than interpreting an older provider package as latest.

## Verdicts

The Cybertec latest-listing columns below refer to all four saved indexes:
[PG15](https://repository.cybertec.at/windows/public/15/extension/),
[PG16](https://repository.cybertec.at/windows/public/16/extension/),
[PG17](https://repository.cybertec.at/windows/public/17/extension/),
[PG18](https://repository.cybertec.at/windows/public/18/extension/).
Additional exact-version Windows-binary web searches found no newer Windows
assets; Linux packages, containers and source mirrors were not counted as Windows binaries.
Full listing snapshots, API responses, exact source texts, member texts and byte
receipts are under the task workspace `codex-sol-extfetch2/evidence/` directory. The compact committed
receipt is `evidence/issue112-relaxed-external-fetch-20261117.json`.

| Candidate / latest target | Latest-version binary source, PG15–18 | Exact-version license evidence / verdict | Fetchable |
| --- | --- | --- | --- |
| pglogical 2.4.8 (2.4.8-w1 packaging) | [Producer release](https://github.com/semihkiroglu/pglogical-windows/releases/tag/2.4.8-w1), all four ZIPs downloaded (exact URLs below) | **ACCEPT PostgreSQL**: upstream REL2_4_8 COPYRIGHT; producer exact-tag LICENSE and THIRD_PARTY_NOTICES; ZIP COPYRIGHT retained. Patch question resolved below. | **YES**, all four majors |
| pg_show_plans 2.1.8 | [v2.1.8 release](https://github.com/cybertec-postgresql/pg_show_plans/releases/tag/v2.1.8) has zero assets. Cybertec PG15–18 latest listed v2.1.7-1 | **ACCEPT PostgreSQL**: exact v2.1.8 LICENSE, commit 92ecb21f8f2307a4bc7db8f01623599e75930fc2 | **NO — NO LATEST BINARY** at the official/provider sources inspected |
| pg_wait_sampling 1.1.11 | [v1.1.11 release](https://github.com/postgrespro/pg_wait_sampling/releases/tag/v1.1.11) has zero assets. Cybertec PG15–18 latest v1.1.9-1 | **ACCEPT PostgreSQL**: exact v1.1.11 LICENSE, commit 7e3a5fc937393596c0a51c5881dd63d7208408d1 | **NO — NO LATEST BINARY** at the sources inspected |
| pg_squeeze 1.9.4 | [REL1_9_4 release](https://github.com/cybertec-postgresql/pg_squeeze/releases/tag/REL1_9_4) has zero assets. Cybertec PG15–18 latest REL1_9_1-1 | **ACCEPT PostgreSQL-style**: exact REL1_9_4 LICENSE, commit 400c5f6ae9bc911073a6824e9a19f4d475fb7331 | **NO — NO LATEST BINARY** at the sources inspected |
| pg_failover_slots 1.2.1 | [v1.2.1 source tag](https://github.com/EnterpriseDB/pg_failover_slots/tree/v1.2.1) is newer than latest release v1.2.0 (zero assets). Cybertec PG15–18 latest v1.2.0-1 | **ACCEPT PostgreSQL-style**: exact v1.2.1 LICENSE, commit 27b1ef236ddd8488be6707196517fb4f9aa90140 | **NO — NO LATEST BINARY**; do not target 1.2.0 as latest |
| pldebugger 1.10 | [v1.10 release](https://github.com/EnterpriseDB/pldebugger/releases/tag/v1.10) has zero assets. Cybertec PG15–18 latest v1.9-1 | **ACCEPT Artistic-2.0**: exact v1.10 README-pldebugger.md and Makefile, commit bf57aa61d5eb131ece767cd7a9db0c167787d1e6 | **NO — NO LATEST BINARY** at the sources inspected |
| pg_crash 0.3 (tag v0.3, not v0.3.0) | [Official release](https://github.com/cybertec-postgresql/pg_crash/releases/tag/v0.3) has zero assets; Cybertec provider v0.3-1 ZIPs exist on all four majors and were downloaded | **ACCEPT BSD-3-Clause**: exact v0.3 LICENSE at commit 1f261763895e94cabe3c5005d7a95093a7c58381. Direct original download; show/link upstream license, preserve ZIP. | **YES**, all four majors; DLL-only package, no install/runtime claim |
| pg_lockout 1.3.0 | Cybertec 1.3.0-1 ZIPs exist and were downloaded on all four majors | **UNVERIFIED**: ZIP doc member contains literal `README.md`; no license text. Exact public source/license not obtained; search details below. | **NO — LICENSE** |
| pg_prohibit_commands 1.2.2 | Cybertec v1.2.2-1 ZIPs exist and were downloaded on all four majors | **UNVERIFIED**: ZIP doc member contains literal `README.md`; no license text. Exact public source/license not obtained; search details below. | **NO — LICENSE** |
| PostGIS / pgRouting latest OSGeo bundles | PG15 latest listed bundle 3.6.2; PG16–18 latest 3.7.0, all downloaded. PG18 actual controls: PostGIS 3.7.0, pgRouting 4.0.1, not listing's 4.0.2. URLs/hashes below. | Main exact sources acceptable GPL-2.0-or-later with Boost/MIT-X portions for pgRouting; **whole-bundle exact component license evidence incomplete**, details below. | **NO — LICENSE**, not G01/G05/G06 or runtime/provenance |

## pglogical patch and notices: resolved for direct fetching

The old concern was that the producer ZIP lacks THIRD_PARTY_NOTICES.md and
separate contributor attribution for a Windows patch derived from ljackwilson's
contribution to upstream issue #442 (including MickeyYadav changes), plus a
producer catchup change. It was not evidence of a restrictive license.

Read and saved the actual upstream COPYRIGHT, producer LICENSE,
THIRD_PARTY_NOTICES.md, exact producer patch, original contributed patch and
issue/comments. Exact producer commit:
`98f8f67e5c3b963cbd93ef452ecf456d880bbfc4`; upstream commit:
`9a0e182745885ad0152ea387988c95a483396a81`.

The producer's [exact-tag notices](https://github.com/semihkiroglu/pglogical-windows/blob/98f8f67e5c3b963cbd93ef452ecf456d880bbfc4/THIRD_PARTY_NOTICES.md)
expressly identify the patch as PostgreSQL-licensed; the producer LICENSE grants
use/copy/modification/distribution under that license. The contributor submitted
his patch to the PostgreSQL-licensed upstream repository and asked for it to be
merged, without a separate restrictive term in the read contribution.
[GitHub Terms D.6](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service#6-contributions-under-repository-license)
provides the repository-license default for contributions absent a separate
agreement. The license acceptance is an evidence-based interpretation of that
contribution and the producer's explicit declaration, not a newly obtained
personal license confirmation from either contributor.

All four actual ZIPs retain `share/pglogical/COPYRIGHT`, including the complete
permission grant and disclaimers; BUILD-INFO and pglogical.control identify
2.4.8. The PostgreSQL grant does not add a separately named NOTICE-file
requirement. Companion contributor notices are recorded and linked in the
Catalog evidence; no ZIP is altered or repackaged. **The exact 2.4.8-w1 license
is accepted for direct original fetching under the relaxed policy.**

## Missing Cybertec exact-version license evidence

Saved provider root/Windows pages, current documentation index, contrib index,
book index and legalnotice, PG15–18 package/version listings, exact ZIP member
inventories, public GitHub repository searches and exact-name searches. Broad
pg_lockout repository search returned unrelated password/lockout projects;
`pg_lockout in:name` and `pg_prohibit_commands in:name` both returned zero.
Direct expected `cybertec-postgresql/{name}` and `aiven/{name}` repository API
requests did not obtain public repositories. Web searches for each exact name
with license/source/version found provider listings but no exact license text.
Attempted doc URLs `pg-lockout.html` / `pg-prohibit-commands.html` returned 404;
the separate docs.cybertec-postgresql.com root was unavailable (saved errors).
The linked Windows installation-guide PDF URL returned 404 (saved error).
The provider documentation's generic PostgreSQL legalnotice is not a license
statement for these exact modules. No provider was contacted.

No claim of global source absence or legal prohibition is made. The exact
1.3.0 / 1.2.2 terms were **not obtained**. Missing ZIP notices alone would not
block a verified permissive source license (as pg_crash shows); the missing
exact-version license here does. No unlicensed records enter the fetch index.

## OSGeo current-byte component license review

Re-downloaded all four current bundles. PG18 is exactly 83,739,256 bytes /
`ac9e9486b3f9161ad86aea948c99b34ca67438f59263f91d2bcb961b51c7a419`,
1,045 members. Member hashes and control texts are saved. Historical rights or
runtime receipts were not substituted for these current bytes. The provider's
4.0.2 text was not substituted for `pgrouting.control = 4.0.1`.

Obtained actual PostGIS 3.7.0 LICENSE.TXT/COPYING and pgRouting v4.0.1
LICENSE/BOOST_LICENSE_1_0.txt/README. These identify GPL-2.0-or-later plus the
listed third-party portions; they are acceptable source licenses. Current ZIP
contains Apache-2.0 root LICENSE, GPLv2 `bin/COPYING` alongside osm2pgrouting
README, GDAL's multi-license `gdal-data/LICENSE.TXT`, MIT ogr_fdw terms,
BSD-style pgSphere and pointcloud copyright files. Read the full saved texts.
The root LICENSE is not a license inventory assigning Apache-2.0 to every
bundled DLL or extension.

Examined current DLL strings as unsigned component/version evidence (no build
attestation demanded): GDAL paths identify 3.13.1; PROJ identifies 9.8.1;
SFCGAL paths identify v2.3.0 and CGAL 6.0.1; GEOS C API identifies 3.15.0.
Obtained exact GDAL 3.13.1 LICENSE.TXT, PROJ 9.8.1 COPYING, SFCGAL v2.3.0
LICENSE, CGAL 6.0.1 Installation/LICENSE.GPL, and GEOS 3.15.0 COPYING.
These narrow the original G03 gap but do not cover the entire bundle.
A further scan including short and UTF-16 strings identified `bin/libgsl-28.dll`
as GSL 2.8. Downloaded the GNU gsl-2.8 source archive and read its README/COPYING
(GPLv3 terms); GSL is no longer listed as an unresolved version. The GUI also
contains `libintl-9.dll`: its strings identify gettext but did not settle an exact
release, and the read notices do not assign exact-version terms to that member.
`GNU.Gettext.dll` separately contains a gettext 0.18.1.1 source path; it cannot
supply the version of the different native `libintl-9.dll`. Other GUI/runtime
components still lack a complete exact-version license inventory. The source
PostGIS dependency overview is not an exact-version license inventory of all
of them. Exact component terms/versions for the complete bundle remain
**not obtained**, so G03 is still a license-evidence blocker. This does not
require signed source-to-DLL provenance, independent admission, runtime closure,
reproducibility or a new rights gate. The relaxed policy removes G01/G05/G06.

## Implementation scope

`external/direct-get.json` records reviewed exact versions, source URL, byte
count, measured SHA-256 and license references/hashes. Existing external
oracle_fdw, pgvector and pg_trickle records are retained for PG15–18; their
actual assets were also re-downloaded and hashes confirmed. They retain their
existing scope/coverage (pg_trickle currently has PG18 only).

The existing `download-all --source external` command reads this small Catalog
record file over HTTPS, selects latest or exact `--version`, then reuses
ExternalProviderAssetTransport and ExternalOriginalBatchStager. A small direct
Cybertec branch skips GitHub metadata for that HTTPS provider and shares the
same ZIP/hash/atomic handling. No fake GitHub IDs are invented (provider-only
rows use zero). Historical signed-admission APIs/records remain available;
the public external command no longer calls their verification path. Native
signed-feed code is unchanged. No Build implementation change is needed.

Examples after the support PR is merged and a CLI containing it is separately
made available (this PR publishes neither CLI nor feed):

```text
pgextwin download-all --source external --pg all
pgextwin download-all --source external --pg all --extension pglogical --version 2.4.8
pgextwin download-all --source external --pg 18 --extension pg_crash --version 0.3
```

Exact version lookup uses the record's upstreamVersion, not filename patterns;
an absent version fails without substituting an older/latest version. `latest`
is an explicit per-extension/per-PG Catalog choice, not a live upstream version
resolver; updates require reviewed records. PG14 is retained only in historical
paths, not added to these records. Native mixed-source behavior is unchanged.

## Actual downloaded new-candidate bytes

All SHA-256 values below were computed from downloaded ZIPs; local
`downloads/` stores originals and `evidence/*.receipt.json` stores inventories.

| File / exact provider URL | Bytes | SHA-256 |
| --- | ---: | --- |
| [pg_crash-15-public-v0.3-1.zip](https://repository.cybertec.at/windows/public/15/extension/pg_crash-15-public-v0.3-1.zip) | 44,130 | `161401c96ffe585ca51f80a0c7d88f2af1796ee3e39c02d064fd0dce04d524f0` |
| [pg_crash-16-public-v0.3-1.zip](https://repository.cybertec.at/windows/public/16/extension/pg_crash-16-public-v0.3-1.zip) | 44,275 | `94da1cd1acbe2f146bdb2233a27f2e5a69a1ea5a604bf97575d8c7994f2547c5` |
| [pg_crash-17-public-v0.3-1.zip](https://repository.cybertec.at/windows/public/17/extension/pg_crash-17-public-v0.3-1.zip) | 34,325 | `808f56bd6c4bf3bc3e526ad5c971535a01fd7909ba71ff7b4dc2359f22590358` |
| [pg_crash-18-public-v0.3-1.zip](https://repository.cybertec.at/windows/public/18/extension/pg_crash-18-public-v0.3-1.zip) | 34,331 | `37b9dbb8e38500efd9264656decb3a60eaf984c50fc7e67b36b61652e7605cb7` |
| [pg_lockout-15-public-1.3.0-1.zip](https://repository.cybertec.at/windows/public/15/extension/pg_lockout-15-public-1.3.0-1.zip) | 122,240 | `1c4a77b2aa7a1f4e3790cd9cce284573d516e08f1fb2e7443d0d918fbd48e6ff` |
| [pg_lockout-16-public-1.3.0-1.zip](https://repository.cybertec.at/windows/public/16/extension/pg_lockout-16-public-1.3.0-1.zip) | 124,017 | `4b9719e8ae149d4d2e049c9080ca0cf3ce98bfc396e5884b678b72548aaa8150` |
| [pg_lockout-17-public-1.3.0-1.zip](https://repository.cybertec.at/windows/public/17/extension/pg_lockout-17-public-1.3.0-1.zip) | 45,633 | `dd08ec5a91664c67ade53b3ea280573226f0a03016c15b9e325b95cdb12350a2` |
| [pg_lockout-18-public-1.3.0-1.zip](https://repository.cybertec.at/windows/public/18/extension/pg_lockout-18-public-1.3.0-1.zip) | 45,654 | `432f8066c701319bf80ae81606fa6b5a60f67ba483bbae45651b6c16c2b9d817` |
| [pg_prohibit_commands-15-public-v1.2.2-1.zip](https://repository.cybertec.at/windows/public/15/extension/pg_prohibit_commands-15-public-v1.2.2-1.zip) | 179,713 | `8f56128ba935fc327b7853b0fd7896d0fe49d2c38eb6ad491d68c631eb672a0b` |
| [pg_prohibit_commands-16-public-v1.2.2-1.zip](https://repository.cybertec.at/windows/public/16/extension/pg_prohibit_commands-16-public-v1.2.2-1.zip) | 181,640 | `69c69965528f6594893148ee52c6813719fd8e211aa244a69dfa042744a8d4dd` |
| [pg_prohibit_commands-17-public-v1.2.2-1.zip](https://repository.cybertec.at/windows/public/17/extension/pg_prohibit_commands-17-public-v1.2.2-1.zip) | 65,415 | `a80f62a67d507ce62eaa0d2aec01504fb2dd29ccfa889b77900f6e4738949a65` |
| [pg_prohibit_commands-18-public-v1.2.2-1.zip](https://repository.cybertec.at/windows/public/18/extension/pg_prohibit_commands-18-public-v1.2.2-1.zip) | 65,427 | `452cef5ffe66e4c84a329ac5a5c59b958010e5d2a2d5e156f8f6dbcbc87c5e30` |
| [pglogical-2.4.8-pg15-w1-x64.zip](https://github.com/semihkiroglu/pglogical-windows/releases/download/2.4.8-w1/pglogical-2.4.8-pg15-w1-x64.zip) | 176,749 | `ff60107d6adef9a5b61dc2b78214f8ac9831a8df8f230a9cd9c90e7f7d3ebef2` |
| [pglogical-2.4.8-pg16-w1-x64.zip](https://github.com/semihkiroglu/pglogical-windows/releases/download/2.4.8-w1/pglogical-2.4.8-pg16-w1-x64.zip) | 176,275 | `be599b6d3171cbb4d12d26bab51f909cb179af3ad7b4b6768c5fb89f4dec1157` |
| [pglogical-2.4.8-pg17-w1-x64.zip](https://github.com/semihkiroglu/pglogical-windows/releases/download/2.4.8-w1/pglogical-2.4.8-pg17-w1-x64.zip) | 176,170 | `3cba8b233db52835ca62586d337132c816c42237151716e57dfa28a860633d7b` |
| [pglogical-2.4.8-pg18-w1-x64.zip](https://github.com/semihkiroglu/pglogical-windows/releases/download/2.4.8-w1/pglogical-2.4.8-pg18-w1-x64.zip) | 176,460 | `1f69a4528b506a1bda01b8171f83d44268bbefe08b0adab49e00788c26d52eb3` |
| [postgis-bundle-pg15-3.6.2x64.zip](https://download-cache.osgeo.org/postgis/windows/pg15/postgis-bundle-pg15-3.6.2x64.zip) | 123,986,945 | `520c3fd7ebf95050d8d89dc1b626f4f43111a3d726f60b73bbbbbd95784688eb` |
| [postgis-bundle-pg16-3.7.0x64.zip](https://download-cache.osgeo.org/postgis/windows/pg16/postgis-bundle-pg16-3.7.0x64.zip) | 84,037,123 | `9fd299d661a049833a84584afd2aaea755e189a4d107b9bf579b56ce154d9eb0` |
| [postgis-bundle-pg17-3.7.0x64.zip](https://download-cache.osgeo.org/postgis/windows/pg17/postgis-bundle-pg17-3.7.0x64.zip) | 84,044,726 | `eceb7ed45276db6c9f8757e65ccf8d0ceedaebdcd0c401d442371ce8def61450` |
| [postgis-bundle-pg18-3.7.0x64.zip](https://download-cache.osgeo.org/postgis/windows/pg18/postgis-bundle-pg18-3.7.0x64.zip) | 83,739,256 | `ac9e9486b3f9161ad86aea948c99b34ca67438f59263f91d2bcb961b51c7a419` |

## Validation and publication boundary

- Catalog full Python suite: **1,072 tests PASS**.
- .NET 11 Release build: **PASS, 0 warnings / 0 errors**.
- Existing plus new .NET contract suite: **535 checks PASS**. New cases cover unsigned
  direct GET, latest and exact old-version selection, missing license evidence,
  PG14/19 exclusion, absent exact version, and whole-batch cleanup after a corrupt
  or redirected provider response. Existing native/signed-admission tests pass.
- Existing ZIP integrity verifier run against **all 17 actual downloaded
  catalog originals: PASS** (size, SHA-256, ZIP/CRC/member validation).
- Build existing qualified-cohort suite: **8 tests PASS**; Build clone unchanged.
- `git diff --check`: PASS. No new workflow or publisher changes.

Test logs are retained in the task workspace `evidence/`. The PR uses the existing
validation/Windows packaging CI. No issuer or admission workflow is dispatched;
no feed/CLI release is published, no publication state changed, no PR merged or
auto-merge enabled. PGroonga and TimescaleDB were not modified.
