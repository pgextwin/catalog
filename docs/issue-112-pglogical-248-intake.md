# Issue #112 — pglogical 2.4.8 Windows source intake (2026-11-13 JST)

**CANDIDATE_ONLY / GET DENY / MIRROR DENY / REDISTRIBUTION DENY.**
This is a new upstream-unofficial community packaging provider, **not** an authorized
pgextwin download, signed Catalog pin, Publisher event, or official pglogical build.

## Authenticated read-only GitHub observation

- Provider: https://github.com/semihkiroglu/pglogical-windows
- Provider GitHub repository ID: `1324318750`.
- Release: https://github.com/semihkiroglu/pglogical-windows/releases/tag/2.4.8-w1
  (published 2026-09-02; release ID `381578857`, tag commit
  `98f8f67e5c3b963cbd93ef452ecf456d880bbfc4`).
- Upstream pglogical stable version: `2.4.8`, tag `REL2_4_8`;
  the provider claims source commit
  `9a0e182745885ad0152ea387988c95a483396a81`.
- Provider's historical Windows build:
  https://github.com/semihkiroglu/pglogical-windows/actions/runs/33683623757
  (`workflow_dispatch`, attempt 1, top-level SUCCESS).
  PG14, PG15, PG16, PG17 and PG18 build-and-smoke jobs: SUCCESS.
  Publish unified Release and generate artifact attestation steps: SUCCESS.
  This is **provider-reported** CI, not an independent pgextwin test or
  cryptographically verified supply-chain assertion.

| PG | GitHub asset ID | GitHub-reported size | GitHub API digest SHA256 |
| --- | ---: | ---: | --- |
| 14 | 541766447 | 176778 | `e722ca3eb5caad4da06620c32632d8b6ee7129b840d4e7da253721594c5024d3` |
| 15 | 541766450 | 176749 | `ff60107d6adef9a5b61dc2b78214f8ac9831a8df8f230a9cd9c90e7f7d3ebef2` |
| 16 | 541766449 | 176275 | `be599b6d3171cbb4d12d26bab51f909cb179af3ad7b4b6768c5fb89f4dec1157` |
| 17 | 541766446 | 176170 | `3cba8b233db52835ca62586d337132c816c42237151716e57dfa28a860633d7b` |
| 18 | 541766448 | 176460 | `1f69a4528b506a1bda01b8171f83d44268bbefe08b0adab49e00788c26d52eb3` |

Every asset is named `pglogical-2.4.8-pg<major>-w1-x64.zip` on the
provider's `2.4.8-w1` release. The upstream/producer documented PostgreSQL
License and third-party copyright/NOTICE material in `THIRD_PARTY_NOTICES.md`.
Provider reports source SHA pinning, Windows smoke, and artifact attestation.

## Independently established technical evidence (2026-11-13 JST)

- Original provider ZIP SHA256, fixed release identity, bounded archive
  contents and Windows x64 PE identity verified for PG14–18 in genuine
  PR-only GitHub Actions. Original bytes were fetched ephemerally.
- [PR Run 43443993355](https://github.com/pgextwin/catalog/actions/runs/43443993355),
  exact PR head `be04287af8da83c990446e1f8950d836a197ddb9`,
  completed SUCCESS, attempt 1: independently pinned five original ZIPs
  to GitHub Sigstore verified signer workflow, source commit and provider
  release-run provenance, and exercised real two-node Windows provider /
  subscriber replication with initial sync and UPDATE for PG14–18.
- [PR Validate 43443993384](https://github.com/pgextwin/catalog/actions/runs/43443993384),
  and original postmerge Validate 43444701990 / Website 43444702243,
  all SUCCESS at their respective original heads.
- **Historical failure is not a pass:** Run 43443397870 at older
  `d9a194e8` was FAILURE (two-node replication 5/5 FAILURE).
  The changed-head PR Run above resolved it; the failed run was not rerun
  or reclassified as SUCCESS.

The independent Sigstore check authenticates a provider's signed assertions
about the original ZIP hashes and source/run identity; it does NOT establish
reproducible builds, all compiled-source attribution, patch copyright or
transitive runtime/NOTICE clearance.

## Windows patch and third-party rights inventory (not closed)

Authenticated provider source evidence:

- `semihkiroglu/pglogical-windows` source
  `patches/pglogical-2.4.8-windows.patch` Git blob
  `06f5797641f58b5ca3c30e3394f6c78dbb34d623`.
- Provider `THIRD_PARTY_NOTICES.md` Git blob
  `d45005bdc61e1781e695d4d1ac8d54972e5151dd`
  identifies a patch derived from upstream issue
  [#442](https://github.com/2ndQuadrant/pglogical/issues/442),
  including contributions attributed to **ljackwilson** and **MickeyYadav**,
  and producer-specific subscriber-catchup changes. The provider asserts
  PostgreSQL License; this statement has not yet been independently
  reconciled with the exact contributing authors' permissions.
- Provider `LICENSE` Git blob `255a60b8aafccefc331109c99e2f7270d04ed60c`
  contains the PostgreSQL License. The original ZIP allowlist includes
  `share/pglogical/COPYRIGHT`; it does **not** contain the provider's
  `THIRD_PARTY_NOTICES.md` or separately identify all patch contributors.
  Determine whether the packaged copyright/license text and external
  companion notices fulfill each applicable attribution/distribution
  requirement. Do not alter the third-party original ZIP to add notices.

### Exact PE import inventory — new independent candidate audit

`scripts/issue112_pglogical_pe_import_inventory.py` verifies each original
asset's SHA256, safe ZIP members and PE32+ AMD64 headers, then enumerates
**static and delay-loaded import-module names** from all three packaged
binaries for each PostgreSQL 14–18 major. A PR-only read-only workflow
rejects invalid import RVA, malformed sections, unsafe module names,
duplicate descriptors, unsupported VA delay imports and absent imports
before any inventory can pass. It outputs no ZIP artifact, signed admission
or public download. Its results are not final until the corresponding
new PR's genuine source-audit CI checks complete.

Even a complete static import-name inventory cannot establish actual
Windows DLL loader search, transitive imports or non-import dynamic
LoadLibrary dependencies. Compare exact import names against the real
pinned EDB PostgreSQL installation and Windows runtime for **each major**,
including the client executable, and resolve unmatched or incompatible
modules without making an automatic source-specific authorization grant.

## Still-required authentic admission and publication gates

Before user-facing pgextwin GET: close patch copyright/notice obligations,
all applicable binary/transitive dependencies and runtime loader paths,
and the exact source-to-binary rights basis. Obtain genuine fresh
source-specific owner-signed Build issuer admission through protected main,
independent verifier, and all formal Publisher App/Environment requirements.
The independently successful technical tests do not grant those rights.

The five registry candidates intentionally continue to retain
`originalSha256=null`, `originalBytes=null`, `rightsReviewed=false`,
`provenanceVerified=false`, `compatibilityVerified=false`,
`dependenciesVerified=false`, `downloadAuthorized=false`.
Those fields are **unadmitted registry authority**, not a denial of the
separate independent nonpublishing test results. Do not promote them
until every required admission gate is genuinely met.

**Current state: CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY /
REDISTRIBUTION_DENY / RELEASE_DENY / PUBLISH_DENY.** The separately
admitted 11-asset cohort and public CLI v0.3.16 are unchanged.

Offline review:
```bash
python scripts/issue112_external_package_cohorts.py --catalog . --source github --extension pglogical --pg all --latest-per-pg --output /tmp/pglogical-review.json
python scripts/issue112_external_package_cohorts.py --catalog . --source github --extension pglogical --version 2.4.8 --pg all --output /tmp/pglogical-248-review.json
```
Both commands generate **nonpublishing** review plans only; no provider GET or
actual public `download-all` authorization is implied.


## PG14–18 real-EDB PE dependency path candidate audit (new PR scope)

The separate `issue112-pglogical-dependency-resolution.yml` PR-only Windows
matrix is designed to identify where **each original provider PE import name**
can be found in a pinned, freshly installed EnterpriseDB PostgreSQL directory
(`PGROOT/bin`, `PGROOT/lib`) or the Windows runner `System32`.
It reuses the exact-five-original SHA256/ZIP/PE parser and the existing
protected Build EDB installer implementation. It follows EDB application
binary imports with a finite graph bound and marks API-set names as virtual
contracts rather than inventing physical DLLs. It uses in-memory original ZIP
bytes and emits text-only candidate locations; it never stages, uploads,
mirrors, signs or publishes an original.

This is **not** an assertion of a live Windows loader search order: System32
transitive dependencies, API-set mappings, forwarded exports, SxS resolution,
delay/dynamic `LoadLibrary`, executable runtime branching, local DLL
search-policy differences and component copyright/NOTICE remain independent
gates. Any unresolved, unparseable, or depth-limited name is reported
separately. A successful inventory job only means the bounded investigation
completed; it does **not** mean dependency closure or licensing clearance.

The original successful PG14–18 Sigstore/two-node runs and earlier PE import
inventory are reused by reference and never rerun merely for this receipt.
Until the new PR CI passes, this proposed audit has **no passing receipt**;
even afterward `CANDIDATE_ONLY`, `GET_DENY`, `MIRROR_DENY`,
`REDISTRIBUTION_DENY`, `RELEASE_DENY` and `PUBLISH_DENY` persist.
