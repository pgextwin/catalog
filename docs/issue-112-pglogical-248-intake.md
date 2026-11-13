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

## Admission gap and acceptance

The sizes and hashes above are **GitHub REST Release metadata only**; neither
independently rehashed original bytes nor verified the provider's attestation.
The discovery configuration and five candidate records deliberately retain
`originalSha256=null`, `originalBytes=null`, all approval flags FALSE, and
no signed admission. Published GitHub API digests are **not** promoted to an
independently verified original hash. No ZIP is fetched by this change.

Before real pgextwin GET: independently fetch the original provider ZIPs,
compare actual sizes/SHA256, inspect archive/member safety and PE imports,
verify Windows PG14–18 runtime per corresponding major (including plugin
loading/replication), establish source-to-binary manufacturer provenance,
evaluate upstream and patch licensing/NOTICE/dependency closure, and obtain
a fresh authentic owner/Build issuer source-specific signed admission through
protected main and required CI. Publisher App/Environment and all distribution
gates remain unchanged; do not reuse older or unrelated signed admissions.
The current 11-asset authorized cohort and v0.3.16 public CLI remain unchanged.

Offline review:
```bash
python scripts/issue112_external_package_cohorts.py --catalog . --source github --extension pglogical --pg all --latest-per-pg --output /tmp/pglogical-review.json
python scripts/issue112_external_package_cohorts.py --catalog . --source github --extension pglogical --version 2.4.8 --pg all --output /tmp/pglogical-248-review.json
```
Both commands generate **nonpublishing** review plans only; no provider GET or
actual public `download-all` authorization is implied.
