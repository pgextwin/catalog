# Issue #112: pg_track_settings Cybertec original — rights/notice/provenance disposition

**CANDIDATE_ONLY; unresolved, no new authorized public GET.**
This is an explicit licensing and original-producer gap assessment for the
Cybertec `pg_track_settings` 2.1.2 Windows originals, not a license grant,
producer attestation or an admission decision.

## Facts bound to completed evidence (do not rerun successes)

- Original audit: https://github.com/pgextwin/catalog/pull/303
- Original private PR run: https://github.com/pgextwin/catalog/actions/runs/43016446662
  (pull_request, attempt 1, exact PR HEAD
  `61f0317b6fbca41a920f912defd7b5d1371776a1`, 10/10 SUCCESS).
- PG14–18 independent originals: each 29,613 bytes, 18 CRC-valid ZIP entries.
  Across all five, **13 installable SQL/control files match exact upstream source
  bytes** at tag `2.1.2`, commit
  `36a23f3c6d684c40140da1a24b1c3ee0e707b77a`.
  All five originals have **zero separately named LICENSE/NOTICE members**.
  Complete SHA256 values are recorded in Issue #112 comment 6795342059.
- Pinned upstream file
  https://github.com/rjuju/pg_track_settings/blob/36a23f3c6d684c40140da1a24b1c3ee0e707b77a/LICENSE
  has Git blob `480aa8d292243ebe5c152a37fe1787bee77811ce`;
  the text attributes copyright to **Julien Rouhaud (2015–2023)** and
  permits copying/distribution subject to reproducing its copyright and
  notice paragraphs in all copies.
- The source license is **not embedded** in those Cybertec distribution ZIPs;
  source-to-installable-SQL byte identity alone neither establishes the
  Cybertec package's full third-party rights nor attests which producer
  assembled the original ZIP.
- Disposable EDB Windows PostgreSQL 14–18 SQL functional acceptance (5/5)
  is genuine but only supports SQL/runtime compatibility.

## Disposition

The upstream grant addresses the identified **upstream SQL source license**,
but it does not cure absent **distributed copyright/notice content** or the
lack of a **producer-signed, original-SHA-bound build/source attestation**.
A link to upstream LICENSE, an unsigned sidecar written by pgextwin, or a
successful SQL test cannot be substituted for the source-specific authorized
admission. Do not alter provider originals, fabricate a producer receipt, or
publish a ZIP/GET record from this evidence.

Unresolved obligations before admission:

1. Independently enumerate **every original ZIP member** and document rights,
   attribution and actual distribution-notice compliance for each; ensure
   the complete required original copyright/notice accompanies any authorized
   distribution in a legally accepted form.
2. Obtain verifiable Cybertec producer attribution linking **each of the five
   exact original SHA256 digests** to the original build inputs and packaging
   process (or build a new, distinguishable pgextwin-owned source-pinned package
   via its genuine native/signing workflow, with no claim it is Cybertec's original).
3. Complete independent source-specific signing/authorization, dependency
   inventory and the real Publisher Environment/App/HEAD/Run/attempt checks.
   Only then may catalog feed, direct-get or Release exposure be considered.

This document deliberately contains no secrets, unsigned public links,
publisher approval, release invocation or code altering the public cohort.

**PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY.**
