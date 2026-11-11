# Issue #112 — pg_track_settings 2.1.2: licensed source-owned PRIVATE pilot

**CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY.** This is a separately labeled pgextwin-owned SQL source packaging experiment, NOT a repaired Cybertec original, producer attestation, native issuer approval, signature, or authorized public download.

## Existing provider-original blocker

The Cybertec original ZIPs PG14–18 were independently rehashed and Windows SQL tested in Catalog PR #303 (10/10), but all five lack a separately named LICENSE/NOTICE member and a producer-signed, exact-ZIP-SHA-bound build receipt. Do not attach a self-authored notice to those originals, rename them, or treat runtime tests as producer provenance. Previous successful PR #303 tests are retained, not rerun.

## Separate source-owned candidate

Upstream rjuju/pg_track_settings tag 2.1.2 at exact commit 36a23f3c6d684c40140da1a24b1c3ee0e707b77a includes 12 SQL files, one control, and a 943-byte LICENSE (Git blob 480aa8d292243ebe5c152a37fe1787bee77811ce). Its license requires copyright and notice paragraphs in distributed copies. The candidate embeds that unmodified LICENSE alongside all 13 installable source files, NOT a modified Cybertec ZIP. No third-party DLL is packaged.

Example private invocation: python scripts/issue112_track_owned_source_pilot.py --source pinned-upstream --pg 18 --output /tmp/track-source-pg18.zip

The source must be a genuine Git checkout at the pinned commit. The builder validates all 14 exact Git source blobs, copyright notice, installable filename allowlist and control default version. It creates exactly 15 deterministic ZIP members: LICENSE, SOURCE-INPUTS.json, and 13 files in share/extension. Source-input metadata contains per-file SHA256, selected PG major, and **false** Cybertec provenance, independent signature, public GET, mirror, release and Publisher flags. Distinct PG majors are explicit candidate outputs; no provider file is renamed or used to generate another major.

Missing/mutated/linked source, wrong commit, unknown major, unexpected declared source filename, invalid output path and overwrite are rejected. The PR-only CI rechecks the pinned upstream source, runs hostile offline tests, creates five nonpublic candidates, and independently tests the new ZIP SQL in disposable Windows EDB PostgreSQL 14–18. No artifact upload, tag, signature, publisher, production CLI, public release or Website update.

## Future public acceptance

The new package requires distinct native registration and source ownership, independent license/dependency review, protected-main build, genuine signer, independent attestation, formal Publisher Environment/App/HEAD/Run/attempt authorization, immutable public Release byte checks, Catalog and Website verification. The existing Cybertec denial policy and external source-specific P3 holds remain unchanged. Neither embedded metadata nor PR-only CI constitutes independent provenance or publication authority.
