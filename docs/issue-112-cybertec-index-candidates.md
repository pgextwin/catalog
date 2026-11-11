# Issue #112 — Cybertec Windows extension directory: metadata-only discovery

Cybertec publishes per-PostgreSQL-major public Windows extension directory indexes at
`https://repository.cybertec.at/windows/public/NN/extension/`.
The observed PG16 and PG17 indexes include ZIP filenames for `pgvector`,
`pgaudit`, `pgtap`, `pg_wait_sampling`, `pg_partman`, `hypopg`, `orafce`,
`pg_hint_plan`, `pg_qualstats` and other extensions. Directory names are
provider packaging labels, **not** independently verified upstream versions.

`scripts/issue112_cybertec_windows_index.py` performs read-only, size-bounded GETs
of only the five canonical PG14–18 directory HTML indexes, with redirects
rejected. It extracts exact-basename ZIP candidate filenames, rejects unsafe
links, duplicate filenames and cross-major filename claims, and produces
deterministic metadata and observed-name coverage. The PR-only CI runs hostile
offline tests, then exactly one index-only GET for each supported PG major.
No ZIP, installer, .version sidecar, or binary bytes are fetched or uploaded.

**Important compatibility distinction:** this directory belongs to the
Cybertec PGEE / public demo distribution. A listing is not evidence of
compatibility with community PostgreSQL or EDB Windows binaries; nor is it a
redistribution license, independent original SHA256, reviewed component notices,
producer provenance, verified loader dependencies, or a signed admission.
Even observed filenames across all five majors prove neither latest upstream
release nor a functional full-major cohort.

Status: **CANDIDATE_ONLY; PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY.**
No new provider credentials, permission, workflow_dispatch, signing, Publisher,
Release, Catalog download entry, or Website advertisement. Existing P3 holds
and previous accepted releases are unchanged.

After PR-only index checks pass, the next narrow investigation should select
one small and independently traceable ZIP for *private* original-byte and
Windows PG ABI review. Establish upstream version, source, rights/NOTICE and
genuine signed authorization before proposing any production download path.
