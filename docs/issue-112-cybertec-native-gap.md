# Issue #112 — Cybertec PGEE index versus already-published native Catalog

**Status: CANDIDATE_ONLY, no new public GET.** This is a prioritization receipt,
not source-byte validation, compatibility evidence, a version resolver or permission.
It makes no network requests itself, never downloads an archive, and cannot issue
an authorization. Existing source-specific P3 holds and all public DENY gates remain.

The authenticated, successful PR #301 index-only run `43004702275` observed
**216 ZIP filenames and 20 distinct extension names** across PG14–18. Comparison
with `extensions/*.json` in protected Catalog at `b3745b4c5580ab248932ecec23d8d6c5d1a9e0f2`
shows **7 overlapping native names** (`hypopg`, `orafce`, `pg_hint_plan`,
`pg_partman`, `pg_qualstats`, `pgaudit`, `pgtap`) and **13 not registered as native**:

- Observed in *all five* Cybertec PGEE indexes: `pg_crash`, `pg_lockout`,
  `pg_permissions`, `pg_prohibit_commands`, `pg_show_plans`, `pg_squeeze`,
  `pg_track_settings`, `pgvector`, `pldebugger`, `plpgsql_sec`.
- Observed in *four* indexes (PG15–18): `pg_failover_slots`, `pg_wait_sampling`,
  `repl_proxy`.

The presence of a filename in these indexes is **not evidence** of upstream
latest version, native EDB/community Windows compatibility, functional PG support,
provider provenance, or sufficient rights/NOTICE; all remain unverified. The
new discovery names are research candidates only, never CLI download choices.
`pgvector` has an independent source-specific P3 hold and cannot be promoted
by this prioritization. Its Cybertec v0.8.2 packaging is older than upstream
v0.8.7. The `pgtap` 1.3.4 PG14–18 ZIP cohort is already in a native formal
pgextwin release (`pgextwin/pgtap`, `v1.3.4-windows.1`); do not replicate it.

To reproduce **with no additional ZIP GET** from a local Catalog checkout:

```bash
python scripts/issue112_cybertec_windows_index.py > /tmp/cybertec-index.txt
python scripts/issue112_cybertec_native_gap.py --catalog . --index /tmp/cybertec-index.txt
```

The first command performs the existing bounded index-only HTML GETs (five,
PG14–18). The second command reads only the existing report plus native Catalog
manifests; it does **zero network GETs**. It checks the source deny flags,
filename/major identity, manifest identities and SHA256 declaration shapes,
refuses duplicate or unbounded input, and reports the raw name overlap, separately
from the subset of majors declared available by the native Catalog. Its
`catalogNativeOverlappingMajorDeclarations` are **declarations**, not independent
byte-level re-verification, and equality of the upstream/provider ZIPs is **not**
claimed. A catalog name with a different upstream version must be evaluated as a
separate candidate rather than automatically treated as equivalent.

Next substantive work is on the previously unimplemented, non-held source names:
compare authenticated upstream latest tags and licensing, independently retrieve
original bytes in a private verification context, verify original SHA256 plus
archive contents / dependency provenance, and validate on corresponding normal
Windows PostgreSQL builds. Only a separately reviewed original issuer and genuine
protected Publisher path can ever make CLI public GET available.

**PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY** for all Cybertec candidates.
