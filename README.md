# pgextwin catalog

[日本語](README_ja.md) | English

Machine-readable catalog for Windows x64 PostgreSQL extension binaries published by **pgextwin**.

The catalog stores metadata only. Binary files remain canonical in each extension repository's GitHub Releases.

## Layout

```text
index.json
schema/
  extension.schema.json
extensions/
  <extension>.json
```

## Principles

- one catalog record per extension,
- no binary artifacts are committed here,
- every download points to a canonical GitHub Release,
- upstream project and license are always recorded,
- PostgreSQL binary availability is explicit per major version,
- unpublished or unverified builds are not listed as available.

The catalog schema is versioned so the website and future `pgextwin` CLI can consume the same data safely.

## Availability and PostgreSQL lifecycle

Catalog schema v1 deliberately separates **historical binary availability** from **current PostgreSQL maintenance**.

For `postgresql.<major>.available`:

- `true` means a published and verified Windows x64 binary asset exists for that PostgreSQL major,
- `false` means such a verified published asset is not currently recorded,
- it does **not** mean that the PostgreSQL community still maintains that major.

PostgreSQL lifecycle dates and current maintenance status are derived from the canonical lifecycle metadata in [`pgextwin/build/metadata/postgresql.json`](https://github.com/pgextwin/build/blob/main/metadata/postgresql.json). The website combines catalog records with that metadata at display time.

Extension records must not duplicate date-dependent `maintained` booleans or PostgreSQL EOL dates. Existing published assets remain available after PostgreSQL EOL unless they are separately withdrawn for another reason.

## Current milestone

All eight initial extensions — pg_bigm, pg_cron, pg_hint_plan, pgAudit, set_user, pg_repack, pg_ivm, and pg_qualstats — have published PostgreSQL 14–18 Windows x64 Releases and are registered in this catalog. **Initial extension roadmap: complete.**

Catalog schema v1 remains in use. Catalog schema v2 and broader package-metadata work are separate future milestones.
