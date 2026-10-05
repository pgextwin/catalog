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
- PostgreSQL compatibility is explicit per major version,
- unpublished or unverified builds are not listed as available.

The catalog schema is versioned so the website and future `pgextwin` CLI can consume the same data safely.
