# Issue #112 — pg_track_settings 2.1.2, Cybertec exact original audit

**Status: CANDIDATE_ONLY. No new CLI public GET, mirror, or Release.**

Source identity: https://github.com/rjuju/pg_track_settings
The upstream tag 2.1.2 resolves to full commit
36a23f3c6d684c40140da1a24b1c3ee0e707b77a.
The upstream tree has SQL and extension control files and PostgreSQL-license
LICENSE (Git blob 480aa8d292243ebe5c152a37fe1787bee77811ce).
This is a source file/license observation, **not** a legal assertion about
the entirety of any Cybertec ZIP.

Cybertec PGEE public directory index-only verification previously observed
pg_track_settings-14-public-2.1.2.zip through
pg_track_settings-18-public-2.1.2.zip on the five PG-major indexes.
These are **Cybertec PGEE packages**, not proven community PostgreSQL/EDB
Windows-compatible and not authenticated producer artifacts.

PR-only .github/workflows/issue112-cybertec-track-original.yml
performs five independent, canonical-source HTTPS original ZIP GETs on
ephemeral read-only CI runners, one per major. The Python verifier allows no
redirect, enforces content type, bounded download, SHA256 of the **actual
original ZIP bytes**, safe archive paths, no symlinks/duplicate casefolded
paths, CRC, expansion limits, expected control and 2.1.2 SQL. For each
original it prints full original SHA256, size, member count, package
license/notice member names, per-installable-member SHA256 and exact byte
comparison to a separately checked-out upstream tag commit.

**No original ZIP is uploaded, cached as an artifact, committed or mirrored.**
Matching SQL/control files do **not** prove original binary producer identity,
complete rights/notice inventory, independently authenticated build provenance
or runtime compatibility. Missing/differing pinned SQL bytes are reported,
not silently normalized or treated as approval.

Before any signed Catalog admission: independently evaluate original-package
rights and source-to-byte attribution, establish PG14–18 Windows native
CREATE EXTENSION plus function-level acceptance on ordinary EDB/community
installations (not just PGEE), independently sign and pass source-specific
publisher authorization. SQL-based extension status alone waives no gate.

**PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY.**
