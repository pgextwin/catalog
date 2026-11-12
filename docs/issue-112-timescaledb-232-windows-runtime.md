# Issue #112 — TimescaleDB 2.32.0 exact Windows SQL acceptance (private)

**Nonpublishing / no redistribution / no signed GET admission.**

New upstream official stable 2.32.0 has PG16/17/18 original Windows ZIPs
(Release 442824242). Original GitHub GET Run 43242594902, HEAD
84f6aa357a4b7dcbc33af4db72986b29a9530de9, independently rehashed
all three actual original ZIPs; an evidence-only exact run ledger is proposed
by PR #358. This job never copies the 2.31.0 ZIP or its signature.

This separate read-only Windows matrix uses the **existing** 2.31.0 CI
installation/SQL acceptance procedure, with a strict exact version selector.
For each disposable EDB PG16/17/18 host it re-GETs the 2.32.0 original from
the pinned official Release, refuses unexpected redirects/length/SHA256/unsafe
ZIP members, extracts into a create-only temporary staging directory,
executes the upstream setup.exe against pg_config, then creates a real
PostgreSQL cluster with TimescaleDB shared preload. It asserts the exact
2.32.0 CREATE EXTENSION result, hypertable creation, sample insertion and
query. The existing 2.31.0 workflow retains its default pinned version.

No output ZIP upload, distribution mirror, change to production CLI/Catalog
GET admission, installer persistence or Publisher credentials. Exact Windows
SQL success (if observed) is runtime evidence only. Complete licenses,
third-party NOTICES, dependencies, producer-signed source-to-binary linkage,
and fresh owner/Environment/Publisher authorization must still separately
pass before any external public GET.
