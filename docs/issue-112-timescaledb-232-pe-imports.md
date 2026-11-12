# Issue #112 — TimescaleDB 2.32.0 original Windows PE dependency triage

**CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY.**

This scope checks the **new 2.32.0** provider originals independently of
historical 2.31.0 binary receipts, without replaying any successful original
Run. PG16, PG17 and PG18 use separate exact Release 442824242 asset IDs,
sizes and SHA256 receipts. The reviewed 2.32.0 selection is joined to the
protected exact-original ledger (including original push Run/job identifiers)
before any network GET. The public provider originals are read only into
ephemeral CI storage, with no uploaded or redistributed ZIPs.

The existing bounded SHA256, approved HTTPS redirect, ZIP path/CRC/size,
per-DLL byte/SHA256 and AMD64 PE32+ validation code is reused. The existing
OSGeo import/delay-import table parser is reused as well; no duplicate PE
parser or CLI distribution path is introduced. Expected exact DLL names are
version-specific: timescaledb.dll, timescaledb-2.32.0.dll, and
timescaledb-tsl-2.32.0.dll. A 2.31.0 DLL is rejected in the 2.32.0 scan.
Duplicate basenames, unsafe ZIP entries, unexpected members, wrong
original digests and cross-PG asset substitutions fail closed.

Every nonbundled DLL-name import is reported with exact consumer paths.
Windows-system and PostgreSQL-host names are **unverified triage hints**,
not runtime resolutions. A PE table that cannot be parsed is reported as
NOT_PARSED, never as a successful dependency resolution. No dynamic
LoadLibrary paths, loader search order, component source identity,
license/NOTICE attribution, setup.exe embedded payload rights, exact
signed upstream producer-to-asset provenance, owner admission or
formal Publisher approval is established here.

The new CI runs offline hostile tests, then a separate original 2.32.0
read-only PE audit per PG major, on both PR and genuine protected-main push.
All acceptance and permission flags stay false. Even PASS means only an
original-byte-bound static dependency observation. Promotion requires all
remaining independently signed and authorized gates, and cannot reuse the
expired 11-ZIP external issuer or any 2.31.0 signed admission.
