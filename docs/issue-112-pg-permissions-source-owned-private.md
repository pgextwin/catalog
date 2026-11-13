# Issue #112 — pg_permissions v1.4.1 source-owned private SQL pilot

**CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY.**

This is a new pgextwin source-owned SQL-only candidate. It is not a Cybertec
provider original, independently attested binary or public CLI admission.

Upstream: cybertec-postgresql/pg_permissions, source tag REL_1_4_1, immutable
commit 3360447e0668fed2b9db6a0ae1d086533781f9bd. The existing source
identity checker enforces nine separately pinned Git blobs: seven SQL files,
one control file and the complete upstream LICENSE. Deterministic private
ZIPs are built separately for PG14, PG15, PG16, PG17, PG18. The SQL extension
default version remains 1.4; upstream package version is 1.4.1.

The shared bounded, deterministic SQL archive helper enforces exact member
allowlists, fixed timestamps and regular file attributes, ZIP CRC, canonical
bytes, no traversal and strictly bounded source member sizes. Each ZIP contains
LICENSE, SOURCE-INPUTS.json and 8 SQL/control members under share/extension/.
The manifest records the source identity, every SHA256, selected PG major,
rights text included and explicit negative publication/admission flags.
Output is create-only and confined to the caller's private filesystem.

To build a private candidate from an exact clean source checkout:

    python scripts/issue112_pg_permissions_owned_source_pilot.py --source SOURCE_DIR --pg 18 --output NEW_PRIVATE_FILE.zip

The PR-only Windows workflow fetches the exact source ref, checks its Git
commit and source member bytes, creates five local ZIP candidates, validates
distinct SHA256 and removes all temporary files. It does not upload artifacts,
issue OIDC/issuer admission, enable Provider GET, sign, create Releases or
invoke Publisher. Its passing result would establish package reproducibility,
NOT real PostgreSQL Windows CREATE EXTENSION from the ZIP.

Unlike signed producer provenance, a developer-authored manifest does not
authenticate Cybertec's original ZIP. Existing Windows SQL functional evidence
from Cybertec originals is not attributed to these distinct ZIP bytes.
Further requirements: protected original-main build, native PG14-18 runtime
from the own-source package, independent attestation, rights and dependency
closure, Publisher Environment/App admission, protected Catalog pin, official
create-only Release, public EXE Windows E2E and Website download.

PGroonga remains held; TimescaleDB remains DENY; OSGeo has separate unclosed
producer-provenance, DLL dependency and NOTICE requirements. The existing
11 authenticated external original-provider GET assets are unchanged.
