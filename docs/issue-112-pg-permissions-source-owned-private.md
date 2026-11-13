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
distinct SHA256 and removes all temporary files. A separate PR-only Windows
PG14–18 matrix then installs disposable PostgreSQL with a pinned installer,
reconstructs each exact private ZIP, independently hashes it and verifies the
eight extracted SQL/control files against immutable source-byte SHA256 and the
nine-file receipt (including the complete original LICENSE). The extracted
files, not the provider's original ZIP, are installed with create-only paths.
The matrix runs CREATE EXTENSION, checks extversion 1.4 and exercises
permission view, target and diff SQL. Temporary files and installed members
are removed. Required checks must actually pass before claiming Windows
runtime acceptance; merely adding a workflow is not acceptance.

No workflow uploads ZIP artifacts, issues OIDC/admission, enables provider GET,
signs, creates Releases or invokes Publisher. The independently signed
source-owned producer and formal public delivery gates remain unfulfilled.

Unlike signed producer provenance, a developer-authored manifest does not
authenticate Cybertec's original ZIP. Existing Windows SQL functional evidence
from Cybertec originals is not attributed to these distinct ZIP bytes.
Further requirements: protected original-main producer build and its native
Windows postmerge acceptance, independent attestation, SBOM/rights/dependency
closure, Publisher Environment/App admission, protected Catalog signed pin,
official create-only Release, public EXE Windows E2E and Website download.
The independent Cybertec-original runtime remains a separate evidence stream.

PGroonga remains held; TimescaleDB remains DENY; OSGeo has separate unclosed
producer-provenance, DLL dependency and NOTICE requirements. The existing
11 authenticated external original-provider GET assets are unchanged.
