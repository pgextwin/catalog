# Issue #112 — pg_show_plans v2.1.8 source-owned Windows pilot

Status: **CANDIDATE_ONLY; nonpublishing**. No new user-visible extension download.

## Why this distinct path

The Cybertec PGEE Windows directory contains pg_show_plans packages advertised
with a provider v2.1.7 packaging label in the observed PG16–17 listings.
Upstream's 2026-06-03 latest GitHub Release is **v2.1.8**. Therefore an
old Cybertec binary should not be presented as the latest upstream version,
and PGEE-specific DLLs should not be automatically treated as community
PostgreSQL binaries.

Upstream source: https://github.com/cybertec-postgresql/pg_show_plans
Upstream Release: https://github.com/cybertec-postgresql/pg_show_plans/releases/tag/v2.1.8

The GitHub v2.1.8 annotated tag object
(c59e1686a30be9eeb222c25e41a1c9ac1a6437aa) was reported as signature
**verified** by GitHub, pointing to commit
92ecb21f8f2307a4bc7db8f01623599e75930fc2.
The license is the PostgreSQL License (copyright CYBERTEC).
This is *observed source identification*, not a provider-binary attestation
and not an independently re-verified GPG trust path.

The seven required official source Git blobs are hard-pinned in the separate
Python verifier. The source C file, control, four SQLs and LICENSE are checked
as exact bytes before the Windows build. The upstream **Release is v2.1.8**
while the SQL extension's internal default_version is **2.1**; those must
never be confused in a Catalog version filter.

## Actual proof to collect

The PR-only, read-only GitHub Actions workflow installs disposable existing
EDB Windows PostgreSQL 14, 15, 16, 17 and 18, compiles the *same exact
tag-pinned source* with the runner's MSVC x64 compiler, validates required
DLL exports, installs into disposable PostgreSQL, starts with
shared_preload_libraries, invokes CREATE EXTENSION, and exercises its C
function and SQL view. This is a new **pgextwin-owned build feasibility
pilot**, distinct from any downloaded Cybertec binary.

The source guard has hostile offline tests for modified Git blob inputs,
unsafe filenames, symlinks, missing inputs, and forbidden publisher flags.
There is no workflow_dispatch, schedule, original Cybertec ZIP GET,
output artifact upload, package/release/signature creation, Catalog feed
edit, Website edit, Publisher, or elevated GitHub token.

A passing PR test is **not** the official production build, independent
Windows package rehash, SBOM/vulnerability or producer-origin attestation.
Only subsequently built, immutable, independently attested pgextwin-owned
ZIPs could be considered for the normal source-specific signer/Publisher
route. This pilot does **not** grant GET permission to its own DLLs nor to
Cybertec originals. Native registration/repository, full lifecycle tests,
postmerge signed original, independent audit, and formal Publisher gates
are distinct next steps, if the pilot succeeds.

**PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY / PUBLISH_DENY.**

## MSVC compiler correction based on first original PR run

The initial real Windows PG14–18 compilation reported identical C2375 errors
at upstream pg_show_plans.c line 126: its function prototype lacks the explicit
extern used by the PostgreSQL PG_FUNCTION_INFO_V1 macro. The source guard first
checks the pristine seven source blobs, and an opt-in, one-occurrence patch then
replaces the redundant prototype with a comment in the disposable copy.
The PG_FUNCTION_INFO_V1 macro already provides the correct exported function
prototype across PG14-18 (PG16+ additionally marks PGDLLEXPORT). A duplicate,
missing or prepatched declaration is rejected. The derived source hash is printed in the
nonpublishing CI log; no upstream file, pinned commit, producer ZIP, license
or public artifact is modified. Separate offline hostile tests cover the patch.
