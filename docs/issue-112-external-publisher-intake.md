# Issue #112 — source-specific external Publisher intake boundary

Status: **READ-ONLY ORIGIN-METADATA MATCH, NOT AUTHORIZED**. This
independently mergeable step adds
[`scripts/external_provider_release_identity.py`](../scripts/external_provider_release_identity.py)
and hostile offline tests. It checks the exact two previously reviewed PG18
source assets against separately authenticated GitHub REST repository/Release
metadata, including immutable numeric identifiers, stable tag, Release state,
exact asset URL, byte size and GitHub API SHA256 digest.

The comparator is **not** an authenticator for supplied JSON and **not** a
cryptographic verifier. Only the caller can authenticate the GitHub REST GET;
locally fabricated fixture JSON never qualifies. The existing signed
nonpublishing Catalog candidate is similarly **not** source-specific
Publisher consent, third-party binary signing or publication permission.
No Release, Catalog public signed feed, Website, downloader, mirror, ZIP
contents, or existing Publisher workflow is changed by this step.

## Two exact provider-origin checks

- Official `laurenz/oracle_fdw`, Release `335861225`,
  PG18 asset `442625860`. Original SHA256:
  `ad1fc057888b89f968de34f14bd7088c2b05d674a8df4b40ba47ed772c317678`.
  Preserve upstream oracle_fdw license notice and separate Oracle Instant
  Client licensing; do not distribute Client binaries.
- Unofficial `andreiramani/pgvector_pgsql_windows`, Release `419235203`,
  PG18 asset `661612613`. Original SHA256:
  `7c4ae0e2b2cb1e547779209a34a7d3f05b82fd7912818bf3d7042266eda87e7d`.
  Show community status and the upstream pgvector license/disclaimer before
  or with the original-provider reference. No upstream endorsement.

The current GitHub REST asset `digest` is present for **these two exact**
assets and is compared. This does **not** impose an upstream Sigstore,
SPDX, Grype, or fixed source SHA requirement on other providers.

## Formal admission prerequisites (not yet met)

1. Configure a dedicated, adequately protected external direct-provider
   Publisher Environment and a least-privilege App; verify their actual
   identity and environment protection from GitHub administrator state.
2. Add a source-specific, deny-by-default formal admission policy for each
   exact origin, operation and displayed rights/NOTICE/dependency treatment.
   Neither reference-link permission nor ZIP source licensing confers
   third-party Client redistribution or mirror rights.
3. Independently verify the original-main Sigstore candidate **actual bytes**
   and exact signer, source SHA, run and attempt. Never promote a local
   approval boolean or unsigned review JSON into signing authority.
4. Inside the authorized Publisher boundary, reauthenticate provider
   repository/Release/asset IDs; compare SHA256/size/URL and rehash actual
   downloaded bytes. Check target PostgreSQL/Windows ABI and dependency
   conditions, using the existing successful runtime evidence.
5. Only after the genuine technical authorization and separate signed public
   admission are proven may the existing .NET direct-origin GET-only path be
   minimally adapted for these assets. Independently verify the actual
   retrieved bytes. Do not create a proxy or mirror. Existing native
   downloader path must remain isolated and fail-closed.

**Present state:** both records remain `SIGNED_NONPUBLISHING` candidate
pins; **203/203 DOWNLOAD_DENY and MIRROR_DENY**. A future protected PR can
consume the comparator as one check, but it must not treat its output as
Publisher approval. No existing successful Run needs to be repeated.


## Offline original ZIP verifier for the future authorized external path

The isolated `dotnet/src/PgExtWin.Releases/ExternalOriginalZipIntegrity.cs`
checks *caller-supplied* original ZIP bytes and their **exact expected SHA256
and byte length**, then checks archive structure, bounded decompression,
nonempty payload, duplicate members, ZIP traversal/Windows ADS paths and
symlink entries. Synthetic hostile fixtures are included in the .NET contract
runner. This verifier makes **no HTTP request**, writes **no file**, extracts
or installs nothing and cannot authorize any external download. The expected
digest is not independently trusted until verified from a separately
authenticated, formally authorized external signed feed.

This does not replace the existing Windows PG18 actual runtime evidence or
claim a second real-byte provider fetch. The native-only REST/browser
downloaders and the CLI `--source external|all` download denial are unchanged.
The formally approved Publisher and separate signed client admission still
must be established before any direct provider GET.
