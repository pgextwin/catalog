# pgextwin CLI — Issue #112 PR-1 (nonpublishing)

Inert .NET 10 CLI prototype. Not an installer, signer, download agent, release producer or trusted verification engine.

- Core: strict JSON, Python P0-compatible canonical JSON/SHA256 golden vectors, P0 manifest envelope **structure only**.
- Catalog: **untrusted local** Catalog v2 reader, per-PG upstream versions and preload metadata.
- Cli: `list` and `search`, requiring `--catalog-dir PATH`, always displays `UNVERIFIED` and makes no HTTP requests.
- Contract.Tests: local synthetic/hostile test console with no external NuGet dependencies.

Run from repository root with .NET 10 SDK:

```bash
dotnet build dotnet/PgExtWin.slnx --configuration Release
dotnet run --project dotnet/tests/PgExtWin.Contract.Tests --configuration Release --no-build
dotnet run --project dotnet/src/PgExtWin.Cli -- list --catalog-dir . --pg 18
dotnet run --project dotnet/src/PgExtWin.Cli -- search cron --catalog-dir .
```

SDK `global.json` stays within the .NET 10 feature bands (`latestFeature`).

The existing Python P0 JSON Schema + Manifest builder and P1 authenticated Release/Sigstore verifier are unchanged and remain authoritative. Structural/golden tests never imply real signatures. No genuine 70 ZIP audit has occurred. P1 BLOCKED, P2 NO-GO, publication DENY, `publicationAuthorized=false`.

## PR-2: pinned original Release GET-only reader

The `PgExtWin.Releases` library requires a **separately authenticated**
`ReleasePin` with exact extension, release tag, packaging SHA,
numeric repository/Release/asset IDs, original ZIP filename, SHA256 and byte count.
Its GET-only adapter validates source Repository metadata and stable, non-draft
Release metadata before streaming the exact `github.com/pgextwin/.../releases/download/...`
asset. Only GitHub-owned Release asset redirect hosts are allowed.
It stages into a new temporary file, checks every byte/size/hash, and
refuses overwrites/reparse directory output paths. On any error it removes
the temporary file and refuses success.

This is an **unwired library**, deliberately not an automatically trusted
`download` command: PR-2 does not create or authenticate trust policy and
does not download live original Releases as part of CI. Caller may NOT derive
the pin from the same untrusted Release API response. The returned receipt
is at most `INTEGRITY_ONLY`, explicitly `SignatureVerified=false` and
`PublicationAuthorized=false`. Existing P1 remains the only source of
genuine SLSA/SPDX X.509 signature acceptance. No release, signing, bundle or
installer functionality is added. Tests exercise injected mock HTTP only.
