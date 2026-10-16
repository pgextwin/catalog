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
