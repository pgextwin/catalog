# pgextwin CLI — Issue #112 (nonpublishing, PR-2)

.NET 10 local-only `list/search` and explicit **single-asset** GET-only `download`.
This is not an installer, a signer, a fleet/bundle generator, a Publisher or a trusted
Sigstore verification engine. The Python P0 Manifest v1 builder/Schema and P1
Release/Sigstore verification remain the authoritative independent acceptance path.

```bash
dotnet build dotnet/PgExtWin.slnx --configuration Release
dotnet run --project dotnet/tests/PgExtWin.Contract.Tests --configuration Release --no-build
dotnet run --project dotnet/src/PgExtWin.Cli -- list --catalog-dir . --pg 18
dotnet run --project dotnet/src/PgExtWin.Cli -- search cron --catalog-dir .
```

A **separately administrator-authenticated** P1 policy and SHA256 are mandatory for
a real download. The hash must arrive by an independently authenticated channel,
not merely by copy/pasting it from the same Catalog, GitHub API or snapshot.
The output directory must already exist, be link-free and not contain a colliding
filename. This command is NOT executed in CI and does not authenticate signatures:

```bash
dotnet run --project dotnet/src/PgExtWin.Cli -- download pg_cron --pg 18 \
  --catalog-dir /trusted/catalog-snapshot --policy /independently/approved/policy.json \
  --policy-sha256 OUT_OF_BAND_64_HEX_DIGEST --output /private/staging
```

It checks all pinned Catalog raw SHA256s, numeric Repo/Release/asset ID inventories,
release/tag/asset metadata and 1 original ZIP's streamed actual bytes with a 64MiB
cap, and writes to a collision-free private staging filename before no-overwrite
rename. Explicit HTTPS GET only; auto-redirect disabled, bounded manually to
approved GitHub asset transport hosts. All evidence stays **INTEGRITY_ONLY**:
`SIGNATURE_VERIFIED=0` / `PUBLISH=DENY`, including when the digest matches.

Tests use synthetic P1 policy, in-memory ZIP and a fake HTTP transport with
no external network/credentials. No real 70 ZIP rehash or Sigstore run has occurred.
P1 BLOCKED, P2 NO-GO, formal publication DENY, `publicationAuthorized=false`.
