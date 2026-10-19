# pgextwin CLI v0.3.1 — Windows x64 EXE lightweight release

## Preserved CLI behavior

```powershell
.\pgextwin.exe download-all --pg all
.\pgextwin.exe download-all --pg all --fixed
```

The default still independently verifies the genuine GitHub Actions Sigstore-signed
Catalog feed and downloads all 14 × PostgreSQL 14–18 original extension ZIPs via
bounded HTTPS/redirects and per-file SHA256. The `--fixed` mode retains the
historical immutable Catalog/policy. No extension install, signature authenticity
claim, privilege escalation, Publisher or P1 safety override was added.

## 2026-10-19 private Windows size tests (same .NET 10.0.402 + 10.0.13 runtime)

| Configuration | Windows EXE original bytes | Reduction vs v0.3.0 | Real PG18 ZIP SHA256 | Signed feed |
|---|---:|---:|---|---|
| v0.3.0 published, no trim or compression | 79,338,604 | baseline | previously 70/70 | success |
| v0.3.0 compression only | 40,452,771 | 49.01% | 14/14 PASS | success |
| compression only after source-generator changes | 40,469,202 | 48.99% | 14/14 PASS | success |
| compression + `PublishTrimmed=true`, `TrimMode=partial` | 15,218,396 | 80.82% | 14/14 PASS | success |
| **compression + `PublishTrimmed=true`, `TrimMode=full`** | **12,827,394** | **83.83%** | **14/14 PASS** | **success** |

Proof for second trial:
https://github.com/pgextwin/catalog/actions/runs/39251994011

Both trimming modes initially failed with the real `IL2026` warning under
`TreatWarningsAsErrors`: a dynamically typed `JsonSerializer.Serialize()`
in `BatchReleaseDownloader`. Rather than suppressing IL2026 or disabling
warnings, we converted both the batch receipt and the local Catalog listing to
explicit source-generated `JsonSerializerContext` types. The JSON property
names and original denial flags are unchanged and tested. The final full-trim
Windows candidate passed `--version`, `--help`, local JSON listing, explicit
security DENY, genuine anonymous signed Catalog feed verification and 14/14
actual original PG18 ZIP rehashing.

## Reproducible production build

```powershell
dotnet publish dotnet/src/PgExtWin.Cli/PgExtWin.Cli.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:RuntimeFrameworkVersion=10.0.13 -p:PublishTrimmed=true -p:TrimMode=full -p:EnableCompressionInSingleFile=true -p:DebugType=none -p:DebugSymbols=false -o out --nologo
```

Production R6 candidate and PR Windows smoke apply exactly the same flags.
Sigstore feed's source identity, signer workflow, SHA and verified timestamp
remain required at runtime. If trim warnings or runtime verification regress,
the build/test is FAIL, not a success or a justification to bypass protections.

## Acceptance remaining for this v0.3.1 implementation

- Fresh protected PR mandatory Validate + private Windows build/smoke +
  **exact default no-token 70 original ZIP real SHA256**.
- After protected merge: exact-main postmerge Validate, full 70 ZIP,
  independent signed R6 actual Windows EXE and exact SHA256.
- Separately reviewed/create-only v0.3.1 CLI-only R7 release intent pinning
  original successful R6 run/SHA/EXE hash. Published original EXE must be
  independently re-downloaded and tested against the genuine Sigstore
  attestation and actual default 70 ZIP.
- Preserve stable metadata-only Catalog feed `releases/latest` pointer;
  CLI is published as prerelease with `--latest=false`.
