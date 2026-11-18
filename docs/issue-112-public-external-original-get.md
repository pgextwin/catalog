# Download original external Windows ZIPs with the CLI

[日本語](#日本語) | [English](#english)

## 日本語

Windows CLI v0.3.17以降は、[原本取得用カタログ](../external/direct-get.json)に
バージョンごとのライセンス確認記録があるZIPを、提供元から直接取得します。
各ZIPのSHA-256とバイト数を照合し、すべての照合が済んだ時点で新しいサブフォルダーに保存します。

[CLIのリリース一覧](https://github.com/pgextwin/catalog/releases)から
v0.3.17以降の `pgextwin.exe` と `SHA256SUMS.txt` を取得し、
実行ファイルのSHA-256を確認してください。PowerShellで出力先を作成してから実行します。

```powershell
New-Item -ItemType Directory -Force C:\pgextwin-originals
.\pgextwin.exe download-all --source external --pg all --output C:\pgextwin-originals
.\pgextwin.exe download-all --source external --pg 18 --output C:\pgextwin-originals
.\pgextwin.exe download-all --source external --pg 14 --extension oracle_fdw --version 2.9.0 --output C:\pgextwin-originals
```

`--pg all` はカタログに記録のある全PGメジャーから最新として指定された版を取得します。
バージョンを指定する場合は `--extension` と `--version` を併用してください。
PostGISとpgRoutingは、どちらを選んでも該当する同じバンドルを取得します。
ZIPの利用前に、提供元のライセンス、インストール手順、依存関係を確認してください。
oracle_fdwに必要なOracle Clientは別途入手します。

v0.3.16以前の署名付き取得認可には有効期限があります。
期限付きの認可なしで取得するにはv0.3.17以降が必要です。

## English

Windows CLI v0.3.17 and later retrieve original ZIPs directly from providers
using the [direct GET catalog](../external/direct-get.json). Each record carries
license evidence for its version, the provider URL, and the original SHA-256
and size. The CLI commits the ZIPs to a new local subdirectory after the
whole batch passes verification.

Get `pgextwin.exe` and `SHA256SUMS.txt` for v0.3.17 or later from
[CLI releases](https://github.com/pgextwin/catalog/releases) and check the
executable's SHA-256. Create the output parent before running the CLI.

```powershell
New-Item -ItemType Directory -Force C:\pgextwin-originals
.\pgextwin.exe download-all --source external --pg all --output C:\pgextwin-originals
.\pgextwin.exe download-all --source external --pg 18 --output C:\pgextwin-originals
.\pgextwin.exe download-all --source external --pg all --extension pgvector --version 0.8.7 --output C:\pgextwin-originals
```

`--pg all` selects the records marked latest across the listed PostgreSQL majors.
Use `--version` with `--extension` to select an exact recorded older or current
version. Selecting either PostGIS or pgRouting fetches its shared provider ZIP.
Check the provider's licenses, installation instructions, and dependencies
before using a ZIP. For oracle_fdw, obtain Oracle Client separately.

The v0.3.17 catalog includes 23 ZIPs. That covers oracle_fdw 2.9.0 and community
pgvector 0.8.7 for PG14–18, pg_trickle 0.108.3 for PG18, and pglogical 2.4.8,
pg_crash 0.3, and shared PostGIS/pgRouting bundles for PG15–18.
The [2026-11-13 Windows E2E run](https://github.com/pgextwin/catalog/actions/runs/43348662236)
records the 11 ZIPs verified under the old signed-admission flow. Upgrade
from v0.3.16 to remove the external admission expiry from the CLI.
