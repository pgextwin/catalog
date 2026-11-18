# Download original external Windows packages with the CLI

[日本語](#日本語) | [English](#english)

## 日本語

Windows x64版CLI v0.3.18では、PostgreSQLが入っていないPCでも、外部提供元の拡張機能、
空間拡張バンドル、ツール、ドライバーを取得できます。[CLIのリリース一覧](https://github.com/pgextwin/catalog/releases)から
`pgextwin.exe` と `SHA256SUMS.txt` を取得し、実行ファイルのSHA-256を確認してください。

```powershell
New-Item -ItemType Directory -Force C:\pgextwin-originals
.\pgextwin.exe download pgvector --version 0.8.7 --pg 18 --output C:\pgextwin-originals
.\pgextwin.exe list --category spatial --pg 14
.\pgextwin.exe search odbc --category drivers
.\pgextwin.exe download psqlodbc --output C:\pgextwin-originals
.\pgextwin.exe download postgis --pg 14 --version 3.6.2 --output C:\pgextwin-originals
.\pgextwin.exe download-all --source external --category tools --output C:\pgextwin-originals
```

カテゴリは `extensions`（拡張機能）、`spatial`（空間拡張）、`tools`（ツール）、`drivers`（ドライバー）です。
`--pg` では取得対象のPostgreSQLメジャーバージョンを指定します。バージョンに依存しないファイルも取得対象になります。
`--pg` を省くと、カタログに記録されたすべてのPostgreSQLメジャーバージョンが対象になります。
名前を指定して取得するには `download ITEM` を使います。`--version EXACT` を付けるとカタログに記録された版を指定でき、
省略すると最新として記録された版を取得します。複数のパッケージをまとめて取得するには `download-all` を使います。
PostGISとpgRoutingは同じバンドルを取得します。

すべてのファイルのSHA-256とバイト数を確認してから、出力先に新しいサブフォルダーを作って原本をまとめて保存します。
CLIはファイルの展開や実行を行いません。ライセンスの根拠と照合値は[拡張機能カタログ](../external/direct-get.json)と
[追加パッケージのカタログ](../external/standalone-get.json)で確認できます。oracle_fdwに必要なOracle Clientは別途入手します。

署名付きpgextwinフィードから取得する場合は `download-all --pg 18`、個別取得には
`download pg_cron --source pgextwin --pg 18` を使います。

## English

Windows x64 CLI v0.3.18 downloads original external extensions, spatial
bundles, tools, and drivers on a PC without PostgreSQL. Get `pgextwin.exe` and
`SHA256SUMS.txt` from the [CLI releases](https://github.com/pgextwin/catalog/releases)
and verify the executable's SHA-256. Use an existing output directory or omit
`--output` to use the current directory.

```powershell
New-Item -ItemType Directory -Force C:\pgextwin-originals
.\pgextwin.exe download pgvector --version 0.8.7 --pg 18 --output C:\pgextwin-originals
.\pgextwin.exe list --category spatial --pg 14
.\pgextwin.exe search odbc --category drivers
.\pgextwin.exe download psqlodbc --output C:\pgextwin-originals
.\pgextwin.exe download postgis --pg 14 --version 3.6.2 --output C:\pgextwin-originals
.\pgextwin.exe download-all --source external --category tools --output C:\pgextwin-originals
```

Categories are `extensions`, `spatial`, `tools`, and `drivers`. Browse with
`list` or `search TERM`. Add `--format json` for structured results.
`--pg` filters by the target PostgreSQL major, with major-independent packages
available for any selection. The external default is all recorded majors.
Use `download ITEM` for a named package. Add `--version EXACT` for an exact
recorded version, or omit it for the version marked latest in the Catalog.
Use `download-all` for bulk selections.

PostGIS and pgRouting select the same bundle. PG14 uses the upstream installer
and PG15–18 use the existing OSGeo ZIPs. PgBouncer and psqlODBC use the projects’
Windows ZIPs. Check licenses, exact versions, provider URLs, and file pins in
the [external extension manifest](../external/direct-get.json) and the
[standalone package manifest](../external/standalone-get.json).
Oracle Client is a separate dependency of oracle_fdw.

Each download checks the original file’s SHA-256 and exact size. The CLI saves
a completed selection in a new subdirectory. For example, `download psqlodbc`
writes under `pgextwin-external-psqlodbc-all/any/psqlodbc/`. Files are left
intact. The CLI requires no EDB registration and performs no installation.

Use `download-all --pg 18` for the signed pgextwin feed, or
`download pg_cron --source pgextwin --pg 18` to select a single signed-feed
record. The v0.3.17 `--extension` option on external bulk downloads remains
available to existing scripts. Without a category filter, it still selects from
the earlier ZIP catalog and preserves the legacy receipt. Local `list` and `search`
continue to accept `--catalog-dir` with the existing local metadata formats.
