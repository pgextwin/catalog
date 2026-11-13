# Issue #112 — verified public CLI external original GET (GET-only)

[日本語](#日本語) | [English](#english)

## 日本語

**提供元からの原本ZIP直接取得に限定。** pgextwinは外部ZIPを再配布・ミラー・再圧縮・インストールしません。
公開CLIと**期限内の**Build/main由来の署名付き取得認可がそろい、Catalogの保護mainにある
最新選択と原本のRelease・Asset ID／サイズ／SHA256が一致するときだけ取得します。
期限切れ、署名不正、未承認の拡張・PGメジャー・バージョン、権限不足は **DENY** です。

[正式CLI v0.3.15 Release](https://github.com/pgextwin/catalog/releases/tag/cli-v0.3.15)
から `pgextwin.exe` と `SHA256SUMS.txt` を取得し、実行ファイルのSHA256を確認してください。
出力先フォルダーは事前に作成し、Windows PowerShellで実行します。

```powershell
# 認可済みの最新原本を、観測済みの全PGメジャーについて一括取得
.\pgextwin.exe download-all --source external --pg all --output C:\pgextwin-originals

# PG18だけ
.\pgextwin.exe download-all --source external --pg 18 --output C:\pgextwin-originals

# 拡張名＋バージョン指定（署名済み最新選択に存在するものだけ）
.\pgextwin.exe download-all --source external --pg all --extension oracle_fdw --version 2.9.0 --output C:\pgextwin-originals
```

`--extension` と `--version` は、追加の提供元や過去のリリースを許可するオプションではありません。
`--version` は `--extension` と併用し、正確に署名済みの対象だけを絞ります。
`--pg all` は**全PGに対する互換性の保証ではなく**、署名済みで登録されたPGメジャーの原本を選びます。
CLIはダウンロードしたZIPを新しいサブディレクトリへまとめて確定し、一部失敗したセットを成功扱いしません。

**2026-11-13 11:00 JSTに成功が確認された範囲**：
`oracle_fdw` 2.9.0（PG14～18：5 ZIP）、
コミュニティ版 `pgvector` 0.8.7（PG14～18：5 ZIP）、
`pg_trickle` 0.108.3（PG18：1 ZIP）、計 **11 ZIP / 9,743,563 bytes**。
[Windows E2E Run 43348662236](https://github.com/pgextwin/catalog/actions/runs/43348662236)
で正式ReleaseのCLIを認証し、全11件の原本サイズ・SHA256照合に成功しました。
これは**その時点の認可・動作証跡**であり、将来の署名期限や新しいバージョンへの永続的な許可ではありません。

GitHubの匿名REST APIは時間枠の制限を受けます。HTTP 403のときは、
認可期限とレート制限を区別してください。必要なら適切な読み取り権限の
`GH_TOKEN` または `GITHUB_TOKEN` をプロセス環境に設定できます。
トークンをコマンド引数・ログ・Issueへ書き込まないでください。
認可の更新や署名チェックの迂回はできません。

**未認可の追加提供元**：PostGIS / pgRouting（OSGeoバンドル）、PGroonga、
TimescaleDB等の調査・検証は正式取得認可と別です。
候補JSONや独立SHA256の一致だけでは、公開CLIの取得対象には追加されません。
OSGeoの最新バンドル1件の選択は現時点では**非公開のレビュー計画**です。

原本のZIPの取得は、ライセンス上の再配布許諾やWindowsでの動作、
Oracle Instant Client等の別途必要な依存ファイルの提供を意味しません。
ZIPの適用・インストールについては提供元の手順とライセンスを確認してください。

## English

The published CLI can perform a user-local **direct original-provider GET**,
not a mirror, repackage, redistribution or installation. It requires a
nonexpired independent Build/main Sigstore admission bound to the current
protected Catalog latest selection and exact release/asset/byte identities.
There is **no unsigned or historical fallback**.

Download `pgextwin.exe` and `SHA256SUMS.txt` from the
[CLI v0.3.15 Release](https://github.com/pgextwin/catalog/releases/tag/cli-v0.3.15)
and verify its SHA256 before running. Create the output parent directory first.

```powershell
.\pgextwin.exe download-all --source external --pg all --output C:\pgextwin-originals
.\pgextwin.exe download-all --source external --pg 18 --output C:\pgextwin-originals
.\pgextwin.exe download-all --source external --pg all --extension pgvector --version 0.8.7 --output C:\pgextwin-originals
```

`--pg all` selects only **individually admitted** PostgreSQL majors, not
unobserved compatibility. `--version` requires `--extension` and filters
the **current signed** cohort; it cannot authorize an unsigned older version.
The original ZIPs are verified as a single atomic batch in a new output
subdirectory, with no successful partial commit.

At 2026-11-13 11:00 JST, genuine Windows
[E2E Run 43348662236](https://github.com/pgextwin/catalog/actions/runs/43348662236)
verified the published CLI v0.3.15 and 11 original ZIPs / 9,743,563 bytes:
oracle_fdw 2.9.0 (PG14–18), community pgvector 0.8.7 (PG14–18),
and pg_trickle 0.108.3 (PG18). This is a historical passing observation,
not a permanent admission; expired signed admissions fail closed.

Anonymous GitHub REST quotas can yield HTTP 403; a read-scoped environment
`GH_TOKEN` or `GITHUB_TOKEN` may be used for authenticated checks.
Never expose tokens or bypass the expiry or signed admission. PostGIS,
pgRouting, PGroonga and TimescaleDB remain **review candidates, not
publicly admitted GET-only sources**. Verify provider licenses,
dependencies and installation prerequisites separately.
