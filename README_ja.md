# pgextwin catalog

[English](README.md) | **日本語**

**pgextwin** が公開するPostgreSQL拡張機能のWindows x64バイナリについて、機械可読なメタデータを管理するリポジトリです。

バイナリそのものはこのリポジトリには保存せず、各Extension repositoryのGitHub Releasesを正規の配布元とします。

## 構成

```text
index.json
schema/
  extension.schema.json
extensions/
  <extension>.json
```

## 方針

- 1 Extensionにつき1つのcatalog record
- バイナリはcommitしない
- download先は各Extensionの正規GitHub Release
- upstreamとlicenseを必ず記録
- PostgreSQL majorごとのバイナリ公開状況を明示
- 未公開・未検証のbuildを「利用可能」として登録しない

Websiteと将来の `pgextwin` CLIが同じデータを安全に利用できるよう、catalog schemaをversion管理します。

## バイナリの利用可能性とPostgreSQL Lifecycle

Catalog schema v1では、**過去を含むバイナリの利用可能性**と**現在のPostgreSQLメンテナンス状態**を意図的に別概念として扱います。

`postgresql.<major>.available` は次の意味です。

- `true`: そのPostgreSQL major向けの検証済みWindows x64バイナリassetが公開済み
- `false`: そのような検証済み公開assetが現在catalogに記録されていない
- PostgreSQLコミュニティが現在そのmajorをメンテナンスしている、という意味ではない

PostgreSQLのEOL日と現在のmaintenance状態は、正規のLifecycle metadataである [`pgextwin/build/metadata/postgresql.json`](https://github.com/pgextwin/build/blob/main/metadata/postgresql.json) から導出します。Websiteは表示時にCatalog recordとこのmetadataを組み合わせます。

各Extension JSONへ日付依存の `maintained` booleanやPostgreSQL EOL日を重複保存しません。PostgreSQLがEOLを迎えても、別の理由で明示的に撤回しない限り、既存の公開済みassetは保持します。

## 現在のmilestone

初期8 Extension（pg_bigm、pg_cron、pg_hint_plan、pgAudit、set_user、pg_repack、pg_ivm、pg_qualstats）はすべてPostgreSQL 14〜18向けWindows x64 Releaseまで公開済みで、このcatalogにも8件すべて登録済みです。**Initial extension roadmap: 完了。**

Catalog schema v1を引き続き維持します。schema v2やpackage metadata拡張は後続の独立した作業として扱います。
