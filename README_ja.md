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
- PostgreSQL互換性をメジャーバージョン単位で明示
- 未公開・未検証のbuildを「利用可能」として登録しない

Websiteと将来の `pgextwin` CLIが同じデータを安全に利用できるよう、catalog schemaをversion管理します。

## 現在のmilestone

初期8 Extension（pg_bigm、pg_cron、pg_hint_plan、pgAudit、set_user、pg_repack、pg_ivm、pg_qualstats）はすべてPostgreSQL 14〜18向けWindows x64 Releaseまで公開済みで、このcatalogにも8件すべて登録済みです。**Initial extension roadmap: 完了。**

このmilestoneでは現行のcatalog schema v1を維持します。schema v2やpackage metadata拡張は後続の独立した作業として扱います。
