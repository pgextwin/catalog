# pgextwin catalog

[English](README.md) | **日本語**

**pgextwin** が公開するPostgreSQL ExtensionのWindows x64バイナリについて、機械可読な配布metadataを管理します。

Catalogはmetadataのみを保持します。バイナリ、checksum、SBOM、vulnerability report、Attestationの正規実体は、各Extension repositoryのGitHub Release / GitHub Artifact Attestationsにあります。

## 構成

```text
index.json
schema/
  index.schema.json
  extension.schema.json
extensions/
  <extension>.json
scripts/
  validate_catalog.py
tests/
  test_validate_catalog.py
```

## Catalog schema v2

schema v2は、現行Websiteが利用しているv1 fieldを維持しつつ、将来のWebsite/CLI向けに安定したmachine-readable distribution metadataを追加します。

後方互換のため次を維持します。

- `displayName`
- `description`
- `upstream`
- `repository`
- `license`
- `architecture`
- `latest.releaseTag`
- `postgresql.<major>.available`
- `postgresql.<major>.asset`

v2では主に次を追加します。

- Release公開日時、canonical Release URL、checksum asset名
- PostgreSQL majorごとのcanonical direct download URLとSHA-256
- PostgreSQL majorごとのsupply-chain evidence提供状態
- Test Contract v2から投影した利用者向けruntime requirement
- 現在のCIが保証するcapability coverageとfunctional scenario
- exact commitへ固定した`capabilitiesSource`

## availabilityとmaintenanceは別概念

`postgresql.<major>.available` は引き続き**historical binary availability**です。

- `true`: そのPostgreSQL major向けの検証済みWindows x64 binary assetが公開済み
- `false`: そのような検証済み公開assetがCatalogに記録されていない
- PostgreSQLコミュニティが現在そのmajorをメンテナンスしている、という意味ではない

PostgreSQLのLifecycle/EOL日と現在のmaintenance状態は、引き続き [`pgextwin/build/metadata/postgresql.json`](https://github.com/pgextwin/build/blob/main/metadata/postgresql.json) だけを正規情報源とします。Extension recordへEOL日や日付依存の`maintained` booleanを複製しません。

PostgreSQLがEOLを迎えても、既存の公開binaryはhistorical downloadとして残り得ます。

## Direct downloadとSHA-256

`available: true` の各entryは、v2で次を必須とします。

```json
{
  "available": true,
  "asset": "example-pg18-windows-x64.zip",
  "downloadUrl": "https://github.com/pgextwin/example/releases/download/v1/example-pg18-windows-x64.zip",
  "sha256": "<64 lowercase hex>"
}
```

`downloadUrl` はrecordのrepository / release tag / asset filenameと一致する必要があります。CIのremote verificationは、現在公開中のGitHub Releaseから**実際の`SHA256SUMS.txt`**を取得し、CatalogのSHA-256と照合します。GitHubがrelease asset digestを返す場合はそれも追加照合します。

## Runtime requirements

`runtime.requirements` が、Test Contract v2から取得した利用者向けruntime snapshotの正規表現です。

- `extensionCreation`
- `preload`
- `backgroundWorker`
- `clientExecutable.required`
- `clientExecutable.packagePaths`

`runtime.sharedPreloadLibraries` は既存consumerとの後方互換のためだけに維持します。このfieldだけを見て「shared preloadが利用者に必須」と判断してはいけません。

Test Contract v2では、CIの`testSetup`と利用者の`runtimeRequirements`を意図的に分離しています。CIが`shared_preload_libraries`を使用していても、runtime requirementが`either`や`optional`である場合があります。

## Test Contract由来capability

`capabilities` は、`smoke-test.ps1`のimplementation detailを複製せず、現在のpgextwin CIが実際に何をassertしているかを公開します。

- Test Contract version
- CREATE EXTENSION coverage
- background worker coverage
- client executable coverage
- server log assertion coverage
- upgrade coverage
- stableなfunctional scenario ID / description
- evidence type
- 必要な場合のPostgreSQL major scope

coverageはTest Contract v2と同じ`covered` / `not-covered` / `not-applicable`を使用します。

`capabilitiesSource`にはexact sourceを記録します。

```json
{
  "repository": "pgextwin/pg_cron",
  "path": "config/test-contract.json",
  "commit": "<40-character commit SHA>"
}
```

CIはこのimmutable commitのファイルを取得し、Catalog snapshotと意味的に一致することを検証します。`main`のようなmutable refはsource identityとして許可しません。

## Supply-chain evidence

各`available: true` binaryには、次のevidence状態を持たせます。

- Build Provenance Attestation
- SPDX SBOM Release asset
- SBOM Attestation
- vulnerability report Release asset

AttestationはRelease assetではないため、asset filenameを要求しません。

SBOM / vulnerability reportは、`available: true`ならasset filename、canonical download URL、SHA-256を必須とします。`available: false`なのに架空のasset情報を持つことは許可しません。

初期8 Extensionの現在公開中ReleaseはStep 6〜10導入前に作成されたhistorical Releaseで、実assetはPG14〜18 ZIPと`SHA256SUMS.txt`だけです。そのためv2 recordではBuild Provenance Attestation、SBOM asset、SBOM Attestation、vulnerability reportを正しく`available: false`としています。既存Releaseをretroactiveに変更しません。

Step 6〜10対応release pathで将来作成されるReleaseでは、実際にevidenceが存在するときだけ該当fieldを`available: true`へできます。

## Vulnerability reportはpoint-in-time evidence

Vulnerability reportは、特定のSBOMを特定時点のGrype vulnerability databaseと照合した結果です。恒久的なsecurity verdictではありません。

Catalogには`secure`、`safe`、`trusted`、`vulnerabilityFree`、mutableな`vulnerabilities: 0`のようなfieldを追加しません。

Step 10はreport-only baselineのままで、Catalog v2はrelease-specificなvulnerability reportが存在するかだけを表現します。

## Validation

local validation:

```text
python scripts/validate_catalog.py
python -m unittest discover -s tests -v
```

CIではさらに次を実行します。

```text
python scripts/validate_catalog.py --verify-remote
```

remote verificationは、immutableなTest Contract commitと現在のcanonical GitHub Releaseを確認し、Release identity、asset URL、公開`SHA256SUMS.txt`、Test Contract由来snapshotを照合します。requestには回数制限付きretryを行い、GitHub APIには`contents: read`のworkflow tokenを使用します。

## Catalog v2とWebsite v2の境界

Catalog v2はmachine-readable API contractです。**Website v2は今回実装しません。**

現行Websiteは上記のv1-compatible fieldをそのまま利用でき、PostgreSQL lifecycle metadataとは従来どおり表示時に結合します。将来のWebsite v2は、direct download integrity、runtime requirement、capability coverage、supply-chain evidenceを同じ意味のまま利用できます。
