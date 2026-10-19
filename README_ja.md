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

## GitHubのみで正式ReleaseをCatalogへ反映（追加App不要）

これは**認証済み担当者による操作を含む代替経路**であり、無人で正式公開する仕組みではありません。未署名の候補、失敗したPromotion、公開前のDraftを正式Release扱いしません。

1. **実際に公開済み**で不変の、担当者が明示的に`PUBLISH`した正式Releaseのみを対象にします。候補やmainのWindowsビルド成功だけでは不足です。[署名付き正式Releaseの読み取り専用検証Workflow](https://github.com/pgextwin/catalog/actions/workflows/verify-manual-release.yml) を保護された`main`から開き、対象拡張と公開済み`release_tag`を指定し、GitHubの認証済み「Run workflow」で実行します。ローカルPC・VM・Private Writerは不要です。
2. Run全体の**SUCCESS**を確認します。公開ZIP/SPDX/Grypeの実バイトSHA256、GitHub Attestation、固定ソース・mainでの正式Promotion成功、Catalog schemaとオフライン・リモート検証が必要です。失敗Runの免除、古いArtifactの流用は禁止です。
3. そのRunの`verified-manual-release-record` Artifactを取得し、認証済みGitHub接続またはGUIで現在の`catalog/main`と比較します。検証済みの`extensions/<extension>.json` **1件だけ**を変更する保護PRを作成します。古いレコードへの巻戻し、競合PR、無関係な変更、main変化による不一致は停止します。この読取専用Workflow自体はPRを作成・承認・マージしません。**手動PR経路では専用提案Appの導入は必須ではありません。**
4. PRの正確なheadに対する必須Catalog CIを通してからマージします。その後、[CatalogからWebsiteへの公開監査](https://github.com/pgextwin/catalog/actions/workflows/notify-website.yml) と日本語・英語サイト、ZIP直リンク、SHA256を確認します。別コミットの成功結果やスケジュール実行を代替の証拠にしません。

現在の通常ChatのGitHub接続でWorkflow Dispatchを起動できない場合、**GitHub上の「Run workflow」操作だけ**は認証済み担当者が行います。専用AppやVMの導入は要求しません。未達成の正式公開ゲートは迂回せず、公開前にはCatalog/Websiteを新Releaseへ進めません。運用上の制約は[公開サイト末尾](https://pgextwin.github.io/website/ja/)にも記載しています。

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

## 独立したWindows Extension Landscape Registry (v1)

ルートの `index.json` / `extensions/*.json` は、**pgextwinが実際に公開したバイナリだけ**を扱うCatalog v2です。独立した `landscape/index.json` / `landscape/extensions/*.json` は、配布済み（Catalog参照のみ）、今後の候補、pgextwinでは当面実装しない拡張機能と外部取得先を扱います。`available` の意味やReleaseのSHA-256は変更しません。

外部取得先の公開・商用条件、通常PostgreSQLとの互換性、公式/コミュニティ/ベンダー/パッケージマネージャの区別を記録します。`not-planned` は利用不可・非互換の意味ではありません。`lastReviewed` は最終レビュー日であり、現在も有効という保証ではありません。候補の優先順位は暫定です。

独立validatorは `python scripts/validate_landscape.py`。CIでdistribution Catalogと別々に検証します。
