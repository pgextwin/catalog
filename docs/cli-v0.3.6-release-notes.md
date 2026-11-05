# pgextwin CLI v0.3.6 — local external original ZIP batch verification

## 日本語

v0.3.6 は保護された Catalog main に追加済みの `verify-external-all` を、Windows x64 自己完結型CLIで提供するためのバージョンです。

このコマンドは **ユーザーが別途取得して配置した、変更のない外部提供元ZIPをローカルで一括検証** します。既存の `ExternalOriginalZipIntegrity` を再利用し、サイズ・SHA256・ZIP構造・提供元Release/Asset同一性・重複とパストラバーサルを検証します。全件合格した場合のみ成功を返します。

~~~powershell
.\pgextwin.exe verify-external-all --ledger .\evidence\issue112-external-pg18-direct-link-review-v1.json --input-dir C:\original-external --pg 18
~~~

台帳原本: [PG18外部2件の非公開参照用台帳](../evidence/issue112-external-pg18-direct-link-review-v1.json)。
配置形式と終了コード: [オフライン一括検証ガイド](issue-112-external-offline-batch-v1.md)。

**機能の限界:** ZIPの取得、署名・来歴の認証、配布認可、ミラー、展開、インストールは一切行いません。ローカル台帳は未認証の検証用データであり、独立署名済み外部Catalogではありません。`download-all --source external|all` は引き続き `DOWNLOAD_DENY` / exit 2 です。ネイティブCatalogからの通常の `download-all` は変更ありません。

CLI本体の新規公開は既存の保護main → private Windows候補 → 独立Sigstore検証 → create-only Release → 公開EXE実バイト再取得のワークフローだけで行います。コマンドの追加は外部バイナリ自体の配布承認ではありません。

## English

CLI v0.3.6 makes the previously merged `verify-external-all` command available in the Windows x64 single-file CLI. It verifies **locally pre-obtained, unmodified provider ZIPs only**, using exact size, SHA256, safe ZIP structure, pinned provider identity and all-or-nothing processing.

~~~powershell
.\pgextwin.exe verify-external-all --ledger .\evidence\issue112-external-pg18-direct-link-review-v1.json --input-dir C:\original-external --pg 18
~~~

The ledger is an untrusted review reference, **not** independently signed distribution authorization. No external HTTP GET, mirror, repackaging, installation or Sigstore verification of original provider ZIPs is performed. `download-all --source external|all` remains `DOWNLOAD_DENY`; native download-all remains unchanged.

The CLI versioned Release remains subject to existing protected-main, genuine Windows binary, independent signing, create-only and public-byte verification gates. See [the offline batch contract](issue-112-external-offline-batch-v1.md).
