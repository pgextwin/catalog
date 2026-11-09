# pgextwin CLI v0.3.6 — local external original ZIP batch verification

## 日本語

v0.3.6では、保護されたCatalogのmainブランチに追加済みの `verify-external-all` を、Windows x64向けの自己完結型CLIで提供します。

このコマンドは、**利用者が別途取得・配置した、変更されていない外部提供元の原本ZIP** をローカルで一括検証します。既存の `ExternalOriginalZipIntegrity` を使用し、サイズ・SHA256・ZIP構造・提供元ReleaseとAssetの同一性・重複・パストラバーサルを検証します。すべて合格した場合にのみ成功を返します。

~~~powershell
.\pgextwin.exe verify-external-all --ledger .\evidence\issue112-external-pg18-direct-link-review-v1.json --input-dir C:\original-external --pg 18
~~~

台帳原本: [PG18外部2件の非公開参照用台帳](../evidence/issue112-external-pg18-direct-link-review-v1.json)。
配置形式と終了コード: [オフライン一括検証ガイド](issue-112-external-offline-batch-v1.md)。

このコマンドは、ZIPの取得、署名・来歴の認証、配布認可、ミラー、展開、インストールを行いません。ローカル台帳は未認証の検証用データであり、独立して署名された外部Catalogではありません。v0.3.6時点では、`download-all --source external|all` は引き続き `DOWNLOAD_DENY` / exit 2 です。ネイティブCatalogからの通常の `download-all` に変更はありません。

CLI本体の新規公開は、保護されたmain → 非公開Windows候補 → 独立Sigstore検証 → create-only Release → 公開EXEの実バイト再取得、という既存のワークフローでのみ行います。このコマンドの追加によって、外部バイナリ自体の配布が承認されるわけではありません。

## English

CLI v0.3.6 makes the previously merged `verify-external-all` command available in the Windows x64 single-file CLI. It verifies **locally pre-obtained, unmodified provider ZIPs only**, using exact size, SHA256, safe ZIP structure, pinned provider identity and all-or-nothing processing.

~~~powershell
.\pgextwin.exe verify-external-all --ledger .\evidence\issue112-external-pg18-direct-link-review-v1.json --input-dir C:\original-external --pg 18
~~~

The ledger is an untrusted review reference, **not** independently signed distribution authorization. No external HTTP GET, mirror, repackaging, installation or Sigstore verification of original provider ZIPs is performed. `download-all --source external|all` remains `DOWNLOAD_DENY`; native download-all remains unchanged.

The CLI versioned Release remains subject to existing protected-main, genuine Windows binary, independent signing, create-only and public-byte verification gates. See [the offline batch contract](issue-112-external-offline-batch-v1.md).
