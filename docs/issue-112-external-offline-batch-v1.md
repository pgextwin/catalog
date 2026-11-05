# External original ZIP batch verification — Issue #112 (nonpublishing pilot)

Status: **local offline verification implemented; network bulk acquisition remains DOWNLOAD_DENY**.

This adds a reusable .NET verification step without changing native download-all.
It uses ExternalOriginalZipIntegrity.Verify for unchanged provider ZIPs, returning
success only after the entire selected set has verified.

## 日本語

提供元からユーザーが別途取得済みの外部ZIPを一括して整合性検証します。
外部提供元からの自動ダウンロード、配布承認、ミラー、インストールではありません。

配置例：

~~~text
C:\original-external\
  pg18\
    oracle_fdw\
      oracle_fdw-2.9.0-pg18-win64.zip
    pgvector\
      vector.v0.8.7-pg18.zip
~~~

CLI実行：

~~~powershell
.\pgextwin.exe verify-external-all --ledger .\evidence\issue112-external-pg18-direct-link-review-v1.json --input-dir C:\original-external --pg 18
~~~

全件成功時のみ EXTERNAL_BULK_INTEGRITY_ONLY ZIP_COUNT=... BYTES=...
が出力されます。原本の不足、サイズ・SHA256不一致、危険なZIPエントリ、
重複IDや提供元のすり替え、認可フラグの偽装は DENY / exit 2 です。
取得済み原本の署名・来歴・ABI・ライセンス・配布権限は認証しません。

## English: contract and boundaries

Inputs: versioned review ledger, local original ZIP root, PG major or all.
Original ZIP placement: INPUT/pgMAJOR/EXTENSION/ASSET_NAME.

- Reuses exact SHA256, byte-size and ZIP structural checks. Originals are never
  extracted, executed, overwritten, copied, installed or redistributed.
- Verifies provider-hosted GitHub release URL format, numeric provider asset identity,
  file-name safety, duplicate identifiers and case-insensitive path collisions.
- Requires false publication/download/mirror flags. A local review ledger is
  **untrusted evidence, not a signed external download authorization**.
- All-or-nothing result and no network calls. No partial successful result.
- Supports multiple original providers without assuming native pgextwin ZIP naming.

The protected Catalog review ledger for the initial PG18 pair is:
evidence/issue112-external-pg18-direct-link-review-v1.json .
This is a nonpublishing reference, not a source authorization.

Existing authenticated native download-all is unchanged. CLI external automatic
download remains DENY. Operators may independently retrieve provider ZIPs under
their own applicable terms; this feature is only local integrity verification.

## Follow-on implementation, not yet completed

For real CLI external network bulk acquisition, first establish reviewed protected
source-specific original-provider admission and independently signed external
Catalog pins. After that, add a provider GET-only adapter reusing existing
all-or-nothing batch output, without altering native release transports.
No current policy false flags are changed or bypassed.

Synthetic test coverage: successful two-provider bulk, invalid PG, tampered original
bytes and SHA256, missing file, forged permission, substituted provider URL and
duplicate asset IDs. Does not claim any new live provider GET or Publisher success.
