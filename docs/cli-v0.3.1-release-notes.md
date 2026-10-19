# pgextwin CLI v0.3.1 — 83.83% smaller Windows executable

## English

### Highlights

The Windows x64 self-contained, single-file `pgextwin.exe` is now **12.83 MB (12,827,362 bytes)**, down from **79.34 MB (79,338,604 bytes)** in v0.3.0 — an **83.83% reduction**.

- Full .NET 10 trimming and single-file compression, with trim-safe, source-generated `System.Text.Json` serialization. The original IL2026 warnings were resolved rather than suppressed.
- The default one-line command continues to download the **latest Catalog-registered releases**, currently **14 extensions × PostgreSQL 14–18 = 70 original ZIPs**.
- The Catalog selection feed is independently verified using Sigstore, including its signer identity, source commit and immutable Catalog hashes, without requiring anonymous GitHub REST API access.
- Each downloaded original ZIP is checked against its approved SHA256; incomplete batches are discarded and existing output is never overwritten.
- `--fixed` retains the historical immutable Catalog snapshot for explicit compatibility/rollback.

### Get started

Download [pgextwin.exe for Windows x64](https://github.com/pgextwin/catalog/releases/download/cli-v0.3.1/pgextwin.exe) and [SHA256SUMS.txt](https://github.com/pgextwin/catalog/releases/download/cli-v0.3.1/SHA256SUMS.txt).

```powershell
.\pgextwin.exe download-all --pg all
.\pgextwin.exe download-all --pg 18
.\pgextwin.exe download-all --pg all --fixed
```

Other commands include read-only local Catalog `list` and `search`. Local Catalog listing remains explicitly `UNVERIFIED`.

### Security and verification

**The CLI executable and the Catalog selection feed are Sigstore-verified. Individual extension ZIPs are not individually Sigstore-authenticated**: their SHA256 is rechecked, but their status remains **`INTEGRITY_ONLY`**. No extension signature/provenance verification, installation, service modification, offline bundle, or distribution/publication authorization is implied. CLI v0.3.1 is a GitHub prerelease, **not** a Windows Authenticode-signed installer.

- Published EXE SHA256: `baee38b3aafdd1bbb7f61857747358dbd40ab056d989aa0f753c93b2025a7580`
- Original signed build source: `a7a1d93d38d7338d80404c402eb5faaaa96b272e`
- [Original protected-main R6 Sigstore build](https://github.com/pgextwin/catalog/actions/runs/39253153311) — SUCCESS
- [Release creation, checksum, SPDX and license verification](https://github.com/pgextwin/catalog/actions/runs/39253881898) — SUCCESS
- [Independent public EXE re-download, Sigstore and Windows 70/70 ZIP SHA256](https://github.com/pgextwin/catalog/actions/runs/39254657650) — SUCCESS

```powershell
Get-FileHash .\pgextwin.exe -Algorithm SHA256
gh attestation verify .\pgextwin.exe --repo pgextwin/catalog --signer-workflow pgextwin/catalog/.github/workflows/cli-candidate.yml --source-ref refs/heads/main --source-digest a7a1d93d38d7338d80404c402eb5faaaa96b272e
```

[Visual CLI guide (English)](https://pgextwin.github.io/website/en/cli.html) · [Visual CLI guide (Japanese)](https://pgextwin.github.io/website/ja/cli.html)

---

## 日本語

### 主な変更点

Windows x64向けの自己完結型・単一ファイル `pgextwin.exe` を、v0.3.0の **79.34 MB（79,338,604バイト）**から **12.83 MB（12,827,362バイト）**に軽量化しました。**削減率は83.83%**です。

- .NET 10の完全トリミングと単一ファイル圧縮を採用。JSON出力にはトリミング対応の`System.Text.Json`ソース生成方式を用い、IL2026警告を抑制するのではなく原因を修正しました。
- 標準の1行コマンドで**Catalogに登録された最新版**を取得します。現在は**14拡張×PostgreSQL 14～18の元ZIP計70件**です。
- Sigstore署名付きCatalog選択フィードの発行元・コミット・不変CatalogのSHA256を独立検証します。GitHub匿名REST APIの利用は不要です。
- 各ZIPのSHA256を再計算し、不一致や一部失敗の場合には出力を確定させません。既存ファイルの上書きも行いません。
- `--fixed` で過去の不変Catalogスナップショットを明示的に利用できます。

### 使い方

[Windows x64用 pgextwin.exe](https://github.com/pgextwin/catalog/releases/download/cli-v0.3.1/pgextwin.exe) と [SHA256SUMS.txt](https://github.com/pgextwin/catalog/releases/download/cli-v0.3.1/SHA256SUMS.txt) を取得してください。

```powershell
.\pgextwin.exe download-all --pg all
.\pgextwin.exe download-all --pg 18
.\pgextwin.exe download-all --pg all --fixed
```

ローカルCatalogを読み取る `list`／`search` にも対応しています。ローカルの一覧情報は明示的に `UNVERIFIED` です。

### 安全性と検証証跡

**Sigstore検証済みなのはCLI本体とCatalog選択フィードです。拡張ZIPの個別の真正署名が検証されたわけではありません。** 拡張ZIPはSHA256によるバイト整合性のみで、状態は **`INTEGRITY_ONLY`** です。個別ZIPの署名・来歴・導入・サービス変更・オフライン統合ZIP・配布／公開認可は成立していません。CLI v0.3.1は公開済みのプレリリースであり、Windows Authenticode署名付きインストーラーではありません。

- 公開EXEのSHA256：`baee38b3aafdd1bbb7f61857747358dbd40ab056d989aa0f753c93b2025a7580`
- 署名済み元ビルドのソースコミット：`a7a1d93d38d7338d80404c402eb5faaaa96b272e`
- [保護main上のR6署名・検証](https://github.com/pgextwin/catalog/actions/runs/39253153311)：SUCCESS
- [Release作成・SHA256・SPDX・ライセンス検証](https://github.com/pgextwin/catalog/actions/runs/39253881898)：SUCCESS
- [公開EXEの再取得・Sigstore検証・Windows 70 ZIP全件SHA256再検証](https://github.com/pgextwin/catalog/actions/runs/39254657650)：SUCCESS

```powershell
Get-FileHash .\pgextwin.exe -Algorithm SHA256
gh attestation verify .\pgextwin.exe --repo pgextwin/catalog --signer-workflow pgextwin/catalog/.github/workflows/cli-candidate.yml --source-ref refs/heads/main --source-digest a7a1d93d38d7338d80404c402eb5faaaa96b272e
```

[Website図解（日本語）](https://pgextwin.github.io/website/ja/cli.html) · [Website visual guide (English)](https://pgextwin.github.io/website/en/cli.html)
