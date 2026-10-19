# pgextwin CLI v0.3.2 — verbose diagnostics for reliable Windows downloads

## English

### Changes in v0.3.2

- Add opt-in `--verbose` to the read-only CLI commands. Diagnostics with UTC timestamps go to **stderr**, leaving normal stdout, including JSON output, unchanged.
- Observe verification of the Sigstore-signed Catalog selection feed, all immutable Catalog JSON records, and the historical fixed SHA256-pinned Catalog.
- Trace each extension ZIP from download start through transfer progress (8 MiB intervals for the browser transport), byte count, independent SHA256 recheck, and atomic batch completion.
- Reject duplicate `--verbose` or invalid options without bypassing the fail-closed security policy.
- Preserve v0.3.1's trimmed and compressed, self-contained Windows x64 single-file distribution and latest-by-default / `--fixed` behavior.

### Usage

```powershell
.\pgextwin.exe download-all --pg all --verbose
.\pgextwin.exe download-all --pg 18 --fixed --verbose
.\pgextwin.exe download-all --pg all --verbose 2> download-verbose.log
```

[Download Windows x64 EXE](https://github.com/pgextwin/catalog/releases/download/cli-v0.3.2/pgextwin.exe) · [Checksums](https://github.com/pgextwin/catalog/releases/download/cli-v0.3.2/SHA256SUMS.txt) · [Detailed usage](https://github.com/pgextwin/catalog/blob/main/docs/cli-v0.3.2-verbose.md)

### Security and provenance

- EXE SHA256: `d4e8f63d402066b21db9d537f7679b51137ec47d9834fa4fd75b5889ad34e6f4`
- Source protected-main commit: `a537f14f39be4b4ffc366cd0fef83f87aa4b9c39`
- [Protected-main signed build and independent Sigstore check](https://github.com/pgextwin/catalog/actions/runs/39341486152) — SUCCESS
- [PR #134, validated Windows builds and real ZIP downloads](https://github.com/pgextwin/catalog/pull/134) — MERGED

The **EXE and signed Catalog feed have their own verified provenance**. Original extension ZIPs are checked for byte integrity only, not individually Sigstore-authenticated: `INTEGRITY_ONLY` remains unchanged. This GitHub CLI prerelease is not an Authenticode-signed installer and does not grant install/publish authority for extensions. Issue #75 GO B/G4/G5 remain gated.

---

## 日本語

### v0.3.2 の変更点

- 読み取り専用CLIに `--verbose` を追加。UTCの時刻付きログを**標準エラー出力**へ出し、通常の標準出力やJSON結果は変更しません。
- Sigstore署名付きCatalogの検証、不変CatalogレコードのSHA256照合、過去の固定Catalog取得を順番に表示します。
- 各ZIPの取得開始、転送量（8 MiB単位）、取得バイト数、SHA256の再照合、一括配置の確定まで追跡できます。
- `--verbose` の二重指定と不正な引数は拒否し、既存の安全な失敗処理を維持します。
- v0.3.1の.NET完全トリミング＋圧縮による軽量なWindows x64単体EXE、最新版の標準取得と `--fixed` を維持します。

### 実行例

```powershell
.\pgextwin.exe download-all --pg all --verbose
.\pgextwin.exe download-all --pg 18 --fixed --verbose
.\pgextwin.exe download-all --pg all --verbose 2> download-verbose.log
```

[Windows x64 EXEを取得](https://github.com/pgextwin/catalog/releases/download/cli-v0.3.2/pgextwin.exe) · [SHA256一覧](https://github.com/pgextwin/catalog/releases/download/cli-v0.3.2/SHA256SUMS.txt) · [詳しい使い方](https://github.com/pgextwin/catalog/blob/main/docs/cli-v0.3.2-verbose.md)

### 安全性・検証証跡

- EXE SHA256：`d4e8f63d402066b21db9d537f7679b51137ec47d9834fa4fd75b5889ad34e6f4`
- 署名済み元mainコミット：`a537f14f39be4b4ffc366cd0fef83f87aa4b9c39`
- [main上の署名付きWindowsビルドと独立Sigstore検証](https://github.com/pgextwin/catalog/actions/runs/39341486152)：SUCCESS
- [PR #134：Windows実行・元ZIP検証済み](https://github.com/pgextwin/catalog/pull/134)：MERGED

**EXEとCatalogフィードのSigstore検証**と、拡張機能ZIPの**SHA256バイト整合性**は別です。各ZIPの状態は引き続き `INTEGRITY_ONLY` であり、CLI自体はWindows Authenticode署名付きインストーラーではありません。拡張機能の正式配布・インストール許可、Issue #75 GO B/G4/G5の未成立ゲートは変更しません。
