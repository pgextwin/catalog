# pgextwin CLI v0.3.2 — verbose progress

## English

Use `--verbose` with any supported command. Diagnostic events are
timestamped (UTC ISO 8601) and written to **stderr**. Normal results,
including `--format json` on list/search, stay on **stdout** and are
unchanged by the flag.

```powershell
.\pgextwin.exe --version
.\pgextwin.exe download-all --pg all --verbose
.\pgextwin.exe download-all --pg 18 --fixed --verbose
.\pgextwin.exe list --catalog-dir C:\approved\catalog --format json --verbose
```

For a persistent log in Windows PowerShell / PowerShell:

```powershell
.\pgextwin.exe download-all --pg all --verbose 2> download-verbose.log
```

Events include `FEED_FETCH_START`, `FEED_SIGSTORE_VERIFIED`,
`CATALOG_RECORD_VERIFIED`, `ZIP_START`, `ZIP_TRANSFER` (every
8 MiB of an individual browser download), `ZIP_VERIFIED`, and
`BATCH_COMPLETE`. Fixed snapshot downloads report `FIXED_POLICY_SHA256_VERIFIED`.
The progress log never prints ephemeral CDN redirect query strings,
private tokens or untrusted HTTP headers. Diagnostics are informational;
they do not change acceptance or failure criteria.

**Trust boundary:** The Catalog feed's Sigstore verification does **not**
authenticate original extension ZIP signatures. The published ZIPs are
still `INTEGRITY_ONLY`. `PUBLISH=DENY`, installation and Issue #75
GO B/G4/G5 gates are unchanged. A failure still exits nonzero,
cleans any partial batch staging and never falls back to a weaker mode.

## 日本語

`--verbose` を指定すると、処理中の詳細ログをUTC時刻付きで
**標準エラー出力 (stderr)** に表示します。通常の実行結果と
`list/search --format json` の機械可読出力は、引き続き **標準出力 (stdout)** に出力します。

```powershell
.\pgextwin.exe download-all --pg all --verbose
.\pgextwin.exe download-all --pg 18 --fixed --verbose
.\pgextwin.exe download-all --pg all --verbose 2> download-verbose.log
```

Catalogの取得、Sigstore署名検証、SHA256固定値との照合、各ZIPの取得開始、
8 MiBごとの転送量、ZIPのSHA256再計算、一括保存の原子的な確定までを記録します。
詳細ログを有効にしても、個別ZIPの真正署名が検証されるわけではありません。
検証状態の `INTEGRITY_ONLY` と、正式配布・インストールのDENY条件は変わりません。
