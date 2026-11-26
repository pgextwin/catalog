# standalone-get 台帳3行の版別ライセンス原本照合記録（E3 PR5）

E3 PR5（監査是正）の成果物。Sol の E3 最終独立監査（`~/workspace/e3-audit/
AUDIT.md`）の重大指摘 M3 への対応として、`external/standalone-get.json` の
全3行について、登録時相当の原本バイト照合を 2026-11-26 に Muse が実施し、
その実施記録を証跡として残す。PR4 の対応表
（`issue112-direct-get-license-evidence-mapping.md`）で未決とされた3行が対象。

## 照合方法

- 配布物は台帳 `originalProviderUrl` から取得し、サイズと SHA-256 が台帳の
  固定値（`originalBytes` / `originalSha256`）と一致することを全行で確認した
  （取得バイトの同一性が全ての前提）。
- ライセンス文書は、配布物内の文書と、台帳 `licenseEvidence` が固定する
  上流原本（コミット固定 URL）の双方を SHA-256 で照合した。
- 同梱依存物は配布物を展開して列挙した（ZIP は unzip、MSI と NSIS
  インストーラは 7z で一覧化・展開）。
- 配布条件は、各ライセンスが再配布を禁じていないこと、帰属表示等の条件が
  配布物内の文書で満たされる形になっていることを確認した。
- 本記録は証跡の作成であり、CLI 取得時の新しい照合ゲートは増設していない。

## 1. postgis 3.6.2（PG14 セットアップ EXE）

### 配布物の同一性

- `postgis-bundle-pg14x64-setup-3.6.2-1.exe`: 104,787,481 B、
  SHA-256 `f245ddfb104abc14cc2b3533f9023d005e71a493e210b2694caef14637cb5594`
  — 台帳固定値と完全一致。
- 形式は NSIS-3 Unicode インストーラ。7z で一覧化・展開し、全 1,633
  ファイルを確認した。

### ライセンス文書の照合

台帳 `licenseEvidence` の上流原本（コミット固定 URL から取得）:

| 文書 | 照合先 | サイズ | SHA-256 | 結果 |
|---|---|---|---|---|
| LICENSE.TXT（PostGIS） | postgis/postgis `08d9b9f7…` | 3,002 B | `81749eea887e…` | 台帳ピンと一致 |
| LICENSE（pgRouting） | pgRouting/pgrouting `8988eebd…` | 18,092 B | `8177f9751321…` | 台帳ピンと一致 |
| README.md（pgRouting） | pgRouting/pgrouting `8988eebd…` | 3,056 B | `267633489ede…` | 台帳ピンと一致 |

配布物（EXE）内のライセンス文書:

| 文書 | サイズ | SHA-256 | 内容・対応 |
|---|---|---|---|
| `bin/COPYING` | 18,092 B | `8177f9751321…` | GPL-2.0 全文。pgRouting LICENSE の台帳ピンと**バイト一致**（PostGIS／pgRouting の GPL 文書が配布物内に同梱されている） |
| `LICENSE`（ルート） | 10,173 B | `a6cba85bc92e…` | Apache License 2.0 全文。ルート `README.md` は h3-pg のもので Apache バッジを持ち、この文書が h3-pg のライセンス文書に対応する |
| `gdal-data/LICENSE.TXT` | 21,841 B | `1dae3468e81d…` | GDAL/OGR Licensing（GDAL 本体とデータのライセンス文書） |
| `COPYRIGHT.pg_sphere` | 845 B | `624fe87f220e…` | pg_sphere の BSD 形式著作権文書 |
| `pgpointcloud_COPYRIGHT` | — | `c4c71656d1ea…` | pointcloud の BSD 形式著作権文書 |
| `ogrfdw_LICENSE.md` | — | `97eeff61daab…` | ogr_fdw の MIT ライセンス文書 |

### 同梱依存物

拡張コンポーネント（`lib/*.dll` 12件と各 `*_version.txt` から同定）:

| コンポーネント | 版 | ライセンス | 照合の根拠 |
|---|---|---|---|
| PostGIS（postgis-3 / raster / topology / tiger geocoder / address_standardizer） | 3.6.2 | GPL-2.0-or-later | 上流原本 LICENSE.TXT を台帳ピンで byte 照合。GPL 全文は `bin/COPYING` として配布物内に同梱 |
| pgRouting（libpgrouting-4.0） | 4.0.1 | GPL-2.0-or-later | 上流原本 LICENSE を台帳ピンで byte 照合し、同一バイトが `bin/COPYING` として配布物内にも存在 |
| SFCGAL（postgis_sfcgal-3、libSFCGAL） | 2.2.0 | LGPL-2.0（GNU Library GPL v2） | 配布物内に文書がないため、上流原本 LICENSE をタグ `v2.2.0` から取得して照合（25,374 B、SHA-256 `89198f6d51f2…`） |
| MobilityDB（libMobilityDB-1.3） | 1.3.0-rc1 | PostgreSQL License | 配布物内に文書がないため、上流原本 LICENSE.txt をタグ `v1.3.0rc1` から取得して照合（1,285 B、SHA-256 `6203975f214d…`） |
| pg_sphere | 1.5.2 | BSD 形式 | 配布物内 `COPYRIGHT.pg_sphere` |
| pointcloud | 1.2.5 | BSD 形式 | 配布物内 `pgpointcloud_COPYRIGHT` |
| h3-pg（h3 / h3_postgis） | 4.1.4 | Apache-2.0 | 配布物内ルート `LICENSE` ＋ `README.md` |
| ogr_fdw | 1.1.7 | MIT | 配布物内 `ogrfdw_LICENSE.md` |
| osm2pgrouting | 3.0.0 | GPL-2.0 | `bin/COPYING`（GPL 全文）の同梱と版ファイルで同定 |

ランタイムライブラリ（`bin/*.dll` 39件）: libgdal-35（GDAL 3.9.2、
ライセンス文書は配布物内 `gdal-data/LICENSE.TXT`）、libgeos／libgeos_c
（GEOS 3.14.1、LGPL-2.1 — 上流原本 COPYING をタグ `3.14.1` から取得して
照合、26,530 B、SHA-256 `dc626520dcd5…`）、libproj_8_2（PROJ 8.2.1、
MIT 形式 — 上流原本 COPYING をタグ `8.2.1` から取得して照合、1,784 B、
SHA-256 `6a8f30793e87…`）、libsqlite3-0、libtiff-6／libtiffxx-6、
libcurl、libssl-3-x64／libcrypto-3-x64（OpenSSL 3、Apache-2.0）、
libxml2-2、libexpat-1、libiconv-2／libcharset-1／libintl-8、liblz4、
liblzma-5、libzstd、zlib1、libpcre2-8-0／libpcre2-posix-3、libfreexl-1、
libarchive-13、libb2-1、libbz2-1、libssh2-1、libpsl-5、libidn2-0、
libunistring-5、libgmp-10／libgmpxx-4、libgsl-28／libgslcblas-0、
libprotobuf-c-1、libopenjp2、libreadline8、libtermcap-0、
libgcc_s_seh-1／libstdc++-6。これらは OSGeo／MSYS2 系バンドルの標準
ランタイム集合であり、いずれも再配布を禁じないライセンス（MIT／BSD／
Apache-2.0／LGPL／GPL 系）の同定までとし、個別の原本バイト照合は
行っていない（GDAL・GEOS・PROJ を除く）。

### 配布条件

PostGIS・pgRouting・osm2pgrouting は GPL-2.0-or-later で、再配布は
ライセンス全文の同梱を条件に許諾され、その全文（`bin/COPYING`）が
配布物自体に含まれている。LGPL 系（GEOS・SFCGAL・iconv 等）、MIT／
BSD／Apache-2.0／PostgreSQL License の各コンポーネントも再配布を
禁じていない。配布物は上流（PostGIS Windows バンドル）の公開
インストーラそのものであり、無改変で台帳固定値と一致する。

### 結論

**成立。** 成立の範囲: 配布物の同一性（台帳固定値との完全一致）、
拡張コンポーネント全件の版別ライセンス原本照合（配布物内文書または
正確な版の上流原本による）、配布条件の確認。ランタイムライブラリ群は
GDAL・GEOS・PROJ を原本照合、その他は一覧化とライセンス同定まで。

## 2. pgbouncer 1.26.1

### 配布物の同一性

- `pgbouncer-1.26.1-windows-x86_64.zip`: 2,540,874 B、
  SHA-256 `5d3fa0bc9bd40f8845655f50a9bafd315db9e9ac51ee1a511393e9f60828b57b`
  — 台帳固定値と完全一致。

### ライセンス文書の照合

| 文書 | サイズ | SHA-256 | 結果 |
|---|---|---|---|
| ZIP 内 `pgbouncer-1.26.1-windows-x86_64/COPYRIGHT` | 848 B | `d7388fd77986…` | 台帳ピン（配布物内ファイル）と一致 |
| 上流 `COPYRIGHT`（pgbouncer/pgbouncer `f03e9bf2…`） | 831 B | `af68760b7e21…` | 台帳ピンと一致 |

ZIP 内 COPYRIGHT と上流原本はテキストとして同一であり、差分は行末の
CRLF 化のみ（17行・+17 B でサイズ差と整合）。ISC License の本文と
著作権表示（Marko Kreen, Skype Technologies OÜ）が両方に含まれる。

### 同梱依存物・配布条件

ZIP の内容は全6ファイル（pgbouncer.exe、pgbevent.dll、pgbouncer.ini、
userlist.txt、README.md、COPYRIGHT）で、実行ファイル2件はいずれも
pgbouncer プロジェクト自身の成果物。第三者の同梱コンポーネントはない。
ISC License は著作権表示の保持を条件に再配布を許諾し、その表示文書
（COPYRIGHT）が配布 ZIP 自体に含まれている。

### 結論

**成立。**

## 3. psqlodbc 13.02.0000

### 配布物の同一性

- `psqlodbc_13_02_0000-x64.zip`: 3,868,961 B、
  SHA-256 `0d2f93c43752019c5e35f4369b1c32b40671f90a833dff3c7273569b6cbf1808`
  — 台帳固定値と完全一致。
- ZIP の内容は `psqlodbc_x64.msi` と `README.txt` の2ファイル。

### ライセンス文書の照合

| 文書 | サイズ | SHA-256 | 結果 |
|---|---|---|---|
| ZIP 内 `README.txt` | 1,367 B | `6c0f9eeb6534…` | 台帳ピンと一致。著作権表示（Insight Distribution Systems／PostgreSQL Global Development Group／Sankyo Unyu Service／Christian Czezatke・Dan McGuirk）と、GNU Library General Public License（version 2 以降）の許諾文を含み、全文は license.txt を参照する |
| 上流 `license.txt`（postgresql-interfaces/psqlodbc `ccd36c48…`） | 25,746 B | `3892f5f0585c…` | 台帳ピンと一致（LGPL 全文） |

### 同梱依存物

MSI の内容（7z で列挙した全22ファイル）:

- ドライバ本体（psqlodbc プロジェクト、LGPL-2.0-or-later）:
  psqlodbc30a.dll、psqlodbc35w.dll、pgenlist.dll、pgenlista.dll、
  pgxalib.dll（＋各 .pdb）。ライセンスは ZIP 内 README.txt の許諾文と
  台帳ピン済みの上流 license.txt で byte 照合済み。
- libpq.dll: PostgreSQL License（PostgreSQL のクライアントライブラリ）。
- libssl_1_1_x64.dll／libcrypto_1_1_x64.dll: OpenSSL 1.1（OpenSSL
  License）。
- msvcp140.dll／vcruntime140.dll: Microsoft Visual C++ 再頒布可能
  ランタイム。
- docs 一式（README と HTML 文書）。

MSI 内には上記同梱物の個別ライセンス文書は含まれていないため、
ドライバ本体以外は同定レベルとする。

### 配布条件

LGPL-2.0-or-later は再配布を許諾し、配布 ZIP には許諾文と著作権表示を
含む README.txt が同梱され、全文は台帳に固定された上流原本で確認
できる。同梱物（libpq・OpenSSL・MSVC ランタイム）のライセンスも
再配布を禁じていない。

### 結論

**成立。** 成立の範囲: 配布物の同一性、ドライバ本体のライセンス原本
照合（配布物内 README.txt と上流 license.txt の双方を byte 照合）、
配布条件の確認。同梱 DLL は列挙とライセンス同定まで。

## 対応表への反映

本記録により、対応表の standalone 3行は未決から成立へ移る
（direct-get 24行と合わせて 27行中 成立27・未決0）。終了記録
（`j05-observe-only-retirement.md`）の項目4も本記録を根拠に更新した。
