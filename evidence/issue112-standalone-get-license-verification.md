# standalone-get 台帳行の版別ライセンス原本照合記録（E3 PR5＋PR6 深化、PR-1 で psqlODBC 残件解消）

E3 PR5 で作成し、E3 再監査（`~/workspace/e3-audit/REAUDIT.md` の M3）の
指摘を受けて PR6（2026-11-26）で部品単位まで深化させた記録。対象は
`external/standalone-get.json` の全3行。再監査の判定は「3行とも未決」
であり、本記録はその不足（同梱・静的リンク部品ごとの固定上流原本と
配布条件の対応）を埋めるためのものである。PR6 時点の結論は3行とも
未決だった。その後、オーナー決定（2026-11-26、K4 解釈 B）により
PR7（#547）で3行ともいったん**成立**としたが、最終確認監査
（M3）が、PostGIS と psqlODBC の2行は本記録自体に固定原本の不足が
明記されており解釈 B の根拠を満たさないとして FAIL と判定した。
これを受けてオーナー決定（2026-11-26、選択肢 B）により、この2行は
**未決**に戻り、PgBouncer のみ**成立**のままとなった。未決の2行は
明記された残件として F フェーズの台帳管理へ引き継ぎ、E3 はこの
状態で完了する。解釈 B 自体は引き続き採用する判定基準である。

その後、PostGIS 行についてはオーナー決定 D3（2026-11-26）により
台帳からの引退が決まり、`external/standalone-get.json` から当該行を
削除した。決定の経緯: 原本チャネル（OSGeo）の PG14 ディレクトリの
最新は 3.6.1 で、3.6.2 の成果物（EXE・ZIP とも）が存在しなかった
（Case D）。3.6.1 への版下げは行わない。PG14 は上流サポート終了済み
（2026-11-12）であり、署名 feed の対象範囲にも PG14 は含まれて
いない。したがって PostGIS 行は未決の残件ではなくなり、F フェーズへ
の引き継ぎ対象からも外れた。未決の残件は psqlODBC のみである
（両台帳合計で成立25・未決1）。下記 §1 の部品単位の記録は、
引退前の照合記録としてそのまま保持する。

その後、psqlODBC の残件は PR-1（2026-11-26）で解消した。上流の
最新版 18.00.0006（2026-11-02 のセキュリティリリース）へ x64 / x86 の
両アーキテクチャで切り替え、部品単位の固定を機械可読マニフェスト
`evidence/issue112-standalone-get-component-pins.json` に集約した。
最終確認監査で不足とされた MSVC ランタイムの再頒布条件の固定原本は、
オーナー決定 A（2026-11-26）により、インストーラが指定する公式
ページから決定的に抽出した条文テキストで固定した。実施記録は §4。
これにより未決の残件は消滅し、両台帳合計は 26行中 成立26・未決0 と
なった。§3 は引退した 13.02.0000 の照合記録として保持する。
根拠: Established under owner decision 2026-11-26 (K4 interpretation B): component identification, pinned originals, and redistribution permission confirmed for each component license; license texts not reproduced inside upstream's distribution artifacts are recorded as a distribution-form characteristic of the upstream artifact.

## PR5 記録の訂正（事実誤り）

PR6 の実測で判明した PR5 記録の誤りを明示して訂正する。

1. **PgBouncer「第三者の同梱コンポーネントはない」は誤り。**
   `pgbouncer.exe` は libevent と OpenSSL を静的リンクしている（下記 §2）。
   PR5 は ZIP 内ファイル数だけを見て実行ファイル内部の部品を取りこぼした。
2. **PostGIS の DLL 列挙は不完全だった。** PR5 は `bin/*.dll` 39件を
   対象としたが、配布物全体では DLL 119件あり、`bin/postgisgui/`
   サブツリー（shp2pgsql-gui 用の GTK スタック）が未対象だった。
   また PR5 が「OpenSSL 3」とした部品の正確な版は 3.0.7 である。
3. **PR5 の結論「成立」は確認範囲に対して過大だった。** PR5 本文自体が
   ランタイム群・同梱 DLL を「同定まで」と認めながら結論では成立として
   おり、再監査もこの点を支持しなかった。本記録では結論を未決に戻す。
4. **細部の数値誤り。** 配布物内 `COPYRIGHT.pg_sphere` のサイズは
   845 B ではなく 1,547 B（SHA-256 は PR5 記録どおり
   `624fe87f220e…` で一致）。

## 照合方法（PR6）

- 配布物は台帳 `originalProviderUrl` から再取得し、サイズと SHA-256 が
  台帳固定値と一致することを全行で再確認した（前提の同一性）。
- 部品の版は、バイナリ内の版文字列・FileVersion リソース・埋め込み
  ソースパス・提供元の固定コミットのビルド定義から確定した（根拠を
  部品ごとに明記）。
- ライセンス原本は、各部品の正確な版について、タグを解決した
  **コミット固定 URL** から取得し、完全な SHA-256（64桁）で記録した。
- 配布条件は、各ライセンスの再配布条件（特にライセンス文・NOTICE の
  同梱義務）と、配布物内に当該文書が実在するかを対応付けた。
- 本記録は証跡の作成であり、CLI 取得時の新しい照合ゲートは増設していない。

凡例: 「原本」列は `リポジトリ @コミット のファイル（サイズ, SHA-256）`。
「配布物内」列は、当該部品のライセンス文書が配布物内に実在するか。

## 1. postgis 3.6.2（PG14 セットアップ EXE）

（本行はオーナー決定 D3（2026-11-26）により台帳から引退した。
以下の記録は引退前の照合記録として保持するもので、現在の台帳行では
ない。引退の根拠は冒頭の D3 記録を参照）

### 配布物の同一性

- `postgis-bundle-pg14x64-setup-3.6.2-1.exe`: 104,787,481 B、
  SHA-256 `f245ddfb104abc14cc2b3533f9023d005e71a493e210b2694caef14637cb5594`
  — 台帳固定値と完全一致（PR6 で再取得・再確認）。
- NSIS-3 Unicode インストーラ。7z で展開した全 1,633 項目と DLL 119件
  （`bin/`、`lib/`、`bin/postgisgui/` 配下）を確認した。
- 配布物内に実在するライセンス／著作権文書は次の6件のみである
  （ツリー全体を検索して確認）: ルート `LICENSE`、`bin/COPYING`、
  `gdal-data/LICENSE.TXT`、`COPYRIGHT.pg_sphere`、
  `pgpointcloud_COPYRIGHT`、`ogrfdw_LICENSE.md`。

### 拡張コンポーネント

| 部品 | 版（根拠） | ライセンス | 原本 | 配布物内 |
|---|---|---|---|---|
| PostGIS | 3.6.2（台帳・版ファイル） | GPL-2.0-or-later | 台帳ピン: postgis/postgis @`08d9b9f749fa3531591055db2a736bfb6df47006` LICENSE.TXT（3,002 B, `81749eea887e78402c9b85896cd629b155bc29256927f818f01001f038146391`） | GPL 全文が `bin/COPYING` として同梱 |
| pgRouting | 4.0.1（台帳・版ファイル） | GPL-2.0-or-later | 台帳ピン: pgRouting/pgrouting @`8988eebdff0e01327c9d48fe7c80b437dc9bc992` LICENSE（18,092 B, `8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643`）。同コミットの README.md（3,056 B, `267633489eded7cdb9992b61169b5d025830c5b28d9eb53bea83c0180fc9b765`）も台帳ピンと一致 | `bin/COPYING` がこの LICENSE と**バイト一致** |
| SFCGAL | 2.2.0（DLL 内ソースパス `SFCGAL-v2.2.0`、PR5 の版ファイル同定と一致） | LGPL-2.0（GNU Library GPL v2） | SFCGAL/SFCGAL @`d1ba2619e8fa8ce2f6ff6bab7fe0d51fbc9413a0`（タグ v2.2.0）LICENSE（25,374 B, `89198f6d51f260c7486eff132dfcb7db879b719542196e145a4408b0cae0dee6`） | なし |
| MobilityDB | 1.3.0-rc1（版ファイル `MobilityDB_version.txt`） | PostgreSQL License | MobilityDB/MobilityDB @`cb8753ee2e9e545fa8ff6fb70877ffe0d6ad912a`（タグ v1.3.0rc1）LICENSE.txt（1,285 B, `6203975f214d44c13098a0c536ffd3ca4384f6bf4c83012dc27ec90374d4502a`） | なし |
| pg_sphere | 1.5.2（版ファイル） | BSD 形式 | 配布物内文書自体を原本として記録: `COPYRIGHT.pg_sphere`（1,547 B, `624fe87f220e257e56bd577f34e806e5d2e840a35d019b940ff5ad1c5016ca36`） | **あり（この文書）** |
| pointcloud | 1.2.5（版ファイル） | BSD 形式 | 配布物内文書: `pgpointcloud_COPYRIGHT`（1,556 B, `c4c71656d1ea3310b4866057e96f8f38972ccaec145ca76f58caeaa362fb95e4`） | **あり（この文書）** |
| h3-pg | 4.1.4（版ファイル） | Apache-2.0 | 配布物内文書: ルート `LICENSE`（10,173 B, `a6cba85bc92e0cff7a450b1d873c0eaa2e9fc96bf472df0247a26bec77bf3ff9`、Apache-2.0 全文。ルート README.md が h3-pg のもの） | **あり（この文書）** |
| ogr_fdw | 1.1.7（版ファイル） | MIT | 配布物内文書: `ogrfdw_LICENSE.md`（1,082 B, `97eeff61daab8f581d50c896237dad9ec5749a815109a7fcb7d39c990d4f9103`） | **あり（この文書）** |
| osm2pgrouting | 3.0.0（版ファイル） | GPL-2.0 | GPL 全文は `bin/COPYING` として同梱（pgRouting と同一バイト） | GPL 全文あり |

### ランタイムライブラリ（主ツリー bin/・lib/）

| 部品（DLL） | 版（根拠） | ライセンス | 原本（コミット固定） | 配布物内 |
|---|---|---|---|---|
| GDAL（libgdal-35） | 3.9.2（DLL 内文字列 `GDAL 3.9.2`） | GDAL/OGR Licensing（MIT 系） | OSGeo/gdal @`3aae5b4cf30c958ab339157b4f8115922e2f2562`（タグ v3.9.2）LICENSE.TXT（21,841 B, `1dae3468e81d00da56e2936f74d33b8b3ad09d726437f19ce209a5dabea41f77`） | **あり**: `gdal-data/LICENSE.TXT` が原本とバイト一致 |
| GEOS（libgeos / libgeos_c） | 3.14.1（CAPI 文字列 `3.14.1-CAPI-1.20.5`） | LGPL-2.1 | libgeos/geos @`c389f532d25fe6228861d9b19339f9cb57ca4bdb`（タグ 3.14.1）COPYING（26,530 B, `dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551`） | なし |
| PROJ（libproj_8_2） | 8.2.1（DLL 内文字列 `Rel. 8.2.1`） | MIT | OSGeo/PROJ @`deb1a5720fdfcd50d53c93ffb4011cacb36f2c89`（タグ 8.2.1）COPYING（1,784 B, `6a8f30793e877d32e3f88b972f0970a051a3b5a26cd057d3993cb51e21c43319`） | なし |
| OpenSSL（libssl-3-x64 / libcrypto-3-x64） | 3.0.7（FileVersion） | Apache-2.0 | openssl/openssl @`19cc035b6c6f2283573d29c7ea7f7d675cf750ce`（タグ openssl-3.0.7）LICENSE.txt（10,175 B, `7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a`） | なし |
| libcurl（libcurl） | 8.7.1（FileVersion・`libcurl/8.7.1`） | curl license（MIT/X 系） | curl/curl @`de7b3e89218467159a7af72d58cea8425946e97d`（タグ curl-8_7_1）COPYING（1,088 B, `adb1fc06547fd136244179809f7b7c2d2ae6c4534f160aa513af9b6a12866a32`） | なし |
| libtiff（libtiff-6 / libtiffxx-6） | 4.5.0（DLL 内文字列 `LIBTIFF, Version 4.5.0`） | BSD 形式（libtiff license） | gitlab libtiff/libtiff @`38eb7b00cb5767770017fb91743a960ffd96d774`（タグ v4.5.0）LICENSE.md（1,164 B, `0780558a8bfba0af1160ec1ff11ade4f41c0d7deafd6ecfc796b492a788e380d`） | なし |
| libxml2（libxml2-2） | 2.12.5（DLL 内パスの `rel-libxml2-2.12.5w64`） | MIT | GNOME/libxml2 @`e189e9945317ad4c8603fa2300d11d11f5e2e335`（タグ v2.12.5）Copyright（1,289 B, `7fb0a66f3989f9bd5c7e5438a3de02cd4a7a47dde0aea2f7ea2ba2ff454ee6a4`） | なし |
| SQLite（libsqlite3-0） | 3.41.2（DLL 内版文字列） | Public Domain | sqlite/sqlite @`e671c4fbc057f8b1505655126eaf90640149ced6`（タグ version-3.41.2）LICENSE.md（263 B, `9c6479123f32a1ed50d9a0af203dfe8972e65035b0cdeef436b5f8d0924517fe`、public domain の表明） | なし（条件なし） |
| expat（libexpat-1） | 2.5.0（DLL 内文字列 `expat_2.5.0`） | MIT | libexpat/libexpat @`654d2de0da85662fcc7644a7acd7c2dd2cfb21f0`（タグ R_2_5_0）expat/COPYING（1,144 B, `122f2c27000472a201d337b9b31f7eb2b52d091b02857061a8880371612d9534`） | なし |
| libiconv（libiconv-2 / libcharset-1） | 1.17（FileVersion） | LGPL-2.1 | GNU libiconv @`4b9c27bec873392533dd3ef309cd62962a644e18`（savannah、タグ v1.17）COPYING.LIB（26,530 B, `dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551`。LGPL-2.1 全文であり GEOS の COPYING と同一バイト） | なし |
| gettext libintl（libintl-8） | 0.22.5（FileVersion） | LGPL-2.1 | autotools-mirror/gettext @`0d53c885229fc59ca3ce6a8e70fb3f6d59ece361`（タグ v0.22.5）gettext-runtime/intl/COPYING.LIB（26,545 B, `3fe5361f24b7c49ba12911c08f5a33f9cb18871d95d9fb881f5b8a4793e04288`） | なし |
| lz4（liblz4） | 1.9.3（DLL 内ソースパス `lz4-1.9.3`） | BSD-2-Clause（ライブラリ） | lz4/lz4 @`d44371841a2f1728a3f36839fd4b7e872d0927d3`（タグ v1.9.3）LICENSE（565 B, `2ba56d6195e9bb84500784a49099edae53eb103785b25928c194809dba5a025c`） | なし |
| xz / liblzma（liblzma-5） | 5.6.1（FileVersion） | Public Domain 中心（一部 LGPL 表明を含む） | tukaani-project/xz @`fd1b975b7851e081ed6e5cf63df946cd5cbdbb94`（タグ v5.6.1）COPYING（4,650 B, `0864e508475f20b43a2393957fdb5a966558099ffa8fed1e3e73fe2b3eebb145`） | なし |
| zstd（libzstd） | 1.5.6（DLL 内版文字列） | BSD-3-Clause | facebook/zstd @`794ea1b0afca0f020f4e57b6732332231fb23c70`（タグ v1.5.6）LICENSE（1,549 B, `7055266497633c9025b777c78eb7235af13922117480ed5c674677adc381c9d8`） | なし |
| zlib（zlib1） | 1.2.13（FileVersion） | zlib license | madler/zlib @`04f42ceca40f73e2978b50e93806c2a18c1281fc`（タグ v1.2.13）LICENSE（1,002 B, `845efc77857d485d91fb3e0b884aaa929368c717ae8186b66fe1ed2495753243`） | なし |
| PCRE2（libpcre2-8-0 / libpcre2-posix-3） | 10.42（DLL 内文字列 `10.42 2022-12-11`） | BSD-3-Clause | PCRE2Project/pcre2 @`52c08847921a324c804cabf2814549f50bce1265`（タグ pcre2-10.42）LICENCE（3,477 B, `87d884eceb7fc54611470ce9f74280d28612b0c877adfc767e9676892a638987`） | なし |
| libarchive（libarchive-13） | 3.7.2（DLL 内文字列） | BSD-2-Clause | libarchive/libarchive @`6468cd1f5c9b76e2c3b10cdd6938faf6b82823b6`（タグ v3.7.2）COPYING（3,086 B, `b2cdf763345de2de34cebf54394df3c61a105c3b71288603c251f2fa638200ba`） | なし |
| bzip2（libbz2-1） | 1.0.8（DLL 内文字列 `1.0.8, 13-Jul-2019`） | BSD 形式 | gitlab bzip2/bzip2 @`6a8690fc8d26c815e798c588f796eabe9d684cf0`（タグ bzip2-1.0.8）LICENSE（1,896 B, `c6dbbf828498be844a89eaa3b84adbab3199e342eb5cb2ed2f0d4ba7ec0f38a3`） | なし |
| libssh2（libssh2-1） | 1.11.0（FileVersion） | BSD-3-Clause | libssh2/libssh2 @`1c3f1b7da588f2652260285529ec3c1f1125eb4e`（タグ libssh2-1.11.0）COPYING（1,959 B, `fda5e2522c58ba1f31c9f2044747616457466f4aebec16ade4af86e3a16a8e02`） | なし |
| libpsl（libpsl-5） | 0.21.5（DLL 内文字列） | MIT | rockdaboot/libpsl @`ba4c49a205408845834b1648ad23c15ee09f722b`（タグ 0.21.5）LICENSE（1,060 B, `322392e6001b2b3b0fca705dc9f11f26e12441188ecde50eb1d22909980b2925`） | なし |
| libidn2（libidn2-0） | 2.3.7（DLL 内版文字列。libpsl 内文字列 `+libidn2/2.3.7` とも一致） | LGPL-3.0-or-later（ライブラリ）／GPL-3.0（ツール） | libidn/libidn2 @`1e132ac794a939c02c5f26c538a6d21afeced271`（タグ v2.3.7）COPYING（1,555 B, `73483f797a83373fca1b968c11785b98c4fc4803cdc7d3210811ca8b075d6d76`、二重ライセンスの要約文書） | なし |
| protobuf-c（libprotobuf-c-1） | 1.2.1（DLL 内ソースパス `protobuf-c-1.2.1`） | BSD-2-Clause | protobuf-c/protobuf-c @`006d69bd8481738323c58af5cd4c8477d09eb9f5`（タグ v1.2.1）LICENSE（1,574 B, `034c4e3c3835c0d01c457406ff42acf23fa0df1382b70b8ff4fe47e7183981eb`） | なし |
| OpenJPEG（libopenjp2） | 2.5.2（DLL 内版文字列） | BSD-2-Clause | uclouvain/openjpeg @`39e8c50a2f9bdcf36810ee3d41bcbf1cc78968ae`（タグ v2.5.2）LICENSE（2,112 B, `a6af136f3e15038a666b61f376612a07d9a4e48cb7c01adbf3e33b3f14ab49b6`） | なし |
| libpq（postgisgui/libpq） | PostgreSQL 14.6（DLL 内ビルドパス `postgresql-14.6`、EDB Jenkins ビルド） | PostgreSQL License | postgres/postgres @`6dde6ed3efb4baaa0955f78ba5c93e9490aaa490`（タグ REL_14_6）COPYRIGHT（1,192 B, `f6d6616acdb598742e2a7c64fa0551c1c72c309d279fd2d90370e5fdd41c8945`） | なし |
| GCC ランタイム（libgcc_s_seh-1 / libstdc++-6 / libwinpthread-1） | GCC 13.2.0（DLL 内ソースパス `gcc-13.2.0`） | GPL-3.0 + GCC Runtime Library Exception（winpthread は MIT/BSD 形式） | gcc-mirror/gcc @`c891d8dc23e1a46ad9f3e757d09e57b500d40044`（タグ releases/gcc-13.2.0）COPYING.RUNTIME（3,324 B, `9d6b43ce4d8de0c878bf16b54d8e7a10d9bd42b75178153e3af6a815bdc90f74`、例外条項の原本） | なし |

### GUI サブツリー（bin/postgisgui/）の追加部品

主ツリーと重複する DLL（curl、OpenSSL、GEOS 等）は上表で扱い、ここは
GUI 固有の部品のみを挙げる。

| 部品（DLL） | 版（根拠） | ライセンス | 原本（コミット固定） | 配布物内 |
|---|---|---|---|---|
| GLib 一式（libglib-2.0-0 / libgobject / libgio / libgmodule / libgthread） | 2.80.0（FileVersion） | LGPL-2.1 | GNOME/glib @`763cc3b238398614c20069fd67642730e3a6519b`（タグ 2.80.0）COPYING（25,967 B, `fa6f36630bb1e0c571d34b2bbdf188d08495c9dbf58f28cac112f303fc1f58fb`） | なし |
| cairo（libcairo-2） | 1.18.0（DLL 内ソースパス `cairo-1.18.0`） | LGPL-2.1／MPL-1.1 の選択 | gitlab.freedesktop.org cairo/cairo @`3909090108bb2db55330e3eb148aebe664735363`（タグ 1.18.0）COPYING（1,576 B, `67228a9f7c5f9b67c58f556f1be178f62da4d9e2e6285318d8c74d567255abdf`） | なし |
| Pango（libpango-1.0-0 他） | 1.52.2（FileVersion） | LGPL-2.0-or-later | GNOME/pango @`7fe0a98f6180069732aa819fb5f1f2fa4f5d10f1`（タグ 1.52.2）COPYING（25,292 B, `d245807f90032872d1438d741ed21e2490e1175dc8aa3afa5ddb6c8e529b58e5`） | なし |
| gdk-pixbuf（libgdk_pixbuf-2.0-0） | 2.42.10（FileVersion） | LGPL-2.1 | GNOME/gdk-pixbuf @`9ac257eb38f772fec4253e8051743029e75a2acd`（タグ 2.42.10）COPYING（26,530 B, `dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551`） | なし |
| GTK+ 2（libgtk-win32-2.0-0 / libgdk-win32 / libgail） | 2.24.33（FileVersion） | LGPL-2.1 | GNOME/gtk @`68631945733158f164427db84f01301d7e875763`（タグ 2.24.33）COPYING（25,292 B, `d245807f90032872d1438d741ed21e2490e1175dc8aa3afa5ddb6c8e529b58e5`） | なし |
| ATK（libatk-1.0-0） | 2.52.0（FileVersion） | LGPL-2.1-or-later | **未取得**（at-spi2-core への統合後のタグ @AT_SPI2_CORE_2_52_0 では atk/COPYING のパスを確認できず） | なし |
| HarfBuzz（libharfbuzz-0 他） | 8.3.1（DLL 内ソースパス `harfbuzz-8.3.1`） | MIT 形式（Old MIT） | harfbuzz/harfbuzz @`2b3631a866b3077d9d675caa4ec9010b342b5a7c`（タグ 8.3.1）COPYING（1,971 B, `ba8f810f2455c2f08e2d56bb49b72f37fcf68f1f4fade38977cfd7372050ad64`） | なし |
| FreeType（libfreetype-6） | 2.13.2（FileVersion） | FreeType License（FTL）／GPL-2.0 の選択 | freetype/freetype @`920c5502cc3ddda88f6c7d85ee834ac611bb11cc`（タグ VER-2-13-2）docs/FTL.TXT（6,743 B, `08c135755dd589039470f1fdbb400daaabaaa50d0b366d19cebff4d22986baa1`） | なし |
| fontconfig（libfontconfig-1） | 2.15.0（DLL 内ソースパス） | MIT 形式 | gitlab.freedesktop.org fontconfig/fontconfig @`72b9a48f57de6204d99ce1c217b5609ee92ece9b`（タグ 2.15.0）COPYING（8,616 B, `51a51aa9823704fd90bccc616cdd17ebabb5b2b3e9cbde886ca02c7002288067`） | なし |
| pixman（libpixman-1-0） | 0.43.4（DLL 内ソースパス） | MIT | gitlab.freedesktop.org pixman/pixman @`54cad71674ec485cbbbf49876feaa8a69b97c828`（タグ pixman-0.43.4）COPYING（2,087 B, `fac9270f0987b96ff4533fca3548c633e02083cbba4a0172a3b149b2e4019793`） | なし |
| FriBidi（libfribidi-0） | 1.0.13（DLL 内文字列） | LGPL-2.1 | fribidi/fribidi @`b54871c339dabb7434718da3fed2fa63320997e5`（タグ v1.0.13）COPYING（26,440 B, `32434afcc8666ba060e111d715bfdb6c2d5dd8a35fa4d3ab8ad67d8f850d2f2b`） | なし |
| libpng（libpng16-16） | 1.6.43（DLL 内文字列） | libpng License（zlib 系） | pnggroup/libpng @`ed217e3e601d8e462f7fd1e04bed43ac42212429`（タグ v1.6.43）LICENSE（5,345 B, `7317e078e2d3b5d7ba5a6159e650945153262b44b76f6700f8e9edb261c5143e`） | なし |
| gettext libintl（libintl-9、GUI 側） | 0.19.8（FileVersion。主ツリーの libintl-8 = 0.22.5 とは別版） | LGPL-2.1 | autotools-mirror/gettext @`c737bf843616ca984c9416048a2da845e9ad3f50`（タグ v0.19.8.1）gettext-runtime/intl/COPYING.LIB（26,545 B, `3fe5361f24b7c49ba12911c08f5a33f9cb18871d95d9fb881f5b8a4793e04288`） | なし |
| GNU.Gettext.dll（.NET） | 版未確定 | LGPL（gettext の .NET バインディング） | **未取得** | なし |

### 版・原本を確定できなかった部品（PostGIS）

| 部品（DLL） | 状況 |
|---|---|
| libthai（libthai-0）／libdatrie（libdatrie-1） | ライセンスは LGPL-2.1 と同定。版がバイナリから確定できず、コミット固定原本は未取得 |
| graphite2（libgraphite2） | LGPL-2.1／MIT／GPL-2.0 の選択制と同定。版未確定・原本未取得 |
| libffi（libffi-8） | MIT と同定。版未確定・原本未取得 |
| brotli（libbrotlicommon / libbrotlidec / libbrotlienc） | MIT と同定。版未確定・原本未取得 |
| libb2（libb2-1） | CC0 と同定。版未確定・原本未取得 |
| readline（libreadline8 / libtermcap-0） | GPL-3.0。soname から 8.x 系と分かるが細版未確定・原本未取得 |
| GMP（libgmp-10 / libgmpxx-4） | 6.3.0（DLL 内ソースパス `gmp-6.3.0`）。LGPL-3.0-or-later／GPL-2.0-or-later の二重。上流は Mercurial 管理で、コミット固定の git 原本を取得できず |
| GSL（libgsl-28 / libgslcblas-0） | soname から 2.8 と推定。GPL-3.0。原本未取得 |
| FreeXL（libfreexl-1） | 1.0.6（DLL 内ソースパス）。MPL-1.1／GPL／LGPL の三重ライセンス。上流は Fossil 管理で原本未取得 |
| libunistring（libunistring-5） | 1.2（DLL 内ソースパス `libunistring-1.2`）。LGPL-3.0／GPL-3.0。原本未取得 |
| Apache Arrow（libgdal 内） | GDAL の文字列に `parquet-cpp-arrow version 13.0.0` の言及があり、Arrow C++（Apache-2.0）が静的リンクされている可能性を示す。実在と範囲は未検証 |

### 配布条件と結論（PostGIS）

拡張コンポーネントと主要ランタイムについては、正確な版のライセンス
原本をコミット固定で対応付けられた（上表）。GPL 系の全文は配布物内の
`bin/COPYING` で、GDAL の文書は `gdal-data/LICENSE.TXT` で満たされる。
しかし LGPL／MIT／BSD 系ランタイムの大半は、ライセンス文の同梱を
再配布条件に含むにもかかわらず、その文書が配布物内に実在しない
（配布物内のライセンス文書は6件のみ）。NSIS インストーラの表示画面に
追加のライセンス文が含まれる可能性は本記録では検証していない。
さらに上記のとおり、版・原本を確定できない部品が残る。

**結論: 未決。** 残る不足: (1) ランタイム大半のライセンス文が配布物内に
なく、配布条件の充足をファイルレベルで確認できない。(2) libthai、
libdatrie、graphite2、libffi、brotli、libb2、readline、GMP、GSL、
FreeXL、libunistring、ATK、GNU.Gettext.dll は版の確定または
コミット固定原本の取得ができていない。(3) GDAL 内の Arrow 静的リンクの
有無と範囲が未検証。

## 2. pgbouncer 1.26.1

### 配布物の同一性

- `pgbouncer-1.26.1-windows-x86_64.zip`: 2,540,874 B、
  SHA-256 `5d3fa0bc9bd40f8845655f50a9bafd315db9e9ac51ee1a511393e9f60828b57b`
  — 台帳固定値と完全一致（PR6 で再取得・再確認）。
- ZIP の内容は全6ファイル（pgbouncer.exe、pgbevent.dll、pgbouncer.ini、
  userlist.txt、README.md、COPYRIGHT）。

### 静的リンク部品の確定（PR5 の誤りの訂正）

PR5 は「実行ファイル2件はいずれも pgbouncer プロジェクト自身の成果物。
第三者の同梱コンポーネントはない」としたが、これは誤りである。

- 提供元の固定コミット `f03e9bf263d7ccd5d1d152a61811bf3258dd6b87` の
  Windows ビルド定義（`.github/workflows/pgbouncer-ci.yml` の windows
  ジョブ）は、MSYS2 の `mingw-w64-*-libevent` と `mingw-w64-*-openssl`
  を導入し、`LDFLAGS=-static` と
  `LIBS="-liphlpapi $(pkgconf --libs --static openssl)"` で
  「MSYS2 ランタイム DLL に依存しないよう静的リンクする」と明記して
  この ZIP を生成する。
- 実配布 `pgbouncer.exe` の文字列に、OpenSSL のソースパス
  `../openssl-3.6.5/crypto/...` が多数含まれ、版は **OpenSSL 3.6.5**
  と確定する。libevent の関数名・メッセージ文字列
  （`event_base`、`evdns` 系）も含まれ、版文字列 **`2.1.13-stable`**
  が存在する。
- `pgbouncer.exe` のインポートは Windows システム DLL と UCRT のみで、
  第三者 DLL への動的依存はない（静的リンクの裏付け）。libpq の
  文字列はなく、libpq はリンクされていない。
- MSYS2 パッケージは workflow で版固定されていないため、部品の版は
  上記のとおり実バイナリ自体から確定した。

### 部品ごとの照合

| 部品 | 版（根拠） | ライセンス | 原本（コミット固定） | 配布物内 |
|---|---|---|---|---|
| PgBouncer 本体（pgbouncer.exe / pgbevent.dll） | 1.26.1（台帳・配布物名） | ISC | 台帳ピン: pgbouncer/pgbouncer @`f03e9bf263d7ccd5d1d152a61811bf3258dd6b87` COPYRIGHT（831 B, `af68760b7e2115d97b35680d5f84c0096857d581e8c19c5f7642cfe98eda9f4c`） | **あり**: ZIP 内 COPYRIGHT（848 B, `d7388fd779866b8eef57ce88801169027a4ca1e936c7d1ab4e6537eee95c6477`）が台帳ピンと一致し、上流原本とは CRLF 化のみの差（17行・+17 B）でテキスト同一。ISC の著作権表示保持条件はこの文書で満たされる |
| OpenSSL（静的リンク） | 3.6.5（exe 内ソースパス） | Apache-2.0 | openssl/openssl @`c8bd5a57108599ac650bbae77fcabe3109dab2e8`（タグ openssl-3.6.5）LICENSE.txt（10,175 B, `7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a`） | **なし** |
| libevent（静的リンク） | 2.1.13-stable（exe 内版文字列） | BSD-3-Clause | libevent/libevent @`79ddfb460847999b807cba76d04e73891f29c6ee`（タグ release-2.1.13-stable）LICENSE（4,528 B, `ff02effc9b331edcdac387d198691bfa3e575e7d244ad10cb826aa51ef085670`） | **なし** |

### 配布条件と結論（PgBouncer）

- OpenSSL 3.6.5 の Apache-2.0 は、再配布物にライセンスのコピーを
  添付することを条件とする（§4(a)）。OpenSSL 本体は NOTICE ファイルを
  持たないため §4(d) の対象となる NOTICE 内容は上流に存在しないが、
  §4(a) のライセンス文自体が ZIP 内に存在しない。
- libevent の BSD-3-Clause は、バイナリ再配布に著作権表示・条件・
  免責の複製を文書または付属資料へ含めることを条件とするが、
  ZIP 内に libevent の表示は存在しない。
- PgBouncer 本体の ISC 条件は ZIP 内 COPYRIGHT で満たされる。

**結論: 成立**（オーナー決定 2026-11-26、K4 解釈 B。本記録冒頭の
根拠文のとおり）。ライセンス原本は全部品について正確な版で固定でき、
各部品ライセンスの再配布許諾も確認した。静的リンク部品2件
（OpenSSL 3.6.5、libevent 2.1.13）の表示・ライセンス文が配布物内に
存在しない点は、上流配布物の配布形態の特性として記録する。

## 3. psqlodbc 13.02.0000

（本行は PR-1（2026-11-26）で 18.00.0006 へ切り替えて台帳から
削除した。以下の記録は引退前の照合記録として保持するもので、
現在の台帳行ではない。切替後の記録は §4）

### 配布物の同一性

- `psqlodbc_13_02_0000-x64.zip`: 3,868,961 B、
  SHA-256 `0d2f93c43752019c5e35f4369b1c32b40671f90a833dff3c7273569b6cbf1808`
  — 台帳固定値と完全一致（PR6 で再取得・再確認）。
- ZIP の内容は `psqlodbc_x64.msi` と `README.txt` の2ファイル。
  MSI の内容は全22ファイル（ドライバ DLL 5件＋PDB 3件、同梱 DLL 5件、
  docs 9件）。MSI 内に同梱部品のライセンス文書は含まれていない。

### 部品ごとの照合

| 部品 | 版（根拠） | ライセンス | 原本（コミット固定） | 配布物内 |
|---|---|---|---|---|
| psqlODBC ドライバ本体（psqlodbc30a / psqlodbc35w / pgenlist / pgenlista / pgxalib） | 13.02.0000（台帳・MSI） | LGPL-2.0-or-later | 台帳ピン: postgresql-interfaces/psqlodbc @`ccd36c486ab2eb1c2a7cb0692666a96e34f81427` license.txt（25,746 B, `3892f5f0585c553b72d0d4942d5a75935d0e8b0dcd0f5caa000a6853d648c67b`、LGPL 全文） | **あり（ZIP 側）**: ZIP 内 README.txt（1,367 B, `6c0f9eeb65345061c45a12916f58037b434fe687eb91fccb360f32f35ca44991`）が台帳ピンと一致し、著作権表示と LGPL の許諾文（全文は license.txt 参照）を含む |
| libpq（libpq.dll） | PostgreSQL 13.4 由来（DLL 内 PDB パス `C:\home\postgresql-13.4_x64\...\libpq.pdb` とソースパス） | PostgreSQL License | postgres/postgres @`e849f3f1f884ad140b60a24354c6371cbd2efbb6`（タグ REL_13_4）COPYRIGHT（1,192 B, `31ccadc0a70e8e0e8a35c5833567b64388dfe34987d962e1911554e271294105`） | なし |
| OpenSSL（libssl_1_1_x64 / libcrypto_1_1_x64） | 1.1.1l（両 DLL 内文字列 `OpenSSL 1.1.1l 24 Aug 2021`） | OpenSSL License + SSLeay License（二重ライセンス。Apache-2.0 ではない旧体系） | openssl/openssl @`fb047ebc87b18bdc4cf9ddee9ee1f5ed93e56aff`（タグ OpenSSL_1_1_1l）LICENSE（6,121 B, `c32913b33252e71190af2066f08115c69bc9fddadf3bf29296e20c835389841c`） | なし |
| MSVC ランタイム（msvcp140 / vcruntime140） | 14.16.27033.0（両 DLL の FileVersion。Visual Studio 2017（15.9）の VC++ 再頒布可能ランタイム） | Microsoft の再頒布条件（Visual Studio ライセンス条項に基づく再頒布可能コード） | **コミット固定の公開原本は存在しない**（Microsoft の条項文書は版管理リポジトリで公開されていない）。版の同定のみ | なし |

### 配布条件と結論（psqlODBC）

- ドライバ本体の LGPL 条件は、ZIP 内 README.txt の許諾文・著作権表示と、
  台帳ピン済みの上流 license.txt（全文）で確認できる。
- OpenSSL 1.1.1 の二重ライセンスは、再配布の文書に OpenSSL Project の
  謝辞表示を含めること等を条件とするが、MSI／ZIP 内に当該表示はない。
  libpq の PostgreSQL License の著作権表示も MSI 内にない。
- MSVC ランタイムは Microsoft の再頒布条件でアプリケーションと共に
  再頒布が許諾される部類だが、条件の原本をコミット固定で示す手段がない。

**結論: 未決。** 残る不足: (1) libpq（PostgreSQL 13.4）と OpenSSL 1.1.1l の
ライセンス原本は版固定で対応付けられたが、両部品の表示が配布物内に
存在せず、配布条件の充足を配布物の範囲で確認できない。
(2) MSVC ランタイム 14.16.27033.0 は版同定のみで、条件の固定原本がない。

## 4. psqlodbc 18.00.0006（x64 / x86）— 残件解消（PR-1、2026-11-26）

未決の残件だった psqlODBC 行は、上流の最新版 18.00.0006 へ切り替えて
解消した。13.02.0000 の行は台帳から削除した（`latest: false` での残置は
しない。引退注記は本節末尾）。切替はオーナー指示（2026-11-26）により
x64 / x86 の両アーキテクチャで行い、台帳は `psqlodbc_x64.msi` と
`psqlodbc_x86.msi` の2レコードとなった。同名・同版の2レコードを CLI が
受理するための前提として、先行して PR-1a（#550）で
`ExternalSignedCatalogCohort` の重複同一性キーに assetName を追加し、
その修正を含む CLI v0.6.1 をリリースした（#551、タグ cli-v0.6.1、
2026-11-26 19:52 JST）。部品単位の固定は機械可読マニフェスト
`evidence/issue112-standalone-get-component-pins.json` を正本とし、本節は
その再掲である（`pin_upstream_originals.py --verify` でマニフェストと
本節の全ハッシュ・全サイズの一致を検証済み。両アーキテクチャとも
unaccountedPeCount = 0、unpinnedOriginalCount = 0、
redistributionUnconfirmedCount = 0）。

### 配布物の同一性

- `psqlodbc_x64.msi`: 4,587,520 B、SHA-256
  `8962543113df83410b74f113db1ef80717b65a1dc7869e18c24bd852dd65535f`
  — GitHub リリース（REL-18_00_0006）から取得。postgresql.org FTP の
  同一ファイルともバイト一致（cmp クリーン）を確認した。
- `psqlodbc_x86.msi`: 4,087,808 B、SHA-256
  `b5e3d749a148d56b184984b23305794c3d602317b30215945a5ca7c5233dc24a`
  — 同上（GitHub は 302 で release-assets CDN へ、FTP はリダイレクト
  なしの 200）。
- 両 MSI とも File テーブル全22行（DLL 10件＋PDB 4件＋文書8件）が
  完全なインストールマニフェストであり、CustomAction テーブルは
  存在しない。タグ REL-18_00_0006 は注釈付きタグを剥がしてコミット
  `96fa03dbc968c40920c907bf18d3b4cbd8efeebc` に解決される。

### 部品ごとの照合（要約）

- **psqlODBC 本体**: podbc30a.dll / podbc35w.dll の FileVersion は
  18.00.0006。WiX はビルド成果物 psqlodbc30a.dll / psqlodbc35w.dll を
  この名前で導入し、DuplicateFile テーブルで psqlodbc30a.dll /
  psqlodbc35w.dll という複製も配置する（pgenlist 系が import する
  名前）。pgenlist.dll / pgenlista.dll / pgxalib.dll は版リソースを
  持たない本体付属 DLL。リポジトリ唯一のサブモジュール libs/mimalloc
  @`229ec9cbdc81cf1ffb705cbd8a07503589847426` は出荷 DLL 内に痕跡が
  ない（mi_* エクスポート・文字列とも無し）。ライセンス上の注意:
  リポジトリの license.txt の本文は GNU Library General Public
  License Version 2（1991年6月）である一方、MSI のライセンス
  ダイアログ（installer/lgpl.rtf）が表示するのは GNU LGPL Version 2.1
  （1999年2月）であり、上流内部で版表記が一致していない。両方とも
  固定したため、この不一致自体が証跡として残る。ダイアログ RTF は
  x64 / x86 でバイト一致する。
- **libpq**: FileVersion 文字列「18.6」（固定版 18.0.6.0、ProductName
  PostgreSQL）。上流の GitHub Actions が postgres/postgres の
  REL_18_STABLE ブランチ（ワークフローにコミット固定なし）を
  チェックアウトし、OpenSSL 3_5_9 とともにビルドしたもの（PDB パス
  が裏付け）。原本は REL_18_6 タグのコミット
  `724edf9bde9d356724ad384a2e196edc3c9f80f7` の COPYRIGHT で固定した
  （REL_18_STABLE ブランチ自体の COPYRIGHT とバイト一致を別途確認
  済みであり、固定した文本はビルド元ブランチが保持する文本そのもの）。
- **OpenSSL**: 両 DLL とも FileVersion 3.5.9（バナー「OpenSSL 3.5.9
  29 Sep 2026」）。slproweb の Win64/Win32 OpenSSL-3_5_9 ビルド。
  原本はタグ openssl-3.5.9 の解決コミット
  `45e844fa2a14ec92d146bd8f5778ac130b6625fb` の LICENSE.txt
  （Apache-2.0）。当該コミットのルートに NOTICE ファイルは存在
  せず、Apache-2.0 §4(d) の対象はない。x86 側の DLL 名には
  アーキテクチャ接尾辞がない（libcrypto-3.dll / libssl-3.dll）。
- **Microsoft Visual C++ ランタイム**: vcruntime140.dll と
  msvcp140.dll（ともに FileVersion 14.51.36247.0）がアプリフォルダに
  同梱される。詳細は次項。

### Microsoft 条文の固定（オーナー決定 A、2026-11-26）

最終確認監査（M3）で不足とされた MSVC ランタイムの再頒布条件の固定
原本は、計画した2点固定（版固定 VC_redist 本体内の License.rtf ＋
コミット固定の再頒布リスト）がこの世代では物理的に不可能だったため、
オーナー決定 A（2026-11-26）により代替証跡で固定した。事実関係:

- 版対応は Microsoft の winget-pkgs マニフェスト
  `Microsoft.VCRedist.2015+.x64` / `.x86` の版 14.51.36247.0（DLL の
  FileVersion と4要素完全一致）で確定し、版固定 URL
  （download.visualstudio.microsoft.com の /download/pr/ 形式。
  aka.ms の浮動リダイレクトは使わない）から取得した VC_redist 本体の
  SHA-256 がマニフェストの InstallerSha256 と完全一致した。さらに
  本体内のペイロードを取り出し、同梱 DLL（vcruntime140.dll /
  msvcp140.dll）がペイロードとバイト一致することを両アーキテクチャで
  確認した（決定的な同一性証明）。
- この世代の VC_redist 本体には License.rtf がそもそも含まれて
  いない。Burn バンドルは WixStandardBootstrapperApplication の
  HyperlinkLicense 形式で、条文の所在として
  https://aka.ms/VCRedistLicense を指定するのみである（x64 本体と
  ペイロード MSI `bab5d0257e6a18a4a008e683442e3077b38172dd61af3cb1c588b46724a714e2` /
  `476427800c1c958dc4e71d9a0f2f3983b2608da70835db9ee5f3b8ac387e9617` の
  全体を走査し `{\rtf` の出現が0件であることを確認。x86 本体も同様）。
  再頒布リストの文書は Microsoft 社内リポジトリ
  （visualstudio-release-docs）から Learn へ発行されており、公開の
  コミット固定原本は存在しない。
- 決定 A の固定方法: インストーラ自身が指定する公式ページから条文
  テキストだけを決定的に抽出し、そのテキストを原本として固定する。
  取得記録（2026-11-26 19:56 JST 取得）:
  - 開始 URL: https://aka.ms/VCRedistLicense → 301 →
    https://visualstudio.microsoft.com/license-terms/vs2026-ga-visualcpp-v14-redist-runtime/
    （200）。ページ全体は 238,435 B、SHA-256
    `570914a701495d5e7542ee1398ff8490f9a922ce03b416a815b53284ee528462`。
  - ページは条文を埋め込み文書として提示しており、その実体は
    https://visualstudio.microsoft.com/wp-content/uploads/2025/10/Visual-C-V14-License-Redistributable_and_Runtime_ENU.docx
    （39,553 B、SHA-256
    `08651651a7602fc7c0e2763de0fde1ff9f868df2780597cd1775ee9d6441c783`、
    リダイレクトなしの 200）。
  - 抽出テキスト（DOCX の word/document.xml の段落を文書順に連結する
    決定的抽出。再実行で同一バイトになることを確認済み）は
    11,877 B、SHA-256
    `5169806e806b0ae92d8843298d7f83098117841df70a75d0dc42295ce13f7336`。
    写しを `evidence/ms-vc14-redist-license-terms.txt` として
    コミットした。文書の同一性はテキスト内の「MICROSOFT SOFTWARE
    LICENSE TERMS — MICROSOFT VISUAL C++ V14 REDISTRIBUTABLE and
    RUNTIME」「Last Updated: October 1, 2025」「EULA ID:
    Cpp_v14_ENU.1033」による。条文はアーキテクチャ中立であり、
    x64 / x86 の両方に適用される。
- 再頒布の実質は、Microsoft 公式の Visual Studio 2026 再頒布リスト
  （Distributable Code）「Visual C++ Runtime Files」の節で確認した:
  `[VisualStudioFolder]\VC\redist` 配下のファイルは無改変で自プロ
  グラムとともにコピー・配布でき、同梱 DLL はまさにそのファイル群を
  無改変でアプリフォルダに配置したものである。
- **vcruntime140_1.dll の扱い（x64）**: 同梱の msvcp140.dll と
  pgxalib.dll が import するが、MSI 内には配布されていない
  （システム側の VC++ 再頒布可能ランタイムへの依存。VC_redist
  ペイロード内には 50,112 B、SHA-256
  `a7146c08f89fe5b04541ab507cdb59ff7b44534d4ba3c668a426c6450a03434e`
  として存在する）。concrt140.dll も同梱されず、何からも import
  されていない。**x86 には vcruntime140_1.dll 自体が存在しない**
  （x86 の msvcp140.dll は VCRUNTIME140.dll のみを import する）。

### 部品ファイルと固定原本（マニフェスト再掲）

#### psqlodbc_x64.msi の部品ファイル（全 22 ファイル中 PE 10 件）

| 部品 | ファイル | バイト数 | SHA-256 |
|---|---|---|---|
| psqlODBC | `podbc30a.dll` | 657,920 | `0719fb503226e24ad228febfa57d5f05520dbc71e477b15b6223a63e7c6087d9` |
| psqlODBC | `podbc35w.dll` | 677,888 | `22e3af2e100716bb3e95bcf40089ea53b997c2728a64d094a0dcb315c285bfbd` |
| psqlODBC | `psqlodbc30a.dll` | 657,920 | `0719fb503226e24ad228febfa57d5f05520dbc71e477b15b6223a63e7c6087d9` |
| psqlODBC | `psqlodbc35w.dll` | 677,888 | `22e3af2e100716bb3e95bcf40089ea53b997c2728a64d094a0dcb315c285bfbd` |
| psqlODBC | `pgenlist.dll` | 31,232 | `f0a7ed0620a46f964486d2b5b35ad0337f9b6353377fe210e3dce5d01593b72d` |
| psqlODBC | `pgenlista.dll` | 31,232 | `fc545a6eca23337c8fe4026e9f45f286fa2bf75d9b9764f05e675158d0e7d8e6` |
| psqlODBC | `pgxalib.dll` | 45,568 | `5c744e46050491720be66279b612ad166cbd692346a254421aee90ac78cd1c98` |
| psqlODBC | `psqlodbc30a.pdb` | 2,387,968 | `91b0e286385f21f91d11ac9767385d7490c509e2dc6babdd0ffaf8d7a22f7dc1` |
| psqlODBC | `psqlodbc35w.pdb` | 2,461,696 | `fdd45b2b680d57db94c7530f38831839870a6ac3b0332c436b3131a6e74d6738` |
| psqlODBC | `pgenlist.pdb` | 798,720 | `e5be682d02448d34554333cbdbeb1b421c4f74f490856476ce411d37df0f6aa5` |
| psqlODBC | `pgenlista.pdb` | 798,720 | `16f321b3bc5870e3192aeb2fe63a9022d7ef526c9186140c6697a0d049e57744` |
| libpq (PostgreSQL) | `libpq.dll` | 384,000 | `da48d4ac0ca160d1eb41a759605a48af8c8757ad8634d16682d7b7fa5fe6a469` |
| OpenSSL | `libcrypto-3-x64.dll` | 6,996,480 | `81bc67d537fcd320d8ede1c5a49506629f0fd04e42ec7e9b0bab70a822d4fba5` |
| OpenSSL | `libssl-3-x64.dll` | 1,294,336 | `0242e31713fa090d75c0cc2e17c4ee2cbc3a27ca53f7a45729f30983d593bcb1` |
| Microsoft Visual C++ Runtime | `vcruntime140.dll` | 178,616 | `d1f4225df2cd877dbf130d5668a021dce3f94118455ff5ec952061c30afc9ce7` |
| Microsoft Visual C++ Runtime | `msvcp140.dll` | 643,512 | `7c26614e1d733892c2deac7e245ce115504b1d80592dd0a01b08e3e5a55f89ca` |

固定原本:

| 部品 | 原本 | バイト数 | SHA-256 |
|---|---|---|---|
| psqlODBC | https://raw.githubusercontent.com/postgresql-interfaces/psqlodbc/96fa03dbc968c40920c907bf18d3b4cbd8efeebc/license.txt | 25,746 | `3892f5f0585c553b72d0d4942d5a75935d0e8b0dcd0f5caa000a6853d648c67b` |
| psqlODBC | https://github.com/postgresql-interfaces/psqlodbc/releases/download/REL-18_00_0006/psqlodbc_x64.msi のメンバー `LicenseAgreementDlg/LicenseText (installer/lgpl.rtf)` | 48,209 | `46877f59ecaf27ce07f67f5645b5bec7d9f9628f2e1c047fbd99a3be980870cd` |
| libpq (PostgreSQL) | https://raw.githubusercontent.com/postgres/postgres/724edf9bde9d356724ad384a2e196edc3c9f80f7/COPYRIGHT | 1,198 | `3d6af92ff8a4c2cdf69afb1cf44edea727922f5cd0cf8b5f72b11cdecac8fdfd` |
| OpenSSL | https://raw.githubusercontent.com/openssl/openssl/45e844fa2a14ec92d146bd8f5778ac130b6625fb/LICENSE.txt | 10,175 | `7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a` |
| Microsoft Visual C++ Runtime | https://download.visualstudio.microsoft.com/download/pr/ebdab8e5-1d7b-4d9f-a11b-cbb1720c3b12/843068991DAAA1F73AD9F6239BCE4D0F6A07A51F18C37EA2A867E9BECA71295C/VC_redist.x64.exe | 18,731,856 | `843068991daaa1f73ad9f6239bce4d0f6a07a51f18c37ea2a867e9beca71295c` |
| Microsoft Visual C++ Runtime | https://visualstudio.microsoft.com/license-terms/vs2026-ga-visualcpp-v14-redist-runtime/（抽出テキストのコミット済み写し: `evidence/ms-vc14-redist-license-terms.txt`） | 11,877 | `5169806e806b0ae92d8843298d7f83098117841df70a75d0dc42295ce13f7336` |

#### psqlodbc_x86.msi の部品ファイル（全 22 ファイル中 PE 10 件）

| 部品 | ファイル | バイト数 | SHA-256 |
|---|---|---|---|
| psqlODBC | `podbc30a.dll` | 587,776 | `82df0b1179f79f37aa0dca426c1b1412da7b2c20ccf903b29dc4b944db0bd9b0` |
| psqlODBC | `podbc35w.dll` | 601,088 | `81dac59e1080b4ab993df6f9c8d9177f4a831c6f03777739d5654e14a08612cf` |
| psqlODBC | `psqlodbc30a.dll` | 587,776 | `82df0b1179f79f37aa0dca426c1b1412da7b2c20ccf903b29dc4b944db0bd9b0` |
| psqlODBC | `psqlodbc35w.dll` | 601,088 | `81dac59e1080b4ab993df6f9c8d9177f4a831c6f03777739d5654e14a08612cf` |
| psqlODBC | `pgenlist.dll` | 26,112 | `941e01d213bb9e6786437a1651bb5a0184830bd245ef147551760531543b44ab` |
| psqlODBC | `pgenlista.dll` | 26,112 | `360674bb0890063fa18bfdf300e333a02b58f149fac31d3e411f4c014fca8930` |
| psqlODBC | `pgxalib.dll` | 37,888 | `e97c459cecfdb5ac3c382921749da1f97ab4466778d9a033ef2ac92a90580267` |
| psqlODBC | `psqlodbc30a.pdb` | 2,445,312 | `cd0e4c922d44704b81c84750796648afbbd695367594f56a6bcf34c7887ebb5e` |
| psqlODBC | `psqlodbc35w.pdb` | 2,519,040 | `8b0bc806e5b9baff5eea318f20aee6f5bba2e7d1421a23c3c299f9f9e8441900` |
| psqlODBC | `pgenlist.pdb` | 798,720 | `94fcfa190a5f0a27ba201b45e24c2cdb20be7f8d626b686c8d5de2aaed118eaa` |
| psqlODBC | `pgenlista.pdb` | 798,720 | `be3ecafc39e5d83e3aa4df5735275ed54f57c34083519e96dc2ed0a3ced73073` |
| libpq (PostgreSQL) | `libpq.dll` | 332,288 | `9332cc850b986b33ce3d7ee00a291a49fc1f46ff519fd07fb3f297b0c862fd7e` |
| OpenSSL | `libcrypto-3.dll` | 4,490,752 | `2daf2ad5346c7c51a3427a7db852d4c4f6ac5f9d78dada535aaff7ab716ac706` |
| OpenSSL | `libssl-3.dll` | 1,067,520 | `113e29a66da47888e3f51347d1a13fc8bb707d953c197d30fce16ab11372fb2b` |
| Microsoft Visual C++ Runtime | `vcruntime140.dll` | 123,328 | `2fa6efc053203460a23d3a25158f227d895d2dadc63acc1a372da97c3a4281c3` |
| Microsoft Visual C++ Runtime | `msvcp140.dll` | 618,944 | `f0cda2a0cf1fe6fbbf579b9098462329d3aaa7513a207af2e0f33b01456e388a` |

固定原本:

| 部品 | 原本 | バイト数 | SHA-256 |
|---|---|---|---|
| psqlODBC | https://raw.githubusercontent.com/postgresql-interfaces/psqlodbc/96fa03dbc968c40920c907bf18d3b4cbd8efeebc/license.txt | 25,746 | `3892f5f0585c553b72d0d4942d5a75935d0e8b0dcd0f5caa000a6853d648c67b` |
| psqlODBC | https://github.com/postgresql-interfaces/psqlodbc/releases/download/REL-18_00_0006/psqlodbc_x86.msi のメンバー `LicenseAgreementDlg/LicenseText (installer/lgpl.rtf)` | 48,209 | `46877f59ecaf27ce07f67f5645b5bec7d9f9628f2e1c047fbd99a3be980870cd` |
| libpq (PostgreSQL) | https://raw.githubusercontent.com/postgres/postgres/724edf9bde9d356724ad384a2e196edc3c9f80f7/COPYRIGHT | 1,198 | `3d6af92ff8a4c2cdf69afb1cf44edea727922f5cd0cf8b5f72b11cdecac8fdfd` |
| OpenSSL | https://raw.githubusercontent.com/openssl/openssl/45e844fa2a14ec92d146bd8f5778ac130b6625fb/LICENSE.txt | 10,175 | `7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a` |
| Microsoft Visual C++ Runtime | https://download.visualstudio.microsoft.com/download/pr/57eef8ae-a341-46c3-b0bc-c041027b54cd/F0BAB33A302B3CDB2E11113760D016F54FD3D2632C65BA7834FAC4F0ABD7F1A3/VC_redist.x86.exe | 6,941,536 | `f0bab33a302b3cdb2e11113760d016f54fd3d2632c65ba7834fac4f0abd7f1a3` |
| Microsoft Visual C++ Runtime | https://visualstudio.microsoft.com/license-terms/vs2026-ga-visualcpp-v14-redist-runtime/（抽出テキストのコミット済み写し: `evidence/ms-vc14-redist-license-terms.txt`） | 11,877 | `5169806e806b0ae92d8843298d7f83098117841df70a75d0dc42295ce13f7336` |

### 配布条件と結論（psqlODBC 18.00.0006）

- ドライバ本体の LGPL 条件は、MSI のライセンスダイアログが表示する
  LGPL 2.1 全文（固定済み）と、リリースコミットで固定した上流
  license.txt で確認できる（両者の版表記の不一致は上記のとおり
  記録した）。
- libpq の PostgreSQL License と OpenSSL 3.5.9 の Apache-2.0 は、
  正確な版の原本をコミット固定で対応付けた。両部品の表示が MSI 内に
  存在しない点は、上流配布物の配布形態の特性として記録する
  （K4 解釈 B）。
- MSVC ランタイムは、版固定 VC_redist 本体のハッシュ固定とペイ
  ロードのバイト一致で同定を確定し、条文テキストはオーナー決定 A
  の方法で固定し、再頒布許諾は Microsoft 公式の再頒布リストで
  確認した。

**結論: 成立**（オーナー決定 2026-11-26、K4 解釈 B、および条文固定に
ついて同日のオーナー決定 A）。全部品について同定・原本固定・再配布
許諾がそろい、マニフェストの3カウントは両アーキテクチャとも 0 で
ある。これにより standalone の未決残件は消滅し、両台帳合計は
26行中 **成立26・未決0** となった。

### 13.02.0000 の引退注記

13.02.0000（`psqlodbc_13_02_0000-x64.zip`、3,868,961 B、SHA-256
`0d2f93c43752019c5e35f4369b1c32b40671f90a833dff3c7273569b6cbf1808`）は
台帳から削除した。理由: CVE-2026-109448 および
CVE-2026-120057..120067 の対象版であること、同梱 OpenSSL 1.1.1l が
サポート終了済みであること、VS 2017 再頒布条件の固定原本が存在
しないこと。旧行の照合記録は本記録 §3 とカタログコミット
`7480a281` の時点の台帳に保存される（Git 履歴は書き換えない）。


## 対応表への反映

本記録（PR6）により、対応表の standalone 3行は PR5 の「成立」から
いったん**未決**へ戻った（direct-get 24行と合わせて 27行中
成立24・未決3、再監査の判定と一致）。その後、表示を含まない配布形態に
対する K4 の扱いについてオーナー決定（2026-11-26、解釈 B）が下り、
PR7（#547）で3行ともいったん**成立**となった（27行中 成立27・未決0）。
しかし最終確認監査（M3）が、PostGIS と psqlODBC の2行は本記録自体に
固定原本の不足が明記されており解釈 B の根拠を満たさないとして FAIL と
判定した。オーナー決定（2026-11-26、選択肢 B）により、この2行は
**未決**に戻り、対応表は 27行中 **成立25・未決2** となった。
PgBouncer は成立のままである。未決の2行は明記された残件として
F フェーズの台帳管理へ引き継ぎ、E3 はこの状態で完了する。終了記録
（`j05-observe-only-retirement.md`）の項目4・項目7も本決定に合わせて
更新した。

その後、PostGIS 行はオーナー決定 D3（2026-11-26）により台帳から
引退した（冒頭の D3 記録を参照）。対応表は 26行中
**成立25・未決1** となり、未決の残件は psqlODBC のみとなった。
PostGIS 行は残件として F フェーズへ引き継がない。

その後、psqlODBC 行は PR-1（2026-11-26）で上流 18.00.0006
（x64 / x86 の2レコード）へ切り替えて成立とし（§4）、対応表は
26行中 **成立26・未決0** となった。未決の残件は消滅し、F フェーズへ
引き継ぐ未決残件はない。
