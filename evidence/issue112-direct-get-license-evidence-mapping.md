# Direct GET 台帳行と登録時ライセンス照合証跡の対応表

E3 PR4（DESIGN.md §4.4 手順④）の成果物。`external/direct-get.json`（24行）と
`external/standalone-get.json`（3行）の全行について、各行の固定値（版・PG・成果物）
を、登録・更新時点の原本バイトによるライセンス照合証跡へ対応付ける。

## 判定基準

- **成立**: 台帳行とは別に、登録時点の照合記録（レビュー文書／受領 JSON／署名
  admission 内の版別 treatment／登録コミット本文）が、当該版・当該成果物の固定値に
  結び付いて存在し、台帳 `licenseEvidence` のバイト固定（SHA-256）と整合する。
- **未決**: 台帳内の `licenseEvidence`（URL＋SHA-256）しか存在せず、登録時の独立した
  照合記録がリポジトリ内で確認できない。推測では埋めない。未決は「ライセンスが
  無効」という意味ではなく、「登録時照合への対応付けが記録から成立しない」という
  意味である。
- 次のものは単独では証跡として扱わない: 別版の調査の流用、ZIP ハッシュ・サイズの
  一致のみ、タグ参照 URL のみ。
- 本対応表は記録であり、CLI 取得時の新しい照合ゲートは増設しない。

## 照合方法（2026-11-26、E3 PR4 実施時）

- 凍結 admission（Run 44030098818）11レコードと direct-get 11行の資産同一性
  （assetId・releaseId・バイト数・SHA-256・資産名）: 全行一致。
- 同 admission の licenseUrl と台帳 licenseEvidence URL: 11行全て一致。
  noticeTreatment・dependencyTreatment は全レコードに存在。
- 緩和レビュー受領 JSON（`evidence/issue112-relaxed-external-fetch-20261117.json` の
  `downloaded`）のバイト数・SHA-256 と pglogical／pg_crash 8行: 全行一致。
- OSGeo PG19 行: 登録コミット 92e508b 本文記載の ZIP バイト数・SHA-256 が台帳行と一致。
- standalone 3行（E3 PR5 で照合実施、PR6 で深化・訂正）: 配布物を
  台帳固定値で取得し直し、サイズ・SHA-256 の完全一致を確認。PR5 の
  照合記録に対し、再監査（M3）の指摘で PR6 が部品単位の深化を行い、
  PR5 の事実誤り（PgBouncer の静的リンク部品の見落とし等）を訂正した。
  3行とも**未決**である。実施記録は
  `evidence/issue112-standalone-get-license-verification.md`。

## 結果概要

- direct-get.json: 24行中 **成立24・未決0**
- standalone-get.json: 3行中 **成立0・未決3**（PR4 時点では未決3。
  E3 PR5 で登録時相当の原本照合を実施して成立へ移したが、再監査が
  未決と判定し、PR6 の深化でも配布条件の充足確認と一部部品の
  版・原本確定が残ったため未決に戻る）
- 合計: 27行中 **成立24・未決3**

## 対応表

| 拡張 | 版 | 台帳のライセンス表記 | PG | 成果物（固定値） | 配布方法 | 同梱依存 | 判定 | 証跡参照・理由 |
|---|---|---|---|---|---|---|---|---|

| oracle_fdw | 2.9.0 | PostgreSQL | 14 | oracle_fdw-2.9.0-pg14-win64.zip（375533 B, sha256 91a9857041c3…） | direct-get.json | —（単体成果物） | 成立 | 凍結署名 admission（run-44030098818）の版別レコード（licenseUrl・noticeTreatment・dependencyTreatment を版別に保持。資産同一性と licenseUrl の台帳一致を 2026-11-26 に機械照合） |
| oracle_fdw | 2.9.0 | PostgreSQL | 15 | oracle_fdw-2.9.0-pg15-win64.zip（363671 B, sha256 3894a25a80cf…） | direct-get.json | —（単体成果物） | 成立 | 凍結署名 admission（run-44030098818）の版別レコード（licenseUrl・noticeTreatment・dependencyTreatment を版別に保持。資産同一性と licenseUrl の台帳一致を 2026-11-26 に機械照合） |
| oracle_fdw | 2.9.0 | PostgreSQL | 16 | oracle_fdw-2.9.0-pg16-win64.zip（365436 B, sha256 b9e8826d11c7…） | direct-get.json | —（単体成果物） | 成立 | 凍結署名 admission（run-44030098818）の版別レコード（licenseUrl・noticeTreatment・dependencyTreatment を版別に保持。資産同一性と licenseUrl の台帳一致を 2026-11-26 に機械照合） |
| oracle_fdw | 2.9.0 | PostgreSQL | 17 | oracle_fdw-2.9.0-pg17-win64.zip（371386 B, sha256 a67d0582e855…） | direct-get.json | —（単体成果物） | 成立 | 凍結署名 admission（run-44030098818）の版別レコード（licenseUrl・noticeTreatment・dependencyTreatment を版別に保持。資産同一性と licenseUrl の台帳一致を 2026-11-26 に機械照合） |
| oracle_fdw | 2.9.0 | PostgreSQL | 18 | oracle_fdw-2.9.0-pg18-win64.zip（365101 B, sha256 ad1fc057888b…） | direct-get.json | —（単体成果物） | 成立 | 凍結署名 admission（run-44030098818）の版別レコード（licenseUrl・noticeTreatment・dependencyTreatment を版別に保持。資産同一性と licenseUrl の台帳一致を 2026-11-26 に機械照合）＋PG18 direct-link review JSON |
| pgvector | 0.8.7 | PostgreSQL | 14 | vector.v0.8.7-pg14.zip（174619 B, sha256 51dd3626905d…） | direct-get.json | —（単体成果物） | 成立 | 凍結署名 admission（run-44030098818）の版別レコード（licenseUrl・noticeTreatment・dependencyTreatment を版別に保持。資産同一性と licenseUrl の台帳一致を 2026-11-26 に機械照合） |
| pgvector | 0.8.7 | PostgreSQL | 15 | vector.v0.8.7-pg15.zip（174667 B, sha256 33562f2d2bab…） | direct-get.json | —（単体成果物） | 成立 | 凍結署名 admission（run-44030098818）の版別レコード（licenseUrl・noticeTreatment・dependencyTreatment を版別に保持。資産同一性と licenseUrl の台帳一致を 2026-11-26 に機械照合） |
| pgvector | 0.8.7 | PostgreSQL | 16 | vector.v0.8.7-pg16.zip（174594 B, sha256 69dee8f23796…） | direct-get.json | —（単体成果物） | 成立 | 凍結署名 admission（run-44030098818）の版別レコード（licenseUrl・noticeTreatment・dependencyTreatment を版別に保持。資産同一性と licenseUrl の台帳一致を 2026-11-26 に機械照合） |
| pgvector | 0.8.7 | PostgreSQL | 17 | vector.v0.8.7-pg17.zip（174653 B, sha256 acd9d678200e…） | direct-get.json | —（単体成果物） | 成立 | 凍結署名 admission（run-44030098818）の版別レコード（licenseUrl・noticeTreatment・dependencyTreatment を版別に保持。資産同一性と licenseUrl の台帳一致を 2026-11-26 に機械照合） |
| pgvector | 0.8.7 | PostgreSQL | 18 | vector.v0.8.7-pg18.zip（174796 B, sha256 7c4ae0e2b2cb…） | direct-get.json | —（単体成果物） | 成立 | 凍結署名 admission（run-44030098818）の版別レコード（licenseUrl・noticeTreatment・dependencyTreatment を版別に保持。資産同一性と licenseUrl の台帳一致を 2026-11-26 に機械照合）＋PG18 direct-link review JSON |
| pg_trickle | 0.108.3 | Apache-2.0 | 18 | pg_trickle-0.108.3-pg18-windows-amd64.zip（7029107 B, sha256 c2841dacee6f…） | direct-get.json | —（単体成果物） | 成立 | 凍結署名 admission（run-44030098818）の版別レコード（licenseUrl・noticeTreatment・dependencyTreatment を版別に保持。資産同一性と licenseUrl の台帳一致を 2026-11-26 に機械照合） |
| pglogical | 2.4.8 | PostgreSQL | 15 | pglogical-2.4.8-pg15-w1-x64.zip（176749 B, sha256 ff60107d6ade…） | direct-get.json | —（単体成果物） | 成立 | 2026-11-17 緩和レビュー（文書＋受領 JSON）: PostgreSQL License を ACCEPT と判定し、正確な版のソース／生成元コミットを固定。受領 JSON のバイト数・SHA-256 が台帳行と完全一致（機械照合済み） |
| pg_crash | 0.3 | BSD-3-Clause | 15 | pg_crash-15-public-v0.3-1.zip（44130 B, sha256 161401c96ffe…） | direct-get.json | —（単体成果物） | 成立 | 2026-11-17 緩和レビュー（文書＋受領 JSON）: BSD-3-Clause を ACCEPT と判定し、正確な版のソースコミットを固定。受領 JSON のバイト数・SHA-256 が台帳行と完全一致（機械照合済み） |
| pglogical | 2.4.8 | PostgreSQL | 16 | pglogical-2.4.8-pg16-w1-x64.zip（176275 B, sha256 be599b6d3171…） | direct-get.json | —（単体成果物） | 成立 | 2026-11-17 緩和レビュー（文書＋受領 JSON）: PostgreSQL License を ACCEPT と判定し、正確な版のソース／生成元コミットを固定。受領 JSON のバイト数・SHA-256 が台帳行と完全一致（機械照合済み） |
| pg_crash | 0.3 | BSD-3-Clause | 16 | pg_crash-16-public-v0.3-1.zip（44275 B, sha256 94da1cd1acbe…） | direct-get.json | —（単体成果物） | 成立 | 2026-11-17 緩和レビュー（文書＋受領 JSON）: BSD-3-Clause を ACCEPT と判定し、正確な版のソースコミットを固定。受領 JSON のバイト数・SHA-256 が台帳行と完全一致（機械照合済み） |
| pglogical | 2.4.8 | PostgreSQL | 17 | pglogical-2.4.8-pg17-w1-x64.zip（176170 B, sha256 3cba8b233db5…） | direct-get.json | —（単体成果物） | 成立 | 2026-11-17 緩和レビュー（文書＋受領 JSON）: PostgreSQL License を ACCEPT と判定し、正確な版のソース／生成元コミットを固定。受領 JSON のバイト数・SHA-256 が台帳行と完全一致（機械照合済み） |
| pg_crash | 0.3 | BSD-3-Clause | 17 | pg_crash-17-public-v0.3-1.zip（34325 B, sha256 808f56bd6c4b…） | direct-get.json | —（単体成果物） | 成立 | 2026-11-17 緩和レビュー（文書＋受領 JSON）: BSD-3-Clause を ACCEPT と判定し、正確な版のソースコミットを固定。受領 JSON のバイト数・SHA-256 が台帳行と完全一致（機械照合済み） |
| pglogical | 2.4.8 | PostgreSQL | 18 | pglogical-2.4.8-pg18-w1-x64.zip（176460 B, sha256 1f69a4528b50…） | direct-get.json | —（単体成果物） | 成立 | 2026-11-17 緩和レビュー（文書＋受領 JSON）: PostgreSQL License を ACCEPT と判定し、正確な版のソース／生成元コミットを固定。受領 JSON のバイト数・SHA-256 が台帳行と完全一致（機械照合済み） |
| pg_crash | 0.3 | BSD-3-Clause | 18 | pg_crash-18-public-v0.3-1.zip（34331 B, sha256 37b9dbb8e385…） | direct-get.json | —（単体成果物） | 成立 | 2026-11-17 緩和レビュー（文書＋受領 JSON）: BSD-3-Clause を ACCEPT と判定し、正確な版のソースコミットを固定。受領 JSON のバイト数・SHA-256 が台帳行と完全一致（機械照合済み） |
| postgis | 3.6.2 | Multiple (PostGIS, pgRouting and bundled components) | 15 | postgis-bundle-pg15-3.6.2x64.zip（123986945 B, sha256 520c3fd7ebf9…） | direct-get.json | PostGIS 本体＋pgRouting＋同梱物群（PG14 セットアップ EXE。OSGeo レビュー文書の対象範囲外） | 成立 | OSGeo bundle ライセンスレビュー: 台帳の正確な SHA-256・サイズ固定への適用を明記し、同梱物ごとに照合（登録 #439 で同梱） |
| postgis | 3.7.0 | Multiple (PostGIS, pgRouting and bundled components) | 16 | postgis-bundle-pg16-3.7.0x64.zip（84037123 B, sha256 9fd299d661a0…） | direct-get.json | PostGIS 本体＋pgRouting＋同梱物群（PG14 セットアップ EXE。OSGeo レビュー文書の対象範囲外） | 成立 | OSGeo bundle ライセンスレビュー: 台帳の正確な SHA-256・サイズ固定への適用を明記し、同梱物ごとに照合（登録 #439 で同梱） |
| postgis | 3.7.0 | Multiple (PostGIS, pgRouting and bundled components) | 17 | postgis-bundle-pg17-3.7.0x64.zip（84044726 B, sha256 eceb7ed45276…） | direct-get.json | PostGIS 本体＋pgRouting＋同梱物群（PG14 セットアップ EXE。OSGeo レビュー文書の対象範囲外） | 成立 | OSGeo bundle ライセンスレビュー: 台帳の正確な SHA-256・サイズ固定への適用を明記し、同梱物ごとに照合（登録 #439 で同梱） |
| postgis | 3.7.0 | Multiple (PostGIS, pgRouting and bundled components) | 18 | postgis-bundle-pg18-3.7.0x64.zip（83739256 B, sha256 ac9e9486b3f9…） | direct-get.json | PostGIS 本体＋pgRouting＋同梱物群（PG14 セットアップ EXE。OSGeo レビュー文書の対象範囲外） | 成立 | OSGeo bundle ライセンスレビュー: 台帳の正確な SHA-256・サイズ固定への適用を明記し、同梱物ごとに照合（登録 #439 で同梱） |
| postgis | 3.7.0 | Multiple (PostGIS, pgRouting and bundled components) | 19 | postgis-bundle-pg19-3.7.0x64.zip（83705586 B, sha256 5d5630aa0405…） | direct-get.json | PostGIS 本体＋pgRouting＋同梱物群（明細表は PG15–18 用のみ存在。PG19 は登録コミットの照合完了記録による） | 成立 | 登録コミット 92e508b（#491）: コミット本文に「登録前に同梱物全ての版別ライセンス照合を完了」と記録され、ZIP のバイト数・SHA-256 が台帳行と一致。制限: PG19 専用の同梱物別明細表は存在しない（PG15–18 の表を PG19 の明細として流用していない） |
| postgis | 3.6.2 | Multiple (PostGIS and pgRouting primarily GPL-2.0-or-later) | 14 | postgis-bundle-pg14x64-setup-3.6.2-1.exe（104787481 B, sha256 f245ddfb104a…） | standalone-get.json | PostGIS 本体＋pgRouting＋同梱物群（PG14 セットアップ EXE。OSGeo レビュー文書の対象範囲外） | 未決 | E3 PR6 の深化記録 `evidence/issue112-standalone-get-license-verification.md`: 配布物が台帳固定値と完全一致、拡張部品と主要ランタイム（GDAL 3.9.2・GEOS 3.14.1・PROJ 8.2.1・OpenSSL 3.0.7・GTK スタック等）の版別ライセンス原本をコミット固定で対応付けた。一方、ランタイム大半のライセンス文が配布物内に実在せず配布条件の充足を確認できず、一部部品（libthai・GMP・FreeXL 等）は版・原本が未確定。再監査 M3 の未決判定を維持 |
| pgbouncer | 1.26.1 | ISC | — | pgbouncer-1.26.1-windows-x86_64.zip（2540874 B, sha256 5d3fa0bc9bd4…） | standalone-get.json | pgbouncer 本体＋静的リンク部品（libevent・OpenSSL） | 未決 | E3 PR6 の深化記録 `evidence/issue112-standalone-get-license-verification.md`: 配布物が台帳固定値と完全一致、ZIP 内 COPYRIGHT が台帳ピンと一致し上流原本ともテキスト同一（CRLF 化のみ）。PR5 の「第三者依存なし」は誤りで、exe は libevent 2.1.13-stable と OpenSSL 3.6.5 を静的リンク（提供元の固定コミットのビルド定義と実バイナリで確定）。両部品の原本は版固定で対応付けたが、Apache-2.0 文と libevent の表示が ZIP 内に存在せず、配布条件の充足を確認できない |
| psqlodbc | 13.02.0000 | LGPL-2.0-or-later | — | psqlodbc_13_02_0000-x64.zip（3868961 B, sha256 0d2f93c43752…） | standalone-get.json | MSI 内に libpq・OpenSSL 1.1・MSVC ランタイムを同梱 | 未決 | E3 PR6 の深化記録 `evidence/issue112-standalone-get-license-verification.md`: 配布物が台帳固定値と完全一致、ZIP 内 README.txt と上流 license.txt が台帳ピンと一致。同梱部品の版を確定し原本を版固定で対応付けた（libpq = PostgreSQL 13.4、OpenSSL 1.1.1l）が、両部品の表示が MSI 内に存在せず配布条件の充足を確認できず、MSVC ランタイム 14.16.27033.0 は版同定のみで条件の固定原本がない |
