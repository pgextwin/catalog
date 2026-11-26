# J05 observe-only 終了記録（E3 PR4）

記録日: 2026-11-26（JST）
更新: E3 PR5（監査是正、2026-11-26）で項目4と手順④の結果を更新した。
さらに E3 再監査（M3）が standalone 3行を未決と判定したため、PR6
（2026-11-26）で証跡を部品単位まで深化させ、項目4の K4 対応付けは
standalone 3行について**未完（未決）**に改めた。その後、PR7
（#547）でオーナー決定（2026-11-26、K4 解釈 B）により3行とも成立
とし、項目4の K4 対応付けは完了したとしたが、最終確認監査（M3）が
PostGIS と psqlODBC の2行は固定原本の不足により解釈 B の根拠を
満たさないとして FAIL と判定した。オーナー決定（2026-11-26、
選択肢 B）により、この2行は未決の残件として F フェーズの台帳管理へ
引き継ぎ、E3 はこの状態で完了する。項目4の対応付けは
成立25・未決2である（下記）。
さらにその後、オーナー決定 D3（2026-11-26）により PostGIS 3.6.2
（PG14）行は台帳から引退し（原本チャネル OSGeo に 3.6.2 の成果物が
存在しない Case D、および PG14 の上流サポート終了 2026-11-12 が
根拠。3.6.1 への版下げはしない）、項目4の対応付けは
成立25・未決1（未決は psqlODBC のみ）となった（下記）。
最後に、残る psqlODBC の未決は PR-1（2026-11-26）で解消した。
上流の最新版 18.00.0006 へ x64 / x86 の両アーキテクチャで切り替え、
部品単位の固定を機械可読マニフェスト
`evidence/issue112-standalone-get-component-pins.json` に集約し、
MSVC ランタイムの再頒布条件の固定原本はオーナー決定 A
（2026-11-26）によりインストーラ指定の公式ページから決定的に
抽出した条文テキストで固定した。項目4の対応付けは
成立26・未決0 となり、未決の残件は消滅した（下記）。
対象: J05 決定（旧 external-11 署名 admission は更新せず、失効後は検証側の
observe-only とする）の終了処理。設計正本は `DESIGN.md` §4.2（終了条件7項目）と
§4.4（E3 の手順）。本記録は証跡の所在を示すものであり、J05 の再発行・再署名は
一切行っていない。

## 実施した変更

### Build（pgextwin/build、ブランチ `proposal-e/e3-pr4-j05-cutoff`、コミット 704d11b）

- `.github/workflows/external-direct-get-issuer.yml`
  - `workflow_dispatch` の選択肢から `qualified_cohort` を削除（残りは
    pg_trickle / hypopg / portalcorp_pgvector で、従来どおり存続）
  - job の `if` 条件から `qualified_cohort` を削除
  - 取得ステップの reviewed 系3方向フェッチ（pg_trickle / reviewed_pg14_17 /
    reviewed_pg18）を単一取得へ戻した
  - issuer ステップの `qualified_cohort` 分岐と専用 env（ORIGINAL_PG18_DIR /
    ORIGINAL_PG14_17_DIR）・後始末行を削除
  - independent-verify の 11件分岐と 5/7件分岐（いずれも cohort 形状専用）を削除。
    未知のレコード数は従来どおり fail-closed（"unsupported exact signed cohort"）
  - propose-public-pin-pr の `qualified_cohort` ケースを削除
- `scripts/external-direct-get-issuer.py`: 共有の owner-run 検証
  `validate_original_owner_run` の許可集合から `qualified_cohort` を削除。
  孤児化した cohort issuer／pin-pr モジュールが直接起動されても検証で拒否される
- テスト: 退役状態を固定するよう更新（hypopg-cohort テストの選択肢集合、
  qualified-cohort テストの workflow 形状アサーション）＋ issuer テストに
  `test_retired_qualified_cohort_dispatch_is_denied` を追加
- cohort 専用モジュール群（qualified-cohort-issuer / -pin-pr、reviewed-*、
  originals.sh の reviewed_* ターゲット）の物理削除は DESIGN §4.5 により E4 の
  担当範囲であり、本 PR では到達不能化までにとどめる

### Catalog（pgextwin/catalog、同名ブランチ）

- `.github/workflows/validate.yml`: 署名 pin 検証器
  （`scripts/validate_public_get_pin.py`）のステップを削除。通常 CI が失効済み
  admission のオンライン Sigstore 検証に依存する状態を解消した
- `.github/workflows/cli-candidate.yml`: Windows ステップから検証器の呼び出しと
  専用 env を削除。署名メタデータの Git blob バイト忠実性チェック
  （`git hash-object --no-filters`）は存続し、ステップ名をバイト確認のみの
  名称へ変更。PR パストリガーは変更なし
- `.github/workflows/archive-pin-audit.yml`: 挙動は不変（手動 dispatch +
  `--all-online`）。ヘッダーコメントを現行状態（唯一のオンライン再検証経路）
  に合わせて更新
- テスト2件を退役後の状態へ更新（検証器が per-PR 経路に存在しないこと、
  履歴監査に `--all-online` で残ること、バイト忠実性チェックが残ることを固定）
- 新規証跡: `evidence/issue112-direct-get-license-evidence-mapping.md`（手順④の
  対応表）と本記録

## 実際の停止範囲

- **自動発行**: 旧来から存在しない（issuer は `workflow_dispatch` 専用）。
  スケジュール・イベント駆動の再発行経路は元々なく、本 PR でも新設していない
- **手動再発行**: `qualified_cohort` の dispatch 選択肢、job 条件、取得・発行・
  独立検証・pin PR の各分岐、および共有 owner-run 検証の受理を全て閉じた。
  これにより Run 44030098818 型の11件 admission は、オーナー操作でも再発行
  できない
- **停止しないもの**: issuer の他選択肢（pg_trickle / hypopg /
  portalcorp_pgvector）、共有の発行 App、保護 Environment
  `external-direct-provider-publisher`、履歴監査（archive-pin-audit）、
  署名 feed の契約（`cli_signed_feed.py` は別契約として不変更）、
  `external_new_stable_watch.py`（履歴 diff の読み取りのみで認可効果なし）

## DESIGN §4.2 終了条件7項目の判定

1. **現在の参照の消滅 — 成立。**
   現在の Catalog 状態から旧 admission へ届く実行経路はない。.NET の
   `ExternalSignedCatalogCohort.StageLatestVerifiedAsync` と
   `ExternalSignedDirectGetAdmission` には本番呼び出し元が存在せず
   （`Program.cs` が呼ぶのは台帳のみを読む `DownloadAsync` /
   `ListDownloadsAsync`）、本 PR で通常 CI（validate / cli-candidate）からの
   検証器呼び出しも撤去した。残存は検証器スクリプト自体・テスト fixture・
   手動履歴監査（項目6）のみ。到達不能な .NET 型の物理削除は §4.5 により E4。
2. **自動・手動の再発行停止 — 成立。**
   上記「実際の停止範囲」のとおり。証跡: Build コミット 704d11b の差分と、
   拒否を固定する新規テスト `test_retired_qualified_cohort_dispatch_is_denied`
   （PASS）。
3. **Direct GET の成立 — 成立。**
   CLI の本番経路は2台帳（direct-get.json / standalone-get.json）のみを読み、
   旧 admission を参照しない。.NET 契約テスト 620 checks PASS（本 PR の変更前
   ベースライン、対象コードは不変更）で `ExternalDirectGetTests` を含む。
   公開 E2E ワークフロー（cli-published-e2e / issue112-external-public-get-e2e）
   は本 PR で変更していない。
4. **中核4点の維持 — 署名・完全性・認可は維持。K4 の対応付けは
   成立26・未決0（PostGIS 3.6.2（PG14）行はオーナー決定 D3
   （2026-11-26）により引退し、残件ではない。psqlODBC の未決は
   PR-1（2026-11-26）で 18.00.0006 への切替により解消した）。**
   DESIGN §4.2 項目4の正本は「現用対象に適用される署名・完全性・認可・
   ライセンス検証の維持（Direct GET の登録・更新時ライセンス原本照合
   証跡との対応付けを含む）」である。PR4 時点の本記録は署名 feed の
   成立（`.NET --signed-feed` PASS 94 checks、`cli_signed_feed.py` と
   feed 契約は変更対象外）に限っており、監査で不成立と判定された。
   PR5 で standalone 3行の照合記録を作成し対応表を成立27としたが、
   再監査（M3）は3行とも未決と判定した。PR6 で証跡を部品単位まで
   深化させた結果、direct-get 24行は成立のまま、standalone 3行は
   いったん未決となった（対応表は成立24・未決3）。未決の理由は、
   部品のライセンス原本はおおむね版固定で対応付けられたものの、
   配布物内に部品のライセンス表示が存在せず配布条件の充足を
   確認できない部品が残ること、および一部部品の版・原本が未確定で
   あることであり、詳細は照合記録
   `evidence/issue112-standalone-get-license-verification.md` にある。
   その後、オーナー決定（2026-11-26、K4 解釈 B）により、外部
   Direct GET については部品同定・原本固定・各部品ライセンスの
   再配布許諾確認をもって K4 が充足するとされ、配布物内に再現
   されないライセンス文は上流配布物の配布形態の特性として記録する
   こととなった。根拠: Established under owner decision 2026-11-26 (K4 interpretation B): component identification, pinned originals, and redistribution permission confirmed for each component license; license texts not reproduced inside upstream's distribution artifacts are recorded as a distribution-form characteristic of the upstream artifact.
   PR7（#547）ではこの根拠により standalone 3行は成立となり、
   対応表は成立27・未決0、項目4の K4 対応付けは完了したとした。
   しかし最終確認監査（M3）は、PostGIS（libthai・libdatrie の版と
   固定原本が未確定、GMP・FreeXL は原本未取得、GDAL 内の Arrow
   静的リンクが未検証）と psqlODBC（MSVC ランタイムの再頒布条件の
   固定原本がない）の2行について、照合記録自体に固定原本の不足が
   明記されており、上記の根拠が求める「固定原本」を満たさないとして
   FAIL と判定した。PgBouncer は全部品の版・固定原本・再配布許諾が
   記録されており成立のままである。オーナー決定（2026-11-26、
   選択肢 B）により、この2行は未決に戻し、対応表は
   **成立25・未決2** となった。項目4の K4 対応付けは、未決の2行を
   明記された残件として F フェーズの台帳管理へ引き継ぐ形で扱い、
   E3 はこの状態で完了する。
   その後の残件解消で PostGIS 行はオーナー決定 D3（2026-11-26）
   により引退したため、項目4の K4 対応付けは一時
   **成立25・未決1**（未決は psqlODBC のみ）となった。PostGIS 行の
   引退根拠は、原本チャネル（OSGeo）の PG14 ディレクトリに 3.6.2 の
   成果物が存在しないこと（最新は 3.6.1。Case D）と、PG14 の上流
   サポート終了（2026-11-12）であり、PostGIS 行を成立として
   扱ったものではない。
   最後に、psqlODBC の未決は PR-1（2026-11-26）で解消した。
   上流の最新版 18.00.0006（2026-11-02 のセキュリティリリース）へ
   x64 / x86 の両アーキテクチャで切り替え（オーナー指示
   2026-11-26）、全部品の同定・原本固定・再配布許諾を機械可読
   マニフェスト `evidence/issue112-standalone-get-component-pins.json`
   で確定した。最終確認監査で不足とされた MSVC ランタイムの
   再頒布条件の固定原本は、オーナー決定 A（2026-11-26）により、
   インストーラが指定する公式ページ
   （aka.ms/VCRedistLicense → visualstudio.microsoft.com の
   VS2026 VC++ v14 再頒布条項）から決定的に抽出した条文テキスト
   （`evidence/ms-vc14-redist-license-terms.txt`）で固定した。
   項目4の K4 対応付けの現行状態は **成立26・未決0** であり、
   未決の残件は消滅した。実施記録は照合記録
   `evidence/issue112-standalone-get-license-verification.md` §4。
   署名・完全性・認可の各境界は本 PR 群で変更しておらず、
   既存テストで維持を確認している。
5. **履歴証跡の固定 — 成立。**
   Run 44030098818 の admission 原本と Sigstore attestation は Catalog Git 内に
   凍結保存されている（`external/signed-direct-get/qualified_cohort/run-44030098818/`、
   登録コミット 1b06cff）。原本の固定値: issuerRunId 44030098818、
   issuedAt 2026-11-17T06:18:01Z、expiresAt 2026-11-18T06:18:01Z
   （= 2026-11-18 15:18:01 JST、J05 記録と一致）、issuerCommit 3a874e70…、
   catalogCommit 86e0ac5d…、App 5609317、Environment
   external-direct-provider-publisher。`latest.json`（admissionSha256
   b746769d…）を含む `external/` 配下は本 PR で一切変更していない
   （git 差分ゼロを確認）。
6. **履歴監査の保存 — 成立。**
   `archive-pin-audit.yml` は手動 dispatch 専用のまま、検証器を `--all-online`
   で呼び、全アーカイブ（失効分を含む）を再検証できる。更新後のテストが
   その存在を固定している。
7. **監視役目の終了 — 終了条件はそろった（ジョブ終了操作自体は
   本 PR の範囲外）。**
   項目1〜3・5・6 の証跡はそろった。項目4については、オーナー決定
   （2026-11-26、選択肢 B）により、未決の2行（PostGIS と
   psqlODBC）を明記された残件として F フェーズの台帳管理へ
   引き継ぐことをもって、J05 監視の安全な終了条件はそろったものと
   する。その後 PostGIS 行はオーナー決定 D3（2026-11-26）により
   引退したため、F フェーズへ引き継ぐ未決の残件は psqlODBC のみ
   となった（PostGIS 行は引退であり、成立として扱ったものではない）。
   さらにその後、psqlODBC の未決は PR-1（2026-11-26）で解消した
   ため、現時点で F フェーズへ引き継ぐ未決の残件はない。
   PR7（#547）で記載した「standalone 3行の成立
   （成立27・未決0）を根拠とする完了」の文言は、本決定により
   置き換えられる。運用監視ジョブ自体の終了は親タスク側の別作業で
   あり、本 PR では行わない。

## 手順④ ライセンス証跡対応付けの結果

対応表: `evidence/issue112-direct-get-license-evidence-mapping.md`

- direct-get.json: 24行中 **成立24・未決0**
- standalone-get.json: 3行中 **成立3・未決0**（PgBouncer 1行と
  psqlODBC 18.00.0006 の x64 / x86 2行。対応表では psqlODBC を
  1行として数える。E3 PR6 で深化した時点では PgBouncer のみ成立、
  psqlODBC は未決の残件だった。PostGIS 3.6.2（PG14）行は
  オーナー決定 D3（2026-11-26）により引退し、psqlODBC は PR-1
  （2026-11-26）で成立とした。下記）
- 合計: 26行中 **成立26・未決0**

PR4 時点では standalone の3行（postgis 3.6.2（PG14 セットアップ EXE）、
pgbouncer 1.26.1、psqlodbc 13.02.0000）が未決だった。理由は登録
コミット 6b6d15f が件名のみで照合内容の記録がなく、台帳外の登録時
照合記録が確認できなかったためである。E3 PR5（監査是正）で、3行とも
配布物を台帳固定値で取得し直し、サイズ・SHA-256 の完全一致、配布物内
ライセンス文書と台帳ピン済み上流原本の byte 照合、同梱物の列挙、
配布条件の確認を実施し、実施記録
`evidence/issue112-standalone-get-license-verification.md` を証跡として
成立へ移した（各行の成立範囲は同記録に明記）。CLI 取得時の新しい
照合ゲートは増設していない。

その後、E3 再監査（M3）が3行とも未決と判定した。PR6（2026-11-26）で
同記録を部品単位まで深化させ、PR5 の事実誤り（PgBouncer の静的リンク
部品の見落とし、PostGIS の DLL 列挙漏れ等）を訂正した。深化後も、
配布物内に部品のライセンス表示がなく配布条件の充足を確認できない
部品と、版・原本が未確定の部品が残ったため、3行ともいったん未決の
ままとした。その後 PR7（#547）で、オーナー決定（2026-11-26、
K4 解釈 B）により3行ともいったん成立としたが、最終確認監査
（M3）が PostGIS と psqlODBC の2行は固定原本の不足により解釈 B の
根拠を満たさないとして FAIL と判定した。オーナー決定
（2026-11-26、選択肢 B）により、この2行は未決に戻り、項目4の
K4 対応付けは成立25・未決2となった。未決の2行は明記された残件
として F フェーズの台帳管理へ引き継ぎ、E3 はこの状態で完了する。

その後、PostGIS 行はオーナー決定 D3（2026-11-26）により台帳から
引退した（根拠は項目4の D3 記録のとおり）。対応付けは一時
成立25・未決1 となり、F フェーズの台帳管理へ引き継ぐ未決の残件は
psqlODBC のみとなった。

最後に、その psqlODBC も PR-1（2026-11-26）で上流 18.00.0006
（x64 / x86）へ切り替えて成立とした（根拠は項目4の PR-1 記録の
とおり）。現行の対応付けは **成立26・未決0** であり、F フェーズの
台帳管理へ引き継ぐ未決の残件はない。

## R10（ExternalOriginalBatchStager）の扱い

同一 digest・同一条件の ZIP 構造／CRC 反復として整理対象だったが、精査の
結果、**安全に除ける反復はなく、コードは変更しない**。検証は3回あるが、
転送時（メモリ内バイト）と保存後（ディスク上の実ファイルを保持ハンドル
経由で再読）は対象バイトの出所と時点が異なり、確定直前の再検証は §4.1
No.8 が維持を命じる対象そのもの（ディレクトリロック・stage tree 検証・
ハンドル解放をまたぎ、create-only atomic commit の直前）。保存後と確定
直前の実バイト SHA-256／サイズ、保持ハンドルと file identity、stage tree、
権限、確定時の適用認可、create-only atomic commit は全て現行どおり維持
される。

## テスト結果（変更前後）

- Build direct-get 系7ファイル: 変更前 全 PASS → 変更後 全 PASS
  （issuer テストは退役拒否の新規ケースを含む）
- Catalog Python: 変更前 1090 tests OK → 変更後 1090 tests OK
- Catalog .NET: 変更前ベースライン 全体 PASS 620 checks /
  `--signed-feed` PASS 94 checks（本 PR は .NET コード不変更）
