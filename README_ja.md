# pgextwin カタログ

[English](README.md) | 日本語

PostgreSQL拡張機能の**非公式Windows x64バイナリ**を探す場合は、[pgextwinの日本語サイト](https://pgextwin.github.io/website/ja/)をご利用ください。

このリポジトリは、サイトに掲載するダウンロード情報を管理しています。**ZIPファイルの配布先ではありません。** バイナリとリリースノートは、各拡張機能のGitHub Releasesページにあります。

## 配布元と詳しい検証情報

利用者向けの配布元は、公式・コミュニティによる **external** と、参考ビルド・
独自ビルドを含む **pgextwin** の2種類に分類しています。CLIはpgextwinの成果物には
署名付きCatalogフィードを、外部成果物にはバージョンごとのライセンス確認と
原本の照合情報がそろった記録を使います。参照したソース、
採用・不採用の理由、依存関係、検証の証跡は
[外部成果物の調査・選択方針](docs/issue-112-external-windows-sources.md)にまとめています。

## Windows CLIでパッケージを取得する

Windows CLI v0.3.18では、PostgreSQLが入っていないPCでも、外部の拡張機能、空間拡張バンドル、
ツール、ドライバーを検索して取得できます。たとえば、`pgextwin list --category spatial` で
空間拡張を一覧表示し、`pgextwin download psqlodbc` でドライバーを取得できます。
ファイルを保存する前に、SHA-256と正確なバイト数を照合します。

[ダウンロード手順](docs/issue-112-public-external-original-get.md) ·
[CLIのリリース一覧](https://github.com/pgextwin/catalog/releases)

## 確認できる情報

- 利用中のPostgreSQLメジャーバージョン向けの公開状況
- 公開済みZIPのダウンロード先とSHA-256チェックサム
- 事前ロードや追加の実行ファイルなど、インストール時の要件
- 各Releaseに付属するSPDX形式のSBOM、脆弱性レポート、署名付き証明の有無

PostgreSQLのサポートが終了しても、過去のバイナリが残る場合があります。ダウンロードできることは、上流のサポートが続いていることを意味しません。

## 導入するときは

利用中のPostgreSQLメジャーバージョンと一致するZIPを選び、SHA-256を照合してください。インストール手順は各拡張機能のREADMEを、機能や制限事項は上流プロジェクトの説明を参照してください。pgextwinはPostgreSQL、EDB、各拡張機能の開発元とは独立しています。

[日本語カタログ](https://pgextwin.github.io/website/ja/) · [English catalog](https://pgextwin.github.io/website/en/)
