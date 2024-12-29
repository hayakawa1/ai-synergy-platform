# AI Synergy - エンジニアマッチングプラットフォーム

AI Synergyは、AIを活用してシステム開発の依頼者と開発者を結ぶ新しい形のマッチングプラットフォームです。

## 主な機能

- Google認証によるログイン
- クライアントによる案件登録
- エンジニアによる案件検索と提案
- 案件の期限管理
- プロフィール管理

## 技術スタック

- Python 3.8+
- Flask
- SQLAlchemy
- Google OAuth2.0
- Tailwind CSS

## セットアップ

1. リポジトリをクローン
```bash
git clone [repository-url]
cd engineer-matching
```

2. 仮想環境を作成し、有効化
```bash
python -m venv venv
source venv/bin/activate  # Unix系
venv\Scripts\activate     # Windows
```

3. 依存パッケージをインストール
```bash
pip install -r requirements.txt
```

4. 環境変数の設定
`.env`ファイルを作成し、以下の変数を設定：
```
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
```

5. データベースの初期化
```bash
flask db upgrade
```

6. 開発サーバーの起動
```bash
python app.py
```

## ライセンス

MIT License 