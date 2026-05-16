# py-webauthn-passkey

Amazon Cognito を使わず、**py_webauthn + SQLite + bcrypt** でパスキー（WebAuthn/FIDO2）認証を実装したサンプルアプリです。

Discoverable Credentials（メールアドレス省略ログイン）に対応しています。

## 記事

Zenn「パスキー完全ガイド」第10章 — py_webauthnで実装するパスキー認証

## セットアップ

### 1. 依存パッケージのインストール

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

### 2. 環境変数の設定（任意）

デフォルトは `localhost:5000` で動作します。本番環境や ngrok を使う場合は以下を設定してください。

| 変数名 | 説明 | デフォルト |
|---|---|---|
| `RP_ID` | Relying Party ID（ドメイン名） | `localhost` |
| `RP_NAME` | サービス名 | `Passkey Sample` |
| `ORIGIN` | オリジン（プロトコル・ポート含む） | `http://localhost:5000` |
| `SECRET_KEY` | Flask セッション署名キー | 起動時にランダム生成 |

### 3. アプリの起動

```bash
python app.py
```

http://localhost:5000 でアクセスできます。

### 4. ngrok で外部公開（パスキーに必要）

WebAuthn は HTTPS または `localhost` が必要です。外部デバイスでテストする場合は ngrok で公開します。

```bash
ngrok http 5000
```

起動後、環境変数を ngrok のドメインに合わせて設定してください。

```bash
export RP_ID=xxxx.ngrok-free.app
export ORIGIN=https://xxxx.ngrok-free.app
python app.py
```

## ファイル構成

| ファイル | 内容 |
|---|---|
| `auth.py` | WebAuthn 登録・認証・パスワード管理・DB操作 |
| `app.py` | Flask ルート定義 |
| `static/passkey.js` | ブラウザ側の WebAuthn API ラッパー |
| `templates/` | Jinja2 テンプレート |
