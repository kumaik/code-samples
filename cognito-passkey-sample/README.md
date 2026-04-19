# cognito-passkey-sample

Amazon Cognito + Flask でパスキー（WebAuthn/FIDO2）認証を実装したサンプルアプリです。

## 記事

https://zenn.dev/kumaik/articles/cognito-passkey-flask

## セットアップ

### 1. 依存パッケージのインストール

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

### 2. 環境変数の設定

`.env.example` をコピーして `.env` を作成し、各値を設定します。

```bash
cp .env.example .env
```

| 変数名 | 説明 |
|---|---|
| `COGNITO_REGION` | AWS リージョン（例: `ap-northeast-1`） |
| `COGNITO_USER_POOL_ID` | User Pool ID |
| `COGNITO_CLIENT_ID` | パスワード認証用クライアント ID（シークレットあり） |
| `COGNITO_CLIENT_SECRET` | クライアントシークレット |
| `COGNITO_PASSKEY_CLIENT_ID` | パスキー認証用クライアント ID（シークレットなし） |
| `SECRET_KEY` | Flask セッション署名キー（任意の文字列） |

### 3. アプリの起動

```bash
bash scripts/start.sh
```

http://localhost:5000 でアクセスできます。

### 4. ngrok で外部公開（パスキーに必要）

WebAuthn は HTTPS が必要なため、ngrok などで外部公開します。

```bash
ngrok http 5000
```

Cognito の User Pool 設定でそのドメインを RP ID として登録してください。

## Cognito 設定要件

| 設定項目 | 値 |
|---|---|
| サインイン識別子 | メールアドレス |
| パスワード認証クライアントの認証フロー | `USER_PASSWORD_AUTH` を有効化 |
| パスキー認証クライアントの認証フロー | `USER_AUTH` を有効化 |
| パスキー認証クライアント | シークレットなし |
| WebAuthn（パスキー） | ngrok ドメインをサードパーティードメインとして登録 |
| MFA | **無効**（パスキーと Cognito MFA は併用不可） |
