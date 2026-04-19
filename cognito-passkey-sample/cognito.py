"""AWS Cognito 認証ヘルパー"""
import base64
import hashlib
import hmac
import json
import os

import boto3
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

REGION = os.environ["COGNITO_REGION"]
USER_POOL_ID = os.environ["COGNITO_USER_POOL_ID"]
CLIENT_ID = os.environ["COGNITO_CLIENT_ID"]
CLIENT_SECRET = os.environ["COGNITO_CLIENT_SECRET"]
PASSKEY_CLIENT_ID = os.environ["COGNITO_PASSKEY_CLIENT_ID"]  # シークレットなし・パスキー専用

# 公開API（initiate_auth など）は IAM 署名不要
_client = boto3.client(
    "cognito-idp",
    region_name=REGION,
    config=Config(signature_version=UNSIGNED),
)

# 管理API（admin_create_user など）は IAM 認証が必要
# 環境変数 AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY または ~/.aws/credentials を使用
_admin_client = boto3.client("cognito-idp", region_name=REGION)


def _secret_hash(username: str) -> str:
    msg = username + CLIENT_ID
    dig = hmac.new(CLIENT_SECRET.encode(), msg.encode(), hashlib.sha256).digest()
    return base64.b64encode(dig).decode()


class AuthError(Exception):
    pass


# ---------------------------------------------------------------------------
# ログイン
# ---------------------------------------------------------------------------

def authenticate(username: str, password: str) -> dict:
    """
    ユーザー名とパスワードで認証する。
    MFA が必要な場合は {"challenge": "SOFTWARE_TOKEN_MFA"|"MFA_SETUP", "session": ...} を返す。
    成功時は {"access_token": ..., "id_token": ..., "refresh_token": ...} を返す。
    失敗時は AuthError を送出。
    """
    try:
        resp = _client.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password,
                "SECRET_HASH": _secret_hash(username),
            },
            ClientId=CLIENT_ID,
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("NotAuthorizedException", "UserNotFoundException"):
            raise AuthError("ユーザー名またはパスワードが正しくありません")
        if code == "UserNotConfirmedException":
            raise AuthError("メールアドレスが未確認です。確認コードを入力してください")
        if code == "PasswordResetRequiredException":
            raise AuthError("パスワードのリセットが必要です")
        raise AuthError(f"認証エラー: {e.response['Error']['Message']}")

    result = resp["AuthenticationResult"]
    return {
        "access_token": result["AccessToken"],
        "id_token": result["IdToken"],
        "refresh_token": result["RefreshToken"],
    }


# ---------------------------------------------------------------------------
# ユーザー登録
# ---------------------------------------------------------------------------

def sign_up(username: str, email: str, password: str) -> None:
    """
    新規ユーザーを Cognito に登録する（メール送信なし・即時確認済み状態）。
    admin_create_user + admin_set_user_password を使用。
    失敗時は AuthError を送出。
    """
    try:
        _admin_client.admin_create_user(
            UserPoolId=USER_POOL_ID,
            Username=username,
            UserAttributes=[{"Name": "email", "Value": email}],
            MessageAction="SUPPRESS",  # 確認メール・ウェルカムメールを送信しない
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "UsernameExistsException":
            raise AuthError("そのメールアドレスはすでに使用されています")
        if code == "InvalidParameterException":
            raise AuthError(f"入力値が不正です: {e.response['Error']['Message']}")
        raise AuthError(f"登録エラー: {e.response['Error']['Message']}")

    try:
        _admin_client.admin_set_user_password(
            UserPoolId=USER_POOL_ID,
            Username=username,
            Password=password,
            Permanent=True,  # 仮パスワードではなく本パスワードとして設定
        )
    except ClientError as e:
        # パスワード設定失敗時はユーザーを削除してロールバック
        _admin_client.admin_delete_user(UserPoolId=USER_POOL_ID, Username=username)
        code = e.response["Error"]["Code"]
        if code == "InvalidPasswordException":
            raise AuthError("パスワードが要件を満たしていません（8文字以上、大文字・小文字・数字・記号を含む）")
        raise AuthError(f"登録エラー: {e.response['Error']['Message']}")


# ---------------------------------------------------------------------------
# ユーザー属性
# ---------------------------------------------------------------------------

def get_user_attributes(access_token: str) -> dict:
    """
    ログイン中ユーザーの属性を取得する。
    戻り値: {"email": ..., "name": ..., ...}
    """
    try:
        resp = _client.get_user(AccessToken=access_token)
    except ClientError as e:
        raise AuthError(f"属性取得エラー: {e.response['Error']['Message']}")

    return {attr["Name"]: attr["Value"] for attr in resp["UserAttributes"]}


def update_user_attributes(access_token: str, attributes: dict) -> None:
    """
    ログイン中ユーザーの属性を更新する。
    attributes: {"name": "山田太郎"} などのdict
    """
    try:
        _client.update_user_attributes(
            AccessToken=access_token,
            UserAttributes=[{"Name": k, "Value": v} for k, v in attributes.items()],
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NotAuthorizedException":
            raise AuthError("セッションが無効です。再ログインしてください")
        raise AuthError(f"属性更新エラー: {e.response['Error']['Message']}")


# ---------------------------------------------------------------------------
# パスキー登録
# ---------------------------------------------------------------------------

def start_webauthn_registration(access_token: str) -> dict:
    """
    パスキー登録を開始する。
    戻り値: ブラウザの navigator.credentials.create() に渡す PublicKeyCredentialCreationOptions (dict)
    """
    try:
        resp = _client.start_web_authn_registration(AccessToken=access_token)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ForbiddenException":
            raise AuthError("このユーザープールではパスキーが有効になっていません")
        raise AuthError(f"パスキー登録開始エラー: {e.response['Error']['Message']}")
    return resp["CredentialCreationOptions"]


def complete_webauthn_registration(access_token: str, credential: dict) -> None:
    """
    ブラウザの navigator.credentials.create() のレスポンスを Cognito に送信して登録を完了する。
    """
    try:
        _client.complete_web_authn_registration(
            AccessToken=access_token,
            Credential=credential,
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "WebAuthnChallengeNotFoundException":
            raise AuthError("登録セッションが期限切れです。再度お試しください")
        if code == "WebAuthnCredentialNotSupportedException":
            raise AuthError("このデバイスのパスキーはサポートされていません")
        raise AuthError(f"パスキー登録完了エラー: {e.response['Error']['Message']}")


# ---------------------------------------------------------------------------
# パスキー認証
# ---------------------------------------------------------------------------

def initiate_passkey_auth(username: str) -> dict:
    """
    パスキー専用クライアント（シークレットなし）でパスキー認証を開始する。
    SECRET_HASH不要。
    戻り値: {"session": ..., "credential_request_options": {...}}
    """
    try:
        resp = _client.initiate_auth(
            AuthFlow="USER_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PREFERRED_CHALLENGE": "WEB_AUTHN",
            },
            ClientId=PASSKEY_CLIENT_ID,
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("NotAuthorizedException", "UserNotFoundException"):
            raise AuthError("ユーザーが見つかりません")
        raise AuthError(f"パスキー認証開始エラー: {e.response['Error']['Message']}")

    challenge_name = resp.get("ChallengeName")
    if challenge_name != "WEB_AUTHN":
        raise AuthError("パスキーが登録されていません。先にパスキーを登録してください")

    options = json.loads(resp["ChallengeParameters"]["CREDENTIAL_REQUEST_OPTIONS"])
    return {
        "session": resp["Session"],
        "credential_request_options": options,
    }


def respond_passkey_challenge(username: str, cognito_session: str, credential: dict) -> dict:
    """
    パスキー専用クライアントでチャレンジに応答し、トークンを返す。
    SECRET_HASH不要。
    戻り値: {"access_token": ..., "id_token": ..., "refresh_token": ...}
    """
    try:
        resp = _client.respond_to_auth_challenge(
            ClientId=PASSKEY_CLIENT_ID,
            ChallengeName="WEB_AUTHN",
            Session=cognito_session,
            ChallengeResponses={
                "USERNAME": username,
                "CREDENTIAL": json.dumps(credential),
            },
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NotAuthorizedException":
            raise AuthError("パスキーの検証に失敗しました")
        if code == "WebAuthnChallengeNotFoundException":
            raise AuthError("認証セッションが期限切れです。再度お試しください")
        raise AuthError(f"パスキー認証エラー: {e.response['Error']['Message']}")

    result = resp["AuthenticationResult"]
    return {
        "access_token": result["AccessToken"],
        "id_token": result["IdToken"],
        "refresh_token": result["RefreshToken"],
    }


# ---------------------------------------------------------------------------
# パスキー管理
# ---------------------------------------------------------------------------

def list_webauthn_credentials(access_token: str) -> list:
    """
    ログイン中ユーザーの登録済みパスキー一覧を返す。
    戻り値: [{"credential_id": ..., "friendly_name": ..., "created_at": ...}, ...]
    """
    try:
        resp = _client.list_web_authn_credentials(AccessToken=access_token)
    except ClientError as e:
        raise AuthError(f"パスキー一覧取得エラー: {e.response['Error']['Message']}")

    credentials = []
    for c in resp.get("Credentials", []):
        credentials.append({
            "credential_id": c.get("CredentialId"),
            "friendly_name": c.get("FriendlyCredentialName") or "パスキー",
            "created_at": c.get("CreatedAt").isoformat() if c.get("CreatedAt") else None,
            "authenticator_attachment": c.get("AuthenticatorAttachment"),
        })
    return credentials


def delete_webauthn_credential(access_token: str, credential_id: str) -> None:
    """
    指定したパスキーを削除する。
    """
    try:
        _client.delete_web_authn_credential(
            AccessToken=access_token,
            CredentialId=credential_id,
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ForbiddenException":
            raise AuthError("このパスキーを削除する権限がありません")
        raise AuthError(f"パスキー削除エラー: {e.response['Error']['Message']}")


# ---------------------------------------------------------------------------
# パスワード変更
# ---------------------------------------------------------------------------

def change_password(access_token: str, old_password: str, new_password: str) -> None:
    """
    ログイン中ユーザーのパスワードを変更する。
    access_token はセッションから渡す。
    失敗時は AuthError を送出。
    """
    try:
        _client.change_password(
            PreviousPassword=old_password,
            ProposedPassword=new_password,
            AccessToken=access_token,
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NotAuthorizedException":
            raise AuthError("現在のパスワードが正しくありません")
        if code == "InvalidPasswordException":
            raise AuthError("新しいパスワードが要件を満たしていません（8文字以上、大文字・小文字・数字・記号を含む）")
        if code == "LimitExceededException":
            raise AuthError("試行回数が上限に達しました。しばらくしてからお試しください")
        raise AuthError(f"パスワード変更エラー: {e.response['Error']['Message']}")
