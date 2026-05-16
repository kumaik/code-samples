"""パスワード + パスキー認証ヘルパー（Cognito なし / bcrypt + py_webauthn）"""

import base64
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone

import bcrypt
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AuthenticationCredential,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

RP_ID = os.environ.get("RP_ID", "localhost")
RP_NAME = os.environ.get("RP_NAME", "Passkey Sample")
ORIGIN = os.environ.get("ORIGIN", f"http://{RP_ID}:5000")

DB_PATH = os.path.join(os.path.dirname(__file__), "data.db")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class AuthError(Exception):
    pass


# ---------------------------------------------------------------------------
# DB ヘルパー
# ---------------------------------------------------------------------------


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS users (
                email         TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                name          TEXT NOT NULL DEFAULT ''
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS passkey_credentials (
                credential_id TEXT PRIMARY KEY,
                user_email    TEXT NOT NULL,
                user_handle   TEXT NOT NULL,
                public_key    BLOB NOT NULL,
                sign_count    INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS user_totp (
                email   TEXT PRIMARY KEY,
                secret  TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0
            )"""
        )


# ---------------------------------------------------------------------------
# ユーザー管理
# ---------------------------------------------------------------------------


def sign_up(email: str, password: str) -> None:
    """メールアドレスとパスワードで新規ユーザーを登録する。"""
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, password_hash),
            )
    except sqlite3.IntegrityError:
        raise AuthError("そのメールアドレスはすでに使用されています")


def authenticate(email: str, password: str) -> None:
    """パスワード認証。失敗時は AuthError を送出。"""
    with get_db() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE email=?", (email,)
        ).fetchone()
    if not row or not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        raise AuthError("メールアドレスまたはパスワードが正しくありません")


def get_user_attributes(email: str) -> dict:
    with get_db() as conn:
        row = conn.execute(
            "SELECT email, name FROM users WHERE email=?", (email,)
        ).fetchone()
    if not row:
        raise AuthError("ユーザーが見つかりません")
    return {"email": row["email"], "name": row["name"]}


def update_user_attributes(email: str, attributes: dict) -> None:
    if "name" in attributes:
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET name=? WHERE email=?", (attributes["name"], email)
            )


def change_password(email: str, old_password: str, new_password: str) -> None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE email=?", (email,)
        ).fetchone()
    if not row or not bcrypt.checkpw(old_password.encode(), row["password_hash"].encode()):
        raise AuthError("現在のパスワードが正しくありません")
    new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET password_hash=? WHERE email=?", (new_hash, email)
        )


# ---------------------------------------------------------------------------
# パスキー登録
# ---------------------------------------------------------------------------


def start_webauthn_registration(email: str) -> tuple[dict, bytes, bytes]:
    """
    WebAuthn 登録オプションを生成する。
    戻り値: (options_dict, challenge_bytes, user_handle_bytes)
    呼び出し側で challenge と user_handle をセッションに保存すること。
    """
    with get_db() as conn:
        rows = conn.execute(
            "SELECT credential_id FROM passkey_credentials WHERE user_email=?", (email,)
        ).fetchall()

    exclude = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(row["credential_id"]))
        for row in rows
    ]

    user_handle = secrets.token_bytes(32)

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_handle,
        user_name=email,
        user_display_name=email,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
        exclude_credentials=exclude,
    )

    return json.loads(options_to_json(options)), options.challenge, user_handle


def complete_webauthn_registration(
    email: str,
    user_handle: bytes,
    credential_data: dict,
    challenge: bytes,
) -> None:
    """attestation を検証してクレデンシャルを DB に保存する。"""
    cred = RegistrationCredential(
        id=credential_data["id"],
        raw_id=base64url_to_bytes(credential_data["rawId"]),
        response=AuthenticatorAttestationResponse(
            client_data_json=base64url_to_bytes(
                credential_data["response"]["clientDataJSON"]
            ),
            attestation_object=base64url_to_bytes(
                credential_data["response"]["attestationObject"]
            ),
            transports=credential_data["response"].get("transports", []),
        ),
        type=credential_data.get("type", "public-key"),
    )

    verification = verify_registration_response(
        credential=cred,
        expected_challenge=challenge,
        expected_rp_id=RP_ID,
        expected_origin=ORIGIN,
        require_user_verification=False,
    )

    with get_db() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO passkey_credentials
               (credential_id, user_email, user_handle, public_key, sign_count, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                _b64url(verification.credential_id),
                email,
                _b64url(user_handle),
                bytes(verification.credential_public_key),
                verification.sign_count,
                datetime.now(timezone.utc).isoformat(),
            ),
        )


# ---------------------------------------------------------------------------
# パスキー認証
# ---------------------------------------------------------------------------


def start_webauthn_authentication(email: str | None = None) -> tuple[dict, bytes]:
    """
    WebAuthn 認証オプションを生成する。
    email あり → allow_credentials に絞り込み（メールアドレス入力ありフロー）
    email なし → allow_credentials=[]（Discoverable Credentials フロー）
    戻り値: (options_dict, challenge_bytes)
    """
    allow = []
    if email:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT credential_id FROM passkey_credentials WHERE user_email=?",
                (email,),
            ).fetchall()
        allow = [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(row["credential_id"]))
            for row in rows
        ]

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return json.loads(options_to_json(options)), options.challenge


def complete_webauthn_authentication(
    credential_data: dict,
    challenge: bytes,
) -> str:
    """
    assertion を検証してログイン済みユーザーのメールアドレスを返す。
    credential_id で DB を検索するためメールアドレスの事前指定不要。
    """
    cred = AuthenticationCredential(
        id=credential_data["id"],
        raw_id=base64url_to_bytes(credential_data["rawId"]),
        response=AuthenticatorAssertionResponse(
            client_data_json=base64url_to_bytes(
                credential_data["response"]["clientDataJSON"]
            ),
            authenticator_data=base64url_to_bytes(
                credential_data["response"]["authenticatorData"]
            ),
            signature=base64url_to_bytes(credential_data["response"]["signature"]),
            user_handle=(
                base64url_to_bytes(credential_data["response"]["userHandle"])
                if credential_data["response"].get("userHandle")
                else None
            ),
        ),
        type=credential_data.get("type", "public-key"),
    )

    credential_id = _b64url(cred.raw_id)

    with get_db() as conn:
        row = conn.execute(
            """SELECT user_email, public_key, sign_count
               FROM passkey_credentials WHERE credential_id=?""",
            (credential_id,),
        ).fetchone()

    if not row:
        raise AuthError("このパスキーに紐づくアカウントが見つかりません")

    verification = verify_authentication_response(
        credential=cred,
        expected_challenge=challenge,
        expected_rp_id=RP_ID,
        expected_origin=ORIGIN,
        credential_public_key=bytes(row["public_key"]),
        credential_current_sign_count=row["sign_count"],
        require_user_verification=False,
    )

    with get_db() as conn:
        conn.execute(
            "UPDATE passkey_credentials SET sign_count=? WHERE credential_id=?",
            (verification.new_sign_count, credential_id),
        )

    return row["user_email"]


# ---------------------------------------------------------------------------
# パスキー一覧・削除
# ---------------------------------------------------------------------------


def list_webauthn_credentials(email: str) -> list:
    with get_db() as conn:
        rows = conn.execute(
            """SELECT credential_id, created_at
               FROM passkey_credentials WHERE user_email=? ORDER BY created_at""",
            (email,),
        ).fetchall()
    return [
        {
            "credential_id": row["credential_id"],
            "friendly_name": "パスキー",
            "created_at": row["created_at"],
            "authenticator_attachment": None,
        }
        for row in rows
    ]


def delete_webauthn_credential(email: str, credential_id: str) -> None:
    with get_db() as conn:
        result = conn.execute(
            "DELETE FROM passkey_credentials WHERE credential_id=? AND user_email=?",
            (credential_id, email),
        )
    if result.rowcount == 0:
        raise AuthError("クレデンシャルが見つかりません")
