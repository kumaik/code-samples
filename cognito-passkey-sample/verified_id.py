"""Microsoft Entra Verified ID 発行ヘルパー"""
import os
import uuid

import requests as http

TENANT_ID = os.environ["AZURE_TENANT_ID"]
CLIENT_ID = os.environ["AZURE_CLIENT_ID"]
CLIENT_SECRET = os.environ["AZURE_CLIENT_SECRET"]
VC_API_ENDPOINT = os.environ.get(
    "VC_API_ENDPOINT",
    "https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/",
)
VC_DID_AUTHORITY = os.environ["VC_DID_AUTHORITY"]
VC_CREDENTIAL_MANIFEST = os.environ["VC_CREDENTIAL_MANIFEST"]

_TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
_VC_SCOPE = "3db474b9-6a0c-4840-96ac-1fceb342124f/.default"


class VCError(Exception):
    pass


def get_access_token() -> str:
    """Entra ID から client_credentials でアクセストークンを取得する。"""
    resp = http.post(_TOKEN_URL, data={
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": _VC_SCOPE,
    })
    if not resp.ok:
        raise VCError(f"アクセストークン取得エラー: {resp.status_code} {resp.text}")
    return resp.json()["access_token"]


def create_issuance_request(claims: dict, callback_base_url: str, api_key: str) -> dict:
    """
    Verified ID 発行リクエストを作成する。

    Args:
        claims: VC に埋め込むクレーム {"username": ..., "name": ..., ...}
        callback_base_url: コールバック受信用の公開 URL（例: ngrok の https URL）
        api_key: コールバック検証用の共有キー

    Returns:
        {"state": ..., "url": ..., "expiry": ..., "qrCode": ...}
    """
    state = str(uuid.uuid4())
    access_token = get_access_token()

    payload = {
        "authority": VC_DID_AUTHORITY,
        "includeQRCode": True,
        "registration": {
            "clientName": "Cognito Passkey VC Issuer",
        },
        "callback": {
            "url": f"{callback_base_url}/api/vc/issuance-callback",
            "state": state,
            "headers": {"api-key": api_key},
        },
        "type": "ignore-this",
        "manifest": VC_CREDENTIAL_MANIFEST,
        "claims": claims,
    }

    resp = http.post(
        f"{VC_API_ENDPOINT}createIssuanceRequest",
        json=payload,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if resp.status_code != 201:
        raise VCError(f"Verified ID API エラー: {resp.status_code} {resp.text}")

    result = resp.json()
    result["state"] = state
    return result
