import io
import os
import secrets
import sqlite3
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

load_dotenv()

import verified_id

import pyotp
import qrcode
import qrcode.image.svg

import cognito  # noqa: E402

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

# Verified ID コールバック検証用 API キー（起動時に生成）
_VC_API_KEY = secrets.token_hex(32)

# 発行リクエストの状態管理（state → {status, message}）
_vc_cache: dict = {}

DB_PATH = os.path.join(os.path.dirname(__file__), "data.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS passkey_users (
                user_handle TEXT PRIMARY KEY,
                email TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS user_totp (
                email   TEXT PRIMARY KEY,
                secret  TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0
            )"""
        )


init_db()

APP_NAME = "Cognito Passkey Sample"


def _make_qr_svg(otpauth_uri: str) -> str:
    """otpauth:// URI から SVG 文字列を生成する。"""
    img = qrcode.make(otpauth_uri, image_factory=qrcode.image.svg.SvgImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("profile"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("profile"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        try:
            tokens = cognito.authenticate(username, password)
        except cognito.AuthError as e:
            flash(str(e), "error")
            return render_template("login.html")

        # 自前 TOTP が有効なら検証ステップへ
        with get_db() as conn:
            row = conn.execute(
                "SELECT 1 FROM user_totp WHERE email=? AND enabled=1", (username,)
            ).fetchone()

        if row:
            session["pending_username"] = username
            session["pending_access_token"] = tokens["access_token"]
            return redirect(url_for("login_mfa"))

        session["username"] = username
        session["access_token"] = tokens["access_token"]
        flash("ログインしました", "success")
        return redirect(url_for("profile"))

    return render_template("login.html")


@app.route("/login/mfa", methods=["GET", "POST"])
def login_mfa():
    """パスワードログイン後の自前 TOTP 検証ステップ。"""
    if "pending_username" not in session:
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        username = session["pending_username"]

        with get_db() as conn:
            row = conn.execute(
                "SELECT secret FROM user_totp WHERE email=? AND enabled=1", (username,)
            ).fetchone()

        if row and pyotp.TOTP(row["secret"]).verify(code, valid_window=1):
            access_token = session.pop("pending_access_token")
            session.pop("pending_username")
            session["username"] = username
            session["access_token"] = access_token
            flash("ログインしました", "success")
            return redirect(url_for("profile"))
        else:
            error = "認証コードが正しくありません"

    return render_template("login_mfa.html", error=error)


@app.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    """ログイン済みユーザーの TOTP 設定・再設定。"""
    email = session["username"]
    error = None

    if request.method == "GET":
        # 未確定のシークレットがあれば使い回す、なければ新規生成
        with get_db() as conn:
            row = conn.execute(
                "SELECT secret FROM user_totp WHERE email=? AND enabled=0", (email,)
            ).fetchone()
        secret = row["secret"] if row else pyotp.random_base32()
        with get_db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO user_totp (email, secret, enabled) VALUES (?, ?, 0)",
                (email, secret),
            )
        otpauth_uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=APP_NAME)
        return render_template("mfa_setup.html", qr_svg=_make_qr_svg(otpauth_uri), secret=secret)

    # POST: コード検証 → 有効化
    with get_db() as conn:
        row = conn.execute(
            "SELECT secret FROM user_totp WHERE email=? AND enabled=0", (email,)
        ).fetchone()

    if not row:
        flash("先にQRコードを読み込んでください", "error")
        return redirect(url_for("mfa_setup"))

    code = request.form.get("code", "").strip()
    if pyotp.TOTP(row["secret"]).verify(code, valid_window=1):
        with get_db() as conn:
            conn.execute("UPDATE user_totp SET enabled=1 WHERE email=?", (email,))
        flash("TOTPの設定が完了しました", "success")
        return redirect(url_for("profile"))
    else:
        error = "認証コードが正しくありません"

    otpauth_uri = pyotp.TOTP(row["secret"]).provisioning_uri(name=email, issuer_name=APP_NAME)
    return render_template("mfa_setup.html", qr_svg=_make_qr_svg(otpauth_uri), secret=row["secret"], error=error)


@app.route("/mfa/disable", methods=["POST"])
@login_required
def mfa_disable():
    """TOTP を無効化する。"""
    email = session["username"]
    with get_db() as conn:
        conn.execute("DELETE FROM user_totp WHERE email=?", (email,))
    flash("TOTPを無効化しました", "info")
    return redirect(url_for("profile"))


@app.route("/logout")
def logout():
    session.clear()
    flash("ログアウトしました", "info")
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "username" in session:
        return redirect(url_for("profile"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")

        if password != password_confirm:
            flash("パスワードが一致しません", "error")
            return render_template("signup.html", email=email)

        try:
            cognito.sign_up(email, email, password)
            flash("登録が完了しました。ログインしてください", "success")
            return redirect(url_for("login"))
        except cognito.AuthError as e:
            flash(str(e), "error")
            return render_template("signup.html", email=email)

    return render_template("signup.html", email="")



@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    access_token = session["access_token"]

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        try:
            cognito.update_user_attributes(access_token, {"name": name})
            flash("プロフィールを更新しました", "success")
            return redirect(url_for("profile"))
        except cognito.AuthError as e:
            flash(str(e), "error")

    try:
        attrs = cognito.get_user_attributes(access_token)
    except cognito.AuthError as e:
        flash(str(e), "error")
        attrs = {}

    with get_db() as conn:
        totp_enabled = conn.execute(
            "SELECT 1 FROM user_totp WHERE email=? AND enabled=1", (session["username"],)
        ).fetchone() is not None

    return render_template("profile.html", attrs=attrs, totp_enabled=totp_enabled)


@app.route("/passkey/register/start", methods=["POST"])
@login_required
def passkey_register_start():
    try:
        options = cognito.start_webauthn_registration(session["access_token"])
        return jsonify(options)
    except cognito.AuthError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/passkey/register/complete", methods=["POST"])
@login_required
def passkey_register_complete():
    data = request.get_json()
    user_handle = data.pop("user_handle", None) if data else None
    app.logger.debug("passkey_register_complete credential: %s", data)
    try:
        cognito.complete_webauthn_registration(session["access_token"], data)
        if user_handle:
            email = session["username"]
            with get_db() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO passkey_users (user_handle, email) VALUES (?, ?)",
                    (user_handle, email),
                )
        return jsonify({"ok": True})
    except cognito.AuthError as e:
        app.logger.error("passkey_register_complete error: %s", e)
        return jsonify({"error": str(e)}), 400


@app.route("/passkey/identify/start", methods=["POST"])
def passkey_identify_start():
    """Step 1: Return a bare WebAuthn challenge (no username) so the browser shows the passkey picker."""
    challenge = secrets.token_urlsafe(32)
    session["identify_challenge"] = challenge
    return jsonify({
        "challenge": challenge,
        "timeout": 60000,
        "userVerification": "required",
        "rpId": request.host.split(":")[0],
    })


@app.route("/passkey/identify/complete", methods=["POST"])
def passkey_identify_complete():
    """Step 2: Extract userHandle from assertion, look up email, start Cognito WEB_AUTHN auth."""
    data = request.get_json() or {}
    user_handle = data.get("userHandle")
    credential_id = data.get("id")

    if not user_handle:
        return jsonify({"error": "パスキーからユーザー情報を取得できませんでした"}), 400

    with get_db() as conn:
        row = conn.execute(
            "SELECT email FROM passkey_users WHERE user_handle = ?", (user_handle,)
        ).fetchone()

    if not row:
        return jsonify({"error": "このパスキーに紐づくアカウントが見つかりません"}), 400

    email = row["email"]
    try:
        result = cognito.initiate_passkey_auth(email)
        session["passkey_username"] = email
        session["passkey_cognito_session"] = result["session"]
        return jsonify({
            "credential_request_options": result["credential_request_options"],
            "credential_id": credential_id,
        })
    except cognito.AuthError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/passkey/auth/start", methods=["POST"])
def passkey_auth_start():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    if not username:
        return jsonify({"error": "メールアドレスが取得できませんでした"}), 400
    try:
        result = cognito.initiate_passkey_auth(username)
        session["passkey_username"] = username
        session["passkey_cognito_session"] = result["session"]
        return jsonify(result["credential_request_options"])
    except cognito.AuthError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/passkey/auth/complete", methods=["POST"])
def passkey_auth_complete():
    credential = request.get_json()
    username = session.pop("passkey_username", None)
    cognito_session = session.pop("passkey_cognito_session", None)
    if not cognito_session:
        return jsonify({"error": "セッションが無効です。再度お試しください"}), 400
    try:
        tokens = cognito.respond_passkey_challenge(username, cognito_session, credential)
        session["username"] = username
        session["access_token"] = tokens["access_token"]
        return jsonify({"ok": True})
    except cognito.AuthError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/passkey/list")
@login_required
def passkey_list():
    try:
        credentials = cognito.list_webauthn_credentials(session["access_token"])
        return jsonify(credentials)
    except cognito.AuthError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/passkey/delete", methods=["POST"])
@login_required
def passkey_delete():
    data = request.get_json() or {}
    credential_id = data.get("credential_id", "").strip()
    if not credential_id:
        return jsonify({"error": "credential_id が指定されていません"}), 400
    try:
        cognito.delete_webauthn_credential(session["access_token"], credential_id)
        # DBからも user_handle マッピングを削除（credential_id での検索は不要、Cognito側で削除済み）
        return jsonify({"ok": True})
    except cognito.AuthError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        new_password_confirm = request.form.get("new_password_confirm", "")

        if new_password != new_password_confirm:
            flash("新しいパスワードが一致しません", "error")
            return render_template("password.html")

        try:
            cognito.change_password(session["access_token"], old_password, new_password)
            flash("パスワードを変更しました", "success")
            return redirect(url_for("profile"))
        except cognito.AuthError as e:
            flash(str(e), "error")

    return render_template("password.html")


# ---------------------------------------------------------------------------
# Verified ID 発行
# ---------------------------------------------------------------------------


@app.route("/vc/issue")
@login_required
def vc_issue():
    """VC 発行ページ。"""
    return render_template("vc_issue.html")


@app.route("/api/vc/issuance-request", methods=["POST"])
@login_required
def vc_issuance_request():
    """Cognito ユーザー属性を取得し Verified ID 発行リクエストを作成する。"""
    try:
        attrs = cognito.get_user_attributes(session["access_token"])
    except cognito.AuthError as e:
        return jsonify({"error": str(e)}), 400

    claims = {
        "username":    attrs.get("email", ""),
        "name":        attrs.get("name", ""),
        "given_name":  attrs.get("given_name", ""),
        "family_name": attrs.get("family_name", ""),
    }

    callback_base_url = os.environ.get("VC_CALLBACK_BASE_URL", "").rstrip("/")
    if not callback_base_url:
        return jsonify({"error": "VC_CALLBACK_BASE_URL が設定されていません（ngrok URL を設定してください）"}), 500

    try:
        result = verified_id.create_issuance_request(claims, callback_base_url, _VC_API_KEY)
    except verified_id.VCError as e:
        return jsonify({"error": str(e)}), 500

    _vc_cache[result["state"]] = {
        "status": "request_created",
        "message": "QR コードをスキャンしてください",
    }

    return jsonify({
        "id":     result["state"],
        "url":    result.get("url"),
        "qrCode": result.get("qrCode"),
        "expiry": result.get("expiry"),
    }), 201


@app.route("/api/vc/issuance-callback", methods=["POST"])
def vc_issuance_callback():
    """Verified ID からのコールバックを受信する。"""
    api_key = request.headers.get("api-key", "")
    if api_key != _VC_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    state = data.get("state")
    code = data.get("code")          # issuance_successful | issuance_error 等
    error = data.get("error", {})

    if not state or state not in _vc_cache:
        return jsonify({"error": "unknown state"}), 400

    if code == "issuance_successful":
        _vc_cache[state] = {"status": "issued", "message": "発行完了"}
    elif code == "issuance_error":
        _vc_cache[state] = {
            "status": "error",
            "message": error.get("message", "発行エラーが発生しました"),
        }
    else:
        _vc_cache[state] = {"status": code, "message": ""}

    return jsonify({"status": "ok"})


@app.route("/api/vc/issuance-response")
@login_required
def vc_issuance_response():
    """ブラウザのポーリングに応答する。"""
    state = request.args.get("id")
    if not state or state not in _vc_cache:
        return jsonify({"status": "unknown"}), 404
    return jsonify(_vc_cache[state])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("[init] 認証: AWS Cognito (USER_PASSWORD_AUTH)")
    app.run(debug=True, host="0.0.0.0", port=5000)
