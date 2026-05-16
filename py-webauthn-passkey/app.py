import base64
import io
import os
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

import pyotp
import qrcode
import qrcode.image.svg

import auth

auth.init_db()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

APP_NAME = "Passkey Sample"


def _make_qr_svg(otpauth_uri: str) -> str:
    img = qrcode.make(otpauth_uri, image_factory=qrcode.image.svg.SvgImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")


def _challenge_to_session(challenge: bytes) -> str:
    """bytes をセッション保存用の base64url 文字列に変換する。"""
    return base64.urlsafe_b64encode(challenge).rstrip(b"=").decode()


def _challenge_from_session(s: str) -> bytes:
    """セッションから取り出した base64url 文字列を bytes に戻す。"""
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (pad % 4))


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
# Routes: ログイン / ログアウト / 登録
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
        email = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        try:
            auth.authenticate(email, password)
        except auth.AuthError as e:
            flash(str(e), "error")
            return render_template("login.html")

        # 自前 TOTP が有効なら検証ステップへ
        with auth.get_db() as conn:
            row = conn.execute(
                "SELECT 1 FROM user_totp WHERE email=? AND enabled=1", (email,)
            ).fetchone()

        if row:
            session["pending_username"] = email
            return redirect(url_for("login_mfa"))

        session["username"] = email
        flash("ログインしました", "success")
        return redirect(url_for("profile"))

    return render_template("login.html")


@app.route("/login/mfa", methods=["GET", "POST"])
def login_mfa():
    if "pending_username" not in session:
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        username = session["pending_username"]

        with auth.get_db() as conn:
            row = conn.execute(
                "SELECT secret FROM user_totp WHERE email=? AND enabled=1", (username,)
            ).fetchone()

        if row and pyotp.TOTP(row["secret"]).verify(code, valid_window=1):
            session.pop("pending_username")
            session["username"] = username
            flash("ログインしました", "success")
            return redirect(url_for("profile"))
        else:
            error = "認証コードが正しくありません"

    return render_template("login_mfa.html", error=error)


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
            auth.sign_up(email, password)
            session["username"] = email
            flash("登録が完了しました", "success")
            return redirect(url_for("profile"))
        except auth.AuthError as e:
            flash(str(e), "error")
            return render_template("signup.html", email=email)

    return render_template("signup.html", email="")


# ---------------------------------------------------------------------------
# Routes: プロフィール / パスワード変更
# ---------------------------------------------------------------------------


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    email = session["username"]

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        try:
            auth.update_user_attributes(email, {"name": name})
            flash("プロフィールを更新しました", "success")
            return redirect(url_for("profile"))
        except auth.AuthError as e:
            flash(str(e), "error")

    try:
        attrs = auth.get_user_attributes(email)
    except auth.AuthError as e:
        flash(str(e), "error")
        attrs = {}

    with auth.get_db() as conn:
        totp_enabled = conn.execute(
            "SELECT 1 FROM user_totp WHERE email=? AND enabled=1", (email,)
        ).fetchone() is not None

    return render_template("profile.html", attrs=attrs, totp_enabled=totp_enabled)


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
            auth.change_password(session["username"], old_password, new_password)
            flash("パスワードを変更しました", "success")
            return redirect(url_for("profile"))
        except auth.AuthError as e:
            flash(str(e), "error")

    return render_template("password.html")


# ---------------------------------------------------------------------------
# Routes: TOTP
# ---------------------------------------------------------------------------


@app.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    email = session["username"]
    error = None

    if request.method == "GET":
        with auth.get_db() as conn:
            row = conn.execute(
                "SELECT secret FROM user_totp WHERE email=? AND enabled=0", (email,)
            ).fetchone()
        secret = row["secret"] if row else pyotp.random_base32()
        with auth.get_db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO user_totp (email, secret, enabled) VALUES (?, ?, 0)",
                (email, secret),
            )
        otpauth_uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=APP_NAME)
        return render_template("mfa_setup.html", qr_svg=_make_qr_svg(otpauth_uri), secret=secret)

    with auth.get_db() as conn:
        row = conn.execute(
            "SELECT secret FROM user_totp WHERE email=? AND enabled=0", (email,)
        ).fetchone()

    if not row:
        flash("先にQRコードを読み込んでください", "error")
        return redirect(url_for("mfa_setup"))

    code = request.form.get("code", "").strip()
    if pyotp.TOTP(row["secret"]).verify(code, valid_window=1):
        with auth.get_db() as conn:
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
    email = session["username"]
    with auth.get_db() as conn:
        conn.execute("DELETE FROM user_totp WHERE email=?", (email,))
    flash("TOTPを無効化しました", "info")
    return redirect(url_for("profile"))


# ---------------------------------------------------------------------------
# Routes: パスキー登録
# ---------------------------------------------------------------------------


@app.route("/passkey/register/start", methods=["POST"])
@login_required
def passkey_register_start():
    try:
        options, challenge, user_handle = auth.start_webauthn_registration(session["username"])
        session["reg_challenge"] = _challenge_to_session(challenge)
        session["reg_user_handle"] = _challenge_to_session(user_handle)
        return jsonify(options)
    except auth.AuthError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/passkey/register/complete", methods=["POST"])
@login_required
def passkey_register_complete():
    challenge_str = session.pop("reg_challenge", None)
    user_handle_str = session.pop("reg_user_handle", None)
    if not challenge_str or not user_handle_str:
        return jsonify({"error": "登録セッションが無効です。再度お試しください"}), 400

    data = request.get_json()
    try:
        auth.complete_webauthn_registration(
            email=session["username"],
            user_handle=_challenge_from_session(user_handle_str),
            credential_data=data,
            challenge=_challenge_from_session(challenge_str),
        )
        return jsonify({"ok": True})
    except auth.AuthError as e:
        app.logger.error("passkey_register_complete error: %s", e)
        return jsonify({"error": str(e)}), 400


# ---------------------------------------------------------------------------
# Routes: パスキー認証
#
# Cognito の USERNAME 必須制約がないため、メールアドレスの有無に関わらず
# start → complete の 1 フローに統合できる。
# ---------------------------------------------------------------------------


@app.route("/passkey/auth/start", methods=["POST"])
def passkey_auth_start():
    data = request.get_json() or {}
    email = data.get("username", "").strip() or None
    try:
        options, challenge = auth.start_webauthn_authentication(email)
        session["auth_challenge"] = _challenge_to_session(challenge)
        return jsonify(options)
    except auth.AuthError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/passkey/auth/complete", methods=["POST"])
def passkey_auth_complete():
    challenge_str = session.pop("auth_challenge", None)
    if not challenge_str:
        return jsonify({"error": "セッションが無効です。再度お試しください"}), 400

    credential = request.get_json()
    try:
        email = auth.complete_webauthn_authentication(
            credential_data=credential,
            challenge=_challenge_from_session(challenge_str),
        )
        session["username"] = email
        return jsonify({"ok": True})
    except auth.AuthError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/passkey/list")
@login_required
def passkey_list():
    try:
        credentials = auth.list_webauthn_credentials(session["username"])
        return jsonify(credentials)
    except auth.AuthError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/passkey/delete", methods=["POST"])
@login_required
def passkey_delete():
    data = request.get_json() or {}
    credential_id = data.get("credential_id", "").strip()
    if not credential_id:
        return jsonify({"error": "credential_id が指定されていません"}), 400
    try:
        auth.delete_webauthn_credential(session["username"], credential_id)
        return jsonify({"ok": True})
    except auth.AuthError as e:
        return jsonify({"error": str(e)}), 400


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("[init] 認証: 自前 WebAuthn (py_webauthn + bcrypt / Cognito なし)")
    app.run(debug=True, host="0.0.0.0", port=5000)
