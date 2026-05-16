/**
 * WebAuthn / Passkey ユーティリティ（Cognito なし版）
 *
 * 01 版との主な差分:
 * - loginWithPasskey が 1 ステップに統合（メールあり・なし共通フロー）
 *   Cognito の USERNAME 必須制約がなくなったため、Discoverable Credentials を
 *   サーバー側で直接 credential_id から解決できる。
 * - registerPasskey から user_handle の返送が不要（サーバー側で管理）
 */

// ---------------------------------------------------------------------------
// Base64URL ↔ ArrayBuffer 変換
// ---------------------------------------------------------------------------

function base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
  const binary = atob(padded);
  const buf = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
  return buf.buffer;
}

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// ---------------------------------------------------------------------------
// パスキー登録
// ---------------------------------------------------------------------------

async function registerPasskey(onSuccess, onError) {
  try {
    // 1. サーバーから CredentialCreationOptions を取得
    const resp = await fetch('/passkey/register/start', { method: 'POST' });
    const options = await resp.json();
    if (options.error) throw new Error(options.error);

    // 2. challenge と user.id を ArrayBuffer に変換
    options.challenge = base64urlToBuffer(options.challenge);
    options.user.id = base64urlToBuffer(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map(c => ({
        ...c, id: base64urlToBuffer(c.id),
      }));
    }

    // 3. ブラウザの WebAuthn API でパスキーを生成
    const credential = await navigator.credentials.create({ publicKey: options });

    // 4. ArrayBuffer を base64url に戻してサーバーへ送信
    //    user_handle はサーバー側で管理するため送信不要
    const payload = {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON:    bufferToBase64url(credential.response.clientDataJSON),
        attestationObject: bufferToBase64url(credential.response.attestationObject),
        transports: credential.response.getTransports
          ? credential.response.getTransports()
          : [],
      },
      clientExtensionResults: credential.getClientExtensionResults
        ? credential.getClientExtensionResults()
        : {},
    };
    if (credential.authenticatorAttachment) {
      payload.authenticatorAttachment = credential.authenticatorAttachment;
    }

    const completeResp = await fetch('/passkey/register/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const result = await completeResp.json();
    if (result.error) throw new Error(result.error);

    onSuccess('パスキーを登録しました');
  } catch (e) {
    if (e.name === 'NotAllowedError') {
      onError('パスキーの登録がキャンセルされました');
    } else {
      onError(e.message || 'パスキー登録に失敗しました');
    }
  }
}

// ---------------------------------------------------------------------------
// パスキーでログイン（メールあり・なし共通 1 ステップフロー）
//
// Cognito 版の 2 ステップ識別フロー（/passkey/identify/*）は不要になった。
// サーバーは credential_id から直接ユーザーを特定できるため、
// メールアドレスの有無によらず /passkey/auth/start → /passkey/auth/complete の
// 1 往復で完結する。
// ---------------------------------------------------------------------------

async function loginWithPasskey(email, onSuccess, onError) {
  try {
    // 1. 認証オプションを取得（email は省略可）
    const resp = await fetch('/passkey/auth/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(email ? { username: email } : {}),
    });
    const options = await resp.json();
    if (options.error) throw new Error(options.error);

    options.challenge = base64urlToBuffer(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map(c => ({
        ...c, id: base64urlToBuffer(c.id),
      }));
    }

    // 2. ブラウザでパスキーを選択・署名
    const assertion = await navigator.credentials.get({ publicKey: options });

    const payload = {
      id: assertion.id,
      rawId: bufferToBase64url(assertion.rawId),
      type: assertion.type,
      response: {
        clientDataJSON:    bufferToBase64url(assertion.response.clientDataJSON),
        authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
        signature:         bufferToBase64url(assertion.response.signature),
        userHandle: assertion.response.userHandle
          ? bufferToBase64url(assertion.response.userHandle) : null,
      },
    };

    // 3. サーバーで検証
    const completeResp = await fetch('/passkey/auth/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const result = await completeResp.json();
    if (result.error) throw new Error(result.error);

    onSuccess();
  } catch (e) {
    if (e.name === 'NotAllowedError') {
      onError('パスキーの使用がキャンセルされました');
    } else {
      onError(e.message || 'パスキー認証に失敗しました');
    }
  }
}
