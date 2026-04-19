/**
 * WebAuthn / Passkey ユーティリティ
 * Cognito の start_web_authn_registration / respond_to_auth_challenge と連携する
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

    // 2. user.id（userHandle）を base64url のまま保持してから ArrayBuffer に変換
    const userHandle = options.user.id;  // base64url string
    options.challenge = base64urlToBuffer(options.challenge);
    options.user.id = base64urlToBuffer(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map(c => ({
        ...c, id: base64urlToBuffer(c.id),
      }));
    }

    // 3. ブラウザの WebAuthn API でパスキーを生成
    const credential = await navigator.credentials.create({ publicKey: options });

    // 4. ArrayBuffer を base64url に戻してサーバーへ送信（user_handle も含める）
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
      user_handle: userHandle,
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
// パスキーでログイン
//
// email あり → 1ステップ（Cognito へ直接）
// email なし → 2ステップ（自前チャレンジでアカウント特定 → Cognito 認証）
//
// onProgress(message) : ステップ進行中のメッセージ通知（2ステップ時のみ）
// ---------------------------------------------------------------------------

async function loginWithPasskey(email, onSuccess, onError, onProgress) {
  try {
    if (email) {
      // --- メールアドレスあり：1回の認証で完了 ---
      const resp = await fetch('/passkey/auth/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: email }),
      });
      const options = await resp.json();
      if (options.error) throw new Error(options.error);

      options.challenge = base64urlToBuffer(options.challenge);
      if (options.allowCredentials) {
        options.allowCredentials = options.allowCredentials.map(c => ({
          ...c, id: base64urlToBuffer(c.id),
        }));
      }

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

      const completeResp = await fetch('/passkey/auth/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const result = await completeResp.json();
      if (result.error) throw new Error(result.error);

      onSuccess();

    } else {
      // --- メールアドレスなし：2ステップ認証 ---

      // Step 1: アカウント特定
      if (onProgress) onProgress('アカウントを特定しています... (1/2)');

      const startResp = await fetch('/passkey/identify/start', { method: 'POST' });
      const identifyOptions = await startResp.json();
      if (identifyOptions.error) throw new Error(identifyOptions.error);

      identifyOptions.challenge = base64urlToBuffer(identifyOptions.challenge);

      const assertion1 = await navigator.credentials.get({
        publicKey: {
          challenge:        identifyOptions.challenge,
          timeout:          identifyOptions.timeout,
          userVerification: identifyOptions.userVerification,
          rpId:             identifyOptions.rpId,
          allowCredentials: [],
        },
      });

      const userHandle = assertion1.response.userHandle
        ? bufferToBase64url(assertion1.response.userHandle)
        : null;

      // Step 2: Cognito 認証
      if (onProgress) onProgress('サーバーと認証しています... (2/2)');

      const identifyCompleteResp = await fetch('/passkey/identify/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userHandle, id: assertion1.id }),
      });
      const identified = await identifyCompleteResp.json();
      if (identified.error) throw new Error(identified.error);

      const cognitoOptions = identified.credential_request_options;
      const credentialId = identified.credential_id;

      cognitoOptions.challenge = base64urlToBuffer(cognitoOptions.challenge);
      if (cognitoOptions.allowCredentials) {
        cognitoOptions.allowCredentials = cognitoOptions.allowCredentials.map(c => ({
          ...c, id: base64urlToBuffer(c.id),
        }));
      } else {
        cognitoOptions.allowCredentials = [{
          type: 'public-key',
          id: base64urlToBuffer(credentialId),
        }];
      }

      const assertion2 = await navigator.credentials.get({ publicKey: cognitoOptions });

      const payload = {
        id: assertion2.id,
        rawId: bufferToBase64url(assertion2.rawId),
        type: assertion2.type,
        response: {
          clientDataJSON:    bufferToBase64url(assertion2.response.clientDataJSON),
          authenticatorData: bufferToBase64url(assertion2.response.authenticatorData),
          signature:         bufferToBase64url(assertion2.response.signature),
          userHandle: assertion2.response.userHandle
            ? bufferToBase64url(assertion2.response.userHandle) : null,
        },
      };

      const completeResp = await fetch('/passkey/auth/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const result = await completeResp.json();
      if (result.error) throw new Error(result.error);

      onSuccess();
    }
  } catch (e) {
    if (e.name === 'NotAllowedError') {
      onError('パスキーの使用がキャンセルされました');
    } else {
      onError(e.message || 'パスキー認証に失敗しました');
    }
  }
}
