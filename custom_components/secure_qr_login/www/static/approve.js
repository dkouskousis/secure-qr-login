(() => {
  const message = document.getElementById('message');
  const details = document.getElementById('details');
  const authActions = document.getElementById('authActions');
  const openApp = document.getElementById('openApp');
  const browserLogin = document.getElementById('browserLogin');

  const params = new URLSearchParams(location.search);
  const sessionId = params.get('session_id') || '';
  const qrToken = params.get('qr_token') || '';
  const authorizationCode = params.get('code') || '';
  const clientIdDefault = location.origin + '/';

  let accessToken = null;
  let refreshToken = null;
  let clientId = null;
  let externalAuthResolve = null;

  function browserTokens() {
    try {
      return JSON.parse(localStorage.getItem('hassTokens'));
    } catch {
      return null;
    }
  }

  function saveTokens(data, cid) {
    // Browser OAuth tokens follow the same storage convention as HA frontend.
    // Companion App external-auth tokens are never persisted here.
    const expiresIn = data.expires_in || 1800;
    localStorage.setItem('hassTokens', JSON.stringify({
      hassUrl: location.origin,
      clientId: cid,
      access_token: data.access_token,
      refresh_token: data.refresh_token || refreshToken,
      expires_in: expiresIn,
      expires: Date.now() + expiresIn * 1000
    }));
  }

  function authHeaders(extra = {}) {
    return accessToken
      ? {...extra, Authorization: `Bearer ${accessToken}`}
      : extra;
  }

  function companionBridgeAvailable() {
    return Boolean(
      window.externalAppV2
      || window.externalApp
      || window.webkit?.messageHandlers?.getExternalAuth
    );
  }

  function companionDeepLink() {
    const query = new URLSearchParams({
      session_id: sessionId,
      qr_token: qrToken,
      external_auth: '1',
      server: 'default'
    });
    return `homeassistant://navigate/secure_qr_login/approve?${query.toString()}`;
  }

  function requestExternalAuth(force = false) {
    if (!companionBridgeAvailable()) return Promise.resolve(false);

    return new Promise((resolve) => {
      let settled = false;
      const timeout = setTimeout(() => {
        if (!settled) {
          settled = true;
          externalAuthResolve = null;
          resolve(false);
        }
      }, 5000);

      externalAuthResolve = (success, data) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        externalAuthResolve = null;

        if (success && data?.access_token) {
          accessToken = data.access_token;
          refreshToken = null;
          clientId = null;
          resolve(true);
        } else {
          resolve(false);
        }
      };

      const payload = {callback: 'externalAuthSetToken', force};

      try {
        if (window.externalAppV2) {
          window.externalAppV2.postMessage(JSON.stringify({
            type: 'getExternalAuth',
            payload
          }));
          return;
        }

        if (window.externalApp) {
          window.externalApp.getExternalAuth(JSON.stringify(payload));
          return;
        }

        window.webkit.messageHandlers.getExternalAuth.postMessage(payload);
      } catch {
        clearTimeout(timeout);
        externalAuthResolve = null;
        resolve(false);
      }
    });
  }

  // Stable callback name required by the Home Assistant Companion App bridge.
  window.externalAuthSetToken = (success, data) => {
    if (externalAuthResolve) externalAuthResolve(Boolean(success), data || null);
  };

  async function exchangeAuthorizationCode(code) {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: clientIdDefault
    });
    const r = await fetch('/auth/token', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: body.toString(),
      cache: 'no-store'
    });
    if (!r.ok) return false;

    const d = await r.json();
    if (!d.access_token) return false;

    accessToken = d.access_token;
    refreshToken = d.refresh_token || null;
    clientId = clientIdDefault;
    saveTokens(d, clientIdDefault);

    const clean = new URL(location.href);
    clean.searchParams.delete('code');
    history.replaceState(null, '', clean.pathname + clean.search);
    return true;
  }

  async function refreshAccess() {
    if (companionBridgeAvailable()) {
      return requestExternalAuth(true);
    }

    if (!refreshToken || !clientId) return false;

    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: clientId
    });
    const r = await fetch('/auth/token', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: body.toString(),
      cache: 'no-store'
    });
    if (!r.ok) return false;

    const d = await r.json();
    accessToken = d.access_token;
    refreshToken = d.refresh_token || refreshToken;
    if (accessToken) saveTokens(d, clientId);
    return Boolean(accessToken);
  }

  async function request(url, options = {}) {
    options.cache = 'no-store';
    options.headers = authHeaders(options.headers || {});

    let r = await fetch(url, options);
    if (r.status === 401 && await refreshAccess()) {
      options.headers = authHeaders(options.headers || {});
      r = await fetch(url, options);
    }
    return r;
  }

  function showError(text) {
    details.hidden = true;
    authActions.hidden = true;
    message.hidden = false;
    message.className = 'error';
    message.textContent = text;
  }

  function loginUrl() {
    const redirect = location.origin + location.pathname
      + '?session_id=' + encodeURIComponent(sessionId)
      + '&qr_token=' + encodeURIComponent(qrToken);

    return '/auth/authorize?response_type=code'
      + '&client_id=' + encodeURIComponent(clientIdDefault)
      + '&redirect_uri=' + encodeURIComponent(redirect);
  }

  function showAuthChoices() {
    message.textContent = 'Authenticate with Home Assistant to approve this login.';
    message.className = 'muted';
    message.hidden = false;

    openApp.href = companionDeepLink();
    browserLogin.href = loginUrl();
    authActions.hidden = false;
  }

  async function load() {
    if (!sessionId || !qrToken) {
      return showError('Invalid QR code.');
    }

    // Companion App: request a short-lived access token directly from the
    // official external-auth bridge. No app refresh token is exposed to us.
    if (companionBridgeAvailable()) {
      await requestExternalAuth(false);
    }

    if (!accessToken && authorizationCode) {
      await exchangeAuthorizationCode(authorizationCode);
    }

    if (!accessToken) {
      const stored = browserTokens();
      if (stored) {
        accessToken = stored.access_token || null;
        refreshToken = stored.refresh_token || null;
        clientId = stored.clientId || clientIdDefault;
      }
    }

    if (!accessToken) {
      showAuthChoices();
      return;
    }

    const r = await request(
      '/api/secure_qr_login/approval?session_id='
      + encodeURIComponent(sessionId)
      + '&qr_token='
      + encodeURIComponent(qrToken)
    );

    const d = await r.json().catch(() => ({}));
    if (!r.ok) {
      if (d.error === 'qr_expired') {
        return showError('This QR code has expired. Scan the current code again.');
      }
      if (d.error === 'user_not_allowed') {
        return showError('This Home Assistant account is not allowed to approve QR login.');
      }
      return showError('This login request is no longer valid.');
    }

    authActions.hidden = true;
    document.getElementById('account').textContent = d.account || '—';
    document.getElementById('ip').textContent = d.client_ip || '—';
    document.getElementById('agent').textContent = d.user_agent || '—';
    message.hidden = true;
    details.hidden = false;
  }

  async function act(action) {
    document.getElementById('approve').disabled = true;
    document.getElementById('deny').disabled = true;

    const r = await request('/api/secure_qr_login/approval/action', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        session_id: sessionId,
        qr_token: qrToken,
        action
      })
    });

    const d = await r.json().catch(() => ({}));
    details.hidden = true;
    message.hidden = false;

    if (!r.ok) {
      return showError(
        d.error === 'qr_expired'
          ? 'QR expired. Scan the current code again.'
          : 'Approval failed.'
      );
    }

    message.className = action === 'approve' ? 'ok' : 'error';
    message.textContent = action === 'approve'
      ? 'Approved. The other device can now finish signing in.'
      : 'Login denied.';
  }

  document.getElementById('approve').addEventListener('click', () => act('approve'));
  document.getElementById('deny').addEventListener('click', () => act('deny'));

  load().catch(() => showError('Unable to validate the login request.'));
})();
