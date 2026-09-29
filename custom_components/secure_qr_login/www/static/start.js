(() => {
  const state = document.getElementById('state');
  const qrBox = document.getElementById('qr');
  const progress = document.getElementById('progress');

  const clientIdDefault = location.origin + '/';

  let sessionId = '';
  let deviceSecret = '';
  let qrTimer = null;
  let pollTimer = null;
  let qrLifetime = 10;
  let externalAuthResolve = null;

  const post = async (url, body) => fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
    cache: 'no-store'
  });

  function candidateWindows() {
    const windows = [window];

    // The login page can be opened directly, from the HA frontend, or from the
    // Companion App WebView. Check same-origin parent/top contexts when they are
    // accessible so an existing HA session is detected in all of those cases.
    try {
      if (window.parent && window.parent !== window) windows.push(window.parent);
    } catch {}

    try {
      if (window.top && !windows.includes(window.top)) windows.push(window.top);
    } catch {}

    return windows;
  }

  function browserTokens() {
    for (const target of candidateWindows()) {
      try {
        const memory = target.__tokenCache?.tokens;
        if (memory?.access_token) return memory;
      } catch {}

      try {
        const raw = target.localStorage?.getItem('hassTokens');
        if (raw) {
          const stored = JSON.parse(raw);
          if (stored?.access_token || stored?.refresh_token) return stored;
        }
      } catch {}
    }

    return null;
  }

  function companionBridgeWindow() {
    for (const target of candidateWindows()) {
      try {
        if (
          target.externalAppV2
          || target.externalApp
          || target.webkit?.messageHandlers?.getExternalAuth
        ) {
          return target;
        }
      } catch {}
    }

    return null;
  }

  function installExternalAuthCallback() {
    const callback = (success, data) => {
      if (externalAuthResolve) {
        externalAuthResolve(Boolean(success), data || null);
      }
    };

    for (const target of candidateWindows()) {
      try {
        target.externalAuthSetToken = callback;
      } catch {}
    }
  }

  function requestExternalAuth(force = false) {
    const bridge = companionBridgeWindow();
    if (!bridge) return Promise.resolve(null);

    return new Promise((resolve) => {
      let settled = false;
      const timeout = setTimeout(() => {
        if (!settled) {
          settled = true;
          externalAuthResolve = null;
          resolve(null);
        }
      }, 5000);

      externalAuthResolve = (success, data) => {
        if (settled) return;

        settled = true;
        clearTimeout(timeout);
        externalAuthResolve = null;

        resolve(
          success && data?.access_token
            ? {access_token: data.access_token}
            : null
        );
      };

      const payload = {callback: 'externalAuthSetToken', force};

      try {
        if (bridge.externalAppV2) {
          bridge.externalAppV2.postMessage(JSON.stringify({
            type: 'getExternalAuth',
            payload
          }));
          return;
        }

        if (bridge.externalApp) {
          bridge.externalApp.getExternalAuth(JSON.stringify(payload));
          return;
        }

        bridge.webkit.messageHandlers.getExternalAuth.postMessage(payload);
      } catch {
        clearTimeout(timeout);
        externalAuthResolve = null;
        resolve(null);
      }
    });
  }

  async function tokenIsValid(accessToken) {
    if (!accessToken) return false;

    try {
      const response = await fetch('/api/', {
        headers: {Authorization: `Bearer ${accessToken}`},
        cache: 'no-store'
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  async function refreshBrowserToken(tokens) {
    if (!tokens?.refresh_token) return null;

    const clientId = tokens.clientId || clientIdDefault;
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token,
      client_id: clientId
    });

    try {
      const response = await fetch('/auth/token', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: body.toString(),
        cache: 'no-store'
      });

      if (!response.ok) return null;

      const data = await response.json();
      if (!data.access_token) return null;

      // Keep HA frontend storage current if the token was refreshed here.
      const expiresIn = data.expires_in || 1800;
      const updated = {
        ...tokens,
        hassUrl: location.origin,
        clientId,
        access_token: data.access_token,
        refresh_token: data.refresh_token || tokens.refresh_token,
        expires_in: expiresIn,
        expires: Date.now() + expiresIn * 1000
      };

      try {
        localStorage.setItem('hassTokens', JSON.stringify(updated));
      } catch {}

      return updated;
    } catch {
      return null;
    }
  }

  async function alreadyAuthenticated() {
    installExternalAuthCallback();

    // Browser/frontend authentication: verify the access token instead of
    // redirecting merely because stale localStorage happens to exist.
    const stored = browserTokens();
    if (stored?.access_token && await tokenIsValid(stored.access_token)) {
      return true;
    }

    if (stored?.refresh_token) {
      const refreshed = await refreshBrowserToken(stored);
      if (
        refreshed?.access_token
        && await tokenIsValid(refreshed.access_token)
      ) {
        return true;
      }
    }

    // Companion App authentication: request only a temporary access token.
    // The app's refresh token is never exposed to this page.
    const appTokens = await requestExternalAuth(false);
    if (
      appTokens?.access_token
      && await tokenIsValid(appTokens.access_token)
    ) {
      return true;
    }

    return false;
  }

  function redirectToHome() {
    clearInterval(qrTimer);
    clearInterval(pollTimer);

    state.className = 'ok';
    state.textContent = 'Already signed in. Opening Home Assistant…';

    // replace() keeps the QR entry page out of browser history, so Back does
    // not immediately return the user to the login flow.
    window.location.replace('/');
  }

  function fail(text) {
    state.className = 'error';
    state.textContent = text;
    clearInterval(qrTimer);
    clearInterval(pollTimer);
  }

  function requestError(data, fallback) {
    if (data.error === 'disabled') {
      return 'QR Login is disabled.';
    }
    if (data.error === 'session_locked') {
      return 'This login request was locked after repeated invalid secret attempts.';
    }
    if (data.error === 'pending_limit_reached') {
      return 'Too many QR login requests are already pending.';
    }
    if (data.error === 'origin_rejected') {
      return 'This request was rejected by the same-origin security policy.';
    }
    if (data.error === 'country_not_allowed') {
      if (data.reason === 'nabu_client_ip_unavailable') {
        return 'Country restriction is enabled, but Nabu Casa did not provide a usable public client IP.';
      }
      if (
        [
          'database_unavailable',
          'lookup_failed',
          'client_ip_missing',
          'client_ip_invalid'
        ].includes(data.reason)
      ) {
        return 'Country restriction is enabled, but local GeoIP resolution is unavailable.';
      }
      return `QR Login is not allowed from country ${data.country || 'unknown'}.`;
    }
    return fallback;
  }

  async function rotateQr() {
    const response = await post('/api/secure_qr_login/qr', {
      session_id: sessionId,
      device_secret: deviceSecret
    });

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      fail(requestError(data, 'Unable to refresh QR code.'));
      return;
    }

    const blob = await response.blob();
    const old = qrBox.querySelector('img');
    if (old && old.dataset.url) {
      URL.revokeObjectURL(old.dataset.url);
    }

    const url = URL.createObjectURL(blob);
    const img = document.createElement('img');
    img.src = url;
    img.dataset.url = url;
    img.alt = 'Secure QR Login code';
    qrBox.replaceChildren(img);

    progress.animate(
      [{transform: 'scaleX(1)'}, {transform: 'scaleX(0)'}],
      {duration: qrLifetime * 1000, fill: 'forwards'}
    );
  }

  async function poll() {
    const response = await post('/api/secure_qr_login/status', {
      session_id: sessionId,
      device_secret: deviceSecret
    });
    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      if (
        ['disabled', 'session_not_found', 'session_locked'].includes(data.error)
      ) {
        fail(requestError(data, 'Login window closed or expired.'));
      }
      return;
    }

    if (data.status === 'denied') {
      fail('Login denied.');
      return;
    }
    if (data.status !== 'approved') {
      return;
    }

    clearInterval(qrTimer);
    clearInterval(pollTimer);

    const expiresIn = data.token_expires_in || 1800;
    localStorage.setItem('hassTokens', JSON.stringify({
      hassUrl: window.location.origin,
      clientId: window.location.origin + '/',
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_in: expiresIn,
      expires: Date.now() + expiresIn * 1000
    }));

    state.className = 'ok';
    state.textContent = 'Approved. Opening Home Assistant…';
    setTimeout(() => {
      window.location.replace('/');
    }, 500);
  }

  async function init() {
    state.textContent = 'Checking existing Home Assistant session…';

    if (await alreadyAuthenticated()) {
      redirectToHome();
      return;
    }

    const response = await post('/api/secure_qr_login/start', {});
    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      fail(
        requestError(
          data,
          'Unable to start login session.'
        )
      );
      return;
    }

    sessionId = data.session_id;
    deviceSecret = data.device_secret;
    qrLifetime = data.qr_lifetime || 10;

    await rotateQr();
    qrTimer = setInterval(rotateQr, qrLifetime * 1000);
    pollTimer = setInterval(poll, 2000);
  }

  init().catch(() => fail('Unable to start Secure QR Login.'));
})();
