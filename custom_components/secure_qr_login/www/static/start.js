(() => {
  const state = document.getElementById('state');
  const qrBox = document.getElementById('qr');
  const progress = document.getElementById('progress');

  let sessionId = '';
  let deviceSecret = '';
  let qrTimer = null;
  let pollTimer = null;
  let qrLifetime = 10;

  const post = async (url, body) => fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
    cache: 'no-store'
  });

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
      if (data.reason === 'cloudflare_headers_missing') {
        return 'Country restriction is enabled, but trusted Cloudflare GeoIP headers are missing.';
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
