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
    clearInterval(qrTimer); clearInterval(pollTimer);
  }

  async function rotateQr() {
    const response = await post('/api/secure_qr_login/qr', {
      session_id: sessionId,
      device_secret: deviceSecret
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      fail(data.error === 'disabled' ? 'QR Login is disabled.' : 'Unable to refresh QR code.');
      return;
    }
    const blob = await response.blob();
    const old = qrBox.querySelector('img');
    if (old && old.dataset.url) URL.revokeObjectURL(old.dataset.url);
    const url = URL.createObjectURL(blob);
    const img = document.createElement('img');
    img.src = url; img.dataset.url = url; img.alt = 'Secure QR Login code';
    qrBox.replaceChildren(img);
    progress.animate([{transform:'scaleX(1)'},{transform:'scaleX(0)'}], {duration:qrLifetime*1000,fill:'forwards'});
  }

  async function poll() {
    const response = await post('/api/secure_qr_login/status', {
      session_id: sessionId,
      device_secret: deviceSecret
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (['disabled','session_not_found'].includes(data.error)) fail('Login window closed or expired.');
      return;
    }
    if (data.status === 'denied') return fail('Login denied.');
    if (data.status !== 'approved') return;

    clearInterval(qrTimer); clearInterval(pollTimer);
    const expiresIn = data.token_expires_in || 1800;
    localStorage.setItem('hassTokens', JSON.stringify({
      hassUrl: window.location.origin,
      clientId: window.location.origin + '/',
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_in: expiresIn,
      expires: Date.now() + expiresIn * 1000
    }));
    state.className = 'ok'; state.textContent = 'Approved. Opening Home Assistant…';
    setTimeout(() => { window.location.replace('/'); }, 500);
  }

  async function init() {
    const response = await post('/api/secure_qr_login/start', {});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) return fail(data.error === 'disabled' ? 'QR Login is disabled. Enable the 3-minute window first.' : 'Unable to start login session.');
    sessionId = data.session_id;
    deviceSecret = data.device_secret;
    qrLifetime = data.qr_lifetime || 10;
    await rotateQr();
    qrTimer = setInterval(rotateQr, qrLifetime * 1000);
    pollTimer = setInterval(poll, 2000);
  }

  init().catch(() => fail('Unable to start Secure QR Login.'));
})();
