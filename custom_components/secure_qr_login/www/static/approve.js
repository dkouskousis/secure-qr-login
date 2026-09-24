(() => {
  const message = document.getElementById('message');
  const details = document.getElementById('details');
  const params = new URLSearchParams(location.search);
  const sessionId = params.get('session_id') || '';
  const qrToken = params.get('qr_token') || '';
  const authorizationCode = params.get('code') || '';
  const clientIdDefault = location.origin + '/';
  let accessToken = null;
  let refreshToken = null;
  let clientId = null;

  function browserTokens() {
    try { return JSON.parse(localStorage.getItem('hassTokens')); } catch { return null; }
  }

  function saveTokens(data, cid) {
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

  function authHeaders(extra={}) {
    return accessToken ? {...extra, Authorization:`Bearer ${accessToken}`} : extra;
  }

  async function exchangeAuthorizationCode(code) {
    const body = new URLSearchParams({grant_type:'authorization_code',code,client_id:clientIdDefault});
    const r = await fetch('/auth/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body.toString(),cache:'no-store'});
    if (!r.ok) return false;
    const d = await r.json();
    if (!d.access_token) return false;
    accessToken = d.access_token;
    refreshToken = d.refresh_token || null;
    clientId = clientIdDefault;
    saveTokens(d, clientIdDefault);
    const clean = new URL(location.href);
    clean.searchParams.delete('code');
    history.replaceState(null,'',clean.pathname + clean.search);
    return true;
  }

  async function refreshAccess() {
    if (!refreshToken || !clientId) return false;
    const body = new URLSearchParams({grant_type:'refresh_token',refresh_token:refreshToken,client_id:clientId});
    const r = await fetch('/auth/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body.toString(),cache:'no-store'});
    if (!r.ok) return false;
    const d = await r.json();
    accessToken = d.access_token;
    refreshToken = d.refresh_token || refreshToken;
    if (accessToken) saveTokens(d, clientId);
    return !!accessToken;
  }

  async function request(url, options={}) {
    options.cache = 'no-store';
    options.headers = authHeaders(options.headers || {});
    let r = await fetch(url, options);
    if (r.status === 401 && await refreshAccess()) {
      options.headers = authHeaders(options.headers || {});
      r = await fetch(url, options);
    }
    return r;
  }

  function showError(text) { details.hidden=true; message.hidden=false; message.className='error'; message.textContent=text; }

  function loginUrl() {
    const redirect = location.origin + location.pathname + '?session_id=' + encodeURIComponent(sessionId) + '&qr_token=' + encodeURIComponent(qrToken);
    return '/auth/authorize?response_type=code&client_id=' + encodeURIComponent(clientIdDefault) + '&redirect_uri=' + encodeURIComponent(redirect);
  }

  async function load() {
    if (!sessionId || !qrToken) return showError('Invalid QR code.');

    if (authorizationCode) await exchangeAuthorizationCode(authorizationCode);
    if (!accessToken) {
      const stored = browserTokens();
      if (stored) {
        accessToken = stored.access_token || null;
        refreshToken = stored.refresh_token || null;
        clientId = stored.clientId || clientIdDefault;
      }
    }

    if (!accessToken) {
      message.replaceChildren();
      const text = document.createTextNode('Authentication required. ');
      const a = document.createElement('a');
      a.href = loginUrl(); a.className='button approve'; a.textContent='Sign in to Home Assistant';
      message.append(text,a);
      return;
    }

    const r = await request('/api/secure_qr_login/approval?session_id=' + encodeURIComponent(sessionId) + '&qr_token=' + encodeURIComponent(qrToken));
    const d = await r.json().catch(()=>({}));
    if (!r.ok) return showError(d.error === 'qr_expired' ? 'This QR code has expired. Scan the current code again.' : 'This login request is no longer valid.');
    document.getElementById('account').textContent = d.account || '—';
    document.getElementById('ip').textContent = d.client_ip || '—';
    document.getElementById('agent').textContent = d.user_agent || '—';
    message.hidden = true; details.hidden = false;
  }

  async function act(action) {
    document.getElementById('approve').disabled = true;
    document.getElementById('deny').disabled = true;
    const r = await request('/api/secure_qr_login/approval/action', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({session_id:sessionId,qr_token:qrToken,action})
    });
    const d = await r.json().catch(()=>({}));
    details.hidden = true; message.hidden = false;
    if (!r.ok) return showError(d.error === 'qr_expired' ? 'QR expired. Scan the current code again.' : 'Approval failed.');
    message.className = action === 'approve' ? 'ok' : 'error';
    message.textContent = action === 'approve' ? 'Approved. The other device can now finish signing in.' : 'Login denied.';
  }

  document.getElementById('approve').addEventListener('click',()=>act('approve'));
  document.getElementById('deny').addEventListener('click',()=>act('deny'));
  load().catch(()=>showError('Unable to validate the login request.'));
})();
