(() => {
  const status = document.getElementById('status');
  const countdown = document.getElementById('countdown');
  const activeBody = document.getElementById('active');
  const historyBody = document.getElementById('history');
  const activeEmpty = document.getElementById('activeEmpty');
  const historyEmpty = document.getElementById('historyEmpty');
  const revokeAllButton = document.getElementById('revokeAll');
  const clearHistoryButton = document.getElementById('clearHistory');
  const saveSettingsButton = document.getElementById('saveSettings');
  const geoUpdateButton = document.getElementById('geoUpdate');
  const tabButtons = Array.from(document.querySelectorAll('.tab-button'));
  const tabPanels = Array.from(document.querySelectorAll('.tab-panel'));
  const loginsBadge = document.getElementById('loginsBadge');

  let accessToken = null;
  let refreshToken = null;
  let clientId = null;
  let externalAuthResolve = null;
  let enabled = false;
  let remainingSeconds = 0;
  let lastSyncedAt = performance.now();

  const clientIdDefault = location.origin + '/';

  function candidateWindows() {
    const windows = [window];
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
          if (stored?.access_token) return stored;
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

  function companionBridgeAvailable() {
    return companionBridgeWindow() !== null;
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
    if (!bridge) return Promise.resolve(false);

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
        resolve(false);
      }
    });
  }

  function adoptBrowserTokens() {
    const stored = browserTokens();
    if (!stored) return false;

    accessToken = stored.access_token || null;
    refreshToken = stored.refresh_token || null;
    clientId = stored.clientId || clientIdDefault;
    return Boolean(accessToken);
  }

  async function refreshAccess() {
    if (companionBridgeAvailable() && await requestExternalAuth(true)) {
      return true;
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

    const data = await r.json();
    accessToken = data.access_token || null;
    refreshToken = data.refresh_token || refreshToken;
    return Boolean(accessToken);
  }

  async function ensureAuthentication() {
    installExternalAuthCallback();

    if (adoptBrowserTokens()) return true;

    if (companionBridgeAvailable() && await requestExternalAuth(false)) {
      return true;
    }

    return adoptBrowserTokens();
  }

  function authHeaders(extra = {}) {
    return accessToken
      ? {...extra, Authorization: `Bearer ${accessToken}`}
      : {...extra};
  }

  async function request(url, options = {}) {
    const baseHeaders = {...(options.headers || {})};
    const requestOptions = {
      ...options,
      cache: 'no-store',
      headers: authHeaders(baseHeaders)
    };

    let response = await fetch(url, requestOptions);
    if (response.status === 401 && await refreshAccess()) {
      response = await fetch(url, {
        ...options,
        cache: 'no-store',
        headers: authHeaders(baseHeaders)
      });
    }
    return response;
  }

  const textCell = (value, className = '', label = '') => {
    const td = document.createElement('td');
    td.textContent = value || '—';
    if (className) td.className = className;
    if (label) td.dataset.label = label;
    return td;
  };

  function activateTab(name, persist = true) {
    const target = tabPanels.find(panel => panel.dataset.panel === name);
    if (!target) return;

    for (const button of tabButtons) {
      button.classList.toggle('active', button.dataset.tab === name);
      button.setAttribute(
        'aria-selected',
        button.dataset.tab === name ? 'true' : 'false'
      );
    }

    for (const panel of tabPanels) {
      panel.classList.toggle('active', panel === target);
    }

    if (persist) {
      try {
        localStorage.setItem('secureQrLoginAdminTab', name);
      } catch {}
    }
  }

  function restoreTab() {
    let saved = 'overview';
    try {
      saved = localStorage.getItem('secureQrLoginAdminTab') || 'overview';
    } catch {}
    activateTab(saved, false);
  }

  const selectedValues = (select) =>
    Array.from(select.selectedOptions).map(option => option.value);

  function showAuthenticationError() {
    enabled = false;
    status.textContent = 'Authentication required';
    status.className = 'status danger';
    countdown.textContent =
      'The admin panel could not authenticate with Home Assistant.';
  }

  function renderCountdown() {
    if (!enabled) {
      countdown.textContent = 'Off by default. No new QR sessions can be created.';
      return;
    }

    const elapsed = Math.floor((performance.now() - lastSyncedAt) / 1000);
    const left = Math.max(0, remainingSeconds - elapsed);
    countdown.textContent =
      `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')} remaining`;

    if (left === 0) {
      enabled = false;
      status.textContent = 'DISABLED';
      status.className = 'status danger';
    }
  }

  function renderActive(items) {
    activeBody.replaceChildren();
    activeEmpty.hidden = items.length !== 0;
    revokeAllButton.disabled = items.length === 0;

    for (const item of items) {
      const tr = document.createElement('tr');
      tr.append(
        textCell(item.user_name, '', 'Account'),
        textCell(item.client_ip, '', 'IP address'),
        textCell(item.user_agent, 'agent', 'Browser / device'),
        textCell(
          item.delivered_at
            ? new Date(item.delivered_at * 1000).toLocaleString()
            : '—',
          '',
          'Signed in'
        )
      );

      const action = document.createElement('td');
      action.dataset.label = 'Action';
      const button = document.createElement('button');
      button.className = 'revoke';
      button.textContent = 'Revoke';
      button.addEventListener('click', async () => {
        if (!confirm(`Revoke QR login for ${item.user_name || 'this account'}?`)) {
          return;
        }
        button.disabled = true;
        await revoke(item.login_id);
      });

      action.append(button);
      tr.append(action);
      activeBody.append(tr);
    }
  }

  function renderHistory(items) {
    historyBody.replaceChildren();
    historyEmpty.hidden = items.length !== 0;
    clearHistoryButton.disabled = items.length === 0;

    for (const item of items) {
      const tr = document.createElement('tr');
      tr.append(
        textCell(
          item.at ? new Date(item.at * 1000).toLocaleString() : '—',
          '',
          'Time'
        ),
        textCell(item.event, '', 'Event'),
        textCell(item.user_name, '', 'Account'),
        textCell(item.client_ip, '', 'IP address'),
        textCell(item.detail, '', 'Details')
      );
      historyBody.append(tr);
    }
  }

  async function state() {
    const r = await request('/api/secure_qr_login/admin/state');

    if (!r.ok) {
      if (r.status === 401) showAuthenticationError();
      return false;
    }

    const d = await r.json();
    enabled = Boolean(d.enabled);
    remainingSeconds = Number(d.remaining_seconds || 0);
    lastSyncedAt = performance.now();

    status.textContent = enabled ? 'ENABLED' : 'DISABLED';
    status.className = 'status ' + (enabled ? '' : 'danger');
    renderCountdown();

    document.getElementById('window').textContent = `${d.window_seconds}s`;
    document.getElementById('rotation').textContent = `${d.qr_lifetime_seconds}s`;
    document.getElementById('pending').textContent =
      `${d.pending_sessions} / ${d.max_pending_sessions}`;
    const activeCount = (d.active || []).length;
    document.getElementById('activeCount').textContent = String(activeCount);
    loginsBadge.textContent = String(activeCount);
    loginsBadge.hidden = activeCount === 0;

    document.getElementById('version').textContent = d.version || '—';
    document.getElementById('overviewVersion').textContent = d.version || '—';
    document.getElementById('build').textContent = d.build || '—';

    renderActive(d.active || []);
    renderHistory(d.history || []);
    return true;
  }

  function fillSelect(select, items, selected, labelKey = null) {
    select.replaceChildren();
    const chosen = new Set(selected || []);

    for (const item of items) {
      const option = document.createElement('option');
      if (typeof item === 'string') {
        option.value = item;
        option.textContent = `notify.${item}`;
      } else {
        option.value = item.id;
        option.textContent = labelKey ? item[labelKey] : item.name;
      }
      option.selected = chosen.has(option.value);
      select.append(option);
    }
  }

  function fillCountrySelect(select, codes, selected) {
    select.replaceChildren();
    const chosen = new Set(selected || []);
    let displayNames = null;

    try {
      displayNames = new Intl.DisplayNames(
        [navigator.language || 'en'],
        {type: 'region'}
      );
    } catch {}

    for (const code of codes || []) {
      const option = document.createElement('option');
      option.value = code;
      const name = displayNames?.of(code) || code;
      option.textContent = `${name} (${code})`;
      option.selected = chosen.has(code);
      select.append(option);
    }
  }

  async function loadSettings() {
    const r = await request('/api/secure_qr_login/admin/settings');
    if (!r.ok) {
      if (r.status === 401) showAuthenticationError();
      return false;
    }

    const d = await r.json();
    const v = d.values;

    document.getElementById('settingWindow').value = v.enable_window_seconds;
    document.getElementById('settingQr').value = v.qr_lifetime_seconds;
    document.getElementById('settingPending').value = v.max_pending_sessions;
    document.getElementById('settingHistory').value = v.history_limit;
    document.getElementById('settingNotifyApproved').checked = v.notify_on_approved;
    document.getElementById('settingNotifyDenied').checked = v.notify_on_denied;
    document.getElementById('settingPrivate').checked = v.allow_private_networks;

    fillSelect(
      document.getElementById('settingUsers'),
      d.users || [],
      v.allowed_user_ids || []
    );
    fillSelect(
      document.getElementById('settingNotify'),
      d.notify_services || [],
      v.notify_services || []
    );
    fillCountrySelect(
      document.getElementById('settingCountries'),
      d.country_codes || [],
      v.allowed_countries || []
    );

    const geo = d.geoip || {};
    const release = geo.local_database_release
      ? ` · Database: ${geo.local_database_release}`
      : '';

    let geoText = 'Country filtering is available.';
    if (geo.provider === 'nabu_casa') {
      geoText = geo.current_country
        ? `Provider: Nabu Casa + local GeoIP database · Current country: ${geo.current_country}${release}.`
        : geo.local_database_error
          ? `Nabu Casa request detected, but local GeoIP is unavailable (${geo.local_database_error}). Country filtering will fail closed.`
          : 'Nabu Casa request detected, but a usable public client IP/country was not available. Country filtering will fail closed.';
    } else if (geo.current_country) {
      geoText =
        `Provider: Home Assistant client IP + local GeoIP database · Current country: ${geo.current_country}${release}.`;
    } else if (geo.local_database_ready) {
      geoText =
        `Local GeoIP database is ready${release}, but this request could not be mapped to a public country (${geo.resolution_reason || 'unknown'}).`;
    } else {
      geoText = geo.local_database_error
        ? `Local GeoIP database is not ready (${geo.local_database_error}). Country filtering will fail closed until it can be loaded.`
        : 'Local GeoIP database is not ready. Country filtering will fail closed until it can be loaded.';
    }
    document.getElementById('geoStatus').textContent = geoText;

    const warning = document.getElementById('geoWarning');
    if (geo.local_database_error) {
      warning.hidden = false;
      warning.textContent =
        `GeoIP database update failed — still using ${geo.local_database_release || 'the last valid database'}.`;
    } else {
      warning.hidden = true;
      warning.textContent = '';
    }

    const attempt = geo.last_update_attempt
      ? new Date(geo.last_update_attempt).toLocaleString()
      : 'Never';
    const success = geo.last_successful_update
      ? new Date(geo.last_successful_update).toLocaleString()
      : 'Never';
    document.getElementById('geoTimes').textContent =
      `Last update attempt: ${attempt} · Last successful update: ${success}`;
    return true;
  }

  async function updateGeoIP() {
    geoUpdateButton.disabled = true;
    geoUpdateButton.textContent = 'Checking…';

    const r = await request('/api/secure_qr_login/admin/geoip-update', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: '{}'
    });

    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      alert(`GeoIP update failed: ${data.error || 'unknown error'}`);
    }

    await Promise.all([state(), loadSettings()]);
    geoUpdateButton.disabled = false;
    geoUpdateButton.textContent = 'Check for GeoIP update';
  }

  async function saveSettings() {
    const message = document.getElementById('settingsMessage');
    const countries = selectedValues(
      document.getElementById('settingCountries')
    );

    const payload = {
      enable_window_seconds:
        Number(document.getElementById('settingWindow').value),
      qr_lifetime_seconds:
        Number(document.getElementById('settingQr').value),
      max_pending_sessions:
        Number(document.getElementById('settingPending').value),
      history_limit:
        Number(document.getElementById('settingHistory').value),
      allowed_user_ids:
        selectedValues(document.getElementById('settingUsers')),
      notify_services:
        selectedValues(document.getElementById('settingNotify')),
      notify_on_approved:
        document.getElementById('settingNotifyApproved').checked,
      notify_on_denied:
        document.getElementById('settingNotifyDenied').checked,
      allowed_countries: countries,
      allow_private_networks:
        document.getElementById('settingPrivate').checked
    };

    saveSettingsButton.disabled = true;
    message.className = 'notice muted';
    message.textContent = 'Saving…';

    const r = await request('/api/secure_qr_login/admin/settings', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });

    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      message.className = 'notice error';
      message.textContent =
        `Unable to save settings: ${data.error || 'unknown error'}.`;
    } else {
      message.className = 'notice ok';
      message.textContent = 'Settings saved.';
      await Promise.all([state(), loadSettings()]);
    }

    saveSettingsButton.disabled = false;
  }

  async function setEnabled(value) {
    const r = await request('/api/secure_qr_login/admin/window', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({enabled: value})
    });

    if (!r.ok) {
      alert('Unable to change the QR login window.');
    }
    await state();
  }

  async function revoke(loginId) {
    const r = await request('/api/secure_qr_login/admin/revoke', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({login_id: loginId})
    });
    if (!r.ok) {
      alert('Unable to revoke this login. It may already have been revoked.');
    }
    await state();
  }

  async function revokeAll() {
    if (!confirm(
      'Revoke every QR-created login? This also closes the current QR login window and cancels pending requests.'
    )) {
      return;
    }

    revokeAllButton.disabled = true;
    const r = await request('/api/secure_qr_login/admin/revoke-all', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: '{}'
    });
    if (!r.ok) alert('Unable to revoke all QR logins.');
    await state();
  }

  async function clearHistory() {
    if (!confirm(
      'Clear the Secure QR Login security history? Active logins will not be changed.'
    )) {
      return;
    }

    clearHistoryButton.disabled = true;
    const r = await request('/api/secure_qr_login/admin/clear-history', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: '{}'
    });
    if (!r.ok) alert('Unable to clear history.');
    await state();
  }

  async function boot() {
    restoreTab();

    status.textContent = 'Authenticating…';
    status.className = 'status';
    countdown.textContent =
      'Connecting securely to your Home Assistant session…';

    if (!await ensureAuthentication()) {
      showAuthenticationError();
      return;
    }

    const [stateOk, settingsOk] = await Promise.all([
      state(),
      loadSettings()
    ]);

    if (!stateOk || !settingsOk) {
      return;
    }

    setInterval(renderCountdown, 250);
    setInterval(state, 5000);
  }

  for (const button of tabButtons) {
    button.setAttribute('role', 'tab');
    button.addEventListener('click', () => activateTab(button.dataset.tab));
  }

  document.getElementById('enable').addEventListener(
    'click',
    () => setEnabled(true)
  );
  document.getElementById('disable').addEventListener(
    'click',
    () => setEnabled(false)
  );
  revokeAllButton.addEventListener('click', revokeAll);
  clearHistoryButton.addEventListener('click', clearHistory);
  saveSettingsButton.addEventListener('click', saveSettings);
  geoUpdateButton.addEventListener('click', updateGeoIP);

  boot().catch(() => showAuthenticationError());
})();
