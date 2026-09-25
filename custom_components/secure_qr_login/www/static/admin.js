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

  let token = null;
  let enabled = false;
  let remainingSeconds = 0;
  let lastSyncedAt = performance.now();

  try {
    token = JSON.parse(localStorage.getItem('hassTokens'))?.access_token || null;
  } catch {}

  const headers = (extra = {}) => token
    ? {...extra, Authorization: `Bearer ${token}`}
    : extra;

  const textCell = (value, className = '') => {
    const td = document.createElement('td');
    td.textContent = value || '—';
    if (className) td.className = className;
    return td;
  };

  const selectedValues = (select) =>
    Array.from(select.selectedOptions).map(option => option.value);

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
        textCell(item.user_name),
        textCell(item.client_ip),
        textCell(item.user_agent, 'agent'),
        textCell(item.delivered_at ? new Date(item.delivered_at * 1000).toLocaleString() : '—')
      );

      const action = document.createElement('td');
      const button = document.createElement('button');
      button.className = 'revoke';
      button.textContent = 'Revoke';
      button.addEventListener('click', async () => {
        if (!confirm(`Revoke QR login for ${item.user_name || 'this account'}?`)) return;
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
        textCell(item.at ? new Date(item.at * 1000).toLocaleString() : '—'),
        textCell(item.event),
        textCell(item.user_name),
        textCell(item.client_ip),
        textCell(item.detail)
      );
      historyBody.append(tr);
    }
  }

  async function state() {
    const r = await fetch('/api/secure_qr_login/admin/state', {
      headers: headers(),
      cache: 'no-store'
    });

    if (!r.ok) {
      status.textContent = 'Authentication required';
      status.className = 'status danger';
      return;
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
    document.getElementById('activeCount').textContent = String((d.active || []).length);
    document.getElementById('version').textContent = d.version || '—';
    document.getElementById('build').textContent = d.build || '—';

    renderActive(d.active || []);
    renderHistory(d.history || []);
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
      displayNames = new Intl.DisplayNames([navigator.language || 'en'], {type: 'region'});
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
    const r = await fetch('/api/secure_qr_login/admin/settings', {
      headers: headers(),
      cache: 'no-store'
    });
    if (!r.ok) return;

    const d = await r.json();
    const v = d.values;

    document.getElementById('settingWindow').value = v.enable_window_seconds;
    document.getElementById('settingQr').value = v.qr_lifetime_seconds;
    document.getElementById('settingPending').value = v.max_pending_sessions;
    document.getElementById('settingHistory').value = v.history_limit;
    document.getElementById('settingNotifyApproved').checked = v.notify_on_approved;
    document.getElementById('settingNotifyDenied').checked = v.notify_on_denied;
    document.getElementById('settingPrivate').checked = v.allow_private_networks;

    fillSelect(document.getElementById('settingUsers'), d.users || [], v.allowed_user_ids || []);
    fillSelect(document.getElementById('settingNotify'), d.notify_services || [], v.notify_services || []);
    fillCountrySelect(
      document.getElementById('settingCountries'),
      d.country_codes || [],
      v.allowed_countries || []
    );

    const geo = d.geoip || {};
    const release = geo.local_database_release ? ` · Database: ${geo.local_database_release}` : '';
    let geoText = 'Country filtering is available.';
    if (geo.provider === 'nabu_casa') {
      geoText = geo.current_country
        ? `Provider: Nabu Casa + local GeoIP database · Current country: ${geo.current_country}${release}.`
        : geo.local_database_error
        ? `Nabu Casa request detected, but local GeoIP is unavailable (${geo.local_database_error}). Country filtering will fail closed.`
        : 'Nabu Casa request detected, but a usable public client IP/country was not available. Country filtering will fail closed.';
    } else if (geo.current_country) {
      geoText = `Provider: Home Assistant client IP + local GeoIP database · Current country: ${geo.current_country}${release}.`;
    } else if (geo.local_database_ready) {
      geoText = `Local GeoIP database is ready${release}, but this request could not be mapped to a public country (${geo.resolution_reason || 'unknown'}).`;
    } else {
      geoText = geo.local_database_error
        ? `Local GeoIP database is not ready (${geo.local_database_error}). Country filtering will fail closed until it can be loaded.`
        : 'Local GeoIP database is not ready. Country filtering will fail closed until it can be loaded.';
    }
    document.getElementById('geoStatus').textContent = geoText;
  }

  async function saveSettings() {
    const message = document.getElementById('settingsMessage');
    const countries = selectedValues(document.getElementById('settingCountries'));

    const payload = {
      enable_window_seconds: Number(document.getElementById('settingWindow').value),
      qr_lifetime_seconds: Number(document.getElementById('settingQr').value),
      max_pending_sessions: Number(document.getElementById('settingPending').value),
      history_limit: Number(document.getElementById('settingHistory').value),
      allowed_user_ids: selectedValues(document.getElementById('settingUsers')),
      notify_services: selectedValues(document.getElementById('settingNotify')),
      notify_on_approved: document.getElementById('settingNotifyApproved').checked,
      notify_on_denied: document.getElementById('settingNotifyDenied').checked,
      allowed_countries: countries,
      allow_private_networks: document.getElementById('settingPrivate').checked
    };

    saveSettingsButton.disabled = true;
    message.className = 'notice muted';
    message.textContent = 'Saving…';

    const r = await fetch('/api/secure_qr_login/admin/settings', {
      method: 'POST',
      headers: headers({'Content-Type': 'application/json'}),
      body: JSON.stringify(payload),
      cache: 'no-store'
    });

    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      message.className = 'notice error';
      message.textContent = `Unable to save settings: ${data.error || 'unknown error'}.`;
    } else {
      message.className = 'notice ok';
      message.textContent = 'Settings saved.';
      await Promise.all([state(), loadSettings()]);
    }

    saveSettingsButton.disabled = false;
  }

  async function setEnabled(value) {
    await fetch('/api/secure_qr_login/admin/window', {
      method: 'POST',
      headers: headers({'Content-Type': 'application/json'}),
      body: JSON.stringify({enabled: value}),
      cache: 'no-store'
    });
    await state();
  }

  async function revoke(loginId) {
    const r = await fetch('/api/secure_qr_login/admin/revoke', {
      method: 'POST',
      headers: headers({'Content-Type': 'application/json'}),
      body: JSON.stringify({login_id: loginId}),
      cache: 'no-store'
    });
    if (!r.ok) alert('Unable to revoke this login. It may already have been revoked.');
    await state();
  }

  async function revokeAll() {
    if (!confirm('Revoke every QR-created login? This also closes the current QR login window and cancels pending requests.')) return;

    revokeAllButton.disabled = true;
    const r = await fetch('/api/secure_qr_login/admin/revoke-all', {
      method: 'POST',
      headers: headers({'Content-Type': 'application/json'}),
      body: '{}',
      cache: 'no-store'
    });
    if (!r.ok) alert('Unable to revoke all QR logins.');
    await state();
  }

  async function clearHistory() {
    if (!confirm('Clear the Secure QR Login security history? Active logins will not be changed.')) return;

    clearHistoryButton.disabled = true;
    const r = await fetch('/api/secure_qr_login/admin/clear-history', {
      method: 'POST',
      headers: headers({'Content-Type': 'application/json'}),
      body: '{}',
      cache: 'no-store'
    });
    if (!r.ok) alert('Unable to clear history.');
    await state();
  }

  document.getElementById('enable').addEventListener('click', () => setEnabled(true));
  document.getElementById('disable').addEventListener('click', () => setEnabled(false));
  revokeAllButton.addEventListener('click', revokeAll);
  clearHistoryButton.addEventListener('click', clearHistory);
  saveSettingsButton.addEventListener('click', saveSettings);

  state();
  loadSettings();
  setInterval(renderCountdown, 250);
  setInterval(state, 5000);
})();
