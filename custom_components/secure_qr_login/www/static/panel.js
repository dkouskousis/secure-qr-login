class SecureQrLoginPanel extends HTMLElement {
  constructor() {
    super();
    this._hass = null;
    this._rendered = false;
    this._timer = null;
    this._enabled = false;
    this._remaining = 0;
    this._syncedAt = performance.now();
  }

  set hass(value) {
    this._hass = value;
    if (!this._rendered) this._render();
    this._refreshAll();
  }

  set narrow(_value) {}
  set route(_value) {}
  set panel(_value) {}

  connectedCallback() {
    if (!this._rendered) this._render();
  }

  disconnectedCallback() {
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
  }

  _q(id) {
    return this.querySelector('#' + id);
  }

  async _api(method, path, data) {
    if (!this._hass) throw new Error('Home Assistant context is unavailable');
    return this._hass.callApi(method, path, data);
  }

  _render() {
    this._rendered = true;
    this.innerHTML = `
      <link rel="stylesheet" href="/secure_qr_login/static/app.css?v=1.5.4">
      <div class="secure-qr-panel">
        <div class="admin-shell">
          <header class="admin-header">
            <div>
              <div class="eyebrow">Home Assistant security</div>
              <h1>Secure QR Login</h1>
              <p class="header-subtitle">Manage temporary QR access, security policy and login activity.</p>
            </div>
            <div class="header-meta">
              <span class="version-chip">v<span id="version">—</span></span>
            </div>
          </header>

          <nav class="tabs" aria-label="Secure QR Login sections">
            <button class="tab-button active" data-tab="overview" type="button">Overview</button>
            <button class="tab-button" data-tab="settings" type="button">Settings</button>
            <button class="tab-button" data-tab="logins" type="button">Active logins <span id="loginsBadge" class="tab-badge">0</span></button>
            <button class="tab-button" data-tab="history" type="button">History</button>
          </nav>

          <section class="tab-panel active" data-panel="overview">
            <div class="hero-card">
              <div class="hero-status">
                <div>
                  <div class="section-kicker">Temporary login window</div>
                  <div id="status" class="status">Loading…</div>
                  <p id="countdown" class="status-detail muted"></p>
                </div>
                <div class="hero-actions">
                  <button id="enable" class="btn btn-primary">Enable temporarily</button>
                  <button id="disable" class="btn btn-secondary">Disable now</button>
                  <a class="btn btn-ghost" href="/secure_qr_login/start" target="_blank" rel="noopener">Open login screen</a>
                </div>
              </div>
              <div class="metrics-grid">
                <article class="metric-card"><span class="metric-label">Window</span><strong id="window">—</strong><span class="metric-caption">Maximum open duration</span></article>
                <article class="metric-card"><span class="metric-label">QR rotation</span><strong id="rotation">—</strong><span class="metric-caption">Token refresh interval</span></article>
                <article class="metric-card"><span class="metric-label">Pending</span><strong id="pending">—</strong><span class="metric-caption">Current requests / limit</span></article>
                <article class="metric-card"><span class="metric-label">Active logins</span><strong id="activeCount">—</strong><span class="metric-caption">QR-created sessions</span></article>
              </div>
            </div>
          </section>

          <section class="tab-panel" data-panel="settings">
            <div class="settings-layout">
              <article class="surface-card">
                <div class="card-heading"><div><div class="section-kicker">Core policy</div><h2>Login controls</h2></div></div>
                <div class="form-grid">
                  <label class="control"><span>Login window</span><input id="settingWindow" type="number" min="60" max="300" step="10"></label>
                  <label class="control"><span>QR rotation</span><input id="settingQr" type="number" min="5" max="30" step="1"></label>
                  <label class="control"><span>Maximum pending sessions</span><input id="settingPending" type="number" min="1" max="5" step="1"></label>
                  <label class="control"><span>History entries</span><input id="settingHistory" type="number" min="20" max="200" step="10"></label>
                </div>
              </article>

              <article class="surface-card">
                <div class="card-heading"><div><div class="section-kicker">Access</div><h2>Users & notifications</h2></div></div>
                <div class="settings-columns">
                  <label class="control"><span>Allowed users</span><select id="settingUsers" multiple size="6"></select><small>Leave empty to allow all active non-system users.</small></label>
                  <label class="control"><span>Notification targets</span><select id="settingNotify" multiple size="6"></select></label>
                </div>
                <div class="toggle-grid">
                  <label class="toggle-row"><span><strong>Approved login notification</strong></span><input id="settingNotifyApproved" type="checkbox"></label>
                  <label class="toggle-row"><span><strong>Denied login notification</strong></span><input id="settingNotifyDenied" type="checkbox"></label>
                </div>
              </article>

              <article class="surface-card">
                <div class="card-heading"><div><div class="section-kicker">GeoIP policy</div><h2>Country restriction</h2></div></div>
                <div class="settings-columns geo-columns">
                  <label class="control"><span>Allowed countries</span><select id="settingCountries" multiple size="10"></select><small>Leave empty to disable country filtering.</small></label>
                  <div class="geo-side">
                    <label class="toggle-row"><span><strong>Allow private / local clients</strong></span><input id="settingPrivate" type="checkbox"></label>
                    <div id="geoWarning" class="notice notice-error" hidden></div>
                    <div id="geoStatus" class="notice notice-neutral"></div>
                    <div id="geoTimes" class="notice notice-subtle"></div>
                    <button id="geoUpdate" class="btn btn-secondary">Check for GeoIP update</button>
                  </div>
                </div>
              </article>

              <div id="settingsMessage" class="notice"></div>
              <div class="sticky-save">
                <div><strong>Security settings</strong><span class="muted">Changes apply immediately after saving.</span></div>
                <button id="saveSettings" class="btn btn-primary">Save settings</button>
              </div>
            </div>
          </section>

          <section class="tab-panel" data-panel="logins">
            <article class="surface-card">
              <div class="card-heading split-heading"><div><div class="section-kicker">Session control</div><h2>Active QR logins</h2></div><button id="revokeAll" class="btn btn-danger">Revoke all</button></div>
              <div class="tablewrap modern-table">
                <table><thead><tr><th>Account</th><th>IP</th><th>Browser / device</th><th>Signed in</th><th></th></tr></thead><tbody id="active"></tbody></table>
              </div>
              <div id="activeEmpty" class="empty-state" hidden><strong>No active QR logins</strong></div>
            </article>
          </section>

          <section class="tab-panel" data-panel="history">
            <article class="surface-card">
              <div class="card-heading split-heading"><div><div class="section-kicker">Audit trail</div><h2>Security history</h2></div><button id="clearHistory" class="btn btn-danger-outline">Clear history</button></div>
              <div class="tablewrap modern-table">
                <table><thead><tr><th>Time</th><th>Event</th><th>Account</th><th>IP</th><th>Details</th></tr></thead><tbody id="history"></tbody></table>
              </div>
              <div id="historyEmpty" class="empty-state" hidden><strong>No security history</strong></div>
            </article>
          </section>
        </div>
      </div>
    `;

    this.querySelectorAll('.tab-button').forEach((button) => {
      button.addEventListener('click', () => this._selectTab(button.dataset.tab));
    });
    this._q('enable').addEventListener('click', () => this._setEnabled(true));
    this._q('disable').addEventListener('click', () => this._setEnabled(false));
    this._q('saveSettings').addEventListener('click', () => this._saveSettings());
    this._q('geoUpdate').addEventListener('click', () => this._updateGeoIP());
    this._q('revokeAll').addEventListener('click', () => this._revokeAll());
    this._q('clearHistory').addEventListener('click', () => this._clearHistory());

    if (!this._timer) {
      this._timer = setInterval(() => this._renderCountdown(), 250);
      setInterval(() => this._refreshState(), 5000);
    }
  }

  _selectTab(name) {
    this.querySelectorAll('.tab-button').forEach((button) => {
      button.classList.toggle('active', button.dataset.tab === name);
    });
    this.querySelectorAll('.tab-panel').forEach((panel) => {
      panel.classList.toggle('active', panel.dataset.panel === name);
    });
  }

  _renderCountdown() {
    if (!this._enabled) {
      this._q('countdown').textContent = 'Off by default. No new QR sessions can be created.';
      return;
    }
    const elapsed = Math.floor((performance.now() - this._syncedAt) / 1000);
    const left = Math.max(0, this._remaining - elapsed);
    this._q('countdown').textContent =
      `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')} remaining`;
  }

  async _refreshAll() {
    if (!this._hass || !this._rendered) return;
    await Promise.allSettled([this._refreshState(), this._loadSettings()]);
  }

  async _refreshState() {
    try {
      const d = await this._api('GET', 'secure_qr_login/admin/state');
      this._enabled = Boolean(d.enabled);
      this._remaining = Number(d.remaining_seconds || 0);
      this._syncedAt = performance.now();

      this._q('status').textContent = this._enabled ? 'ENABLED' : 'DISABLED';
      this._q('status').className = 'status ' + (this._enabled ? '' : 'danger');
      this._q('window').textContent = `${d.window_seconds}s`;
      this._q('rotation').textContent = `${d.qr_lifetime_seconds}s`;
      this._q('pending').textContent = `${d.pending_sessions} / ${d.max_pending_sessions}`;
      this._q('activeCount').textContent = String((d.active || []).length);
      this._q('loginsBadge').textContent = String((d.active || []).length);
      this._q('version').textContent = d.version || '—';
      this._renderCountdown();
      this._renderActive(d.active || []);
      this._renderHistory(d.history || []);
    } catch (err) {
      this._q('status').textContent = 'Unable to load';
      this._q('status').className = 'status danger';
      this._q('countdown').textContent = err?.message || 'Home Assistant API request failed.';
    }
  }

  _fillSelect(select, items, selected, kind) {
    select.replaceChildren();
    const chosen = new Set(selected || []);
    for (const item of items || []) {
      const option = document.createElement('option');
      if (kind === 'user') {
        option.value = item.id;
        option.textContent = item.name;
      } else if (kind === 'notify') {
        option.value = item;
        option.textContent = 'notify.' + item;
      } else {
        option.value = item;
        let name = item;
        try {
          name = new Intl.DisplayNames([navigator.language || 'en'], {type: 'region'}).of(item) || item;
        } catch {}
        option.textContent = `${name} (${item})`;
      }
      option.selected = chosen.has(option.value);
      select.append(option);
    }
  }

  async _loadSettings() {
    try {
      const d = await this._api('GET', 'secure_qr_login/admin/settings');
      const v = d.values;
      this._q('settingWindow').value = v.enable_window_seconds;
      this._q('settingQr').value = v.qr_lifetime_seconds;
      this._q('settingPending').value = v.max_pending_sessions;
      this._q('settingHistory').value = v.history_limit;
      this._q('settingNotifyApproved').checked = v.notify_on_approved;
      this._q('settingNotifyDenied').checked = v.notify_on_denied;
      this._q('settingPrivate').checked = v.allow_private_networks;
      this._fillSelect(this._q('settingUsers'), d.users, v.allowed_user_ids, 'user');
      this._fillSelect(this._q('settingNotify'), d.notify_services, v.notify_services, 'notify');
      this._fillSelect(this._q('settingCountries'), d.country_codes, v.allowed_countries, 'country');

      const geo = d.geoip || {};
      const release = geo.local_database_release ? `Database: ${geo.local_database_release}` : 'Database not loaded';
      this._q('geoStatus').textContent =
        `${geo.provider === 'nabu_casa' ? 'Nabu Casa' : 'Home Assistant client IP'} · ${geo.current_country || 'Country unknown'} · ${release}`;
      this._q('geoWarning').hidden = !geo.local_database_error;
      this._q('geoWarning').textContent = geo.local_database_error
        ? `GeoIP database update failed — still using ${geo.local_database_release || 'the last valid database'}.`
        : '';
      const attempt = geo.last_update_attempt ? new Date(geo.last_update_attempt).toLocaleString() : 'Never';
      const success = geo.last_successful_update ? new Date(geo.last_successful_update).toLocaleString() : 'Never';
      this._q('geoTimes').textContent = `Last attempt: ${attempt} · Last success: ${success}`;
    } catch (err) {
      this._q('settingsMessage').className = 'notice notice-error';
      this._q('settingsMessage').textContent = err?.message || 'Unable to load settings.';
    }
  }

  _selected(id) {
    return Array.from(this._q(id).selectedOptions).map((o) => o.value);
  }

  async _saveSettings() {
    const button = this._q('saveSettings');
    const message = this._q('settingsMessage');
    button.disabled = true;
    message.className = 'notice notice-neutral';
    message.textContent = 'Saving…';
    try {
      await this._api('POST', 'secure_qr_login/admin/settings', {
        enable_window_seconds: Number(this._q('settingWindow').value),
        qr_lifetime_seconds: Number(this._q('settingQr').value),
        max_pending_sessions: Number(this._q('settingPending').value),
        history_limit: Number(this._q('settingHistory').value),
        allowed_user_ids: this._selected('settingUsers'),
        notify_services: this._selected('settingNotify'),
        notify_on_approved: this._q('settingNotifyApproved').checked,
        notify_on_denied: this._q('settingNotifyDenied').checked,
        allowed_countries: this._selected('settingCountries'),
        allow_private_networks: this._q('settingPrivate').checked
      });
      message.className = 'notice ok';
      message.textContent = 'Settings saved.';
      await this._refreshAll();
    } catch (err) {
      message.className = 'notice notice-error';
      message.textContent = err?.message || 'Unable to save settings.';
    } finally {
      button.disabled = false;
    }
  }

  async _setEnabled(value) {
    try {
      await this._api('POST', 'secure_qr_login/admin/window', {enabled: value});
      await this._refreshState();
    } catch (err) {
      alert(err?.message || 'Unable to change the QR login window.');
    }
  }

  async _updateGeoIP() {
    const button = this._q('geoUpdate');
    button.disabled = true;
    button.textContent = 'Checking…';
    try {
      await this._api('POST', 'secure_qr_login/admin/geoip-update', {});
      await Promise.all([this._refreshState(), this._loadSettings()]);
    } catch (err) {
      alert(err?.message || 'GeoIP update failed.');
      await this._loadSettings();
    } finally {
      button.disabled = false;
      button.textContent = 'Check for GeoIP update';
    }
  }

  _renderActive(items) {
    const body = this._q('active');
    body.replaceChildren();
    this._q('activeEmpty').hidden = items.length !== 0;
    this._q('revokeAll').disabled = items.length === 0;

    for (const item of items) {
      const row = document.createElement('tr');
      for (const value of [
        item.user_name || '—',
        item.client_ip || '—',
        item.user_agent || '—',
        item.delivered_at ? new Date(item.delivered_at * 1000).toLocaleString() : '—'
      ]) {
        const td = document.createElement('td');
        td.textContent = value;
        row.append(td);
      }
      const action = document.createElement('td');
      const button = document.createElement('button');
      button.className = 'btn btn-danger-outline';
      button.textContent = 'Revoke';
      button.addEventListener('click', async () => {
        if (!confirm('Revoke this QR login?')) return;
        try {
          await this._api('POST', 'secure_qr_login/admin/revoke', {login_id: item.login_id});
          await this._refreshState();
        } catch (err) {
          alert(err?.message || 'Unable to revoke login.');
        }
      });
      action.append(button);
      row.append(action);
      body.append(row);
    }
  }

  _renderHistory(items) {
    const body = this._q('history');
    body.replaceChildren();
    this._q('historyEmpty').hidden = items.length !== 0;
    this._q('clearHistory').disabled = items.length === 0;
    for (const item of items) {
      const row = document.createElement('tr');
      for (const value of [
        item.at ? new Date(item.at * 1000).toLocaleString() : '—',
        item.event || '—',
        item.user_name || '—',
        item.client_ip || '—',
        item.detail || '—'
      ]) {
        const td = document.createElement('td');
        td.textContent = value;
        row.append(td);
      }
      body.append(row);
    }
  }

  async _revokeAll() {
    if (!confirm('Revoke every QR-created login?')) return;
    try {
      await this._api('POST', 'secure_qr_login/admin/revoke-all', {});
      await this._refreshState();
    } catch (err) {
      alert(err?.message || 'Unable to revoke all logins.');
    }
  }

  async _clearHistory() {
    if (!confirm('Clear the Secure QR Login security history?')) return;
    try {
      await this._api('POST', 'secure_qr_login/admin/clear-history', {});
      await this._refreshState();
    } catch (err) {
      alert(err?.message || 'Unable to clear history.');
    }
  }
}

if (!customElements.get('secure-qr-login-panel')) {
  customElements.define('secure-qr-login-panel', SecureQrLoginPanel);
}
