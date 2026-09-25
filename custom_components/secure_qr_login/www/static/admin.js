(() => {
  const status = document.getElementById('status');
  const countdown = document.getElementById('countdown');
  const activeBody = document.getElementById('active');
  const historyBody = document.getElementById('history');
  const activeEmpty = document.getElementById('activeEmpty');
  const historyEmpty = document.getElementById('historyEmpty');
  const revokeAllButton = document.getElementById('revokeAll');
  const clearHistoryButton = document.getElementById('clearHistory');

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

  function renderCountdown() {
    if (!enabled) {
      countdown.textContent = 'Off by default. No new QR sessions can be created.';
      return;
    }

    const elapsed = Math.floor((performance.now() - lastSyncedAt) / 1000);
    const left = Math.max(0, remainingSeconds - elapsed);
    const minutes = Math.floor(left / 60);
    const seconds = left % 60;

    countdown.textContent = `${minutes}:${String(seconds).padStart(2, '0')} remaining`;

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
        textCell(
          item.delivered_at
            ? new Date(item.delivered_at * 1000).toLocaleString()
            : '—'
        )
      );

      const action = document.createElement('td');
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
    document.getElementById('activeCount').textContent =
      String((d.active || []).length);
    document.getElementById('version').textContent = d.version || '—';
    document.getElementById('build').textContent = d.build || '—';

    renderActive(d.active || []);
    renderHistory(d.history || []);
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
    const r = await fetch('/api/secure_qr_login/admin/revoke-all', {
      method: 'POST',
      headers: headers({'Content-Type': 'application/json'}),
      body: '{}',
      cache: 'no-store'
    });

    if (!r.ok) {
      alert('Unable to revoke all QR logins.');
    }
    await state();
  }

  async function clearHistory() {
    if (!confirm('Clear the Secure QR Login security history? Active logins will not be changed.')) {
      return;
    }

    clearHistoryButton.disabled = true;
    const r = await fetch('/api/secure_qr_login/admin/clear-history', {
      method: 'POST',
      headers: headers({'Content-Type': 'application/json'}),
      body: '{}',
      cache: 'no-store'
    });

    if (!r.ok) {
      alert('Unable to clear history.');
    }
    await state();
  }

  document.getElementById('enable').addEventListener('click', () => setEnabled(true));
  document.getElementById('disable').addEventListener('click', () => setEnabled(false));
  revokeAllButton.addEventListener('click', revokeAll);
  clearHistoryButton.addEventListener('click', clearHistory);

  state();
  setInterval(renderCountdown, 250);
  setInterval(state, 5000);
})();
