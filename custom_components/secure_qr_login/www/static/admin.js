(() => {
  const status = document.getElementById('status');
  const countdown = document.getElementById('countdown');
  const audit = document.getElementById('audit');
  let token = null;

  try { token = JSON.parse(localStorage.getItem('hassTokens'))?.access_token || null; } catch {}
  const headers = () => token ? {Authorization:`Bearer ${token}`} : {};

  async function state() {
    const r = await fetch('/api/secure_qr_login/admin/state',{headers:headers(),cache:'no-store'});
    if (!r.ok) { status.textContent='Authentication required'; return; }
    const d = await r.json();
    status.textContent = d.enabled ? 'ENABLED' : 'DISABLED';
    status.className = 'status ' + (d.enabled ? '' : 'danger');
    countdown.textContent = d.enabled ? `${d.remaining_seconds}s remaining · ${d.pending_sessions} pending session(s)` : 'Off by default. No new QR sessions can be created.';
    audit.textContent = (d.audit || []).map(x => `${new Date(x.at*1000).toLocaleString()}  ${x.event}  ${x.user_name || ''}  ${x.client_ip || ''}`).join('\n') || 'No events yet.';
  }

  async function setEnabled(enabled) {
    await fetch('/api/secure_qr_login/admin/window',{
      method:'POST',headers:{...headers(),'Content-Type':'application/json'},body:JSON.stringify({enabled})
    });
    await state();
  }

  document.getElementById('enable').addEventListener('click',()=>setEnabled(true));
  document.getElementById('disable').addEventListener('click',()=>setEnabled(false));
  state(); setInterval(state,1000);
})();
