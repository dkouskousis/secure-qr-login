"""Static UI regression tests for the tabbed admin panel."""

from pathlib import Path


ROOT = Path(__file__).parents[1]
ADMIN_HTML = ROOT / "custom_components/secure_qr_login/www/admin.html"
ADMIN_JS = ROOT / "custom_components/secure_qr_login/www/static/admin.js"
APP_CSS = ROOT / "custom_components/secure_qr_login/www/static/app.css"


def test_admin_panel_has_all_primary_tabs() -> None:
    html = ADMIN_HTML.read_text(encoding="utf-8")

    for name in ("overview", "settings", "logins", "history"):
        assert f'data-tab="{name}"' in html
        assert f'data-panel="{name}"' in html


def test_admin_panel_keeps_required_runtime_ids() -> None:
    html = ADMIN_HTML.read_text(encoding="utf-8")

    required_ids = {
        "status",
        "countdown",
        "enable",
        "disable",
        "window",
        "rotation",
        "pending",
        "activeCount",
        "settingWindow",
        "settingQr",
        "settingPending",
        "settingHistory",
        "settingUsers",
        "settingNotify",
        "settingNotifyApproved",
        "settingNotifyDenied",
        "settingCountries",
        "settingPrivate",
        "geoUpdate",
        "saveSettings",
        "revokeAll",
        "clearHistory",
        "active",
        "history",
    }

    for element_id in required_ids:
        assert f'id="{element_id}"' in html


def test_tab_state_is_persisted_client_side() -> None:
    js = ADMIN_JS.read_text(encoding="utf-8")

    assert "secureQrLoginAdminTab" in js
    assert "activateTab" in js
    assert "restoreTab" in js


def test_admin_css_contains_mobile_and_tab_layouts() -> None:
    css = APP_CSS.read_text(encoding="utf-8")

    assert ".tabs" in css
    assert ".tab-panel" in css
    assert ".sticky-save" in css
    assert "@media(max-width:680px)" in css


def test_qr_entry_redirects_existing_authenticated_session() -> None:
    """QR entry verifies an existing HA session before starting a new flow."""
    js = (
        ROOT
        / "custom_components/secure_qr_login/www/static/start.js"
    ).read_text(encoding="utf-8")

    assert "alreadyAuthenticated" in js
    assert "tokenIsValid" in js
    assert "refreshBrowserToken" in js
    assert "requestExternalAuth" in js
    assert "redirectToDestination" in js
    assert "/api/secure_qr_login/destination" in js
    assert "safeRedirectPath" in js

    # The authentication check must happen before beginLogin() is called.
    # Keep this syntax-agnostic because start.js intentionally uses legacy
    # callback-style JavaScript for Samsung/Tizen browser compatibility.
    init_start = js.index("function init()")
    init_end = js.index("\n  init();", init_start)
    init_block = js[init_start:init_end]

    assert "alreadyAuthenticated(function (authenticated)" in init_block
    assert "if (authenticated)" in init_block
    assert init_block.index(
        "alreadyAuthenticated(function (authenticated)"
    ) < init_block.index("beginLogin();")

    # beginLogin() is the only place that creates the new QR session.
    assert "postJson('/api/secure_qr_login/start'" in js
