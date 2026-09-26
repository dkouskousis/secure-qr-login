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
