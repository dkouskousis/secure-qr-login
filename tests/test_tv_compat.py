"""Static compatibility checks for the TV QR login page."""

from pathlib import Path

START_JS = Path("custom_components/secure_qr_login/www/static/start.js")


def test_tv_start_page_avoids_modern_browser_only_syntax() -> None:
    source = START_JS.read_text(encoding="utf-8")

    forbidden = (
        "=>",
        "async ",
        "await ",
        "?.",
        "replaceChildren(",
        "URL.createObjectURL(",
        ".animate(",
        "fetch(",
    )

    for token in forbidden:
        assert token not in source, f"TV start.js contains incompatible token: {token}"
