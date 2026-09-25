"""Repository consistency checks."""

import json
from pathlib import Path

from custom_components.secure_qr_login.const import VERSION


ROOT = Path(__file__).parents[1]


def test_manifest_version_matches_python_constant() -> None:
    manifest = json.loads(
        (ROOT / "custom_components/secure_qr_login/manifest.json").read_text()
    )
    assert manifest["version"] == VERSION


def test_hacs_metadata_is_valid_json() -> None:
    data = json.loads((ROOT / "hacs.json").read_text())
    assert data["name"] == "Secure QR Login"
