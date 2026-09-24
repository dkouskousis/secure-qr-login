"""Constants for Secure QR Login."""

DOMAIN = "secure_qr_login"
NAME = "Secure QR Login"
VERSION = "1.0.0"

PLATFORMS = ["switch"]

# The feature is deliberately disabled at startup and may only be enabled
# temporarily. These defaults are security-sensitive and intentionally fixed.
ENABLE_WINDOW_SECONDS = 180
SESSION_LIFETIME_SECONDS = 180
QR_LIFETIME_SECONDS = 10
ACCESS_TOKEN_DEFAULT_SECONDS = 1800

START_LIMIT_PER_IP = 6
START_LIMIT_WINDOW_SECONDS = 60
STATUS_LIMIT_PER_IP = 120
STATUS_LIMIT_WINDOW_SECONDS = 60
GLOBAL_START_LIMIT = 30
GLOBAL_START_WINDOW_SECONDS = 60

SESSION_ID_BYTES = 24
DEVICE_SECRET_BYTES = 32
QR_TOKEN_BYTES = 24

CLIENT_NAME = "Secure QR Login"

PANEL_URL_PATH = "secure-qr-login"
