"""Constants and security bounds for Secure QR Login."""

DOMAIN = "secure_qr_login"
NAME = "Secure QR Login"
VERSION = "1.4.0"

PLATFORMS = ["switch"]

# Config-entry option keys. They are persisted by Home Assistant, but from
# v1.4.0 onward they are managed from the integration's own admin panel.
CONF_ENABLE_WINDOW_SECONDS = "enable_window_seconds"
CONF_QR_LIFETIME_SECONDS = "qr_lifetime_seconds"
CONF_MAX_PENDING_SESSIONS = "max_pending_sessions"
CONF_HISTORY_LIMIT = "history_limit"
CONF_ALLOWED_USER_IDS = "allowed_user_ids"
CONF_NOTIFY_SERVICES = "notify_services"
CONF_NOTIFY_ON_APPROVED = "notify_on_approved"
CONF_NOTIFY_ON_DENIED = "notify_on_denied"
CONF_ALLOWED_COUNTRIES = "allowed_countries"
CONF_ALLOW_PRIVATE_NETWORKS = "allow_private_networks"

# Secure defaults.
DEFAULT_ENABLE_WINDOW_SECONDS = 180
DEFAULT_QR_LIFETIME_SECONDS = 10
DEFAULT_MAX_PENDING_SESSIONS = 3
DEFAULT_HISTORY_LIMIT = 100
DEFAULT_ALLOWED_USER_IDS: list[str] = []
DEFAULT_NOTIFY_SERVICES: list[str] = []
DEFAULT_NOTIFY_ON_APPROVED = True
DEFAULT_NOTIFY_ON_DENIED = True
DEFAULT_ALLOWED_COUNTRIES: list[str] = []
DEFAULT_ALLOW_PRIVATE_NETWORKS = True

# Deliberately conservative configurable bounds.
MIN_ENABLE_WINDOW_SECONDS = 60
MAX_ENABLE_WINDOW_SECONDS = 300
MIN_QR_LIFETIME_SECONDS = 5
MAX_QR_LIFETIME_SECONDS = 30
MIN_MAX_PENDING_SESSIONS = 1
MAX_MAX_PENDING_SESSIONS = 5
MIN_HISTORY_LIMIT = 20
MAX_HISTORY_LIMIT = 200

# A stolen/guessed session id still cannot retrieve credentials without the
# device secret. Repeated failures destroy the session to limit online probing.
MAX_DEVICE_SECRET_FAILURES = 5

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

STORAGE_VERSION = 1
STORAGE_KEY = f"{DOMAIN}.security"
