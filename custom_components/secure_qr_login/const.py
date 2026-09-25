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
DEFAULT_ALLOW_PRIVATE_NETWORKS = False

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

# ISO-3166-1 alpha-2 country codes accepted by the country allowlist.
ISO_COUNTRY_CODES = frozenset(
    """
    AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ
    BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
    CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ
    DE DJ DK DM DO DZ
    EC EE EG EH ER ES ET
    FI FJ FK FM FO FR
    GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY
    HK HM HN HR HT HU
    ID IE IL IM IN IO IQ IR IS IT
    JE JM JO JP
    KE KG KH KI KM KN KP KR KW KY KZ
    LA LB LC LI LK LR LS LT LU LV LY
    MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ
    NA NC NE NF NG NI NL NO NP NR NU NZ
    OM
    PA PE PF PG PH PK PL PM PN PR PS PT PW PY
    QA
    RE RO RS RU RW
    SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ
    TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ
    UA UG UM US UY UZ
    VA VC VE VG VI VN VU
    WF WS
    YE YT
    ZA ZM ZW
    """.split()
)
