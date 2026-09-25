# Secure QR Login for Home Assistant

A security-focused Home Assistant custom integration that lets a new browser sign in by scanning a short-lived QR code with a Home Assistant session that is already authenticated.

## Security model

Secure QR Login is **disabled by default**. An administrator opens a short login window; the secure default is **3 minutes**. At the end of that window the feature disables itself and every pending or undelivered login is invalidated.

Each login request uses three independent values:

1. **Session ID** — public request identifier.
2. **Device secret** — 256-bit secret delivered only to the requesting browser. It never appears in the QR code and only its SHA-256 digest is retained server-side.
3. **QR token** — independent short-lived value rotated every **10 seconds** by default and embedded only in the current QR code.

The QR token can approve or deny a request. It **cannot retrieve credentials**. Credentials are delivered exactly once to the originating browser only after it proves possession of the separate device secret.

## Features

### Temporary security window
- OFF by default after Home Assistant starts.
- Administrator-only enable/disable control.
- Default duration: 180 seconds.
- Configurable only within a conservative 60–300 second range.
- Closing the window immediately invalidates all pending requests and revokes any token created but not yet delivered.

### Rotating QR
- Default rotation: every 10 seconds.
- Configurable from 5–30 seconds.
- Expired QR tokens cannot approve a session.
- Taking a screenshot of an old QR does not provide a reusable login credential.

### User allowlist
- Optional allowlist of Home Assistant users.
- If empty, all active non-system HA users may approve login **only for their own account**.
- If configured, only selected users may approve.
- Cross-account token issuance is not supported.

### Pending-session limit
- Default maximum: 3 simultaneous pending requests.
- Configurable from 1–5.
- This is in addition to per-IP and global rate limiting.

### Phone notifications
Configure one or more Home Assistant `notify.*` services, including Companion App `notify.mobile_app_*` services.

Notifications can be enabled independently for:
- approved QR logins
- denied QR logins

Notifications contain no session token, QR token, device secret, access token or refresh token.

### Active QR logins and manual revoke
The admin panel lists active sessions created through Secure QR Login with:
- account
- source IP
- browser/user agent
- sign-in time

An administrator can press **Revoke**. The integration looks up the corresponding Home Assistant refresh token by its internal token ID and removes it through Home Assistant's authentication manager.

The raw refresh-token secret is never stored by the integration.

### Persistent security history
Security events survive Home Assistant restarts. The history includes events such as:
- login window enabled/disabled
- session started
- approved / denied
- credentials delivered
- token revoked
- expired request
- externally revoked token detected
- orphaned undelivered token automatically revoked

The history length is configurable from 20–200 records.

### Restart-safe provisional token handling
After approval, Home Assistant creates a refresh token before the requesting browser receives it. Secure QR Login persists only the **non-secret internal refresh-token ID** before reporting approval success.

If Home Assistant restarts during that small interval, the integration detects the undelivered token during startup and automatically revokes it. This prevents an orphaned valid token from surviving a restart.

### Home Assistant diagnostics
The integration supports HA config-entry diagnostics.

Diagnostics deliberately exclude:
- IP addresses
- browser/user-agent values
- user IDs
- session IDs
- refresh-token IDs
- access/refresh tokens
- device secrets
- QR tokens

Only operational counts, version information, safe settings and event-type counts are exported.

## Configuration

Open:

**Settings → Devices & services → Secure QR Login → Configure**

Available settings:

- Login window duration
- QR rotation interval
- Maximum pending sessions
- History size
- User allowlist
- Notification targets
- Notify on approved
- Notify on denied

Security-sensitive numeric settings have enforced minimum/maximum ranges rather than accepting arbitrary values.

## Installation

1. Add this repository to HACS as a custom **Integration** repository.
2. Install **Secure QR Login**.
3. Restart Home Assistant.
4. Go to **Settings → Devices & services → Add integration → Secure QR Login**.
5. Open the **QR Login** sidebar panel.

## Usage

1. In the QR Login panel, press **Enable temporarily**.
2. On the device that needs to sign in, open:

   `/secure_qr_login/start`

3. Scan the displayed QR code with a phone/browser that is already signed in to the same Home Assistant instance.
4. Verify the IP/browser information and press **Approve**.
5. The requesting browser receives its Home Assistant credentials and opens the frontend.
6. The new QR-created login is now visible under **Active QR logins**, where an administrator can revoke it.

## Home Assistant entity

The integration exposes `switch.secure_qr_login`.

Turning it on opens a fresh bounded login window. Turning it off immediately closes the window and invalidates in-flight requests. The entity rejects non-administrator service calls.

Its attributes expose:
- remaining seconds
- configured window duration
- QR rotation interval
- pending requests
- maximum pending requests

## Stored data

The integration's persistent storage contains only security metadata required for history and revocation. It does **not** store authentication credentials.

For active QR logins it stores the Home Assistant refresh token's internal ID, which is used only to find and revoke that token later. The actual refresh-token secret is not persisted.

## Reverse proxies / Cloudflare

Use a correctly configured Home Assistant reverse proxy and HTTPS. Home Assistant's standard trusted-proxy configuration remains your responsibility.

Secure QR Login also performs same-origin checks for browser POST requests and never puts access/refresh tokens in URLs.

## Why there is no reCAPTCHA

The feature is externally unavailable while disabled, is open only for a short administrator-controlled window, has a pending-session hard cap, per-IP/global rate limiting, rotating QR tokens and a device-bound credential exchange.

Adding reCAPTCHA would introduce an external dependency and additional browser data sharing without strengthening the core authentication boundary.

## Dependency

QR SVG generation uses `segno==1.6.6`, pinned in `manifest.json`.

## Version

Current integration version: **1.1.0**

## License

MIT
