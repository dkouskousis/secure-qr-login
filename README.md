# Secure QR Login for Home Assistant

Secure QR Login is a security-focused Home Assistant custom integration that lets a new browser sign in by scanning a short-lived QR code with a Home Assistant session that is already authenticated.

## Security model

The integration is **OFF by default**. An administrator opens a short login window; the secure default is **180 seconds**.

Each request uses three independent values:

1. **Session ID** — public request identifier.
2. **Device secret** — a high-entropy secret known only to the browser requesting login. It never appears in the QR code; only its SHA-256 digest is retained server-side.
3. **QR token** — an independent bearer value rotated every **10 seconds** by default and embedded only in the current QR.

The QR token can approve or deny a request, but it cannot retrieve credentials. Home Assistant credentials are delivered exactly once and only to the browser that proves possession of the separate device secret.

## Security controls

- OFF by default after Home Assistant starts.
- Administrator-only temporary enable/disable.
- Login window configurable only from 60–300 seconds.
- QR rotation configurable only from 5–30 seconds.
- Per-IP and global request rate limits.
- Hard limit of 1–5 simultaneous pending requests.
- Strict same-origin policy for all state-changing POST endpoints.
- Requests without an explicit same-origin `Origin` header are rejected.
- Five invalid device-secret attempts permanently destroy that login request.
- Old QR tokens become invalid immediately after rotation.
- QR token is invalidated immediately after approve/deny.
- Access and refresh tokens never appear in URLs.
- Credential delivery is single-use.
- Pending and undelivered sessions are invalidated when the security window closes.
- Undelivered provisional refresh tokens are revoked after restart.
- No external JavaScript or CSS dependencies.
- CSP does not use `unsafe-inline`; CSS and JavaScript are served from local static files only.
- Sensitive responses use `Cache-Control: no-store`.
- Approval pages use `Referrer-Policy: no-referrer`.
- Cross-account token minting is not supported.

## Companion App

The approval page supports the Home Assistant Companion App:

- `homeassistant://navigate/...` deep-link handoff.
- Android `externalAppV2` bridge.
- Android legacy `externalApp` fallback.
- iOS `webkit.messageHandlers.getExternalAuth`.
- The integration requests only a temporary access token from the app.
- The Companion App refresh token is never exposed to or stored by Secure QR Login.
- Browser OAuth remains available as a fallback.

## User allowlist

An optional allowlist controls which Home Assistant users may approve QR login.

If the allowlist is empty, any active non-system HA user may approve a login **only for their own account**.

If configured, only selected users may approve.

## Notifications

One or more Home Assistant `notify.*` services can be selected, including Companion App services.

Notifications may be enabled independently for:

- approved logins
- denied logins

Notifications contain no authentication secrets.

## Active QR logins

The admin panel shows active logins created through this integration:

- account
- source IP
- browser/user agent
- sign-in time

An administrator can:

- revoke one QR-created login
- **revoke all QR-created logins**
- close the current login window
- cancel all pending/provisional requests

Revoke actions use Home Assistant's own refresh-token revocation mechanism.

The integration stores only Home Assistant's non-secret internal refresh-token ID for later revocation; it does not persist the actual refresh token.

## Security history

Security history survives Home Assistant restarts and includes events such as:

- login window enabled/disabled
- session started
- approved / denied
- credentials delivered
- session locked after invalid secrets
- token revoked
- all QR-created tokens revoked
- expired request
- externally revoked token detected
- orphaned undelivered token automatically revoked

The admin panel also includes **Clear history**. Clearing history does not change active logins.

## Diagnostics

Home Assistant config-entry diagnostics are supported.

Diagnostics deliberately exclude:

- IP addresses
- user names and user IDs
- browser/user-agent strings
- session IDs
- refresh-token IDs
- access/refresh tokens
- device secrets
- QR tokens

Only operational counts, safe settings, version information and event-type counts are exported.

## Admin panel

The sidebar admin panel displays:

- current enabled/disabled state
- live server-synchronised countdown
- configured login-window duration
- QR rotation interval
- pending session count / limit
- active QR-created logins
- persistent security history
- integration version/build

The countdown updates locally for a smooth display but re-synchronises with the server every few seconds. The server remains authoritative.

## Automated tests and releases

GitHub Actions runs on every push and pull request.

The test suite covers:

- security primitives
- secret separation
- QR expiry and replay protection
- strict Origin enforcement
- rate limits
- allowlist behavior
- safe configuration bounds
- persistent metadata
- full HTTP login flow
- one-time credential delivery
- repeated invalid device-secret lockout
- history clearing
- bulk revocation
- Python compilation
- JSON validation
- JavaScript syntax

A GitHub release is created automatically only after the test job passes. Stale CI runs are prevented from publishing a release if `main` has moved forward.

## Configuration

All runtime/security settings are managed directly from the **QR Login** admin panel. The legacy Home Assistant options flow is no longer used, so there is a single configuration surface.

Available settings:

- Login window duration
- QR rotation interval
- Maximum pending sessions
- History size
- User allowlist
- Notification targets
- Notify on approved
- Notify on denied
- Allowed countries
- Allow private/local network clients without GeoIP

Saving settings closes any currently open QR-login window and cancels pending requests. Already-delivered QR-created logins are not revoked.

## Country restriction / GeoIP

Country restriction is optional and is implemented as an additional policy layer using Cloudflare's `CF-IPCountry` request header.

When an allowed-country list is configured:

- the requesting browser must come from one of the configured two-letter country codes;
- `/start`, `/qr`, and `/status` are all country-checked;
- public requests fail closed if the expected Cloudflare headers are missing;
- local/private clients may optionally bypass GeoIP because local traffic does not normally pass through Cloudflare.

Cloudflare IP Geolocation (or the Add visitor location headers Managed Transform) must be enabled so the origin receives `CF-IPCountry`.

The implementation also requires `CF-Ray` and `CF-Connecting-IP` before trusting `CF-IPCountry`. If Cloudflare headers are present, they take precedence over `request.remote`; this prevents a private cloudflared/reverse-proxy address from accidentally bypassing the country policy.

GeoIP is not an authentication factor and should not be treated as exact location proof. It remains secondary to the integration's QR, device-secret, admin-window and Home Assistant authentication controls.

For the country header to be meaningful, the public Home Assistant origin should not also be directly exposed to the Internet outside Cloudflare/Tunnel, because HTTP request headers are not cryptographic proof on a directly reachable origin.

## Installation

1. Add this repository to HACS as a custom **Integration** repository.
2. Install **Secure QR Login**.
3. Restart Home Assistant.
4. Go to **Settings → Devices & services → Add integration → Secure QR Login**.
5. Open the **QR Login** sidebar panel.

## Usage

1. In the QR Login panel, press **Enable temporarily**.
2. On the new device open:

   `/secure_qr_login/start`

3. Scan the rotating QR code.
4. Open the approval page in the Home Assistant Companion App or an authenticated browser.
5. Verify the IP/browser details and press **Approve**.
6. The requesting browser receives the credentials once and opens Home Assistant.
7. The new QR-created login appears under **Active QR logins** and can be revoked later.

## Reverse proxies / Cloudflare

Use HTTPS and a correctly configured Home Assistant reverse proxy. Home Assistant's normal trusted-proxy configuration remains your responsibility.

The strict same-origin check compares the browser `Origin` to the host seen by Home Assistant, so proxy host/scheme handling must be configured correctly.

## Why there is no reCAPTCHA

The feature is unavailable while disabled and combines:

- short administrator-controlled windows
- rotating QR tokens
- independent device secrets
- strict same-origin POST enforcement
- per-IP/global rate limits
- hard pending-session limits
- repeated-secret-failure lockout
- optional Cloudflare-backed country restriction

Adding reCAPTCHA would introduce an external dependency and additional browser data sharing without strengthening the core authentication boundary.

## Dependency

QR SVG generation uses `segno==1.6.6`, pinned in `manifest.json`.

## Version

Current integration version: **1.4.0**

## License

MIT
