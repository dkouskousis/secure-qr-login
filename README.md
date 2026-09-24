# Secure QR Login for Home Assistant

A security-focused Home Assistant custom integration that lets a new browser sign in by scanning a short-lived QR code with a Home Assistant session that is already authenticated.

## Security model

Secure QR Login is **disabled by default**. An administrator opens a login window for exactly **3 minutes**. At the end of that window, the feature disables itself and every pending or unconsumed session is invalidated.

Each login request uses three independent values:

1. **Session ID** — public request identifier.
2. **Device secret** — 256-bit secret delivered only to the requesting browser. It is never placed in the QR code and only its SHA-256 digest is retained server-side.
3. **QR token** — independent short-lived value rotated every **10 seconds** and embedded only in the current QR code.

The QR token allows an authenticated Home Assistant user to approve or deny a request. It **cannot retrieve credentials**. Credentials are delivered only once to the originating browser after it proves possession of the device secret.

### Additional hardening

- QR Login starts OFF after Home Assistant restart.
- Enabling is limited to administrators.
- Public session creation and status polling are rate-limited.
- QR tokens expire after 10 seconds and are invalidated immediately after approval/denial.
- Access and refresh tokens never appear in a URL.
- Sensitive HTTP responses use `Cache-Control: no-store`.
- Approval pages use `Referrer-Policy: no-referrer` and a restrictive CSP.
- A user can approve a login only for **their own Home Assistant account**. There is no username mapping or cross-account token minting.
- An issued refresh token is revoked if the session expires or the security window closes before credentials are consumed.
- Pending sessions are memory-only and disappear on restart.
- No remote JavaScript is loaded by the login pages.

## Why there is no reCAPTCHA

The feature is externally unavailable while disabled, is only open for a three-minute administrator-controlled window, and has both per-IP and global rate limiting. Adding reCAPTCHA would introduce an external Google dependency and additional browser data sharing without materially improving the core authentication boundary.

## Installation

1. Add this repository to HACS as a custom **Integration** repository.
2. Install **Secure QR Login**.
3. Restart Home Assistant.
4. Go to **Settings → Devices & services → Add integration → Secure QR Login**.
5. Open the **QR Login** sidebar panel.

## Usage

1. In the QR Login panel, press **Enable for 3 minutes**.
2. On the device that needs to sign in, open:

   `/secure_qr_login/start`

3. Scan the displayed QR code with a phone/browser that is already signed in to the same Home Assistant instance.
4. Verify the IP/browser information and press **Approve**.
5. The requesting browser receives its Home Assistant credentials and opens the frontend.

The QR code rotates every 10 seconds. A screenshot of an older QR becomes unusable once that token expires.

## Home Assistant entity

The integration also exposes `switch.secure_qr_login`. Turning it on starts a fresh three-minute window and turning it off immediately closes the window and purges pending sessions. The entity rejects non-administrator service calls.

## Reverse proxies / Cloudflare

Use a correctly configured Home Assistant reverse proxy and HTTPS. The integration derives its client origin only from same-host requests. Home Assistant's normal trusted proxy configuration remains your responsibility.

## Dependency

QR SVG generation uses `segno==1.6.6`, pinned in `manifest.json`.

## Security notes

This integration creates normal Home Assistant refresh tokens through Home Assistant's own authentication manager. Installing any custom integration that can mint authentication tokens should be treated as security-sensitive. Review updates before installing them and keep Home Assistant itself current.

## License

MIT
