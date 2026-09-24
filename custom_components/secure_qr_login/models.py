"""In-memory models for Secure QR Login."""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any

from .security import digest_matches


@dataclass(slots=True)
class LoginSession:
    """One login request created by the target browser."""

    session_id: str
    device_secret_digest: str
    client_ip: str
    user_agent: str
    client_id: str
    created_at: float
    expires_at: float

    status: str = "pending"
    qr_token_digest: str = ""
    qr_expires_at: float = 0.0
    approved_user_id: str = ""
    approved_user_name: str = ""
    approved_at: float = 0.0
    refresh_token: Any | None = None
    access_token: str | None = None
    token_expires_in: int = 0
    consumed: bool = False

    def expired(self, now: float | None = None) -> bool:
        return (now or time.time()) >= self.expires_at

    def qr_valid(self, token: str, now: float | None = None) -> bool:
        """Validate the currently displayed QR token."""
        current = now or time.time()
        return (
            bool(self.qr_token_digest)
            and current < self.qr_expires_at
            and digest_matches(token, self.qr_token_digest)
        )

    def device_secret_valid(self, secret: str) -> bool:
        return digest_matches(secret, self.device_secret_digest)

    def public_status(self) -> dict[str, Any]:
        """Return non-sensitive status information only."""
        return {
            "status": self.status,
            "expires_in": max(0, int(self.expires_at - time.time())),
        }

    def approval_details(self) -> dict[str, Any]:
        """Return details visible to an authenticated approver."""
        return {
            "status": self.status,
            "client_ip": self.client_ip,
            "user_agent": self.user_agent,
            "expires_in": max(0, int(self.expires_at - time.time())),
        }


@dataclass(slots=True)
class AuditEntry:
    """Token-free audit entry kept in memory."""

    event: str
    session_id: str
    at: float = field(default_factory=time.time)
    client_ip: str = ""
    user_id: str = ""
    user_name: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "event": self.event,
            "session_id": self.session_id,
            "at": self.at,
            "client_ip": self.client_ip,
            "user_id": self.user_id,
            "user_name": self.user_name,
        }
