"""Models for Secure QR Login.

Authentication credentials are intentionally never serialised by these models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any

from .security import digest_matches


@dataclass(slots=True)
class LoginSession:
    """One in-memory login request created by the target browser."""

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
        current = now or time.time()
        return (
            bool(self.qr_token_digest)
            and current < self.qr_expires_at
            and digest_matches(token, self.qr_token_digest)
        )

    def device_secret_valid(self, secret: str) -> bool:
        return digest_matches(secret, self.device_secret_digest)

    def public_status(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "expires_in": max(0, int(self.expires_at - time.time())),
        }

    def approval_details(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "client_ip": self.client_ip,
            "user_agent": self.user_agent,
            "expires_in": max(0, int(self.expires_at - time.time())),
        }


@dataclass(slots=True)
class ActiveLogin:
    """Persisted metadata for a QR-created HA refresh token.

    refresh_token_id is an internal identifier, not the refresh-token secret.
    It is persisted solely so an administrator can revoke the HA token later.
    """

    login_id: str
    refresh_token_id: str
    user_id: str
    user_name: str
    client_ip: str
    user_agent: str
    approved_at: float
    delivered: bool = False
    delivered_at: float = 0.0

    def as_storage(self) -> dict[str, Any]:
        return {
            "login_id": self.login_id,
            "refresh_token_id": self.refresh_token_id,
            "user_id": self.user_id,
            "user_name": self.user_name,
            "client_ip": self.client_ip,
            "user_agent": self.user_agent,
            "approved_at": self.approved_at,
            "delivered": self.delivered,
            "delivered_at": self.delivered_at,
        }

    @classmethod
    def from_storage(cls, data: dict[str, Any]) -> "ActiveLogin":
        return cls(
            login_id=str(data.get("login_id", "")),
            refresh_token_id=str(data.get("refresh_token_id", "")),
            user_id=str(data.get("user_id", "")),
            user_name=str(data.get("user_name", "")),
            client_ip=str(data.get("client_ip", "")),
            user_agent=str(data.get("user_agent", "")),
            approved_at=float(data.get("approved_at", 0)),
            delivered=bool(data.get("delivered", False)),
            delivered_at=float(data.get("delivered_at", 0)),
        )

    def as_public(self) -> dict[str, Any]:
        return {
            "login_id": self.login_id,
            "user_id": self.user_id,
            "user_name": self.user_name,
            "client_ip": self.client_ip,
            "user_agent": self.user_agent,
            "approved_at": self.approved_at,
            "delivered_at": self.delivered_at,
        }


@dataclass(slots=True)
class AuditEntry:
    """Credential-free audit/history entry."""

    event: str
    session_id: str
    at: float = field(default_factory=time.time)
    client_ip: str = ""
    user_id: str = ""
    user_name: str = ""
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "event": self.event,
            "session_id": self.session_id,
            "at": self.at,
            "client_ip": self.client_ip,
            "user_id": self.user_id,
            "user_name": self.user_name,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditEntry":
        return cls(
            event=str(data.get("event", "")),
            session_id=str(data.get("session_id", "")),
            at=float(data.get("at", 0)),
            client_ip=str(data.get("client_ip", "")),
            user_id=str(data.get("user_id", "")),
            user_name=str(data.get("user_name", "")),
            detail=str(data.get("detail", "")),
        )
