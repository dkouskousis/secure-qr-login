"""Simple in-memory fixed-window rate limiting."""

from __future__ import annotations

from dataclasses import dataclass
import time


@dataclass(slots=True)
class _Bucket:
    started: float
    count: int = 0


class FixedWindowLimiter:
    """Small per-key fixed-window limiter suitable for HA's event loop."""

    def __init__(self, limit: int, window: int) -> None:
        self.limit = limit
        self.window = window
        self._buckets: dict[str, _Bucket] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        bucket = self._buckets.get(key)
        if bucket is None or now - bucket.started >= self.window:
            self._buckets[key] = _Bucket(started=now, count=1)
            self._cleanup(now)
            return True
        if bucket.count >= self.limit:
            return False
        bucket.count += 1
        return True

    def _cleanup(self, now: float) -> None:
        expired = [
            key for key, bucket in self._buckets.items()
            if now - bucket.started >= self.window
        ]
        for key in expired:
            self._buckets.pop(key, None)
