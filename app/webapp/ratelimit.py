"""Per-IP rate limiting for the public HTTP surface.

A fixed-window counter is enough here: the goal is to stop a public tunnel URL
from being hammered or used to fan out chain lookups, not to enforce precise
fairness. Buckets are pruned lazily so memory cannot grow without bound.

Note: ``ThreadingHTTPServer`` serves requests on multiple threads, so the
counter is guarded by a lock.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

#: Endpoints that trigger upstream network calls (chain APIs, puzzle datasets).
EXPENSIVE_PATHS = (
    "/api/wallet/assets",
    "/api/auth/challenge",
    "/api/auth/verify",
)


@dataclass
class _Bucket:
    window_start: float
    count: int = 0
    blocked_until: float = 0.0


@dataclass
class RateLimitDecision:
    allowed: bool
    remaining: int
    retry_after: int = 0
    limit: int = 0

    def headers(self) -> Dict[str, str]:
        out = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(self.remaining, 0)),
        }
        if not self.allowed:
            out["Retry-After"] = str(max(self.retry_after, 1))
        return out


class RateLimiter:
    """Fixed-window limiter with a separate, stricter budget for heavy paths."""

    def __init__(self, *, limit: int = 60, window: float = 60.0,
                 expensive_limit: Optional[int] = None,
                 clock=time.monotonic, max_buckets: int = 4096):
        self.limit = limit
        self.window = window
        self.expensive_limit = expensive_limit if expensive_limit is not None else limit
        self._clock = clock
        self._max_buckets = max_buckets
        self._buckets: Dict[Tuple[str, str], _Bucket] = {}
        self._lock = threading.Lock()

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _is_expensive(path: str) -> bool:
        return any(path.startswith(p) for p in EXPENSIVE_PATHS)

    def _prune(self, now: float) -> None:
        if len(self._buckets) <= self._max_buckets:
            return
        stale = [k for k, b in self._buckets.items()
                 if b.window_start + self.window < now and b.blocked_until < now]
        for key in stale:
            self._buckets.pop(key, None)

    # -- main -------------------------------------------------------------
    def check(self, client_ip: str, path: str) -> RateLimitDecision:
        """Record a request and decide whether it may proceed."""
        expensive = self._is_expensive(path)
        budget = self.expensive_limit if expensive else self.limit
        key = (client_ip, "expensive" if expensive else "normal")
        now = self._clock()

        with self._lock:
            self._prune(now)
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(window_start=now)
                self._buckets[key] = bucket

            # hard block still in force
            if bucket.blocked_until > now:
                return RateLimitDecision(
                    allowed=False, remaining=0,
                    retry_after=int(bucket.blocked_until - now) + 1, limit=budget,
                )

            # roll the window
            if now - bucket.window_start >= self.window:
                bucket.window_start = now
                bucket.count = 0

            bucket.count += 1
            if bucket.count > budget:
                bucket.blocked_until = bucket.window_start + self.window
                return RateLimitDecision(
                    allowed=False, remaining=0,
                    retry_after=int(bucket.window_start + self.window - now) + 1,
                    limit=budget,
                )
            return RateLimitDecision(
                allowed=True, remaining=budget - bucket.count, limit=budget,
            )

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
