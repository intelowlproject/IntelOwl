# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Per-user rate limiter for the chatbot.

Fixed-window counter backed by a Django named cache (``chatbot_rate_limit``),
shared between the REST view and the WebSocket consumer so a user who sends via
both paths hits the same bucket.
"""

import time

from django.core.cache import caches

CACHE_ALIAS = "chatbot_rate_limit"


class RateLimiter:
    """Count actions per key within a fixed time window.

    ``allow()`` is a read-only check (no side effect); ``increment()`` records
    one action.  Callers MUST pair them: after ``allow()`` passes, call
    ``increment()`` before the protected action, otherwise every concurrent
    request at the boundary slips through.
    """

    def __init__(self, limit: int = 5, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds
        self._cache = caches[CACHE_ALIAS]

    def allow(self, key: str) -> tuple[bool, int]:
        """Return ``(True, 0)`` when the key is under the limit,
        or ``(False, retry_after_seconds)`` when it is exhausted.
        ``retry_after`` is an estimate — it subtracts elapsed time within the
        current window, but a client that retries at exactly ``retry_after``
        may still be rate-limited if the window hasn't ticked over yet.
        """
        current = self._cache.get(self._cache_key(key), 0)
        if current < self.limit:
            return True, 0
        # Estimate how long until the window rolls over.
        elapsed = time.time() % self.window_seconds
        retry_after = int(self.window_seconds - elapsed)
        return False, retry_after

    def increment(self, key: str) -> int:
        """Record one action for *key* and return the new count.

        Uses ``incr`` which is atomic under Redis and sets a TTL so dead
        counters don't accumulate.  Handles the initial ``incr`` on a missing
        key (Redis returns 1, some backends raise ValueError).
        """
        cache_key = self._cache_key(key)
        try:
            new = self._cache.incr(cache_key)
        except ValueError:
            # Key doesn't exist yet — seed it with expiry.
            self._cache.set(cache_key, 1, timeout=self.window_seconds)
            return 1
        return new

    def _cache_key(self, key: str) -> str:
        """Produce a cache key that changes every ``self.window_seconds``.

        Key format: ``chatbot_rate_{key}_{window_ts}``
        Example:   ``chatbot_rate_7_1742345600``
        """
        window_ts = int(time.time() / self.window_seconds)
        return f"chatbot_rate_{key}_{window_ts}"


def _build_rate_limiter() -> RateLimiter:
    """Return a RateLimiter configured from Django settings.

    Defined here (not in views.py / consumers.py) so the threshold and window
    are read from a single place.
    """
    from django.conf import settings

    return RateLimiter(
        limit=settings.CHATBOT_RATE_LIMIT,
        window_seconds=settings.CHATBOT_RATE_LIMIT_WINDOW,
    )
