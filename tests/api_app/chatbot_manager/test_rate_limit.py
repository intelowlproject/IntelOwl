# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

"""Unit tests for the chatbot RateLimiter.

All tests use LocMemCache (no Redis dependency) so they work in CI and
offline.  time.time is patched for window-boundary assertions.
"""

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from api_app.chatbot_manager.rate_limit import CACHE_ALIAS, RateLimiter

LOCMEM = {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
TEST_CACHES = {"default": LOCMEM, CACHE_ALIAS: LOCMEM}

_user_b = "7"
_limit = 5


def _make_limiter(limit=_limit, window=60):
    return RateLimiter(limit=limit, window_seconds=window)


def _fresh_key():
    """Return a per-test key so LocMemCache state from one test never leaks into
    another.  SimpleTestCase does not flush the cache between tests, and all
    tests share the same process-scoped LocMemCache."""
    import uuid

    return str(uuid.uuid4())


class RateLimiterAllowTests(SimpleTestCase):
    """allow() is a pure read — no counter mutation."""

    @override_settings(CACHES=TEST_CACHES)
    def test_allow_returns_true_when_under_limit(self):
        user = _fresh_key()
        limiter = _make_limiter()
        for _ in range(4):
            limiter.increment(user)
        allowed, retry_after = limiter.allow(user)
        self.assertTrue(allowed)
        self.assertEqual(retry_after, 0)

    @override_settings(CACHES=TEST_CACHES)
    def test_allow_returns_true_at_edge_of_limit(self):
        user = _fresh_key()
        limiter = _make_limiter()
        for _ in range(4):
            limiter.increment(user)
        # 4 < 5, so the 5th action should be allowed
        allowed, _ = limiter.allow(user)
        self.assertTrue(allowed)

    @override_settings(CACHES=TEST_CACHES)
    def test_allow_returns_false_at_limit(self):
        user = _fresh_key()
        limiter = _make_limiter()
        for _ in range(_limit):
            limiter.increment(user)
        allowed, retry_after = limiter.allow(user)
        self.assertFalse(allowed)
        self.assertGreater(retry_after, 0, "retry_after should be positive")

    @override_settings(CACHES=TEST_CACHES)
    def test_retry_after_decreases_as_time_passes(self):
        """retry_after is recalculated from the current time, so it shrinks as the
        window progresses."""
        limiter = _make_limiter()
        # Freeze time at the very start of a window.
        window_start = 1742345600.0  # arbitrary, exactly on a 60s boundary
        user = _fresh_key()
        with patch("api_app.chatbot_manager.rate_limit.time.time", return_value=window_start):
            for _ in range(_limit):
                limiter.increment(user)
            _, first = limiter.allow(user)
        # 10 seconds later, retry_after should be ~10s smaller.
        with patch(
            "api_app.chatbot_manager.rate_limit.time.time",
            return_value=window_start + 10,
        ):
            _, later = limiter.allow(user)
        self.assertEqual(later, first - 10)
        self.assertGreater(later, 0)


class RateLimiterIncrementTests(SimpleTestCase):
    """increment() mutates the counter atomically."""

    @override_settings(CACHES=TEST_CACHES)
    def test_counter_resets_after_window(self):
        limiter = _make_limiter()
        window_start = 1742345600.0
        user = _fresh_key()
        # Fill the current window.
        with patch("api_app.chatbot_manager.rate_limit.time.time", return_value=window_start):
            for _ in range(_limit):
                limiter.increment(user)
            allowed, _ = limiter.allow(user)
            self.assertFalse(allowed)
        # Advance to the next window.
        with patch(
            "api_app.chatbot_manager.rate_limit.time.time",
            return_value=window_start + 61,
        ):
            allowed, _ = limiter.allow(user)
            self.assertTrue(allowed, "counter should reset in the next window")
            limiter.increment(user)
            current = limiter._cache.get(limiter._cache_key(user), 0)
            self.assertEqual(current, 1)

    @override_settings(CACHES=TEST_CACHES)
    def test_different_users_have_independent_counters(self):
        limiter = _make_limiter()
        user_a = _fresh_key()
        # Saturate user A.
        for _ in range(_limit):
            limiter.increment(user_a)
        # User B should still be free.
        allowed, _ = limiter.allow(_user_b)
        self.assertTrue(allowed)

    @override_settings(CACHES=TEST_CACHES)
    def test_increment_is_thread_safety_smoke(self):
        """10 concurrent increments — at most *limit* should succeed."""
        limiter = _make_limiter()
        user = _fresh_key()
        results = []

        def attempt():
            if limiter.allow(user)[0]:
                limiter.increment(user)
                results.append("accepted")
            else:
                results.append("rejected")

        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(lambda _: attempt(), range(10)))

        accepted = sum(1 for r in results if r == "accepted")
        rejected = sum(1 for r in results if r == "rejected")
        self.assertLessEqual(accepted, _limit)
        self.assertEqual(accepted + rejected, 10)


class RateLimiterCacheKeyTests(SimpleTestCase):
    """The cache key changes every window_seconds."""

    @override_settings(CACHES=TEST_CACHES)
    def test_cache_keys_differ_across_windows(self):
        limiter = _make_limiter(window=60)
        # 1000 and 1010 are both in window 16 (960–1019).
        with patch("api_app.chatbot_manager.rate_limit.time.time", return_value=1000.0):
            k1 = limiter._cache_key("u1")
        with patch("api_app.chatbot_manager.rate_limit.time.time", return_value=1010.0):
            k2 = limiter._cache_key("u1")
        # 1020 falls into window 17.
        with patch("api_app.chatbot_manager.rate_limit.time.time", return_value=1020.0):
            k3 = limiter._cache_key("u1")
        self.assertEqual(k1, k2, "same window → same key")
        self.assertNotEqual(k2, k3, "next window → new key")
