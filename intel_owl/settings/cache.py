import os

from ._util import set_permissions

__all__ = ["CACHES"]


DEFAULT_CACHE = "/tmp/dj_cache_intelowl_default"
PAYMENTS_CACHE = "/tmp/dj_cache_intelowl_certego_saas"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.filebased.FileBasedCache",
        "LOCATION": DEFAULT_CACHE,
    },
    "certego_saas": {
        "BACKEND": "django.core.cache.backends.filebased.FileBasedCache",
        "LOCATION": PAYMENTS_CACHE,
        "KEY_PREFIX": "certego_saas",
    },
}
os.makedirs(DEFAULT_CACHE, exist_ok=True)
os.makedirs(PAYMENTS_CACHE, exist_ok=True)
set_permissions(DEFAULT_CACHE)
set_permissions(PAYMENTS_CACHE)
