import os

from ._util import set_permissions

__all__ = ["CACHES"]


DEFAULT_CACHE = "/tmp/dj_cache_intelowl_default"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.filebased.FileBasedCache",
        "LOCATION": DEFAULT_CACHE,
    }
}
os.makedirs(DEFAULT_CACHE, exist_ok=True)
set_permissions(DEFAULT_CACHE)
