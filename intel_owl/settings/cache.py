import os

from ._util import set_permissions

MEDIA_ROOT = "/opt/deploy/files_required"
DEFAULT_CACHE = f"{MEDIA_ROOT}/dj_cache_intelowl_default"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.filebased.FileBasedCache",
        "LOCATION": DEFAULT_CACHE,
    }
}
os.makedirs(DEFAULT_CACHE, exist_ok=True)
set_permissions(DEFAULT_CACHE)
