# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

# Security Stuff
from django.core.management.utils import get_random_secret_key

from ._util import get_secret
from .commons import STAGE_LOCAL, STAGE_PRODUCTION, STAGE_STAGING, WEB_CLIENT_DOMAIN

logger = logging.getLogger(__name__)

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = get_secret("DJANGO_SECRET", None) or get_random_secret_key()

HTTPS_ENABLED = get_secret("HTTPS_ENABLED", False) == "True"
if HTTPS_ENABLED:
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_SECURE = True
    WEB_CLIENT_URL = f"https://{WEB_CLIENT_DOMAIN}"
else:
    WEB_CLIENT_URL = f"http://{WEB_CLIENT_DOMAIN}"

CSRF_COOKIE_SAMESITE = "Strict"
CSRF_TRUSTED_ORIGINS = [f"{WEB_CLIENT_URL}"]
if STAGE_LOCAL:
    # required to allow requests from port 3001 (frontend development)
    CSRF_TRUSTED_ORIGINS = [f"{WEB_CLIENT_URL}:80/"]

# Conditional ALLOWED_HOSTS configuration
if STAGE_PRODUCTION or STAGE_STAGING:
    if not WEB_CLIENT_DOMAIN:
        raise ValueError(
            "WEB_CLIENT_DOMAIN must be set in production/staging environments."
        )

    _allowed_hosts = sorted(
        {
            host.strip()
            for host in WEB_CLIENT_DOMAIN.split(",")
            if host.strip()
        }
    )

    if not _allowed_hosts:
        raise ValueError(
            "WEB_CLIENT_DOMAIN contained no valid hosts after parsing."
        )

    ALLOWED_HOSTS = _allowed_hosts
    logger.info(f"ALLOWED_HOSTS restricted to: {ALLOWED_HOSTS}")

elif STAGE_LOCAL:
    ALLOWED_HOSTS = ["*"]
    logger.warning(
        "ALLOWED_HOSTS set to ['*'] - only use this in local development!"
    )

else:
    raise RuntimeError(
        "Unknown deployment stage. Please configure STAGE and "
        "WEB_CLIENT_DOMAIN appropriately."
    )