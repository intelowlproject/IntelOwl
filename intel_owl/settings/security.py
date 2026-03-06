import os
import logging

from intel_owl.settings.commons import STAGE_LOCAL, STAGE_PRODUCTION, STAGE_STAGING

logger = logging.getLogger(__name__)

# Get WEB_CLIENT_DOMAIN from environment
WEB_CLIENT_DOMAIN = os.environ.get("WEB_CLIENT_DOMAIN", "").strip()

# Conditional ALLOWED_HOSTS configuration
if STAGE_PRODUCTION or STAGE_STAGING:
    # Validate WEB_CLIENT_DOMAIN is set
    if not WEB_CLIENT_DOMAIN:
        raise ValueError(
            "WEB_CLIENT_DOMAIN must be set in production/staging environments."
        )

    # Parse WEB_CLIENT_DOMAIN into individual hosts (supports comma-separated)
    _allowed_hosts = sorted(
        {
            host.strip()
            for host in WEB_CLIENT_DOMAIN.split(",")
            if host.strip()
        }
    )

    # Validate that we have at least one valid host
    if not _allowed_hosts:
        raise ValueError(
            "WEB_CLIENT_DOMAIN contained no valid hosts after parsing."
        )

    ALLOWED_HOSTS = _allowed_hosts

    logger.info(f"ALLOWED_HOSTS restricted to production values: {ALLOWED_HOSTS}")
elif STAGE_LOCAL:
    # Allow all hosts for local development
    ALLOWED_HOSTS = ["*"]
    logger.warning(
        "ALLOWED_HOSTS set to ['*'] - this should only be used in local development!"
    )
else:
    # Default fallback for unknown environments
    ALLOWED_HOSTS = ["*"]
    logger.warning(
        "ALLOWED_HOSTS set to ['*'] - environment not detected, using permissive setting!"
    )