import logging
import requests
from django.conf import settings

logger = logging.getLogger(__name__)


def normalize_version(v):
    """
    Convert '1.2.3' → (1, 2, 3) so versions can be compared.
    Stops at the first non-numeric part.
    """
    parts = []
    for x in v.split("."):
        if x.isdigit():
            parts.append(int(x))
        else:
            break
    return tuple(parts)


def fetch_latest_version():
    """
    Fetch the latest IntelOwl version string from the update URL.
    Returns a version string without any leading 'v', or None on error.
    """
    update_url = getattr(settings, "UPDATE_CHECK_URL", None)

    if not update_url:
        logger.warning("UPDATE_CHECK_URL not configured")
        return None

    try:
        resp = requests.get(
            update_url,
            headers={"User-Agent": "IntelOwl-Update-Checker"},
            timeout=5,
        )
        resp.raise_for_status()

        data = resp.json()
        tag = data.get("tag_name")
        if not tag:
            logger.warning("release response missing tag_name")
            return None

        # remove optional 'v' prefix
        return tag.lstrip("v")

    except requests.RequestException as exc:
        logger.error(f"update check failed: {exc}")
        return None
    except ValueError:
        logger.error("invalid JSON in update response")
        return None


def check_for_update():
    """
    Compare the running IntelOwl version with the latest available one
    and log a warning if a newer version exists.
    """
    current_version_str = getattr(settings, "INTEL_OWL_VERSION", None)
    latest_str = fetch_latest_version()

    if not current_version_str:
        logger.warning("INTEL_OWL_VERSION setting missing")
        return

    if not latest_str:
        return  # fetch logged any errors

    current_version_str = str(current_version_str).lstrip("v")

    current = normalize_version(current_version_str)
    latest = normalize_version(latest_str)

    if not current or not latest:
        # fallback string compare if parsing failed
        if latest_str != current_version_str:
            logger.warning(
                f"Update available: {latest_str} " f"(current: {current_version_str})"
            )
        return

    if latest > current:
        logger.warning(
            f"New IntelOwl version available: {latest_str} "
            f"(current: {current_version_str})"
        )
    elif latest < current:
        logger.info(
            f"Local version ahead of release: " f"{current_version_str} > {latest_str}"
        )
    else:
        logger.info(f"IntelOwl version up to date ({current_version_str})")
