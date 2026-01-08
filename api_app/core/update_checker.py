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
        return None, "UPDATE_CHECK_URL not configured"

    try:
        resp = requests.get(
            update_url,
            headers={"User-Agent": "IntelOwl-Update-Checker"},
            timeout=5,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.error(f"update check failed: {exc}")
        return None, "Failed to fetch release information"

    try:
        data = resp.json()
    except ValueError:
        logger.error("invalid JSON in update response")
        return None, "Invalid response from update server"

    tag = data.get("tag_name")
    if not tag:
        return None, "Release response missing tag_name"

    return tag.lstrip("v"), None


def check_for_update():
    """
    Compare the running IntelOwl version with the latest available one.

    Returns:
        (success: bool, message: str)
    """
    current_version_str = getattr(settings, "INTEL_OWL_VERSION", None)
    if not current_version_str:
        return False, "INTEL_OWL_VERSION setting missing"

    latest_str, error = fetch_latest_version()
    if error:
        return False, error

    current_version_str = str(current_version_str).lstrip("v")

    current = normalize_version(current_version_str)
    latest = normalize_version(latest_str)

    if not current or not latest:
        if latest_str != current_version_str:
            return (
                True,
                f"Update available: {latest_str} (current: {current_version_str})",
            )
        return True, f"IntelOwl version up to date ({current_version_str})"

    if latest > current:
        return (
            True,
            f"New IntelOwl version available: {latest_str} "
            f"(current: {current_version_str})",
        )

    if latest < current:
        return (
            True,
            f"Local version ahead of release: " f"{current_version_str} > {latest_str}",
        )

    return True, f"IntelOwl version up to date ({current_version_str})"
