import logging

import requests
from django.conf import settings
from django.utils.timezone import now

logger = logging.getLogger(__name__)


def normalize_version(v: str) -> tuple[int, ...]:
    parts: list[int] = []
    for x in v.split("."):
        if x.isdigit():
            parts.append(int(x))
        else:
            break
    return tuple(parts)


def fetch_latest_version() -> tuple[str | None, str | None]:
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
        logger.error("update check failed: %s", exc)
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


def check_for_update() -> tuple[bool, str]:
    from certego_saas_notifications.models import Notification

    from api_app.models import UpdateCheckStatus

    current_version_str = getattr(settings, "INTEL_OWL_VERSION", None)
    if not current_version_str:
        return False, "INTEL_OWL_VERSION setting missing"

    latest_str, error = fetch_latest_version()
    if error:
        return False, error

    current_version_str = str(current_version_str).lstrip("v")

    current = normalize_version(current_version_str)
    latest = normalize_version(latest_str) if latest_str else ()

    state, _ = UpdateCheckStatus.objects.get_or_create(pk=1)
    state.last_checked_at = now()
    update_fields = {"last_checked_at"}

    if not current or not latest:
        state.save(update_fields=list(update_fields))
        if latest_str != current_version_str:
            return (
                True,
                f"Update available: {latest_str} (current: {current_version_str})",
            )
        return True, f"IntelOwl version up to date ({current_version_str})"

    if latest > current:
        if state.latest_version != latest_str or not state.notified:
            logger.info(
                "New IntelOwl version available: %s (current: %s)",
                latest_str,
                current_version_str,
            )

            Notification.objects.create(
                title="New IntelOwl Version Available",
                description=(
                    f"Version {latest_str} is available "
                    f"(current: {current_version_str})"
                ),
                level="info",
                for_admins=True,
            )

            state.latest_version = latest_str
            state.notified = True
            update_fields.update({"latest_version", "notified"})

        state.save(update_fields=list(update_fields))
        return (
            True,
            f"New IntelOwl version available: {latest_str} "
            f"(current: {current_version_str})",
        )

    if latest < current:
        state.save(update_fields=list(update_fields))
        return (
            True,
            f"Local version ahead of release: {current_version_str} > {latest_str}",
        )

    state.save(update_fields=list(update_fields))
    return True, f"IntelOwl version up to date ({current_version_str})"
