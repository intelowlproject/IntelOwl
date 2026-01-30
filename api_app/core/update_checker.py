import logging
from typing import Optional, Tuple

import requests
from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils.timezone import now

from api_app.models import UpdateCheckStatus

logger = logging.getLogger(__name__)

try:
    from api_app.user_events_manager.queryset import UserEventQuerySet
except Exception:
    UserEventQuerySet = None

try:
    from certego_saas_notifications.models import Notification
except Exception:
    Notification = None

STORED_TAG_MAX_LEN = UpdateCheckStatus._meta.get_field("latest_version").max_length


def normalize_version(v: str) -> Tuple[int, ...]:
    parts: list[int] = []
    for x in str(v).split("."):
        if x.isdigit():
            parts.append(int(x))
        else:
            break
    return tuple(parts)


def fetch_latest_version() -> Tuple[Optional[str], Optional[str]]:
    url = getattr(settings, "UPDATE_CHECK_URL", None)
    if not url:
        return None, "UPDATE_CHECK_URL not configured"

    try:
        resp = requests.get(url, headers={"User-Agent": "IntelOwl-Update-Checker"}, timeout=5)
    except requests.RequestException as exc:
        logger.error("Update check HTTP request failed: %s", exc)
        return None, "Failed to fetch release information"

    try:
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.error("Update check HTTP error: %s", exc)
        return None, "Update server returned an error"

    try:
        data = resp.json()
    except ValueError:
        logger.error("Invalid JSON from update server")
        return None, "Invalid response from update server"

    tag = data.get("tag_name")
    if not tag:
        logger.warning("Update response missing tag_name")
        return None, "Release response missing tag_name"

    return str(tag).lstrip("v"), None


def _notify_admins(title: str, message: str) -> None:
    try:
        if UserEventQuerySet is not None:
            UserEventQuerySet.notify_admins(title=title, message=message, persistent=True, severity="warning")
            return
        if Notification is not None:
            Notification.objects.create(
                title=title,
                description=message,
                level="info",
                for_admins=True,
            )
            return
        logger.info("No notification backend available; skipping admin notification")
    except Exception:
        logger.exception("Failed to send admin notification")


def check_for_update() -> Tuple[bool, str]:
    current_version = getattr(settings, "INTEL_OWL_VERSION", None)
    if not current_version:
        return False, "INTEL_OWL_VERSION setting missing"

    latest, err = fetch_latest_version()
    if err:
        return False, err

    latest_full = latest or ""
    stored_latest = latest_full[:STORED_TAG_MAX_LEN] if latest_full else None
    current_str = str(current_version).lstrip("v")

    current_v = normalize_version(current_str)
    latest_v = normalize_version(latest_full)

    try:
        with transaction.atomic():
            try:
                state, _ = UpdateCheckStatus.objects.select_for_update().get_or_create(pk=1)
            except IntegrityError:
                state = UpdateCheckStatus.objects.select_for_update().get(pk=1)

            state.last_checked_at = now()

            if not current_v or not latest_v:
                if latest_full != current_str:
                    message = f"Update available: {latest_full} (current: {current_str})"
                else:
                    message = f"IntelOwl version up to date ({current_str})"

                state.save(update_fields=["last_checked_at"])
                return True, message

            if latest_v > current_v:
                message = f"New IntelOwl version available: {latest_full} (current: {current_str})"

                should_notify = (state.latest_version != stored_latest) or (not state.notified)
                if should_notify:
                    state.latest_version = stored_latest
                    state.notified = True
                    state.save(update_fields=["latest_version", "notified", "last_checked_at"])

                    def _send_notification():
                        _notify_admins(
                            "New IntelOwl version available",
                            f"Version {latest_full} is available (current: {current_str})",
                        )

                    if getattr(settings, "TESTING", False):
                        _send_notification()
                    else:
                        transaction.on_commit(_send_notification)

                    logger.info(
                        "New IntelOwl version available (notified scheduled): %s (current: %s)",
                        latest_full,
                        current_str,
                    )
                else:
                    state.save(update_fields=["last_checked_at"])

                return True, message

            if latest_v < current_v:
                state.save(update_fields=["last_checked_at"])
                return (
                    True,
                    f"Local version ahead of release: {current_str} > {latest_full}",
                )

            state.save(update_fields=["last_checked_at"])
            return True, f"IntelOwl version up to date ({current_str})"

    except Exception:
        logger.exception("Unexpected error during update check (db/transaction)")
        return False, "Unexpected error during update check. See logs for details."
