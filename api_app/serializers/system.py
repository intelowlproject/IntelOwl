from django.conf import settings
from rest_framework import serializers

from api_app.core.update_checker import normalize_version
from api_app.models import UpdateCheckStatus


class SystemUpdateStatusSerializer(serializers.Serializer):
    current_version = serializers.CharField()
    latest_version = serializers.CharField(allow_null=True)
    update_available = serializers.BooleanField()
    last_checked_at = serializers.DateTimeField(allow_null=True)
    notified = serializers.BooleanField()

    @staticmethod
    def from_state(state: UpdateCheckStatus | None):
        current_version = str(getattr(settings, "INTEL_OWL_VERSION", "")).lstrip("v")

        latest_version = state.latest_version if state else None
        last_checked_at = state.last_checked_at if state else None
        notified = state.notified if state else False

        update_available = False
        if latest_version and normalize_version(latest_version) > normalize_version(current_version):
            update_available = True

        return {
            "current_version": current_version,
            "latest_version": latest_version,
            "update_available": update_available,
            "last_checked_at": last_checked_at,
            "notified": notified,
        }
