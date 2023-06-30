# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin

from api_app.admin import AbstractConfigAdminView
from api_app.choices import ScanMode
from api_app.playbooks_manager.models import PlaybookConfig


@admin.register(PlaybookConfig)
class PlaybookConfigAdminView(AbstractConfigAdminView):
    list_display = (
        "name",
        "type",
        "disabled",
        "get_analyzers",
        "get_connectors",
        "get_visualizers",
        "get_pivots",
        "runtime_configuration",
        "scan_mode",
    )

    def _get_plugins(self, qs):  # noqa
        return [elem.name for elem in qs]

    def get_analyzers(self, obj: PlaybookConfig):
        return self._get_plugins(obj.analyzers.all())

    def get_connectors(self, obj: PlaybookConfig):
        return self._get_plugins(obj.connectors.all())

    def get_visualizers(self, obj: PlaybookConfig):
        return self._get_plugins(obj.visualizers.all())

    def get_pivots(self, obj: PlaybookConfig):
        return self._get_plugins(obj.pivots.all())

    def scan_mode(self, obj: PlaybookConfig) -> str:
        return ScanMode(obj.scan_configuration.mode).name
