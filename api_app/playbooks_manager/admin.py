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
        "runtime_configuration",
        "scan_mode",
    )
    filter_horizontal = ["analyzers", "connectors"]

    @staticmethod
    def _get_plugins(qs):
        return [elem.name for elem in qs]

    @admin.display(description="Analyzers")
    def get_analyzers(self, obj: PlaybookConfig):
        return self._get_plugins(obj.analyzers.all())

    @admin.display(description="Connectors")
    def get_connectors(self, obj: PlaybookConfig):
        return self._get_plugins(obj.connectors.all())

    @admin.display(description="Visualizers")
    def get_visualizers(self, obj: PlaybookConfig):
        return self._get_plugins(obj.visualizers.all())

    @staticmethod
    def scan_mode(obj: PlaybookConfig) -> str:
        return ScanMode(obj.scan_mode).name
