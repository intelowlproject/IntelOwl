# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin

from api_app.core.admin import AbstractConfigAdminView, AbstractReportAdminView
from api_app.visualizers_manager.models import VisualizerConfig, VisualizerReport


@admin.register(VisualizerReport)
class VisualizerReportAdminView(AbstractReportAdminView):
    ...


@admin.register(VisualizerConfig)
class VisualizerConfigAdminView(AbstractConfigAdminView):
    list_display = AbstractConfigAdminView.list_display + (
        "get_analyzers",
        "get_connectors",
    )

    def _get_plugins(self, qs):
        return [elem.name for elem in qs]

    def get_analyzers(self, obj: VisualizerConfig):
        return self._get_plugins(obj.analyzers.all())

    def get_connectors(self, obj: VisualizerConfig):
        return self._get_plugins(obj.connectors.all())
