# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin

from api_app.admin import AbstractReportAdminView, PythonConfigAdminView
from api_app.visualizers_manager.models import VisualizerConfig, VisualizerReport


@admin.register(VisualizerReport)
class VisualizerReportAdminView(AbstractReportAdminView):
    ...


@admin.register(VisualizerConfig)
class VisualizerConfigAdminView(PythonConfigAdminView):
    list_display = PythonConfigAdminView.list_display + ("get_playbooks",)

    @admin.display(description="Playbooks")
    def get_playbooks(self, instance: VisualizerConfig):
        return list(instance.playbooks.values_list("name", flat=True))
