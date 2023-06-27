# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin

from api_app.core.admin import AbstractReportAdminView, PythonConfigAdminView
from api_app.visualizers_manager.forms import VisualizerConfigAdminForm
from api_app.visualizers_manager.models import VisualizerConfig, VisualizerReport


@admin.register(VisualizerReport)
class VisualizerReportAdminView(AbstractReportAdminView):
    ...


@admin.register(VisualizerConfig)
class VisualizerConfigAdminView(PythonConfigAdminView):
    list_display = AbstractConfigAdminView.list_display + ("playbook",)

    form = VisualizerConfigAdminForm
