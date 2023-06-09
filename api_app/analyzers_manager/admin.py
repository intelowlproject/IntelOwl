# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from django.contrib import admin

from api_app.analyzers_manager.forms import AnalyzerConfigAdminForm
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.core.admin import AbstractReportAdminView, PythonConfigAdminView


@admin.register(AnalyzerReport)
class AnalyzerReportAdminView(AbstractReportAdminView):
    ...


@admin.register(AnalyzerConfig)
class AnalyzerConfigAdminView(PythonConfigAdminView):
    list_display = PythonConfigAdminView.list_display + (
        "type",
        "docker_based",
        "maximum_tlp",
    )
    form = AnalyzerConfigAdminForm
