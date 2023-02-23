# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from django.contrib import admin

from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.core.admin import AbstractConfigAdminView, AbstractReportAdminView


@admin.register(AnalyzerReport)
class AnalyzerReportAdminView(AbstractReportAdminView):
    ...


@admin.register(AnalyzerConfig)
class AnalyzerConfigAdminView(AbstractConfigAdminView):
    list_display = AbstractConfigAdminView.list_display + (
        "type",
        "docker_based",
        "external_service",
        "leaks_info",
    )
