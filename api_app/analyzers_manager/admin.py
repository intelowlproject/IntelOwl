# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin

from api_app.analyzers_manager.models import AnalyzerReport


@admin.register(AnalyzerReport)
class AnalyzerReportAdminView(admin.ModelAdmin):
    list_display = (
        "id",
        "name",
        "job",
        "status",
        "start_time",
        "end_time",
    )
    list_display_links = ("id",)
    search_fields = ("name",)
