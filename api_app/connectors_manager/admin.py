# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin

from api_app.connectors_manager.models import ConnectorReport


@admin.register(ConnectorReport)
class ConnectorReportAdminView(admin.ModelAdmin):
    list_display = (
        "id",
        "status",
        "connector",
        "job",
        "start_time",
        "end_time",
    )
    list_display_links = ("id",)
    search_fields = ("connector",)
