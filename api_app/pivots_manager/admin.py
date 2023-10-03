# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin

from api_app.admin import AbstractReportAdminView, PythonConfigAdminView
from api_app.pivots_manager.forms import PivotConfigAdminForm
from api_app.pivots_manager.models import PivotConfig, PivotMap, PivotReport


@admin.register(PivotReport)
class PivotReportAdminView(AbstractReportAdminView):
    ...


@admin.register(PivotConfig)
class PivotConfigAdminView(PythonConfigAdminView):
    list_display = PythonConfigAdminView.list_display + (
        "get_related_config",
        "playbook_to_execute",
    )
    form = PivotConfigAdminForm

    @admin.display(description="Related Config")
    def get_related_config(self, instance: PivotConfig):
        return instance.related_config


@admin.register(PivotMap)
class PivotMapAdminView(admin.ModelAdmin):
    list_display = ["pk", "starting_job", "pivot_config", "ending_job", "owner"]
