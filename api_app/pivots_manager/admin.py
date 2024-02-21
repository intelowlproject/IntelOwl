# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin
from django.http import HttpRequest

from api_app.admin import AbstractReportAdminView, PythonConfigAdminView
from api_app.pivots_manager.forms import PivotConfigAdminForm
from api_app.pivots_manager.models import PivotConfig, PivotMap, PivotReport


@admin.register(PivotReport)
class PivotReportAdminView(AbstractReportAdminView):
    ...


@admin.register(PivotConfig)
class PivotConfigAdminView(PythonConfigAdminView):
    list_display = PythonConfigAdminView.list_display + (
        "get_related_configs",
        "playbook_to_execute",
    )
    form = PivotConfigAdminForm

    @admin.display(description="Related Configs")
    def get_related_configs(self, instance: PivotConfig):
        return list(instance.related_configs.values_list("name", flat=True))


@admin.register(PivotMap)
class PivotMapAdminView(admin.ModelAdmin):
    list_display = ["pk", "starting_job", "pivot_config", "ending_job", "owner"]

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj=None) -> bool:
        return False
