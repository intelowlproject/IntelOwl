# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin

from api_app.pivot_manager.forms import PivotConfigModelForm
from api_app.pivot_manager.models import Pivot, PivotConfig


@admin.register(PivotConfig)
class PivotConfigAdminView(admin.ModelAdmin):
    list_display = ["name", "config", "field", "playbook_to_execute"]
    form = PivotConfigModelForm


@admin.register(Pivot)
class PivotAdminView(admin.ModelAdmin):

    list_display = ["starting_job", "configuration", "value", "ending_job", "owner"]

    @staticmethod
    def configuration(instance: Pivot) -> str:
        return instance.config.name
