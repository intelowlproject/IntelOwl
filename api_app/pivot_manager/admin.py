# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin

from api_app.core.admin import AbstractConfigAdminView
from api_app.pivot_manager.models import Pivot, PivotConfig


@admin.register(PivotConfig)
class PivotConfigAdminView(AbstractConfigAdminView):
    list_display = ["name", "config", "field", "playbook"]


@admin.register(Pivot)
class PivotAdminView(admin.ModelAdmin):
    list_display = ["starting_job", "configuration", "ending_job"]
    list_filter = ["config"]

    @staticmethod
    def configuration(instance: Pivot) -> str:
        return instance.config.name
