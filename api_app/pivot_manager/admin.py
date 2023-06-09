# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin

from api_app.core.admin import AbstractConfigAdminView
from api_app.pivot_manager.models import PivotConfig


@admin.register(PivotConfig)
class PivotConfigAdminView(AbstractConfigAdminView):
    list_display = ["name", "config", "field", "playbook"]
