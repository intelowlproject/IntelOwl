# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin

from api_app.admin import AbstractReportAdminView, PythonConfigAdminView
from api_app.ingestors_manager.models import IngestorConfig, IngestorReport


# flake8: noqa
@admin.register(IngestorReport)
class IngestorReportAdminView(AbstractReportAdminView): ...


@admin.register(IngestorConfig)
class IngestorConfigAdminView(PythonConfigAdminView):
    list_display = (
        "name",
        "python_module",
        "disabled",
        "get_playbooks_choice",
        "schedule",
    )
    exclude = ["user", "periodic_task"]

    @admin.display(description="Playbooks choice")
    def get_playbooks_choice(self, instance: IngestorConfig):
        return instance.playbooks_names
