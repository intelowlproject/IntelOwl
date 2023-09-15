# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin

from api_app.admin import AbstractReportAdminView, PythonConfigAdminView
from api_app.connectors_manager.models import ConnectorConfig, ConnectorReport


@admin.register(ConnectorReport)
class ConnectorReportAdminView(AbstractReportAdminView):
    ...


@admin.register(ConnectorConfig)
class ConnectorConfigAdminView(PythonConfigAdminView):
    list_display = PythonConfigAdminView.list_display + (
        "maximum_tlp",
        "run_on_failure",
    )
