# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin

from api_app.connectors_manager.forms import ConnectorConfigAdminForm
from api_app.connectors_manager.models import ConnectorConfig, ConnectorReport
from api_app.core.admin import AbstractConfigAdminView, AbstractReportAdminView


@admin.register(ConnectorReport)
class ConnectorReportAdminView(AbstractReportAdminView):
    ...


@admin.register(ConnectorConfig)
class ConnectorConfigAdminView(AbstractConfigAdminView):
    list_display = AbstractConfigAdminView.list_display + (
        "maximum_tlp",
        "run_on_failure",
    )
    form = ConnectorConfigAdminForm
