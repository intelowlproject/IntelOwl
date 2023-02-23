# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from celery import group

from api_app.core.views import AbstractConfigAPI, PluginActionViewSet

from .models import ConnectorConfig, ConnectorReport
from .serializers import ConnectorConfigSerializer

logger = logging.getLogger(__name__)


__all__ = [
    "ConnectorConfigAPI",
    "ConnectorActionViewSet",
]


class ConnectorConfigAPI(AbstractConfigAPI):
    serializer_class = ConnectorConfigSerializer


class ConnectorActionViewSet(PluginActionViewSet):
    queryset = ConnectorReport.objects.all()

    @property
    def report_model(self):
        return ConnectorReport

    def perform_retry(self, report: ConnectorReport):
        signature = ConnectorConfig.objects.get(report.name).get_signature(
            report.job.id,
            report.runtime_configuration.get(report.name, {}),
            report.parent_playbook,
        )
        group(signature)()
