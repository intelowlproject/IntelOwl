# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

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

    @classmethod
    @property
    def report_model(cls):
        return ConnectorReport

    def perform_retry(self, report: ConnectorReport):
        config: ConnectorConfig = ConnectorConfig.objects.get(name=report.name)
        signature = config.get_signature(
            report.job.pk,
            report.runtime_configuration.get(report.name, {}),
            report.parent_playbook,
        )
        signature()
