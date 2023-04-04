# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from api_app.core.views import AbstractConfigAPI, PluginActionViewSet

from .models import ConnectorReport
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
        signature = report.config.get_signature(
            report.job,
        )
        signature()
