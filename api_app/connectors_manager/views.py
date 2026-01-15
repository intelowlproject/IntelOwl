# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from api_app.decorators import classproperty

from ..views import PluginConfigViewSet, PythonConfigViewSet, PythonReportActionViewSet
from .models import ConnectorConfig, ConnectorReport
from .serializers import ConnectorConfigSerializer

logger = logging.getLogger(__name__)


__all__ = [
    "ConnectorConfigViewSet",
    "ConnectorActionViewSet",
]


class ConnectorConfigViewSet(PythonConfigViewSet):
    serializer_class = ConnectorConfigSerializer


class ConnectorActionViewSet(PythonReportActionViewSet):
    @classproperty
    def report_model(cls):
        return ConnectorReport


class ConnectorPluginConfigViewSet(PluginConfigViewSet):
    queryset = ConnectorConfig.objects.all()
