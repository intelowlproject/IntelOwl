# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from api_app.decorators import classproperty
from api_app.views import PluginConfigViewSet, PythonConfigViewSet, PythonReportActionViewSet
from api_app.connectors_manager.models import ConnectorConfig, ConnectorReport
from api_app.connectors_manager.serializers import ConnectorConfigSerializer

logger = logging.getLogger(__name__)


__all__ = [
    "ConnectorConfigViewSet",
    "ConnectorActionViewSet",
]


class ConnectorConfigViewSet(PythonConfigViewSet):
    """ViewSet for ConnectorConfig model."""
    serializer_class = ConnectorConfigSerializer


class ConnectorActionViewSet(PythonReportActionViewSet):
    """ViewSet for connector actions."""

    @classproperty
    def report_model(cls):  # type: ignore
        return ConnectorReport


class ConnectorPluginConfigViewSet(PluginConfigViewSet):
    """ViewSet for connector plugin configuration."""
    queryset = ConnectorConfig.objects.all()
