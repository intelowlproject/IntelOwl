# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from api_app.core.views import PluginActionViewSet, PythonConfigViewSet

from .models import ConnectorReport
from .serializers import ConnectorConfigSerializer

logger = logging.getLogger(__name__)


__all__ = [
    "ConnectorConfigViewSet",
    "ConnectorActionViewSet",
]


class ConnectorConfigViewSet(PythonConfigViewSet):
    serializer_class = ConnectorConfigSerializer


class ConnectorActionViewSet(PluginActionViewSet):
    @classmethod
    @property
    def report_model(cls):
        return ConnectorReport
