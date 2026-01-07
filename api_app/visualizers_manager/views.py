# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from api_app.decorators import classproperty
from api_app.views import (
    PluginConfigViewSet,
    PythonConfigViewSet,
    PythonReportActionViewSet,
)
from api_app.visualizers_manager.models import VisualizerConfig, VisualizerReport
from api_app.visualizers_manager.serializers import VisualizerConfigSerializer

logger = logging.getLogger(__name__)


__all__ = [
    "VisualizerConfigViewSet",
]


class VisualizerConfigViewSet(PythonConfigViewSet):
    serializer_class = VisualizerConfigSerializer


class VisualizerActionViewSet(PythonReportActionViewSet):
    @classproperty
    def report_model(cls):
        return VisualizerReport


class VisualizerPluginConfigViewSet(PluginConfigViewSet):
    queryset = VisualizerConfig.objects.all()
