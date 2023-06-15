# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from api_app.core.views import AbstractConfigAPI, PluginActionViewSet
from api_app.visualizers_manager.models import VisualizerReport
from api_app.visualizers_manager.serializers import VisualizerConfigSerializer

logger = logging.getLogger(__name__)


__all__ = [
    "VisualizerConfigAPI",
]


class VisualizerConfigAPI(AbstractConfigAPI):
    serializer_class = VisualizerConfigSerializer


class VisualizerActionViewSet(PluginActionViewSet):
    @classmethod
    @property
    def report_model(cls):
        return VisualizerReport
