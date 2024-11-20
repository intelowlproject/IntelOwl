# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

from rest_framework import mixins

from ..permissions import isPluginActionsPermission
from ..views import PluginConfigViewSet, PythonConfigViewSet, PythonReportActionViewSet
from .filters import AnalyzerConfigFilter
from .models import AnalyzerConfig, AnalyzerReport
from .serializers import AnalyzerConfigSerializer

logger = logging.getLogger(__name__)


__all__ = [
    "AnalyzerConfigViewSet",
    "AnalyzerActionViewSet",
]


class AnalyzerConfigViewSet(
    PythonConfigViewSet,
    mixins.CreateModelMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
):
    serializer_class = AnalyzerConfigSerializer
    filterset_class = AnalyzerConfigFilter
    queryset = AnalyzerConfig.objects.all()

    def get_permissions(self):
        permissions = super().get_permissions()
        if self.action in ["destroy", "update", "partial_update"]:
            permissions.append(isPluginActionsPermission())
        return permissions


class AnalyzerActionViewSet(PythonReportActionViewSet):
    @classmethod
    @property
    def report_model(cls):
        return AnalyzerReport


class AnalyzerPluginConfigViewSet(PluginConfigViewSet):
    queryset = AnalyzerConfig.objects.all()
