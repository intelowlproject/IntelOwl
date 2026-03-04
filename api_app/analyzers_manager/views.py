# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

from rest_framework import mixins
from rest_framework.exceptions import NotFound

from api_app.decorators import classproperty
from api_app.models import PluginConfig
from api_app.permissions import isPluginActionsPermission
from api_app.views import PluginConfigViewSet, PythonConfigViewSet, PythonReportActionViewSet
from api_app.analyzers_manager.filters import AnalyzerConfigFilter
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer

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
    """ViewSet for AnalyzerConfig model with full CRUD operations."""
    serializer_class = AnalyzerConfigSerializer
    filterset_class = AnalyzerConfigFilter
    queryset = AnalyzerConfig.objects.all()

    def get_permissions(self):
        permissions = super().get_permissions()
        if self.action in ["destroy", "update", "partial_update"]:
            permissions.append(isPluginActionsPermission())
        return permissions


class AnalyzerActionViewSet(PythonReportActionViewSet):
    """ViewSet for analyzer actions."""

    @classproperty
    def report_model(cls):  # type: ignore
        return AnalyzerReport


class AnalyzerPluginConfigViewSet(PluginConfigViewSet):
    """ViewSet for analyzer plugin configuration."""
    queryset = AnalyzerConfig.objects.all()

    def update(self, request, name=None):
        obj: AnalyzerConfig = self.get_queryset().get(name=name)
        if obj.python_module.module == "basic_observable_analyzer.BasicObservableAnalyzer":
            for data in request.data:
                try:
                    plugin_config: PluginConfig = PluginConfig.objects.get(
                        parameter=data["parameter"],
                        owner=request.user,
                        analyzer_config=obj.pk,
                    )
                    data["id"] = plugin_config.pk
                except PluginConfig.DoesNotExist:
                    raise NotFound("Requested plugin config does not exist.")
        return super().update(request, name)
