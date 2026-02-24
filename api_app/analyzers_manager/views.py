# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

from rest_framework import mixins
from rest_framework.exceptions import NotFound

from api_app.decorators import classproperty
from api_app.models import PluginConfig

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
    @classproperty
    def report_model(cls):
        return AnalyzerReport


class AnalyzerPluginConfigViewSet(PluginConfigViewSet):
    queryset = AnalyzerConfig.objects.all()

    def update(self, request, name=None):
        obj: AnalyzerConfig = self.get_queryset().get(name=name)
        if (
            obj.python_module.module
            == "basic_observable_analyzer.BasicObservableAnalyzer"
        ):
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
