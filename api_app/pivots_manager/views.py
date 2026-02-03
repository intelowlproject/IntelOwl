from rest_framework import mixins, viewsets
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated

from api_app.decorators import classproperty
from api_app.models import PluginConfig
from api_app.pivots_manager.models import PivotConfig, PivotMap, PivotReport
from api_app.pivots_manager.permissions import (
    PivotActionsPermission,
    PivotOwnerPermission,
)
from api_app.pivots_manager.serializers import PivotConfigSerializer, PivotMapSerializer
from api_app.views import (
    PluginConfigViewSet,
    PythonConfigViewSet,
    PythonReportActionViewSet,
)


class PivotConfigViewSet(
    PythonConfigViewSet,
    mixins.CreateModelMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
):
    serializer_class = PivotConfigSerializer
    queryset = PivotConfig.objects.all()

    def get_queryset(self):
        return (
            super()
            .get_queryset()
            .prefetch_related(
                "related_analyzer_configs",
                "related_connector_configs",
                "playbooks_choice",
            )
        )

    def get_permissions(self):
        permissions = super().get_permissions()
        if self.action in ["destroy", "update", "partial_update"]:
            permissions.append(PivotActionsPermission())
        return permissions

    def perform_destroy(self, instance: PivotConfig):
        for pivot_map in PivotMap.objects.filter(pivot_config=instance):
            pivot_map.pivot_config = None
            pivot_map.save()
        return super().perform_destroy(instance)


class PivotActionViewSet(PythonReportActionViewSet):
    @classproperty
    def report_model(cls):
        return PivotReport


class PivotMapViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated, PivotOwnerPermission]
    serializer_class = PivotMapSerializer
    lookup_field = "pk"
    queryset = PivotMap.objects.all()


class PivotPluginConfigViewSet(PluginConfigViewSet):
    queryset = PivotConfig.objects.all()

    def update(self, request, name=None):
        obj: PivotConfig = self.get_queryset().get(name=name)
        for data in request.data:
            try:
                plugin_config: PluginConfig = PluginConfig.objects.get(
                    parameter=data["parameter"],
                    owner=request.user,
                    pivot_config=obj.pk,
                )
                data["id"] = plugin_config.pk
            except PluginConfig.DoesNotExist:
                raise NotFound("Requested plugin config does not exist.")
        return super().update(request, name)
