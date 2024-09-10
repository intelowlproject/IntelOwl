from rest_framework import mixins, viewsets
from rest_framework.permissions import IsAuthenticated

from api_app.pivots_manager.models import PivotConfig, PivotMap, PivotReport
from api_app.pivots_manager.permissions import (
    PivotActionsPermission,
    PivotOwnerPermission,
)
from api_app.pivots_manager.serializers import PivotConfigSerializer, PivotMapSerializer
from api_app.views import PythonConfigViewSet, PythonReportActionViewSet


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
    @classmethod
    @property
    def report_model(cls):
        return PivotReport


class PivotMapViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated, PivotOwnerPermission]
    serializer_class = PivotMapSerializer
    lookup_field = "pk"
    queryset = PivotMap.objects.all()
