from rest_framework import mixins, viewsets
from rest_framework.permissions import IsAuthenticated

from api_app.pivots_manager.models import PivotMap, PivotReport
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

    def get_permissions(self):
        permissions = super().get_permissions()
        if self.action in ["destroy", "update", "partial_update"]:
            permissions.append(PivotActionsPermission())
        return permissions


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
