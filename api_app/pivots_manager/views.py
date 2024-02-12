from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from api_app.pivots_manager.models import PivotMap, PivotReport
from api_app.pivots_manager.permissions import PivotOwnerPermission
from api_app.pivots_manager.serializers import PivotConfigSerializer, PivotMapSerializer
from api_app.views import PythonConfigViewSet, PythonReportActionViewSet


class PivotConfigViewSet(PythonConfigViewSet):
    serializer_class = PivotConfigSerializer


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
