from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from api_app.pivots_manager.models import PivotConfig, PivotMap
from api_app.pivots_manager.permissions import PivotOwnerPermission
from api_app.pivots_manager.serializers import PivotConfigSerializer, PivotMapSerializer
from api_app.views import AbstractConfigViewSet


class PivotConfigViewSet(AbstractConfigViewSet):
    serializer_class = PivotConfigSerializer
    queryset = PivotConfig.objects.all()


class PivotMapViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated, PivotOwnerPermission]
    serializer_class = PivotMapSerializer
    lookup_field = "pk"
    queryset = PivotMap.objects.all()
