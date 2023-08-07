from rest_framework import mixins, viewsets
from rest_framework.permissions import IsAuthenticated

from api_app.pivots_manager.models import Pivot, PivotConfig
from api_app.pivots_manager.permissions import PivotOwnerPermission
from api_app.pivots_manager.serializers import PivotConfigSerializer, PivotSerializer
from api_app.views import AbstractConfigViewSet


class PivotConfigViewSet(AbstractConfigViewSet, mixins.CreateModelMixin):
    serializer_class = PivotConfigSerializer
    queryset = PivotConfig.objects.all()


class PivotViewSet(viewsets.ReadOnlyModelViewSet, mixins.CreateModelMixin):
    permission_classes = [IsAuthenticated, PivotOwnerPermission]
    serializer_class = PivotSerializer
    lookup_field = "pk"
    queryset = Pivot.objects.all()
