from rest_framework import mixins, viewsets
from rest_framework.permissions import IsAuthenticated

from api_app.core.views import AbstractConfigViewSet
from api_app.pivots_manager.models import Pivot, PivotConfig
from api_app.pivots_manager.permissions import PivotOwnerPermission
from api_app.pivots_manager.serializers import PivotConfigSerializer, PivotSerializer


class PivotConfigViewSet(AbstractConfigViewSet, mixins.CreateModelMixin):
    serializer_class = PivotConfigSerializer

    def get_queryset(self):
        return PivotConfig.objects.all()


class PivotViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, PivotOwnerPermission]
    serializer_class = PivotSerializer
    lookup_field = "pk"

    def get_queryset(self):
        return Pivot.objects.all()
