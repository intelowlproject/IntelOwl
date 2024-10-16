from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from api_app.data_model_manager.serializers import (
    DomainDataModelSerializer,
    FileDataModelSerializer,
    IPDataModelSerializer,
)
from api_app.mixins import PaginationMixin
from api_app.permissions import IsObjectOwnerOrSameOrgPermission


class BaseDataModelView(PaginationMixin, viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated, IsObjectOwnerOrSameOrgPermission]
    ordering = ["date"]

    def get_queryset(self):
        return self.serializer_class.Meta.model.objects.all()


class DomainDataModelView(BaseDataModelView):
    serializer_class = DomainDataModelSerializer


class IPDataModelView(BaseDataModelView):
    serializer_class = IPDataModelSerializer


class FileDataModelView(BaseDataModelView):
    serializer_class = FileDataModelSerializer
