# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer
from rest_framework import serializers as rfs
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response

from api_app.core.views import AbstractConfigAPI, PluginActionViewSet

from .filters import AnalyzerConfigFilter
from .models import AnalyzerConfig, AnalyzerReport
from .serializers import AnalyzerConfigSerializer

logger = logging.getLogger(__name__)


__all__ = [
    "AnalyzerConfigAPI",
    "AnalyzerActionViewSet",
]


class AnalyzerConfigAPI(AbstractConfigAPI):
    serializer_class = AnalyzerConfigSerializer
    filterset_class = AnalyzerConfigFilter

    def get_queryset(self):
        return super().get_queryset().prefetch_related("parameters")

    @add_docs(
        description="Update plugin with latest configuration",
        request=None,
        responses={
            200: inline_serializer(
                name="PluginUpdateSuccessResponse",
                fields={
                    "status": rfs.BooleanField(allow_null=False),
                    "detail": rfs.CharField(allow_null=True),
                },
            ),
        },
    )
    @action(
        detail=True, methods=["post"], url_name="pull", permission_classes=[IsAdminUser]
    )
    def pull(self, request, name=None):
        logger.info(f"update request from user {request.user}, name {name}")
        obj: AnalyzerConfig = self.get_object()
        success = obj.python_class.update()
        if not success:
            raise ValidationError({"detail": "No update implemented"})

        return Response(data={"status": True}, status=status.HTTP_200_OK)


class AnalyzerActionViewSet(PluginActionViewSet):
    @classmethod
    @property
    def report_model(cls):
        return AnalyzerReport
