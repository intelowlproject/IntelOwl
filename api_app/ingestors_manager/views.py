# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response

from api_app.ingestors_manager.models import IngestorConfig
from api_app.ingestors_manager.serializers import IngestorConfigSerializer
from api_app.views import PluginConfigViewSet, PythonConfigViewSet

logger = logging.getLogger(__name__)


class IngestorConfigViewSet(PythonConfigViewSet):
    serializer_class = IngestorConfigSerializer

    @action(
        methods=["post"],
        detail=True,
        url_path="organization",
    )
    def disable_in_org(self, request, name=None):
        return Response(status=status.HTTP_404_NOT_FOUND)

    @disable_in_org.mapping.delete
    def enable_in_org(self, request, name=None):
        return Response(status=status.HTTP_404_NOT_FOUND)


class IngestorPluginConfigViewSet(PluginConfigViewSet):
    queryset = IngestorConfig.objects.all()
