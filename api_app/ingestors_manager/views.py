# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from rest_framework import status
from rest_framework.response import Response

from api_app.ingestors_manager.serializers import IngestorConfigSerializer
from api_app.views import PythonConfigViewSet

logger = logging.getLogger(__name__)


class IngestorConfigViewSet(PythonConfigViewSet):
    serializer_class = IngestorConfigSerializer

    def disable_in_org(self, request, pk=None):
        return Response(status=status.HTTP_404_NOT_FOUND)

    def enable_in_org(self, request, pk=None):
        return Response(status=status.HTTP_404_NOT_FOUND)
