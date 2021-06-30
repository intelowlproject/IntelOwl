# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import generics
from rest_framework.response import Response

from .serializers import ConnectorConfigSerializer


class ConnectorListAPI(generics.ListAPIView):
    def list(self, request):
        connector_config = ConnectorConfigSerializer.read_and_verify_config()
        return Response(connector_config)
