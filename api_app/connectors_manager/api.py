# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import generics
from rest_framework.response import Response

from api_app.connectors_manager.serializers import ConnectorConfigSerializer
from api_app.connectors_manager import helpers


class ConnectorListAPI(generics.ListAPIView):
    def list(self, request):
        connector_config = helpers.get_connector_config()

        for key, config in connector_config.items():
            serializer = ConnectorConfigSerializer(data=config)
            if serializer.is_valid():
                connector_config[key] = serializer.data  # mutate with processed config

        return Response(connector_config)
