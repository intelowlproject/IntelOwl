# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import generics
from rest_framework.response import Response
from rest_framework.exceptions import NotFound

from api_app.core.views import PluginActionViewSet
from .serializers import ConnectorConfigSerializer
from .models import ConnectorReport


class ConnectorListAPI(generics.ListAPIView):
    def list(self, request):
        connector_config = ConnectorConfigSerializer.read_and_verify_config()
        return Response(connector_config)


class ConnectorActionViewSet(PluginActionViewSet):
    queryset = ConnectorReport.objects.all()

    def get_object(self, job_id, connector_name) -> ConnectorReport:
        try:
            return self.queryset.get(
                job_id=job_id,
                connector_name=connector_name,
            )
        except ConnectorReport.DoesNotExist:
            raise NotFound()

    def _post_kill(self, report):
        pass
