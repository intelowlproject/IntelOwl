# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import generics
from rest_framework.response import Response

from api_app.core.views import PluginActionViewSet
from .serializers import ConnectorConfigSerializer
from .models import ConnectorReport
from . import controller as connectors_controller


class ConnectorListAPI(generics.ListAPIView):
    def list(self, request):
        connector_config = ConnectorConfigSerializer.read_and_verify_config()
        return Response(connector_config)


class ConnectorActionViewSet(PluginActionViewSet):
    queryset = ConnectorReport.objects.all()

    @property
    def report_model(self):
        return ConnectorReport

    def perform_retry(self, report: ConnectorReport):
        connectors_to_execute, runtime_configuration = super().perform_retry(
            self, report
        )
        connectors_controller.start_connectors(
            report.job.id,
            connectors_to_execute,
            runtime_configuration,
        )
