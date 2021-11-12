# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer
from rest_framework import generics
from rest_framework import serializers as rfs
from rest_framework import status
from rest_framework.response import Response

from api_app.core.views import PluginActionViewSet, PluginHealthCheckAPI

from . import controller as connectors_controller
from .models import ConnectorReport
from .serializers import ConnectorConfigSerializer

logger = logging.getLogger(__name__)


class ConnectorListAPI(generics.ListAPIView):

    serializer_class = ConnectorConfigSerializer

    @add_docs(
        description="Get the uploaded connector configuration",
        parameters=[],
        responses={
            200: ConnectorConfigSerializer,
            500: inline_serializer(
                name="GetConnectorConfigsFailedResponse",
                fields={"error": rfs.StringRelatedField()},
            ),
        },
    )
    def get(self, request, *args, **kwargs):
        # @extend_schema needs to be applied to the entrypoint method of the view
        # `list` call is proxied through the entrypoint `get`
        return super().get(request, *args, **kwargs)

    def list(self, request):
        try:
            logger.info(
                f"get_connector_configs received request from {str(request.user)}."
            )
            cc = self.serializer_class.read_and_verify_config()
            return Response(cc, status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception(
                f"get_connector_configs requester:{str(request.user)} error:{e}."
            )
            return Response(
                {"error": "error in get_connector_configs. Check logs."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ConnectorActionViewSet(PluginActionViewSet):
    queryset = ConnectorReport.objects.all()

    @property
    def report_model(self):
        return ConnectorReport

    def perform_retry(self, report: ConnectorReport):
        connectors_to_execute, runtime_configuration = super().perform_retry(report)
        connectors_controller.start_connectors(
            report.job.id,
            connectors_to_execute,
            runtime_configuration,
        )


class ConnectorHealthCheckAPI(PluginHealthCheckAPI):
    def perform_healthcheck(self, connector_name):
        return connectors_controller.run_healthcheck(connector_name)
