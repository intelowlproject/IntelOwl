# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer
from rest_framework import serializers as rfs
from rest_framework import status
from rest_framework.response import Response

from api_app.core.views import PluginActionViewSet, PluginHealthCheckAPI
from certego_saas.ext.views import APIView

from ..models import CustomConfig
from . import controller as connectors_controller
from .models import ConnectorReport
from .serializers import ConnectorConfigSerializer

logger = logging.getLogger(__name__)


__all__ = [
    "ConnectorListAPI",
    "ConnectorActionViewSet",
    "ConnectorHealthCheckAPI",
]


class ConnectorListAPI(APIView):

    serializer_class = ConnectorConfigSerializer

    @add_docs(
        description="Get and parse the `connector_config.json` file",
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
        try:
            cc = self.serializer_class.read_and_verify_config()
            CustomConfig.apply(cc, request.user, CustomConfig.PluginType.CONNECTOR)
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
    def perform_healthcheck(self, connector_name: str) -> bool:
        return connectors_controller.run_healthcheck(connector_name)
