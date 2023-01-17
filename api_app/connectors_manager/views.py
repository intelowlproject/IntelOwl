# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import typing

from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer
from rest_framework import serializers as rfs
from rest_framework import status
from rest_framework.response import Response

from api_app.core.views import PluginActionViewSet, PluginHealthCheckAPI
from certego_saas.ext.views import APIView

from ..models import OrganizationPluginState, PluginConfig
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
            PluginConfig.apply(cc, request.user, PluginConfig.PluginType.CONNECTOR)
            OrganizationPluginState.apply(
                cc, request.user, PluginConfig.PluginType.CONNECTOR
            )
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
        from intel_owl import tasks

        tasks.run_connector.apply_async(args=[report.job.id, report])


class ConnectorHealthCheckAPI(PluginHealthCheckAPI):
    def perform_healthcheck(self, connector_name: str) -> bool:
        from rest_framework.exceptions import ValidationError

        from api_app.connectors_manager.classes import Connector
        from api_app.connectors_manager.dataclasses import ConnectorConfig

        connector_config = ConnectorConfig.get(connector_name)
        if connector_config is None:
            raise ValidationError({"detail": "Connector doesn't exist"})

        class_: typing.Type[Connector] = connector_config.get_class()

        try:
            status = class_.health_check(connector_name)
        except NotImplementedError:
            raise ValidationError({"detail": "No healthcheck implemented"})

        return status
