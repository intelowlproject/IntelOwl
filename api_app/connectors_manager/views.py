# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from rest_framework import generics, status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework import serializers as rfs
from django.utils.module_loading import import_string

from api_app.core.views import PluginActionViewSet, PluginHealthCheckAPI
from .serializers import ConnectorConfigSerializer
from .models import ConnectorReport
from . import controller as connectors_controller
from .dataclasses import ConnectorConfig
from .classes import Connector
from drf_spectacular.utils import (
    extend_schema as add_docs,
    inline_serializer,
)

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

    _config: ConnectorConfig

    def get_cls_path(self, connector_name) -> str:
        connector_dataclasses = ConnectorConfigSerializer.get_as_dataclasses()
        if connector_dataclasses.get(connector_name, None) is None:
            raise ValidationError({"detail": "Connector doesn't exist"})
        self._config = connector_dataclasses[connector_name]
        return self._config.get_full_import_path()

    def perform_healthcheck(self, connector_name):
        klass = import_string(self.get_cls_path(connector_name))
        # check if subclass overridded the method or not
        if klass.health_check.__func__ == Connector.health_check.__func__:
            raise ValidationError({"detail": "No healthcheck implemented"})
        return klass.health_check({}, self._config)
