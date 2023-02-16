# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import typing

from celery import group
from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer
from rest_framework import serializers as rfs

from api_app.core.views import PluginActionViewSet, PluginHealthCheckAPI, PluginListAPI

from .dataclasses import ConnectorConfig
from .models import ConnectorReport
from .serializers import ConnectorConfigSerializer

logger = logging.getLogger(__name__)


__all__ = [
    "ConnectorListAPI",
    "ConnectorActionViewSet",
    "ConnectorHealthCheckAPI",
]


class ConnectorListAPI(PluginListAPI):
    @property
    def serializer_class(self) -> typing.Type[ConnectorConfigSerializer]:
        return ConnectorConfigSerializer

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
        return super(request, *args, **kwargs)


class ConnectorActionViewSet(PluginActionViewSet):
    queryset = ConnectorReport.objects.all()

    @property
    def report_model(self):
        return ConnectorReport

    def perform_retry(self, report: ConnectorReport):
        signatures, _ = ConnectorConfig.stack(
            job_id=report.job.id,
            plugins_to_execute=[report.connector_name],
            runtime_configuration=report.runtime_configuration,
            parent_playbook=report.parent_playbook,
        )
        group(signatures)()


class ConnectorHealthCheckAPI(PluginHealthCheckAPI):
    @property
    def config_model(self) -> typing.Type[ConnectorConfig]:
        return ConnectorConfig
