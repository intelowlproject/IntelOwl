# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from rest_framework import serializers as rfs

from api_app.core.serializers import AbstractConfigSerializer
from .models import ConnectorReport


class ConnectorConfigSerializer(AbstractConfigSerializer):
    """
    Serializer for `connector_config.json`.
    """

    CONFIG_FILE_NAME = "connector_config.json"


class ConnectorReportSerializer(rfs.ModelSerializer):
    """
    ConnectorReport model's serializer.
    """

    name = rfs.CharField(source="connector")

    class Meta:
        model = ConnectorReport
        fields = (
            "name",
            "status",
            "report",
            "errors",
            "process_time",
            "start_time",
        )
