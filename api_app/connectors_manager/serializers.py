# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from rest_framework import serializers as rfs

from api_app.core.serializers import AbstractConfigSerializer

from .models import ConnectorConfig, ConnectorReport


class ConnectorConfigSerializer(AbstractConfigSerializer):
    class Meta:
        model = ConnectorConfig
        fields = rfs.ALL_FIELDS


class ConnectorReportSerializer(rfs.ModelSerializer):
    """
    ConnectorReport model's serializer.
    """

    type = rfs.CharField(default="connector")

    class Meta:
        model = ConnectorReport
        fields = (
            "name",
            "status",
            "report",
            "errors",
            "process_time",
            "start_time",
            "end_time",
            "runtime_configuration",
            "type",
            "parent_playbook",
        )
