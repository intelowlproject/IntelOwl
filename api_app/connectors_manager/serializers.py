# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from pathlib import PosixPath

from django.conf import settings
from rest_framework import serializers as rfs

from api_app.core.serializers import AbstractConfigSerializer
from api_app.models import TLP, PluginConfig

from .models import ConnectorReport


class ConnectorConfigSerializer(AbstractConfigSerializer):
    """
    Serializer for `connector_config.json`.
    """

    maximum_tlp = rfs.ChoiceField(choices=TLP.choices)
    run_on_failure = rfs.BooleanField(default=False)

    @classmethod
    @property
    def config_file_name(cls) -> str:
        return "connector_config.json"

    @classmethod
    def _get_type(cls):
        return PluginConfig.PluginType.CONNECTOR

    @property
    def python_path(self) -> PosixPath:
        return settings.BASE_CONNECTOR_PYTHON_PATH


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
