# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from typing import Dict

from django.utils.module_loading import import_string
from rest_framework import serializers as rfs


from api_app.core.serializers import AbstractConfigSerializer
from .models import ConnectorReport
from .dataclasses import ConnectorConfig


class ConnectorConfigSerializer(AbstractConfigSerializer):
    """
    Serializer for `connector_config.json`.
    """

    CONFIG_FILE_NAME = "connector_config.json"

    def validate_python_module(self, python_module: str):
        clspath = f"api_app.connectors_manager.connectors.{python_module}"
        try:
            import_string(clspath)
        except ImportError:
            raise rfs.ValidationError(
                f"`python_module` incorrect, {clspath} couldn't be imported"
            )

        return python_module

    @classmethod
    def dict_to_dataclass(cls, data: dict) -> ConnectorConfig:
        return ConnectorConfig(**data)

    @classmethod
    def get_as_dataclasses(cls) -> Dict[str, ConnectorConfig]:
        return {
            name: cls.dict_to_dataclass(attrs)
            for name, attrs in cls.read_and_verify_config().items()
        }


class ConnectorReportSerializer(rfs.ModelSerializer):
    """
    ConnectorReport model's serializer.
    """

    name = rfs.CharField(source="connector_name")

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
