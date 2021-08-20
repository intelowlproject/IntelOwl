# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.utils.module_loading import import_string
from rest_framework import serializers as rfs


from api_app.core.serializers import AbstractConfigSerializer
from api_app.models import TLP
from .models import ConnectorReport


class ConnectorConfigSerializer(AbstractConfigSerializer):
    """
    Serializer for `connector_config.json`.
    """

    maximum_tlp = rfs.ChoiceField(choices=TLP.choices)

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


class ConnectorReportSerializer(rfs.ModelSerializer):
    """
    ConnectorReport model's serializer.
    """

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
