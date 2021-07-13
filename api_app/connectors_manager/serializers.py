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

    def validate_python_module(self, python_module: str):
        from .controller import build_import_path
        from django.utils.module_loading import import_string

        clspath = build_import_path(python_module)
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
