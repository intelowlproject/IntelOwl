# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from enum import Enum

from rest_framework import serializers as rfs

from api_app.core.serializers import AbstractConfigSerializer
from .models import AnalyzerReport


class AnalyzerReportSerializer(rfs.ModelSerializer):
    """
    AnalyzerReport model's serializer.
    """

    name = rfs.CharField(source="analyzer_name")

    class Meta:
        model = AnalyzerReport
        fields = (
            "name",
            "status",
            "report",
            "errors",
            "process_time",
            "start_time",
            "end_time",
        )


class AnalyzerConfigSerializer(AbstractConfigSerializer):
    """
    Serializer for `analyzer_config.json`.
    """

    CONFIG_FILE_NAME = "analyzer_config.json"

    class TypeChoices(Enum):
        FILE = "file"
        OBSERVABLE = "observable"

    class HashChoices(Enum):
        MD5 = "md5"
        SHA256 = "sha256"

    class ObservableTypes(Enum):
        IP = "ip"
        URL = "url"
        DOMAIN = "domain"
        HASH = "hash"
        GENERIC = "generic"

    # Required fields
    type = rfs.ChoiceField(required=True, choices=[c.value for c in TypeChoices])
    external_service = rfs.BooleanField(required=True)
    # Optional Fields
    leaks_info = rfs.BooleanField(required=False, default=False)
    run_hash = rfs.BooleanField(required=False, default=False)
    run_hash_type = rfs.ChoiceField(
        required=False, choices=[c.value for c in HashChoices]
    )
    supported_filetypes = rfs.ListField(required=False)
    not_supported_filetypes = rfs.ListField(required=False)
    observable_supported = rfs.ListField(
        child=rfs.ChoiceField(choices=[c.value for c in ObservableTypes]),
        required=False,
    )

    def validate_python_module(self, python_module: str):
        from django.utils.module_loading import import_string
        from .controller import build_import_path

        clspath = build_import_path(
            python_module,
            observable_analyzer=(
                self.initial_data["type"] == self.TypeChoices.OBSERVABLE.value
                or (
                    self.initial_data["type"] == self.TypeChoices.FILE.value
                    and self.initial_data.get("run_hash", False)
                )
            ),
        )
        try:
            import_string(clspath)
        except ImportError:
            raise rfs.ValidationError(
                f"`python_module` incorrect, {clspath} couldn't be imported"
            )

        return python_module
