# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from pathlib import PosixPath

from django.conf import settings
from rest_framework import serializers as rfs

from api_app.core.serializers import AbstractConfigSerializer
from api_app.models import PluginConfig

from .constants import HashChoices, ObservableTypes, TypeChoices
from .models import AnalyzerReport


class AnalyzerReportSerializer(rfs.ModelSerializer):
    """
    AnalyzerReport model's serializer.
    """

    type = rfs.CharField(default="analyzer")

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
            "runtime_configuration",
            "type",
            "parent_playbook",
        )


class AnalyzerConfigSerializer(AbstractConfigSerializer):
    """
    Serializer for `analyzer_config.json`.
    """

    TypeChoices = TypeChoices
    HashChoices = HashChoices
    ObservableTypes = ObservableTypes

    # Required fields
    type = rfs.ChoiceField(required=True, choices=TypeChoices.values)
    external_service = rfs.BooleanField(required=True)
    # Optional Fields
    leaks_info = rfs.BooleanField(required=False, default=False)
    docker_based = rfs.BooleanField(required=False, default=False)
    run_hash = rfs.BooleanField(required=False, default=False)
    run_hash_type = rfs.ChoiceField(required=False, choices=HashChoices.values)
    supported_filetypes = rfs.ListField(required=False, default=[])
    not_supported_filetypes = rfs.ListField(required=False, default=[])
    observable_supported = rfs.ListField(
        child=rfs.ChoiceField(choices=ObservableTypes.values),
        required=False,
        default=[],
    )

    @classmethod
    @property
    def config_file_name(cls) -> str:
        return "analyzer_config.json"

    @classmethod
    def _get_type(cls):
        return PluginConfig.PluginType.ANALYZER

    @property
    def python_path(self) -> PosixPath:
        if self.initial_data["type"] == self.TypeChoices.OBSERVABLE or (
            self.initial_data["type"] == self.TypeChoices.FILE
            and self.initial_data.get("run_hash", False)
        ):
            return settings.BASE_ANALYZER_OBSERVABLE_PYTHON_PATH
        else:
            return settings.BASE_ANALYZER_FILE_PYTHON_PATH
